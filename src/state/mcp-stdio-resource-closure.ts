// Original stdio scope custody only. A missing READY is never, by itself,
// proof of an uncreated namespace; the complete native retirement is required.
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ProcessContainment, ProcessContainmentPlanV1, ProcessContainmentDeathEvidenceV1,
  ProcessContainmentNoSpawnEvidenceV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readInstalledMcpStdioRunJoined, readInstalledMcpStdioRecoveryJoined, type InstalledMcpStdioRunScope, type InstalledMcpStdioRecoveryScope } from '../sandbox/mcp-stdio-native.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import type { NativeMcpStdioRunOwner, RunMcpStdioLaunchBinding, NativeMcpStdioRecoveryOwner, McpStdioRecoveryBinding } from './mcp-stdio-broker-native.js';
import { assertInstalledMcpStdioRunJoined, assertInstalledMcpStdioRecoveryJoined } from './mcp-stdio-native-binding.js';
import type { HeldRunMcpStdioInput, HeldRecoveryMcpStdioInput } from './native-owner.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import type { SqliteDriver } from './sqlite-driver.js';

async function publishStdioRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  binding: RunMcpStdioLaunchBinding | McpStdioRecoveryBinding,
  joined: ReturnType<typeof readInstalledMcpStdioRunJoined> | ReturnType<typeof readInstalledMcpStdioRecoveryJoined>, purpose: 'run' | 'recovery') {
  const original = joined.originalLifecycle, physical = joined.joined.observation;
  if (!original.retirement || !original.joined.deathJoined || !original.joined.outputCustodyRetired || !original.joined.ownerDrained ||
      original.joined.responseRefused || physical.cgroupPopulated !== 0 ||
      physical.remainingTrackedDescendants !== 0 || original.binding.kind !== purpose)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original scope has no complete safe local process/pipe/FD retirement');
  requireEqual(original.retirement, physical, 'MCP original immutable retirement and same-scope actual joined observation');
  const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, binding.plannedContainmentRef);
  const samePurpose = 'launchOpId' in binding ? purpose === 'run' && plan.owner.kind === 'run_invocation' &&
    plan.owner.runId === binding.runId && plan.owner.opId === binding.launchOpId && plan.owner.attempt === binding.attempt && plan.owner.dispatchId === binding.dispatchId
    : purpose === 'recovery' && plan.owner.kind === 'reconciliation_probe' && plan.owner.runId === binding.runId &&
      plan.owner.principalId === binding.principalId && plan.owner.probeKind === binding.probeKind && plan.owner.probeOrdinal === binding.probeOrdinal &&
      plan.owner.originalOpId === binding.originalOpId && plan.owner.originalAttempt === binding.originalAttempt && plan.owner.originalDispatchId === binding.originalDispatchId &&
      plan.owner.previousWaitingSubjectRef === binding.previousWaitingSubjectRef && plan.owner.probeNonceDigest === binding.probeNonceDigest &&
      plan.owner.brokerDispatchId === binding.brokerDispatchId && plan.owner.supervisorInstanceId === binding.inspectorSupervisorInstanceId &&
      plan.owner.stateOwnerEpoch === binding.inspectorStateOwnerEpoch;
  if (plan.backend.kind !== 'linux' || !samePurpose || plan.planDigest !== binding.plannedContainmentDigest ||
      original.reservation.cgroupInode !== physical.cgroupId || original.binding.sandboxLaunchSpecRef !== binding.sandboxLaunchSpecRef ||
      original.binding.nonce !== binding.nonce) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original local retirement changes its exact prepared purpose/domain');
  const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner)), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const observedAt = new Date(physical.observedAtMs).toISOString(), common = { schemaVersion: 1 as const,
    planRef: binding.plannedContainmentRef, sandboxLaunchSpecRef: binding.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: binding.sandboxLaunchSpecDigest,
    owner: plan.owner, launchNonceDigest: plan.launchNonceDigest, inspectorSupervisorInstanceId: owner.supervisorInstanceId,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt };
  let containment: ProcessContainment | undefined, containmentRef: string | undefined;
  const metadata: PublishedArtifact[] = [inspectorArtifact];
  let evidence: ProcessContainmentDeathEvidenceV1 | ProcessContainmentNoSpawnEvidenceV1;
  if (original.containment) {
    const ready = original.containment;
    if (physical.namespaceInitDeadAndReaped !== 1 || ready.namespaceInitPid <= 0 || ready.cgroupId !== physical.cgroupId || ready.pidNamespaceId !== physical.pidNamespaceId ||
        ready.namespaceInitStartToken !== physical.namespaceInitStartToken || ready.namespaceInitPid !== physical.namespaceInitPid)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original READY and retired namespace identities differ');
    containment = { schemaVersion: 1, planRef: binding.plannedContainmentRef, sandboxLaunchSpecRef: binding.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: binding.sandboxLaunchSpecDigest, owner: plan.owner, filesystemBinding: plan.filesystemBinding, launchNonceDigest: plan.launchNonceDigest,
      backend: { kind: 'linux', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId, pidNamespaceId: ready.pidNamespaceId,
        cgroupPath: plan.backend.cgroupPath, cgroupId: ready.cgroupId, namespaceInitStartToken: ready.namespaceInitStartToken,
        subreaperStartToken: plan.backend.subreaperStartToken }, createdAt: new Date(ready.observedAtMs).toISOString() };
    const artifact = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1'); containmentRef = artifact.ref; metadata.push(artifact);
    const core = { ...common, kind: 'containment_all_descendants_dead' as const, containmentRef,
      backend: { ...containment.backend as Extract<ProcessContainment['backend'], { kind: 'linux' }>, cgroupPopulated: 0 as const,
        namespaceInitDeadAndReaped: true as const, remainingTrackedDescendants: 0 as const } };
    evidence = { ...core, evidenceDigest: canonicalSha256(core) };
  } else {
    if (physical.namespaceInitDeadAndReaped !== 0 || physical.namespaceInitPid !== 0 || original.joined.execReleased || original.joined.spawnAttempted || original.progressKind !== 9)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP missing READY cannot prove that its original namespace was never created');
    const core = { ...common, kind: 'containment_plan_quiescent' as const, backend: { kind: 'linux' as const,
      cgroupPath: plan.backend.cgroupPath, cgroupObservation: { kind: 'empty' as const, cgroupId: physical.cgroupId, populated: 0 as const },
      pidNamespaceObservation: { kind: 'never_created' as const, pidNamespaceReservationId: plan.backend.pidNamespaceReservationId },
      subreaperStartToken: plan.backend.subreaperStartToken, matchingLaunchNonceProcessCount: 0 as const } };
    evidence = { ...core, evidenceDigest: canonicalSha256(core) };
  }
  const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.kind === 'containment_all_descendants_dead'
    ? 'cliq-process-containment-death-evidence-v1' : 'cliq-process-containment-no-spawn-evidence-v1');
  const raw = await artifacts.publishBytes(joined.lifecycleSnapshot, 'application/octet-stream', purpose === 'run'
    ? 'cliq-mcp-stdio-native-lifecycle-bytes-v1' : 'cliq-mcp-stdio-recovery-native-lifecycle-bytes-v1');
  const projection = await artifacts.publishCanonical(original, original.format);
  return { joined, original, physical, plan, containment, containmentRef, evidence, evidenceRef: evidenceArtifact.ref,
    nativeClosure: { kind: 'linux_original_join' as const, lifecycleRawRef: raw.ref, lifecycleProjectionRef: projection.ref },
    metadata: [...metadata, evidenceArtifact, raw, projection], observedAt };
}

export async function publishOriginalMcpStdioRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  native: NativeMcpStdioRunOwner, binding: RunMcpStdioLaunchBinding, scope: InstalledMcpStdioRunScope, input: HeldRunMcpStdioInput) {
  const joined = readInstalledMcpStdioRunJoined(scope, input);
  assertInstalledMcpStdioRunJoined(native, joined.ownerJoined, binding); scope.assertJoined(joined.joined);
  const proof = await publishStdioRetirement(driver, artifacts, owner, binding, joined, 'run');
  return { ...proof, joined, original: joined.originalLifecycle, physical: joined.joined.observation };
}

export async function publishOriginalMcpStdioRecoveryRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  native: NativeMcpStdioRecoveryOwner, binding: McpStdioRecoveryBinding, scope: InstalledMcpStdioRecoveryScope, input: HeldRecoveryMcpStdioInput) {
  const joined = readInstalledMcpStdioRecoveryJoined(scope, input);
  assertInstalledMcpStdioRecoveryJoined(native, joined.ownerJoined, binding); scope.assertJoined(joined.joined);
  const proof = await publishStdioRetirement(driver, artifacts, owner, binding, joined, 'recovery');
  return { ...proof, joined, original: joined.originalLifecycle, physical: joined.joined.observation };
}
