// One successor writer for a completely born original server whose ordinary
// effect was never claimed. Current cleanup is not the old native authority,
// and an unavailable setup outcome is never relabelled "not initialized".
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { InvocationJournalEntry, RecoveryClosureV1, ProcessContainment, ProcessContainmentPlanV1,
  ProcessContainmentDeathEvidenceV1, ProcessContainmentNoSpawnEvidenceV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readInstalledMcpStdioRunCleanup } from '../sandbox/mcp-stdio-native.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { insertArtifactMetadata } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError, joinResourceOperations } from './errors.js';
import { decodeMcpStdioLifecycleData, type HeldRunMcpStdioInput } from './native-owner.js';
import { readMcpServerLaunchContext, readMcpServerNativeResources } from './mcp-server-history.js';
import { mcpServerFailedLaunchData } from './mcp-server-terminal-data.js';
import { appendInvocationJournalEntry, nextJournalSequence, readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { readRun } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import type { SqliteDriver } from './sqlite-driver.js';

type History = Awaited<ReturnType<typeof readRetainedStateOwnerHistory>>;
export async function settleMcpStdioServerWithoutEffect(input: Readonly<{
  driver: SqliteDriver; artifacts: ArtifactCatalog; reads: ArtifactCatalog; owner: StateOwnerContext; cut: RecoveryClosureV1;
  context: Awaited<ReturnType<typeof readMcpServerLaunchContext>>; prepared: InvocationJournalEntry; claim?: InvocationJournalEntry;
  tool: InvocationJournalEntry; history: History; original: History['entries'][number];
  receipt: Parameters<typeof readInstalledMcpStdioRunCleanup>[0]; actual: ReturnType<typeof readInstalledMcpStdioRunCleanup>; physical: HeldRunMcpStdioInput;
}>) {
  const { driver, artifacts, reads, owner, cut, context, prepared, claim, tool, history, original, receipt, actual, physical } = input;
  const run = cut.run, p = context.preparation, lifecycle = decodeMcpStdioLifecycleData(actual.lifecycleSnapshot), cleanup = actual.observation;
  const active = assertActiveStateOwner(driver, owner), plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(reads, p.plannedContainmentRef);
  if (lifecycle.binding.kind !== 'run' || lifecycle.joined.effectReleased || lifecycle.joined.responseRefused ||
      !cleanup.priorSupervisorDead || !cleanup.priorControllerDead || !cleanup.outputCustodyRetired || cleanup.remainingDescendants !== 0 ||
      active.ownerEpoch <= original.owner.ownerEpoch || plan.backend.kind !== 'linux' || plan.owner.kind !== 'run_invocation' ||
      plan.planDigest !== p.plannedContainmentDigest || plan.planDigest !== digestOmitting(plan, 'planDigest') ||
      cut.journal.some(entry => entry.opId === tool.opId && entry.attempt === tool.attempt && entry.phase === 'dispatch_claimed'))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP successor cannot close unsafe, live or effect-claimed original server resources');
  requireEqual(readInvocationAttempt(driver, run.id, tool.opId, tool.attempt), [tool], 'MCP successor preserves the original unclaimed ordinary effect reservation');
  const metadata: PublishedArtifact[] = [], inspector = supervisorInspectorIdentity(active), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const observedAt = new Date(cleanup.observedAtMs).toISOString(); metadata.push(inspectorArtifact);
  const [raw, projection, cleanupRaw, cleanupProjection] = await joinResourceOperations([
    artifacts.publishBytes(actual.lifecycleSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-native-lifecycle-bytes-v1'),
    artifacts.publishCanonical(lifecycle, lifecycle.format), artifacts.publishBytes(actual.cleanupSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-native-cleanup-bytes-v1'),
    artifacts.publishCanonical(cleanup, cleanup.format)]);
  metadata.push(raw, projection, cleanupRaw, cleanupProjection);
  const nativeClosure = { kind: 'linux_successor_cleanup' as const, lifecycleRawRef: raw.ref, lifecycleProjectionRef: projection.ref,
    cleanupRawRef: cleanupRaw.ref, cleanupProjectionRef: cleanupProjection.ref };
  const common = { schemaVersion: 1 as const, planRef: p.plannedContainmentRef, sandboxLaunchSpecRef: p.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: p.sandboxLaunchSpecDigest, owner: plan.owner, launchNonceDigest: plan.launchNonceDigest,
    inspectorSupervisorInstanceId: active.supervisorInstanceId, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt };
  let containmentRef: string | undefined, evidenceRef: string, evidence: ProcessContainmentDeathEvidenceV1 | ProcessContainmentNoSpawnEvidenceV1;
  if (lifecycle.containment) {
    const birth = lifecycle.containment;
    if (!claim) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP unclaimed server cannot have created its execution namespace');
    const containment: ProcessContainment = { schemaVersion: 1, planRef: p.plannedContainmentRef, sandboxLaunchSpecRef: p.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: p.sandboxLaunchSpecDigest, owner: plan.owner, filesystemBinding: plan.filesystemBinding, launchNonceDigest: plan.launchNonceDigest,
      backend: { kind: 'linux', cgroupPath: plan.backend.cgroupPath, cgroupId: birth.cgroupId, pidNamespaceReservationId: plan.backend.pidNamespaceReservationId,
        pidNamespaceId: birth.pidNamespaceId, namespaceInitStartToken: birth.namespaceInitStartToken, subreaperStartToken: plan.backend.subreaperStartToken },
      createdAt: new Date(birth.observedAtMs).toISOString() };
    const artifact = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1'); metadata.push(artifact); containmentRef = artifact.ref;
    const core = { ...common, kind: 'containment_all_descendants_dead' as const, containmentRef,
      backend: { ...containment.backend as Extract<ProcessContainment['backend'], { kind: 'linux' }>, cgroupPopulated: 0 as const,
        namespaceInitDeadAndReaped: true as const, remainingTrackedDescendants: 0 as const } };
    evidence = { ...core, evidenceDigest: canonicalSha256(core) };
  } else {
    if (lifecycle.joined.spawnAttempted || lifecycle.joined.execReleased || cleanup.retirement.namespaceInitPid !== 0 || cleanup.retirement.namespaceInitDeadAndReaped !== 0)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP missing original namespace birth cannot prove never-created execution');
    const core = { ...common, kind: 'containment_plan_quiescent' as const, backend: { kind: 'linux' as const, cgroupPath: plan.backend.cgroupPath,
      cgroupObservation: { kind: 'empty' as const, cgroupId: cleanup.retirement.cgroupId, populated: 0 as const },
      pidNamespaceObservation: { kind: 'never_created' as const, pidNamespaceReservationId: plan.backend.pidNamespaceReservationId },
      subreaperStartToken: plan.backend.subreaperStartToken, matchingLaunchNonceProcessCount: 0 as const } };
    evidence = { ...core, evidenceDigest: canonicalSha256(core) };
  }
  const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.kind === 'containment_all_descendants_dead'
    ? 'cliq-process-containment-death-evidence-v1' : 'cliq-process-containment-no-spawn-evidence-v1'); evidenceRef = evidenceArtifact.ref; metadata.push(evidenceArtifact);
  const resources = await readMcpServerNativeResources(driver, reads, context, prepared, claim, { nativeClosure,
    ...(evidence.kind === 'containment_all_descendants_dead' ? { processContainmentRef: containmentRef, deathEvidenceRef: evidenceRef } : { noSpawnEvidenceRef: evidenceRef }) });
  const stoppedAt = observedAt, settledAt = sampleCanonicalNow(), terminalSeq = nextJournalSequence(driver, run.id);
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-failure-v1' as const, runId: run.id, launchOpId: prepared.opId,
    attempt: prepared.attempt, preparedJournalSeq: prepared.seq, ...(claim ? { claimedJournalSeq: claim.seq } : { claimStatus: 'not_claimed' as const }),
    targetRef: prepared.target, requestRef: prepared.requestRef, grantRef: p.grantRef, dispatchId: p.dispatchId, sandboxLaunchSpecRef: p.sandboxLaunchSpecRef,
    nativeClosure, reason: 'creator_lost_before_effect_claim' as const, stoppedAt,
    instance: lifecycle.joined.execReleased ? 'setup_outcome_unavailable' as const : 'not_initialized' as const,
    ...(evidence.kind === 'containment_all_descendants_dead' ? { closure: 'containment_dead' as const, processContainmentRef: containmentRef, containmentDeathEvidenceRef: evidenceRef }
      : { closure: 'plan_quiescent' as const, noSpawnEvidenceRef: evidenceRef }) };
  const local = mcpServerFailedLaunchData({ failure: { ...core, failureDigest: canonicalSha256(core) }, prepared, claim, run, terminalSeq, settledAt });
  for (const plan of [local.failurePlan, local.settlementPlan]) metadata.push(await artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind));
  let clock: ReturnType<typeof advanceTimeFence> | undefined;
  driver.transaction(connection => {
    const current = assertActiveStateOwner(connection, owner); readInstalledMcpStdioRunCleanup(receipt, physical);
    const now = sampleCanonicalNow(); clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
    const fresh = owner.filesystem.observePriorProcessDeath(original.process.pid, original.process.processStartToken);
    history.assertUnchanged(connection); resources.assertUnchanged(connection);
    requireEqual(readRun(connection, run.id), run, 'MCP successor exact original Run/Checkpoint/Stop/budget cut');
    requireEqual(readInvocationJournal(connection, run.id), cut.journal, 'MCP successor exact original whole Journal with no ordinary effect claim');
    requireEqual(readInvocationAttempt(connection, run.id, prepared.opId, prepared.attempt), claim ? [prepared, claim] : [prepared], 'MCP successor exact original optional launch claim');
    requireEqual(readInvocationAttempt(connection, run.id, tool.opId, tool.attempt), [tool], 'MCP successor cannot settle, refund or resend the original ordinary effect');
    if (current.ownerEpoch <= original.owner.ownerEpoch || nextJournalSequence(connection, run.id) !== terminalSeq ||
        Date.parse(now) < cleanup.observedAtMs || Date.parse(now) - cleanup.observedAtMs > 5000 || fresh < cleanup.observedAtMs || fresh > Date.parse(now) || now < settledAt)
      throw new KernelStorageError('LEASE_FENCED', 'MCP unclaimed successor cleanup is not fresh in its real original terminal transaction');
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
    appendInvocationJournalEntry(connection, local.terminal);
    const changed = connection.prepare('UPDATE runs SET budget_consumed_json=?,budget_reserved_json=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?')
      .run(JSON.stringify(local.settlement.budgetConsumedAfter), JSON.stringify(local.settlement.budgetReservedAfter), now, run.id, BigInt(run.revision));
    if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'MCP successor separate launch settlement lost its original budget CAS');
    appendRunStateEvent(connection, readRun(connection, run.id), now);
  }); requireHealthyFence(clock);
  return { run: readRun(driver, run.id), entry: local.terminal };
}
