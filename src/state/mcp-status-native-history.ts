// Full purpose3 retained history. This never opens a native input, performs
// cleanup or recreates a mutex/token. Live actions retain separate owners.
import { canonicalSha256 } from '../kernel/canonical.js';
import { controlWireRecord, controlWireRef, controlWireText, assertControlWireJson } from '../kernel/control-wire-data.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { decodeMcpInitializeResult, decodeMcpToolsListResult } from '../kernel/mcp.js';
import type { McpInboundMessageData } from '../kernel/mcp-wire.js';
import type { ProcessContainment, ProcessContainmentDeathEvidenceV1, ProcessContainmentNoSpawnEvidenceV1 } from '../kernel/execution.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { decodeMcpStdioRecoveryLifecycleData, decodeMcpStdioRecoveryCleanupData } from './native-owner.js';
import { readMcpStdioCapture } from './mcp-stdio-history.js';
import { decodeMcpStatusRetirement, isMcpStatusUnavailableRetirement } from './mcp-status-proof.js';
import { projectMcpStatusResponse } from './mcp-status-protocol.js';
import type { readMcpStatusProbePreparation } from './mcp-status-preparation.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import type { SqliteDriver } from './sqlite-driver.js';

type Prepared = Awaited<ReturnType<typeof readMcpStatusProbePreparation>>;
function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export async function readMcpStatusRetirementHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, prepared: Prepared,
  reference: string, digest: string) {
  const value = decodeMcpStatusRetirement(await readCanonicalArtifact(artifacts, reference));
  if (value.retirementDigest !== digest || canonicalSha256(value) !== reference) fail('MCP status retirement changed its exact complete-byte identity');
  requireEqual(value.binding, prepared.binding, 'MCP status original exact native recovery binding');
  const bytes = await artifacts.readBoundedBytes(value.nativeClosure.lifecycleRawRef, 16_777_216), lifecycle = decodeMcpStdioRecoveryLifecycleData(bytes);
  requireEqual(await readCanonicalArtifact(artifacts, value.nativeClosure.lifecycleProjectionRef), lifecycle, 'MCP complete original recovery native bytes/hash-chain projection');
  requireEqual(lifecycle.binding, { ...prepared.inputBinding, kind: 'recovery' }, 'MCP original recovery native input birth');
  requireEqual(lifecycle.controller, prepared.preparation.controller, 'MCP recovery original actual native controller');
  requireEqual(lifecycle.originalSupervisor, prepared.preparation.originalSupervisor, 'MCP recovery original actual Supervisor process');
  const root = prepared.history.rootIdentity, native = lifecycle.joined;
  const unavailable = isMcpStatusUnavailableRetirement(value);
  const originalJoin = !('cleanupRawRef' in value.nativeClosure);
  let physical = lifecycle.retirement, inspector = prepared.original, history = prepared.history;
  if (!('cleanupRawRef' in value.nativeClosure)) {
    if (!value.joined || !native.deathJoined || !native.ownerDrained || !native.outputCustodyRetired ||
        native.execReleased !== value.joined.execReleased || native.statusReleased !== value.joined.statusReleased ||
        native.protocolCompleted !== (value.joined.completedStages.length === 4))
      fail('MCP original status closure has no complete original native custody join');
  } else {
    const domain = value.creatorProcessDomain;
    if (!domain || value.joined) fail('MCP successor cannot fabricate an original native owner join');
    const cleanupBytes = await artifacts.readBoundedBytes(value.nativeClosure.cleanupRawRef, 16_777_216), cleanup = decodeMcpStdioRecoveryCleanupData(cleanupBytes);
    requireEqual(await readCanonicalArtifact(artifacts, value.nativeClosure.cleanupProjectionRef), cleanup, 'MCP status separate real current checker native bytes/projection');
    requireEqual(cleanup.originalBinding, lifecycle.binding, 'MCP status cleanup exact original complete native input');
    requireEqual(cleanup.originalController, lifecycle.controller, 'MCP status cleanup original actual controller');
    requireEqual(cleanup.originalReservation, lifecycle.reservation, 'MCP status cleanup original reserved cgroup identity');
    history = await readRetainedStateOwnerHistory(driver, artifacts, domain.inspectorStateOwnerEpoch);
    const current = history.entries.find(entry => entry.owner.ownerEpoch === domain.inspectorStateOwnerEpoch);
    if (!current || current.owner.ownerEpoch <= prepared.original.owner.ownerEpoch || current.owner.supervisorInstanceId === prepared.original.owner.supervisorInstanceId ||
        domain.creatorProcessIdentityRef !== prepared.original.owner.processIdentityRef || domain.creatorProcessIdentityDigest !== prepared.original.owner.processIdentityDigest ||
        canonicalSha256(cleanup) !== value.nativeClosure.cleanupProjectionRef || cleanup.originalBirthDigest !== sha256Bytes(bytes) ||
        cleanup.currentChecker.stateOwnerEpoch !== current.owner.ownerEpoch || cleanup.currentChecker.supervisorInstanceId !== current.owner.supervisorInstanceId ||
        cleanup.currentChecker.supervisorPid !== current.process.pid || cleanup.currentChecker.supervisorStartToken !== current.process.processStartToken ||
        !cleanup.priorSupervisorDead || !cleanup.priorControllerDead || !cleanup.outputCustodyRetired || cleanup.remainingDescendants !== 0 ||
        cleanup.observedAtMs !== parseCanonicalTime(value.observedAt))
      fail('MCP status successor cleanup lacks its exact strictly newer checker, old birth and real creator/controller deaths');
    inspector = current; physical = cleanup.retirement;
  }
  if (canonicalSha256(lifecycle) !== value.nativeClosure.lifecycleProjectionRef || native.responseRefused !== unavailable || !physical ||
      unavailable && (lifecycle.progressKind !== 9 || !native.execReleased || !native.deathJoined || !native.ownerDrained ||
        !native.outputCustodyRetired || !lifecycle.containment || !value.processContainmentRef) ||
      physical.cgroupPopulated !== 0 || physical.remainingTrackedDescendants !== 0 ||
      physical.cgroupId !== lifecycle.reservation.cgroupInode || physical.observedAtMs !== parseCanonicalTime(value.observedAt) ||
      lifecycle.reservation.cgroupName !== `cliq-mcp-stdio-recovery-${prepared.preparation.nonce}` ||
      lifecycle.stateRootIdentity.deviceId !== root.deviceId || lifecycle.stateRootIdentity.fileId !== root.directoryFileId ||
      [lifecycle.stateRootIdentity, lifecycle.runtimeIdentity, lifecycle.privateParentIdentity, lifecycle.birthIdentity].some(identity => identity.ownerUid !== root.ownerUid))
    fail('MCP recovery retirement lacks its exact original native process, response, root and complete joined custody');
  const plan = prepared.plan, spec = prepared.spec;
  if (plan.backend.kind !== 'linux' || spec.owner.kind !== 'reconciliation_probe') fail('MCP recovery lost its exact Linux status-only plan/spec');
  const evidence = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1 | ProcessContainmentNoSpawnEvidenceV1>(artifacts, value.retirementEvidenceRef);
  if (evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest') || evidence.observedAt !== value.observedAt ||
      evidence.planRef !== prepared.preparation.plannedContainmentRef || evidence.sandboxLaunchSpecRef !== prepared.preparation.sandboxLaunchSpecRef ||
      evidence.sandboxLaunchSpecDigest !== spec.launchSpecDigest || evidence.launchNonceDigest !== plan.launchNonceDigest ||
      evidence.inspectorSupervisorInstanceId !== inspector.owner.supervisorInstanceId ||
      inspector.owner.acquiredAt > value.observedAt || inspector.owner.state === 'terminal' && inspector.owner.releasedAt < value.observedAt)
    fail('MCP recovery retirement changed its original owner, plan, actual observation time or lifetime');
  requireEqual(evidence.owner, plan.owner, 'MCP recovery death/no-spawn original exact owner');
  await readSupervisorInspector(artifacts, inspector.owner, { runtime: { runtimeBundleRef: inspector.owner.runtimeBundleRef,
    runtimeBundleManifestDigest: inspector.owner.runtimeBundleManifestDigest } }, evidence);
  let containment: ProcessContainment | undefined;
  if (value.processContainmentRef && evidence.kind === 'containment_all_descendants_dead') {
    containment = await readCanonicalArtifact<ProcessContainment>(artifacts, value.processContainmentRef);
    const birth = lifecycle.containment;
    if (!birth || containment.backend.kind !== 'linux' || evidence.backend.kind !== 'linux' || evidence.containmentRef !== value.processContainmentRef ||
        containment.planRef !== prepared.preparation.plannedContainmentRef || containment.sandboxLaunchSpecRef !== prepared.preparation.sandboxLaunchSpecRef ||
        containment.sandboxLaunchSpecDigest !== spec.launchSpecDigest || containment.launchNonceDigest !== plan.launchNonceDigest ||
        containment.backend.cgroupPath !== plan.backend.cgroupPath || containment.backend.cgroupId !== birth.cgroupId ||
        containment.backend.pidNamespaceId !== birth.pidNamespaceId || containment.backend.namespaceInitStartToken !== birth.namespaceInitStartToken ||
        containment.backend.pidNamespaceReservationId !== plan.backend.pidNamespaceReservationId || containment.backend.subreaperStartToken !== plan.backend.subreaperStartToken ||
        birth.cgroupPopulated !== 1 || birth.namespaceInitDeadAndReaped !== 0 || birth.observedAtMs !== parseCanonicalTime(containment.createdAt) ||
        physical.namespaceInitDeadAndReaped !== 1 || physical.pidNamespaceId !== birth.pidNamespaceId || physical.namespaceInitPid !== birth.namespaceInitPid ||
        physical.namespaceInitStartToken !== birth.namespaceInitStartToken || containment.createdAt < prepared.preparation.createdAt || containment.createdAt > value.observedAt)
      fail('MCP recovery original READY and retired native namespace/cgroup identities differ');
    requireEqual(containment.owner, plan.owner, 'MCP status original READY owner');
    requireEqual(containment.filesystemBinding, plan.filesystemBinding, 'MCP status original empty root binding');
    requireEqual(evidence.backend, { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
      'MCP recovery exact original all-descendant death');
  } else if (!value.processContainmentRef && evidence.kind === 'containment_plan_quiescent') {
    if (lifecycle.containment || native.spawnAttempted || native.execReleased || native.statusReleased || physical.namespaceInitPid !== 0 ||
        physical.namespaceInitDeadAndReaped !== 0 || originalJoin && lifecycle.progressKind !== 9 || evidence.backend.kind !== 'linux')
      fail('MCP status missing original READY cannot impersonate a positive no-spawn result');
    requireEqual(evidence.backend, { kind: 'linux', cgroupPath: plan.backend.cgroupPath,
      cgroupObservation: { kind: 'empty', cgroupId: physical.cgroupId, populated: 0 },
      pidNamespaceObservation: { kind: 'never_created', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId },
      subreaperStartToken: plan.backend.subreaperStartToken, matchingLaunchNonceProcessCount: 0 }, 'MCP status original real no-spawn reservation');
  } else fail('MCP recovery retirement mixed original death and no-spawn purposes');
  const bundle = await readCanonicalArtifact<import('../policy/runtime-authority.js').RuntimeBundleManifest>(artifacts, prepared.original.owner.runtimeBundleRef);
  const isolation = bundle.entries.filter(entry => entry.entryId === 'linux_bubblewrap');
  if (isolation.length !== 1 || isolation[0]!.role !== 'platform_helper' || !isolation[0]!.executable) fail('MCP recovery original signed isolation image is absent');
  const server = prepared.recipe;
  requireEqual(lifecycle.images.server, { digest: server.serverDigest, byteCount: server.serverByteCount }, 'MCP status original sealed signed server');
  const launcher = bundle.entries.filter(entry => entry.entryId === 'linux_worker_controller');
  if (launcher.length !== 1 || launcher[0]!.role !== 'platform_helper' || !launcher[0]!.executable) fail('MCP status original signed controller image is absent');
  requireEqual(lifecycle.images.client, { digest: launcher[0]!.digest, byteCount: launcher[0]!.byteCount }, 'MCP recovery original signed controller image');
  requireEqual(lifecycle.images.isolation, { digest: isolation[0]!.digest, byteCount: isolation[0]!.byteCount }, 'MCP recovery original signed isolation image');
  requireEqual(lifecycle.images.recipe, { digest: prepared.preparation.nativeRecipeRef, byteCount: prepared.recipeBytes.length }, 'MCP recovery complete original sealed recipe bytes');
  history.assertUnchanged(driver); prepared.history.assertUnchanged(driver);
  return { value, lifecycle, evidence, containment, prepared, inspector, history };
}

export function decodeMcpStatusCapture(value: unknown) {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP status original capture');
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'binding', 'captures', 'statusResponseRef', 'statusResponseDigest',
    'responseProjection', 'schemaValid', 'disposition', 'statusReceivedAt', 'retirementRef', 'retirementDigest', 'observedAt', 'captureDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-stdio-recovery-capture-v1' || data.captureDigest !== digestOmitting(data, 'captureDigest') ||
      data.statusResponseRef !== data.statusResponseDigest || typeof data.schemaValid !== 'boolean' ||
      !['structured_content', 'rpc_error', 'tool_error', 'missing_structured_content', 'malformed_result'].includes(data.responseProjection as string) ||
      !['completed', 'failed', 'unresolved'].includes(data.disposition as string) || !Array.isArray(data.captures) || data.captures.length !== 3)
    throw new TypeError('MCP signed status capture changes its closed original response/retirement graph');
  for (const key of ['statusResponseRef', 'statusResponseDigest', 'retirementRef', 'retirementDigest', 'captureDigest']) controlWireRef(data[key]);
  const phases = ['initialize', 'tools_list', 'tools_call'];
  data.captures.forEach((value, index) => {
    const entry = controlWireRecord(value, ['phase', 'captureRef']); controlWireRef(entry.captureRef);
    if (entry.phase !== phases[index]) throw new TypeError('MCP status capture repeats/substitutes a fixed response phase');
  });
  parseCanonicalTime(controlWireText(data.statusReceivedAt)); parseCanonicalTime(controlWireText(data.observedAt));
  return data;
}
export async function readMcpStatusCaptureHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, prepared: Prepared, source: Parameters<typeof projectMcpStatusResponse>[1],
  reference: string, digest: string) {
  const value = decodeMcpStatusCapture(await readCanonicalArtifact(artifacts, reference));
  if (value.captureDigest !== digest || canonicalSha256(value) !== reference) fail('MCP status capture changed its exact complete-byte identity');
  requireEqual(value.binding, prepared.binding, 'MCP status complete original response native binding');
  const retirement = await readMcpStatusRetirementHistory(driver, artifacts, prepared, value.retirementRef as string, value.retirementDigest as string);
  const joined = retirement.value.joined;
  if (!joined || joined.kind !== 'mcp_stdio_recovery_owner_joined' || retirement.value.nativeClosure.kind !== 'linux_original_join' ||
      !joined.execReleased || !joined.setupReleased || !joined.statusReleased || joined.completedStages.join(',') !== 'initialize,initialized,tools_list,tools_call' ||
      retirement.evidence.kind !== 'containment_all_descendants_dead' || value.observedAt !== retirement.value.observedAt ||
      (value.statusReceivedAt as string) < prepared.preparation.createdAt || (value.statusReceivedAt as string) > (value.observedAt as string))
    fail('MCP status result lacks its complete original protocol followed by actual process/pipe/output join');
  const responses: Array<Extract<McpInboundMessageData, { kind: 'result' | 'error' }>> = [];
  for (const descriptor of value.captures as Array<{ phase: string; captureRef: string }>) {
    const captured = await readMcpStdioCapture(artifacts, descriptor.captureRef);
    if (captured.capture.phase !== descriptor.phase) fail('MCP status raw complete capture substituted its original phase');
    responses.push(captured.decoded.response);
  }
  const [initialize, list, response] = responses;
  if (initialize?.kind !== 'result' || list?.kind !== 'result' || !response) fail('MCP status capture lost its genuine original initialization and discovery');
  const negotiation = decodeMcpInitializeResult(initialize.result), tools = decodeMcpToolsListResult(list.result);
  // The source reader already roots the original registry. The first three
  // immutable request frames and the complete captured responses must agree.
  const fullSource = await (await import('./mcp-registration.js')).readMcpRegistryClosure(driver, artifacts, prepared.binding.registryRevisionRef, prepared.binding.principalId);
  if (negotiation.initializeDigest !== fullSource.registry.initializeDigest || negotiation.capabilityDigest !== fullSource.registry.capabilityDigest ||
      canonicalSha256(tools.map(tool => tool.interface)) !== fullSource.registry.probedToolsListDigest)
    fail('MCP status response changed its original signed negotiation or complete tool interfaces');
  const projection = projectMcpStatusResponse(response, source);
  requireEqual(value.responseProjection, projection.projection, 'MCP status original raw response projection');
  requireEqual(value.schemaValid, projection.schemaValid, 'MCP status exact original output schema result');
  requireEqual(value.disposition, projection.disposition, 'MCP status exact signed predicate result');
  requireEqual(await readCanonicalArtifact(artifacts, value.statusResponseRef as string), projection.response, 'MCP status complete actual projected response');
  if (canonicalSha256(projection.response) !== value.statusResponseRef) fail('MCP status real response digest is not its complete canonical bytes');
  return { value, retirement, projection, responses };
}
