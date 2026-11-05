// The sole persisted admission of a signed read-only status nonce. Native
// input birth happens only after this transaction, never from retained data.
import { randomBytes } from 'node:crypto';
import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, identityHash, sha256Bytes } from '../kernel/identity.js';
import { decodeInstalledControlEnvelope, decodeInstalledControlRequest, type RunReconcileRequestV1 } from '../kernel/control-wire.js';
import { decodeMcpInvocationWait, decodeMcpStatusProbePreparation } from '../kernel/mcp-status.js';
import type { Run } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { assertLinuxWorkerController, type LinuxWorkerController } from '../sandbox/linux-worker.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodePlatformProcessIdentity } from './decoders.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { withHeldInstalledRuntime, withInstalledWorkerRoot, type HeldInstalledRuntime, type HeldInstalledAnchor } from './installed-runtime.js';
import type { NativeMcpStdioRecoveryOwner } from './mcp-stdio-broker-native.js';
import { readInstalledMcpStdioRecipeData } from './mcp-stdio-native-binding.js';
import { decodeMcpStdioRecipeData } from './mcp-stdio-recipe.js';
import { assertMcpStdioRecipeData } from './mcp-stdio-recipe-audit.js';
import { publishMcpStdioLaunch } from './mcp-stdio-launch.js';
import { mcpReadonlyStatusRequestData } from './mcp-status-source.js';
import { mcpStatusProbeBinding } from './mcp-status-preparation.js';
import { validateMcpInvocationWait } from './mcp-status-state.js';
import { readReconciliationProbeCapacity } from './reconciliation-capacity.js';
import { readInvocationJournal } from './repositories/journal.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { insertControlRequest, readControlRequest, readRun, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

export type McpStatusUserMutation = Readonly<{ request: RunReconcileRequestV1; identity: AuthenticatedControlIdentity }>;
function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
const revision = (actual: number, expected: number) => {
  if (!Number.isSafeInteger(expected) || expected < 1) throw new KernelStorageError('INVALID_REQUEST', 'MCP status requires its exact positive revision');
  if (actual !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'MCP status original Run revision changed');
};
function decodeMutation(value: McpStatusUserMutation): McpStatusUserMutation {
  const request = decodeInstalledControlRequest(value.request);
  if (request.method !== 'run.reconcile' || request.resolution.kind !== 'probe_now')
    throw new KernelStorageError('INVALID_REQUEST', 'MCP signed status accepts only the existing probe_now mutation');
  return Object.freeze({ request, identity: value.identity });
}

/** Replay returns the original durable enqueue response, without creating a
 * native job or replacing the old nonce even when its probe has since closed. */
export const replayMcpStatusProbe = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, value: McpStatusUserMutation) => {
  const mutation = decodeMutation(value); assertCurrentControlFrame(owner, mutation.identity); assertActiveStateOwner(driver, owner);
  await validateControlChannelClosure(artifacts, owner, mutation.identity);
  const row = readControlRequest(driver, mutation.identity.principalId, 'run.reconcile', mutation.request.requestId);
  if (!row) return undefined;
  if (row.requestDigest !== mutation.request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'MCP status requestId was reused');
  const run = readRun(driver, mutation.request.runId);
  if (readSessionPrincipalId(driver, run.sessionId) !== mutation.identity.principalId) throw new KernelStorageError('NOT_FOUND', 'MCP status Run is unavailable');
  const response = decodeInstalledControlEnvelope(await readCanonicalArtifact(artifacts, row.responseRef), 'run.reconcile');
  if (!response.ok || response.result.method !== 'run.reconcile' || response.result.snapshot.operation !== 'agent' ||
      response.result.snapshot.run.id !== run.id || !response.result.snapshot.run.waitingOnRef || response.result.resolution.kind !== 'probe_enqueued')
    fail('MCP status replay lost its original exact durable enqueue response');
  const wait = decodeMcpInvocationWait(await readCanonicalArtifact(artifacts, response.result.snapshot.run.waitingOnRef));
  const state = wait.probeState;
  if (state.phase !== 'user_in_flight' || state.dispatch.subjectKind !== 'mcp_recovery' ||
      state.dispatch.controlRequestId !== mutation.request.requestId || state.dispatch.controlRequestDigest !== mutation.request.requestDigest ||
      state.dispatch.dispatchDigest !== response.result.resolution.dispatchDigest || state.userProbeCount !== response.result.resolution.userProbeCount)
    fail('MCP status replay substituted another original authenticated nonce');
  const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, artifacts, run.id);
  await (await import('./mcp-status-history.js')).readMcpStatusWaitHistory(driver, artifacts, cut, wait);
  assertActiveStateOwner(driver, owner); assertCurrentControlFrame(owner, mutation.identity);
  requireEqual(readRun(driver, run.id), cut.run, 'MCP status replay current complete Run');
  return immutableSnapshot({ response, replayed: true as const });
});

export const beginMcpStatusProbe = stateOperation('RECOVERY_REQUIRED', async (driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: Readonly<{ runId: string; expectedRunRevision: number; probeStartedAt: string;
    native: NativeMcpStdioRecoveryOwner; selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor; controller: LinuxWorkerController;
    signal: AbortSignal; mutation?: McpStatusUserMutation }>) => {
  const reads = artifacts.withReadSignal(input.signal); reads.assertReadActive(); assertActiveStateOwner(driver, owner);
  const mutation = input.mutation && decodeMutation(input.mutation);
  if (mutation && await replayMcpStatusProbe(driver, reads, owner, mutation))
    throw new KernelStorageError('REVISION_CONFLICT', 'MCP status request already has an original persisted nonce');
  const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, reads, input.runId);
  const selected = await validateMcpInvocationWait(driver, reads, cut), { run, wait, source } = selected;
  revision(run.revision, input.expectedRunRevision);
  const state = wait.probeState, at = input.probeStartedAt;
  if (at < run.updatedAt || at < wait.createdAt) fail('MCP status native preparation regressed its original current wait time');
  const channel = mutation ? await validateControlChannelClosure(reads, owner, mutation.identity) : undefined;
  if (mutation) {
    const request = mutation.request;
    assertCurrentControlFrame(owner, mutation.identity);
    if (readSessionPrincipalId(driver, run.sessionId) !== mutation.identity.principalId) throw new KernelStorageError('NOT_FOUND', 'MCP status Run is unavailable');
    if (request.runId !== run.id || request.expectedRevision !== input.expectedRunRevision || request.waitingOnRef !== run.waitingOnRef ||
        state.phase !== 'automatic_exhausted' || !Number.isSafeInteger(state.userProbeCount + 1))
      throw new KernelStorageError('INVALID_REQUEST', 'MCP probe_now requires its exact exhausted original wait');
  } else if (state.phase !== 'automatic_pending' || at < state.nextProbeAt)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP automatic signed status is not due or already in flight');
  const automatic = !mutation, ordinal = state.phase === 'automatic_pending' ? state.automaticProbeCount + 1 :
    state.phase === 'automatic_exhausted' ? state.userProbeCount + 1 : 0;
  const probeKind = automatic ? 'automatic' as const : 'user_requested' as const;
  const nonce = randomBytes(32).toString('hex'), probeNonceDigest = sha256Bytes(Buffer.from(nonce)), deadline = addCanonicalDuration(at, 30_000);
  const brokerDispatchId = identityHash('cliq-mcp-readonly-status-dispatch-v1', run.id, canonicalSha256(source.subject), probeKind, ordinal, probeNonceDigest);
  const request = mcpReadonlyStatusRequestData(source, { previousWaitingSubjectRef: run.waitingOnRef!, wait, probeKind, probeOrdinal: ordinal,
    probeNonceDigest, probeStartedAt: at, probeDeadlineAt: deadline, supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch });
  assertLinuxWorkerController(input.controller);
  const runtime = await withHeldInstalledRuntime(input.selected, async held => { await held.revalidate(input.signal); return held.bundle; }, input.signal);
  requireEqual(runtime, source.bundle, 'MCP status original signed installed runtime');
  const resources = decodeSandboxProfile(await readCanonicalArtifact(reads, source.spec.sandboxProfileRef)).resources;
  let cgroupParent = ''; withInstalledWorkerRoot(input.selected, input.anchor, (_fd, root) => { cgroupParent = root; });
  const originalSupervisor = decodePlatformProcessIdentity(await readCanonicalArtifact(reads, owner.processIdentityRef));
  const processOwner = { kind: 'reconciliation_probe' as const, runId: run.id, principalId: source.original.principalId,
    originalOpId: source.claim.opId, originalAttempt: source.claim.attempt, originalDispatchId: source.claim.dispatchId!,
    previousWaitingSubjectRef: run.waitingOnRef!, probeKind, probeOrdinal: ordinal, probeNonceDigest, brokerDispatchId,
    supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch };
  const launch = await publishMcpStdioLaunch(reads, { purpose: { kind: 'recovery', owner: processOwner,
    requestRef: request.requestArtifact.ref, requestDigest: request.request.requestDigest, targetRef: request.targetArtifact.ref, targetDigest: request.target.targetDigest },
    bundle: runtime, controller: input.controller, cgroupParent, lock: owner.filesystem, executable: source.executable, nonce, createdAt: at, resources });
  // This private friend rejects structural native objects before observing
  // their token and verifies the complete fixed purpose3 recipe itself.
  const recipeBytes = readInstalledMcpStdioRecipeData(input.native), recipe = decodeMcpStdioRecipeData(recipeBytes);
  assertMcpStdioRecipeData(recipe, { purpose: 'recovery', transport: source.transport, serverByteCount: launch.serverEntry.byteCount, resources,
    effectServerToolName: source.original.execution.serverToolName, statusOperationName: source.template.statusOperationName, arguments: source.argumentsValue });
  const recipeArtifact = await artifacts.publishBytes(recipeBytes, 'application/octet-stream', 'cliq-mcp-stdio-native-recipe-bytes-v1');
  const core = { schemaVersion: 1 as const, format: 'cliq-mcp-status-probe-preparation-v1' as const, runId: run.id, principalId: source.original.principalId,
    previousWaitingSubjectRef: run.waitingOnRef!, reconciliationSubjectDigest: canonicalSha256(source.subject), probeKind, probeOrdinal: ordinal,
    probeNonceDigest, nonce, brokerDispatchId, brokerFenceTokenDigest: input.native.releaseFenceTokenDigest,
    brokerRequestRef: request.requestArtifact.ref, brokerRequestDigest: request.request.requestDigest, brokerTargetRef: request.targetArtifact.ref,
    brokerTargetDigest: request.target.targetDigest, nativeRecipeRef: recipeArtifact.ref, plannedContainmentRef: launch.planArtifact.ref,
    plannedContainmentDigest: launch.plan.planDigest, sandboxLaunchSpecRef: launch.specArtifact.ref, sandboxLaunchSpecDigest: launch.spec.launchSpecDigest,
    inspectorSupervisorInstanceId: owner.supervisorInstanceId, inspectorStateOwnerEpoch: owner.ownerEpoch,
    originalSupervisor: { pid: originalSupervisor.pid, processStartToken: originalSupervisor.processStartToken },
    controller: { pid: input.controller.pid, processStartToken: input.controller.processStartToken }, createdAt: at, probeDeadlineAt: deadline };
  const preparation = decodeMcpStatusProbePreparation({ ...core, preparationDigest: canonicalSha256(core) });
  const preparationArtifact = await artifacts.publishCanonical(preparation, preparation.format);
  const dispatchCore = { schemaVersion: 1 as const, format: 'cliq-reconciliation-probe-dispatch-v1' as const, runId: run.id,
    reconciliationSubjectDigest: core.reconciliationSubjectDigest, probeKind, probeOrdinal: ordinal, probeNonceDigest, probeStartedAt: at,
    probeDeadlineAt: deadline, owningSupervisorInstanceId: owner.supervisorInstanceId, subjectKind: 'mcp_recovery' as const,
    brokerDispatchId, brokerRequestDigest: core.brokerRequestDigest, brokerTargetDigest: core.brokerTargetDigest, brokerFenceTokenDigest: core.brokerFenceTokenDigest,
    previousWaitingSubjectRef: run.waitingOnRef!, preparationRef: preparationArtifact.ref, preparationDigest: preparation.preparationDigest,
    ...(mutation ? { controlRequestId: mutation.request.requestId, controlRequestDigest: mutation.request.requestDigest } : {}) };
  const dispatch = { ...dispatchCore, dispatchDigest: canonicalSha256(dispatchCore) };
  const nextWait = decodeMcpInvocationWait({ ...wait, probeState: automatic
    ? { phase: 'automatic_in_flight', automaticProbeCount: ordinal, userProbeCount: 0, dispatch }
    : { phase: 'user_in_flight', automaticProbeCount: 8, userProbeCount: ordinal, dispatch } });
  const metadata: PublishedArtifact[] = [...launch.metadata, recipeArtifact, preparationArtifact, ...(channel?.metadata ?? []),
    ...await reads.mapReads([request.statusRequest, request.targetArtifact, request.requestArtifact], plan => artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind)),
    await artifacts.publishCanonical(dispatch, dispatch.format), await artifacts.publishCanonical(nextWait, 'cliq-waiting-subject-v1')];
  const nextRun: Run = { ...run, waitingOnRef: canonicalSha256(nextWait), revision: run.revision + 1, updatedAt: at };
  const response = mutation ? { protocolVersion: 1 as const, ok: true as const, result: { method: 'run.reconcile' as const,
    snapshot: { schemaVersion: 1 as const, operation: 'agent' as const, run: nextRun, latestRunItemSeq: cut.items.length },
    resolution: { kind: 'probe_enqueued' as const, dispatchDigest: dispatch.dispatchDigest, userProbeCount: ordinal } } } : undefined;
  const responseArtifact = response && await artifacts.publishCanonical(response, 'cliq-control-response-v1');
  if (mutation) {
    const { requestDigest: _digest, ...requestCore } = mutation.request;
    const artifact = await artifacts.publishCanonical(requestCore, 'cliq-run-reconcile-request-core-v1');
    if (artifact.ref !== mutation.request.requestDigest) fail('MCP status original control request bytes changed');
    metadata.push(artifact, responseArtifact!);
  }
  const capacity = await readReconciliationProbeCapacity(driver, reads);
  let outcome: TimeFenceAdvance | undefined;
  driver.transaction(connection => {
    reads.assertReadActive(); assertActiveStateOwner(connection, owner);
    requireEqual(readRun(connection, run.id), run, 'MCP status original dispatch Run');
    requireEqual(readInvocationJournal(connection, run.id), cut.journal, 'MCP status original dispatch Journal');
    source.registry.assertUnchanged(connection); source.original.history.assertUnchanged(connection); capacity.assertAvailable(connection);
    if (mutation) {
      assertCurrentControlFrame(owner, mutation.identity);
      if (readControlRequest(connection, mutation.identity.principalId, 'run.reconcile', mutation.request.requestId))
        throw new KernelStorageError('REVISION_CONFLICT', 'MCP status request already committed');
    }
    const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    if (now < at || now >= deadline) fail('MCP status original native probe expired or regressed before dispatch commit');
    for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
    connection.prepare('UPDATE runs SET waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?').run(nextRun.waitingOnRef!, at, run.id);
    requireEqual(readRun(connection, run.id), nextRun, 'MCP status committed exact nonce'); appendRunStateEvent(connection, nextRun, at);
    if (mutation) insertControlRequest(connection, { principalId: mutation.identity.principalId, method: 'run.reconcile', requestId: mutation.request.requestId,
      requestDigest: mutation.request.requestDigest, channelIdentityRef: mutation.identity.channelIdentityRef,
      channelIdentityDigest: mutation.identity.channelIdentityDigest, responseRef: responseArtifact!.ref, committedAt: now });
  });
  requireHealthyFence(outcome);
  const binding = mcpStatusProbeBinding(source, nextWait, preparation);
  const assertCurrent = (connection: SqliteConnection | SqliteDriver = driver) => {
    reads.assertReadActive(); assertActiveStateOwner(connection, owner);
    requireEqual(readRun(connection, run.id), nextRun, 'MCP status exact original current nonce Run');
    requireEqual(readInvocationJournal(connection, run.id), cut.journal, 'MCP status exact original current nonce Journal');
    source.registry.assertUnchanged(connection); source.original.history.assertUnchanged(connection);
    if (sampleCanonicalNow() >= deadline) throw new KernelStorageError('LEASE_FENCED', 'MCP status original thirty second nonce elapsed');
  };
  return { cut: { ...cut, run: nextRun }, run: nextRun, wait: nextWait, source, preparation, launch, resources, metadata, ...binding, assertCurrent, response };
});
