// Iterative exact original wait/probe history. It validates retained facts,
// never recursively enters Run recovery or creates native proof/authority.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeInstalledControlEnvelope, decodeInstalledControlRequest } from '../kernel/control-wire.js';
import { decodeMcpInvocationWait, decodeMcpRecoveryProbeEvidence, mcpUnresolvedProbeState, type McpInvocationWaitV1 } from '../kernel/mcp-status.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { KernelStorageError } from './errors.js';
import { readMcpStatusCaptureHistory, readMcpStatusRetirementHistory } from './mcp-status-native-history.js';
import { readMcpStatusProbePreparation } from './mcp-status-preparation.js';
import { decodeMcpStatusProbeWrapper, decodeMcpStatusProbeClosure } from './mcp-status-proof.js';
import { readMcpReconcileSource } from './mcp-status-source.js';
import { readCheckpoint, readControlRequest, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
type Source = Awaited<ReturnType<typeof readMcpReconcileSource>>;
export type McpStatusHistoryCut = Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'journal'>;
const base = ({ probeState: _state, ...value }: McpInvocationWaitV1) => value;
async function userSource(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: McpStatusHistoryCut, wait: McpInvocationWaitV1) {
  const state = wait.probeState;
  if (state.phase !== 'user_in_flight') fail('MCP user probe changed its exact user-requested phase');
  const dispatch = state.dispatch;
  if (dispatch.subjectKind !== 'mcp_recovery') fail('MCP user probe changed its exact purpose');
  const principalId = readSessionPrincipalId(driver, cut.run.sessionId);
  const row = readControlRequest(driver, principalId, 'run.reconcile', dispatch.controlRequestId);
  if (!row || row.requestDigest !== dispatch.controlRequestDigest) fail('MCP user probe lost its original authenticated enqueue');
  const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, dispatch.controlRequestDigest);
  const request = decodeInstalledControlRequest({ ...core, requestDigest: dispatch.controlRequestDigest });
  const response = decodeInstalledControlEnvelope(await readCanonicalArtifact(artifacts, row.responseRef), 'run.reconcile');
  if (request.method !== 'run.reconcile' || request.resolution.kind !== 'probe_now' || request.runId !== cut.run.id ||
      request.requestId !== dispatch.controlRequestId || request.waitingOnRef !== dispatch.previousWaitingSubjectRef || !response.ok ||
      response.result.method !== 'run.reconcile' || response.result.resolution.kind !== 'probe_enqueued' || response.result.snapshot.operation !== 'agent')
    fail('MCP user probe substituted its original public request, source or response');
  const snapshot = response.result.snapshot, run = snapshot.run;
  if (run.id !== cut.run.id || run.sessionId !== cut.run.sessionId || run.specRef !== cut.run.specRef || run.createdAt !== cut.run.createdAt ||
      run.deadlineAt !== cut.run.deadlineAt || run.revision !== request.expectedRevision + 1 || run.revision > cut.run.revision ||
      run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || run.waitingOnRef !== canonicalSha256(wait) ||
      run.updatedAt !== dispatch.probeStartedAt || row.committedAt < run.updatedAt || row.committedAt >= dispatch.probeDeadlineAt ||
      snapshot.latestRunItemSeq !== readCheckpoint(driver, run.latestCheckpointId).runItemSeq ||
      response.result.resolution.dispatchDigest !== dispatch.dispatchDigest || response.result.resolution.userProbeCount !== state.userProbeCount)
    fail('MCP user probe changed its exact durable original enqueue snapshot');
  const { channel } = await readHistoricalControlChannel(driver, artifacts, { principalId, channelIdentityRef: row.channelIdentityRef, channelIdentityDigest: row.channelIdentityDigest });
  if (channel.openedAt > row.committedAt) fail('MCP user probe original channel postdates its request commit');
  return { row, request, response };
}

/** One wrapper's source walk is separate from its native proof. Callers that
 * resolve a Journal row must additionally validate the complete wait chain. */
export async function readMcpStatusProbeEvidence(driver: SqliteDriver, artifacts: ArtifactCatalog, source: Source, reference: string, digest: string) {
  const wrapper = decodeMcpStatusProbeWrapper(await readCanonicalArtifact(artifacts, reference));
  if (wrapper.evidenceDigest !== digest || canonicalSha256(wrapper) !== reference || wrapper.runId !== source.prepared.runId)
    fail('MCP probe wrapper changed its full original artifact identity');
  const wait = decodeMcpInvocationWait(await readCanonicalArtifact(artifacts, wrapper.waitingSubjectRef)), state = wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') fail('MCP probe wrapper has no exact original persisted in-flight nonce');
  const dispatch = state.dispatch;
  if (dispatch.subjectKind !== 'mcp_recovery' || wrapper.probeKind !== dispatch.probeKind || wrapper.probeOrdinal !== dispatch.probeOrdinal ||
      wrapper.probeNonceDigest !== dispatch.probeNonceDigest || wrapper.probeDispatchDigest !== dispatch.dispatchDigest ||
      wrapper.probeStartedAt !== dispatch.probeStartedAt || wrapper.probeDeadlineAt !== dispatch.probeDeadlineAt)
    fail('MCP probe wrapper substituted another original dispatch, count, nonce or deadline');
  requireEqual(wait.subject, source.subject, 'MCP probe original signed subject');
  const prepared = await readMcpStatusProbePreparation(driver, artifacts, wait, source);
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(dispatch)), dispatch, 'MCP exact persisted original dispatch bytes');
  if (wrapper.outcome === 'subject_observation') {
    const evidence = decodeMcpRecoveryProbeEvidence(await readCanonicalArtifact(artifacts, wrapper.subjectEvidenceRef));
    if (evidence.evidenceDigest !== wrapper.subjectEvidenceDigest || evidence.runId !== wait.runId || evidence.waitingSubjectRef !== wrapper.waitingSubjectRef ||
        evidence.opId !== source.claim.opId || evidence.attempt !== source.claim.attempt || evidence.probeKind !== dispatch.probeKind ||
        evidence.probeOrdinal !== dispatch.probeOrdinal || evidence.probeNonceDigest !== dispatch.probeNonceDigest || evidence.probeDispatchDigest !== dispatch.dispatchDigest ||
        evidence.registryRevisionRef !== source.registry.ref || evidence.registryManifestDigest !== source.registry.registry.manifestDigest ||
        evidence.serverToolName !== source.original.execution.serverToolName || evidence.profileId !== source.profile.profileId || evidence.profileDigest !== source.profile.profileDigest ||
        evidence.statusRequestTemplateRef !== source.recovery.statusRequestTemplateRef || evidence.statusRequestTemplateDigest !== source.recovery.statusRequestTemplateDigest ||
        evidence.statusRequestDigest !== source.statusRequest.digest || evidence.brokerDispatchId !== dispatch.brokerDispatchId || evidence.brokerTargetDigest !== dispatch.brokerTargetDigest ||
        evidence.completedPredicateRef !== source.recovery.completedPredicateRef || evidence.completedPredicateDigest !== source.recovery.completedPredicateDigest ||
        evidence.failedPredicateRef !== source.recovery.failedPredicateRef || evidence.failedPredicateDigest !== source.recovery.failedPredicateDigest || evidence.observedAt !== wrapper.observedAt)
      fail('MCP status evidence substituted its exact original signed profile, actual probe or observation');
    const capture = await readMcpStatusCaptureHistory(driver, artifacts, prepared, source, evidence.statusCaptureRef, evidence.statusCaptureDigest);
    if (capture.value.statusResponseRef !== evidence.statusResponseRef || capture.value.statusResponseDigest !== evidence.statusResponseDigest ||
        capture.value.observedAt !== evidence.observedAt || capture.value.disposition !== evidence.disposition ||
        wrapper.inspectorIdentityRef !== capture.retirement.evidence.inspectorIdentityRef || wrapper.inspectorIdentityDigest !== capture.retirement.evidence.inspectorIdentityDigest)
      fail('MCP signed status wrapper lost its original complete response, real joined inspector or exact predicate outcome');
    return { wrapper, wait, prepared, source, evidence, capture, retirement: capture.retirement,
      closure: undefined, lateCapture: undefined, reason: 'observation' as const };
  }
  const cancellation = wrapper.outcome === 'probe_cancelled';
  const closure = decodeMcpStatusProbeClosure(await readCanonicalArtifact(artifacts, cancellation ? wrapper.cancellationClosureRef : wrapper.timeoutClosureRef));
  const closureDigest = cancellation ? wrapper.cancellationClosureDigest : wrapper.timeoutClosureDigest;
  if (closure.closureDigest !== closureDigest || closure.runId !== wait.runId || closure.waitingSubjectRef !== wrapper.waitingSubjectRef ||
      closure.probeKind !== dispatch.probeKind || closure.probeOrdinal !== dispatch.probeOrdinal || closure.probeNonceDigest !== dispatch.probeNonceDigest ||
      closure.probeDispatchDigest !== dispatch.dispatchDigest || closure.probeDeadlineAt !== dispatch.probeDeadlineAt || closure.closedAt !== wrapper.observedAt ||
      closure.inspectorIdentityRef !== wrapper.inspectorIdentityRef || closure.inspectorIdentityDigest !== wrapper.inspectorIdentityDigest ||
      closure.brokerDispatchId !== dispatch.brokerDispatchId || closure.brokerTargetDigest !== dispatch.brokerTargetDigest || closure.brokerFenceTokenDigest !== dispatch.brokerFenceTokenDigest ||
      (closure.format === 'cliq-reconciliation-probe-cancellation-closure-v1') !== cancellation)
    fail('MCP closure changed its original native status nonce or inspector');
  const retirement = await readMcpStatusRetirementHistory(driver, artifacts, prepared, closure.retirementRef, closure.retirementDigest);
  if (cancellation && retirement.value.nativeClosure.kind !== 'linux_original_join')
    fail('MCP successor cleanup cannot impersonate the original owning shutdown cancellation');
  if (retirement.value.observedAt > closure.closedAt || retirement.evidence.inspectorIdentityRef !== closure.inspectorIdentityRef ||
      retirement.evidence.inspectorIdentityDigest !== closure.inspectorIdentityDigest)
    fail('MCP probe closed before its genuine original process/pipe/native retirement');
  let lateCapture: Awaited<ReturnType<typeof readMcpStatusCaptureHistory>> | undefined;
  if (closure.lateStatusCaptureRef) {
    lateCapture = await readMcpStatusCaptureHistory(driver, artifacts, prepared, source, closure.lateStatusCaptureRef, closure.lateStatusCaptureDigest!);
    if (lateCapture.value.retirementRef !== closure.retirementRef || lateCapture.value.retirementDigest !== closure.retirementDigest ||
        (lateCapture.value.observedAt as string) > closure.closedAt)
      fail('MCP late audit attempted to borrow another nonce retirement or future result');
  }
  return { wrapper, wait, prepared, source, evidence: undefined, capture: undefined, closure, retirement, lateCapture,
    reason: cancellation ? 'shutdown_cancel' as const : 'timeout' as const };
}

export async function readMcpStatusWaitHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: McpStatusHistoryCut, value: McpInvocationWaitV1) {
  const wait = decodeMcpInvocationWait(value), entries = cut.journal.filter(entry => entry.opId === wait.subject.opId && entry.attempt === wait.subject.attempt), unknown = entries[2];
  if (!unknown || unknown.phase !== 'unknown') fail('MCP status history lost its one original settled UNKNOWN');
  // A later signed resolution does not replace the immutable original source
  // triple, and remains independently validated by its dedicated reader.
  const originalCut = { ...cut, journal: cut.journal.filter(entry => entry.opId !== wait.subject.opId || entry.attempt !== wait.subject.attempt || entry.seq <= unknown.seq) };
  const source = await readMcpReconcileSource(driver, artifacts, originalCut, wait.subject.opId, wait.subject.attempt);
  if (wait.runId !== cut.run.id || wait.frontierRef !== source.original.request.frontierRef || wait.createdAt < unknown.timestamp ||
      wait.createdAt > cut.run.updatedAt || wait.createdFromRevision >= cut.run.revision) fail('MCP retained wait changed its original Run, frontier, time or revision');
  requireEqual(wait.subject, source.subject, 'MCP retained original signed reconciliation subject');
  const seen = new Set<string>(); let cursor = wait;
  for (;;) {
    artifacts.assertReadActive(); const reference = canonicalSha256(cursor);
    if (seen.has(reference)) fail('MCP original wait history contains a cycle'); seen.add(reference);
    requireEqual(base(cursor), base(wait), 'MCP exact immutable original waiting subject history');
    const state = cursor.probeState;
    if (state.phase === 'automatic_pending' && state.automaticProbeCount === 0) {
      if (state.nextProbeAt !== cursor.createdAt) fail('MCP initial original automatic wait changed its due time');
      return { wait, source, history: seen };
    }
    if (state.phase === 'automatic_in_flight' || state.phase === 'user_in_flight') {
      const prepared = await readMcpStatusProbePreparation(driver, artifacts, cursor, source);
      requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(state.dispatch)), state.dispatch, 'MCP full original persisted dispatch');
      if (state.phase === 'user_in_flight') await userSource(driver, artifacts, cut, cursor);
      cursor = prepared.previous; continue;
    }
    const proof = await readMcpStatusProbeEvidence(driver, artifacts, source, state.lastProbeEvidenceRef, state.lastProbeEvidenceDigest);
    if (proof.wrapper.outcome === 'subject_observation' && proof.evidence?.disposition !== 'unresolved')
      fail('MCP known signed effect outcome cannot be rewritten as another unresolved wait');
    requireEqual(base(proof.wait), base(cursor), 'MCP unresolved evidence original immutable wait');
    requireEqual(state, mcpUnresolvedProbeState(proof.wait, state.lastProbeEvidenceRef, state.lastProbeEvidenceDigest, proof.wrapper.observedAt, proof.reason),
      'MCP exact original bounded probe counts, thirty second deadline and backoff');
    cursor = proof.wait;
  }
}
