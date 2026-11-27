// Closed status-inspection data. Decoding cannot create a native probe,
// resolve an effect, close a nonce or grant an executable capability.
import { canonicalSha256 } from './canonical.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from './identity.js';
import { assertBoundedJsonValue } from './json.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import type { ReconciliationProbeDispatchV1, ReconciliationProbeStateV1 } from './reconciliation.js';
import { immutableSnapshot } from '../model/immutable.js';

export type McpReconciliationSubject = Readonly<{
  kind: 'invocation'; recovery: 'mcp_reconcile'; opKind: 'mcp'; opId: string; attempt: number;
  registryRevisionRef: string; registryManifestDigest: string; serverToolName: string; profileId: string; profileDigest: string;
  statusRequestTemplateRef: string; statusRequestTemplateDigest: string;
  completedPredicateRef: string; completedPredicateDigest: string; failedPredicateRef: string; failedPredicateDigest: string;
}>;
export type McpInvocationWaitV1 = Readonly<{
  schemaVersion: 1; kind: 'reconciliation'; runId: string; createdFromRevision: number; createdAt: string;
  frontierRef: string; subject: McpReconciliationSubject; probeState: Exclude<ReconciliationProbeStateV1, { phase: 'manual_only' }>;
}>;
export type McpRecoveryProbeEvidenceV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-recovery-probe-evidence-v1'; runId: string; waitingSubjectRef: string;
  opId: string; attempt: number; probeKind: 'automatic' | 'user_requested'; probeOrdinal: number;
  probeNonceDigest: string; probeDispatchDigest: string; registryRevisionRef: string; registryManifestDigest: string;
  serverToolName: string; profileId: string; profileDigest: string; statusRequestTemplateRef: string; statusRequestTemplateDigest: string;
  statusRequestDigest: string; brokerDispatchId: string; brokerTargetDigest: string;
  statusResponseRef: string; statusResponseDigest: string; statusCaptureRef: string; statusCaptureDigest: string;
  completedPredicateRef: string; completedPredicateDigest: string; failedPredicateRef: string; failedPredicateDigest: string;
  disposition: 'completed' | 'failed' | 'unresolved'; observedAt: string; evidenceDigest: string;
}>;
export type McpReconciledEffectResultV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-reconciled-effect-result-v1'; runId: string; opId: string; attempt: number;
  originalDispatchId: string; unknownJournalSeq: number; budgetSettlementRef: string;
  probeEvidenceRef: string; probeEvidenceDigest: string; originalResponse: 'unavailable'; observedAt: string; resultDigest: string;
}> & (Readonly<{ disposition: 'completed'; code: 'TOOL_RESULT_UNAVAILABLE'; effect: 'confirmed_completed' }> |
  Readonly<{ disposition: 'failed'; code: 'TOOL_EXECUTION_FAILED'; effect: 'confirmed_failed' }>);
/** Original source intent before the in-flight wait. It contains no later
 * wait ref or dispatch digest, and is never native birth/execution proof. */
export type McpStatusProbePreparationV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-status-probe-preparation-v1'; runId: string; principalId: string;
  previousWaitingSubjectRef: string; reconciliationSubjectDigest: string; probeKind: 'automatic' | 'user_requested'; probeOrdinal: number;
  probeNonceDigest: string; nonce: string; brokerDispatchId: string; brokerFenceTokenDigest: string;
  brokerRequestRef: string; brokerRequestDigest: string; brokerTargetRef: string; brokerTargetDigest: string; nativeRecipeRef: string;
  plannedContainmentRef: string; plannedContainmentDigest: string; sandboxLaunchSpecRef: string; sandboxLaunchSpecDigest: string;
  inspectorSupervisorInstanceId: string; inspectorStateOwnerEpoch: number;
  originalSupervisor: Readonly<{ pid: number; processStartToken: string }>;
  controller: Readonly<{ pid: number; processStartToken: string }>;
  createdAt: string; probeDeadlineAt: string; preparationDigest: string;
}>;
const subjectKeys = ['kind', 'recovery', 'opKind', 'opId', 'attempt', 'registryRevisionRef', 'registryManifestDigest', 'serverToolName',
  'profileId', 'profileDigest', 'statusRequestTemplateRef', 'statusRequestTemplateDigest', 'completedPredicateRef', 'completedPredicateDigest',
  'failedPredicateRef', 'failedPredicateDigest'] as const;
function json(value: unknown) { assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP status data'); }
function refMembers(data: Record<string, unknown>) {
  for (const [key, value] of Object.entries(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(value);
}
export function decodeMcpReconciliationSubject(value: unknown): McpReconciliationSubject {
  json(value); const data = controlWireRecord(value, subjectKeys);
  if (data.kind !== 'invocation' || data.recovery !== 'mcp_reconcile' || data.opKind !== 'mcp') throw new TypeError('foreign MCP recovery subject');
  for (const name of ['opId', 'serverToolName', 'profileId']) controlWireText(data[name]);
  controlWireInteger(data.attempt); refMembers(data);
  return immutableSnapshot(data) as McpReconciliationSubject;
}
function decodeDispatch(value: unknown, wait: Record<string, unknown>, kind: 'automatic' | 'user_requested', ordinal: number) {
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'reconciliationSubjectDigest', 'probeKind', 'probeOrdinal',
    'probeNonceDigest', 'probeStartedAt', 'probeDeadlineAt', 'owningSupervisorInstanceId', 'dispatchDigest', 'subjectKind',
    'brokerDispatchId', 'brokerRequestDigest', 'brokerTargetDigest', 'brokerFenceTokenDigest', 'previousWaitingSubjectRef', 'preparationRef', 'preparationDigest',
    ...(kind === 'user_requested' ? ['controlRequestId', 'controlRequestDigest'] : [])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-reconciliation-probe-dispatch-v1' || data.subjectKind !== 'mcp_recovery' ||
      data.runId !== wait.runId || data.reconciliationSubjectDigest !== canonicalSha256(wait.subject) || data.probeKind !== kind || data.probeOrdinal !== ordinal ||
      parseCanonicalTime(controlWireText(data.probeDeadlineAt)) - parseCanonicalTime(controlWireText(data.probeStartedAt)) !== 30_000 ||
      data.dispatchDigest !== digestOmitting(data, 'dispatchDigest')) throw new TypeError('MCP recovery dispatch changes its original subject/nonce/deadline');
  for (const name of ['runId', 'owningSupervisorInstanceId', 'brokerDispatchId']) controlWireText(data[name]);
  if (kind === 'user_requested') controlWireText(data.controlRequestId);
  refMembers(data); return data as unknown as ReconciliationProbeDispatchV1;
}
export function decodeMcpInvocationWait(value: unknown): McpInvocationWaitV1 {
  json(value); const data = controlWireRecord(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject', 'probeState']);
  if (data.schemaVersion !== 1 || data.kind !== 'reconciliation') throw new TypeError('foreign MCP recovery wait');
  controlWireText(data.runId); controlWireInteger(data.createdFromRevision, 1); parseCanonicalTime(controlWireText(data.createdAt)); controlWireRef(data.frontierRef);
  decodeMcpReconciliationSubject(data.subject);
  const phase = (data.probeState as { phase?: unknown } | null)?.phase, pending = phase === 'automatic_pending', exhausted = phase === 'automatic_exhausted';
  const automatic = phase === 'automatic_in_flight', user = phase === 'user_in_flight';
  if (!pending && !exhausted && !automatic && !user) throw new TypeError('MCP reconcile wait cannot borrow a manual or foreign probe state');
  const count = (data.probeState as { automaticProbeCount?: unknown }).automaticProbeCount;
  const state = controlWireRecord(data.probeState, ['phase', 'automaticProbeCount', 'userProbeCount', ...(pending ? ['nextProbeAt'] : []),
    ...(automatic || user ? ['dispatch'] : []), ...(exhausted || pending && count !== 0 ? ['lastProbeEvidenceRef', 'lastProbeEvidenceDigest'] : [])]);
  controlWireInteger(state.automaticProbeCount, pending ? 0 : 1, pending ? 7 : 8);
  controlWireInteger(state.userProbeCount, user ? 1 : 0);
  if ((pending || automatic) && state.userProbeCount !== 0 || (exhausted || user) && state.automaticProbeCount !== 8)
    throw new TypeError('MCP recovery cannot reset original automatic/user probe counts');
  if (pending) parseCanonicalTime(controlWireText(state.nextProbeAt)); refMembers(state);
  if (automatic || user) decodeDispatch(state.dispatch, data, automatic ? 'automatic' : 'user_requested',
    (automatic ? state.automaticProbeCount : state.userProbeCount) as number);
  return immutableSnapshot(data) as McpInvocationWaitV1;
}
export function decodeMcpRecoveryProbeEvidence(value: unknown): McpRecoveryProbeEvidenceV1 {
  json(value); const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'opId', 'attempt', 'probeKind', 'probeOrdinal',
    'probeNonceDigest', 'probeDispatchDigest', 'registryRevisionRef', 'registryManifestDigest', 'serverToolName', 'profileId', 'profileDigest',
    'statusRequestTemplateRef', 'statusRequestTemplateDigest', 'statusRequestDigest', 'brokerDispatchId', 'brokerTargetDigest', 'statusResponseRef',
    'statusResponseDigest', 'statusCaptureRef', 'statusCaptureDigest', 'completedPredicateRef', 'completedPredicateDigest', 'failedPredicateRef',
    'failedPredicateDigest', 'disposition', 'observedAt', 'evidenceDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-recovery-probe-evidence-v1' ||
      !['automatic', 'user_requested'].includes(data.probeKind as string) || !['completed', 'failed', 'unresolved'].includes(data.disposition as string) ||
      data.statusResponseRef !== data.statusResponseDigest || data.evidenceDigest !== digestOmitting(data, 'evidenceDigest')) throw new TypeError('MCP status evidence has a foreign purpose, outcome or digest');
  for (const name of ['runId', 'opId', 'serverToolName', 'profileId', 'brokerDispatchId']) controlWireText(data[name]);
  controlWireInteger(data.attempt); controlWireInteger(data.probeOrdinal, 1, data.probeKind === 'automatic' ? 8 : Number.MAX_SAFE_INTEGER);
  parseCanonicalTime(controlWireText(data.observedAt)); refMembers(data); return immutableSnapshot(data) as McpRecoveryProbeEvidenceV1;
}
export function decodeMcpReconciledEffectResult(value: unknown): McpReconciledEffectResultV1 {
  json(value); const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'originalDispatchId', 'unknownJournalSeq',
    'budgetSettlementRef', 'probeEvidenceRef', 'probeEvidenceDigest', 'disposition', 'originalResponse', 'code', 'effect', 'observedAt', 'resultDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-reconciled-effect-result-v1' || data.originalResponse !== 'unavailable' ||
      (data.disposition === 'completed' ? data.effect !== 'confirmed_completed' || data.code !== 'TOOL_RESULT_UNAVAILABLE'
        : data.disposition !== 'failed' || data.effect !== 'confirmed_failed' || data.code !== 'TOOL_EXECUTION_FAILED') ||
      data.resultDigest !== digestOmitting(data, 'resultDigest')) throw new TypeError('MCP signed status cannot invent the original response or relabel its confirmed outcome');
  for (const name of ['runId', 'opId', 'originalDispatchId']) controlWireText(data[name]);
  controlWireInteger(data.attempt); controlWireInteger(data.unknownJournalSeq, 1); parseCanonicalTime(controlWireText(data.observedAt)); refMembers(data);
  return immutableSnapshot(data) as McpReconciledEffectResultV1;
}

export function decodeMcpStatusProbePreparation(value: unknown): McpStatusProbePreparationV1 {
  json(value); const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'principalId', 'previousWaitingSubjectRef',
    'reconciliationSubjectDigest', 'probeKind', 'probeOrdinal', 'probeNonceDigest', 'nonce', 'brokerDispatchId', 'brokerFenceTokenDigest',
    'brokerRequestRef', 'brokerRequestDigest', 'brokerTargetRef', 'brokerTargetDigest', 'nativeRecipeRef', 'plannedContainmentRef', 'plannedContainmentDigest',
    'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'inspectorSupervisorInstanceId', 'inspectorStateOwnerEpoch', 'originalSupervisor',
    'controller', 'createdAt', 'probeDeadlineAt', 'preparationDigest']);
  const nonce = controlWireText(data.nonce, 64, 64);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-status-probe-preparation-v1' || !['automatic', 'user_requested'].includes(data.probeKind as string) ||
      parseCanonicalTime(controlWireText(data.probeDeadlineAt)) - parseCanonicalTime(controlWireText(data.createdAt)) !== 30_000 ||
      !/^[0-9a-f]{64}$/u.test(nonce) || data.probeNonceDigest !== sha256Bytes(Buffer.from(nonce)) ||
      data.preparationDigest !== digestOmitting(data, 'preparationDigest')) throw new TypeError('MCP probe source intent changes its purpose, original nonce or fixed deadline');
  for (const name of ['runId', 'principalId', 'brokerDispatchId', 'inspectorSupervisorInstanceId']) controlWireText(data[name]);
  controlWireInteger(data.probeOrdinal, 1, data.probeKind === 'automatic' ? 8 : Number.MAX_SAFE_INTEGER); controlWireInteger(data.inspectorStateOwnerEpoch, 1);
  for (const name of ['originalSupervisor', 'controller']) {
    const identity = controlWireRecord(data[name], ['pid', 'processStartToken']); controlWireInteger(identity.pid, 1); controlWireText(identity.processStartToken);
  }
  refMembers(data); return immutableSnapshot(data) as McpStatusProbePreparationV1;
}

/** Existing wait transition only. Native task/fence closure and the exact
 * original nonce CAS are independently mandatory in the owning reducer. */
export function mcpUnresolvedProbeState(waitValue: McpInvocationWaitV1, evidenceRef: string, evidenceDigest: string,
  observedAt: string, reason: 'observation' | 'timeout' | 'shutdown_cancel'): McpInvocationWaitV1['probeState'] {
  const wait = decodeMcpInvocationWait(waitValue), state = wait.probeState;
  controlWireRef(evidenceRef); controlWireRef(evidenceDigest);
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') throw new TypeError('MCP unresolved result has no original in-flight nonce');
  const observed = parseCanonicalTime(observedAt), started = parseCanonicalTime(state.dispatch.probeStartedAt), deadline = parseCanonicalTime(state.dispatch.probeDeadlineAt);
  if (!['observation', 'timeout', 'shutdown_cancel'].includes(reason) || observed < started || reason === 'observation' && observed >= deadline || reason === 'timeout' && observed < deadline)
    throw new TypeError('MCP unresolved result cannot borrow an early timeout or closed late-response nonce');
  const last = { lastProbeEvidenceRef: evidenceRef, lastProbeEvidenceDigest: evidenceDigest };
  if (state.phase === 'user_in_flight' || state.automaticProbeCount === 8)
    return immutableSnapshot({ phase: 'automatic_exhausted' as const, automaticProbeCount: 8 as const, userProbeCount: state.userProbeCount, ...last });
  const delays = [1_000, 5_000, 30_000, 120_000, 600_000, 1_800_000, 3_600_000] as const;
  const base = reason === 'shutdown_cancel' ? Math.max(observed, deadline) : observed;
  return immutableSnapshot({ phase: 'automatic_pending' as const, automaticProbeCount: state.automaticProbeCount, userProbeCount: 0 as const,
    nextProbeAt: new Date(base + delays[state.automaticProbeCount - 1]!).toISOString(), ...last });
}
