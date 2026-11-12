// Closed retained data, never a live native owner/fence. The full historical
// reader independently binds this projection to its original byte records.
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireInteger, controlWireText } from '../kernel/control-wire-data.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { McpStdioRecoveryBinding, McpStdioRecoveryUnavailableJoinData, NativeMcpStdioRecoveryJoined } from './mcp-stdio-broker-native.js';
import type { ReconciliationProbeEvidenceV1, ReconciliationProbeCancellationClosureV1, ReconciliationProbeTimeoutClosureV1 } from '../kernel/reconciliation.js';

export type McpStatusRetirementV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-stdio-recovery-retirement-v1'; binding: McpStdioRecoveryBinding;
  processContainmentRef?: string; retirementEvidenceRef: string; observedAt: string; retirementDigest: string;
}> & (Readonly<{
  joined: NativeMcpStdioRecoveryJoined; creatorProcessDomain?: never;
  nativeClosure: Readonly<{ kind: 'linux_original_join'; lifecycleRawRef: string; lifecycleProjectionRef: string }>;
}> | Readonly<{
  joined: McpStdioRecoveryUnavailableJoinData; creatorProcessDomain?: never;
  nativeClosure: Readonly<{ kind: 'linux_original_response_unavailable'; lifecycleRawRef: string; lifecycleProjectionRef: string }>;
}> | Readonly<{
  joined?: never;
  creatorProcessDomain: Readonly<{ authorityDomain: 'linux_installed_native_creator_process_v1'; processObservation: 'absent_or_start_token_mismatch';
    creatorSupervisorInstanceId: string; creatorStateOwnerEpoch: number; creatorProcessIdentityRef: string; creatorProcessIdentityDigest: string;
    inspectorStateOwnerEpoch: number; observedAt: string }>;
  nativeClosure: Readonly<{ kind: 'linux_successor_cleanup' | 'linux_successor_response_unavailable_cleanup';
    lifecycleRawRef: string; lifecycleProjectionRef: string; cleanupRawRef: string; cleanupProjectionRef: string }>;
}>);
export function isMcpStatusUnavailableRetirement(value: McpStatusRetirementV1): boolean {
  return value.nativeClosure.kind === 'linux_original_response_unavailable' || value.nativeClosure.kind === 'linux_successor_response_unavailable_cleanup';
}
const bindingTexts = ['runId', 'principalId', 'probeKind', 'brokerDispatchId', 'inspectorSupervisorInstanceId', 'originalOpId', 'originalDispatchId',
  'effectServerToolName', 'adapterExecutableId', 'profileId', 'statusOperationName'] as const;
const bindingRefs = ['previousWaitingSubjectRef', 'waitingSubjectRef', 'reconciliationSubjectDigest', 'probeNonceDigest', 'probeDispatchDigest',
  'brokerRequestDigest', 'brokerTargetDigest', 'brokerFenceTokenDigest', 'originalInstanceIdentityRef', 'originalInstanceIdentityDigest',
  'registryRevisionRef', 'registryManifestDigest', 'adapterRef', 'adapterDigest', 'adapterExecutableDigest', 'profileDigest',
  'statusRequestTemplateRef', 'statusRequestTemplateDigest', 'statusRequestDigest', 'plannedContainmentRef', 'plannedContainmentDigest',
  'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest'] as const;
const bindingIntegers = ['probeOrdinal', 'probeStartedAtMs', 'probeDeadlineAtMs', 'inspectorStateOwnerEpoch', 'originalAttempt', 'originalDispatchJournalSeq'] as const;
export function decodeMcpStatusBinding(value: unknown): McpStdioRecoveryBinding {
  const data = controlWireRecord(value, [...bindingTexts, ...bindingRefs, ...bindingIntegers, 'nonce']);
  bindingTexts.forEach(key => controlWireText(data[key])); bindingRefs.forEach(key => controlWireRef(data[key]));
  bindingIntegers.forEach(key => controlWireInteger(data[key], key === 'originalAttempt' ? 0 : 1));
  const nonce = controlWireText(data.nonce, 64, 64);
  if (data.probeKind !== 'automatic' && data.probeKind !== 'user_requested' ||
      data.probeKind === 'automatic' && Number(data.probeOrdinal) > 8 || Number(data.probeDeadlineAtMs) - Number(data.probeStartedAtMs) !== 30_000 ||
      data.effectServerToolName === data.statusOperationName || !/^[0-9a-f]{64}$/u.test(nonce) || data.probeNonceDigest !== sha256Bytes(Buffer.from(nonce)))
    throw new TypeError('MCP status binding changed its closed purpose, original nonce or deadline');
  return immutableSnapshot(data) as McpStdioRecoveryBinding;
}
export function decodeMcpStatusRetirement(value: unknown): McpStatusRetirementV1 {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP status retirement');
  const kind = (value as { nativeClosure?: { kind?: unknown } } | null)?.nativeClosure?.kind;
  const successor = kind === 'linux_successor_cleanup' || kind === 'linux_successor_response_unavailable_cleanup';
  const unavailable = kind === 'linux_original_response_unavailable' || kind === 'linux_successor_response_unavailable_cleanup';
  if (kind !== 'linux_original_join' && !successor && !unavailable)
    throw new TypeError('MCP native retirement changed its exact XOR purpose');
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'binding', 'nativeClosure', 'retirementEvidenceRef', 'observedAt', 'retirementDigest',
    successor ? 'creatorProcessDomain' : 'joined'],
    ['processContainmentRef']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-stdio-recovery-retirement-v1' || data.retirementDigest !== digestOmitting(data, 'retirementDigest'))
    throw new TypeError('MCP status retirement has no exact closed native-source projection');
  const binding = decodeMcpStatusBinding(data.binding);
  if (!successor) {
    const joined = controlWireRecord(data.joined, ['kind', 'purpose', 'execReleased', 'setupReleased',
      'statusReleased', 'releaseFenceTokenDigest', 'completedStages', 'tokenRevoked', 'matchingActiveReleaseCount', 'processJoined', 'pipesJoined', 'tasksJoined',
      'outputCustodyRetired', ...(unavailable ? ['reason'] : [])]);
    const phases = ['initialize', 'initialized', 'tools_list', 'tools_call'];
    const expectedKind = unavailable ? 'mcp_stdio_recovery_response_unavailable_joined' : 'mcp_stdio_recovery_owner_joined';
    if (joined.kind !== expectedKind || joined.purpose !== 'recovery' || joined.releaseFenceTokenDigest !== binding.brokerFenceTokenDigest ||
        joined.tokenRevoked !== true || joined.matchingActiveReleaseCount !== 0 || joined.processJoined !== true || joined.pipesJoined !== true ||
        joined.tasksJoined !== true || joined.outputCustodyRetired !== true || ['execReleased', 'setupReleased', 'statusReleased'].some(key => typeof joined[key] !== 'boolean') ||
        !Array.isArray(joined.completedStages) || joined.completedStages.length > 4 || joined.completedStages.some((phase, index) => phase !== phases[index]) ||
        joined.statusReleased === true && (joined.execReleased !== true || joined.setupReleased !== true) || joined.setupReleased === true && joined.execReleased !== true ||
        unavailable && (joined.reason !== 'native_response_refused' || joined.execReleased !== true))
      throw new TypeError('MCP status retirement substitutes a purpose or incomplete native token/process/pipe/task join');
  } else {
    const domain = controlWireRecord(data.creatorProcessDomain, ['authorityDomain', 'processObservation', 'creatorSupervisorInstanceId', 'creatorStateOwnerEpoch',
      'creatorProcessIdentityRef', 'creatorProcessIdentityDigest', 'inspectorStateOwnerEpoch', 'observedAt']);
    if (domain.authorityDomain !== 'linux_installed_native_creator_process_v1' || domain.processObservation !== 'absent_or_start_token_mismatch' ||
        domain.creatorSupervisorInstanceId !== binding.inspectorSupervisorInstanceId || domain.creatorStateOwnerEpoch !== binding.inspectorStateOwnerEpoch ||
        controlWireInteger(domain.inspectorStateOwnerEpoch, 1) <= binding.inspectorStateOwnerEpoch || domain.observedAt !== data.observedAt)
      throw new TypeError('MCP successor retirement cannot pretend to act on its original native mutex or current creator');
    controlWireRef(domain.creatorProcessIdentityRef); controlWireRef(domain.creatorProcessIdentityDigest);
  }
  const closure = controlWireRecord(data.nativeClosure, ['kind', 'lifecycleRawRef', 'lifecycleProjectionRef', ...(successor ? ['cleanupRawRef', 'cleanupProjectionRef'] : [])]);
  if (closure.kind !== kind) throw new TypeError('MCP native retirement changed its exact XOR purpose');
  controlWireRef(closure.lifecycleRawRef); controlWireRef(closure.lifecycleProjectionRef); controlWireRef(data.retirementEvidenceRef); controlWireRef(data.retirementDigest);
  if (successor) { controlWireRef(closure.cleanupRawRef); controlWireRef(closure.cleanupProjectionRef); }
  if (data.processContainmentRef !== undefined) controlWireRef(data.processContainmentRef);
  else if (unavailable) throw new TypeError('MCP unavailable response requires its original spawned containment');
  if (parseCanonicalTime(controlWireText(data.observedAt)) < binding.probeStartedAtMs)
    throw new TypeError('MCP status physical retirement predates its original source intent');
  return immutableSnapshot(data) as McpStatusRetirementV1;
}

export function decodeMcpStatusProbeWrapper(value: unknown): ReconciliationProbeEvidenceV1 {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP probe wrapper');
  const branch = (value as { outcome?: unknown } | null)?.outcome;
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'waitingSubjectDigest', 'probeKind',
    'probeOrdinal', 'probeNonceDigest', 'probeDispatchDigest', 'probeStartedAt', 'probeDeadlineAt', 'inspectorIdentityRef', 'inspectorIdentityDigest',
    'observedAt', 'evidenceDigest', 'outcome', ...(branch === 'subject_observation' ? ['subjectEvidenceKind', 'subjectEvidenceRef', 'subjectEvidenceDigest']
      : branch === 'probe_timeout' ? ['timeoutReason', 'timeoutClosureRef', 'timeoutClosureDigest'] : ['cancellationReason', 'cancellationClosureRef', 'cancellationClosureDigest'])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-reconciliation-probe-evidence-v1' ||
      !['subject_observation', 'probe_timeout', 'probe_cancelled'].includes(data.outcome as string) ||
      data.outcome === 'subject_observation' && data.subjectEvidenceKind !== 'mcp_recovery' ||
      data.outcome === 'probe_timeout' && data.timeoutReason !== 'no_authoritative_observation_before_deadline' ||
      data.outcome === 'probe_cancelled' && data.cancellationReason !== 'owning_supervisor_shutdown' ||
      data.waitingSubjectRef !== data.waitingSubjectDigest || data.evidenceDigest !== digestOmitting(data, 'evidenceDigest'))
    throw new TypeError('MCP probe wrapper changes its closed original subject, outcome or digest');
  for (const [key, value] of Object.entries(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(value);
  controlWireText(data.runId); controlWireInteger(data.probeOrdinal, 1, data.probeKind === 'automatic' ? 8 : Number.MAX_SAFE_INTEGER);
  const start = parseCanonicalTime(controlWireText(data.probeStartedAt)), deadline = parseCanonicalTime(controlWireText(data.probeDeadlineAt)),
    observed = parseCanonicalTime(controlWireText(data.observedAt));
  if (!['automatic', 'user_requested'].includes(data.probeKind as string) || deadline - start !== 30_000 || observed < start ||
      data.outcome === 'subject_observation' && observed >= deadline || data.outcome === 'probe_timeout' && observed < deadline)
    throw new TypeError('MCP probe wrapper changes its original thirty second nonce');
  return immutableSnapshot(data) as ReconciliationProbeEvidenceV1;
}
type McpProbeClosure = Extract<ReconciliationProbeTimeoutClosureV1 | ReconciliationProbeCancellationClosureV1, { subjectKind: 'mcp_recovery' }>;
export function decodeMcpStatusProbeClosure(value: unknown): McpProbeClosure {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP probe closure');
  const cancellation = (value as { format?: unknown } | null)?.format === 'cliq-reconciliation-probe-cancellation-closure-v1';
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'probeKind', 'probeOrdinal',
    'probeNonceDigest', 'probeDispatchDigest', 'probeDeadlineAt', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'closedAt', 'closureDigest',
    'subjectKind', 'brokerDispatchId', 'brokerTargetDigest', 'brokerFenceTokenDigest', 'noActiveReleaseForNonce', 'retirementRef', 'retirementDigest',
    ...(cancellation ? ['reason'] : [])], ['lateStatusCaptureRef', 'lateStatusCaptureDigest']);
  if (data.schemaVersion !== 1 || data.format !== (cancellation ? 'cliq-reconciliation-probe-cancellation-closure-v1' : 'cliq-reconciliation-probe-timeout-closure-v1') ||
      data.subjectKind !== 'mcp_recovery' || data.noActiveReleaseForNonce !== true || cancellation && data.reason !== 'owning_supervisor_shutdown' ||
      !['automatic', 'user_requested'].includes(data.probeKind as string) || data.closureDigest !== digestOmitting(data, 'closureDigest') ||
      (data.lateStatusCaptureRef === undefined) !== (data.lateStatusCaptureDigest === undefined))
    throw new TypeError('MCP closure cannot borrow a task/transport close or mismatching native retirement');
  for (const [key, value] of Object.entries(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(value);
  controlWireText(data.runId); controlWireText(data.brokerDispatchId); controlWireInteger(data.probeOrdinal, 1, data.probeKind === 'automatic' ? 8 : Number.MAX_SAFE_INTEGER);
  const deadline = parseCanonicalTime(controlWireText(data.probeDeadlineAt)), closed = parseCanonicalTime(controlWireText(data.closedAt));
  if (!cancellation && closed < deadline) throw new TypeError('MCP timeout closure cannot close its original nonce early');
  return immutableSnapshot(data) as McpProbeClosure;
}
