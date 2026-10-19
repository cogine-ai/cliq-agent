import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, assertArtifactRef, assertRequestId, digestOmitting, identityHash,
  normalizeBoundedText, parseCanonicalTime } from '../kernel/identity.js';
import type { PublicationInspectionTargetV1, PublicationPathWait, PublicationRecoveryOriginV1,
  PublicationReconciliationSubject, ReconciliationProbeDispatchV1, ReconciliationProbeEvidenceV1,
  ReconciliationProbeTimeoutClosureV1, ReconciliationProbeCancellationClosureV1 } from '../kernel/reconciliation.js';
import { immutableSnapshot } from '../model/immutable.js';

function closed(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    throw new TypeError('publication reconciliation requires closed plain data');
  const data = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(data).length !== fields.length || fields.some(field => !Object.hasOwn(data, field)) ||
      Object.values(data).some(field => !field.enumerable || !Object.hasOwn(field, 'value') || field.value === undefined))
    throw new TypeError('publication reconciliation has unknown, missing or non-data fields');
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 256) !== value) throw new TypeError('invalid reconciliation text');
  return value;
}
function reference(value: unknown): string { const result = text(value); assertArtifactRef(result); return result; }
function integer(value: unknown, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new TypeError('invalid reconciliation integer');
  return value as number;
}
function time(value: unknown): string { const result = text(value); parseCanonicalTime(result); return result; }
function subject(value: unknown): PublicationReconciliationSubject {
  const data = closed(value, ['kind', 'deliveryPlanRef', 'pathOperationId', 'attempt']);
  if (data.kind !== 'publication_path') throw new TypeError('publication inspection cannot substitute a recovery subject');
  reference(data.deliveryPlanRef); text(data.pathOperationId); integer(data.attempt);
  return value as PublicationReconciliationSubject;
}

export function decodePublicationRecoveryOrigin(value: unknown): PublicationRecoveryOriginV1 {
  const graceful = !!value && typeof value === 'object' && Object.hasOwn(value, 'gracefulOwnerDeath');
  const data = closed(value, ['schemaVersion', 'format', 'deliveryRunId', 'deliveryPlanRef', 'opId', 'attempt', 'dispatchId',
    'claimJournalSeq', 'arenaBirthRef', 'arenaBirthDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest',
    ...(graceful ? ['gracefulOwnerDeath'] : ['ownerDeathAcquisitionEvidenceRef', 'ownerDeathAcquisitionEvidenceDigest']), 'observedAt', 'originDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-publication-recovery-origin-v1')
    throw new TypeError('invalid publication recovery origin format');
  for (const field of ['deliveryRunId', 'opId', 'dispatchId']) text(data[field]);
  for (const field of ['deliveryPlanRef', 'arenaBirthRef', 'arenaBirthDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'originDigest']) reference(data[field]);
  if (graceful) {
    const death = closed(data.gracefulOwnerDeath, ['kind', 'priorOwnerRowDigest', 'priorProcessIdentityRef', 'priorProcessIdentityDigest',
      'gracefulTransitionEvidenceRef', 'gracefulTransitionEvidenceDigest', 'processObservation']);
    if (death.kind !== 'observed_after_graceful_release' || death.processObservation !== 'absent_or_start_token_mismatch')
      throw new TypeError('publication graceful history has no exact original process-death observation');
    for (const field of ['priorOwnerRowDigest', 'priorProcessIdentityRef', 'priorProcessIdentityDigest',
      'gracefulTransitionEvidenceRef', 'gracefulTransitionEvidenceDigest']) reference(death[field]);
  } else {
    reference(data.ownerDeathAcquisitionEvidenceRef); reference(data.ownerDeathAcquisitionEvidenceDigest);
  }
  integer(data.attempt); integer(data.claimJournalSeq, 1); time(data.observedAt);
  if (data.originDigest !== digestOmitting(data, 'originDigest')) throw new TypeError('publication recovery origin digest differs');
  return immutableSnapshot(value) as PublicationRecoveryOriginV1;
}

export function decodePublicationInspectionTarget(value: unknown): PublicationInspectionTargetV1 {
  if (!value || typeof value !== 'object') throw new TypeError('invalid publication inspection target');
  const data = closed(value, ['schemaVersion', 'format', 'runId', 'subject', 'preparedJournalSeq', 'claimJournalSeq',
    'unknownJournalSeq', 'unknownEvidenceRef', 'unknownBudgetSettlementRef', ...(Object.hasOwn(value, 'progress') ? ['progress'] : [])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-publication-inspection-target-v1')
    throw new TypeError('invalid publication inspection target format');
  text(data.runId); subject(data.subject);
  const prepared = integer(data.preparedJournalSeq, 1), claim = integer(data.claimJournalSeq, 1), unknown = integer(data.unknownJournalSeq, 1);
  if (prepared >= claim || claim >= unknown) throw new TypeError('publication inspection target lost its original ordered Journal');
  reference(data.unknownEvidenceRef); reference(data.unknownBudgetSettlementRef);
  if (Object.hasOwn(data, 'progress')) {
    const progress = closed(data.progress, ['itemRef', 'checkpointId']); reference(progress.itemRef); text(progress.checkpointId);
  }
  return immutableSnapshot(value) as PublicationInspectionTargetV1;
}

function dispatch(value: unknown, wait: PublicationPathWait, probeKind: 'automatic' | 'user_requested', ordinal: number) {
  const data = closed(value, ['schemaVersion', 'format', 'runId', 'reconciliationSubjectDigest', 'probeKind', 'probeOrdinal',
    'probeNonceDigest', 'probeStartedAt', 'probeDeadlineAt', 'owningSupervisorInstanceId', 'dispatchDigest', 'subjectKind',
    'inspectorTaskId', 'inspectionTargetDigest', 'previousWaitingSubjectRef', ...(probeKind === 'user_requested' ? ['controlRequestId', 'controlRequestDigest'] : [])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-reconciliation-probe-dispatch-v1' || data.subjectKind !== 'publication' ||
      data.runId !== wait.runId || data.probeKind !== probeKind || data.probeOrdinal !== ordinal ||
      data.reconciliationSubjectDigest !== canonicalSha256(wait.subject)) throw new TypeError('publication probe dispatch substituted its subject');
  for (const field of ['probeNonceDigest', 'reconciliationSubjectDigest', 'dispatchDigest', 'inspectionTargetDigest', 'previousWaitingSubjectRef']) reference(data[field]);
  text(data.owningSupervisorInstanceId); text(data.inspectorTaskId);
  const startedAt = time(data.probeStartedAt), deadlineAt = time(data.probeDeadlineAt);
  if (startedAt < wait.createdAt || deadlineAt !== addCanonicalDuration(startedAt, 30_000) ||
      data.inspectorTaskId !== identityHash(wait.runId, canonicalSha256(wait.subject), probeKind, ordinal, data.probeNonceDigest) ||
      data.dispatchDigest !== digestOmitting(data, 'dispatchDigest')) throw new TypeError('publication probe lost its fixed task, nonce or deadline');
  if (probeKind === 'user_requested') { assertRequestId(text(data.controlRequestId)); reference(data.controlRequestDigest); }
  return value as ReconciliationProbeDispatchV1;
}

export function decodePublicationPathWait(value: unknown): PublicationPathWait {
  const data = closed(value, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject', 'probeState']);
  if (data.schemaVersion !== 1 || data.kind !== 'reconciliation') throw new TypeError('invalid publication waiting format');
  text(data.runId); integer(data.createdFromRevision, 1); time(data.createdAt); reference(data.frontierRef); subject(data.subject);
  const stateValue = data.probeState;
  if (!stateValue || typeof stateValue !== 'object') throw new TypeError('missing publication probe state');
  const phase = Object.getOwnPropertyDescriptor(stateValue, 'phase')?.value;
  const wait = value as PublicationPathWait;
  if (phase === 'automatic_pending') {
    const count = Object.getOwnPropertyDescriptor(stateValue, 'automaticProbeCount')?.value;
    const state = closed(stateValue, ['phase', 'automaticProbeCount', 'userProbeCount', 'nextProbeAt',
      ...(count === 0 ? [] : ['lastProbeEvidenceRef', 'lastProbeEvidenceDigest'])]);
    const auto = integer(state.automaticProbeCount);
    if (auto > 7 || state.userProbeCount !== 0 || time(state.nextProbeAt) < wait.createdAt ||
        auto === 0 && state.nextProbeAt !== wait.createdAt) throw new TypeError('invalid publication automatic probe schedule');
    if (auto > 0) { reference(state.lastProbeEvidenceRef); reference(state.lastProbeEvidenceDigest); }
  } else if (phase === 'automatic_in_flight' || phase === 'user_in_flight') {
    const state = closed(stateValue, ['phase', 'automaticProbeCount', 'userProbeCount', 'dispatch']);
    const auto = integer(state.automaticProbeCount, 1), users = integer(state.userProbeCount);
    if (auto > 8 || phase === 'automatic_in_flight' && users !== 0 || phase === 'user_in_flight' && (auto !== 8 || users < 1))
      throw new TypeError('publication in-flight probe has an invalid bounded ordinal');
    dispatch(state.dispatch, wait, phase === 'automatic_in_flight' ? 'automatic' : 'user_requested', phase === 'automatic_in_flight' ? auto : users);
  } else if (phase === 'automatic_exhausted') {
    const state = closed(stateValue, ['phase', 'automaticProbeCount', 'userProbeCount', 'lastProbeEvidenceRef', 'lastProbeEvidenceDigest']);
    if (state.automaticProbeCount !== 8) throw new TypeError('publication automatic exhaustion is not eight probes');
    integer(state.userProbeCount); reference(state.lastProbeEvidenceRef); reference(state.lastProbeEvidenceDigest);
  } else throw new TypeError('publication has no manual-only or unknown probe state');
  return immutableSnapshot(value) as PublicationPathWait;
}

export function decodePublicationProbeEvidence(value: unknown): ReconciliationProbeEvidenceV1 {
  if (!value || typeof value !== 'object') throw new TypeError('invalid publication probe evidence');
  const outcome = Object.getOwnPropertyDescriptor(value, 'outcome')?.value;
  const extra = outcome === 'subject_observation' ? ['subjectEvidenceKind', 'subjectEvidenceRef', 'subjectEvidenceDigest'] :
    outcome === 'probe_timeout' ? ['timeoutReason', 'timeoutClosureRef', 'timeoutClosureDigest'] :
    outcome === 'probe_cancelled' ? ['cancellationReason', 'cancellationClosureRef', 'cancellationClosureDigest'] : [];
  const data = closed(value, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'waitingSubjectDigest', 'probeKind',
    'probeOrdinal', 'probeNonceDigest', 'probeDispatchDigest', 'probeStartedAt', 'probeDeadlineAt', 'inspectorIdentityRef',
    'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'outcome', ...extra]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-reconciliation-probe-evidence-v1' ||
      !['subject_observation', 'probe_timeout', 'probe_cancelled'].includes(outcome) ||
      !['automatic', 'user_requested'].includes(data.probeKind as string)) throw new TypeError('invalid publication probe evidence kind');
  text(data.runId); integer(data.probeOrdinal, 1);
  for (const field of ['waitingSubjectRef', 'waitingSubjectDigest', 'probeNonceDigest', 'probeDispatchDigest',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest']) reference(data[field]);
  const start = time(data.probeStartedAt), deadline = time(data.probeDeadlineAt), observed = time(data.observedAt);
  if (data.waitingSubjectRef !== data.waitingSubjectDigest || deadline !== addCanonicalDuration(start, 30_000) || observed < start ||
      data.probeKind === 'automatic' && (data.probeOrdinal as number) > 8 ||
      data.evidenceDigest !== digestOmitting(data, 'evidenceDigest')) throw new TypeError('publication probe evidence lost its fixed bounds or digest');
  if (outcome === 'subject_observation') {
    if (data.subjectEvidenceKind !== 'publication' || observed > deadline) throw new TypeError('publication observation is late or substitutes another subject');
    reference(data.subjectEvidenceRef); reference(data.subjectEvidenceDigest);
  } else if (outcome === 'probe_timeout') {
    if (data.timeoutReason !== 'no_authoritative_observation_before_deadline' || observed < deadline)
      throw new TypeError('publication timeout has no elapsed actual deadline');
    reference(data.timeoutClosureRef); reference(data.timeoutClosureDigest);
  } else {
    if (data.cancellationReason !== 'owning_supervisor_shutdown') throw new TypeError('publication cancellation has no fixed owning shutdown');
    reference(data.cancellationClosureRef); reference(data.cancellationClosureDigest);
  }
  return immutableSnapshot(value) as ReconciliationProbeEvidenceV1;
}

export function decodePublicationProbeClosure(value: unknown): Extract<ReconciliationProbeTimeoutClosureV1,
  { subjectKind: 'publication' }> | ReconciliationProbeCancellationClosureV1 {
  if (!value || typeof value !== 'object') throw new TypeError('invalid publication probe closure');
  const cancellation = Object.getOwnPropertyDescriptor(value, 'format')?.value === 'cliq-reconciliation-probe-cancellation-closure-v1';
  const data = closed(value, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'probeKind', 'probeOrdinal',
    'probeNonceDigest', 'probeDispatchDigest', 'probeDeadlineAt', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'closedAt',
    'closureDigest', 'subjectKind', 'deliveryPlanRef', 'pathOperationId', 'attempt', 'inspectorTaskId', 'taskClosure',
    ...(cancellation ? ['reason'] : [])]);
  if (data.schemaVersion !== 1 || data.format !== (cancellation ? 'cliq-reconciliation-probe-cancellation-closure-v1' :
      'cliq-reconciliation-probe-timeout-closure-v1') || data.subjectKind !== 'publication' ||
      !['automatic', 'user_requested'].includes(data.probeKind as string)) throw new TypeError('invalid publication probe closure kind');
  for (const field of ['runId', 'pathOperationId', 'inspectorTaskId']) text(data[field]);
  for (const field of ['waitingSubjectRef', 'probeNonceDigest', 'probeDispatchDigest', 'inspectorIdentityRef',
    'inspectorIdentityDigest', 'closureDigest', 'deliveryPlanRef']) reference(data[field]);
  integer(data.attempt); integer(data.probeOrdinal, 1);
  const deadline = time(data.probeDeadlineAt), ended = time(data.closedAt);
  if (!cancellation && ended < deadline || cancellation && data.reason !== 'owning_supervisor_shutdown' ||
      data.probeKind === 'automatic' && (data.probeOrdinal as number) > 8 || data.closureDigest !== digestOmitting(data, 'closureDigest'))
    throw new TypeError('publication probe closure lost its actual time, reason or digest');
  const taskValue = data.taskClosure;
  if (!taskValue || typeof taskValue !== 'object') throw new TypeError('publication closure has no joined task or actual death');
  const kind = Object.getOwnPropertyDescriptor(taskValue, 'closureKind')?.value;
  if (kind === 'cancelled_and_joined') {
    const task = closed(taskValue, ['closureKind', 'inspectorTaskCancelledAndJoined']);
    if (task.inspectorTaskCancelledAndJoined !== true) throw new TypeError('publication closure did not join its task');
  } else if (!cancellation && kind === 'owner_process_dead') {
    const task = closed(taskValue, ['closureKind', 'ownerDeathAcquisitionEvidenceRef', 'ownerDeathAcquisitionEvidenceDigest']);
    reference(task.ownerDeathAcquisitionEvidenceRef); reference(task.ownerDeathAcquisitionEvidenceDigest);
  } else throw new TypeError('publication shutdown requires its actual owning joined task');
  return immutableSnapshot(value) as ReturnType<typeof decodePublicationProbeClosure>;
}
