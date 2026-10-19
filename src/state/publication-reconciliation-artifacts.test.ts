// These are inert wire/CAS records, not StateOwner/native recovery evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { addCanonicalDuration, digestOmitting, identityHash } from '../kernel/identity.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { PublicationInspectionTargetV1, PublicationRecoveryOriginV1 } from '../kernel/reconciliation.js';
import { decodePublicationInspectionTarget, decodePublicationPathWait, decodePublicationProbeClosure,
  decodePublicationProbeEvidence, decodePublicationRecoveryOrigin } from './publication-reconciliation-artifacts.js';

const ref = 'a'.repeat(64), id = 'b'.repeat(43);
function origin(): PublicationRecoveryOriginV1 {
  const value: PublicationRecoveryOriginV1 = { schemaVersion: 1, format: 'cliq-publication-recovery-origin-v1',
    deliveryRunId: id, deliveryPlanRef: ref, opId: id, attempt: 0, dispatchId: id, claimJournalSeq: 2,
    arenaBirthRef: ref, arenaBirthDigest: ref, inspectorIdentityRef: ref, inspectorIdentityDigest: ref,
    ownerDeathAcquisitionEvidenceRef: ref, ownerDeathAcquisitionEvidenceDigest: ref,
    observedAt: '2026-10-19T00:00:00.000Z', originDigest: '' };
  value.originDigest = digestOmitting(value, 'originDigest'); return value;
}
test('publication current-inspector origin is closed data and never accepts invented authority or unread getters', () => {
  const value = origin(); assert.deepEqual(decodePublicationRecoveryOrigin(value), value);
  for (const change of [{ attempt: -1 }, { claimJournalSeq: 0 }, { observedAt: 'not-a-time' },
    { ownerDeathAcquisitionEvidenceRef: 'not-a-ref' }, { nativeHeld: true }]) {
    const bad = { ...value, ...change }; bad.originDigest = digestOmitting(bad, 'originDigest');
    assert.throws(() => decodePublicationRecoveryOrigin(bad), TypeError);
  }
  const hostile = { ...value };
  Object.defineProperty(hostile, 'ownerDeathAcquisitionEvidenceRef', { enumerable: true,
    get() { assert.fail('untrusted origin getter executed'); } });
  assert.throws(() => decodePublicationRecoveryOrigin(hostile), TypeError);
  const hidden = { ...value }; Object.defineProperty(hidden, 'opId', { value: id, enumerable: false });
  assert.throws(() => decodePublicationRecoveryOrigin(hidden), TypeError);
});

test('publication in-flight data retains its exact pending predecessor instead of accepting an ordinal alone', () => {
  const createdAt = '2026-10-19T00:00:00.000Z';
  const subject = { kind: 'publication_path' as const, deliveryPlanRef: ref, pathOperationId: id, attempt: 0 };
  const dispatch = { schemaVersion: 1, format: 'cliq-reconciliation-probe-dispatch-v1', runId: id,
    reconciliationSubjectDigest: canonicalSha256(subject), probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: ref,
    probeStartedAt: createdAt, probeDeadlineAt: addCanonicalDuration(createdAt, 30_000), owningSupervisorInstanceId: id,
    subjectKind: 'publication', inspectorTaskId: identityHash(id, canonicalSha256(subject), 'automatic', 1, ref),
    inspectionTargetDigest: ref, previousWaitingSubjectRef: ref, dispatchDigest: '' };
  dispatch.dispatchDigest = digestOmitting(dispatch, 'dispatchDigest');
  const wait = { schemaVersion: 1, kind: 'reconciliation', runId: id, createdFromRevision: 4, createdAt, frontierRef: ref,
    subject, probeState: { phase: 'automatic_in_flight', automaticProbeCount: 1, userProbeCount: 0, dispatch } };
  assert.deepEqual(decodePublicationPathWait(wait), wait);
  const { previousWaitingSubjectRef: _prior, ...missing } = dispatch;
  missing.dispatchDigest = digestOmitting(missing, 'dispatchDigest');
  assert.throws(() => decodePublicationPathWait({ ...wait, probeState: { ...wait.probeState, dispatch: missing } }), TypeError);
});

test('publication inspection target freezes one original ordered claim and optional durable progress pair', () => {
  const value: PublicationInspectionTargetV1 = { schemaVersion: 1, format: 'cliq-publication-inspection-target-v1', runId: id,
    subject: { kind: 'publication_path', deliveryPlanRef: ref, pathOperationId: id, attempt: 0 },
    preparedJournalSeq: 1, claimJournalSeq: 2, unknownJournalSeq: 3, unknownEvidenceRef: ref, unknownBudgetSettlementRef: ref,
    progress: { itemRef: ref, checkpointId: id } };
  assert.deepEqual(decodePublicationInspectionTarget(value), value);
  for (const change of [{ claimJournalSeq: 1 }, { unknownJournalSeq: 2 }, { progress: { itemRef: ref } },
    { progress: { itemRef: ref, checkpointId: id, cleanupAllowed: true } }, { progress: undefined },
    { subject: { ...value.subject, newAttempt: 1 } }, { rawNativeOwner: {} }])
    assert.throws(() => decodePublicationInspectionTarget({ ...value, ...change }), TypeError);
  const hostile = { ...value };
  Object.defineProperty(hostile, 'subject', { enumerable: true, get() { assert.fail('target getter executed'); } });
  assert.throws(() => decodePublicationInspectionTarget(hostile), TypeError);
});

test('publication shutdown probe closure is truthful joined cancellation, never an early deadline timeout', () => {
  const now = '2026-10-19T00:00:00.000Z', deadline = addCanonicalDuration(now, 30_000);
  const closure = { schemaVersion: 1, format: 'cliq-reconciliation-probe-cancellation-closure-v1', runId: id,
    waitingSubjectRef: ref, probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: ref, probeDispatchDigest: ref,
    probeDeadlineAt: deadline, inspectorIdentityRef: ref, inspectorIdentityDigest: ref, closedAt: now, closureDigest: '',
    reason: 'owning_supervisor_shutdown', subjectKind: 'publication', deliveryPlanRef: ref, pathOperationId: id,
    attempt: 0, inspectorTaskId: id, taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true } };
  closure.closureDigest = digestOmitting(closure, 'closureDigest');
  assert.deepEqual(decodePublicationProbeClosure(closure), closure);
  const wrapper = { schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: id,
    waitingSubjectRef: ref, waitingSubjectDigest: ref, probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: ref,
    probeDispatchDigest: ref, probeStartedAt: now, probeDeadlineAt: deadline, inspectorIdentityRef: ref,
    inspectorIdentityDigest: ref, observedAt: now, evidenceDigest: '', outcome: 'probe_cancelled',
    cancellationReason: 'owning_supervisor_shutdown', cancellationClosureRef: ref, cancellationClosureDigest: closure.closureDigest };
  wrapper.evidenceDigest = digestOmitting(wrapper, 'evidenceDigest');
  assert.deepEqual(decodePublicationProbeEvidence(wrapper), wrapper);
  for (const change of [{ taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: false } },
    { taskClosure: { closureKind: 'owner_process_dead', ownerDeathAcquisitionEvidenceRef: ref, ownerDeathAcquisitionEvidenceDigest: ref } },
    { nativeHeld: true }]) {
    const bad = { ...closure, ...change }; bad.closureDigest = digestOmitting(bad, 'closureDigest');
    assert.throws(() => decodePublicationProbeClosure(bad), TypeError);
  }
  const { reason: _reason, ...base } = closure;
  const timeout = { ...base, format: 'cliq-reconciliation-probe-timeout-closure-v1' };
  timeout.closureDigest = digestOmitting(timeout, 'closureDigest');
  assert.throws(() => decodePublicationProbeClosure(timeout), TypeError);
  const mixed = { ...wrapper, timeoutClosureRef: ref }; mixed.evidenceDigest = digestOmitting(mixed, 'evidenceDigest');
  assert.throws(() => decodePublicationProbeEvidence(mixed), TypeError);
});
