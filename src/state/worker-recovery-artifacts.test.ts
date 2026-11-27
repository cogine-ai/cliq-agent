// Pure retained data only. These values create no owner, task receipt,
// native death observation or permission to close a persisted worker nonce.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, digestOmitting } from '../kernel/identity.js';
import { decodeWorkerProbeClosure, decodeWorkerProbeEvidence } from './worker-recovery.js';

const ref = 'a'.repeat(64), startedAt = '2026-01-01T00:00:00.000Z';
const deadlineAt = addCanonicalDuration(startedAt, 30_000);
const rehash = <T extends { [K in Key]: string }, Key extends string>(value: T, key: Key): T =>
  ({ ...value, [key]: digestOmitting(value, key) });
const closure = () => rehash({ schemaVersion: 1, format: 'cliq-reconciliation-probe-cancellation-closure-v1',
  runId: 'original-run', waitingSubjectRef: ref, probeKind: 'automatic', probeOrdinal: 1,
  probeNonceDigest: ref, probeDispatchDigest: ref, probeDeadlineAt: deadlineAt,
  inspectorIdentityRef: ref, inspectorIdentityDigest: ref, closedAt: addCanonicalDuration(startedAt, 1000),
  closureDigest: '', reason: 'owning_supervisor_shutdown', subjectKind: 'worker_recovery',
  oldWorkerLaunchId: 'original-worker', processContainmentRef: ref, inspectorTaskId: ref,
  taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true } }, 'closureDigest');
const wrapper = () => rehash({ schemaVersion: 1, format: 'cliq-reconciliation-probe-evidence-v1', runId: 'original-run',
  waitingSubjectRef: ref, waitingSubjectDigest: ref, probeKind: 'automatic', probeOrdinal: 1,
  probeNonceDigest: ref, probeDispatchDigest: ref, probeStartedAt: startedAt, probeDeadlineAt: deadlineAt,
  inspectorIdentityRef: ref, inspectorIdentityDigest: ref, observedAt: addCanonicalDuration(startedAt, 1000), evidenceDigest: '',
  outcome: 'probe_cancelled', cancellationReason: 'owning_supervisor_shutdown',
  cancellationClosureRef: canonicalSha256(closure()), cancellationClosureDigest: closure().closureDigest }, 'evidenceDigest');

test('a closed worker cancellation is distinct from timeout and accepts only its joined original-task data branch', () => {
  const value = closure(), actual = decodeWorkerProbeClosure(value);
  assert.deepEqual(actual, value); assert(Object.isFrozen(actual) && Object.isFrozen(actual.taskClosure));
  value.taskClosure.inspectorTaskCancelledAndJoined = false;
  assert.equal(actual.taskClosure.inspectorTaskCancelledAndJoined, true);
  const { reason: _reason, ...common } = closure();
  const timeout = rehash({ ...common, format: 'cliq-reconciliation-probe-timeout-closure-v1', closedAt: deadlineAt }, 'closureDigest');
  assert.deepEqual(decodeWorkerProbeClosure(timeout), timeout);
  assert.throws(() => decodeWorkerProbeClosure(rehash({ ...timeout, closedAt: startedAt }, 'closureDigest')),
    TypeError, 'a real cancellation cannot be relabelled as an early timeout');
  const death = rehash({ ...timeout, taskClosure: { closureKind: 'owner_process_dead',
    ownerDeathAcquisitionEvidenceRef: ref, ownerDeathAcquisitionEvidenceDigest: ref } }, 'closureDigest');
  assert.deepEqual(decodeWorkerProbeClosure(death), death);
  const eighth = rehash({ ...closure(), probeOrdinal: 8, closedAt: addCanonicalDuration(deadlineAt, 1000) }, 'closureDigest');
  assert.deepEqual(decodeWorkerProbeClosure(eighth), eighth, 'real shutdown after the deadline remains cancellation, not a fabricated timeout');
});

test('worker closure data rejects subject substitution, mixed task proofs, unknown fields and changed digests', () => {
  const valid = closure();
  for (const change of [{ subjectKind: 'publication' }, { subjectKind: 'mcp_recovery' }, { probeKind: 'user_requested' },
    { probeOrdinal: 0 }, { probeOrdinal: 9 }, { reason: 'no_authoritative_observation_before_deadline' },
    { taskClosure: { closureKind: 'owner_process_dead', ownerDeathAcquisitionEvidenceRef: ref, ownerDeathAcquisitionEvidenceDigest: ref } },
    { taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: false } },
    { taskClosure: { ...valid.taskClosure, ownerDeathAcquisitionEvidenceRef: ref } }, { oldWorkerLaunchId: '' },
    { processContainmentRef: 'not-a-reference' }, { closedAt: 'not-a-time' }, { deliveryPlanRef: ref },
    { pathOperationId: 'not-worker' }, { timeoutClosureRef: ref }])
    assert.throws(() => decodeWorkerProbeClosure(rehash({ ...valid, ...change }, 'closureDigest')), TypeError);
  assert.throws(() => decodeWorkerProbeClosure({ ...valid, closureDigest: 'b'.repeat(64) }), TypeError);
  const missing: Record<string, unknown> = { ...valid }; delete missing.inspectorTaskId;
  assert.throws(() => decodeWorkerProbeClosure(missing), TypeError);
});

test('closed worker wrappers retain the original thirty-second dispatch bounds and a disjoint cancellation result', () => {
  const valid = wrapper(); assert.deepEqual(decodeWorkerProbeEvidence(valid), valid);
  const { cancellationReason: _reason, cancellationClosureRef: _ref, cancellationClosureDigest: _digest, ...common } = valid;
  const timeout = rehash({ ...common, outcome: 'probe_timeout', observedAt: deadlineAt,
    timeoutReason: 'no_authoritative_observation_before_deadline', timeoutClosureRef: ref, timeoutClosureDigest: ref }, 'evidenceDigest');
  assert.deepEqual(decodeWorkerProbeEvidence(timeout), timeout);
  for (const change of [{ outcome: 'subject_observation', subjectEvidenceKind: 'worker_recovery', subjectEvidenceRef: ref, subjectEvidenceDigest: ref },
    { probeOrdinal: 0 }, { probeOrdinal: 9 }, { probeKind: 'user_requested' }, { waitingSubjectDigest: 'b'.repeat(64) },
    { probeDeadlineAt: addCanonicalDuration(startedAt, 29_999) }, { observedAt: '2025-12-31T23:59:59.999Z' },
    { cancellationReason: 'timeout' }, { timeoutClosureRef: ref }, { subjectEvidenceKind: 'worker_recovery' }])
    assert.throws(() => decodeWorkerProbeEvidence(rehash({ ...valid, ...change }, 'evidenceDigest')), TypeError);
  assert.throws(() => decodeWorkerProbeEvidence(rehash({ ...timeout, observedAt: startedAt }, 'evidenceDigest')), TypeError);
  assert.throws(() => decodeWorkerProbeEvidence({ ...valid, evidenceDigest: 'b'.repeat(64) }), TypeError);
});

test('worker closed-data decoders reject accessors and proxies before inspecting caller properties', () => {
  let accesses = 0; const bad = () => { accesses++; throw new Error('untrusted'); };
  for (const [decode, valid, field] of [[decodeWorkerProbeClosure, closure(), 'format'],
    [decodeWorkerProbeEvidence, wrapper(), 'outcome']] as const) {
    const getter = Object.defineProperty({ ...valid }, field, { enumerable: true, get: bad });
    for (const value of [getter, new Proxy(valid, { get: bad, getPrototypeOf: bad, ownKeys: bad, getOwnPropertyDescriptor: bad }),
      { ...valid, [Symbol('foreign')]: ref }, { ...valid, toJSON: bad }]) assert.throws(() => decode(value), TypeError);
  }
  const nested = { ...closure(), taskClosure: new Proxy(closure().taskClosure, { get: bad, getPrototypeOf: bad, ownKeys: bad }) };
  assert.throws(() => decodeWorkerProbeClosure(nested), TypeError);
  assert.equal(accesses, 0);
});
