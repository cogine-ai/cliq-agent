import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeBrokerInvocationAmbiguity, type BrokerInvocationAmbiguityEvidenceV1 } from './broker-ambiguity.js';
import { digestOmitting } from './identity.js';

// Offline wire examples only: no StateOwner, endpoint, installation, token,
// observation or physical failed release is created by decoding these values.
function wire(): BrokerInvocationAmbiguityEvidenceV1 {
  const value: BrokerInvocationAmbiguityEvidenceV1 = {
    schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1', runId: 'run-1',
    frontierRef: '1'.repeat(64), frontierDigest: '1'.repeat(64), opId: 'model-1', opKind: 'model',
    attempt: 0, dispatchId: 'dispatch-1', dispatchJournalSeq: 2,
    operationRequestRef: '2'.repeat(64), operationRequestDigest: '3'.repeat(64),
    operationTargetRef: '4'.repeat(64), operationTargetDigest: '5'.repeat(64),
    claimingSupervisorInstanceId: 'supervisor-1', claimingStateOwnerEpoch: 1,
    inspectorIdentityRef: '6'.repeat(64), inspectorIdentityDigest: '7'.repeat(64),
    observedAt: '2026-10-15T00:00:00.000Z', evidenceDigest: '',
    ambiguityKind: 'broker_channel_lost_after_claim', brokerFenceTokenDigest: '8'.repeat(64),
    failureCode: 'response_stream_interrupted', durableTerminalResultAbsent: true,
  };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); return value;
}

test('broker ambiguity wire accepts initial attempt zero and the closed failure vocabulary', () => {
  for (const failureCode of ['deadline_after_release_possible', 'connection_lost_after_release_possible', 'response_stream_interrupted'] as const) {
    const value = { ...wire(), failureCode }; value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
    const decoded = decodeBrokerInvocationAmbiguity(value);
    assert.equal(decoded.attempt, 0); assert.equal(decoded.dispatchJournalSeq, 2);
    assert.equal(decoded.failureCode, failureCode); assert.equal(decoded.durableTerminalResultAbsent, true);
    assert.equal(decoded.observedAt, '2026-10-15T00:00:00.000Z');
  }
});

test('broker ambiguity wire refuses extra diagnostic authority, invalid identity and rehashed invalid fields', () => {
  for (const fields of [
    { nativeRefusalCode: 'broker_response_refused' }, { tokenRevoked: true }, { matchingActiveReleaseCount: 0 },
    { ambiguityKind: 'no_release' }, { failureCode: 'arbitrary_remote_error' }, { durableTerminalResultAbsent: false },
    { opKind: 'verifier' }, { attempt: -1 }, { attempt: 0.5 }, { attempt: Number.MAX_SAFE_INTEGER + 1 },
    { dispatchJournalSeq: 0 }, { claimingStateOwnerEpoch: 0 }, { runId: '' }, { runId: 'x'.repeat(257) },
    { frontierDigest: '9'.repeat(64) }, { operationTargetDigest: 'not-a-digest' },
    { observedAt: '2026-10-15T00:00:00Z' },
  ]) {
    const value = { ...wire(), ...fields }; value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
    assert.throws(() => decodeBrokerInvocationAmbiguity(value), TypeError);
  }
  assert.throws(() => decodeBrokerInvocationAmbiguity({ ...wire(), runId: 'foreign-run' }), /digest/);
  const missing = wire() as Partial<BrokerInvocationAmbiguityEvidenceV1>; delete missing.brokerFenceTokenDigest;
  assert.throws(() => decodeBrokerInvocationAmbiguity(missing), /closed shape/);
});
