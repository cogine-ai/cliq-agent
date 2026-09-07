import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { InvocationJournalEntry, RunAssemblyV1 } from '../kernel/types.js';
import { modelRetryState } from './model-retry.js';

const policy: RunAssemblyV1['retry']['model'] = {
  maxDispatchedAttempts: 3, maxZeroByteTransportRetriesPerAttempt: 0, postAttemptDelaysMs: [500, 2000]
};
const time = (offset: number) => new Date(Date.parse('2026-09-07T00:00:00.000Z') + offset).toISOString();
// Pure history fixtures exercise the retry interpreter, not evidence or dispatch authority.
function row(seq: number, attempt: number, phase: InvocationJournalEntry['phase'], offset: number): InvocationJournalEntry {
  return { seq, runId: 'run', opId: 'operation', opKind: 'model', attempt, phase, leaseEpoch: 1,
    target: 'model', requestRef: `request-${attempt}`, replayClass: 'retry',
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, timestamp: time(offset),
    ...(['unknown', 'failed', 'completed'].includes(phase) ? { budgetSettlementRef: `settlement-${attempt}` } : {}),
    ...(phase === 'unknown' ? { evidenceRef: `ambiguity-${attempt}` } : {}),
    ...(phase === 'failed' ? { errorRef: `error-${attempt}` } : {}),
    ...(phase === 'completed' ? { resultRef: `result-${attempt}` } : {}) };
}
const firstUnknown = () => [row(1, 0, 'prepared', 0), row(2, 0, 'dispatch_claimed', 0), row(3, 0, 'unknown', 10)];

test('model retry derives its delay from the first settlement, including later positive failure evidence', () => {
  const history = firstUnknown();
  history.push(row(4, 0, 'failed', 200));
  assert.deepEqual(modelRetryState(policy, history, time(509)), { kind: 'backoff', nextAttempt: 1, dispatchedAttempts: 1, notBefore: time(510) });
  assert.deepEqual(modelRetryState(policy, history, time(510)), { kind: 'ready', nextAttempt: 1, dispatchedAttempts: 1 });
  const noRelease = firstUnknown();
  noRelease[2] = row(3, 0, 'failed', 10);
  assert.deepEqual(modelRetryState(policy, noRelease, time(509)), modelRetryState(policy, history, time(509)));
});

test('late old resolutions neither close a newer attempt nor reset its backoff', () => {
  const history = [...firstUnknown(), row(4, 1, 'prepared', 510), row(5, 0, 'completed', 510)];
  assert.deepEqual(modelRetryState(policy, history, time(510)), { kind: 'pending', attempt: 1, phase: 'prepared', dispatchedAttempts: 1 });
  history.push(row(6, 1, 'dispatch_claimed', 510), row(7, 1, 'unknown', 600));
  assert.deepEqual(modelRetryState(policy, history, time(2599)), { kind: 'backoff', nextAttempt: 2, dispatchedAttempts: 2, notBefore: time(2600) });
  assert.deepEqual(modelRetryState(policy, history, time(2600)), { kind: 'ready', nextAttempt: 2, dispatchedAttempts: 2 });
});

test('replay rejects early, unsettled, completed, duplicate, out-of-order and over-limit retries', () => {
  const unknown = firstUnknown();
  assert.throws(() => modelRetryState(policy, [...unknown, row(4, 1, 'prepared', 509)], time(9999)), /backoff/);
  assert.throws(() => modelRetryState(policy, [unknown[0]!, row(2, 1, 'prepared', 510)], time(510)), /unsettled/);
  assert.throws(() => modelRetryState(policy, [...unknown.slice(0, 2), row(3, 0, 'completed', 10), row(4, 1, 'prepared', 510)], time(510)), /completed/);
  assert.throws(() => modelRetryState(policy, [unknown[0]!, unknown[1]!, row(3, 0, 'dispatch_claimed', 1)], time(510)), /single claim/);
  assert.throws(() => modelRetryState(policy, [unknown[0]!, row(1, 0, 'dispatch_claimed', 0)], time(510)), /Journal order/);
  assert.throws(() => modelRetryState(policy, [...unknown, row(4, 1, 'prepared', 510), row(5, 1, 'dispatch_claimed', 509)], time(510)), /Journal order/);
  assert.throws(() => modelRetryState(policy, [...unknown, row(4, 2, 'prepared', 510)], time(510)), /contiguous/);
  assert.throws(() => modelRetryState(policy, [unknown[0]!, { ...unknown[1]!, opId: 'other' }], time(510)), /identities/);
  assert.throws(() => modelRetryState({ ...policy, postAttemptDelaysMs: [0, 0] } as unknown as typeof policy, [], time(0)), /frozen/);
  const exhausted = [...unknown, row(4, 1, 'prepared', 510), row(5, 1, 'dispatch_claimed', 510), row(6, 1, 'failed', 600),
    row(7, 2, 'prepared', 2600), row(8, 2, 'dispatch_claimed', 2600), row(9, 2, 'unknown', 2700)];
  assert.deepEqual(modelRetryState(policy, exhausted, time(9999)), { kind: 'exhausted', attempt: 2, dispatchedAttempts: 3, evidenceRef: 'ambiguity-2' });
  assert.throws(() => modelRetryState(policy, [...exhausted, row(10, 3, 'prepared', 9999)], time(9999)), /ceiling/);
});
