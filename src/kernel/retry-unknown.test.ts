import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { decodeRetryUnknownCancelledResult, retryUnknownHasLaterClaim } from './retry-unknown.js';
import type { InvocationJournalEntry } from './types.js';

test('terminal retry UNKNOWN has one closed truthful projection and retains its original once-settled charge', () => {
  const value = { schemaVersion: 1, kind: 'retry_unknown_cancelled', opId: 'operation', attempt: 2, unknownJournalSeq: 9,
    budgetSettlementRef: canonicalSha256('original whole-once settlement'), dispatchFenceOrDeathEvidenceRef: canonicalSha256('actual closure'),
    message: 'Run stopped without using the ambiguous result' };
  assert.deepEqual(decodeRetryUnknownCancelledResult(value), value);
  for (const changed of [{ ...value, message: 'Tool failed' }, { ...value, outcome: 'failed' }, { ...value, attempt: -1 },
    { ...value, unknownJournalSeq: 0 }, { ...value, consumed: 0 }, { ...value, retry: true },
    { ...value, dispatchFenceOrDeathEvidenceRef: undefined }]) assert.throws(() => decodeRetryUnknownCancelledResult(changed));
});

test('terminal ambiguity never replaces a later real claimed attempt, including a positively failed one', () => {
  const unknown = { opId: 'operation', attempt: 0 };
  const row = (phase: InvocationJournalEntry['phase'], attempt: number, opId = 'operation'): InvocationJournalEntry =>
    ({ opKind: 'mcp', opId, attempt, phase } as InvocationJournalEntry);
  assert.equal(retryUnknownHasLaterClaim([row('dispatch_claimed', 0), row('unknown', 0), row('prepared', 1), row('failed', 1)], unknown), false);
  assert.equal(retryUnknownHasLaterClaim([row('dispatch_claimed', 1), row('failed', 1)], unknown), true);
  assert.equal(retryUnknownHasLaterClaim([row('dispatch_claimed', 1), row('completed', 1)], unknown), true);
  assert.equal(retryUnknownHasLaterClaim([row('dispatch_claimed', 1, 'other')], unknown), false);
});
