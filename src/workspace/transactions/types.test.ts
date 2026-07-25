import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ABORT_RECORD_ID_PREFIX,
  APPLY_RECORD_ID_PREFIX,
  OPEN_RECORD_ID_PREFIX,
  InvalidTxIdError,
  abortRecordId,
  applyRecordId,
  assertValidTxId,
  isStrictTxId,
  isValidTxId,
  openRecordId,
  validatorSummaryFromResults,
  validatorSummaryFromTx,
  type Transaction,
  type ValidatorResultSummary
} from './types.js';
import { makeTxId } from './store.js';

test('isValidTxId accepts lenient production and fixture shapes', () => {
  assert.equal(isValidTxId(makeTxId()), true);
  assert.equal(isValidTxId('tx_lock'), true);
  assert.equal(isValidTxId('tx_x'), true);
  assert.equal(isValidTxId('tx_' + 'a'.repeat(124)), true);
});

test('isValidTxId rejects path traversal and malformed ids', () => {
  const rejected = [
    '',
    'tx_',
    'tx_' + 'a'.repeat(125),
    'tx_..',
    'tx_../escape',
    'tx_escape/child',
    'tx_escape\\child',
    'tx_has.dot',
    'tx_has space',
    'tx_has\0nul',
    'not_tx_prefix',
    null,
    undefined,
    42
  ];

  for (const value of rejected) {
    assert.equal(isValidTxId(value), false, `expected rejection for ${JSON.stringify(value)}`);
  }
});

test('isStrictTxId only accepts Crockford32 tx ids from makeTxId()', () => {
  assert.equal(isStrictTxId(makeTxId()), true);
  assert.equal(isStrictTxId('tx_lock'), false);
  assert.equal(isStrictTxId('tx_..'), false);
});

test('assertValidTxId throws InvalidTxIdError with a safe display value', () => {
  assert.throws(() => assertValidTxId('tx_../foo'), InvalidTxIdError);
  assert.throws(
    () => assertValidTxId('bad'),
    (error: unknown) => {
      assert.ok(error instanceof InvalidTxIdError);
      assert.match(error.message, /invalid tx id/);
      assert.match(error.message, /path separators/);
      return true;
    }
  );
  assert.throws(
    () => assertValidTxId(123),
    (error: unknown) => {
      assert.ok(error instanceof InvalidTxIdError);
      assert.match(error.message, /123/);
      return true;
    }
  );

  assert.doesNotThrow(() => assertValidTxId('tx_safe'));
});

test('record id helpers prefix the tx id without mutating it', () => {
  const txId = 'tx_01HJKMNPQRSTVWXYZ012345';
  assert.equal(openRecordId(txId), `${OPEN_RECORD_ID_PREFIX}${txId}`);
  assert.equal(applyRecordId(txId), `${APPLY_RECORD_ID_PREFIX}${txId}`);
  assert.equal(abortRecordId(txId), `${ABORT_RECORD_ID_PREFIX}${txId}`);
});

test('validatorSummaryFromResults buckets validator error status under fail', () => {
  const validators: ValidatorResultSummary[] = [
    { name: 'blocking-pass', severity: 'blocking', status: 'pass', durationMs: 1 },
    { name: 'blocking-fail', severity: 'blocking', status: 'fail', durationMs: 2 },
    { name: 'blocking-error', severity: 'blocking', status: 'error', durationMs: 3 },
    { name: 'advisory-pass', severity: 'advisory', status: 'pass', durationMs: 4 },
    { name: 'advisory-fail', severity: 'advisory', status: 'fail', durationMs: 5 },
    { name: 'advisory-error', severity: 'advisory', status: 'error', durationMs: 6 }
  ];

  const summary = validatorSummaryFromResults(validators);
  assert.deepEqual(summary.blocking, { pass: 1, fail: 2 });
  assert.deepEqual(summary.advisory, {
    pass: 1,
    fail: 2,
    names: ['advisory-fail', 'advisory-error']
  });
});

test('validatorSummaryFromTx defaults missing validator results to empty buckets', () => {
  const tx = {
    id: 'tx_x',
    kind: 'edit',
    state: 'staging',
    workspaceId: 'ws',
    sessionId: 'sess',
    workspaceRealPath: '/tmp/ws',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z'
  } satisfies Transaction;

  assert.deepEqual(validatorSummaryFromTx(tx), {
    blocking: { pass: 0, fail: 0 },
    advisory: { pass: 0, fail: 0, names: [] }
  });
});
