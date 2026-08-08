import assert from 'node:assert/strict';
import test from 'node:test';

import {
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

test('isValidTxId accepts safe lenient ids and rejects path traversal shapes', () => {
  assert.equal(isValidTxId('tx_lock'), true);
  assert.equal(isValidTxId('tx_x'), true);
  assert.equal(isValidTxId('tx_abc-123_DEF'), true);

  const generated = makeTxId();
  assert.equal(isValidTxId(generated), true);
  assert.equal(isStrictTxId(generated), true);

  assert.equal(isValidTxId('tx_..'), false);
  assert.equal(isValidTxId('tx_../../foo'), false);
  assert.equal(isValidTxId('tx_foo/bar'), false);
  assert.equal(isValidTxId('tx_foo\\bar'), false);
  assert.equal(isValidTxId('tx_foo.bar'), false);
  assert.equal(isValidTxId('tx_'), false);
  assert.equal(isValidTxId('tx_' + 'a'.repeat(125)), false);
  assert.equal(isValidTxId('not_tx'), false);
  assert.equal(isValidTxId(null), false);
});

test('isStrictTxId requires the full Crockford32 shape', () => {
  assert.equal(isStrictTxId('tx_lock'), false);
  assert.equal(isStrictTxId(makeTxId()), true);
  assert.equal(isStrictTxId('tx_' + '0'.repeat(25)), false);
  assert.equal(isStrictTxId('tx_' + '0'.repeat(27)), false);
});

test('assertValidTxId throws InvalidTxIdError for unsafe values', () => {
  assert.throws(() => assertValidTxId('tx_../escape'), InvalidTxIdError);
  assert.throws(() => assertValidTxId(42), InvalidTxIdError);
  assert.doesNotThrow(() => assertValidTxId('tx_safe'));
});

test('record id helpers embed the tx id under stable prefixes', () => {
  assert.equal(openRecordId('tx_abc'), 'txrec_open_tx_abc');
  assert.equal(applyRecordId('tx_abc'), 'txrec_apply_tx_abc');
  assert.equal(abortRecordId('tx_abc'), 'txrec_abort_tx_abc');
});

test('validatorSummaryFromResults buckets pass/fail and maps error status to fail', () => {
  const validators: ValidatorResultSummary[] = [
    { name: 'size-limit', severity: 'blocking', status: 'pass', durationMs: 1 },
    { name: 'diff-sanity', severity: 'blocking', status: 'fail', durationMs: 2 },
    { name: 'shell', severity: 'blocking', status: 'error', durationMs: 3 },
    { name: 'index-clean', severity: 'advisory', status: 'pass', durationMs: 4 },
    { name: 'custom', severity: 'advisory', status: 'fail', durationMs: 5 }
  ];

  assert.deepEqual(validatorSummaryFromResults(validators), {
    blocking: { pass: 1, fail: 2 },
    advisory: { pass: 1, fail: 1, names: ['custom'] }
  });
});

test('validatorSummaryFromTx reads validators from the transaction record', () => {
  const tx = {
    validators: [
      { name: 'size-limit', severity: 'blocking', status: 'pass', durationMs: 1 }
    ]
  } as Transaction;

  assert.deepEqual(validatorSummaryFromTx(tx), {
    blocking: { pass: 1, fail: 0 },
    advisory: { pass: 0, fail: 0, names: [] }
  });
  assert.deepEqual(validatorSummaryFromTx({} as Transaction), {
    blocking: { pass: 0, fail: 0 },
    advisory: { pass: 0, fail: 0, names: [] }
  });
});
