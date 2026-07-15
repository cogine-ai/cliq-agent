import assert from 'node:assert/strict';
import test from 'node:test';

import { makeTxId } from './store.js';
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

test('isValidTxId accepts short test fixtures and production-shaped ids', () => {
  assert.equal(isValidTxId('tx_a'), true);
  assert.equal(isValidTxId('tx_test_lock_01HX'), true);
  assert.equal(isValidTxId(makeTxId()), true);
});

test('isValidTxId rejects path traversal and malformed shapes', () => {
  const invalid = [
    null,
    undefined,
    42,
    '',
    'no_prefix',
    'tx_',
    'tx_..',
    'tx_../foo',
    'tx_a/../b',
    'tx_a\\b',
    '/etc/passwd',
    'tx_a b',
    'tx_a.b',
    `tx_${'a'.repeat(125)}`
  ];
  for (const value of invalid) {
    assert.equal(isValidTxId(value), false, `expected invalid: ${JSON.stringify(value)}`);
  }
});

test('isStrictTxId accepts only Crockford32 production ids', () => {
  assert.equal(isStrictTxId(makeTxId()), true);
  assert.equal(isStrictTxId('tx_a'), false);
  assert.equal(isStrictTxId('tx_test_lock_01HX'), false);
  assert.equal(isStrictTxId('tx_..'), false);
});

test('assertValidTxId throws InvalidTxIdError with a descriptive message', () => {
  assert.throws(() => assertValidTxId('tx_..'), InvalidTxIdError);
  assert.throws(() => assertValidTxId('tx_..'), /invalid tx id/i);
  assert.throws(() => assertValidTxId('tx_..'), /no path separators/i);
  assert.throws(() => assertValidTxId(123), /invalid tx id: 123/);
  assert.throws(() => assertValidTxId('tx_../foo'), /"tx_\.\.\/foo"/);
  assert.doesNotThrow(() => assertValidTxId('tx_a'));
});

test('record id helpers prefix the tx id', () => {
  assert.equal(openRecordId('tx_abc'), 'txrec_open_tx_abc');
  assert.equal(applyRecordId('tx_abc'), 'txrec_apply_tx_abc');
  assert.equal(abortRecordId('tx_abc'), 'txrec_abort_tx_abc');
});

test('validatorSummaryFromResults buckets pass, fail, and error statuses', () => {
  const validators: ValidatorResultSummary[] = [
    { name: 'size-limit', severity: 'blocking', status: 'pass', durationMs: 1 },
    { name: 'diff-sanity', severity: 'blocking', status: 'fail', durationMs: 2 },
    { name: 'index-clean', severity: 'advisory', status: 'pass', durationMs: 3 },
    { name: 'shell-check', severity: 'advisory', status: 'fail', durationMs: 4 },
    { name: 'custom', severity: 'advisory', status: 'error', durationMs: 5 }
  ];

  assert.deepEqual(validatorSummaryFromResults(validators), {
    blocking: { pass: 1, fail: 1 },
    advisory: { pass: 1, fail: 2, names: ['shell-check', 'custom'] }
  });
});

test('validatorSummaryFromResults treats empty input as zeroed buckets', () => {
  assert.deepEqual(validatorSummaryFromResults(), {
    blocking: { pass: 0, fail: 0 },
    advisory: { pass: 0, fail: 0, names: [] }
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
