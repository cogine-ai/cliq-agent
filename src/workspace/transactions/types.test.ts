import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ABORT_RECORD_ID_PREFIX,
  APPLY_RECORD_ID_PREFIX,
  InvalidTxIdError,
  OPEN_RECORD_ID_PREFIX,
  abortRecordId,
  applyRecordId,
  assertValidTxId,
  isStrictTxId,
  isValidTxId,
  openRecordId,
  validatorSummaryFromResults
} from './types.js';
import type { ValidatorResultSummary } from './types.js';

test('isValidTxId accepts lenient production and fixture shapes', () => {
  assert.equal(isValidTxId('tx_0123456789ABCDEFGHJKMNPQRSTVWXYZ'), true);
  assert.equal(isValidTxId('tx_lock'), true);
  assert.equal(isValidTxId('tx_x'), true);
  assert.equal(isValidTxId('tx_fixture-1'), true);
});

test('isValidTxId rejects path traversal and malformed values', () => {
  const rejected = [
    null,
    undefined,
    42,
    '',
    'tx',
    'tx_',
    'tx_../escape',
    'tx_../../foo',
    'tx_has/slash',
    'tx_has\\backslash',
    'tx_has.dot',
    'tx_has space',
    'tx_has\0nul',
    `tx_${'a'.repeat(125)}`
  ];
  for (const value of rejected) {
    assert.equal(isValidTxId(value), false, `expected reject: ${String(value)}`);
  }
});

test('isStrictTxId only accepts Crockford32 production ids', () => {
  assert.equal(isStrictTxId('tx_06FVXWXFXQPNYVX93FNJ2PR3KC'), true);
  assert.equal(isStrictTxId('tx_lock'), false);
  assert.equal(isStrictTxId('tx_../escape'), false);
});

test('assertValidTxId throws InvalidTxIdError for unsafe ids', () => {
  assert.throws(() => assertValidTxId('tx_../../foo'), InvalidTxIdError);
  assert.throws(() => assertValidTxId('bad'), InvalidTxIdError);
  assert.doesNotThrow(() => assertValidTxId('tx_safe'));
});

test('record id helpers prefix tx ids deterministically', () => {
  const txId = 'tx_fixture';
  assert.equal(openRecordId(txId), `${OPEN_RECORD_ID_PREFIX}${txId}`);
  assert.equal(applyRecordId(txId), `${APPLY_RECORD_ID_PREFIX}${txId}`);
  assert.equal(abortRecordId(txId), `${ABORT_RECORD_ID_PREFIX}${txId}`);
});

test('validatorSummaryFromResults buckets pass/fail and treats error as fail', () => {
  const validators: ValidatorResultSummary[] = [
    { name: 'blocking-pass', severity: 'blocking', status: 'pass', durationMs: 1 },
    { name: 'blocking-fail', severity: 'blocking', status: 'fail', durationMs: 2 },
    { name: 'blocking-error', severity: 'blocking', status: 'error', durationMs: 3 },
    { name: 'advisory-pass', severity: 'advisory', status: 'pass', durationMs: 4 },
    { name: 'advisory-fail', severity: 'advisory', status: 'fail', durationMs: 5 },
    { name: 'advisory-error', severity: 'advisory', status: 'error', durationMs: 6 }
  ];

  assert.deepEqual(validatorSummaryFromResults(validators), {
    blocking: { pass: 1, fail: 2 },
    advisory: { pass: 1, fail: 2, names: ['advisory-fail', 'advisory-error'] }
  });
  assert.deepEqual(validatorSummaryFromResults(), {
    blocking: { pass: 0, fail: 0 },
    advisory: { pass: 0, fail: 0, names: [] }
  });
});
