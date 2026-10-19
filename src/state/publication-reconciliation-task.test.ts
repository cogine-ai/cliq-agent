import assert from 'node:assert/strict';
import test from 'node:test';
import { assertPublicationReconciliationTaskReceipt, startPublicationReconciliationTask } from './publication-reconciliation-task.js';

test('publication probe registration and join receipts cannot be forged from data or callbacks', () => {
  const guarded = Object.defineProperty({}, 'prepare', { get() { assert.fail('forged probe reached SQL'); } });
  const binding = { driver: guarded, artifacts: {}, owner: {}, execution: {}, task: {}, run: {}, wait: {} };
  assert.throws(() => startPublicationReconciliationTask(binding as never,
    async () => { assert.fail('forged probe work'); }, async () => { assert.fail('forged probe join'); }), /genuine same-owner/);
  assert.throws(() => assertPublicationReconciliationTaskReceipt({} as never, binding as never, '2026-10-19T00:00:00.000Z'),
    /actual cancelled and joined/);
});
