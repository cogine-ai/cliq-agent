import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeDeliveryMergeItem } from './delivery.js';

// Inert retained data only: these records prove neither source verification,
// publication permission nor a physical resource lifetime.
const merge = () => ({ schemaVersion: 1, itemId: 'merge', runId: 'delivery', kind: 'delivery_merge',
  sourceRunResultRef: '1'.repeat(64), sourceBaseRef: '2'.repeat(64), sourceDesiredRef: '3'.repeat(64),
  capturedWorkspaceRef: '4'.repeat(64), resultSourceRef: '5'.repeat(64), diffRef: '6'.repeat(64),
  summaryRef: '7'.repeat(64), deliveryPlanRef: '8'.repeat(64), createdAt: '2026-10-18T00:00:00.000Z' });

test('delivery merge data retains all four source identities and no model authority', () => {
  const value = merge();
  assert.deepEqual(decodeDeliveryMergeItem(value), value);
  for (const field of ['sourceRunResultRef', 'sourceBaseRef', 'sourceDesiredRef', 'capturedWorkspaceRef',
    'resultSourceRef', 'diffRef', 'summaryRef', 'deliveryPlanRef']) {
    const missing: Record<string, unknown> = { ...value }; delete missing[field];
    assert.throws(() => decodeDeliveryMergeItem(missing));
    assert.throws(() => decodeDeliveryMergeItem({ ...value, [field]: 'not-a-ref' }));
  }
  for (const extra of [{ producingOpId: 'model-op' }, { approved: true }, { operation: 'agent' },
    { candidateItemId: 'candidate' }, { createdAt: '2026-10-18' }])
    assert.throws(() => decodeDeliveryMergeItem({ ...value, ...extra }));
});

test('delivery merge decoder rejects accessors without invoking them and freezes its snapshot', () => {
  let invoked = false;
  const raw = merge();
  Object.defineProperty(raw, 'sourceBaseRef', { enumerable: true, get() { invoked = true; throw new Error('untrusted getter'); } });
  assert.throws(() => decodeDeliveryMergeItem(raw)); assert.equal(invoked, false);
  const original = merge(), decoded = decodeDeliveryMergeItem(original);
  original.sourceBaseRef = '9'.repeat(64);
  assert.equal(decoded.sourceBaseRef, '2'.repeat(64)); assert.ok(Object.isFrozen(decoded));
});
