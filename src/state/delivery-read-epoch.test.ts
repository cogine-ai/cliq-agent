// Reader/refusal tests only. No Delivery, StateOwner or native evidence is
// fabricated here; positive installed publication remains a Linux obligation.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as recovery from './recovery-closure.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';

test('a fresh paired publication read refuses an actual Agent Run without changing it', async () => {
  assert.equal(typeof recovery.readDeliveryPublicationClosure, 'function');
  const fixture = await createAgentFixture('delivery-read-epoch-refusal', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: Parameters<typeof recovery.readRecoveryClosure>[0] };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(recovery.readDeliveryPublicationClosure(held.driver, fixture.store.artifacts, fixture.runId),
      /requires a delivery Run/u);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
