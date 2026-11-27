// Existing real StateStore seam. These negative cases create no successful
// verifier receipt, native proof, delivery authority or installed qualification.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertVerifiedDeliverySource, readVerifiedDeliverySource } from './delivery-source-authority.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';

test('delivery cannot acquire a verified source from a live Run or another principal', async () => {
  const fixture = await createAgentFixture('delivery-source-authority', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    for (const principalId of [fixture.principalId, 'not-the-source-principal']) {
      await assert.rejects(readVerifiedDeliverySource(held.driver, fixture.store.artifacts, held.owner, {
        principalId, sourceRunId: fixture.runId, expectedRunResultRef: 'a'.repeat(64)
      }), { code: 'INVALID_REQUEST' });
    }
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('delivery rejects unbranded source data before observing its properties', async () => {
  let observed = false;
  const forged = Object.defineProperty({}, 'run', { get() { observed = true; throw new Error('must not observe'); } });
  assert.throws(() => assertVerifiedDeliverySource(undefined as unknown as SqliteDriver,
    undefined as unknown as StateOwnerContext, forged), /verified delivery source/);
  assert.equal(observed, false);
});
