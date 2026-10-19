import assert from 'node:assert/strict';
import test from 'node:test';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { publishInProcessChannel } from './store.js';
import { loadDeliveryContinuation } from './run-continuation.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';

test('the Agent loader exposes an explicit agent-only handle while shared cancellation retains its exact owner', async () => {
  const fixture = await createAgentFixture('tagged-run-continuation', undefined, { mode: 'plan' });
  try {
    assert.equal(fixture.agent.operation, 'agent');
    assert.equal(typeof fixture.agent.prepareModel, 'function');
    assert.equal(typeof fixture.agent.prepareTool, 'function');
    assert.equal('controlAuthority' in fixture.agent, false, 'internal stop composition must not leak an extra loaded authority');
    const channel = await publishInProcessChannel(fixture.store);
    const cancelled = await fixture.agent.cancelRun({ ...channel, requestId: uuidv7(),
      expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    assert.equal(cancelled.response.result.snapshot.operation, 'agent');
    assert.equal(cancelled.run.cancelRequested, true);
    assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.stopIntentRef, cancelled.run.stopIntentRef);
  } finally { await disposeFixture(fixture); }
});

test('the model-free Delivery loader cannot reinterpret an Agent Run or create another authority path', async () => {
  const fixture = await createAgentFixture('delivery-loader-refuses-agent', undefined, { mode: 'plan' });
  try {
    const original = await fixture.store.readRecoveryClosure(fixture.runId);
    // Reuse the original real StateStore owner, never construct native/owner
    // evidence. This only checks a refusal; no delivery is admitted here.
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    await assert.rejects(loadDeliveryContinuation(held.driver, fixture.store.artifacts, held.owner,
      { runId: fixture.runId, releaseKeys: fixture.signed.releaseKeys }), /Agent Run cannot load a delivery continuation/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), original);
  } finally { await disposeFixture(fixture); }
});

test('a revoked constructor reader refuses before reading SQL or interpreting a genuine Agent as Delivery', async () => {
  const fixture = await createAgentFixture('delivery-reader-constructor-cancelled', undefined, { mode: 'plan' });
  const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
  const originalPrepare = held.driver.prepare;
  let queries = 0;
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const cancelled = new AbortController(), reason = new Error('constructor reader was revoked'); cancelled.abort(reason);
    held.driver.prepare = ((...args: Parameters<SqliteDriver['prepare']>) => {
      queries++; return originalPrepare.apply(held.driver, args);
    }) as SqliteDriver['prepare'];
    await assert.rejects(loadDeliveryContinuation(held.driver, fixture.store.artifacts, held.owner,
      { runId: fixture.runId, releaseKeys: fixture.signed.releaseKeys }, undefined, undefined, cancelled.signal), error => error === reason);
    assert.equal(queries, 0);
    held.driver.prepare = originalPrepare;
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { held.driver.prepare = originalPrepare; await disposeFixture(fixture); }
});
