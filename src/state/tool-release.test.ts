import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch, prepareTool, claimTool } from './testing/tool-calls.js';

test('a permanent tool claim cannot release after its worker recovery fence', async () => {
  const fixture = await createAgentFixture('tool-release-fenced', undefined, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const prepared = await prepareTool(fixture);
    const claimed = await claimTool(fixture, prepared);
    await fixture.store.beginWorkerRecovery({ runId: fixture.runId, expectedRunRevision: prepared.run.revision });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(claimed.release(undefined), { code: 'REVISION_CONFLICT' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.equal(before.journal.at(-1)!.phase, 'dispatch_claimed');
    assert.equal(before.run.budgetReserved.toolCalls, 1);
  } finally { await disposeFixture(fixture); }
});

test('tool release rechecks lease expiry without changing or refunding its permanent claim', async (t) => {
  const fixture = await createAgentFixture('tool-release-expired', undefined, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const prepared = await prepareTool(fixture);
    const claimed = await claimTool(fixture, prepared);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 61_000 });
    await assert.rejects(claimed.release(undefined), { code: 'LEASE_FENCED' });
    t.mock.timers.reset();
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await assert.rejects(claimed.release(undefined), { code: 'LEASE_FENCED' });
  } finally { t.mock.timers.reset(); await disposeFixture(fixture); }
});

test('a canonical edit claim cannot release a structural callback in place of an actual native invocation', async () => {
  const fixture = await createAgentFixture('tool-release-forged', undefined, { tools: ['edit'], mode: 'yolo' });
  try {
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'before', new_text: 'after' } }]);
    const claimed = await claimTool(fixture, await prepareTool(fixture));
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    let effects = 0;
    await assert.rejects(claimed.release({ release() { effects++; } }), { code: 'RECOVERY_REQUIRED' });
    assert.equal(effects, 0);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await assert.rejects(claimed.release({ release() { effects++; } }), { code: 'LEASE_FENCED' });
    assert.equal(effects, 0);
  } finally { await disposeFixture(fixture); }
});
