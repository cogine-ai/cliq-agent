import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ContentAddressedStore } from './cas.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch, prepareTool } from './testing/tool-calls.js';

// Existing offline authority fixture and real SQLite/CAS reads only. No native
// invocation is constructed; cancellation must stop before reaching release.
for (const phase of ['before_read', 'during_read'] as const)
  test(`claimed tool release keeps its original read cancellation ${phase}`, async t => {
    const fixture = await createAgentFixture(`tool-release-${phase}`, { wallTimeMs: 300_000 }, { mode: 'yolo' });
    let resume!: () => void;
    const gate = new Promise<void>(resolve => { resume = resolve; });
    let pending: Promise<void> | undefined;
    try {
      await batch(fixture, [{ name: 'read', input: { path: 'a.ts' } }]);
      const prepared = await prepareTool(fixture), abort = new AbortController(), reason = new Error('original tool owner stopped');
      const claimed = await fixture.agent.claimTool({ expectedRunRevision: prepared.run.revision, leaseEpoch: fixture.leaseEpoch,
        opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'original-cancellable-release' }, abort.signal);
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      let enter!: () => void, reads = 0, settled = false;
      const entered = new Promise<void>(resolve => { enter = resolve; });
      const actual = ContentAddressedStore.prototype.read;
      t.mock.method(ContentAddressedStore.prototype, 'read', async function (this: ContentAddressedStore,
        ...args: Parameters<ContentAddressedStore['read']>) {
        reads++;
        const bytes = await actual.apply(this, args);
        if (phase === 'during_read' && reads === 1) { enter(); await gate; }
        return bytes;
      });
      if (phase === 'before_read') abort.abort(reason);
      pending = claimed.release(Object.freeze({}));
      void pending.then(() => { settled = true; }, () => { settled = true; });
      if (phase === 'during_read') {
        await entered; abort.abort(reason);
        await new Promise<void>(resolve => setImmediate(resolve));
        assert.equal(settled, false, 'original pending read must join before release rejects');
        resume();
      }
      await assert.rejects(pending, error => error === reason);
      assert.equal(reads, phase === 'before_read' ? 0 : 1);
      await assert.rejects(claimed.release(Object.freeze({})), { code: 'LEASE_FENCED' });
      assert.equal(reads, phase === 'before_read' ? 0 : 1, 'cancelled one-use release cannot be restarted');
      t.mock.restoreAll();
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before,
        'cancelled validation cannot release, settle or rewrite the permanent claim');
    } finally {
      resume(); if (pending) await Promise.allSettled([pending]);
      t.mock.restoreAll(); await disposeFixture(fixture);
    }
  });
