import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { ContentAddressedStore } from './cas.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';

// Real SQLite/CAS history, with the existing offline authority fixture. This
// exercises the recovery caller; it does not qualify native tool retirement.
test('independent original tool histories read together and all join before recovery returns', async () => {
  const fixture = await createAgentFixture('tool-history-concurrency', { wallTimeMs: 300_000 }, { mode: 'yolo' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const actual = ContentAddressedStore.prototype.read;
  let release!: () => void, timer: ReturnType<typeof setTimeout> | undefined;
  const gate = new Promise<void>(resolve => { release = resolve; });
  try {
    const refs: string[] = [];
    await batch(fixture, [0, 1].map(() => ({ name: 'read', input: { path: 'a.ts' } })));
    for (let index = 0; index < 2; index++) {
      const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
      const ref = await observation(fixture, claimed, { text: `value ${index}` }); refs.push(ref);
      await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0,
        expectedRunRevision: prepared.run.revision, observationRef: ref });
    }
    let inHistory = false, held = false, entered = 0, overlapped = false, joined = 0;
    ContentAddressedStore.prototype.read = async function (ref, signal) {
      const observed = inHistory && refs.includes(ref);
      if (observed) {
        // Either original history can arrive first. Observe entry before real
        // I/O so filesystem completion order cannot manufacture a failure.
        entered++;
        if (entered === 1) {
          held = true;
          timer = setTimeout(() => { held = false; release(); }, 2000);
          await gate; held = false;
        } else {
          overlapped ||= held;
          release();
        }
      }
      const bytes = await actual.call(this, ref, signal);
      if (observed) joined++;
      return bytes;
    };
    const cut = await readRecoveryClosure(driver, fixture.store.artifacts, fixture.runId,
      phase => { inHistory = phase === 'history_tool'; });
    assert.equal(overlapped, true, 'both original histories must enter before either held read is released');
    assert.equal(joined, 2);
    assert.equal(cut.journal.filter(row => row.opKind === 'tool' && row.phase === 'completed').length, 2);
  } finally {
    release(); if (timer) clearTimeout(timer);
    ContentAddressedStore.prototype.read = actual;
    driver.close(); await disposeFixture(fixture);
  }
});
