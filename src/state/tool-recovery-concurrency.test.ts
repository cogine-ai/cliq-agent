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
import { validateToolRecovery } from './tool-recovery.js';
import type { ContinuationItem } from '../kernel/types.js';
import { checkpointFromRow } from './rows.js';

test('tool history does not reinterpret a verifier wait, but still validates its prior tool results', async () => {
  const fixture = await createAgentFixture('tool-history-verifier-wait', { wallTimeMs: 300_000 }, { mode: 'yolo' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a.ts' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: prepared.run.revision, observationRef: await observation(fixture, claimed, { text: 'original' }) });
    const cut = await fixture.store.readRecoveryClosure(fixture.runId), artifacts = fixture.store.artifacts;
    const checkpoints = driver.prepare('SELECT * FROM checkpoints WHERE run_id = ? ORDER BY based_on_run_revision')
      .all(fixture.runId).map(checkpointFromRow);
    const items = new Map(await Promise.all(cut.items.map(async row =>
      [row.itemId, await artifacts.readCanonical<ContinuationItem>(row.payloadRef)] as const)));
    // Pure history projection: this marker is never admitted as a Run or
    // consent. The preceding verifier validator owns the complete wait proof.
    const waitingOnRef = (await artifacts.publishCanonical({ subject: { kind: 'verifier_launch' } }, 'inert-wait-data')).ref;
    const input = { artifacts, run: { ...cut.run, status: 'waiting' as const, nextStep: 'verify' as const,
      activeWorkerLaunchId: undefined, waitingReason: 'approval' as const, waitingOnRef }, spec: cut.runSpec,
      items, journal: cut.journal, checkpoints, workspaceGenerations: cut.workspaceGenerations };
    await validateToolRecovery(input);
    await assert.rejects(validateToolRecovery({ ...input, checkpoints: checkpoints.filter(checkpoint =>
      checkpoint.journalSeq !== cut.journal.length) }), /tool result has no atomically matching ready Checkpoint/);
    for (const kind of ['tool_call', 'unrecognized']) {
      const ref = (await artifacts.publishCanonical({ subject: { kind } }, 'inert-wait-data')).ref;
      await assert.rejects(validateToolRecovery({ ...input, run: { ...input.run, waitingOnRef: ref } }), /approval wait/);
    }
  } finally { driver.close(); await disposeFixture(fixture); }
});

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
