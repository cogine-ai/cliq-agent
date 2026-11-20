import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { ArtifactCatalog } from './artifacts.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, disposeFixture } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { validateToolRecovery } from './tool-recovery.js';
import type { ContinuationItem, WorkspaceEntryManifest, WorkspaceStateManifest } from '../kernel/types.js';
import { checkpointFromRow } from './rows.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';

test('identical sealed workspace graphs verify once per tool history while every later cut reads afresh', async t => {
  // Real SQLite/CAS over the existing offline history fixture. The large files
  // exceed the byte-cache eligibility; no native retirement is qualified here.
  const fixture = await createAgentFixture('tool-history-shared-workspace', { wallTimeMs: 300_000 },
    { mode: 'accept-edits', tools: ['edit'] });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const text = 'x'.repeat(16 * 1024 * 1024 + 1), refs: string[] = [], entryRefs: string[] = [];
    await batch(fixture, [0, 1, 2].map(() => ({ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } })));
    for (let index = 0; index < 3; index++) {
      if (index) Object.assign(fixture, await activateFixtureWorker(fixture, `shared-workspace-${index}`));
      const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
      const result = await fixture.store.artifacts.readCanonical<ToolObservationV1>(await observation(fixture, claimed, { changed: true }));
      const proof = await quiescedToolCheckpoint(fixture, prepared.checkpointId, index < 2 ? text : 'y' + text.slice(1));
      result.postEffect = proof.checkpoint; result.observationDigest = digestOmitting(result, 'observationDigest');
      const published = await fixture.store.artifacts.publishCanonical(result, result.format);
      await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0,
        expectedRunRevision: prepared.run.revision, observationRef: published.ref });
      const state = await fixture.store.artifacts.readCanonical<WorkspaceStateManifest>(proof.workspaceStateRef);
      const entries = await fixture.store.artifacts.readCanonical<WorkspaceEntryManifest>(state.entriesRef);
      const file = entries.entries[0]!; assert(file.kind === 'file');
      refs.push(file.blobRef); entryRefs.push(state.entriesRef);
    }
    assert.equal(entryRefs[0], entryRefs[1]); assert.notEqual(entryRefs[1], entryRefs[2]);
    const open = fs.open.bind(fs), opened = new Map<string, number>(); let inHistory = false, closed = 0;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args), ref = refs.find(ref => String(args[0]).endsWith(path.sep + ref));
      if (inHistory && ref) {
        opened.set(ref, (opened.get(ref) ?? 0) + 1);
        const close = handle.close.bind(handle);
        t.mock.method(handle, 'close', async () => { await close(); closed++; });
      }
      return handle;
    });
    const recover = () => readRecoveryClosure(driver, fixture.store.artifacts, fixture.runId,
      phase => { inHistory = phase === 'history_tool'; });
    for (let traversal = 1; traversal <= 2; traversal++) {
      await recover();
      assert.equal(opened.get(refs[0]!), traversal, 'the same immutable entries graph needs one complete original file verification');
      assert.equal(opened.get(refs[2]!), traversal, 'a distinct entries graph must retain its own complete verification');
      assert.equal(closed, traversal * 2);
    }
    const filename = path.join(fixture.stateRoot, 'cas', refs[0]!);
    inHistory = false;
    await fs.chmod(filename, 0o600); await fs.writeFile(filename, Buffer.alloc(Buffer.byteLength(text), 0x7a));
    await fs.chmod(filename, 0o400);
    await assert.rejects(recover(), { code: 'RECOVERY_REQUIRED' });
    assert.equal(closed, [...opened.values()].reduce((sum, count) => sum + count, 0));
  } finally { t.mock.restoreAll(); driver.close(); await disposeFixture(fixture); }
});

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
  const actual = ArtifactCatalog.prototype.readCanonical;
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
    ArtifactCatalog.prototype.readCanonical = async function <T>(ref: string): Promise<T> {
      const observed = inHistory && refs.includes(ref);
      if (observed) {
        // Existence verification may already own complete bytes. Hold the
        // actual per-use decoder, which still yields and hashes its own copy,
        // so either history can enter first without depending on duplicate I/O.
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
      const value = await actual.call(this, ref) as T;
      if (observed) joined++;
      return value;
    };
    const cut = await readRecoveryClosure(driver, fixture.store.artifacts, fixture.runId,
      phase => { inHistory = phase === 'history_tool'; });
    assert.equal(overlapped, true, 'both original histories must enter before either held read is released');
    assert.equal(joined, 2);
    assert.equal(cut.journal.filter(row => row.opKind === 'tool' && row.phase === 'completed').length, 2);
  } finally {
    release(); if (timer) clearTimeout(timer);
    ArtifactCatalog.prototype.readCanonical = actual;
    driver.close(); await disposeFixture(fixture);
  }
});
