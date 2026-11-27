import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { ChildResultModelContentV1 } from '../kernel/children.js';
import type { WorkspaceDiffV1 } from '../kernel/result.js';
import type { WorkspaceEntry } from '../kernel/types.js';
import { readChildTerminalData } from './child-terminal.js';
import { childPatchManifest, childResultModelContent } from './child-result-artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';
import { createChildRunFixture, activateOfflineChild, completeOfflineChild } from './testing/child-runs.js';
import { openStateStore } from './store.js';
import type { ChildAllocationV1 } from '../kernel/types.js';
import { readChildAdmission } from './child-admission.js';

const ref = (value: string) => sha256Bytes(Buffer.from(value));
const file = (path: string, blob = 'old', mode: 0o644 | 0o755 = 0o644): WorkspaceEntry =>
  ({ path, kind: 'file', mode, size: blob.length, blobRef: ref(blob) });
const link = (path: string, target: string): WorkspaceEntry =>
  ({ path, kind: 'symlink', mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) });
function sourceDiff(): WorkspaceDiffV1 {
  const diff: WorkspaceDiffV1 = { schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: ref('B'),
    resultSourceRef: ref('S'), operations: [
      { path: 'added', kind: 'add', after: file('added') },
      { path: 'chmod', kind: 'modify', before: file('chmod'), after: file('chmod', 'old', 0o755) },
      { path: 'deleted', kind: 'delete', before: file('deleted') },
      { path: 'file', kind: 'modify', before: file('file'), after: file('file', 'new') },
      { path: 'link', kind: 'modify', before: file('link'), after: link('link', 'file') },
      { path: 'linknew', kind: 'add', after: link('linknew', 'file') },
      { path: 'type', kind: 'modify', before: file('type'), after: { path: 'type', kind: 'directory', mode: 0o755 } }
    ], diffDigest: '' };
  diff.diffDigest = digestOmitting(diff, 'diffDigest'); return diff;
}

// Pure immutable data only. These objects do not simulate an accepted child,
// source capture, physical execution, native retirement or publish permission.
test('child patch is the exact ordered B/S diff with full entry identities and only genuine file-mode changes classified as mode', () => {
  const diff = sourceDiff(), before = canonicalJsonBytes(diff), childRunId = 'child-original';
  const patch = childPatchManifest(childRunId, diff);
  assert.equal(patch.admittedForkBaseRef, diff.baseSourceRef); assert.equal(patch.resultSourceRef, diff.resultSourceRef);
  assert.equal(patch.diffRef, canonicalSha256(diff)); assert.equal(patch.childRunId, childRunId);
  assert.equal(patch.patchDigest, digestOmitting(patch, 'patchDigest'));
  assert.deepEqual(patch.operations.map(operation => operation.kind), ['add', 'mode', 'delete', 'modify', 'symlink', 'symlink', 'modify']);
  for (const [index, operation] of diff.operations.entries()) {
    const actual = patch.operations[index]!;
    assert.equal(actual.path, operation.path);
    if (operation.kind !== 'add') assert.equal('expectedEntryDigest' in actual && actual.expectedEntryDigest, canonicalSha256(operation.before));
    else assert(!Object.hasOwn(actual, 'expectedEntryDigest'));
    if (operation.kind !== 'delete') assert.equal('resultEntryDigest' in actual && actual.resultEntryDigest, canonicalSha256(operation.after));
    else assert(!Object.hasOwn(actual, 'resultEntryDigest'));
  }
  assert.deepEqual(canonicalJsonBytes(diff), before); assert(Object.isFrozen(patch)); assert(Object.isFrozen(patch.operations[0]));
  assert.deepEqual(childPatchManifest(childRunId, diff), patch);
  assert.notEqual(childPatchManifest('another-child', diff).patchDigest, patch.patchDigest);
  const changedSource = { ...diff, resultSourceRef: ref('another-S'), diffDigest: '' };
  changedSource.diffDigest = digestOmitting(changedSource, 'diffDigest');
  assert.notEqual(childPatchManifest(childRunId, changedSource).patchDigest, patch.patchDigest);
});

test('child patch refuses malformed, reordered, unchanged or rehashed unsafe diff data without invoking accessors', () => {
  const diff = sourceDiff();
  assert.throws(() => childPatchManifest('child', { ...diff, diffDigest: ref('different') }));
  for (const operations of [[...diff.operations].reverse(), [diff.operations[0]!, diff.operations[0]!],
    [{ path: 'same', kind: 'modify', before: file('same'), after: file('same') }]]) {
    const invalid = { ...diff, operations, diffDigest: '' };
    invalid.diffDigest = digestOmitting(invalid, 'diffDigest');
    assert.throws(() => childPatchManifest('child', invalid as WorkspaceDiffV1));
  }
  let accessed = false;
  const hostile = { ...diff }; Object.defineProperty(hostile, 'operations', { enumerable: true, get() { accessed = true; return []; } });
  assert.throws(() => childPatchManifest('child', hostile)); assert.equal(accessed, false);
  const proxy = new Proxy(diff, { get() { accessed = true; throw new Error('trap'); } });
  assert.throws(() => childPatchManifest('child', proxy)); assert.equal(accessed, false);
});

test('child model-safe output preserves only original summary or terminal reason with separate exact content digest', () => {
  const summary = 'Original complete summary\n';
  const success = childResultModelContent('child', 'mutating', { status: 'completed_unverified', summary });
  assert.deepEqual(success.content, { status: 'completed_unverified', summary });
  assert.equal(success.contentDigest, digestOmitting(success, 'contentDigest'));
  assert(Object.isFrozen(success.content));
  const failed = childResultModelContent('child', 'read_only', { status: 'cancelled', terminalReason: 'parent_cancelled' });
  assert.deepEqual(failed.content, { status: 'cancelled', terminalReason: 'parent_cancelled' });
  assert.equal(failed.contentDigest, digestOmitting(failed, 'contentDigest'));
  assert.throws(() => childResultModelContent('child', 'read_only', { status: 'succeeded', summary: ' ' }));
  assert.throws(() => childResultModelContent('child', 'read_only', { status: 'succeeded', summary, patchManifestRef: ref('patch') } as ChildResultModelContentV1['content']));
  assert.throws(() => childResultModelContent('child', 'read_only', { status: 'cancelled', terminalReason: 'verified' } as ChildResultModelContentV1['content']));
});

// Genuine Store/SQLite/CAS. This is a negative data-reader regression, not an
// accepted child terminal or installed Linux lifecycle qualification.
test('child terminal reader refuses an ordinary admitted root without modifying its Run, Journal or allocation graph', async () => {
  const fixture = await createQueuedFixture('child-terminal-root-refused');
  try {
    const driver = Reflect.get(fixture.store, 'driver') as SqliteDriver;
    const before = canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId));
    await assert.rejects(readChildTerminalData(driver, fixture.store.artifacts, fixture.runId), { code: 'RECOVERY_REQUIRED' });
    assert.deepEqual(canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId)), before);
    const cancelled = new AbortController(); cancelled.abort(new Error('reader stopped'));
    await assert.rejects(readChildTerminalData(driver, fixture.store.artifacts, fixture.runId, { signal: cancelled.signal }), /reader stopped/);
    assert.deepEqual(canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId)), before);
  } finally { await disposeFixture(fixture); }
});

// Actual accepted child admission through the sole local writer. Original
// physical observations remain the existing inert storage fixtures; no child
// terminal rows, execution or process evidence are manufactured here.
test('an admitted child still reserved cannot be mistaken for a completed result or release its parent allocation', async () => {
  const fixture = await createChildRunFixture('child-terminal-reserved-refused');
  try {
    const id = fixture.children[0]!.childRunId;
    const original = await readChildAdmission(fixture.driver, fixture.store.artifacts, id);
    assert.equal(original.allocation.state, 'reserved');
    const childBefore = canonicalJsonBytes(await fixture.store.readRecoveryClosure(id));
    const parentBefore = canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId));
    await assert.rejects(readChildTerminalData(fixture.driver, fixture.store.artifacts, id), { code: 'RECOVERY_REQUIRED' });
    assert.deepEqual(canonicalJsonBytes(await fixture.store.readRecoveryClosure(id)), childBefore);
    assert.deepEqual(canonicalJsonBytes(await fixture.store.readRecoveryClosure(fixture.runId)), parentBefore);
    original.assertUnchanged(fixture.driver);
  } finally { await disposeFixture(fixture); }
});

// Each terminal below is produced by the ordinary accepted-child reducer
// chain. Corrupt rows are rejection-only input and always restored before a
// successful read/close; no corruption is used as positive execution evidence.
for (const mode of ['read_only', 'mutating'] as const) test(`original ${mode} child terminal closes exact output and usage across corruption and genuine reopen`, async () => {
  const fixture = await createChildRunFixture(`child-terminal-${mode}-original`, 1, { mode });
  try {
    const parent = canonicalJsonBytes(fixture.store.getRun(fixture.runId));
    const session = canonicalJsonBytes(fixture.store.getSession(fixture.store.getRun(fixture.runId).sessionId));
    const active = await activateOfflineChild(fixture), completed = await completeOfflineChild(active);
    const data = await readChildTerminalData(fixture.driver, fixture.store.artifacts, active.runId);
    assert.equal(data.run.status, 'completed_unverified'); assert.equal(data.allocation.state, 'child_terminal');
    assert.equal(data.result?.runId, active.runId); assert.equal(data.result?.baseSourceRef, data.spec.baseWorkspaceManifestRef);
    assert.equal(canonicalSha256(data.result), completed.resultRef);
    assert.equal(completed.run.resultRef, completed.resultRef);
    assert.equal(data.modelContent.childRunId, active.runId); assert.equal(data.modelContent.mode, mode);
    assert.deepEqual(canonicalJsonBytes(data.inclusiveBudgetUsage), canonicalJsonBytes(completed.run.budgetConsumed));
    assert.equal(data.summary?.utf8, 'The child inspection is complete.');
    assert.deepEqual(data.modelContent.content, { status: 'completed_unverified', summary: data.summary!.utf8 });
    if (mode === 'mutating') { assert.equal(data.patch?.childRunId, active.runId); assert.deepEqual(data.patch?.operations, []); }
    else assert.equal(data.patch, undefined);
    assert.deepEqual(canonicalJsonBytes(fixture.store.getRun(fixture.runId)), parent);
    assert.deepEqual(canonicalJsonBytes(fixture.store.getSession(data.run.sessionId)), session);
    data.assertUnchanged(fixture.driver);
    const original = fixture.driver.prepare('SELECT row_json FROM child_allocations WHERE child_run_id = ?')
      .get<{ row_json: string }>(active.runId)!.row_json;
    const trigger = fixture.driver.prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='child_allocations_validate_update'")
      .get<{ sql: string }>()!.sql;
    const replace = (row: string) => fixture.driver.transaction(connection => {
      assert.equal(connection.prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='child_allocations_validate_update'")
        .get<{ sql: string }>()!.sql, trigger);
      connection.exec('DROP TRIGGER child_allocations_validate_update');
      connection.prepare('UPDATE child_allocations SET row_json = ? WHERE child_run_id = ?').run(row, active.runId);
      connection.exec(trigger);
    });
    const changedUsage = structuredClone(data.allocation);
    changedUsage.inclusiveBudgetUsage.modelTokens++;
    assert(changedUsage.inclusiveBudgetUsage.modelTokens <= changedUsage.grantedAdditiveCeilings.modelTokens);
    const changedContent = structuredClone(data.allocation);
    const anotherContent = childResultModelContent('another-child', mode, { status: 'completed_unverified', summary: data.summary!.utf8 });
    changedContent.terminal.modelContentRef = (await fixture.store.artifacts.publishCanonical(anotherContent, anotherContent.format)).ref;
    changedContent.terminal.modelContentDigest = anotherContent.contentDigest;
    const corrupt: ChildAllocationV1[] = [changedUsage, changedContent];
    if (mode === 'mutating') {
      const changedPatch = structuredClone(data.allocation);
      if (!('patchManifestRef' in changedPatch.terminal)) throw new Error('actual mutating patch fixture is required');
      const wrong = { ...data.patch!, childRunId: 'another-child', patchDigest: '' }; wrong.patchDigest = digestOmitting(wrong, 'patchDigest');
      changedPatch.terminal.patchManifestRef = (await fixture.store.artifacts.publishCanonical(wrong, 'cliq-child-patch-manifest-v1')).ref;
      corrupt.push(changedPatch);
    }
    for (const altered of corrupt) {
      replace(canonicalJsonBytes(altered).toString('utf8'));
      try {
        await assert.rejects(readChildTerminalData(fixture.driver, fixture.store.artifacts, active.runId));
        assert.throws(() => data.assertUnchanged(fixture.driver));
      } finally { replace(original); }
      data.assertUnchanged(fixture.driver);
      assert.equal((await readChildTerminalData(fixture.driver, fixture.store.artifacts, active.runId)).modelContent.contentDigest,
        data.modelContent.contentDigest);
    }
    const { rename, stat } = await import('node:fs/promises'), path = await import('node:path');
    const summaryPath = path.join(fixture.stateRoot, 'cas', data.result!.summaryRef);
    const retained = path.join(fixture.stateRoot, `held-${mode}-child-summary`);
    await rename(summaryPath, retained);
    try {
      await assert.rejects(readChildTerminalData(fixture.driver, fixture.store.artifacts, active.runId));
      await assert.rejects(stat(summaryPath), { code: 'ENOENT' });
    } finally { await rename(retained, summaryPath); }
    data.assertUnchanged(fixture.driver);
    await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    const restored = await readChildTerminalData(Reflect.get(fixture.store, 'driver') as SqliteDriver, fixture.store.artifacts, active.runId);
    assert.deepEqual(canonicalJsonBytes(restored.result), canonicalJsonBytes(data.result));
    assert.deepEqual(canonicalJsonBytes(restored.modelContent), canonicalJsonBytes(data.modelContent));
    assert.deepEqual(canonicalJsonBytes(restored.allocation), canonicalJsonBytes(data.allocation));
    assert.deepEqual(canonicalJsonBytes(fixture.store.getRun(fixture.runId)), parent);
    assert.deepEqual(canonicalJsonBytes(fixture.store.getSession(restored.run.sessionId)), session);
  } finally { await disposeFixture(fixture); }
});
