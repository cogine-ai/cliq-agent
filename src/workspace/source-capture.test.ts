import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, link, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { setImmediate as scheduleImmediate } from 'node:timers';
import { sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceEntryManifest } from '../kernel/types.js';
import { ArtifactCatalog } from '../state/artifacts.js';
import { ContentAddressedStore } from '../state/cas.js';
import { loadNativeStateOwner, STATE_OWNER_NATIVE_PATH, type HeldWorkspaceRoot } from '../state/native-owner.js';
import { captureWorkspaceEntries } from './source-capture.js';

async function captureFixture(t: TestContext) {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-source-capture-'));
  const workspace = path.join(container, 'source'), objects = path.join(container, 'objects');
  const roots: HeldWorkspaceRoot[] = [], unreadableDirectories: string[] = [];
  t.after(async () => {
    for (const root of roots) root.close();
    for (const directory of unreadableDirectories) await chmod(directory, 0o700);
    await rm(container, { recursive: true, force: true });
  });
  await mkdir(workspace); await mkdir(objects, { mode: 0o700 });
  const native = await loadNativeStateOwner();
  return { container, workspace, artifacts: new ArtifactCatalog(new ContentAddressedStore(objects)),
    async excludeDirectory(directory: string) { unreadableDirectories.push(directory); await chmod(directory, 0); },
    openRoot() { const root = native.openWorkspaceRoot(workspace); roots.push(root); return root; } };
}

test('source enumeration is metadata-only and a selected hardlink streams real bytes independently', async t => {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-source-capture-'));
  const workspace = path.join(container, 'source');
  let root: HeldWorkspaceRoot | undefined;
  t.after(async () => { root?.close(); await rm(container, { recursive: true, force: true }); });
  await mkdir(workspace);
  await writeFile(path.join(workspace, 'selected'), 'before\n');
  await link(path.join(workspace, 'selected'), path.join(workspace, 'other-link'));
  await writeFile(path.join(workspace, 'excluded'), 'must not be read');
  await chmod(path.join(workspace, 'excluded'), 0);
  await mkdir(path.join(workspace, 'empty'));
  root = (await loadNativeStateOwner()).openWorkspaceRoot(workspace);
  const cursor = root.openSnapshot();
  try {
    const paths: string[] = [];
    for (;;) {
      const entry = cursor.next();
      if (entry === null) break;
      try {
        paths.push(entry.path);
        if (entry.path !== 'selected') continue;
        assert.equal(entry.kind, 'file');
        assert.equal(entry.linkCount, 2);
        const reader = entry.openFile();
        try {
          assert.equal(reader.readChunk()!.toString(), 'before\n');
          assert.equal(reader.readChunk(), null);
          reader.assertHeld();
        } finally { reader.close(); }
      } finally { entry.close(); }
    }
    cursor.assertComplete();
    assert.deepEqual(paths.sort(), ['empty', 'excluded', 'other-link', 'selected']);
    assert.equal(await readFile(path.join(workspace, 'selected'), 'utf8'), 'before\n');
  } finally { cursor.close(); }
});

test('selected source files, hardlinks, empty directories and safe links publish real normalized CAS bytes', async t => {
  const { workspace, artifacts, openRoot, excludeDirectory } = await captureFixture(t);
  const bytes = Buffer.alloc(2 * 65536 + 17, 0x62);
  await mkdir(path.join(workspace, '.git'));
  await mkdir(path.join(workspace, '.git', 'objects'));
  await writeFile(path.join(workspace, '.git', 'objects', 'excluded'), 'never ordinary source');
  await excludeDirectory(path.join(workspace, '.git', 'objects'));
  await mkdir(path.join(workspace, 'excluded')); await excludeDirectory(path.join(workspace, 'excluded'));
  await mkdir(path.join(workspace, 'dir')); await mkdir(path.join(workspace, 'empty'));
  await writeFile(path.join(workspace, 'dir', 'a'), bytes, { mode: 0o755 });
  await link(path.join(workspace, 'dir', 'a'), path.join(workspace, 'dir', 'b'));
  await symlink('dir/a', path.join(workspace, 'safe'));
  const before = await stat(path.join(workspace, 'dir', 'a'));
  const root = openRoot();
  const published = await captureWorkspaceEntries(root, artifacts,
    { selectedPaths: ['dir/a', 'dir/b', 'empty', 'safe'], maxEntries: 10, maxBytes: bytes.length * 2 + 5 });
  const manifest = await artifacts.readCanonical<WorkspaceEntryManifest>(published.ref);
  assert.deepEqual(manifest.entries, [
    { path: 'dir', kind: 'directory', mode: 0o755 },
    { path: 'dir/a', kind: 'file', mode: 0o755, size: bytes.length, blobRef: sha256Bytes(bytes) },
    { path: 'dir/b', kind: 'file', mode: 0o755, size: bytes.length, blobRef: sha256Bytes(bytes) },
    { path: 'empty', kind: 'directory', mode: 0o755 },
    { path: 'safe', kind: 'symlink', mode: 0o777, target: 'dir/a', targetDigest: sha256Bytes(Buffer.from('dir/a')) }
  ]);
  assert.equal(manifest.byteCount, bytes.length * 2 + 5);
  assert.deepEqual(await artifacts.readBytes(sha256Bytes(bytes)), bytes);
  assert.deepEqual(await readFile(path.join(workspace, 'dir', 'a')), bytes);
  const after = await stat(path.join(workspace, 'dir', 'a'));
  assert.equal(after.ino, before.ino); assert.equal(after.nlink, 2); assert.equal(after.mode, before.mode);
  assert.equal(after.mtimeMs, before.mtimeMs); assert.equal(after.ctimeMs, before.ctimeMs);
  // A successful capture retires only its cursors/readers, never the caller's root.
  root.assertHeld();
});

test('native source readers bound chunks and reject named entry replacement without following a symlink', async t => {
  const { workspace, openRoot } = await captureFixture(t);
  const bytes = Buffer.alloc(65536 + 9, 0x71);
  await writeFile(path.join(workspace, 'a'), bytes);
  const root = openRoot(), cursor = root.openSnapshot(), entry = cursor.next()!;
  const reader = entry.openFile();
  try {
    assert.equal(reader.readChunk()!.length, 65536);
    assert.equal(reader.readChunk()!.length, 9); assert.equal(reader.readChunk(), null);
    await rename(path.join(workspace, 'a'), path.join(workspace, 'old'));
    await symlink('old', path.join(workspace, 'a'));
    assert.throws(() => reader.readChunk(), /identity changed|closed/);
    assert.throws(() => entry.assertHeld(), /identity changed|closed/);
    assert.throws(() => cursor.assertComplete(), /incomplete|changed/);
    assert.throws(() => entry.openFile.call({}), /invalid opaque source handle/);
  } finally { reader.close(); entry.close(); cursor.close(); }
});

test('source selection is mandatory, exact, bounded and never an implicit recursive directory selection', async t => {
  const { workspace, artifacts, openRoot } = await captureFixture(t);
  await mkdir(path.join(workspace, 'dir')); await writeFile(path.join(workspace, 'dir', 'file'), 'bytes');
  const root = openRoot();
  const capture = (selectedPaths: string[], maxBytes = 5, maxEntries = 10) =>
    captureWorkspaceEntries(root, artifacts, { selectedPaths, maxBytes, maxEntries });
  await assert.rejects(capture(['missing']), /does not exist/);
  await assert.rejects(capture(['dir']), /empty source directory is not empty/);
  await assert.rejects(capture(['dir/file'], 4), /bytes exceed/);
  await chmod(path.join(workspace, 'dir', 'file'), 0);
  await assert.rejects(captureWorkspaceEntries(root, artifacts,
    { selectedPaths: ['dir/file'], maxBytes: 5, maxSingleFileBytes: 4, maxEntries: 10 }), /bytes exceed/);
  await chmod(path.join(workspace, 'dir', 'file'), 0o600);
  await assert.rejects(capture(['dir/file'], 5, 1), /entry limit/);
  for (const invalid of ['../file', '/file', '.git/config', 'dir/../file', 'dir//file', 'dir\\file'])
    await assert.rejects(capture([invalid]), /canonical root-relative/);
  await assert.rejects(capture(['dir/file', 'dir/file']), /duplicate/);
  await assert.rejects(captureWorkspaceEntries(root, artifacts, { maxBytes: 5, maxEntries: 10 } as never), /explicit bounded selection/);
  const empty = await artifacts.readCanonical<WorkspaceEntryManifest>((await capture([])).ref);
  assert.deepEqual(empty.entries, []);
  const exact = await artifacts.readCanonical<WorkspaceEntryManifest>((await capture(['dir/file'])).ref);
  assert.equal(exact.byteCount, 5);
});

test('unsafe selected symlink targets and cycles cannot publish a successful source manifest', async t => {
  const { workspace, artifacts, openRoot } = await captureFixture(t);
  await symlink('../outside', path.join(workspace, 'escape'));
  await symlink('.git/config', path.join(workspace, 'git-link'));
  await symlink('b', path.join(workspace, 'a')); await symlink('a', path.join(workspace, 'b'));
  const root = openRoot();
  const capture = (selectedPaths: string[]) => captureWorkspaceEntries(root, artifacts, { selectedPaths, maxBytes: 100, maxEntries: 10 });
  await assert.rejects(capture(['escape']), /escapes/);
  await assert.rejects(capture(['git-link']), /Git metadata/);
  await assert.rejects(capture(['a', 'b']), /cycle/);
});

test('closing a held source root revokes outstanding native entries and readers', async t => {
  const { workspace, openRoot } = await captureFixture(t);
  await writeFile(path.join(workspace, 'a'), 'bytes');
  const root = openRoot(), cursor = root.openSnapshot(), entry = cursor.next()!, reader = entry.openFile();
  root.close();
  assert.throws(() => reader.readChunk(), /changed|closed/);
  assert.throws(() => entry.openFile(), /requires/);
  assert.throws(() => cursor.next(), /changed|closed/);
  reader.close(); entry.close(); cursor.close();
});

test('pre-cancelled source capture rejects without publishing even an empty selection', async t => {
  const { artifacts, openRoot } = await captureFixture(t);
  const root = openRoot(), abort = new AbortController(); abort.abort(new Error('cancel source capture'));
  await assert.rejects(captureWorkspaceEntries(root, artifacts,
    { selectedPaths: [], maxBytes: 0, maxEntries: 1, signal: abort.signal }), /cancel source capture/);
  root.assertHeld();
});

test('selected nested repositories fail closed instead of silently stripping their Git metadata', async t => {
  const { workspace, artifacts, openRoot } = await captureFixture(t);
  await mkdir(path.join(workspace, 'nested')); await mkdir(path.join(workspace, 'nested', '.git'));
  await writeFile(path.join(workspace, 'nested', 'file'), 'bytes');
  const root = openRoot();
  await assert.rejects(captureWorkspaceEntries(root, artifacts,
    { selectedPaths: ['nested/file'], maxBytes: 5, maxEntries: 5 }), /nested Git metadata/);
  await assert.rejects(captureWorkspaceEntries(root, artifacts,
    { selectedPaths: ['nested/.git'], maxBytes: 5, maxEntries: 5 }), /canonical root-relative/);
  // An entirely excluded nested directory is still never opened.
  const empty = await artifacts.readCanonical<WorkspaceEntryManifest>((await captureWorkspaceEntries(root, artifacts,
    { selectedPaths: [], maxBytes: 0, maxEntries: 5 })).ref);
  assert.deepEqual(empty.entries, []);
});

test('excluded-only metadata inventory yields before completion and observes cancellation', async t => {
  const { workspace, artifacts, openRoot } = await captureFixture(t);
  for (let i = 0; i < 200; i++) await writeFile(path.join(workspace, `excluded-${i}`), 'excluded');
  const abort = new AbortController(), reason = new Error('cancel metadata-only capture');
  const capturing = captureWorkspaceEntries(openRoot(), artifacts,
    // Without cooperative metadata yields the second excluded sibling reaches
    // the hard inventory limit before the event-loop cancellation can run.
    { selectedPaths: [], maxBytes: 0, maxEntries: 1, signal: abort.signal });
  scheduleImmediate(() => abort.abort(reason));
  await assert.rejects(capturing, reason);
});

test('caller-shaped source roots cannot mint captured filesystem bytes', async t => {
  const { artifacts } = await captureFixture(t);
  const fake: HeldWorkspaceRoot = {
    identity: { deviceId: '1', fileId: '2', ownerUid: process.getuid!() },
    assertHeld() {}, readGitConfigChunk() { return null; }, close() {},
    openSnapshot() { return { next() { return null; }, assertComplete() {}, close() {} }; }
  };
  await assert.rejects(captureWorkspaceEntries(fake, artifacts,
    { selectedPaths: [], maxBytes: 0, maxEntries: 1 }), /source workspace handle/);
});

test('actual Worker termination retires live source parent, cursor, entry and reader handles safely', { timeout: 20_000 }, async t => {
  const { workspace } = await captureFixture(t);
  await mkdir(path.join(workspace, 'dir')); await writeFile(path.join(workspace, 'dir', 'file'), 'bytes');
  const workerCode = `
    const { parentPort, workerData } = require('node:worker_threads');
    const native = require(workerData.helperPath);
    const root = native.openWorkspaceRoot(workerData.workspace);
    const cursor = root.openSnapshot();
    const directory = cursor.next();
    if (directory.path !== 'dir') throw new Error('actual source directory missing');
    const child = directory.openDirectory(), entry = child.next(), reader = entry.openFile();
    if (reader.readChunk().toString() !== 'bytes') throw new Error('actual source read missing');
    globalThis.handles = { root, cursor, directory, child, entry, reader };
    if (workerData.closeRoot) root.close();
    parentPort.postMessage('ready');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  `;
  const code = `
    import assert from 'node:assert/strict';
    import { Worker } from 'node:worker_threads';
    for (let round = 0; round < 8; round++) {
      const worker = new Worker(${JSON.stringify(workerCode)}, { eval: true, execArgv: [],
        workerData: { workspace: process.argv[1], helperPath: ${JSON.stringify(STATE_OWNER_NATIVE_PATH)}, closeRoot: round % 2 === 1 } });
      const exited = new Promise(resolve => worker.once('exit', resolve));
      await new Promise((resolve, reject) => {
        worker.once('message', value => { try { assert.equal(value, 'ready'); resolve(); } catch (error) { reject(error); } });
        worker.once('error', reject);
      });
      assert.equal(await worker.terminate(), 1); assert.equal(await exited, 1);
    }
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code, workspace], { stdio: ['ignore', 'ignore', 'pipe'] });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  let stderr = '';
  child.stderr!.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-6000); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 15_000);
  t.after(async () => {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
  });
  const result = await exited;
  clearTimeout(timer);
  assert.equal(result.signal, null, `source environment teardown crashed: ${stderr}`);
  assert.equal(result.code, 0, stderr);
});
