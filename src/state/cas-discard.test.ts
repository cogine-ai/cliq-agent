import assert from 'node:assert/strict';
import { constants, promises as fs, renameSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { Worker } from 'node:worker_threads';
import { channel } from 'node:diagnostics_channel';
import { ArtifactCatalog } from './artifacts.js';
import { INSTALLED_BUILTIN_WORK_CHANNEL, noteInstalledBuiltinWorkPhase } from './installed-work-diagnostics.js';
import ts from 'typescript';
import { ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';
import { discardCasChunks } from './cas-discard.js';

async function fixture(t: TestContext, size = 8 * 1024 * 1024) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-cas-discard-'));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const root = path.join(home, 'objects'); await fs.mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root), ref = await cas.publish(Buffer.alloc(size, 0x73));
  return { home, root, cas, ref, size, filename: path.join(root, ref) };
}

test('whole-object discard verification uses the joined large reader and rereads after settlement', async t => {
  const f = await fixture(t), actualOpen = fs.open.bind(fs), held = new Set<object>();
  let mainThreadReads = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); held.add(handle);
    const close = handle.close.bind(handle);
    t.mock.method(handle, 'close', async () => { await close(); assert(held.delete(handle)); });
    if (args[0] === f.filename) {
      const read = handle.read.bind(handle);
      t.mock.method(handle, 'read', async (...args: Parameters<typeof read>) => { mainThreadReads++; return read(...args); });
    }
    return handle;
  });
  assert.deepEqual(await f.cas.verify(f.ref), { ref: f.ref, byteLength: f.size });
  assert.equal(held.size, 0, 'the original root and file must close after actual worker exit');
  assert.equal(mainThreadReads, 0, 'whole-object recovery must use the same bounded off-thread discard reader');
  t.mock.restoreAll();
  await fs.chmod(f.filename, 0o600);
  const file = await fs.open(f.filename, 'r+');
  try { await file.write(Buffer.from([0x74]), 0, 1, f.size - 1); } finally { await file.close(); }
  await fs.chmod(f.filename, 0o400);
  await assert.rejects(f.cas.verify(f.ref), /digest/, 'the final byte of a later read must still be checked');
});

test('discard verification rereads complete real bytes and refuses size, corruption and link changes', async t => {
  const f = await fixture(t);
  await f.cas.verifyChunks(f.ref, f.size);
  await assert.rejects(f.cas.verifyChunks(f.ref, f.size + 1));
  await fs.link(f.filename, path.join(f.home, 'extra-link'));
  await assert.rejects(f.cas.verifyChunks(f.ref, f.size));
  await fs.unlink(path.join(f.home, 'extra-link'));
  await fs.chmod(f.filename, 0o600);
  await assert.rejects(f.cas.verifyChunks(f.ref, f.size));
  const file = await fs.open(f.filename, 'r+');
  try { await file.write(Buffer.from([0x74]), 0, 1, 0); } finally { await file.close(); }
  await fs.chmod(f.filename, 0o400);
  await assert.rejects(f.cas.verifyChunks(f.ref, f.size), /digest/);
  await assert.rejects(async () => { for await (const _chunk of f.cas.readChunks(f.ref, f.size)) {} }, /corrupt/);
});

for (const boundary of ['same_object', 'different_inode', 'different_signal'] as const)
test(`live discard sharing preserves the ${boundary} boundary and never retains a completed read`, async t => {
  const f = await fixture(t), other = path.join(f.root, 'other');
  if (boundary === 'different_inode') await fs.copyFile(f.filename, other);
  const handles: Awaited<ReturnType<typeof fs.open>>[] = [];
  try {
    handles.push(await fs.open(f.filename, 'r'));
    handles.push(await fs.open(boundary === 'different_inode' ? other : f.filename, 'r'));
    const rootInfo = await fs.lstat(f.root), infos = await Promise.all(handles.map(file => file.stat()));
    // Synchronize only the completion of two genuine descriptor stats. Both
    // callers then enter before any worker can reply; no digest/read/exit is
    // fabricated and the production worker consumes the actual file bytes.
    let entered = 0, release!: () => void;
    const together = new Promise<void>(resolve => { release = resolve; });
    for (const handle of handles) {
      const stat = handle.stat.bind(handle); let first = true;
      t.mock.method(handle, 'stat', async (...args: Parameters<typeof stat>) => {
        const info = await stat(...args);
        if (first) { first = false; if (++entered === 2) release(); await together; }
        return info;
      });
    }
    const signals = [new AbortController().signal, new AbortController().signal];
    let bytes = 0;
    const verify = (index: number) => discardCasChunks({ file: { handle: handles[index]!, info: infos[index]! },
      rootPath: f.root, rootInfo, ref: f.ref, byteLength: f.size },
    signals[boundary === 'different_signal' ? index : 0], count => { bytes += count; });
    await Promise.all([verify(0), verify(1)]);
    assert.equal(bytes, f.size * (boundary === 'same_object' ? 1 : 2));
    await verify(0);
    assert.equal(bytes, f.size * (boundary === 'same_object' ? 2 : 3), 'a settled read is never reused');
    for (const handle of handles) assert((await handle.stat()).isFile(), 'each caller still owns its original descriptor');
  } finally { await Promise.all(handles.map(handle => handle.close())); }
});

test('four discard slots include original FD closes and aborted queued work opens nothing', async t => {
  const f = await fixture(t), actualOpen = fs.open.bind(fs), active = new Set<object>();
  let release!: () => void, enter!: () => void, roots = 0, held = 0, peak = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { enter = resolve; });
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); active.add(handle); peak = Math.max(peak, active.size);
    if (args[0] === f.root) roots++;
    const close = handle.close.bind(handle);
    t.mock.method(handle, 'close', async () => {
      await close(); assert(active.delete(handle));
      if (args[0] === f.filename) { held++; if (held === 4) enter(); await gate; }
    });
    return handle;
  });
  const first = Array.from({ length: 4 }, () => f.cas.verifyChunks(f.ref, f.size));
  const abort = new AbortController(), reason = new Error('queued observer stopped');
  const queued = f.cas.verifyChunks(f.ref, f.size, abort.signal);
  void queued.catch(() => {});
  try {
    await entered; abort.abort(reason); await assert.rejects(queued, error => error === reason);
    assert.equal(roots, 4); assert(peak <= 8);
    assert.equal(active.size, 4, 'original root handles remain held until file closes join');
    release(); await Promise.all(first); assert.equal(active.size, 0);
    t.mock.restoreAll(); await f.cas.verifyChunks(f.ref, f.size);
  } finally { release(); await Promise.allSettled([...first, queued]); t.mock.restoreAll(); }
});

test('discard corruption still joins both real handles and preserves an original close failure', async t => {
  const f = await fixture(t), actualOpen = fs.open.bind(fs), active = new Set<object>(), failure = new Error('original close failed');
  await fs.chmod(f.filename, 0o600); await fs.writeFile(f.filename, Buffer.alloc(f.size, 0x74)); await fs.chmod(f.filename, 0o400);
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); active.add(handle); const close = handle.close.bind(handle);
    t.mock.method(handle, 'close', async () => {
      await close(); assert(active.delete(handle)); if (args[0] === f.filename) throw failure;
    });
    return handle;
  });
  await assert.rejects(f.cas.verifyChunks(f.ref, f.size), error => error instanceof ResourceRetirementError && error.cause === failure);
  assert.equal(active.size, 0);
});

// Run the exact production data-worker source over self-owned real FDs. The
// counter observes actual returned bytes; no process is paused and no native
// authority, Run, clock or recovery proof is manufactured.
for (const fault of ['cancel', 'root_move'] as const) test(`actual discard reader ${fault} after real bytes joins its original thread`, async t => {
  const f = await fixture(t);
  const source = await fs.readFile(new URL('./cas-discard.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('cas-discard.ts', source, ts.ScriptTarget.Latest, true);
  const declaration = parsed.statements.filter(ts.isVariableStatement).flatMap(value => [...value.declarationList.declarations])
    .find(value => value.name.getText(parsed) === 'CAS_DISCARD_SOURCE');
  assert(declaration?.initializer);
  const code = Function(`return (${declaration.initializer.getText(parsed)})`)() as string;
  const root = await fs.open(f.root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const file = await fs.open(f.filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  const info = await file.stat(), rootInfo = await root.stat();
  const before = Object.fromEntries(['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeMs', 'ctimeMs']
    .map(key => [key, info[key as keyof typeof info]]));
  const control = new SharedArrayBuffer(16), bytes = new BigInt64Array(control, 8, 1), stop = new Int32Array(control, 0, 1);
  // Cancel immediately after an actual readSync returns, inside this data-only
  // test Worker. No fabricated bytes, paused process or scheduler race is used.
  const injection = fault === 'cancel' ? `{
    const fs = require('node:fs'), original = fs.readSync, job = require('node:worker_threads').workerData;
    fs.readSync = (...args) => { const count = Reflect.apply(original, fs, args);
      if (args[0] === job.fd && count > 0) Atomics.store(new Int32Array(job.control, 0, 1), 0, 1);
      return count; };
  }` : '';
  const moved = path.join(f.home, 'moved');
  if (fault === 'root_move') renameSync(f.root, moved);
  const worker = new Worker(injection + code, { eval: true, execArgv: [], env: {}, workerData: { control, before,
    fd: file.fd, uid: info.uid, rootPath: f.root, rootDev: rootInfo.dev, rootIno: rootInfo.ino, ref: f.ref, byteLength: f.size } });
  let reply: unknown, error: unknown;
  worker.on('message', value => { reply = value; }); worker.on('error', value => { error = value; });
  const exit = new Promise<number>(resolve => worker.once('exit', resolve));
  try {
    assert.equal(await exit, 0); assert.equal(error, undefined);
    assert(fault === 'cancel' ? reply === 'cancelled' : reply === 'read' || reply === 'root');
    assert.equal(Atomics.load(bytes, 0), 65536n, 'the original reader must stop after its actual first chunk');
    assert.equal((await file.stat()).ino, info.ino, 'the original borrowed descriptor is still held after thread exit');
  } finally {
    Atomics.store(stop, 0, 1); await exit;
    if (fault === 'root_move') renameSync(moved, f.root);
    await file.close(); await root.close();
  }
});


test('nested catalog views preserve the same cancellation lifetime for one live full read', async t => {
  const f = await fixture(t), catalog = new ArtifactCatalog(f.cas), owner = new AbortController();
  const reads = catalog.withReadSignal(owner.signal), actualOpen = fs.open.bind(fs), active = new Set<object>();
  const packets: Array<{ returnedBytes: number }> = [];
  const diagnostic = channel(INSTALLED_BUILTIN_WORK_CHANNEL), receive = (value: unknown) => packets.push(value as typeof packets[number]);
  diagnostic.subscribe(receive); t.after(() => diagnostic.unsubscribe(receive));
  let entered = 0, release!: () => void;
  const together = new Promise<void>(resolve => { release = resolve; });
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); active.add(handle);
    const close = handle.close.bind(handle), stat = handle.stat.bind(handle); let gated = false;
    t.mock.method(handle, 'close', async () => { await close(); assert(active.delete(handle)); });
    if (args[0] === f.filename) t.mock.method(handle, 'stat', async (...args: Parameters<typeof stat>) => {
      const info = await stat(...args);
      if (args[0]?.bigint && !gated) { gated = true; if (++entered === 2) release(); await together; }
      return info;
    });
    return handle;
  });
  noteInstalledBuiltinWorkPhase('tool_select'); const before = packets.at(-1)!.returnedBytes;
  const timer = setTimeout(release, 2000);
  try {
    // The signed guest reader receives a signal-bound catalog and applies the
    // same original signal again. It must not invent a distinct lifetime.
    await Promise.all([reads.withReadSignal(owner.signal).verifyChunks(f.ref, f.size),
      reads.withReadSignal(owner.signal).verifyChunks(f.ref, f.size)]);
    assert.equal(entered, 2); assert.equal(active.size, 0);
    noteInstalledBuiltinWorkPhase('tool_prepare');
    assert.equal(packets.at(-1)!.returnedBytes - before, f.size, 'same-lifetime concurrent consumers share only the live full hash');
    await reads.withReadSignal(owner.signal).verifyChunks(f.ref, f.size);
    noteInstalledBuiltinWorkPhase('tool_claim');
    assert.equal(packets.at(-1)!.returnedBytes - before, 2 * f.size, 'a later consumer still reads every byte again');
    const child = new AbortController(), tighter = reads.withReadSignal(child.signal), childReason = new Error('child stopped');
    child.abort(childReason); await assert.rejects(tighter.verifyChunks(f.ref, f.size), error => error === childReason);
    await reads.verifyChunks(f.ref, f.size);
    const parentReason = new Error('original owner stopped'); owner.abort(parentReason);
    await assert.rejects(reads.withReadSignal(owner.signal).verifyChunks(f.ref, f.size), error => error === parentReason);
    assert.equal(active.size, 0);
  } finally { clearTimeout(timer); release(); }
});
