import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, open, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { identityHash } from '../../kernel/identity.js';
import { loadNativeStateOwner, openGenerationFileWriter, openGenerationSnapshot, STATE_OWNER_NATIVE_PATH } from '../../state/native-owner.js';

test('a maximum-length valid nested private tree does not exhaust the Supervisor C stack', { timeout: 120_000 }, async (t) => {
  // Keep this >PATH_MAX fixture out of backed-up workspaces. Resolve macOS's
  // /var symlink because the native StateOwner rejects symlink ancestors.
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-deep-'));
  await chmod(root, 0o700);
  const nativeModule = new URL('../../state/native-owner.ts', import.meta.url).href;
  const identityModule = new URL('../../kernel/identity.ts', import.meta.url).href;
  const code = `
    import { mkdirSync, chmodSync } from 'node:fs';
    import { loadNativeStateOwner, openGenerationSnapshot } from ${JSON.stringify(nativeModule)};
    import { identityHash } from ${JSON.stringify(identityModule)};
    const native = await loadNativeStateOwner();
    const lock = native.acquireLock(process.argv[1], true);
    const generationId = identityHash('deep-generation');
    const tree = lock.createGenerationTree('deep-run', generationId);
    try {
      process.chdir(process.argv[1] + '/runs/deep-run/generations/' + generationId);
      let relative = '';
      for (let depth = 0; depth < 2000; depth++) {
        relative += relative ? '/d' : 'd';
        mkdirSync('d', {mode:0o755}); chmodSync('d', 0o755); process.chdir('d');
      }
      process.chdir(process.argv[1]);
      const snapshot = openGenerationSnapshot(tree);
      try {
        let count = 0, finalPath = '';
        for (;;) { const entry = snapshot.next(); if(entry === null) break; count++; finalPath = entry.path; }
        snapshot.assertComplete();
        if (count !== 2000 || finalPath.length !== 3999) throw new Error('deep tree was truncated');
      } finally { snapshot.close(); }
    } finally { tree.close(); lock.close(); }
  `;
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code, root], { stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  let stderr = '';
  child.stderr!.on('data', bytes => { if (stderr.length < 6000) stderr += bytes.toString().slice(0, 6000 - stderr.length); });
  child.stdout!.resume();
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
    // BSD/POSIX rm walks deep directories descriptor-relatively; Node's
    // absolute-path recursive rm cannot clean a >PATH_MAX test hierarchy.
    const removed = spawnSync('rm', ['-r', '--', root], { encoding: 'utf8' });
    assert.equal(removed.status, 0, removed.stderr);
  });
  const result = await exited;
  assert.equal(result.signal, null, `native tree traversal crashed: ${stderr}`);
  assert.equal(result.code, 0, stderr);
});

test('terminating isolated worker environments releases live private tree children without crashing the host', { timeout: 30_000 }, async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-teardown-'));
  await chmod(root, 0o700);
  const workerCode = `
    const { parentPort, workerData } = require('node:worker_threads');
    const native = require(workerData.helperPath);
    const held = native.acquireLock(workerData.root, true);
    const handles = [];
    for (const generationId of workerData.ids) {
      const tree = held.createGenerationTree('teardown-read', generationId);
      const writer = tree.openFileWriter('bytes', 0o644, 3);
      writer.writeChunk(Buffer.from('abc')); writer.finish();
      const borrow = tree.borrow();
      const snapshot = tree.openSnapshot();
      const entry = snapshot.next();
      if (entry.kind !== 'file' || entry.file.readChunk().toString() !== 'abc') throw new Error('actual native reader missing');
      const other = held.createGenerationTree('teardown-write', generationId);
      const partial = other.openFileWriter('unfinished', 0o644, 2);
      partial.writeChunk(Buffer.from('a'));
      handles.push({ tree, writer, borrow, snapshot, entry, other, partial });
    }
    globalThis.handles = { held, handles };
    if (workerData.closeOwner) held.close();
    parentPort.postMessage('ready');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  `;
  const code = `
    import assert from 'node:assert/strict';
    import { Worker } from 'node:worker_threads';
    import { createRequire } from 'node:module';
    const require = createRequire(import.meta.url);
    const native = require(${JSON.stringify(STATE_OWNER_NATIVE_PATH)});
    const ids = ${JSON.stringify(Array.from({ length: 8 }, (_, i) => identityHash('teardown-generation', String(i))))};
    for (let round = 0; round < 8; round++) {
      const worker = new Worker(${JSON.stringify(workerCode)}, { eval: true, execArgv: [],
        workerData: { root: process.argv[1], helperPath: ${JSON.stringify(STATE_OWNER_NATIVE_PATH)},
          ids: ids.map(id => id.slice(0, -1) + String(round)), closeOwner: round % 2 === 1 } });
      const exited = new Promise(resolve => worker.once('exit', resolve));
      await new Promise((resolve, reject) => { worker.once('message', value => {
        try { assert.equal(value, 'ready'); resolve(); } catch (error) { reject(error); }
      }); worker.once('error', reject); });
      assert.equal(await worker.terminate(), 1);
      assert.equal(await exited, 1);
      const successor = native.acquireLock(process.argv[1], false);
      try { successor.assertHeld(); } finally { successor.close(); }
    }
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code, root], { stdio: ['ignore', 'ignore', 'pipe'] });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  let stderr = '';
  child.stderr!.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-6000); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 25_000);
  t.after(async () => {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
    await rm(root, { recursive: true, force: true });
  });
  const result = await exited;
  clearTimeout(timer);
  assert.equal(result.signal, null, `private tree environment teardown crashed: ${stderr}`);
  assert.equal(result.code, 0, stderr);
});

test('an actual large private file is observed through bounded native-held chunks', async (t) => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-generation-stream-'));
  await chmod(root, 0o700);
  const native = await loadNativeStateOwner();
  const lock = native.acquireLock(root, true);
  const generationId = identityHash('stream-generation');
  const tree = lock.createGenerationTree('stream-run', generationId);
  t.after(async () => { tree.close(); lock.close(); await rm(root, { recursive: true, force: true }); });
  const file = await open(path.join(root, 'runs/stream-run/generations', generationId, 'large.bin'), 'wx', 0o644);
  const block = Buffer.alloc(64 * 1024, 0x71);
  const expected = createHash('sha256');
  try {
    for (let index = 0; index < 1024; index++) { await file.write(block); expected.update(block); }
    await file.sync();
  } finally { await file.close(); }
  const { openGenerationSnapshot } = await import('../../state/native-owner.js');
  const snapshot = openGenerationSnapshot(tree);
  try {
    assert.throws(() => snapshot.assertComplete(), /not complete/);
    const entry = snapshot.next();
    assert.equal(entry?.kind, 'file');
    if (entry?.kind !== 'file') throw new Error('actual file was not observed');
    assert.equal(entry.byteCount, 64 * 1024 * 1024);
    const observed = createHash('sha256');
    let count = 0;
    try {
      for (;;) {
        const chunk = entry.file.readChunk();
        if (chunk === null) break;
        assert.ok(chunk.byteLength > 0 && chunk.byteLength <= 64 * 1024);
        count += chunk.byteLength; observed.update(chunk);
        await new Promise<void>(resolve => setImmediate(resolve));
        entry.file.assertHeld();
      }
    } finally { entry.file.close(); }
    assert.equal(count, 64 * 1024 * 1024);
    assert.equal(observed.digest('hex'), expected.digest('hex'));
    assert.equal(snapshot.next(), null);
    snapshot.assertComplete();
  } finally { snapshot.close(); }
});

test('a real file above the default source byte budget still uses bounded native streaming', { timeout: 120_000 }, async (t) => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-generation-large-stream-'));
  await chmod(root, 0o700);
  const lock = (await loadNativeStateOwner()).acquireLock(root, true);
  const tree = lock.createGenerationTree('large-stream-run', identityHash('large-stream-generation'));
  t.after(async () => { tree.close(); lock.close(); await rm(root, { recursive: true, force: true }); });
  const block = Buffer.alloc(64 * 1024, 0x5b);
  const byteCount = 8193 * block.length; // 512 MiB + 64 KiB, not a sparse file.
  const expected = createHash('sha256');
  const writer = openGenerationFileWriter(tree, 'above-default.bin', 0o644, byteCount);
  try {
    for (let index = 0; index < 8193; index++) {
      writer.writeChunk(block); expected.update(block);
      await new Promise<void>(resolve => setImmediate(resolve));
      writer.assertHeld();
    }
    writer.finish();
  } finally { writer.close(); }
  const snapshot = openGenerationSnapshot(tree);
  try {
    const entry = snapshot.next();
    assert.equal(entry?.kind, 'file');
    if (entry?.kind !== 'file') throw new Error('actual large file was not observed');
    assert.equal(entry.byteCount, byteCount);
    let observedByteCount = 0;
    const observed = createHash('sha256');
    try {
      for (;;) {
        const chunk = entry.file.readChunk();
        if (chunk === null) break;
        assert.ok(chunk.byteLength > 0 && chunk.byteLength <= 64 * 1024);
        observedByteCount += chunk.length; observed.update(chunk);
        await new Promise<void>(resolve => setImmediate(resolve));
        entry.file.assertHeld();
      }
    } finally { entry.file.close(); }
    assert.equal(observedByteCount, byteCount);
    assert.equal(observed.digest('hex'), expected.digest('hex'));
    assert.equal(snapshot.next(), null); snapshot.assertComplete();
  } finally { snapshot.close(); }
});
