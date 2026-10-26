import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { sha256Bytes } from '../kernel/identity.js';
import { ContentAddressedStore } from './cas.js';
import { publishInstalledCasRoots } from './installed-cas-roots.js';

for (const count of [1, 2, 3, 4]) test(`the ${count}-root install group retains all four actual durable stages and joins before returning`, async t => {
  const home = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-install-cas-'))), root = path.join(home, 'cas');
  const originalOpen = fs.open.bind(fs), barriers: string[][] = [];
  let active = 0, fileSyncs = 0;
  try {
    await mkdir(root, { mode: 0o700 });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof originalOpen>) => {
      const handle = await originalOpen(...args); active++;
      const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); active--; });
      t.mock.method(handle, 'sync', async () => { await sync();
        if (args[0] === root) barriers.push((await readdir(root)).sort()); else fileSyncs++;
      });
      return handle;
    });
    const roots = Array.from({ length: count }, (_, i) => {
      const bytes = Buffer.from(`original install root ${i}`); return [sha256Bytes(bytes), bytes] as const;
    });
    const actual = await publishInstalledCasRoots(new ContentAddressedStore(root), roots);
    assert.equal(active, 0);
    assert.equal(fileSyncs, count, 'every original complete file is synchronized');
    assert.equal(barriers.length, 4, 'one shared barrier follows each fully joined original stage');
    assert.equal(barriers[0]!.length, count); assert(barriers[0]!.every(name => /^\.tmp-stream-/.test(name)));
    assert.equal(barriers[1]!.length, count); assert(barriers[1]!.every(name => /^\.tmp-[0-9a-f]{64}-/.test(name)));
    assert.equal(barriers[2]!.length, 2 * count);
    assert.deepEqual(barriers[3], roots.map(([ref]) => ref).sort());
    assert.deepEqual(actual.map(item => item.ref), roots.map(([ref]) => ref));
    for (const [i, [ref, bytes]] of roots.entries()) {
      assert.equal(actual[i]!.byteLength, bytes.length); assert.deepEqual(await readFile(path.join(root, ref)), bytes);
    }
    assert.equal(active, 0);
  } finally { t.mock.restoreAll(); await rm(home, { recursive: true, force: true }); }
});

test('an install group refuses an invalid size before opening a CAS directory', async () => {
  const cas = new ContentAddressedStore('/this-fixture-does-not-exist');
  await assert.rejects(publishInstalledCasRoots(cas, []), TypeError);
  await assert.rejects(publishInstalledCasRoots(cas, Array.from({ length: 5 }, () => ['a'.repeat(64), Buffer.from('a')] as const)), TypeError);
});

test('a mismatched original install ref refuses only after all actual group descriptors have joined', async t => {
  const home = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-install-cas-ref-'))), root = path.join(home, 'cas');
  const originalOpen = fs.open.bind(fs); let active = 0;
  try {
    await mkdir(root, { mode: 0o700 });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof originalOpen>) => {
      const handle = await originalOpen(...args), close = handle.close.bind(handle); active++;
      t.mock.method(handle, 'close', async () => { await close(); active--; }); return handle;
    });
    const bytes = ['one', 'two', 'three', 'four'].map(value => Buffer.from(value));
    const roots = bytes.map((value, i) => [i === 0 ? 'a'.repeat(64) : sha256Bytes(value), value] as const);
    await assert.rejects(publishInstalledCasRoots(new ContentAddressedStore(root), roots), { code: 'ARTIFACT_MISMATCH' });
    assert.equal(active, 0);
    assert.deepEqual((await readdir(root)).sort(), bytes.map(sha256Bytes).sort(), 'only complete immutable, unreferenced objects may remain');
    for (const value of bytes) assert.deepEqual(await readFile(path.join(root, sha256Bytes(value))), value);
  } finally { t.mock.restoreAll(); await rm(home, { recursive: true, force: true }); }
});
