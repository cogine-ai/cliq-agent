// Actual CAS filesystem conformance only; no Run, permission or native proof.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore, isJoinedCasPublicationFailure } from './cas.js';
import { ResourceRetirementError } from './errors.js';

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-admission-cas-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  return { root, store: new ContentAddressedStore(root) };
}

function publish(store: ContentAddressedStore, count: 2 | 3, values: readonly Uint8Array[]) {
  return count === 2 ? store.publishPair(values as [Uint8Array, Uint8Array])
    : store.publishTriple(values as [Uint8Array, Uint8Array, Uint8Array]);
}

for (const count of [2, 3] as const) {
  test(`fixed admission ${count} retains four actual namespace barriers, every file sync and full immutable bytes`, async t => {
    const { root, store } = await fixture(t), open = fs.open.bind(fs);
    const active = new Set<object>(), boundaries: string[][] = []; let files = 0, peak = 0;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args); active.add(handle); peak = Math.max(peak, active.size);
      const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); active.delete(handle); });
      t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === root) boundaries.push((await readdir(root)).sort()); else files++; });
      return handle;
    });
    const values = Array.from({ length: count }, (_, index) => Buffer.from(`complete-${index}`));
    const result = await publish(store, count, values);
    assert.equal(files, count); assert.equal(boundaries.length, 4); assert.equal(active.size, 0);
    assert(peak > 2 && peak <= count + 1);
    assert.equal(boundaries[0]!.length, count);
    assert(boundaries[0]!.every(name => /^\.tmp-stream-[a-f0-9]{32}$/u.test(name)));
    assert.equal(boundaries[1]!.length, count);
    assert(boundaries[1]!.every(name => /^\.tmp-[a-f0-9]{64}-[a-f0-9]{32}$/u.test(name)));
    assert.equal(boundaries[2]!.length, count * 2);
    assert.deepEqual(boundaries[3], result.map(item => item.ref).sort());
    for (const [index, item] of result.entries()) {
      assert.equal(item.byteLength, values[index]!.length);
      assert.deepEqual(await store.read(item.ref), values[index]);
      assert.equal((await stat(path.join(root, item.ref))).nlink, 1);
      assert.equal((await stat(path.join(root, item.ref))).mode & 0o7777, 0o400);
    }
    assert.equal(active.size, 0);
  });

  test(`fixed admission ${count} rejects absent, extra, sparse and non-byte members before root open`, async t => {
    const { root, store } = await fixture(t), bytes = Buffer.from('valid'); let opened = 0;
    t.mock.method(fs, 'open', async () => { opened++; throw new Error('invalid arity cannot open a protected root'); });
    for (const values of [[], [bytes], Array.from({ length: count + 1 }, () => bytes), new Array(count),
      [...Array.from({ length: count - 1 }, () => bytes), undefined]])
      await assert.rejects(publish(store, count, values as Uint8Array[]), TypeError);
    assert.equal(opened, 0); assert.deepEqual(await readdir(root), []);
  });

  test(`fixed admission ${count} preserves canonical labels and repeated refs with independent publishers`, async t => {
    const { root, store } = await fixture(t), catalog = new ArtifactCatalog(store), shared = { identical: 'data' };
    const values = Array.from({ length: count }, (_, index) => ({ value: shared, schemaKind: `distinct-${index}` }));
    const group = count === 2 ? catalog.publishCanonicalPair(values as [typeof values[number], typeof values[number]])
      : catalog.publishCanonicalTriple(values as [typeof values[number], typeof values[number], typeof values[number]]);
    const [groupOutcome, independentOutcome] = await Promise.allSettled([group, new ContentAddressedStore(root).publish(canonicalJsonBytes(shared))]);
    assert(groupOutcome.status === 'fulfilled'); assert(independentOutcome.status === 'fulfilled');
    const result = groupOutcome.value, independent = independentOutcome.value;
    assert(result.every((item, index) => item.ref === independent && item.schemaKind === `distinct-${index}` &&
      item.mediaType === 'application/json' && item.byteLength === canonicalJsonBytes(shared).length));
    assert.deepEqual(await readFile(path.join(root, independent)), canonicalJsonBytes(shared));
    assert.deepEqual(await readdir(root), [independent]);
    assert.equal((await stat(path.join(root, independent))).nlink, 1);
  });

  for (const mutation of ['rename', 'link', 'unlink'] as const) {
    test(`fixed admission ${count} joins actual ${mutation} mutations before its barrier and cleanup`, async t => {
      const { root, store } = await fixture(t), open = fs.open.bind(fs);
      const actual = fs[mutation].bind(fs) as (...args: string[]) => Promise<void>;
      const failure = new Error('an actual namespace mutation reported failure after taking effect');
      let entered!: () => void, release!: () => void;
      const pendingGate = new Promise<void>(resolve => { entered = resolve; });
      const gate = new Promise<void>(resolve => { release = resolve; });
      let starts = 0, completed = 0, syncs = 0, settled = false; const active = new Set<object>();
      t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
        const handle = await open(...args); active.add(handle);
        const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
        t.mock.method(handle, 'close', async () => { await close(); active.delete(handle); });
        if (args[0] === root) t.mock.method(handle, 'sync', async () => { await sync(); syncs++; });
        return handle;
      });
      t.mock.method(fs, mutation, async (...args: string[]) => {
        const ordinal = starts++; await actual(...args);
        if (ordinal === count - 1) { entered(); await gate; }
        completed++; if (ordinal === 0) throw failure;
      });
      const pending = publish(store, count, Array.from({ length: count }, (_, index) => Buffer.from(`owned-${index}`)));
      void pending.then(() => { settled = true; }, () => { settled = true; });
      try {
        await pendingGate;
        assert.equal(starts, count); assert.equal(settled, false);
        assert.equal(syncs, mutation === 'rename' ? 1 : mutation === 'link' ? 2 : 3);
        release();
        await assert.rejects(pending, error => mutation === 'unlink'
          ? error instanceof ResourceRetirementError && error.cause === failure : error === failure);
        assert(completed >= count); assert.equal(active.size, 0);
        assert.equal(syncs, mutation === 'rename' ? 3 : 4);
        assert((await readdir(root)).every(name => /^[a-f0-9]{64}$/u.test(name)));
        assert.equal(isJoinedCasPublicationFailure(failure), false);
      } finally { release(); await Promise.allSettled([pending]); }
    });
  }

  for (const boundary of [1, 2, 3, 4]) {
    test(`fixed admission ${count} refuses real directory barrier ${boundary} failure after complete cleanup join`, async t => {
      const { root, store } = await fixture(t), open = fs.open.bind(fs), failure = new Error('real root sync returned uncertainty');
      let roots = 0; const active = new Set<object>();
      t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
        const handle = await open(...args); active.add(handle);
        const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
        t.mock.method(handle, 'close', async () => { await close(); active.delete(handle); });
        if (args[0] === root) t.mock.method(handle, 'sync', async () => { await sync(); if (++roots === boundary) throw failure; });
        return handle;
      });
      await assert.rejects(publish(store, count, Array.from({ length: count }, (_, index) => Buffer.from(`barrier-${index}`))),
        error => error instanceof ResourceRetirementError);
      assert.equal(active.size, 0);
      assert((await readdir(root)).every(name => /^[a-f0-9]{64}$/u.test(name)));
      assert(roots >= boundary);
    });
  }

  test(`fixed admission ${count} still hashes every completed final file rather than trusting successful sync`, async t => {
    const { root, store } = await fixture(t), open = fs.open.bind(fs); let roots = 0, damaged = false, damagedRef = '';
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args), sync = handle.sync.bind(handle);
      if (args[0] === root) t.mock.method(handle, 'sync', async () => {
        await sync();
        if (++roots === 4) {
          const name = (await readdir(root)).find(item => /^[a-f0-9]{64}$/u.test(item))!;
          damagedRef = name;
          const filename = path.join(root, name), bytes = await readFile(filename); bytes[0] = bytes[0]! ^ 1;
          await chmod(filename, 0o600); await writeFile(filename, bytes); await chmod(filename, 0o400); damaged = true;
        }
      });
      return handle;
    });
    await assert.rejects(publish(store, count, Array.from({ length: count }, (_, index) => Buffer.from(`hashed-${index}`))),
      error => error instanceof Error && error.message === `artifact ${damagedRef} is corrupt`);
    assert.equal(damaged, true);
  });

  for (const retirement of [false, true]) {
    test(`fixed admission ${count} joins all actual writes and preserves ${retirement ? 'root retirement priority' : 'the original write error'}`, async t => {
      const { root, store } = await fixture(t), open = fs.open.bind(fs);
      const writeFailure = Object.assign(new Error('an actual grouped write reported ENOSPC'), { code: 'ENOSPC' });
      const closeFailure = new Error('the actual root close returned uncertainty');
      const active = new Set<object>(); let writes = 0;
      t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
        const handle = await open(...args); active.add(handle);
        const close = handle.close.bind(handle), write = handle.writeFile.bind(handle);
        t.mock.method(handle, 'close', async () => {
          await close(); active.delete(handle); if (retirement && args[0] === root) throw closeFailure;
        });
        if (String(args[0]).includes('/.tmp-stream-')) t.mock.method(handle, 'writeFile', async (...values: Parameters<typeof write>) => {
          await write(...values); if (++writes === 1) throw writeFailure;
        });
        return handle;
      });
      await assert.rejects(publish(store, count, Array.from({ length: count }, (_, index) => Buffer.from(`write-${index}`))),
        error => retirement ? error instanceof ResourceRetirementError && error.cause === closeFailure : error === writeFailure);
      assert.equal(writes, count); assert.equal(active.size, 0);
      assert.equal(isJoinedCasPublicationFailure(writeFailure), false);
      assert.deepEqual(await readdir(root), []);
    });
  }
}
