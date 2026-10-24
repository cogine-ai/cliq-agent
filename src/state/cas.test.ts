import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readdir,
  rm,
  stat as fsStat,
  symlink,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';

test('publish makes immutable bytes readable by their raw SHA-256 ref', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-publish-'));
  const root = path.join(home, 'objects');
  try {
    await mkdir(root, { mode: 0o700 });
    const store = new ContentAddressedStore(root);
    const bytes = Buffer.from('hello', 'utf8');

    const ref = await store.publish(bytes);

    assert.equal(ref, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    assert.deepEqual(await store.read(ref), bytes);
    assert.equal((await fsStat(path.join(root, ref))).mode & 0o777, 0o400);
    assert.deepEqual(await store.verify(ref), { ref, byteLength: 5 });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('a fixed four-object publication preserves all four durable namespace boundaries and joins its real descriptors', async t => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-four-'));
  const root = path.join(home, 'objects');
  const sources = ['one', 'two', 'three', 'four'].map(value => Buffer.from(value)) as [Buffer, Buffer, Buffer, Buffer];
  const open = fs.open.bind(fs);
  const boundaries: string[][] = [];
  let active = 0, peak = 0, fileSyncs = 0;
  try {
    await mkdir(root, { mode: 0o700 });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args);
      active++; peak = Math.max(peak, active);
      const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); active--; });
      t.mock.method(handle, 'sync', async () => {
        await sync();
        if (args[0] === root) boundaries.push((await readdir(root)).sort());
        else fileSyncs++;
      });
      return handle;
    });
    const store = new ContentAddressedStore(root);
    const results = await store.publishFour(sources);
    assert.equal(active, 0, 'all original file and held-root descriptors join before returning');
    assert.ok(peak > 2 && peak <= 5, 'one held root plus at most four actual file handles, not a whole-process FD claim');
    assert.equal(fileSyncs, 4, 'every complete original file is actually synchronized');
    assert.equal(boundaries.length, 4, 'the four namespace durability boundaries remain distinct');
    assert.equal(boundaries[0]!.length, 4);
    assert.ok(boundaries[0]!.every(name => /^\.tmp-stream-[0-9a-f]{32}$/u.test(name)), 'all immutable staging files precede the first barrier');
    assert.equal(boundaries[1]!.length, 4);
    assert.ok(boundaries[1]!.every(name => /^\.tmp-[0-9a-f]{64}-[0-9a-f]{32}$/u.test(name)), 'all ref-bearing renames precede the second barrier');
    assert.equal(boundaries[2]!.length, 8, 'all four final links and their original temporaries precede the third barrier');
    assert.deepEqual(boundaries[3], results.map(result => result.ref).sort(), 'all temporary unlinks precede the fourth barrier');
    for (const [index, result] of results.entries()) {
      assert.equal(result.byteLength, sources[index]!.length);
      assert.deepEqual(await store.read(result.ref), sources[index]);
      assert.equal((await fsStat(path.join(root, result.ref))).nlink, 1);
    }
  } finally { t.mock.restoreAll(); await rm(home, { recursive: true, force: true }); }
});

test('fixed four-object publication interoperates with same-root single publishers and repeated content refs', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-four-shared-'));
  const root = path.join(home, 'objects');
  try {
    await mkdir(root, { mode: 0o700 });
    const store = new ContentAddressedStore(root), shared = Buffer.from('shared bytes');
    const [batch, singles] = await Promise.all([
      store.publishFour([shared, shared, Buffer.from('third'), shared]),
      Promise.all(Array.from({ length: 4 }, () => new ContentAddressedStore(root).publish(shared)))
    ]);
    assert.equal(batch[0].ref, batch[1].ref); assert.equal(batch[0].ref, batch[3].ref);
    assert.ok(singles.every(ref => ref === batch[0].ref));
    assert.deepEqual((await readdir(root)).sort(), [...new Set(batch.map(item => item.ref))].sort());
    for (const item of batch) { await store.verify(item.ref); assert.equal((await fsStat(path.join(root, item.ref))).nlink, 1); }
  } finally { await rm(home, { recursive: true, force: true }); }
});

test('fixed four-object publication rejects missing or non-byte slots before any I/O', async t => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-four-input-'));
  const root = path.join(home, 'objects'), open = fs.open.bind(fs);
  let opened = 0;
  try {
    await mkdir(root, { mode: 0o700 });
    t.mock.method(fs, 'open', (...args: Parameters<typeof open>) => { opened++; return open(...args); });
    const store = new ContentAddressedStore(root), bytes = Buffer.from('valid');
    for (const sources of [[], [bytes, bytes, bytes], [bytes, bytes, bytes, bytes, bytes],
      new Array(4), [bytes, bytes, undefined, bytes]]) {
      await assert.rejects(store.publishFour(sources as [Buffer, Buffer, Buffer, Buffer]), TypeError,
        'all four actual byte sources are required before opening the protected root');
    }
    assert.equal(opened, 0); assert.deepEqual(await readdir(root), []);
  } finally { t.mock.restoreAll(); await rm(home, { recursive: true, force: true }); }
});

for (const mutation of ['rename', 'link', 'unlink'] as const) {
  test(`fixed four-object ${mutation} failure joins actual sibling mutations before syncing and cleaning the prefix`, async t => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-four-prefix-'));
    const root = path.join(home, 'objects');
    const actual = fs[mutation].bind(fs) as (...args: string[]) => Promise<void>;
    const open = fs.open.bind(fs), failure = new Error(`actual ${mutation} reported failure after mutation`);
    let release!: () => void, entered!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const pending = new Promise<void>(resolve => { entered = resolve; });
    let started = 0, completed = 0, rootSyncs = 0, active = 0, settled = false;
    try {
      await mkdir(root, { mode: 0o700 });
      t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
        const handle = await open(...args); active++;
        const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
        t.mock.method(handle, 'close', async () => { await close(); active--; });
        if (args[0] === root) t.mock.method(handle, 'sync', async () => { await sync(); rootSyncs++; });
        return handle;
      });
      t.mock.method(fs, mutation, async (...args: string[]) => {
        const index = started++;
        await actual(...args); // A real namespace mutation has already happened.
        if (index === 3) { entered(); await gate; }
        completed++;
        if (index === 0) throw failure;
      });
      const store = new ContentAddressedStore(root);
      const publication = store.publishFour([Buffer.from('a'), Buffer.from('b'), Buffer.from('c'), Buffer.from('d')]);
      void publication.then(() => { settled = true; }, () => { settled = true; });
      try {
        await pending;
        assert.equal(settled, false);
        assert.equal(started, 4, 'only this exact stage has started, never later cleanup before sibling join');
        assert.equal(rootSyncs, mutation === 'rename' ? 1 : mutation === 'link' ? 2 : 3,
          'the stage barrier cannot precede the last actual mutation return');
        release();
        await assert.rejects(publication, error => mutation === 'unlink'
          ? error instanceof ResourceRetirementError && error.cause === failure : error === failure);
        assert.ok(completed >= 4);
        assert.equal(active, 0, 'all delivered original descriptors have really closed');
        assert.equal(rootSyncs, mutation === 'rename' ? 3 : 4, 'failed-prefix and cleanup barriers both really run');
        assert.ok((await readdir(root)).every(name => /^[0-9a-f]{64}$/u.test(name)), 'no owned temporary is abandoned');
      } finally { release(); await Promise.allSettled([publication]); }
    } finally { t.mock.restoreAll(); await rm(home, { recursive: true, force: true }); }
  });
}

for (const failingBoundary of [1, 2, 3, 4]) {
  test(`fixed four-object publication retains a recoverable prefix when directory barrier ${failingBoundary} reports failure`, async t => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-four-barrier-'));
    const root = path.join(home, 'objects');
    const open = fs.open.bind(fs), failure = new Error('real directory synchronization reported failure');
    const sources = [Buffer.from('a'), Buffer.from('b'), Buffer.from('c'), Buffer.from('d')] as const;
    let syncs = 0, active = 0;
    try {
      await mkdir(root, { mode: 0o700 });
      t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
        const handle = await open(...args); active++;
        const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
        t.mock.method(handle, 'close', async () => { await close(); active--; });
        if (args[0] === root) t.mock.method(handle, 'sync', async () => {
          await sync(); if (++syncs === failingBoundary) throw failure;
        });
        return handle;
      });
      await assert.rejects(new ContentAddressedStore(root).publishFour(sources), error => error instanceof ResourceRetirementError);
      assert.equal(active, 0); assert.ok(syncs >= failingBoundary);
      assert.ok((await readdir(root)).every(name => /^[0-9a-f]{64}$/u.test(name)), 'failed batch leaves only valid orphan candidates');
      t.mock.restoreAll();
      const store = new ContentAddressedStore(root), recovered = await store.publishFour(sources);
      assert.equal((await readdir(root)).length, 4);
      for (const item of recovered) await store.verify(item.ref);
    } finally { t.mock.restoreAll(); await rm(home, { recursive: true, force: true }); }
  });
}

test('concurrent publication of identical bytes joins the same immutable artifact', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-concurrent-'));
  const root = path.join(home, 'objects');
  try {
    await mkdir(root, { mode: 0o700 });
    const store = new ContentAddressedStore(root);
    const refs = await Promise.all(
      Array.from({ length: 24 }, () => store.publish(Buffer.from('shared bytes', 'utf8')))
    );

    assert.equal(new Set(refs).size, 1);
    assert.deepEqual(await store.read(refs[0]), Buffer.from('shared bytes', 'utf8'));
    assert.deepEqual(await readdir(root), [refs[0]]);
    assert.equal((await fsStat(path.join(root, refs[0]))).nlink, 1);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('publish succeeds when another publisher removes its linked temporary between lstat and unlink', async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-cleanup-race-'));
  const root = path.join(home, 'objects');
  try {
    await mkdir(root, { mode: 0o700 });
    const store = new ContentAddressedStore(root);
    const bytes = Buffer.from('shared bytes', 'utf8');
    const unlink = fs.unlink.bind(fs);
    let secondStarted = false;
    let secondRef: string | undefined;
    t.mock.method(fs, 'unlink', async (temporaryPath: Parameters<typeof fs.unlink>[0]) => {
      if (!secondStarted) {
        secondStarted = true;
        // Pause the first cleanup after lstat; the second publisher's real
        // recovery removes that same temporary before the first unlink resumes.
        secondRef = await store.publish(bytes);
      }
      return unlink(temporaryPath);
    });

    const firstRef = await store.publish(bytes);

    assert.equal(firstRef, secondRef);
    assert.deepEqual(await store.read(firstRef), bytes);
    assert.deepEqual(await readdir(root), [firstRef]);
    assert.equal((await fsStat(path.join(root, firstRef))).nlink, 1);
  } finally {
    t.mock.restoreAll();
    await rm(home, { recursive: true, force: true });
  }
});

for (const { existingArtifact, code } of [
  { existingArtifact: false, code: 'EACCES' },
  { existingArtifact: true, code: 'ENOENT' }
]) {
  test(`publish preserves ${code} when cleaning ${existingArtifact ? 'an unlinked' : 'a linked'} temporary`, async (t) => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-cleanup-error-'));
    const root = path.join(home, 'objects');
    try {
      await mkdir(root, { mode: 0o700 });
      const store = new ContentAddressedStore(root);
      const bytes = Buffer.from('shared bytes', 'utf8');
      if (existingArtifact) await store.publish(bytes);
      const unlink = fs.unlink.bind(fs);
      const failure = Object.assign(new Error('injected temporary cleanup failure'), { code });
      t.mock.method(fs, 'unlink', async (temporaryPath: Parameters<typeof fs.unlink>[0]) => {
        if (code === 'ENOENT') await unlink(temporaryPath);
        throw failure;
      });

      await assert.rejects(store.publish(bytes), (error) => error instanceof ResourceRetirementError &&
        error.code === 'RECOVERY_REQUIRED' && error.cause === failure &&
        (error.cause as NodeJS.ErrnoException).code === code);
    } finally {
      t.mock.restoreAll();
      await rm(home, { recursive: true, force: true });
    }
  });
}

test('constructor rejects roots that are not normalized absolute paths', () => {
  assert.throws(() => new ContentAddressedStore('relative/objects'), /normalized absolute/i);
  assert.throws(
    () => new ContentAddressedStore(`${os.tmpdir()}/parent/../objects`),
    /normalized absolute/i
  );
});

test('constructor preserves the exact held-directory locator grammar without normalizing its final dot away', () => {
  // Syntax only: accepting this locator does not assert that a descriptor is
  // open or that this host supports Linux procfs. Every I/O still verifies the
  // actual private directory. The final dot makes O_NOFOLLOW open a directory,
  // not the procfd symlink, while children stay relative to that exact fd.
  assert.doesNotThrow(() => new ContentAddressedStore('/proc/self/fd/12/.'));
  for (const root of ['/proc/self/fd/012/.', '/proc/self/fd/-1/.', '/proc/other/fd/12/.',
    '/proc/self/fd/12/../.', '/proc/self/fd/12/./', '/tmp/objects/.']) {
    assert.throws(() => new ContentAddressedStore(root), /normalized absolute/i);
  }
});

if (process.platform === 'linux') test('publication through a held directory cannot follow replacement of its original path', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-held-root-'));
  const root = path.join(fixture, 'objects');
  const original = path.join(fixture, 'original');
  let directory: Awaited<ReturnType<typeof fs.open>> | undefined;
  try {
    await mkdir(root, { mode: 0o700 });
    directory = await fs.open(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    const store = new ContentAddressedStore(`/proc/self/fd/${directory.fd}/.`);
    await fs.rename(root, original);
    await mkdir(root, { mode: 0o700 });
    const bytes = Buffer.from('publication stays in the held inode');
    const ref = await store.publish(bytes);
    assert.deepEqual(await fs.readFile(path.join(original, ref)), bytes);
    assert.deepEqual(await readdir(root), []);
    assert.deepEqual(await store.verify(ref), { ref, byteLength: bytes.length });
    assert.deepEqual(await store.read(ref), bytes);
  } finally {
    await directory?.close();
    await rm(fixture, { recursive: true, force: true });
  }
});

test('every operation rejects a missing, symlinked, or incorrectly protected root', async (t) => {
  await t.test('missing root', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-root-missing-'));
    try {
      const store = new ContentAddressedStore(path.join(home, 'objects'));
      await assert.rejects(store.publish(Buffer.from('hello')), /root.*(exist|open|enoent)/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  await t.test('symlink root', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-root-symlink-'));
    const target = path.join(home, 'target');
    const root = path.join(home, 'objects');
    try {
      await mkdir(target, { mode: 0o700 });
      await symlink(target, root);
      const store = new ContentAddressedStore(root);
      await assert.rejects(store.publish(Buffer.from('hello')), /root.*symlink/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  await t.test('root mode is not exactly 0700', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-root-mode-'));
    const root = path.join(home, 'objects');
    try {
      await mkdir(root, { mode: 0o755 });
      const store = new ContentAddressedStore(root);
      await assert.rejects(store.publish(Buffer.from('hello')), /root.*mode.*700/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});

test('publish recovers only a provable link-before-unlink crash residue', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-recover-'));
  const root = path.join(home, 'objects');
  const ref = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  const residue = `.tmp-${ref}-${'a'.repeat(32)}`;
  try {
    await mkdir(root, { mode: 0o700 });
    await writeFile(path.join(root, residue), 'hello', { mode: 0o400 });
    await link(path.join(root, residue), path.join(root, ref));
    assert.equal((await fsStat(path.join(root, ref))).nlink, 2);

    const store = new ContentAddressedStore(root);
    assert.equal(await store.publish(Buffer.from('hello')), ref);

    assert.deepEqual(await readdir(root), [ref]);
    assert.equal((await fsStat(path.join(root, ref))).nlink, 1);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('crash recovery fails closed when all inode links cannot be proven inside the root', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-recover-external-'));
  const root = path.join(home, 'objects');
  const ref = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  const residue = `.tmp-${ref}-${'b'.repeat(32)}`;
  const outside = path.join(home, 'outside-link');
  try {
    await mkdir(root, { mode: 0o700 });
    await writeFile(path.join(root, residue), 'hello', { mode: 0o400 });
    await link(path.join(root, residue), path.join(root, ref));
    await link(path.join(root, residue), outside);

    const store = new ContentAddressedStore(root);
    await assert.rejects(store.publish(Buffer.from('hello')), /cannot prove.*link/i);

    assert.deepEqual((await readdir(root)).sort(), [ref, residue].sort());
    assert.equal((await fsStat(path.join(root, ref))).nlink, 3);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('crash recovery never removes an unrecognized same-inode entry', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-recover-name-'));
  const root = path.join(home, 'objects');
  const ref = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  const foreignName = 'not-a-cas-temporary';
  try {
    await mkdir(root, { mode: 0o700 });
    await writeFile(path.join(root, ref), 'hello', { mode: 0o400 });
    await link(path.join(root, ref), path.join(root, foreignName));

    const store = new ContentAddressedStore(root);
    await assert.rejects(store.publish(Buffer.from('hello')), /unrecognized.*link/i);

    assert.deepEqual((await readdir(root)).sort(), [ref, foreignName].sort());
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('published and crash-residue files reject special permission bits', async (t) => {
  const ref = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

  await t.test('published file', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-special-published-'));
    const root = path.join(home, 'objects');
    try {
      await mkdir(root, { mode: 0o700 });
      await writeFile(path.join(root, ref), 'hello', { mode: 0o400 });
      await chmod(path.join(root, ref), 0o1400);
      const store = new ContentAddressedStore(root);
      await assert.rejects(store.read(ref), /invalid mode/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  await t.test('crash residue', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-special-residue-'));
    const root = path.join(home, 'objects');
    const residue = `.tmp-${ref}-${'c'.repeat(32)}`;
    try {
      await mkdir(root, { mode: 0o700 });
      await writeFile(path.join(root, residue), 'hello', { mode: 0o400 });
      await link(path.join(root, residue), path.join(root, ref));
      await chmod(path.join(root, residue), 0o1400);
      const store = new ContentAddressedStore(root);
      await assert.rejects(store.publish(Buffer.from('hello')), /invalid mode/i);
      assert.deepEqual((await readdir(root)).sort(), [ref, residue].sort());
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});

test('all lookup operations reject non-canonical artifact refs before filesystem access', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-ref-'));
  try {
    const store = new ContentAddressedStore(path.join(home, 'missing-store'));
    const invalidRefs = [
      '',
      'abc',
      'A'.repeat(64),
      `sha256:${'a'.repeat(64)}`,
      `../${'a'.repeat(64)}`,
      `${'a'.repeat(63)}/`
    ];

    for (const ref of invalidRefs) {
      await assert.rejects(store.read(ref), /invalid artifact ref/i);
      await assert.rejects(store.stat(ref), /invalid artifact ref/i);
      await assert.rejects(store.verify(ref), /invalid artifact ref/i);
    }
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('read and verify reject content corruption after publication', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-corrupt-'));
  const root = path.join(home, 'objects');
  try {
    await mkdir(root, { mode: 0o700 });
    const store = new ContentAddressedStore(root);
    const ref = await store.publish(Buffer.from('hello', 'utf8'));
    const objectPath = path.join(root, ref);
    await chmod(objectPath, 0o600);
    await writeFile(objectPath, Buffer.from('jello', 'utf8'));
    await chmod(objectPath, 0o400);

    await assert.rejects(store.read(ref), /corrupt/i);
    await assert.rejects(store.verify(ref), /corrupt/i);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('publish refuses a corrupt object at the expected ref and removes its temporary file', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-collision-'));
  const root = path.join(home, 'objects');
  const ref = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  try {
    await mkdir(root, { mode: 0o700 });
    await writeFile(path.join(root, ref), 'jello', { mode: 0o400 });
    const store = new ContentAddressedStore(root);

    await assert.rejects(store.publish(Buffer.from('hello', 'utf8')), /corrupt/i);
    assert.deepEqual(await readdir(root), [ref]);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('lookup rejects symlink, hardlink, and non-regular artifact paths', async (t) => {
  const ref = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

  await t.test('symlink', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-symlink-'));
    const root = path.join(home, 'objects');
    try {
      await mkdir(root, { mode: 0o700 });
      const target = path.join(home, 'target');
      await writeFile(target, 'hello', { mode: 0o400 });
      await symlink(target, path.join(root, ref));
      const store = new ContentAddressedStore(root);

      await assert.rejects(store.stat(ref), /symlink/i);
      await assert.rejects(store.read(ref), /symlink/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  await t.test('hardlink', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-hardlink-'));
    const root = path.join(home, 'objects');
    try {
      await mkdir(root, { mode: 0o700 });
      const target = path.join(home, 'target');
      await writeFile(target, 'hello', { mode: 0o400 });
      await link(target, path.join(root, ref));
      const store = new ContentAddressedStore(root);

      await assert.rejects(store.stat(ref), /link count/i);
      await assert.rejects(store.read(ref), /link count/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  await t.test('directory', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-directory-'));
    const root = path.join(home, 'objects');
    try {
      await mkdir(root, { mode: 0o700 });
      await mkdir(path.join(root, ref));
      const store = new ContentAddressedStore(root);

      await assert.rejects(store.stat(ref), /regular file/i);
      await assert.rejects(store.read(ref), /regular file/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  await t.test('writable regular file', async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-mode-'));
    const root = path.join(home, 'objects');
    try {
      await mkdir(root, { mode: 0o700 });
      await writeFile(path.join(root, ref), 'hello', { mode: 0o600 });
      const store = new ContentAddressedStore(root);

      await assert.rejects(store.stat(ref), /invalid mode/i);
      await assert.rejects(store.read(ref), /invalid mode/i);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});
