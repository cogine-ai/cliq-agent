import assert from 'node:assert/strict';
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

test('constructor rejects roots that are not normalized absolute paths', () => {
  assert.throws(() => new ContentAddressedStore('relative/objects'), /normalized absolute/i);
  assert.throws(
    () => new ContentAddressedStore(`${os.tmpdir()}/parent/../objects`),
    /normalized absolute/i
  );
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
