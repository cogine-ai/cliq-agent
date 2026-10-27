import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import type { DependencyPackageDescriptorV1 } from '../kernel/dependency.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import type { NativeDependencyPackage } from './dependency-broker-native.js';
import { publishDependencyPackageData } from './dependency-package-publication.js';

/** Real owned file/cursors and SQLite-free CAS content tests. This fixture
 * creates no genuine native package, GET/fence, Run or completion evidence. */
async function fixture() {
  const home = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-publish-'))), root = path.join(home, 'cas');
  await mkdir(root, { mode: 0o700 });
  const bytes = Buffer.alloc(3_145_745, 37), filename = path.join(home, 'owned-package');
  await writeFile(filename, bytes, { flag: 'wx', mode: 0o400 });
  const original = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW), identity = fstatSync(original);
  let cursors = 0, opened = 0, ownerClosed = false, duringRead: (() => void) | undefined;
  const source: NativeDependencyPackage = Object.freeze({ byteCount: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
    openReader() {
      assert(!ownerClosed); opened++;
      const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW), before = fstatSync(fd);
      assert.equal(before.ino, identity.ino); assert.equal(before.dev, identity.dev); cursors++;
      let offset = 0, eof = false, closed = false;
      return Object.freeze({ readChunk() {
        assert(!closed); const chunk = Buffer.alloc(65_536), count = readSync(fd, chunk, 0, chunk.length, offset);
        offset += count; if (!count) eof = true; duringRead?.(); return chunk.subarray(0, count);
      }, assertComplete() { assert(!closed && eof); assert.equal(offset, bytes.length); assert.equal(fstatSync(fd).ino, identity.ino); },
      close() { assert(!closed); closed = true; closeSync(fd); cursors--; } });
    }, close() { assert.equal(cursors, 0); assert(!ownerClosed); closeSync(original); ownerClosed = true; }
  });
  const descriptor: DependencyPackageDescriptorV1 = { packageName: 'owned-package', packageVersion: '1.0.0', endpointRegistrationRef: 'a'.repeat(64),
    canonicalPackagePath: '/owned-package/-/owned-package-1.0.0.tgz', integrityAlgorithm: 'sha512', integrityDigest: createHash('sha512').update(bytes).digest('base64') };
  return { home, root, bytes, source, descriptor, artifacts: new ArtifactCatalog(new ContentAddressedStore(root)),
    state: () => ({ cursors, opened, ownerClosed, inode: fstatSync(original).ino }), setReadHook(value?: () => void) { duringRead = value; },
    async close() { if (!ownerClosed) source.close(); await chmod(root, 0o700); await rm(home, { recursive: true, force: true }); } };
}

test('large package content is streamed, completely persisted and independently reopened with every real cursor joined', async () => {
  const f = await fixture();
  try {
    const artifact = await publishDependencyPackageData(f.artifacts, f.source, f.descriptor, 67_108_864);
    assert(artifact.byteLength > 1_048_576); assert.equal(artifact.ref, f.source.sha256); assert.equal(artifact.byteLength, f.bytes.length);
    assert.equal(f.state().cursors, 0); assert.equal(f.state().ownerClosed, false);
    assert.deepEqual(await f.artifacts.readBytes(artifact.ref), f.bytes);
    f.source.close();
  } finally { await f.close(); }
});
test('real store refusal retains the same original data owner for a new complete cursor and never retires it as metadata success', async () => {
  const f = await fixture();
  try {
    const before = f.state(); await chmod(f.root, 0o500);
    await assert.rejects(publishDependencyPackageData(f.artifacts, f.source, f.descriptor, 67_108_864));
    assert.equal(f.state().cursors, 0); assert.equal(f.state().ownerClosed, false); assert.equal(f.state().inode, before.inode);
    await chmod(f.root, 0o700);
    const actual = await publishDependencyPackageData(f.artifacts, f.source, f.descriptor, 67_108_864);
    assert.equal(actual.ref, f.source.sha256); assert.equal(f.state().opened, 2); assert.equal(f.state().cursors, 0); assert.equal(f.state().ownerClosed, false);
    assert.deepEqual((await readdir(f.root)).filter(name => name.startsWith('.tmp')), []);
  } finally { await f.close(); }
});
test('SRI, byte ceilings and real cancellation refuse without losing original custody or leaving a reader alive', async () => {
  const f = await fixture();
  try {
    await assert.rejects(publishDependencyPackageData(f.artifacts, f.source, f.descriptor, f.bytes.length - 1));
    assert.equal(f.state().opened, 0);
    await assert.rejects(publishDependencyPackageData(f.artifacts, f.source,
      { ...f.descriptor, integrityDigest: Buffer.alloc(64, 49).toString('base64') }, 67_108_864));
    assert.equal(f.state().cursors, 0); assert.equal(f.state().ownerClosed, false);
    const stop = new AbortController(); let reads = 0;
    f.setReadHook(() => { if (++reads === 2) stop.abort(new Error('own content consumer cancelled')); });
    await assert.rejects(publishDependencyPackageData(f.artifacts, f.source, f.descriptor, 67_108_864, stop.signal));
    assert.equal(f.state().cursors, 0); assert.equal(f.state().ownerClosed, false);
    assert.deepEqual((await readdir(f.root)).filter(name => name.startsWith('.tmp')), []);
    f.setReadHook(); assert.equal((await publishDependencyPackageData(f.artifacts, f.source, f.descriptor, 67_108_864)).ref, f.source.sha256);
  } finally { await f.close(); }
});
