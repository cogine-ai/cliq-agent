import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, mkdtemp, open, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { test, type TestContext } from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { sha256Bytes } from '../kernel/identity.js';
import { ArtifactCatalog } from '../state/artifacts.js';
import { ContentAddressedStore } from '../state/cas.js';
import { ResourceRetirementError } from '../state/errors.js';
import { publishSourceGitArtifacts } from './source-git-artifacts.js';
import { classifySourceGitConfig } from './source-git-config.js';

const expected = { repositoryIdentityDigest: 'a'.repeat(64), resources: DEFAULT_SANDBOX_RESOURCES };
async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-git-publication-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, 'cas'), { mode: 0o700 });
  // Deliberately inert bytes, not trusted Git or native validation. The real
  // fixed-helper algorithm test separately supplies genuine pack/index data.
  const index = Buffer.alloc(32, 0x32), pack = Buffer.alloc(32, 0x33), packIndex = Buffer.alloc(1072, 0x34);
  const metadata = { schemaVersion: 1, format: 'cliq-source-git-inspection-output-v1',
    repositoryIdentityDigest: expected.repositoryIdentityDigest, objectFormat: 'sha1', head: { kind: 'unborn', branch: 'main' }, refs: [],
    index: { entries: [], indexTreeObjectId: createHash('sha1').update('tree 0\0').digest('hex'), byteCount: index.length, sha256: sha256Bytes(index) },
    pack: { byteCount: pack.length, sha256: sha256Bytes(pack), trailerObjectHash: 'b'.repeat(40), indexByteCount: packIndex.length,
      indexSha256: sha256Bytes(packIndex), objectIds: [] }, sanitizedConfig: classifySourceGitConfig(Buffer.from('[core]\n')).config };
  const values = { inspection: canonicalJsonBytes(metadata), index, pack, packIndex };
  for (const [name, bytes] of Object.entries(values)) await writeFile(path.join(directory, name), bytes, { mode: 0o600 });
  const closed = new Set<string>();
  const stream = async function* (name: keyof typeof values) {
    const handle = await open(path.join(directory, name), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { for (;;) { const bytes = Buffer.alloc(64), result = await handle.read(bytes, 0, bytes.length, null);
      if (!result.bytesRead) break; yield bytes.subarray(0, result.bytesRead); } }
    finally { await handle.close(); closed.add(name); }
  };
  return { directory, metadata, values, closed, stream, artifacts: new ArtifactCatalog(new ContentAddressedStore(path.join(directory, 'cas'))),
    streams: () => ({ inspection: stream('inspection'), index: stream('index'), pack: stream('pack'), packIndex: stream('packIndex') }) };
}

test('fixed Git artifact publication retains only exact complete declared output data without minting source authority', async t => {
  const f = await fixture(t), result = await publishSourceGitArtifacts(f.artifacts, f.streams(), expected);
  assert.equal(f.closed.size, 4);
  assert.deepEqual(await f.artifacts.readBytes(result.pack.packBytesRef), f.values.pack);
  assert.deepEqual(await f.artifacts.readCanonical(result.privateGitStateRef), result.manifest);
  assert.deepEqual(result.closure.reachableObjectIds, []);
  assert.equal(result.index.canonicalIndexBytesDigest, sha256Bytes(f.values.index));
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.metadata));
});

test('wrong output hash, truncated bytes and an oversized stream cannot produce a retained Git manifest', async t => {
  const f = await fixture(t);
  for (const bytes of [Buffer.alloc(32, 0x35), f.values.index.subarray(1), Buffer.concat([f.values.index, Buffer.from([0])])]) {
    await writeFile(path.join(f.directory, 'index'), bytes);
    await assert.rejects(publishSourceGitArtifacts(f.artifacts, f.streams(), expected), { code: 'ARTIFACT_MISMATCH' });
    assert.equal(f.closed.size, 4, 'all issued streams really close even when a sibling is rejected');
    f.closed.clear();
  }
});

test('fixed output publication waits for every real input close and keeps a late retirement failure above the original byte failure', async t => {
  const f = await fixture(t), first = new Error('own byte stream rejected'), closing = new ResourceRetirementError('own late input close', new Error('own close detail'));
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; }), holding = new Promise<void>(resolve => { entered = resolve; });
  const held = async function* () {
    const file = await open(path.join(f.directory, 'packIndex'), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      for (;;) { const bytes = Buffer.alloc(64), read = await file.read(bytes, 0, bytes.length, null);
        if (!read.bytesRead) break; yield bytes.subarray(0, read.bytesRead); }
    } finally { entered(); await gate; await file.close(); f.closed.add('packIndex'); throw closing; }
  };
  const failed = async function* () {
    const file = await open(path.join(f.directory, 'index'), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { await file.read(Buffer.alloc(1), 0, 1, null); throw first; yield Buffer.alloc(0); }
    finally { await file.close(); f.closed.add('index'); }
  };
  const pending = publishSourceGitArtifacts(f.artifacts, { ...f.streams(), index: failed(), packIndex: held() }, expected);
  let settled = false; const rejected = pending.then(() => { settled = true; assert.fail('data publication must reject'); }, error => { settled = true; assert.equal(error, closing); });
  try {
    await holding; await setImmediate(); assert.equal(settled, false, 'a first failure cannot abandon a still-held sibling FD');
  } finally { release(); await Promise.allSettled([pending, rejected]); }
  await rejected; assert.equal(f.closed.size, 4);
});

test('the original cancellation reason survives complete output joins without a fake success or new read', async t => {
  const f = await fixture(t), abort = new AbortController(), reason = new Error('own source output cancelled');
  const stream = async function* () {
    for await (const bytes of f.stream('index')) { abort.abort(reason); yield bytes; }
  };
  await assert.rejects(publishSourceGitArtifacts(f.artifacts, { ...f.streams(), index: stream() }, expected, abort.signal), error => error === reason);
  assert.equal(f.closed.size, 4);
});
