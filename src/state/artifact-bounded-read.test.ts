import assert from 'node:assert/strict';
import { fstatSync, promises as fs, readdirSync } from 'node:fs';
import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { ArtifactCatalog } from './artifacts.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'artifact-bounded-'));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root)), bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 3 + 17, 0x37);
  const publication = await artifacts.publishBytes(bytes, 'application/octet-stream', 'own-bounded-source-rule');
  return { root, artifacts, bytes, ref: publication.ref };
}
function assertJoined(identities: Array<{ dev: number; ino: number }>): void {
  for (const name of readdirSync(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd')) {
    if (!/^\d+$/u.test(name)) continue;
    let info; try { info = fstatSync(Number(name)); } catch { continue; }
    assert(!identities.some(value => value.dev === info.dev && value.ino === info.ino), 'both original CAS walks must really join');
  }
}

test('bounded artifact input independently verifies size then streams every original byte before acceptance', async t => {
  const f = await fixture(t), original = fs.open;
  const identities: Array<{ dev: number; ino: number }> = []; let objects = 0, bytesRead = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await original(...args); identities.push(await handle.stat());
    if (args[0] === path.join(f.root, f.ref)) {
      objects++; const read = handle.read.bind(handle);
      handle.read = (async (...input: Parameters<typeof handle.read>) => {
        const value = await read(...input); assert(value.bytesRead <= ARTIFACT_CHUNK_BYTES); bytesRead += value.bytesRead; return value;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try {
    assert.deepEqual(await f.artifacts.readBoundedBytes(f.ref, f.bytes.length), f.bytes);
    assert.equal(objects, 2); assert.equal(bytesRead, 2 * f.bytes.length); assertJoined(identities);
  } finally { fs.open = original; }
});

test('oversized bounded input completes its discard verification but starts no whole-object materialization', async t => {
  const f = await fixture(t), original = fs.open; const identities: Array<{ dev: number; ino: number }> = []; let objects = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await original(...args); identities.push(await handle.stat()); if (args[0] === path.join(f.root, f.ref)) objects++; return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(f.artifacts.readBoundedBytes(f.ref, f.bytes.length - 1), { code: 'ARTIFACT_MISMATCH' });
    assert.equal(objects, 1); assertJoined(identities);
    await assert.rejects(f.artifacts.readBoundedBytes(f.ref, -1), TypeError); assert.equal(objects, 1);
  } finally { fs.open = original; }
});

test('cancellation at the complete size-verification close cannot open the next original read', async t => {
  const f = await fixture(t), original = fs.open, abort = new AbortController(), reason = new Error('own bounded read closed');
  const identities: Array<{ dev: number; ino: number }> = []; let objects = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await original(...args); identities.push(await handle.stat());
    if (args[0] === path.join(f.root, f.ref)) {
      objects++; const close = handle.close.bind(handle); handle.close = async () => { await close(); abort.abort(reason); };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(f.artifacts.withReadSignal(abort.signal).readBoundedBytes(f.ref, f.bytes.length), error => error === reason);
    assert.equal(objects, 1); assertJoined(identities);
  } finally { fs.open = original; }
});

test('a real late stream close failure dominates cancellation and never returns bounded content', async t => {
  const f = await fixture(t), original = fs.open, abort = new AbortController(), reason = new Error('own stream cancelled');
  const closing = new Error('actual joined descriptor close failure'), identities: Array<{ dev: number; ino: number }> = []; let objects = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await original(...args); identities.push(await handle.stat());
    if (args[0] === path.join(f.root, f.ref) && ++objects === 2) {
      const read = handle.read.bind(handle), close = handle.close.bind(handle);
      handle.read = (async (...input: Parameters<typeof handle.read>) => { const value = await read(...input); abort.abort(reason); return value; }) as typeof handle.read;
      handle.close = async () => { await close(); throw closing; };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(f.artifacts.withReadSignal(abort.signal).readBoundedBytes(f.ref, f.bytes.length),
      error => error instanceof ResourceRetirementError && error.cause === closing);
    assert.equal(objects, 2); assertJoined(identities);
  } finally { fs.open = original; }
});
