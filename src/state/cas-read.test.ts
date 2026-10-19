import assert from 'node:assert/strict';
import { fstatSync, promises as fs, readdirSync } from 'node:fs';
import { chmod, link, mkdtemp, rm, unlink, utimes } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { ArtifactCatalog } from './artifacts.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore } from './cas.js';
import { ResourceRetirementError } from './errors.js';

function assertJoined(identities: Array<{ dev: number; ino: number }>): void {
  for (const name of readdirSync(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd')) {
    if (!/^\d+$/u.test(name)) continue;
    let info; try { info = fstatSync(Number(name)); } catch { continue; }
    assert(!identities.some(identity => info.dev === identity.dev && info.ino === identity.ino), 'actual original CAS handles must be joined');
  }
}

test('a pre-aborted catalog view opens no root or object and cannot shed its parent cancellation', async () => {
  const root = path.join(os.tmpdir(), 'cliq-cas-must-not-open');
  const catalog = new ArtifactCatalog(new ContentAddressedStore(root));
  const parent = new AbortController(), child = new AbortController(), reason = new Error('original owner closed');
  parent.abort(reason);
  const view = catalog.withReadSignal(parent.signal).withReadSignal(child.signal);
  const actualOpen = fs.open; let opens = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => { opens++; return actualOpen(...args); }) as typeof fs.open;
  try {
    assert.throws(() => view.assertReadActive(), error => error === reason);
    await assert.rejects(view.readBytes('a'.repeat(64)), error => error === reason);
    await assert.rejects(view.readCanonical('a'.repeat(64)), error => error === reason);
    await assert.rejects(view.describe('a'.repeat(64), 'application/json', 'inert-data'), error => error === reason);
    await assert.rejects(async () => { for await (const _part of view.readChunks('a'.repeat(64), 1)) { /* Full consumption required. */ } }, error => error === reason);
    assert.equal(opens, 0); assert.equal(child.signal.aborted, false);
  } finally { fs.open = actualOpen; }
});

test('a whole original CAS read stops after its real first bounded read and joins before rejecting, then reopens normally', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-read-abort-')); await chmod(root, 0o700);
  const cas = new ContentAddressedStore(root), catalog = new ArtifactCatalog(cas);
  const bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 3 + 17, 0x83), ref = await cas.publish(bytes);
  const owner = new AbortController(), reason = new Error('original read owner cancelled');
  const actualOpen = fs.open, identities: Array<{dev: number;ino: number}> = []; let reads = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === path.join(root, ref)) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs); reads++;
        assert(result.bytesRead > 0 && result.bytesRead <= ARTIFACT_CHUNK_BYTES); owner.abort(reason); return result;
      }) as typeof handle.read;
      handle.readFile = async () => { throw new Error('whole-file readFile bypassed the bounded original read'); };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(catalog.withReadSignal(owner.signal).readBytes(ref), error => error === reason);
    assert.equal(reads, 1); assertJoined(identities);
    fs.open = actualOpen;
    assert.deepEqual(await catalog.readBytes(ref), bytes);
    assert.deepEqual(await cas.read(ref), bytes);
  } finally { fs.open = actualOpen; await rm(root, { recursive: true, force: true }); }
});

test('stream cancellation never accepts its observed prefix and joins both original descriptors', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-stream-abort-')); await chmod(root, 0o700);
  const cas = new ContentAddressedStore(root), catalog = new ArtifactCatalog(cas);
  const bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 2 + 3, 0x21), ref = await cas.publish(bytes);
  const owner = new AbortController(), reason = new Error('stream owner cancelled');
  const actualOpen = fs.open, identities: Array<{dev:number;ino:number}> = [];
  fs.open = (async (...args: Parameters<typeof fs.open>) => { const handle = await actualOpen(...args); identities.push(await handle.stat()); return handle; }) as typeof fs.open;
  const iterator = catalog.withReadSignal(owner.signal).readChunks(ref, bytes.length)[Symbol.asyncIterator]();
  try {
    const first = await iterator.next(); assert.equal(first.done, false); assert.deepEqual(first.value, bytes.subarray(0, ARTIFACT_CHUNK_BYTES));
    owner.abort(reason); await assert.rejects(iterator.next(), error => error === reason); assertJoined(identities);
    fs.open = actualOpen; assert.deepEqual(await catalog.readBytes(ref), bytes);
  } finally { fs.open = actualOpen; await iterator.return?.(); await rm(root, { recursive: true, force: true }); }
});

test('actual CAS close uncertainty wins over cancellation and cannot be reported as joined', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-abort-close-')); await chmod(root, 0o700);
  const cas = new ContentAddressedStore(root), bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 2, 0x31), ref = await cas.publish(bytes);
  const owner = new AbortController(), reason = new Error('cancelled original read'), failure = new Error('uncertain actual close');
  const actualOpen = fs.open; let closes = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args);
    if (args[0] === path.join(root, ref)) {
      const read = handle.read.bind(handle), close = handle.close.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => { const result = await read(...readArgs); owner.abort(reason); return result; }) as typeof handle.read;
      handle.close = async () => { await close(); closes++; throw failure; };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(cas.read(ref, owner.signal), error => error instanceof ResourceRetirementError && error.cause === failure);
    assert.equal(closes, 1); assert.equal(owner.signal.aborted, true);
  } finally { fs.open = actualOpen; await rm(root, { recursive: true, force: true }); }
});

for (const kind of ['whole', 'stream'] as const) for (const closing of ['object', 'root'] as const)
  test(`cancellation during actual ${closing} close cannot turn the ${kind} read into accepted bytes`, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-complete-close-')); await chmod(root, 0o700);
    const cas = new ContentAddressedStore(root), bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES + 3, 0x79), ref = await cas.publish(bytes);
    const owner = new AbortController(), reason = new Error('owner cancelled before complete resource join');
    const actualOpen = fs.open, identities: Array<{dev:number;ino:number}> = []; let cancelled = 0;
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await actualOpen(...args); identities.push(await handle.stat());
      if (args[0] === (closing === 'root' ? root : path.join(root, ref))) {
        const close = handle.close.bind(handle);
        handle.close = async () => { await close(); owner.abort(reason); cancelled++; };
      }
      return handle;
    }) as typeof fs.open;
    try {
      await assert.rejects(async () => {
        if (kind === 'whole') await cas.read(ref, owner.signal);
        else for await (const _chunk of cas.readChunks(ref, bytes.length, owner.signal)) { /* Prefixes do not establish verification. */ }
      }, error => error === reason);
      assert.equal(cancelled, 1); assertJoined(identities);
      fs.open = actualOpen; assert.deepEqual(await cas.read(ref), bytes);
    } finally { fs.open = actualOpen; await rm(root, { recursive: true, force: true }); }
  });

for (const mutation of ['mtime', 'ctime', 'mode', 'links'] as const) test('whole CAS reads preserve held integrity checks after bounded I/O: ' + mutation, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-read-integrity-')); await chmod(root, 0o700);
  const cas = new ContentAddressedStore(root), bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 2, 0x42), ref = await cas.publish(bytes);
  const filename = path.join(root, ref), second = path.join(root, 'unexpected-link');
  const actualOpen = fs.open; let changed = false;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args);
    if (args[0] === filename) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs);
        if (!changed) {
          changed = true;
          if (mutation === 'mtime') await utimes(filename, new Date(), new Date(Date.now() + 2000));
          if (mutation === 'ctime') { await chmod(filename, 0o600); await chmod(filename, 0o400); }
          if (mutation === 'mode') await chmod(filename, 0o600);
          if (mutation === 'links') await link(filename, second);
        }
        return result;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try { await assert.rejects(cas.read(ref), /changed|invalid mode|link count/); assert.equal(changed, true); }
  finally { fs.open = actualOpen; if (mutation === 'links') await unlink(second).catch(() => {}); await rm(root, { recursive: true, force: true }); }
});
