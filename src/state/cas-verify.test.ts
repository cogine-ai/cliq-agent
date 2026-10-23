import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { fstatSync, promises as fs, readFileSync, readdirSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import ts from 'typescript';
import { assertArtifactRef } from '../kernel/identity.js';
import { ArtifactCatalog } from './artifacts.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore } from './cas.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';

async function fixture(t: TestContext, bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 3 + 17, 0x83)) {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-verify-')), root = path.join(home, 'objects');
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(home, { recursive: true, force: true }));
  const cas = new ContentAddressedStore(root), ref = await cas.publish(bytes);
  return { home, root, cas, ref, bytes };
}

function assertJoined(identities: Array<{ dev: number; ino: number }>): void {
  for (const name of readdirSync(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd')) {
    if (!/^\d+$/u.test(name)) continue;
    let info; try { info = fstatSync(Number(name)); } catch { continue; }
    assert(!identities.some(identity => info.dev === identity.dev && info.ino === identity.ino), 'original verification descriptors must actually join');
  }
}

// Execute only the three exact existing data-validation functions, with their
// actual imported helpers and real CAS. This creates no Store/Run authority.
function recoveryArtifacts(): (artifacts: ArtifactCatalog, refs: ReadonlyArray<readonly [string, string | undefined]>) => Promise<void> {
  const text = readFileSync(new URL('./recovery-closure.ts', import.meta.url), 'utf8');
  const source = ts.createSourceFile('recovery-closure.ts', text, ts.ScriptTarget.Latest, true);
  const names = ['recoveryFailure', 'requireRecoveryArtifactRef', 'requireRecoveryArtifacts'];
  const selected = names.map(name => {
    const matches = source.statements.filter(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
    assert.equal(matches.length, 1); return matches[0]!.getText(source);
  });
  const output = ts.transpileModule(selected.join('\n') + '\nreturn requireRecoveryArtifacts;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  return new Function('assertArtifactRef', 'KernelStorageError', 'ResourceRetirementError', 'joinResourceOperations', output)(
    assertArtifactRef, KernelStorageError, ResourceRetirementError, joinResourceOperations);
}

test('pre-aborted whole CAS verification opens no object and preserves the original cancellation', async t => {
  const { root, cas, ref } = await fixture(t);
  const owner = new AbortController(), reason = new Error('the original verification owner closed'); owner.abort(reason);
  const actualOpen = fs.open; let opens = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => { opens++; return actualOpen(...args); }) as typeof fs.open;
  try { await assert.rejects(cas.verify(ref, owner.signal), error => error === reason); assert.equal(opens, 0); }
  finally { fs.open = actualOpen; }
  assert.deepEqual(await cas.verify(ref), { ref, byteLength: (await fs.stat(path.join(root, ref))).size });
});

test('whole CAS verification cancels after its first actual bounded read and joins both original descriptors', async t => {
  const { root, cas, ref, bytes } = await fixture(t);
  const owner = new AbortController(), reason = new Error('cancel the original verification');
  const actualOpen = fs.open, identities: Array<{ dev: number; ino: number }> = []; let reads = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === path.join(root, ref)) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs); reads++;
        assert(result.bytesRead > 0 && result.bytesRead <= ARTIFACT_CHUNK_BYTES); owner.abort(reason); return result;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try { await assert.rejects(cas.verify(ref, owner.signal), error => error === reason); assert.equal(reads, 1); assertJoined(identities); }
  finally { fs.open = actualOpen; }
  assert.deepEqual(await cas.verify(ref), { ref, byteLength: bytes.length });
});

test('cancellation after the actual complete digest prevents any later root-path I/O', async t => {
  const { cas, ref } = await fixture(t), owner = new AbortController(), reason = new Error('cancel after original whole digest');
  const actualHash = crypto.createHash, actualLstat = fs.lstat; let afterCancellation = 0;
  crypto.createHash = ((...args: Parameters<typeof crypto.createHash>) => {
    const hash = actualHash(...args), digest = hash.digest.bind(hash);
    hash.digest = ((...digestArgs: Parameters<typeof hash.digest>) => {
      const result = digest(...digestArgs); queueMicrotask(() => owner.abort(reason)); return result;
    }) as typeof hash.digest;
    return hash;
  }) as typeof crypto.createHash;
  fs.lstat = (async (...args: Parameters<typeof fs.lstat>) => {
    if (owner.signal.aborted) afterCancellation++; return actualLstat(...args);
  }) as typeof fs.lstat;
  try { await assert.rejects(cas.verify(ref, owner.signal), error => error === reason); assert.equal(afterCancellation, 0); }
  finally { crypto.createHash = actualHash; fs.lstat = actualLstat; }
});

for (const closing of ['object', 'root'] as const) test(`cancellation during actual ${closing} close cannot accept whole verification`, async t => {
  const { root, cas, ref } = await fixture(t);
  const owner = new AbortController(), reason = new Error('verification owner closed during actual join');
  const actualOpen = fs.open, identities: Array<{ dev: number; ino: number }> = []; let cancelled = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === (closing === 'root' ? root : path.join(root, ref))) {
      const close = handle.close.bind(handle);
      handle.close = async () => { await close(); owner.abort(reason); cancelled++; };
    }
    return handle;
  }) as typeof fs.open;
  try { await assert.rejects(cas.verify(ref, owner.signal), error => error === reason); assert.equal(cancelled, 1); assertJoined(identities); }
  finally { fs.open = actualOpen; }
});

test('whole verification rejects a real root replacement during the original held file read', async t => {
  const { home, root, cas, ref } = await fixture(t);
  const actualOpen = fs.open, identities: Array<{ dev: number; ino: number }> = []; let moved = false;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === path.join(root, ref)) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs);
        if (!moved) { moved = true; await fs.rename(root, path.join(home, 'original-objects')); await mkdir(root, { mode: 0o700 }); }
        return result;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try { await assert.rejects(cas.verify(ref), /CAS root changed during an operation/); assert.equal(moved, true); assertJoined(identities); }
  finally { fs.open = actualOpen; }
});

test('a byte-free catalog view preserves its parent read lifetime and returns no content', async t => {
  const { cas, ref } = await fixture(t);
  const parent = new AbortController(), child = new AbortController(), reason = new Error('parent catalog verification closed');
  const catalog = new ArtifactCatalog(cas), view = catalog.withReadSignal(parent.signal).withReadSignal(child.signal);
  parent.abort(reason);
  const actualOpen = fs.open; let opens = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => { opens++; return actualOpen(...args); }) as typeof fs.open;
  try { await assert.rejects(view.verifyBytes(ref), error => error === reason); assert.equal(opens, 0); assert.equal(child.signal.aborted, false); }
  finally { fs.open = actualOpen; }
  assert.equal(await catalog.verifyBytes(ref), undefined);
});

for (const closing of ['object', 'root'] as const) test(`actual ${closing} close uncertainty dominates verification cancellation`, async t => {
  const { root, cas, ref } = await fixture(t);
  const owner = new AbortController(), reason = new Error('verification cancelled'), failure = new Error('actual close report uncertain');
  const actualOpen = fs.open, identities: Array<{ dev: number; ino: number }> = []; let closes = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === (closing === 'root' ? root : path.join(root, ref))) {
      const close = handle.close.bind(handle);
      handle.close = async () => { await close(); closes++; owner.abort(reason); throw failure; };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(cas.verify(ref, owner.signal), error => error instanceof ResourceRetirementError && error.cause === failure);
    assert.equal(closes, 1); assert.equal(owner.signal.aborted, true); assertJoined(identities);
  } finally { fs.open = actualOpen; }
});

for (const mutation of ['mtime', 'ctime', 'mode', 'links'] as const) test(`whole verification preserves actual held-file ${mutation} guards`, async t => {
  const { root, cas, ref } = await fixture(t), filename = path.join(root, ref);
  const actualOpen = fs.open, identities: Array<{ dev: number; ino: number }> = []; let changed = false;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === filename) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs);
        if (!changed) {
          changed = true;
          if (mutation === 'mtime') await fs.utimes(filename, new Date(), new Date(Date.now() + 2000));
          if (mutation === 'ctime') { await chmod(filename, 0o600); await chmod(filename, 0o400); }
          if (mutation === 'mode') await chmod(filename, 0o600);
          if (mutation === 'links') await fs.link(filename, path.join(root, 'unexpected-link'));
        }
        return result;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try { await assert.rejects(cas.verify(ref), /changed|invalid mode|link count/); assert.equal(changed, true); assertJoined(identities); }
  finally { fs.open = actualOpen; }
});

test('whole verification exhausts the real corrupt object before rejecting its full digest and joining', async t => {
  const { root, cas, ref, bytes } = await fixture(t), filename = path.join(root, ref);
  const corrupt = Buffer.from(bytes); corrupt[corrupt.length - 1] ^= 1;
  await chmod(filename, 0o600); await fs.writeFile(filename, corrupt); await chmod(filename, 0o400);
  const actualOpen = fs.open, identities: Array<{ dev: number; ino: number }> = []; let readBytes = 0, reads = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === filename) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs); readBytes += result.bytesRead; reads++; return result;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try { await assert.rejects(cas.verify(ref), /is corrupt/); assert.equal(readBytes, bytes.length); assert.equal(reads, 4); assertJoined(identities); }
  finally { fs.open = actualOpen; }
});

for (const size of [0, ARTIFACT_CHUNK_BYTES * 3 + 17]) test(`byte-free verification validates all ${size} bytes without an object-sized allocation`, async t => {
  const { cas, ref } = await fixture(t, Buffer.alloc(size, 0x29));
  const allocate = Buffer.allocUnsafe; let objectAllocations = 0;
  Buffer.allocUnsafe = ((...args: Parameters<typeof Buffer.allocUnsafe>) => {
    if (args[0] === size) objectAllocations++; return allocate(...args);
  }) as typeof Buffer.allocUnsafe;
  try {
    assert.deepEqual(await cas.verify(ref), { ref, byteLength: size });
    assert.equal(await new ArtifactCatalog(cas).verifyBytes(ref), undefined); assert.equal(objectAllocations, 0);
  } finally { Buffer.allocUnsafe = allocate; }
});

test('the actual recovery artifact consumer completely verifies each unique object without allocating its discarded bytes', async t => {
  const { root, cas, ref, bytes } = await fixture(t), small = await cas.publish(Buffer.from('small'));
  const requireArtifacts = recoveryArtifacts(), allocate = Buffer.allocUnsafe, actualOpen = fs.open;
  let objectAllocations = 0, readBytes = 0, reads = 0;
  const identities: Array<{ dev: number; ino: number }> = [];
  Buffer.allocUnsafe = ((...args: Parameters<typeof Buffer.allocUnsafe>) => {
    if (args[0] === bytes.length) objectAllocations++; return allocate(...args);
  }) as typeof Buffer.allocUnsafe;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] !== root) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs); readBytes += result.bytesRead; reads++; return result;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try {
    assert.equal(await requireArtifacts(new ArtifactCatalog(cas), [['original', ref], ['same original', ref], ['absent', undefined], ['small', small]]), undefined);
    assert.equal(readBytes, bytes.length + 5); assert.equal(reads, 5); assertJoined(identities);
    assert.equal(objectAllocations, 0, 'discarded recovery bytes must not allocate a whole object buffer');
  } finally { fs.open = actualOpen; Buffer.allocUnsafe = allocate; }
});

test('byte-free catalog verification forwards cancellation during actual I/O, not only before entry', async t => {
  const { root, cas, ref } = await fixture(t);
  const parent = new AbortController(), child = new AbortController(), reason = new Error('cancel actual catalog I/O');
  const view = new ArtifactCatalog(cas).withReadSignal(parent.signal).withReadSignal(child.signal);
  const actualOpen = fs.open, identities: Array<{ dev: number; ino: number }> = []; let reads = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    if (args[0] === path.join(root, ref)) {
      const read = handle.read.bind(handle);
      handle.read = (async (...readArgs: Parameters<typeof handle.read>) => {
        const result = await read(...readArgs); reads++; child.abort(reason); return result;
      }) as typeof handle.read;
    }
    return handle;
  }) as typeof fs.open;
  try { await assert.rejects(view.verifyBytes(ref), error => error === reason); assert.equal(reads, 1); assert.equal(parent.signal.aborted, false); assertJoined(identities); }
  finally { fs.open = actualOpen; }
});

test('the actual recovery consumer joins all failed siblings and preserves close uncertainty over digest failure', async t => {
  const { root, cas, ref } = await fixture(t), corrupt = await cas.publish(Buffer.from('other original bytes'));
  const filename = path.join(root, corrupt); await chmod(filename, 0o600);
  await fs.writeFile(filename, Buffer.from('other changed! bytes')); await chmod(filename, 0o400);
  const requireArtifacts = recoveryArtifacts(), actualOpen = fs.open, failure = new Error('uncertain sibling close');
  const identities: Array<{ dev: number; ino: number }> = []; let objectsClosed = 0, rootsClosed = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await actualOpen(...args); identities.push(await handle.stat());
    const close = handle.close.bind(handle);
    handle.close = async () => {
      await close();
      if (args[0] === root) rootsClosed++; else objectsClosed++;
      if (args[0] === path.join(root, ref)) throw failure;
    };
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(requireArtifacts(new ArtifactCatalog(cas), [['corrupt original', corrupt], ['uncertain close', ref]]),
      error => error instanceof ResourceRetirementError && error.cause === failure);
    assert.equal(objectsClosed, 2); assert.equal(rootsClosed, 2); assertJoined(identities);
  } finally { fs.open = actualOpen; }
});
