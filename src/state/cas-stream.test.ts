import assert from 'node:assert/strict';
import { chmod, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { fstatSync, promises as fs, readdirSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { sha256Bytes } from '../kernel/identity.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore, isJoinedCasPublicationFailure } from './cas.js';
import { ArtifactCatalog } from './artifacts.js';
import { ResourceRetirementError } from './errors.js';

for (const code of ['ENOSPC', 'EIO']) {
  test('only joined direct CAS write ENOSPC is classified, not source reuse: ' + code, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-joined-write-'));
    await chmod(root, 0o700);
    const store = new ContentAddressedStore(root);
    const failure = Object.assign(new Error('injected direct CAS write failure'), { code });
    const originalOpen = fs.open, identities: Array<{ dev: number; ino: number }> = [];
    let writes = 0;
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      identities.push(await handle.stat());
      if (typeof args[0] === 'string' && args[0].startsWith(path.join(root, '.tmp-stream-'))) {
        const actualWrite = handle.writeFile.bind(handle);
        handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => {
          await actualWrite(...writeArgs); writes++; throw failure;
        };
      }
      return handle;
    }) as typeof fs.open;
    try {
      assert.equal(isJoinedCasPublicationFailure(failure), false);
      await assert.rejects(store.publish(Buffer.from('actual CAS temporary bytes')), error => error === failure);
      assert.equal(writes, 1); assert.equal(isJoinedCasPublicationFailure(failure), code === 'ENOSPC');
      assert.deepEqual(await readdir(root), []);
      for (const name of readdirSync(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd')) {
        if (!/^\d+$/.test(name)) continue;
        let info; try { info = fstatSync(Number(name)); } catch { continue; }
        assert(!identities.some(identity => identity.dev === info.dev && identity.ino === info.ino),
          'a classified write failure must first close its real temporary and root descriptors');
      }
      fs.open = originalOpen;
      // Even the same previously classified Error cannot lend provenance to
      // a producer failure. Its errno alone is never a CAS cleanup receipt.
      await assert.rejects(store.publishChunks((async function* () {
        yield Buffer.from('source bytes'); throw failure;
      })(), 64), error => error === failure);
      assert.equal(isJoinedCasPublicationFailure(failure), false);
      assert.deepEqual(await readdir(root), []);
      if (code === 'ENOSPC') {
        const originalUnlink = fs.unlink;
        try {
          // A later cleanup wrapper must revoke an earlier classification on
          // the reused cause too, not only leave the wrapper unclassified.
          fs.open = (async (...args: Parameters<typeof fs.open>) => {
            const handle = await originalOpen(...args);
            if (typeof args[0] === 'string' && args[0].startsWith(path.join(root, '.tmp-stream-'))) {
              const actualWrite = handle.writeFile.bind(handle);
              handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => { await actualWrite(...writeArgs); throw failure; };
            }
            return handle;
          }) as typeof fs.open;
          await assert.rejects(store.publish(Buffer.from('another joined failure')), error => error === failure);
          assert.equal(isJoinedCasPublicationFailure(failure), true);
          fs.unlink = async target => { await originalUnlink(target); throw new Error('cleanup receipt failed'); };
          await assert.rejects(store.publish(Buffer.from('same cause with failed cleanup')), error => error instanceof ResourceRetirementError);
          assert.equal(isJoinedCasPublicationFailure(failure), false);
        } finally { fs.open = originalOpen; fs.unlink = originalUnlink; }
      }
      const ref = await store.publish(Buffer.from('recovered storage'));
      assert.deepEqual(await store.read(ref), Buffer.from('recovered storage'));
    } finally {
      fs.open = originalOpen;
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const stage of ['temporary_metadata', 'temporary_close', 'temporary_unlink', 'root_close', 'root_identity'] as const) {
  test('CAS write ENOSPC cannot borrow a failed publication join: ' + stage, async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-unjoined-write-'));
    const root = path.join(home, 'objects');
    await fs.mkdir(root, { mode: 0o700 });
    const store = new ContentAddressedStore(root);
    const failure = Object.assign(new Error('injected actual CAS write failure'), { code: 'ENOSPC' });
    const retirementFailure = Object.assign(new Error('injected CAS resource retirement failure'), { code: 'EIO' });
    const originalOpen = fs.open, originalUnlink = fs.unlink;
    let writes = 0, failedJoins = 0;
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      const temporary = typeof args[0] === 'string' && args[0].startsWith(path.join(root, '.tmp-stream-'));
      if (temporary) {
        const actualWrite = handle.writeFile.bind(handle);
        handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => {
          await actualWrite(...writeArgs); writes++; throw failure;
        };
        if (stage === 'temporary_metadata') {
          const actualChmod = handle.chmod.bind(handle);
          handle.chmod = async mode => { await actualChmod(mode); failedJoins++; throw retirementFailure; };
        }
      }
      if ((temporary && stage === 'temporary_close') || (args[0] === root && stage === 'root_close')) {
        const actualClose = handle.close.bind(handle);
        handle.close = async () => { await actualClose(); failedJoins++; throw retirementFailure; };
      }
      return handle;
    }) as typeof fs.open;
    fs.unlink = async target => {
      await originalUnlink(target);
      if (typeof target !== 'string' || !target.startsWith(path.join(root, '.tmp-stream-'))) return;
      if (stage === 'temporary_unlink') { failedJoins++; throw retirementFailure; }
      if (stage === 'root_identity') {
        await fs.rename(root, path.join(home, 'original'));
        await fs.mkdir(root, { mode: 0o700 }); failedJoins++;
      }
    };
    try {
      await assert.rejects(store.publish(Buffer.from('real temporary before failed retirement')), error => {
        assert(error instanceof ResourceRetirementError);
        assert.equal(isJoinedCasPublicationFailure(error), false); return true;
      });
      assert.equal(writes, 1); assert.equal(failedJoins, 1);
      assert.equal(isJoinedCasPublicationFailure(failure), false);
    } finally {
      fs.open = originalOpen; fs.unlink = originalUnlink;
      await rm(home, { recursive: true, force: true });
    }
  });
}

test('a real CAS read close failure is resource retirement failure, not a joined inspection error', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-close-failure-'));
  await chmod(root, 0o700);
  const store = new ContentAddressedStore(root);
  const bytes = Buffer.from('a verified artifact still requires its actual handles to retire');
  const ref = await store.publish(bytes);
  const failure = Object.assign(new Error('injected uncertainty after actual FileHandle.close'), { code: 'EIO' });
  const originalOpen = fs.open;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (args[0] === path.join(root, ref)) {
      const actualClose = handle.close.bind(handle);
      handle.close = async () => { await actualClose(); throw failure; };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(async () => {
      for await (const _chunk of store.readChunks(ref, bytes.length)) { /* Exhaust the real file before its close. */ }
    }, error => error instanceof ResourceRetirementError && error.code === 'RECOVERY_REQUIRED' && error.cause === failure);
  } finally {
    fs.open = originalOpen;
    await rm(root, { recursive: true, force: true });
  }
});

test('an interrupted stream cannot hide failure retiring its actual CAS temporary', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-temporary-close-failure-'));
  await chmod(root, 0o700);
  const store = new ContentAddressedStore(root);
  const sourceFailure = new Error('ordinary inspection stopped the stream');
  const closeFailure = Object.assign(new Error('injected temporary close uncertainty'), { code: 'EIO' });
  const originalOpen = fs.open;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (typeof args[0] === 'string' && args[0].startsWith(path.join(root, '.tmp-stream-'))) {
      const actualClose = handle.close.bind(handle);
      handle.close = async () => { await actualClose(); throw closeFailure; };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(store.publishChunks((async function* () {
      yield Buffer.from('partial bytes');
      throw sourceFailure;
    })(), 64), error => error instanceof ResourceRetirementError && error.cause instanceof AggregateError &&
      error.cause.errors.includes(sourceFailure) && error.cause.errors.some(failure =>
        failure instanceof ResourceRetirementError && failure.cause === closeFailure));
    assert.deepEqual(await readdir(root), []);
  } finally {
    fs.open = originalOpen;
    await rm(root, { recursive: true, force: true });
  }
});

test('temporary unlink failure remains retirement failure even alongside an ordinary source error', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-temporary-unlink-failure-'));
  await chmod(root, 0o700);
  const store = new ContentAddressedStore(root);
  const sourceFailure = new Error('ordinary source read failed');
  const unlinkFailure = Object.assign(new Error('injected temporary unlink uncertainty'), { code: 'EIO' });
  const originalUnlink = fs.unlink;
  fs.unlink = async target => {
    await originalUnlink(target);
    if (typeof target === 'string' && target.startsWith(path.join(root, '.tmp-stream-'))) throw unlinkFailure;
  };
  try {
    await assert.rejects(store.publishChunks((async function* () {
      yield Buffer.from('partial');
      throw sourceFailure;
    })(), 64), error => error instanceof ResourceRetirementError && error.cause instanceof AggregateError &&
      error.cause.errors.includes(sourceFailure) && error.cause.errors.includes(unlinkFailure));
    assert.deepEqual(await readdir(root), []);
  } finally {
    fs.unlink = originalUnlink;
    await rm(root, { recursive: true, force: true });
  }
});

test('interrupted CAS publication retains the source, metadata and close failures without deleting an unknown temporary', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-stream-metadata-failure-'));
  await chmod(root, 0o700);
  const store = new ContentAddressedStore(root);
  const sourceFailure = new Error('source read failed');
  const metadataFailure = Object.assign(new Error('temporary metadata failed'), { code: 'EIO' });
  const closeFailure = Object.assign(new Error('temporary close failed'), { code: 'EIO' });
  const originalOpen = fs.open;
  let closes = 0;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (typeof args[0] === 'string' && args[0].startsWith(path.join(root, '.tmp-stream-'))) {
      const actualChmod = handle.chmod.bind(handle), actualClose = handle.close.bind(handle);
      handle.chmod = async mode => { await actualChmod(mode); throw metadataFailure; };
      handle.close = async () => { await actualClose(); closes++; throw closeFailure; };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(store.publishChunks((async function* () {
      yield Buffer.from('partial');
      throw sourceFailure;
    })(), 64), error => {
      assert.ok(error instanceof ResourceRetirementError);
      assert.ok(error.cause instanceof AggregateError);
      const failures = error.cause.errors;
      assert.equal(failures[0], sourceFailure);
      assert.equal(failures.length, 3);
      assert.ok(failures[1] instanceof ResourceRetirementError && failures[1].cause === metadataFailure);
      assert.ok(failures[2] instanceof ResourceRetirementError && failures[2].cause === closeFailure);
      return true;
    });
    assert.equal(closes, 1, 'metadata failure must not bypass closing the real temporary handle');
    const names = await readdir(root);
    assert.equal(names.length, 1, 'without exact held metadata the temporary must not be unlinked');
    assert.match(names[0]!, /^\.tmp-stream-[0-9a-f]{32}$/u);
  } finally {
    fs.open = originalOpen;
    await rm(root, { recursive: true, force: true });
  }
});

test('canonical reads propagate real CAS root retirement failure without tagging ordinary invalid JSON', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-canonical-close-failure-'));
  await chmod(root, 0o700);
  const store = new ContentAddressedStore(root);
  const artifacts = new ArtifactCatalog(store);
  const ref = await store.publish(Buffer.from('{"complete":true}'));
  const invalidRef = await store.publish(Buffer.from('invalid JSON'));
  const failure = Object.assign(new Error('injected root close uncertainty'), { code: 'EIO' });
  const originalOpen = fs.open;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (args[0] === root) {
      const actualClose = handle.close.bind(handle);
      handle.close = async () => { await actualClose(); throw failure; };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(artifacts.readCanonical(ref), error => error instanceof ResourceRetirementError && error.cause === failure);
    fs.open = originalOpen;
    await assert.rejects(artifacts.readCanonical(invalidRef), error => !(error instanceof ResourceRetirementError) &&
      error instanceof Error && 'code' in error && error.code === 'ARTIFACT_MISMATCH');
    await assert.rejects(artifacts.readCanonical('0'.repeat(64)), error => !(error instanceof ResourceRetirementError) &&
      error instanceof Error && 'code' in error && error.code === 'ENOENT');
    assert.deepEqual(await artifacts.readCanonical(ref), { complete: true });
  } finally {
    fs.open = originalOpen;
    await rm(root, { recursive: true, force: true });
  }
});

test('CAS publishes incrementally observed binary chunks as one verified immutable artifact', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-stream-'));
  await chmod(root, 0o700);
  try {
    const store = new ContentAddressedStore(root);
    const bytes = Buffer.from([0, 255, 1, 128, 2, 3]);
    const result = await store.publishChunks((async function* () {
      yield bytes.subarray(0, 2);
      yield Buffer.alloc(0);
      yield bytes.subarray(2);
    })(), bytes.length);
    assert.deepEqual(result, { ref: sha256Bytes(bytes), byteLength: bytes.length });
    assert.deepEqual(await store.read(result.ref), bytes);
    assert.deepEqual(await readdir(root), [result.ref]);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('CAS streaming enforces its exact byte count, digest and bounded chunks, and closes on early return', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-read-stream-'));
  await chmod(root, 0o700);
  try {
    const store = new ContentAddressedStore(root);
    const bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 3 + 7, 0xff);
    const ref = await store.publish(bytes);
    let count = 0;
    const parts: Buffer[] = [];
    for await (const chunk of store.readChunks(ref, bytes.length)) {
      assert.ok(chunk.length > 0 && chunk.length <= ARTIFACT_CHUNK_BYTES);
      count++;
      parts.push(chunk);
    }
    assert.equal(count, 4);
    assert.deepEqual(Buffer.concat(parts), bytes);
    await assert.rejects(async () => {
      for await (const _chunk of store.readChunks(ref, bytes.length - 1)) { /* Exhaustion required. */ }
    }, /byte count/);

    const identities = [statSync(root), statSync(path.join(root, ref))];
    for (let attempt = 0; attempt < 8; attempt++) {
      for await (const _chunk of store.readChunks(ref, bytes.length)) break;
    }
    // Observe real OS descriptors, not the private generator or FileHandle implementation.
    for (const name of readdirSync(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd')) {
      if (!/^\d+$/.test(name)) continue;
      let info;
      try { info = fstatSync(Number(name)); } catch { continue; }
      assert.ok(!identities.some(identity => identity.dev === info.dev && identity.ino === info.ino), 'early return leaked a held CAS descriptor');
    }
    await chmod(path.join(root, ref), 0o600);
    await writeFile(path.join(root, ref), Buffer.alloc(bytes.length, 0x7f));
    await chmod(path.join(root, ref), 0o400);
    await assert.rejects(async () => {
      for await (const _chunk of store.readChunks(ref, bytes.length)) { /* Rehash complete bytes. */ }
    }, /corrupt/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('interrupted or over-limit streams publish no partial artifact and preserve existing bytes', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-interrupted-stream-'));
  await chmod(root, 0o700);
  try {
    const store = new ContentAddressedStore(root);
    const original = Buffer.from('already committed');
    const ref = await store.publish(original);
    const failure = new Error('source stopped before its final chunk');
    await assert.rejects(store.publishChunks((async function* () {
      yield Buffer.from('partial');
      throw failure;
    })(), 64), error => error === failure);
    for (const [chunk, ceiling] of [[Buffer.alloc(2), 1], [Buffer.alloc(ARTIFACT_CHUNK_BYTES + 1), ARTIFACT_CHUNK_BYTES + 1]] as const) {
      await assert.rejects(store.publishChunks((async function* () { yield chunk; })(), ceiling), /byte ceiling/);
    }
    assert.deepEqual(await readdir(root), [ref]);
    assert.deepEqual(await store.read(ref), original);
    const empty = await store.publishChunks((async function* () { yield Buffer.alloc(0); })(), 0);
    assert.deepEqual(empty, { ref: sha256Bytes(Buffer.alloc(0)), byteLength: 0 });
    const chunks = [];
    for await (const chunk of store.readChunks(empty.ref, 0)) chunks.push(chunk);
    assert.deepEqual(chunks, []);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('a stream cannot become verified after its held file changes between real read batches', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-cas-changing-stream-'));
  await chmod(root, 0o700);
  try {
    const store = new ContentAddressedStore(root);
    const bytes = Buffer.alloc(ARTIFACT_CHUNK_BYTES * 2, 0x41);
    const ref = await store.publish(bytes);
    const reading = store.readChunks(ref, bytes.length);
    try {
      assert.deepEqual((await reading.next()).value, bytes.subarray(0, ARTIFACT_CHUNK_BYTES));
      await chmod(path.join(root, ref), 0o600);
      await writeFile(path.join(root, ref), bytes); // Equal bytes do not erase the observed mutation.
      await chmod(path.join(root, ref), 0o400);
      await assert.rejects(async () => { for await (const _chunk of reading) { /* Exhaust before granting authority. */ } }, /changed/);
    } finally { await reading.return(undefined); }
  } finally { await rm(root, { recursive: true, force: true }); }
});
