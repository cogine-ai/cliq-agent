import assert from 'node:assert/strict';
import { fstatSync } from 'node:fs';
import { link, lstat, mkdir, mkdtemp, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { loadNativeStateOwner, openHeldPublicationGitIndex, type HeldWorkspaceRoot } from './native-owner.js';

/** Real descriptor mechanism only. Bytes are deliberately not a Git semantic
 * proof, publication approval, Run or installed execution qualification. */
async function fixture(t: TestContext, initial?: Buffer) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-index-')));
  const state = path.join(directory, 'state'), workspace = path.join(directory, 'workspace'), git = path.join(workspace, '.git');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 }); await mkdir(git, { mode: 0o700 });
  const index = path.join(git, 'index'); if (initial) await writeFile(index, initial, { flag: 'wx', mode: 0o600 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(directory, { recursive: true, force: true }); });
  const input = { repositoryDirectory: root.repositoryDirectory!, maxBytes: 262_144 };
  return { directory, state, workspace, git, index, native, lock, root, input };
}
async function matchingFds(filename: string): Promise<number[]> {
  const expected = await lstat(filename, { bigint: true }), numbers = await readdir(process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd');
  return numbers.flatMap(name => { try {
    const number = Number(name), actual = fstatSync(number, { bigint: true });
    return actual.dev === expected.dev && actual.ino === expected.ino ? [number] : [];
  } catch { return []; } });
}

test('fixed publication index reads every original byte and real EOF before complete, then closes its exact FD', async t => {
  const bytes = Buffer.alloc(160_019, 0x65), f = await fixture(t, bytes);
  assert.deepEqual(await matchingFds(f.index), []);
  const reader = openHeldPublicationGitIndex(f.lock, f.root, f.input);
  const fds = await matchingFds(f.index); assert.equal(fds.length, 1);
  assert.equal(reader.present, true); assert.equal(reader.byteCount, bytes.length);
  assert.throws(() => reader.assertComplete(), { code: 'RECOVERY_REQUIRED' });
  const chunks: Buffer[] = []; for (;;) { const chunk = reader.readChunk(); if (chunk === null) break;
    assert(chunk.length > 0 && chunk.length <= 65536); chunks.push(chunk); }
  reader.assertComplete(); assert.deepEqual(Buffer.concat(chunks), bytes); reader.assertHeld(); reader.close(); reader.close();
  for (const fd of fds) assert.throws(() => fstatSync(fd), { code: 'EBADF' });
  assert.throws(() => reader.readChunk(), { code: 'RECOVERY_REQUIRED' });
});

test('index absence is only a current physical observation, never an automatic empty-index proof', async t => {
  const f = await fixture(t), reader = openHeldPublicationGitIndex(f.lock, f.root, f.input);
  try {
    assert.equal(reader.present, false); assert.equal(reader.byteCount, 0); assert.equal(reader.identity, undefined);
    assert.throws(() => reader.assertComplete(), { code: 'RECOVERY_REQUIRED' });
    assert.equal(reader.readChunk(), null); reader.assertComplete();
    await writeFile(f.index, Buffer.from('new index'), { mode: 0o600, flag: 'wx' });
    assert.throws(() => reader.assertHeld(), { code: 'RECOVERY_REQUIRED' });
  } finally { reader.close(); }
});

for (const kind of ['symlink', 'hardlink', 'directory', 'oversized'] as const) {
  test(`fixed publication index refuses ${kind} before borrowing payload`, async t => {
    const f = await fixture(t);
    if (kind === 'directory') await mkdir(f.index);
    else if (kind === 'symlink') {
      const target = path.join(f.directory, 'unrelated'); await writeFile(target, 'not authorized'); await symlink(target, f.index);
    } else {
      await writeFile(f.index, Buffer.alloc(kind === 'oversized' ? f.input.maxBytes + 1 : 17), { mode: 0o600, flag: 'wx' });
      if (kind === 'hardlink') await link(f.index, path.join(f.git, 'extra-link'));
    }
    assert.throws(() => openHeldPublicationGitIndex(f.lock, f.root, f.input), { code: 'RECOVERY_REQUIRED' });
    f.lock.assertHeld(); f.root.assertHeld();
  });
}

for (const kind of ['fileId', 'deviceId', 'ownerUid'] as const) {
  test(`fixed publication index binds captured original repository ${kind}`, async t => {
    const f = await fixture(t, Buffer.from('physical index bytes'));
    const wrong = { ...f.input.repositoryDirectory, [kind]: kind === 'ownerUid' ? f.input.repositoryDirectory.ownerUid + 1 :
      String(BigInt(f.input.repositoryDirectory[kind]) + 1n) };
    assert.throws(() => openHeldPublicationGitIndex(f.lock, f.root, { ...f.input, repositoryDirectory: wrong }), { code: 'RECOVERY_REQUIRED' });
    assert.deepEqual(await matchingFds(f.index), []);
  });
}

for (const kind of ['index_replace', 'index_mutate', 'git_replace'] as const) {
  test(`fixed publication index rejects ${kind} during its original borrow`, async t => {
    const f = await fixture(t, Buffer.alloc(100_017, 0x78)), reader = openHeldPublicationGitIndex(f.lock, f.root, f.input);
    try {
      assert.equal(reader.readChunk()!.length, 65536);
      if (kind === 'index_mutate') await writeFile(f.index, Buffer.alloc(100_017, 0x79));
      else if (kind === 'index_replace') { await rename(f.index, f.index + '.old'); await writeFile(f.index, 'replacement'); }
      else { await rename(f.git, f.git + '.old'); await mkdir(f.git, { mode: 0o700 }); await writeFile(f.index, 'replacement'); }
      assert.throws(() => reader.readChunk(), { code: 'RECOVERY_REQUIRED' });
      assert.throws(() => reader.assertComplete(), { code: 'RECOVERY_REQUIRED' });
      if (kind === 'git_replace') {
        const today = f.native.openWorkspaceRoot(f.workspace);
        try { assert.throws(() => openHeldPublicationGitIndex(f.lock, today, f.input), { code: 'RECOVERY_REQUIRED' }); }
        finally { today.close(); }
      }
    } finally { reader.close(); }
  });
}

for (const owner of ['workspace', 'state_owner'] as const) {
  test(`${owner} close really joins every fixed index reader before the owner releases`, async t => {
    const f = await fixture(t, Buffer.alloc(100_017, 0x78)), reader = openHeldPublicationGitIndex(f.lock, f.root, f.input);
    reader.readChunk(); const fds = await matchingFds(f.index); assert.equal(fds.length, 1);
    if (owner === 'workspace') f.root.close(); else f.lock.close();
    for (const fd of fds) assert.throws(() => fstatSync(fd), { code: 'EBADF' });
    assert.throws(() => reader.readChunk(), { code: 'RECOVERY_REQUIRED' }); reader.close();
    if (owner === 'state_owner') { const successor = f.native.acquireLock(f.state, false); successor.close(); }
  });
}

test('fixed index bridge rejects structural roots and data accessors without a generic source payload entry', async t => {
  const f = await fixture(t, Buffer.from('physical bytes')); let inspected = false;
  const malicious = Object.defineProperty({}, 'repositoryDirectory', { get() { inspected = true; throw new Error('untrusted accessor'); } });
  assert.throws(() => openHeldPublicationGitIndex(f.lock, {} as HeldWorkspaceRoot, malicious as typeof f.input), TypeError);
  assert.equal(inspected, false);
  assert.throws(() => openHeldPublicationGitIndex(f.lock, f.root, malicious as typeof f.input), TypeError);
  assert.equal(inspected, false);
  const reader = openHeldPublicationGitIndex(f.lock, f.root, f.input);
  try { assert.throws(() => reader.readChunk.call({}), TypeError); }
  finally { reader.close(); }
  assert.throws(() => f.root.readGitConfigChunk(), /Git payload requires/u);
  const cursor = f.root.openSnapshot();
  try { assert.equal(cursor.next(), null); cursor.assertComplete(); }
  finally { cursor.close(); }
});
