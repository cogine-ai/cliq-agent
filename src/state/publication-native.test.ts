import assert from 'node:assert/strict';
import { link, lstat, mkdir, mkdtemp, readFile, readlink, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { identityHash } from '../kernel/identity.js';
import { loadNativeStateOwner, openHeldPublicationOperation as openNativePublicationOperation,
  readHeldPublicationBirth, readRetiredPublicationArena, type HeldPublicationOperation,
  type HeldStateOwnerLock, type HeldWorkspaceRoot, type NativePublicationOperationInput } from './native-owner.js';

type PhysicalInput<T = NativePublicationOperationInput> = T extends unknown ? Omit<T, 'arenaId'> & { arenaId?: string } : never;
const arenaId = (kind: string, target: string) => identityHash('physical-publication-fixture', kind, target);
const arenaPath = (state: string, kind: string, target: string, component: string) =>
  path.join(state, 'runtime', 'publications', arenaId(kind, target), component);
const openHeldPublicationOperation = (lock: HeldStateOwnerLock, root: HeldWorkspaceRoot, input: PhysicalInput) => {
  const operation = openNativePublicationOperation(lock, root, { ...input, arenaId: input.arenaId ?? arenaId(input.kind, input.path) });
  // This approved physical seam supplies no SQL permission or claim. Its
  // normal-operation cases explicitly exercise the mechanism's release gate.
  if (!input.retained) operation.arm();
  return operation;
};

// Real filesystem mechanism only. No Run, approval, Journal or installed
// execution authority is supplied or qualified by this native seam.
test('a structural publication birth stand-in is rejected before input properties execute', () => {
  const hostile = Object.defineProperty({}, 'observe', { get() { assert.fail('structural birth must not be inspected'); } });
  assert.throws(() => readHeldPublicationBirth({} as HeldStateOwnerLock, hostile as HeldPublicationOperation), TypeError);
  assert.throws(() => readRetiredPublicationArena({} as HeldStateOwnerLock, hostile as HeldPublicationOperation), TypeError);
});

test('an actual private birth remains unarmed until its original physical release gate is applied', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-birth-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openNativePublicationOperation(lock, root, { arenaId: arenaId('create', 'file'), kind: 'create', path: 'file',
    parents: [{ ...root.identity, mode: root.mode }], expected: { kind: 'absent' }, desired: { kind: 'file', mode: 420, byteCount: 4,
      digest: createHash('sha256').update('good').digest('hex') }, stagingName: '.stage' });
  try {
    operation.stage(); operation.writeChunk(Buffer.from('good')); while (!operation.finishStage()) { /* bounded actual disk hash */ }
    assert.throws(() => operation.commit(), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(lstat(path.join(workspace, 'file')), { code: 'ENOENT' });
    const birth = readHeldPublicationBirth(lock, operation), actual = await lstat(arenaPath(state, 'create', 'file', ''), { bigint: true });
    assert.deepEqual(birth.arenaIdentity, { deviceId: String(actual.dev), fileId: String(actual.ino), ownerUid: Number(actual.uid), mode: 0o700 });
    assert.equal(birth.parentIdentity.mode, 0o700); assert.equal(birth.arenaId, arenaId('create', 'file'));
    operation.arm(); operation.commit(); assert.equal(await readFile(path.join(workspace, 'file'), 'utf8'), 'good');
  } finally { operation.close(); }
});

test('the original operation retires its exact empty arena with truthful platform observations', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-retire-arena-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'create', path: 'file', parents: [{ ...root.identity, mode: root.mode }],
    expected: { kind: 'absent' }, desired: { kind: 'file', mode: 420, byteCount: 4, digest: createHash('sha256').update('good').digest('hex') }, stagingName: '.stage' });
  try {
    const birth = readHeldPublicationBirth(lock, operation);
    operation.stage(); operation.writeChunk(Buffer.from('good')); while (!operation.finishStage()) { /* bounded hash */ }
    operation.commit(); while (operation.readDestinationChunk() !== null) { /* actual destination */ }
    operation.finishCleanup(); operation.finishArenaRetirement();
    await assert.rejects(lstat(arenaPath(state, 'create', 'file', '')), { code: 'ENOENT' });
    const observation = operation.observe(); assert.equal(observation.arena.retired, true);
    assert.deepEqual(observation.arena.identity, { deviceId: birth.arenaIdentity.deviceId, fileId: birth.arenaIdentity.fileId, ownerUid: birth.arenaIdentity.ownerUid });
    assert.deepEqual(observation.arena.retirementObservation, process.platform === 'linux'
      ? { kind: 'linux_unlinked', linkCount: 0 }
      : { kind: 'darwin_unlinked', heldPathUnchanged: true, parentPathUnchanged: true, observedLinkCount: observation.arena.linkCount });
    assert.throws(() => readHeldPublicationBirth(lock, operation), { code: 'RECOVERY_REQUIRED' });
    operation.finishArenaRetirement(); assert.equal(await readFile(path.join(workspace, 'file'), 'utf8'), 'good');
    assert.throws(() => readRetiredPublicationArena(lock, operation), { code: 'RECOVERY_REQUIRED' });
    operation.close();
    const retirement = readRetiredPublicationArena(lock, operation);
    assert.deepEqual(retirement.arenaIdentity, birth.arenaIdentity); assert.deepEqual(retirement.parentIdentity, birth.parentIdentity);
    assert.deepEqual(retirement.retirementObservation, observation.arena.retirementObservation);
    await mkdir(arenaPath(state, 'create', 'file', ''), { mode: 0o700 });
    assert.throws(() => readRetiredPublicationArena(lock, operation), { code: 'RECOVERY_REQUIRED' });
  } finally { operation.close(); }
  lock.close(); const successor = native.acquireLock(state, false); successor.close();
});

test('the branded native abort accepts only its exact directory and preserves the original cleanup boundary', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-abort-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const parents = [{ ...root.identity, mode: root.mode }];
  const creator = openHeldPublicationOperation(lock, root, { kind: 'mkdir', path: 'directory', parents,
    expected: { kind: 'absent' }, desired: { kind: 'directory', mode: 493 } });
  try {
    creator.stage(); creator.finishStage(); creator.commit(); while (creator.readDestinationChunk() !== null) { /* actual inode */ }
    creator.finishCleanup(); creator.finishArenaRetirement();
  } finally { creator.close(); }
  const before = await lstat(path.join(workspace, 'directory'), { bigint: true });
  const input: NativePublicationOperationInput = { arenaId: arenaId('abort_rmdir', 'directory'), kind: 'abort_rmdir', path: 'directory', parents,
    expected: { kind: 'directory', mode: Number(before.mode & 0o7777n), identity: { deviceId: String(before.dev), fileId: String(before.ino), ownerUid: Number(before.uid) } },
    desired: { kind: 'absent' }, quarantineName: 'preimage' };
  for (const patch of [{ quarantineName: 'other' }, { stagingName: 'desired' }, { desired: { kind: 'directory', mode: 493 } }])
    assert.throws(() => openNativePublicationOperation(lock, root, { ...input, ...patch } as NativePublicationOperationInput), TypeError);
  const operation = openNativePublicationOperation(lock, root, input);
  try {
    assert.equal(operation.readOriginalChunk(), null); operation.stage(); assert.equal(operation.finishStage(), true);
    assert.throws(() => operation.commit(), { code: 'RECOVERY_REQUIRED' }); operation.arm(); operation.commit();
    assert.equal(operation.observe().destination.kind, 'absent');
    const quarantine = operation.observe().quarantine;
    assert.equal(quarantine?.kind, 'directory'); if (quarantine?.kind === 'directory') assert.equal(quarantine.identity.fileId, String(before.ino));
    assert.throws(() => operation.finishCleanup(), { code: 'RECOVERY_REQUIRED' });
    // Actual component preservation only, not a manufactured durable SQL barrier.
    assert.equal(operation.readPreimageChunk(), null); operation.revoke(); operation.finishCleanup(); operation.finishArenaRetirement(); operation.close();
    assert.equal(readRetiredPublicationArena(lock, operation).arenaId, input.arenaId);
    await assert.rejects(lstat(path.join(workspace, 'directory')), { code: 'ENOENT' });
  } finally { operation.close(); }
});

test('a fixed native create preserves its held parent and publishes only its staged bytes', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'create', path: 'answer.txt',
    parents: [{ ...root.identity, mode: 0o700 }], expected: { kind: 'absent' },
    desired: { kind: 'file', mode: 0o644, byteCount: 20, digest: createHash('sha256').update('actual staged bytes\n').digest('hex') }, stagingName: '.cliq-owned-stage' });
  try {
    operation.stage(); operation.writeChunk(Buffer.from('actual staged bytes\n')); operation.finishStage();
    await assert.rejects(readFile(path.join(workspace, 'answer.txt')), { code: 'ENOENT' });
    operation.commit();
    assert.equal(await readFile(path.join(workspace, 'answer.txt'), 'utf8'), 'actual staged bytes\n');
    assert.equal(operation.observe().destination.kind, 'file');
    operation.finishCleanup();
    assert.equal(operation.observe().staging?.kind, 'absent');
  } finally { operation.close(); }
});

test('replace retains the actual original inode and bytes until explicit cleanup', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-replace-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  await writeFile(path.join(workspace, 'answer.txt'), 'original\n', { mode: 0o600 });
  const before = await lstat(path.join(workspace, 'answer.txt'), { bigint: true });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'replace', path: 'answer.txt',
    parents: [{ ...root.identity, mode: root.mode }], expected: { kind: 'file', mode: 0o600, byteCount: 9,
      digest: createHash('sha256').update('original\n').digest('hex') },
    desired: { kind: 'file', mode: 0o644, byteCount: 12, digest: createHash('sha256').update('replacement\n').digest('hex') },
    stagingName: '.cliq-owned-stage', quarantineName: '.cliq-owned-quarantine' });
  try {
    assert.equal(operation.readOriginalChunk()?.toString(), 'original\n');
    assert.equal(operation.readOriginalChunk(), null);
    operation.stage(); operation.writeChunk(Buffer.from('replacement\n')); assert.equal(operation.finishStage(), true);
    operation.commit();
    assert.equal(await readFile(path.join(workspace, 'answer.txt'), 'utf8'), 'replacement\n');
    assert.equal((await lstat(arenaPath(state, 'replace', 'answer.txt', '.cliq-owned-quarantine'), { bigint: true })).ino, before.ino);
    assert.equal(operation.readPreimageChunk()?.toString(), 'original\n'); assert.equal(operation.readPreimageChunk(), null);
    operation.finishCleanup();
    await assert.rejects(lstat(arenaPath(state, 'replace', 'answer.txt', '.cliq-owned-quarantine')), { code: 'ENOENT' });
    assert.equal(await readFile(path.join(workspace, 'answer.txt'), 'utf8'), 'replacement\n');
  } finally { operation.close(); }
});

test('leaf to directory replacement creates a real parent without discarding the old leaf', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-directory-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  await writeFile(path.join(workspace, 'old'), 'old leaf', { mode: 0o600 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'replace', path: 'old',
    parents: [{ ...root.identity, mode: root.mode }], expected: { kind: 'file', mode: 0o600, byteCount: 8,
      digest: createHash('sha256').update('old leaf').digest('hex') }, desired: { kind: 'directory', mode: 0o755 },
    stagingName: '.cliq-owned-stage', quarantineName: '.cliq-owned-quarantine' });
  try {
    assert.equal(operation.readOriginalChunk()?.toString(), 'old leaf'); assert.equal(operation.readOriginalChunk(), null);
    operation.stage(); assert.equal(operation.finishStage(), true); operation.commit();
    assert.equal((await lstat(path.join(workspace, 'old'))).isDirectory(), true);
    assert.equal((await lstat(path.join(workspace, 'old'))).mode & 0o7777, 0o755);
    assert.equal(operation.readPreimageChunk()?.toString(), 'old leaf'); assert.equal(operation.readPreimageChunk(), null);
    operation.finishCleanup();
    const directory = operation.observe().destination;
    assert.equal(directory.kind, 'directory'); assert.equal(directory.linkCount >= 2, true);
  } finally { operation.close(); }
});

test('an empty real directory can become a leaf only after its original identity is verified', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-dir-leaf-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 }); await mkdir(path.join(workspace, 'old'), { mode: 0o700 });
  const before = await lstat(path.join(workspace, 'old'), { bigint: true });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'replace', path: 'old',
    parents: [{ ...root.identity, mode: root.mode }], expected: { kind: 'directory', mode: 0o700,
      identity: { deviceId: String(before.dev), fileId: String(before.ino), ownerUid: Number(before.uid) } },
    desired: { kind: 'file', mode: 0o644, byteCount: 4, digest: createHash('sha256').update('leaf').digest('hex') },
    stagingName: '.cliq-owned-stage', quarantineName: '.cliq-owned-quarantine' });
  try {
    assert.equal(operation.readOriginalChunk(), null);
    operation.stage(); operation.writeChunk(Buffer.from('leaf')); assert.equal(operation.finishStage(), true); operation.commit();
    assert.equal(await readFile(path.join(workspace, 'old'), 'utf8'), 'leaf');
    assert.equal((await lstat(arenaPath(state, 'replace', 'old', '.cliq-owned-quarantine'), { bigint: true })).ino, before.ino);
    assert.equal(operation.readPreimageChunk(), null); operation.finishCleanup();
    await assert.rejects(lstat(arenaPath(state, 'replace', 'old', '.cliq-owned-quarantine')), { code: 'ENOENT' });
  } finally { operation.close(); }
});

test('mkdir and empty directory deletion use one held lifecycle without file hardlink assumptions', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-mkdir-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const parents = [{ ...root.identity, mode: root.mode }];
  const create = openHeldPublicationOperation(lock, root, { kind: 'mkdir', path: 'directory', parents,
    expected: { kind: 'absent' }, desired: { kind: 'directory', mode: 0o755 } });
  try {
    create.stage(); assert.equal(create.finishStage(), true);
    await assert.rejects(lstat(path.join(workspace, 'directory')), { code: 'ENOENT' });
    create.commit(); create.finishCleanup();
    const before = await lstat(path.join(workspace, 'directory'), { bigint: true });
    const remove = openHeldPublicationOperation(lock, root, { kind: 'delete', path: 'directory', parents,
      expected: { kind: 'directory', mode: 0o755, identity: { deviceId: String(before.dev), fileId: String(before.ino), ownerUid: Number(before.uid) } },
      desired: { kind: 'absent' }, quarantineName: '.cliq-owned-quarantine' });
    try {
      assert.equal(remove.readOriginalChunk(), null); remove.stage(); assert.equal(remove.finishStage(), true); remove.commit();
      await assert.rejects(lstat(path.join(workspace, 'directory')), { code: 'ENOENT' });
      assert.equal((await lstat(arenaPath(state, 'delete', 'directory', '.cliq-owned-quarantine'), { bigint: true })).ino, before.ino);
      assert.equal(remove.readPreimageChunk(), null); remove.finishCleanup();
      await assert.rejects(lstat(arenaPath(state, 'delete', 'directory', '.cliq-owned-quarantine')), { code: 'ENOENT' });
    } finally { remove.close(); }
  } finally { create.close(); }
});

test('symlink publication preserves exact target bytes without following either target', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-link-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const parents = [{ ...root.identity, mode: root.mode }];
  const create = openHeldPublicationOperation(lock, root, { kind: 'create', path: 'link', parents,
    expected: { kind: 'absent' }, desired: { kind: 'symlink', target: 'missing/文', digest: createHash('sha256').update('missing/文').digest('hex') },
    stagingName: '.cliq-owned-stage' });
  try {
    create.stage(); assert.equal(create.finishStage(), true); create.commit(); create.finishCleanup();
    assert.equal(await readlink(path.join(workspace, 'link')), 'missing/文');
    const replace = openHeldPublicationOperation(lock, root, { kind: 'replace', path: 'link', parents,
      expected: { kind: 'symlink', target: 'missing/文', digest: createHash('sha256').update('missing/文').digest('hex') },
      desired: { kind: 'symlink', target: 'other', digest: createHash('sha256').update('other').digest('hex') },
      stagingName: '.cliq-next-stage', quarantineName: '.cliq-owned-quarantine' });
    try {
      assert.equal(replace.readOriginalChunk()?.toString(), 'missing/文'); assert.equal(replace.readOriginalChunk(), null);
      replace.stage(); assert.equal(replace.finishStage(), true); replace.commit();
      assert.equal(await readlink(path.join(workspace, 'link')), 'other');
      assert.equal(replace.readPreimageChunk()?.toString(), 'missing/文'); assert.equal(replace.readPreimageChunk(), null);
      replace.finishCleanup(); assert.equal(await readlink(path.join(workspace, 'link')), 'other');
    } finally { replace.close(); }
  } finally { create.close(); }
});

test('post-commit observations hash the real destination instead of reusing the desired digest', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-read-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const digest = createHash('sha256').update('real bytes').digest('hex');
  const operation = openHeldPublicationOperation(lock, root, { kind: 'create', path: 'file', parents: [{ ...root.identity, mode: root.mode }],
    expected: { kind: 'absent' }, desired: { kind: 'file', mode: 0o644, byteCount: 10, digest }, stagingName: '.stage' });
  try {
    operation.stage(); operation.writeChunk(Buffer.from('real bytes')); assert.equal(operation.finishStage(), true); operation.commit();
    const unverified = operation.observe().destination; assert.equal(unverified.kind !== 'absent' && unverified.digest, undefined);
    assert.equal(operation.readDestinationChunk()?.toString(), 'real bytes'); assert.equal(operation.readDestinationChunk(), null);
    const verified = operation.observe().destination; assert.equal(verified.kind !== 'absent' && verified.digest, digest);
    await writeFile(path.join(workspace, 'file'), 'corruption');
    assert.throws(() => operation.observe(), { code: 'RECOVERY_REQUIRED' });
    assert.throws(() => operation.finishCleanup(), { code: 'RECOVERY_REQUIRED' });
    assert.equal(await readFile(path.join(workspace, 'file'), 'utf8'), 'corruption');
  } finally { operation.close(); }
});

test('revocation stops semantic release but permits exact unpublished staging cleanup and descriptor join', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-revoke-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'create', path: 'file', parents: [{ ...root.identity, mode: root.mode }],
    expected: { kind: 'absent' }, desired: { kind: 'file', mode: 0o644, byteCount: 5, digest: createHash('sha256').update('bytes').digest('hex') }, stagingName: '.stage' });
  operation.stage(); operation.writeChunk(Buffer.from('bytes')); assert.equal(operation.finishStage(), true);
  operation.revoke();
  assert.throws(() => operation.commit(), { code: 'RECOVERY_REQUIRED' });
  await assert.rejects(lstat(path.join(workspace, 'file')), { code: 'ENOENT' });
  operation.discardStage(); operation.finishArenaRetirement(); operation.close();
  assert.equal(readRetiredPublicationArena(lock, operation).arenaId, arenaId('create', 'file'));
  await assert.rejects(lstat(arenaPath(state, 'create', 'file', '.stage')), { code: 'ENOENT' });
  await assert.rejects(lstat(arenaPath(state, 'create', 'file', '')), { code: 'ENOENT' });
  lock.close(); const successor = native.acquireLock(state, false); successor.close();
});

test('retained cleanup reopens only exact physically observed destination and preimage identities', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-retained-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 }); await writeFile(path.join(workspace, 'file'), 'old', { mode: 0o600 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  const input = { kind: 'replace' as const, path: 'file', parents: [{ ...root.identity, mode: root.mode }],
    expected: { kind: 'file' as const, mode: 0o600, byteCount: 3, digest: createHash('sha256').update('old').digest('hex') },
    desired: { kind: 'file' as const, mode: 0o644 as const, byteCount: 3, digest: createHash('sha256').update('new').digest('hex') },
    stagingName: '.stage', quarantineName: '.old' };
  const operation = openHeldPublicationOperation(lock, root, input);
  assert.equal(operation.readOriginalChunk()?.toString(), 'old'); assert.equal(operation.readOriginalChunk(), null);
  operation.stage(); operation.writeChunk(Buffer.from('new')); assert.equal(operation.finishStage(), true); operation.commit();
  assert.equal(operation.readDestinationChunk()?.toString(), 'new'); assert.equal(operation.readDestinationChunk(), null);
  assert.equal(operation.readPreimageChunk()?.toString(), 'old'); assert.equal(operation.readPreimageChunk(), null);
  const observation = operation.observe(); assert.notEqual(observation.destination.kind, 'absent'); assert.notEqual(observation.quarantine?.kind, 'absent');
  if (observation.destination.kind === 'absent' || !observation.quarantine || observation.quarantine.kind === 'absent') assert.fail('actual entries required');
  // Persisted path observations carry dev+ino, not a historical file ownerUid.
  // The native reopen must bind those actual inodes and freshly inspect UID.
  const inode = ({ deviceId, fileId }: { deviceId: string; fileId: string }) => ({ deviceId, fileId });
  const retained = { arena: inode(observation.arena.identity), destination: inode(observation.destination.identity), preimage: inode(observation.quarantine.identity) };
  operation.close(); root.close(); lock.close();
  const successor = native.acquireLock(state, false), reopenedRoot = native.openWorkspaceRoot(workspace);
  t.after(async () => { reopenedRoot.close(); successor.close(); await rm(fixture, { recursive: true, force: true }); });
  const recovery = openHeldPublicationOperation(successor, reopenedRoot, { ...input, retained });
  try {
    assert.throws(() => openHeldPublicationOperation(successor, reopenedRoot, { ...input,
      retained: { ...retained, destination: { ...retained.destination, fileId: String(BigInt(retained.destination.fileId) + 1n) } } }), { code: 'RECOVERY_REQUIRED' });
    assert.equal(recovery.readDestinationChunk()?.toString(), 'new'); assert.equal(recovery.readDestinationChunk(), null);
    assert.equal(recovery.readPreimageChunk()?.toString(), 'old'); assert.equal(recovery.readPreimageChunk(), null);
    recovery.finishCleanup();
    await assert.rejects(lstat(arenaPath(state, 'replace', 'file', '.old')), { code: 'ENOENT' });
    assert.equal(await readFile(path.join(workspace, 'file'), 'utf8'), 'new');
  } finally { recovery.close(); }
});

test('a failed preimage consumer can restart a complete bounded read on the same original owner', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-rewind-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace'), old = Buffer.alloc(131073, 0x61);
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 }); await writeFile(path.join(workspace, 'file'), old, { mode: 0o600 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'replace', path: 'file', parents: [{ ...root.identity, mode: root.mode }],
    expected: { kind: 'file', mode: 0o600, byteCount: old.length, digest: createHash('sha256').update(old).digest('hex') },
    desired: { kind: 'file', mode: 0o644, byteCount: 3, digest: createHash('sha256').update('new').digest('hex') }, stagingName: '.stage', quarantineName: '.old' });
  try {
    while (operation.readOriginalChunk() !== null) { /* real full preflight */ }
    operation.stage(); operation.writeChunk(Buffer.from('new')); assert.equal(operation.finishStage(), true); operation.commit();
    assert.equal(operation.readPreimageChunk()?.length, 65536);
    operation.restartRead('preimage');
    const chunks = []; for (;;) { const chunk = operation.readPreimageChunk(); if (chunk === null) break; chunks.push(chunk); }
    assert.deepEqual(chunks.map(chunk => chunk.length), [65536, 65536, 1]); assert.deepEqual(Buffer.concat(chunks), old);
    operation.finishCleanup();
  } finally { operation.close(); }
});

test('a multiply-linked old regular target is refused without creating any publication sibling', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-hardlink-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 }); await writeFile(path.join(workspace, 'file'), 'old', { mode: 0o600 });
  await link(path.join(workspace, 'file'), path.join(workspace, 'alias'));
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  assert.throws(() => openHeldPublicationOperation(lock, root, { kind: 'delete', path: 'file', parents: [{ ...root.identity, mode: root.mode }],
    expected: { kind: 'file', mode: 0o600, byteCount: 3, digest: createHash('sha256').update('old').digest('hex') }, desired: { kind: 'absent' }, quarantineName: '.old' }), { code: 'RECOVERY_REQUIRED' });
  assert.deepEqual((await readdir(workspace)).sort(), ['alias', 'file']);
  assert.equal(await readFile(path.join(workspace, 'alias'), 'utf8'), 'old');
  lock.close(); const successor = native.acquireLock(state, false); successor.close();
});

test('equal bytes at an unowned staging inode cannot be published or cleaned up', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-replaced-stage-')));
  const state = path.join(fixture, 'state'), workspace = path.join(fixture, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(fixture, { recursive: true, force: true }); });
  const operation = openHeldPublicationOperation(lock, root, { kind: 'create', path: 'file', parents: [{ ...root.identity, mode: root.mode }],
    expected: { kind: 'absent' }, desired: { kind: 'file', mode: 0o644, byteCount: 5, digest: createHash('sha256').update('bytes').digest('hex') }, stagingName: '.stage' });
  try {
    operation.stage(); operation.writeChunk(Buffer.from('bytes')); assert.equal(operation.finishStage(), true);
    await rename(arenaPath(state, 'create', 'file', '.stage'), arenaPath(state, 'create', 'file', '.original'));
    await writeFile(arenaPath(state, 'create', 'file', '.stage'), 'bytes', { mode: 0o644 });
    assert.throws(() => operation.commit(), { code: 'RECOVERY_REQUIRED' });
    assert.throws(() => operation.discardStage(), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(lstat(path.join(workspace, 'file')), { code: 'ENOENT' });
    assert.equal(await readFile(arenaPath(state, 'create', 'file', '.stage'), 'utf8'), 'bytes');
    assert.equal(await readFile(arenaPath(state, 'create', 'file', '.original'), 'utf8'), 'bytes');
  } finally { operation.close(); }
});
