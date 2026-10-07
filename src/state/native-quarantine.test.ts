import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { chmod, link, lstat, mkdir, open, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { Module } from 'node:module';
import { constants } from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { StateRootIdentityV1, WorkspaceGenerationIdentityV1 } from '../kernel/types.js';
import { decodeWorkspaceGenerationIdentity } from './decoders.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { openStateStore } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';
import { childFor } from './testing/state-owner-process.js';

const native = await loadNativeStateOwner();
const linux = process.platform === 'linux';
const digest = canonicalSha256({ fixture: 'native-quarantine' });

async function fixture(t: TestContext) {
  const root = await makePrivateDir('.cliq-quarantine-');
  const held = native.acquireLock(root, true);
  t.after(async () => { held.close(); await rm(root, { recursive: true, force: true }); });
  const rootIdentity: StateRootIdentityV1 = {
    schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: linux ? 'linux' : 'macos', canonicalAbsolutePath: root,
    ownerUid: held.root.ownerUid, deviceId: held.root.deviceId, directoryFileId: held.root.fileId,
    mode: 448, openedNoFollow: true, layoutVersion: 1, identityDigest: ''
  };
  rootIdentity.identityDigest = digestOmitting(rootIdentity, 'identityDigest');
  const runId = 'quarantine-run';
  const generationId = identityHash(runId, 'checkpoint', digest, digest);
  const relative = `runs/${runId}/generations/${generationId}${linux ? '' : '.img'}`;
  const source = path.join(root, relative);
  await mkdir(path.dirname(source), { recursive: true, mode: 0o700 });
  const create = async (where: string) => {
    if (linux) {
      await mkdir(where, { mode: 0o700 });
      await mkdir(path.join(where, 'nested'), { mode: 0o755 });
      await writeFile(path.join(where, 'nested/dirty'), 'uncheckpointed bytes', { mode: 0o600 });
      // Quarantine never traverses content, including corrupt/special entries.
      await symlink('/never-follow-this-quarantine-link', path.join(where, 'outside'));
      execFileSync('mkfifo', ['-m', '600', path.join(where, 'fifo')]);
    } else await writeFile(where, 'uncheckpointed image bytes', { mode: 0o600 });
  };
  await create(source);
  const stat = await lstat(source, { bigint: true });
  const shared = { stateRootIdentityRef: canonicalSha256(rootIdentity), stateRootIdentityDigest: rootIdentity.identityDigest };
  const generation: WorkspaceGenerationIdentityV1 = {
    schemaVersion: 1, format: 'cliq-workspace-generation-identity-v1', generationId, runId,
    workspaceIdentityDigest: digest, sourceCheckpointId: 'checkpoint', sourceWorkspaceStateRef: digest,
    sourceWorkspaceStateDigest: digest, sourceTreeDigest: digest, creationNonceDigest: digest,
    locator: linux ? {
      ...shared, kind: 'linux_directory', canonicalRootRelativePath: relative, deviceId: String(stat.dev),
      directoryFileId: String(stat.ino), ownerUid: Number(stat.uid), mode: 448
    } : {
      ...shared, kind: 'macos_vm_volume', backingStoreCanonicalRootRelativePath: relative, backingStoreDeviceId: String(stat.dev),
      backingStoreFileId: String(stat.ino), backingStoreOwnerUid: Number(stat.uid), backingStoreMode: 384,
      backingStoreLinkCount: 1, vmVolumeReservationId: 'volume-reservation', guestVolumeId: 'guest-volume'
    },
    createdAt: '2026-09-08T00:00:00.000Z', identityDigest: ''
  };
  generation.identityDigest = digestOmitting(generation, 'identityDigest');
  const version = 7;
  const targetId = identityHash(generationId, String(version));
  const target = path.join(root, 'quarantine/workspace-generations', targetId);
  const contents = (where: string) => readFile(linux ? path.join(where, 'nested/dirty') : where, 'utf8');
  return { root, held, generation, version, source, target, targetId, create, contents, stat };
}

function changed(generation: WorkspaceGenerationIdentityV1, edit: (value: WorkspaceGenerationIdentityV1) => void) {
  const copy = structuredClone(generation);
  edit(copy);
  copy.identityDigest = digestOmitting(copy, 'identityDigest');
  return copy;
}

test('native quarantine moves only the exact generation and reobserves the same inode on retry', async (t) => {
  const f = await fixture(t);
  const before = await f.contents(f.source);
  const move = f.held.quarantineGeneration(f.generation, f.version);
  assert.deepEqual(move, {
    quarantineCanonicalRootRelativePath: `quarantine/workspace-generations/${f.targetId}`,
    quarantineDeviceId: String(f.stat.dev), quarantineFileId: String(f.stat.ino),
    originalLocatorAbsent: true, renameNoReplace: true, directoryFsyncComplete: true
  });
  assert.ok(Object.isFrozen(move));
  assert.equal(await f.contents(f.target), before);
  assert.equal((await lstat(f.target, { bigint: true })).ino, f.stat.ino);
  await assert.rejects(lstat(f.source), { code: 'ENOENT' });
  assert.deepEqual(f.held.quarantineGeneration(f.generation, f.version), move);
  assert.throws(() => f.held.quarantineGeneration(f.generation, f.version + 1), /exactly one original or exact target/);
  assert.deepEqual(await readdir(path.dirname(f.target)), [f.targetId]);
  assert.equal('evidenceDigest' in move, false);
  assert.equal('moveGeneration' in f.held, false);
});

test('quarantine retries the identical target after a real owner process is killed', async (t) => {
  const f = await fixture(t);
  f.held.close();
  const child = await childFor(t, f.root, 'native');
  assert.equal((await child.request('acquire')).state, 'held');
  assert.equal((await child.quarantine(f.generation, f.version)).state, 'quarantined');
  child.child.kill('SIGKILL');
  await child.exited;
  const successor = native.acquireLock(f.root, false);
  try {
    assert.equal(successor.quarantineGeneration(f.generation, f.version).quarantineFileId, String(f.stat.ino));
    assert.equal(await f.contents(f.target), linux ? 'uncheckpointed bytes' : 'uncheckpointed image bytes');
  } finally { successor.close(); }
});

test('quarantine accepts the StateStore-published root identity without changing SQLite bytes', async (t) => {
  const f = await fixture(t);
  f.held.close();
  const store = await openStateStore(f.root);
  t.after(() => store.close());
  const actualRoot = store.stateRootIdentity;
  const rootArtifact = await store.artifacts.readCanonical<StateRootIdentityV1>(actualRoot.ref);
  assert.equal(canonicalSha256(rootArtifact), actualRoot.ref);
  assert.equal(rootArtifact.identityDigest, actualRoot.digest);
  const generation = changed(f.generation, g => Object.assign(g.locator, {
    stateRootIdentityRef: actualRoot.ref, stateRootIdentityDigest: actualRoot.digest
  }));
  await store.close();
  const before = await readFile(path.join(f.root, KERNEL_DATABASE_FILENAME));
  const held = native.acquireLock(f.root, false);
  try { held.quarantineGeneration(generation, f.version); } finally { held.close(); }
  assert.deepEqual(await readFile(path.join(f.root, KERNEL_DATABASE_FILENAME)), before);
});

test('relocation is not containment death or revocation of an already-open writer', async (t) => {
  const f = await fixture(t);
  const writer = await open(linux ? path.join(f.source, 'nested/dirty') : f.source, 'r+');
  try {
    const move = f.held.quarantineGeneration(f.generation, f.version);
    await writer.write('still open', 0, 'utf8');
    assert.ok((await f.contents(f.target)).startsWith('still open'));
    assert.equal('containmentDeathEvidenceRef' in move, false);
    assert.equal('treeDigest' in move, false);
  } finally { await writer.close(); }
});

test('generation quarantine rejects fabricated identity, path, root, version and platform before moving', async (t) => {
  const f = await fixture(t);
  const mutateLocator = (field: string, value: unknown) => changed(f.generation, (g) => Object.assign(g.locator, { [field]: value }));
  for (const version of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '7']) {
    assert.throws(() => f.held.quarantineGeneration(f.generation, version as number));
  }
  for (const value of [
    { ...f.generation, identityDigest: digest }, { ...f.generation, unexpected: true },
    changed(f.generation, g => { g.generationId = identityHash('another generation'); }),
    mutateLocator('stateRootIdentityRef', digest), mutateLocator('stateRootIdentityDigest', digest),
    mutateLocator(linux ? 'ownerUid' : 'backingStoreOwnerUid', process.geteuid!() + 1),
    mutateLocator(linux ? 'deviceId' : 'backingStoreDeviceId', '999999'),
    mutateLocator(linux ? 'directoryFileId' : 'backingStoreFileId', String(f.stat.ino + 1n)),
    mutateLocator(linux ? 'canonicalRootRelativePath' : 'backingStoreCanonicalRootRelativePath', `runs/../${f.generation.generationId}`),
    mutateLocator(linux ? 'canonicalRootRelativePath' : 'backingStoreCanonicalRootRelativePath', f.source),
    mutateLocator('kind', linux ? 'macos_vm_volume' : 'linux_directory')
  ]) assert.throws(() => f.held.quarantineGeneration(value, f.version));
  for (const runId of ['../escape', 'slash/name', 'nul\0name', 'unicode-é', 'x'.repeat(129)]) {
    const value = changed(f.generation, g => {
      g.runId = runId;
      g.generationId = identityHash(runId, g.sourceCheckpointId, g.sourceWorkspaceStateRef, g.creationNonceDigest);
      Object.assign(g.locator, { [linux ? 'canonicalRootRelativePath' : 'backingStoreCanonicalRootRelativePath']:
        `runs/${runId}/generations/${g.generationId}${linux ? '' : '.img'}` });
    });
    assert.throws(() => f.held.quarantineGeneration(value, f.version));
  }
  assert.equal(await f.contents(f.source), linux ? 'uncheckpointed bytes' : 'uncheckpointed image bytes');
  await assert.rejects(lstat(f.target), { code: 'ENOENT' });
  assert.throws(() => f.held.quarantineGeneration.call({} as HeldStateOwnerLock, f.generation, f.version), /invalid StateOwner/);
});

for (const location of ['runs', 'run', 'generations', 'quarantine', 'target-parent', 'source', 'target'] as const) {
  test(`quarantine refuses symlink or replaced ${location} without following or repairing it`, async (t) => {
    const f = await fixture(t);
    await mkdir(path.dirname(f.target), { recursive: true, mode: 0o700 });
    const locator = { runs: path.join(f.root, 'runs'), run: path.dirname(path.dirname(f.source)), generations: path.dirname(f.source),
      quarantine: path.join(f.root, 'quarantine'), 'target-parent': path.dirname(f.target), source: f.source, target: f.target }[location];
    const saved = `${locator}.saved`;
    if (location === 'target') await f.create(saved); else await rename(locator, saved);
    await symlink(saved, locator);
    assert.throws(() => f.held.quarantineGeneration(f.generation, f.version));
    assert.ok((await lstat(locator)).isSymbolicLink());
    await rm(locator);
    if (location !== 'target') await rename(saved, locator);
    assert.equal(await f.contents(f.source), linux ? 'uncheckpointed bytes' : 'uncheckpointed image bytes');
  });
}

test('quarantine rejects both present, both absent, wrong target and wrong original without overwriting', async (t) => {
  const f = await fixture(t);
  await mkdir(path.dirname(f.target), { recursive: true, mode: 0o700 });
  await f.create(f.target);
  assert.throws(() => f.held.quarantineGeneration(f.generation, f.version), /conflict or identity drift/);
  const original = `${f.source}.retained`;
  await rename(f.source, original);
  assert.throws(() => f.held.quarantineGeneration(f.generation, f.version), /conflict or identity drift/);
  await rm(f.target, { recursive: true });
  assert.throws(() => f.held.quarantineGeneration(f.generation, f.version), /exactly one original or exact target/);
  await f.create(f.source);
  assert.throws(() => f.held.quarantineGeneration(f.generation, f.version), /source identity/);
  assert.equal(await f.contents(original), linux ? 'uncheckpointed bytes' : 'uncheckpointed image bytes');
});

test('quarantine requires the same live owner and exact parent and generation permissions', async (t) => {
  const f = await fixture(t);
  await mkdir(path.dirname(f.target), { recursive: true, mode: 0o700 });
  for (const where of [f.root, path.join(f.root, 'runtime'), path.join(f.root, 'runs'), path.dirname(f.source), path.dirname(f.target), f.source]) {
    const mode = (await lstat(where)).mode & 0o777;
    await chmod(where, 0o755);
    assert.throws(() => f.held.quarantineGeneration(f.generation, f.version));
    await chmod(where, mode);
  }
  if (!linux) {
    await link(f.source, `${f.source}.alias`);
    assert.throws(() => f.held.quarantineGeneration(f.generation, f.version), /source identity/);
    await rm(`${f.source}.alias`);
  }
  f.held.close();
  const successor = native.acquireLock(f.root, false);
  try { assert.throws(() => f.held.quarantineGeneration(f.generation, f.version), /changed or closed/); }
  finally { successor.close(); }
});

test('Linux generation identity has no immutable directory link-count field', async (t) => {
  const f = await fixture(t);
  const locator = { kind: 'linux_directory', stateRootIdentityRef: digest, stateRootIdentityDigest: digest,
    canonicalRootRelativePath: 'runs/r/generations/g', deviceId: '1', directoryFileId: '2', ownerUid: process.geteuid!(), mode: 448 };
  const value = changed(f.generation, g => { g.locator = locator as WorkspaceGenerationIdentityV1['locator']; });
  decodeWorkspaceGenerationIdentity(value);
  assert.throws(() => decodeWorkspaceGenerationIdentity(changed(value, g => Object.assign(g.locator, { linkCount: 1 }))));
});

test('native syscall faults never authorize an incomplete move and exact retries converge', async (t) => {
  const staging = await makePrivateDir('.cliq-quarantine-fault-build-');
  t.after(() => rm(staging, { recursive: true, force: true }));
  const binary = path.join(staging, 'fault.node');
  const includes = JSON.parse(execFileSync(process.execPath, [
    fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'
  ], { encoding: 'utf8' })) as string[];
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(linux ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']),
    ...includes.flatMap(include => ['-I', include]),
    fileURLToPath(new URL('./testing/quarantine-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr);
  const module = new Module(binary);
  process.dlopen(module, binary);
  const binding = module.exports as {
    acquireLock(root: string, create: boolean): { close(): void; moveGeneration(...args: string[]): unknown };
    setFault(point: string, ordinal: number, callback: () => number): void;
  };
  const raw = async (t: TestContext) => {
    const f = await fixture(t);
    f.held.close();
    const held = binding.acquireLock(f.root, false);
    t.after(() => held.close());
    return { ...f, move: () => held.moveGeneration(f.generation.runId, f.generation.generationId, f.targetId, String(f.stat.dev), String(f.stat.ino)) };
  };
  for (let ordinal = 1; ordinal <= 8; ordinal++) await t.test(`fsync failure ${ordinal}`, async (t) => {
    const f = await raw(t);
    binding.setFault('fsync', ordinal, () => constants.errno.EIO);
    assert.throws(f.move, /fsync failed/);
    assert.equal(await f.contents(ordinal <= 6 ? f.source : f.target), linux ? 'uncheckpointed bytes' : 'uncheckpointed image bytes');
    f.move();
    assert.equal((await lstat(f.target, { bigint: true })).ino, f.stat.ino);
  });
  for (const point of ['before_rename', 'after_rename']) await t.test(`${point} failure`, async (t) => {
    const f = await raw(t);
    binding.setFault(point, 1, () => constants.errno.EIO);
    assert.throws(f.move, /no-replace rename failed/);
    assert.equal(await f.contents(point === 'before_rename' ? f.source : f.target), linux ? 'uncheckpointed bytes' : 'uncheckpointed image bytes');
    f.move();
  });
  await t.test('target appears in the rename race: native no-replace preserves both objects', async (t) => {
    const f = await raw(t);
    binding.setFault('before_rename', 1, () => {
      if (linux) mkdirSync(f.target, { mode: 0o700 }); else writeFileSync(f.target, 'concurrent target', { mode: 0o600 });
      return 0;
    });
    assert.throws(f.move, /no-replace rename failed/);
    assert.equal((await lstat(f.source, { bigint: true })).ino, f.stat.ino);
    assert.notEqual((await lstat(f.target, { bigint: true })).ino, f.stat.ino);
    assert.throws(f.move, /conflict or identity drift/);
  });
  await t.test('parent replacement after rename rejects a success observation', async (t) => {
    const f = await raw(t);
    binding.setFault('after_rename', 1, () => {
      renameSync(path.dirname(f.target), `${path.dirname(f.target)}.saved`);
      mkdirSync(path.dirname(f.target), { mode: 0o700 });
      return 0;
    });
    assert.throws(f.move, /post-move descriptor identity/);
    assert.throws(f.move, /exactly one original or exact target/);
  });
});
