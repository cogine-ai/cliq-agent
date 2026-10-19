// Actual readonly native/filesystem mechanism. These component cases create
// no Run, approval, StateOwner context, live preflight brand or publication claim.
import assert from 'node:assert/strict';
import { chmod, lchmod, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import { publicationDirectoryIdentityDigest, type DeliveryCaptureTopologyV1, type DeliveryPlan, type PublicationOperation } from '../kernel/publication.js';
import { loadNativeStateOwner, openHeldPublicationOperation, type HeldWorkspaceRoot } from './native-owner.js';
import { assertPublicationPreflight, inspectPublicationPlan, preparePublicationPreflight } from './publication-preflight.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { StateOwnerContext } from './state-owner.js';

async function fixture(t: TestContext) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-publication-preflight-')));
  const state = path.join(directory, 'state'), workspace = path.join(directory, 'workspace');
  await mkdir(state, { mode: 0o700 }); await mkdir(workspace, { mode: 0o700 });
  const native = await loadNativeStateOwner(), lock = native.acquireLock(state, true), root = native.openWorkspaceRoot(workspace);
  t.after(async () => { root.close(); lock.close(); await rm(directory, { recursive: true, force: true }); });
  const ref = canonicalSha256('readonly component data'), workspaceDigest = canonicalSha256('component workspace identity');
  const directoryIdentity = (identity: HeldWorkspaceRoot['identity'], mode: number) => ({ ...identity, mode,
    identityDigest: publicationDirectoryIdentityDigest(workspaceDigest, { ...identity, mode }) });
  const topologyCore = { schemaVersion: 1 as const, format: 'cliq-delivery-capture-topology-v1' as const,
    inspectionId: identityHash('readonly component inspection'), workspaceIdentityRef: ref, workspaceIdentityDigest: workspaceDigest,
    capturedWorkspaceRef: ref, rootIdentity: directoryIdentity(root.identity, root.mode), directories: [], fileModes: [],
    capturedAt: '2026-10-18T00:00:00.000Z', topologyDigest: '' };
  const topology: DeliveryCaptureTopologyV1 = { ...topologyCore, topologyDigest: digestOmitting(topologyCore, 'topologyDigest') };
  const plan = (operations: PublicationOperation[]): DeliveryPlan => ({ schemaVersion: 1, deliveryRunId: 'physical-data-only',
    sourceRunResultRef: ref, sourceBaseRef: ref, sourceDesiredRef: ref, capturedWorkspaceRef: ref, captureTopologyRef: ref,
    captureTopologyDigest: digestOmitting(topology, 'topologyDigest'), desiredSourceRef: ref, diffRef: ref,
    mergeAlgorithm: 'cliq-diff3-v1', publicationStateMachine: 'cliq-publish-v1', forwardOperations: operations,
    abortOperations: operations.filter(operation => operation.desired.kind === 'directory' && operation.expected.kind !== 'directory')
      .sort((a, b) => b.path.split('/').length - a.path.split('/').length || Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)))
      .map((operation, index) => ({ index, operationId: identityHash('component abort', operation.operationId),
        kind: 'abort_rmdir', path: operation.path, createdByOperationId: operation.operationId,
        quarantineName: 'preimage', quarantineExpected: { kind: 'absent' } })) });
  const parent = { kind: 'existing_directory' as const, expectedIdentityDigest: topology.rootIdentity.identityDigest };
  return { state, workspace, lock, root, topology, plan, parent, directoryIdentity };
}

test('a multiply-linked late target rejects the whole plan before any earlier workspace write', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.workspace, 'z'), 'original', { mode: 0o600 }); await link(path.join(f.workspace, 'z'), path.join(f.workspace, 'alias'));
  const plan = f.plan([
    { index: 0, operationId: identityHash('first'), kind: 'create', path: 'a', parent: f.parent, expected: { kind: 'absent' },
      desired: { kind: 'file', mode: 420, digest: canonicalSha256('new') }, stagingName: '.new', stagingExpected: { kind: 'absent' } },
    { index: 1, operationId: identityHash('late'), kind: 'delete', path: 'z', parent: f.parent,
      expected: { kind: 'file', mode: 0o600, digest: canonicalSha256('original') }, desired: { kind: 'absent' },
      quarantineName: '.old', quarantineExpected: { kind: 'absent' } }
  ]);
  const before = await readdir(f.workspace);
  await assert.rejects(inspectPublicationPlan(f.lock, f.root, plan, f.topology), /multiply-linked/);
  assert.deepEqual(await readdir(f.workspace), before); assert.equal(await readFile(path.join(f.workspace, 'z'), 'utf8'), 'original');
  await assert.rejects(lstat(path.join(f.state, 'runtime', 'publications')), { code: 'ENOENT' });
});

test('physical preflight rejects a structural root before observing its properties', async t => {
  const f = await fixture(t), hostile = Object.defineProperty({}, 'identity', { get() { assert.fail('must reject the fake brand first'); } });
  await assert.rejects(inspectPublicationPlan(f.lock, hostile as HeldWorkspaceRoot, f.plan([]), f.topology), /native source workspace/);
});

test('old symlink permission bits are not invented as a retained expected field', async t => {
  if (process.platform !== 'darwin') { t.skip('requires real lchmod support'); return; }
  const f = await fixture(t), name = path.join(f.workspace, 'link');
  await symlink('old-target', name); await lchmod(name, 0o700);
  assert.equal((await lstat(name)).mode & 0o7777, 0o700);
  const scope = await inspectPublicationPlan(f.lock, f.root, f.plan([
    { index: 0, operationId: identityHash('old real symlink'), kind: 'delete', path: 'link', parent: f.parent,
      expected: { kind: 'symlink', target: 'old-target', digest: sha256Bytes(Buffer.from('old-target')) }, desired: { kind: 'absent' },
      quarantineName: 'old-link', quarantineExpected: { kind: 'absent' } }
  ]), f.topology);
  try { scope.assertHeld(); } finally { scope.close(); }
});

test('file to directory uses its planned parent while directory replacement checks existing children without demanding early emptiness', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.workspace, 'a'), 'old file', { mode: 0o600 });
  await mkdir(path.join(f.workspace, 'd'), { mode: 0o700 });
  await writeFile(path.join(f.workspace, 'd', 'old'), 'old child', { mode: 0o600 });
  const directory = await lstat(path.join(f.workspace, 'd'));
  const directoryMode = directory.mode & 0o7777;
  const capturedDirectory = { path: 'd', ...f.directoryIdentity({ deviceId: String(directory.dev), fileId: String(directory.ino), ownerUid: directory.uid }, directoryMode) };
  const topology = { ...f.topology, directories: [capturedDirectory], topologyDigest: '' };
  topology.topologyDigest = digestOmitting(topology, 'topologyDigest');
  const creatorId = identityHash('file becomes directory');
  const plan = { ...f.plan([
    { index: 0, operationId: creatorId, kind: 'replace', path: 'a', parent: f.parent,
      expected: { kind: 'file', mode: 0o600, digest: canonicalSha256('old file') }, desired: { kind: 'directory', mode: 493 },
      stagingName: 'new-directory', stagingExpected: { kind: 'absent' }, quarantineName: 'old-file', quarantineExpected: { kind: 'absent' } },
    { index: 1, operationId: identityHash('virtual child'), kind: 'create', path: 'a/new',
      parent: { kind: 'planned_directory', createdByOperationId: creatorId }, expected: { kind: 'absent' },
      desired: { kind: 'file', mode: 420, digest: canonicalSha256('new child') }, stagingName: 'new-child', stagingExpected: { kind: 'absent' } },
    { index: 2, operationId: identityHash('remove child first'), kind: 'delete', path: 'd/old',
      parent: { kind: 'existing_directory', expectedIdentityDigest: capturedDirectory.identityDigest },
      expected: { kind: 'file', mode: 0o600, digest: canonicalSha256('old child') }, desired: { kind: 'absent' },
      quarantineName: 'old-child', quarantineExpected: { kind: 'absent' } },
    { index: 3, operationId: identityHash('directory becomes file'), kind: 'replace', path: 'd', parent: f.parent,
      expected: { kind: 'directory', mode: directoryMode, identityDigest: capturedDirectory.identityDigest, empty: true },
      desired: { kind: 'file', mode: 420, digest: canonicalSha256('new file') }, stagingName: 'new-file', stagingExpected: { kind: 'absent' },
      quarantineName: 'old-directory', quarantineExpected: { kind: 'absent' } }
  ]), captureTopologyDigest: topology.topologyDigest };
  const scope = await inspectPublicationPlan(f.lock, f.root, plan, topology);
  try {
    assert.equal(scope.virtualPaths, 1); scope.assertHeld();
    assert.equal(await readFile(path.join(f.workspace, 'a'), 'utf8'), 'old file');
    assert.equal(await readFile(path.join(f.workspace, 'd', 'old'), 'utf8'), 'old child');
    await assert.rejects(lstat(path.join(f.state, 'runtime', 'publications')), { code: 'ENOENT' });
  } finally { scope.close(); }
});

test('readonly preflight records a real private arena parent but neither creates nor adopts one', async t => {
  const f = await fixture(t), directory = path.join(f.state, 'runtime', 'publications');
  await mkdir(directory, { mode: 0o700 });
  const before = await lstat(directory), scope = await inspectPublicationPlan(f.lock, f.root, f.plan([]), f.topology);
  try {
    assert.equal(scope.arenaParent.kind, 'present');
    if (scope.arenaParent.kind === 'present') assert.equal(scope.arenaParent.identity.fileId, String(before.ino));
    scope.assertHeld(); assert.deepEqual(await readdir(directory), []);
  } finally { scope.close(); }
  await chmod(directory, 0o755);
  await assert.rejects(inspectPublicationPlan(f.lock, f.root, f.plan([]), f.topology), /private arena parent/);
});

test('existing parent raw mode drift refuses before writing any planned leaf', async t => {
  const f = await fixture(t), name = path.join(f.workspace, 'parent');
  await mkdir(name, { mode: 0o700 });
  const original = await lstat(name), directory = { path: 'parent', ...f.directoryIdentity({ deviceId: String(original.dev),
    fileId: String(original.ino), ownerUid: original.uid }, original.mode & 0o7777) };
  const topology = { ...f.topology, directories: [directory], topologyDigest: '' };
  topology.topologyDigest = digestOmitting(topology, 'topologyDigest');
  const plan = { ...f.plan([{ index: 0, operationId: identityHash('real parent drift'), kind: 'create', path: 'parent/new',
    parent: { kind: 'existing_directory', expectedIdentityDigest: directory.identityDigest }, expected: { kind: 'absent' },
    desired: { kind: 'file', mode: 420, digest: canonicalSha256('new') }, stagingName: 'new', stagingExpected: { kind: 'absent' }
  }]), captureTopologyDigest: topology.topologyDigest };
  await chmod(name, 0o755);
  await assert.rejects(inspectPublicationPlan(f.lock, f.root, plan, topology), /parent directory identity/);
  assert.deepEqual(await readdir(name), []);
});

test('selective metadata traversal never enters an unrelated nested Git directory', async t => {
  const f = await fixture(t);
  await mkdir(path.join(f.workspace, 'unrelated', '.git'), { recursive: true, mode: 0o700 });
  const scope = await inspectPublicationPlan(f.lock, f.root, f.plan([
    { index: 0, operationId: identityHash('only selected path'), kind: 'create', path: 'new', parent: f.parent,
      expected: { kind: 'absent' }, desired: { kind: 'file', mode: 420, digest: canonicalSha256('new') },
      stagingName: 'new', stagingExpected: { kind: 'absent' } }
  ]), f.topology);
  try { scope.assertHeld(); assert.equal(scope.observedPaths, 0); } finally { scope.close(); }
});

test('a successful observation remains tied to the original root mode and joins even after refusal', async t => {
  const f = await fixture(t), scope = await inspectPublicationPlan(f.lock, f.root, f.plan([]), f.topology);
  try {
    await chmod(f.workspace, 0o755);
    assert.throws(() => scope.assertHeld(), /root identity and raw mode/);
  } finally { scope.close(); }
  scope.close(); assert.throws(() => scope.assertHeld(), /closed/);
});

for (const existing of [false, true]) test(`private arena birth preserves readonly workspace preflight (${existing ? 'existing' : 'absent'} arena parent)`, async t => {
  const f = await fixture(t);
  if (existing) await mkdir(path.join(f.state, 'runtime', 'publications'), { mode: 0o700 });
  const scope = await inspectPublicationPlan(f.lock, f.root, f.plan([]), f.topology);
  const operation = openHeldPublicationOperation(f.lock, f.root, { arenaId: identityHash('preflight private birth'), kind: 'create', path: 'first',
    parents: [{ ...f.root.identity, mode: f.root.mode }], expected: { kind: 'absent' },
    desired: { kind: 'file', mode: 420, byteCount: 0, digest: canonicalSha256('unused-data-only') }, stagingName: 'staged' });
  try {
    scope.assertHeld(); assert.deepEqual(await readdir(f.workspace), []);
    assert.equal(scope.arenaParent.kind, existing ? 'present' : 'absent');
  } finally { operation.close(); scope.close(); }
});

test('actual cross-device publication is refused readonly when a second filesystem exists', async t => {
  if (process.platform !== 'linux') { t.skip('requires a genuine second Linux filesystem; not qualified on this host'); return; }
  const f = await fixture(t);
  let directory: string;
  try { directory = await mkdtemp('/dev/shm/cliq-preflight-crossdev-'); }
  catch { t.skip('no writable /dev/shm second filesystem; no cross-device evidence'); return; }
  t.after(() => rm(directory, { recursive: true, force: true }));
  if ((await lstat(directory)).dev === (await lstat(f.workspace)).dev) { t.skip('candidate filesystem is not distinct'); return; }
  await chmod(directory, 0o700);
  const native = await loadNativeStateOwner(), lock = native.acquireLock(directory, true);
  try {
    const before = await readdir(f.workspace);
    await assert.rejects(inspectPublicationPlan(lock, f.root, f.plan([]), f.topology), /one filesystem/);
    assert.deepEqual(await readdir(f.workspace), before);
    await assert.rejects(lstat(path.join(directory, 'runtime', 'publications')), { code: 'ENOENT' });
  } finally { lock.close(); }
});

test('live preflight cannot be supplied as data or minted with a structural execution callback', async t => {
  const f = await fixture(t);
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('unbranded input must not access SQLite'); } }) as SqliteDriver;
  const owner = { filesystem: f.lock } as StateOwnerContext;
  const hostile = Object.defineProperty({}, 'close', { get() { assert.fail('unbranded input must not be inspected'); } });
  assert.throws(() => assertPublicationPreflight(driver, owner, hostile), /genuine same-owner publication preflight/);
  await assert.rejects(preparePublicationPreflight(driver, {} as ArtifactCatalog, owner, {
    runId: 'data-only', expectedRunRevision: 1, workspaceRoot: f.root,
    worker: { runId: 'data-only', leaseEpoch: 1, launchId: 'data-only', generationRef: 'a'.repeat(64), workerIdentityDigest: 'b'.repeat(64) },
    execution: { assertCurrentDeliveryWorker() { assert.fail('a structural callback must never be called'); } }
  }), /genuine same-owner Run execution/);
});
