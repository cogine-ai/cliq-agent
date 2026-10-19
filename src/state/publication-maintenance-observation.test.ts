// Actual held-directory observations only. No Run, claim, permission or native
// publication proof is manufactured by these read-only mechanism tests.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { chmod, link, lstat, mkdir, mkdtemp, open, realpath, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { Module } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadHeldStateOwnerImage, type NativeStateOwner } from './native-owner.js';
import { observePublicationMaintenancePath } from './publication-maintenance-observation.js';
import { sha256Bytes } from '../kernel/identity.js';
import { publicationDirectoryIdentityDigest, type PublicationPathObservationV1 } from '../kernel/publication.js';
import { ResourceRetirementError } from './errors.js';
import { setImmediate } from 'node:timers/promises';

let native: Promise<NativeStateOwner> | undefined;
let nativeDirectory: string;
let fault: { setFault(point: string, ordinal: number, callback: () => number): void };
async function actualNative() {
  return native ??= (async () => {
    nativeDirectory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-maintenance-native-')));
    const binary = path.join(nativeDirectory, 'fault.node');
    const includes = JSON.parse(execFileSync(process.execPath,
      [fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'], { encoding: 'utf8' })) as string[];
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
      ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']),
      ...includes.flatMap(include => ['-I', include]), fileURLToPath(new URL('./testing/publication-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr); await chmod(binary, 0o500);
    const image = await open(binary);
    try {
      const result = await loadHeldStateOwnerImage(image);
      const module = new Module(binary); process.dlopen(module, binary); fault = module.exports;
      return result;
    } finally { await image.close(); }
  })();
}
test.after(async () => { if (nativeDirectory) await rm(nativeDirectory, { recursive: true, force: true }); });
async function fixture(t: import('node:test').TestContext) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-maintenance-observation-')));
  const root = (await actualNative()).openWorkspaceRoot(directory);
  t.after(async () => { root.close(); await rm(directory, { recursive: true, force: true }); });
  return { directory, root };
}
const identity = 'a'.repeat(64);
const limits = { maxSingleFileBytes: 1024, maxBytes: 4096 };
async function leafReceipt(directory: string, relative: string, bytes: string): Promise<PublicationPathObservationV1> {
  const info = await lstat(path.join(directory, relative), { bigint: true }), parent = await stat(path.dirname(path.join(directory, relative)), { bigint: true });
  return { location: { kind: 'workspace', path: relative }, state: { kind: 'file', mode: Number(info.mode & 0o7777n), digest: sha256Bytes(Buffer.from(bytes)) },
    parentDeviceId: String(parent.dev), parentFileId: String(parent.ino), parentLinkCount: Number(parent.nlink),
    entryDeviceId: String(info.dev), entryFileId: String(info.ino), entryLinkCount: Number(info.nlink) };
}

test('maintenance observes genuine absent and empty paths with their actual direct parent identities', async t => {
  const f = await fixture(t);
  const missing = await observePublicationMaintenancePath(f.root, { path: 'missing', workspaceIdentityDigest: identity,
    completedDescendants: [], ...limits });
  assert.equal(missing.classification, 'absent'); assert.equal(missing.ancestorPath, undefined);
  assert.deepEqual(missing.observation, { location: { kind: 'workspace', path: 'missing' }, state: { kind: 'absent' },
    parentDeviceId: f.root.identity.deviceId, parentFileId: f.root.identity.fileId, parentLinkCount: f.root.linkCount });
  await mkdir(path.join(f.directory, 'empty'), { mode: 0o755 });
  const info = await stat(path.join(f.directory, 'empty'), { bigint: true });
  const empty = await observePublicationMaintenancePath(f.root, { path: 'empty', workspaceIdentityDigest: identity,
    completedDescendants: [], ...limits });
  assert.equal(empty.classification, 'empty_directory'); assert.deepEqual(empty.descendants, []);
  assert.equal(empty.observation.state.kind, 'directory'); assert.equal(empty.observation.entryFileId, String(info.ino));
  assert.equal(empty.observation.entryLinkCount, Number(info.nlink));
  f.root.assertHeld();
});

test('missing or non-directory ancestors remain actual no-follow observations, never invented absent children', async t => {
  const f = await fixture(t); await mkdir(path.join(f.directory, 'd'));
  await writeFile(path.join(f.directory, 'd', 'block'), 'actual bytes', { mode: 0o600 });
  await symlink('block', path.join(f.directory, 'd', 'link'));
  for (const [name, kind] of [['missing', 'absent'], ['block', 'file'], ['link', 'symlink']] as const) {
    const result = await observePublicationMaintenancePath(f.root, { path: `d/${name}/leaf`, workspaceIdentityDigest: identity,
      completedDescendants: [], ...limits });
    assert.equal(result.ancestorPath, `d/${name}`); assert.deepEqual(result.observation.location, { kind: 'workspace', path: `d/${name}` });
    assert.equal(result.observation.state.kind, kind);
    assert.equal(result.classification, kind === 'absent' ? 'absent' : 'unexpected');
    if (result.observation.state.kind === 'file') assert.deepEqual(result.observation.state,
      { kind: 'file', mode: 0o600, digest: sha256Bytes(Buffer.from('actual bytes')) });
    if (result.observation.state.kind === 'symlink') assert.deepEqual(result.observation.state,
      { kind: 'symlink', target: 'block', digest: sha256Bytes(Buffer.from('block')) });
  }
});

test('an uncreated conversion directory retains the complete actual original leaf without following or removing it', async t => {
  const f = await fixture(t), file = path.join(f.directory, 'original'), link = path.join(f.directory, 'link');
  await writeFile(file, 'original bytes', { mode: 0o640 });
  await symlink('original', link);
  for (const [name, expected] of [
    ['original', { kind: 'file', mode: 0o640, digest: sha256Bytes(Buffer.from('original bytes')) }],
    ['link', { kind: 'symlink', target: 'original', digest: sha256Bytes(Buffer.from('original')) }],
  ] as const) {
    const before = await lstat(path.join(f.directory, name), { bigint: true });
    const result = await observePublicationMaintenancePath(f.root, { path: name, workspaceIdentityDigest: identity,
      completedDescendants: [], ...limits });
    assert.equal(result.classification, 'leaf'); assert.equal(result.ancestorPath, undefined);
    assert.deepEqual(result.observation.state, expected); assert.deepEqual(result.descendants, []);
    const after = await lstat(path.join(f.directory, name), { bigint: true });
    assert.equal(after.ino, before.ino); assert.equal(after.mode, before.mode);
    assert.equal(result.observation.entryFileId, String(before.ino));
  }
  await writeFile(file, 'different data');
  const changed = await observePublicationMaintenancePath(f.root, { path: 'original', workspaceIdentityDigest: identity,
    completedDescendants: [], ...limits });
  assert.deepEqual(changed.observation.state, { kind: 'file', mode: 0o640, digest: sha256Bytes(Buffer.from('different data')) });
  const unchangedLink = await observePublicationMaintenancePath(f.root, { path: 'link', workspaceIdentityDigest: identity,
    completedDescendants: [], ...limits });
  assert.deepEqual(unchangedLink.observation.state, { kind: 'symlink', target: 'original', digest: sha256Bytes(Buffer.from('original')) });
});

test('planned descendants require the complete original inode, raw mode and bytes while directory child state stays actual', async t => {
  const f = await fixture(t); await mkdir(path.join(f.directory, 'd'));
  await mkdir(path.join(f.directory, 'd', 'inner'), { mode: 0o755 });
  const innerBirth = await stat(path.join(f.directory, 'd', 'inner'), { bigint: true });
  await writeFile(path.join(f.directory, 'd', 'inner', 'file'), 'planned', { mode: 0o600 });
  await symlink('inner/file', path.join(f.directory, 'd', 'link'));
  const receipt = async (relative: string, state: PublicationPathObservationV1['state']): Promise<PublicationPathObservationV1> => {
    const current = await import('node:fs/promises'), info = await current.lstat(path.join(f.directory, relative), { bigint: true });
    const parent = await stat(path.dirname(path.join(f.directory, relative)), { bigint: true });
    return { location: { kind: 'workspace', path: relative }, state,
      parentDeviceId: String(parent.dev), parentFileId: String(parent.ino), parentLinkCount: Number(parent.nlink),
      entryDeviceId: String(info.dev), entryFileId: String(info.ino), entryLinkCount: Number(info.nlink) };
  };
  const directoryIdentity = { deviceId: String(innerBirth.dev), fileId: String(innerBirth.ino), ownerUid: Number(innerBirth.uid), mode: 0o755 };
  const completedDescendants = [
    { operationId: 'link-op', observation: await receipt('d/link', { kind: 'symlink', target: 'inner/file', digest: sha256Bytes(Buffer.from('inner/file')) }) },
    { operationId: 'file-op', observation: await receipt('d/inner/file', { kind: 'file', mode: 0o600, digest: sha256Bytes(Buffer.from('planned')) }) },
    { operationId: 'inner-op', observation: { ...await receipt('d/inner', { kind: 'directory', mode: 0o755, empty: true,
      identityDigest: publicationDirectoryIdentityDigest(identity, directoryIdentity) }), entryLinkCount: Number(innerBirth.nlink) } },
  ];
  const observed = await observePublicationMaintenancePath(f.root, { path: 'd', workspaceIdentityDigest: identity,
    completedDescendants, ...limits });
  assert.equal(observed.classification, 'planned_descendants');
  assert.deepEqual(observed.descendants.map(value => value.operationId), ['inner-op', 'file-op', 'link-op']);
  assert.equal(observed.descendants[0]!.observation.state.kind, 'directory');
  if (observed.descendants[0]!.observation.state.kind === 'directory') assert.equal(observed.descendants[0]!.observation.state.empty, false);
  assert.equal(observed.observation.state.kind, 'directory');
  if (observed.observation.state.kind === 'directory') assert.equal(observed.observation.state.empty, false);
});

test('the original cumulative read quota cannot expand through caller mutation during an actual file read', async t => {
  const f = await fixture(t); await mkdir(path.join(f.directory, 'd'));
  await writeFile(path.join(f.directory, 'd', 'a'), 'a'); await writeFile(path.join(f.directory, 'd', 'b'), 'b');
  const input = { path: 'd', workspaceIdentityDigest: identity, completedDescendants: [
    { operationId: 'a', observation: await leafReceipt(f.directory, 'd/a', 'a') },
    { operationId: 'b', observation: await leafReceipt(f.directory, 'd/b', 'b') }], maxSingleFileBytes: 1, maxBytes: 1 };
  const scheduled = import('node:timers/promises').then(async ({ setImmediate }) => { await setImmediate(); input.maxBytes = 2; });
  await assert.rejects(observePublicationMaintenancePath(f.root, input), /bytes exceed the capture limit/);
  await scheduled; f.root.assertHeld();
});

test('foreign names, inodes, raw modes or bytes never become planned descendants and unknown subtrees stay unopened', async t => {
  const f = await fixture(t); await mkdir(path.join(f.directory, 'd')); const leaf = path.join(f.directory, 'd', 'file');
  await writeFile(leaf, 'planned', { mode: 0o600 });
  const observation = await leafReceipt(f.directory, 'd/file', 'planned');
  const input = { path: 'd', workspaceIdentityDigest: identity, completedDescendants: [{ operationId: 'original', observation }], ...limits };
  for (const mutation of [
    async () => writeFile(leaf, 'changed'),
    async () => { await writeFile(leaf, 'planned'); await chmod(leaf, 0o644); },
    async () => { await rename(leaf, path.join(f.directory, 'old')); await writeFile(leaf, 'planned', { mode: 0o600 }); },
  ]) {
    await mutation(); const result = await observePublicationMaintenancePath(f.root, input);
    assert.equal(result.classification, 'unexpected'); assert.deepEqual(result.descendants, []);
  }
  await mkdir(path.join(f.directory, 'd', 'foreign')); await mkdir(path.join(f.directory, 'd', 'foreign', '.git'));
  await writeFile(path.join(f.directory, 'd', 'foreign', '.git', 'config'), 'never load this configuration');
  const result = await observePublicationMaintenancePath(f.root, { ...input,
    completedDescendants: [{ operationId: 'current', observation: await leafReceipt(f.directory, 'd/file', 'planned') }] });
  assert.equal(result.classification, 'unexpected'); assert.deepEqual(result.descendants, []);
});

test('single-file, cumulative byte and multi-link targets refuse rather than invent a complete observation', async t => {
  const f = await fixture(t); await writeFile(path.join(f.directory, 'file'), 'bytes');
  for (const quota of [{ maxSingleFileBytes: 4, maxBytes: 10 }, { maxSingleFileBytes: 5, maxBytes: 4 }])
    await assert.rejects(observePublicationMaintenancePath(f.root, { path: 'file', workspaceIdentityDigest: identity,
      completedDescendants: [], ...quota }), /capture limit/);
  await link(path.join(f.directory, 'file'), path.join(f.directory, 'other'));
  await assert.rejects(observePublicationMaintenancePath(f.root, { path: 'file', workspaceIdentityDigest: identity,
    completedDescendants: [], ...limits }), /identity or bytes/);
  f.root.assertHeld();
});

test('metadata yields are global across nested directories and preserve the exact cancellation reason', async t => {
  const f = await fixture(t), count = 140;
  let current = f.directory; const completedDescendants: [] = [];
  for (let index = 0; index < count; index++) { current = path.join(current, 'd'); await mkdir(current); }
  // The target's unexpected subtree is not selected, so a long ancestor walk
  // provides the real global metadata workload without reading foreign bytes.
  const controller = new AbortController(), reason = new Error('original stop reason');
  const stopping = setImmediate().then(() => controller.abort(reason));
  await assert.rejects(observePublicationMaintenancePath(f.root, { path: Array(count + 1).fill('d').join('/'),
    workspaceIdentityDigest: identity, completedDescendants, ...limits, signal: controller.signal }), error => error === reason);
  await stopping; f.root.assertHeld();
});

test('an actual file mutation during a yielded read refuses and joins without returning partial data', async t => {
  const f = await fixture(t), leaf = path.join(f.directory, 'file'); await writeFile(leaf, 'initial');
  const mutation = setImmediate().then(() => writeFileSync(leaf, 'changed'));
  await assert.rejects(observePublicationMaintenancePath(f.root, { path: 'file', workspaceIdentityDigest: identity,
    completedDescendants: [], ...limits }), /identity|changed|metadata|file/);
  await mutation; f.root.assertHeld();
});

test('a real descriptor close failure outranks cancellation and remains sticky on the original root', async t => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-maintenance-close-')));
  const root = (await actualNative()).openWorkspaceRoot(directory);
  t.after(async () => { try { root.close(); } catch (error) { assert.equal((error as { code: string }).code, 'ERR_CLIQ_RESOURCE_RETIREMENT'); }
    await rm(directory, { recursive: true, force: true }); });
  await writeFile(path.join(directory, 'file'), 'original');
  const controller = new AbortController(), reason = new Error('ordinary cancellation');
  fault.setFault('close', 1, () => 5);
  const stopping = setImmediate().then(() => controller.abort(reason));
  await assert.rejects(observePublicationMaintenancePath(root, { path: 'file', workspaceIdentityDigest: identity,
    completedDescendants: [], ...limits, signal: controller.signal }), error => error instanceof ResourceRetirementError && error !== reason);
  await stopping; assert.throws(() => root.assertHeld(), /identity|closed/);
});

test('structural roots are rejected before input getters and closed descendant data cannot supply callbacks', async t => {
  const hostile = Object.defineProperty({}, 'path', { get() { assert.fail('structural root must be rejected before input'); } });
  await assert.rejects(observePublicationMaintenancePath({} as never, hostile as never), /native source workspace/);
  const f = await fixture(t);
  const hostileInput = Object.defineProperty({ workspaceIdentityDigest: identity, completedDescendants: [], ...limits }, 'path',
    { enumerable: true, get() { assert.fail('maintenance input getter must not run'); } });
  await assert.rejects(observePublicationMaintenancePath(f.root, hostileInput as never), /accessors/);
  const observation = Object.defineProperty({}, 'state', { enumerable: true, get() { assert.fail('descendant getter must not run'); } });
  await assert.rejects(observePublicationMaintenancePath(f.root, { path: 'd', workspaceIdentityDigest: identity,
    completedDescendants: [{ operationId: 'callback', observation: observation as never }], ...limits }), /accessors/);
  for (const invalidPath of ['../x', 'd//x', 'd\\x', 'd/.git/x', 'bad\ud800'])
    await assert.rejects(observePublicationMaintenancePath(f.root, { path: invalidPath, workspaceIdentityDigest: identity,
      completedDescendants: [], ...limits }), TypeError);
  f.root.assertHeld();
});
