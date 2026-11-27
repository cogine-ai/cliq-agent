import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { loadNativeStateOwner, type HeldWorkspaceRoot } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';

test('new Session workspace identity opens only descriptors before any Git inspection authority exists', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-descriptors-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const workspace = path.join(root, 'workspace'), target = path.join(root, 'external-config');
  await mkdir(workspace); await mkdir(path.join(workspace, '.git'));
  await writeFile(target, 'raw configuration sentinel must never be an identity input\n');
  await symlink(target, path.join(workspace, '.git/config'));
  const captured = await captureLiveWorkspaceIdentity({ workspacePath: workspace, ownerPrincipalId: 'descriptor-only-test' });
  assert.equal(captured.repository!.schemaVersion, 2);
  assert.equal(captured.repository!.format, 'cliq-repository-identity-v2');
  assert.equal(Object.hasOwn(captured.repository!, 'objectFormat'), false);
  const directory = await lstat(path.join(workspace, '.git'), { bigint: true });
  assert.deepEqual(captured.repository!.gitDirectoryIdentity,
    { deviceId: String(directory.dev), fileId: String(directory.ino), ownerUid: Number(directory.uid) });
  assert.equal(await readFile(target, 'utf8'), 'raw configuration sentinel must never be an identity input\n');
  const native = await loadNativeStateOwner(), held = native.openWorkspaceRoot(workspace);
  try { assert.throws(() => held.readGitConfigChunk(), /owning authorized source inspection/); held.assertHeld(); }
  finally { held.close(); }
});

test('source identity retains every no-follow ancestor and rejects a symlink back to the same root', async t => {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-source-identity-'));
  const saved = `${container}-saved`;
  let held: HeldWorkspaceRoot | undefined;
  t.after(async () => {
    held?.close();
    await rm(container, { recursive: true, force: true });
    await rm(saved, { recursive: true, force: true });
  });
  await chmod(container, 0o700);
  const workspace = path.join(container, 'workspace');
  await mkdir(workspace, { mode: 0o755 });
  await mkdir(path.join(workspace, '.git'), { mode: 0o755 });
  await writeFile(path.join(workspace, '.git/config'), '[core]\n\trepositoryformatversion = 0\n');
  const native = await loadNativeStateOwner();
  // This is the actual native filesystem seam, not a path/FD supplied by a client.
  held = native.openWorkspaceRoot(workspace);
  const stat = await lstat(workspace, { bigint: true });
  assert.deepEqual(held.identity, { deviceId: String(stat.dev), fileId: String(stat.ino), ownerUid: Number(stat.uid) });
  held.assertHeld();
  await rename(container, saved);
  await symlink(saved, container);
  assert.throws(() => held.assertHeld(), /changed or closed/);
  assert.throws(() => held.readGitConfigChunk(), /changed or closed/);
  await rm(container);
  await rename(saved, container);
  held.assertHeld();
  assert.throws(() => held.readGitConfigChunk(), /owning authorized source inspection/);
  held.close();
  assert.throws(() => held.assertHeld(), /changed or closed/);
});

test('descriptor-only identity does not interpret an alias as configuration or object identity', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  await writeFile(path.join(root, '.git/config'), '[core]\nrepositoryformatversion = 0\n[alias]\nobjectFormat = sha256\n');
  const captured = await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' });
  assert.equal(captured.repository!.schemaVersion, 2);
  assert.equal(Object.hasOwn(captured.repository!, 'objectFormat'), false);
});

test('descriptor-only identity does not read even a valid quoted object-format declaration', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  const config = path.join(root, '.git/config');
  await writeFile(config, '[core]\nrepositoryformatversion = 1\n[extensions]\nobjectFormat = "sha256" # frozen hash algorithm\n');
  const captured = await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' });
  assert.equal(Object.hasOwn(captured.repository!, 'objectFormat'), false);
});

test('continued configuration values cannot become pre-authorization identity facts', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  const config = path.join(root, '.git/config');
  await writeFile(config, '[core]\nrepositoryformatversion = 0\n[alias]\nbody = literal \\\n[extensions]\\\nobjectFormat = sha256\n');
  const captured = await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' });
  assert.equal(Object.hasOwn(captured.repository!, 'objectFormat'), false);
});

test('configuration bytes may change without inventing a new descriptor identity or authorizing their read', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  const config = path.join(root, '.git/config');
  await writeFile(config, '[extensions "plugin"]\nobjectFormat = sha256\n');
  const first = await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' });
  await writeFile(config, 'unparseable raw metadata is not a Session identity input\n');
  const second = await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' });
  assert.deepEqual(second, first);
  assert.equal(Object.hasOwn(second.repository!, 'objectFormat'), false);
});
