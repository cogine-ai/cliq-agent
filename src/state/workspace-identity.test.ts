import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { loadNativeStateOwner, type HeldWorkspaceRoot } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';

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
  assert.equal(held.readGitConfigChunk()!.toString(), '[core]\n\trepositoryformatversion = 0\n');
  assert.equal(held.readGitConfigChunk(), null);
  held.close();
  assert.throws(() => held.assertHeld(), /changed or closed/);
});

test('source repository identity does not interpret an alias value as its object format', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  await writeFile(path.join(root, '.git/config'), '[core]\nrepositoryformatversion = 0\n[alias]\nobjectFormat = sha256\n');
  const captured = await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' });
  assert.equal(captured.repository!.objectFormat, 'sha1');
});

test('source repository identity reads quoted Git object-format literals with comments', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  const config = path.join(root, '.git/config');
  await writeFile(config, '[core]\nrepositoryformatversion = 1\n[extensions]\nobjectFormat = "sha256" # frozen hash algorithm\n');
  // Ambient Git is an independent fixture oracle, never production authority.
  assert.equal(execFileSync('git', ['config', '--file', config, '--no-includes', '--get', 'extensions.objectformat'],
    { encoding: 'utf8' }).trim(), 'sha256');
  assert.equal((await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' })).repository!.objectFormat, 'sha256');
});

test('source repository identity does not treat a continued alias body as configuration sections', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  const config = path.join(root, '.git/config');
  await writeFile(config, '[core]\nrepositoryformatversion = 0\n[alias]\nbody = literal \\\n[extensions]\\\nobjectFormat = sha256\n');
  assert.equal(execFileSync('git', ['config', '--file', config, '--no-includes', '--get', 'alias.body'],
    { encoding: 'utf8' }).trim(), 'literal [extensions]objectFormat = sha256');
  assert.equal((await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' })).repository!.objectFormat, 'sha1');
});

test('source repository identity ignores object-format keys in an extensions subsection', async t => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-source-format-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git'));
  const config = path.join(root, '.git/config');
  await writeFile(config, '[extensions "plugin"]\nobjectFormat = sha256\n');
  assert.equal(execFileSync('git', ['config', '--file', config, '--no-includes', '--get', 'extensions.plugin.objectformat'],
    { encoding: 'utf8' }).trim(), 'sha256');
  assert.equal((await captureLiveWorkspaceIdentity({ workspacePath: root, ownerPrincipalId: 'source-test' })).repository!.objectFormat, 'sha1');
});
