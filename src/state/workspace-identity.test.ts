import assert from 'node:assert/strict';
import { link, mkdir, mkdtemp, lstat, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { digestOmitting } from '../kernel/identity.js';
import { decodeRepositoryIdentity, decodeWorkspaceIdentity } from './decoders.js';
import { loadNativeStateOwner } from './native-owner.js';
import { captureLiveWorkspaceIdentity, recaptureLiveWorkspaceIdentity } from './workspace-identity.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('workspace and literal .git identities retain descriptor-derived bigint device and inode ids',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-workspace-id-'));
    const stateRoot = path.join(parent, 'state');
    const workspacePath = path.join(parent, 'workspace');
    const displacedPath = path.join(parent, 'workspace-displaced');
    await mkdir(stateRoot, { mode: 0o700 });
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      await mkdir(workspacePath, { mode: 0o700 });
      await mkdir(path.join(workspacePath, '.git'), { mode: 0o700 });
      const principalId = 'local-principal-fixture';
      const captured = await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: principalId,
        filesystem: held });
      const root = await lstat(workspacePath, { bigint: true });
      const git = await lstat(path.join(workspacePath, '.git'), { bigint: true });
      assert.equal(captured.identity.rootIdentity.deviceId, root.dev.toString(10));
      assert.equal(captured.identity.rootIdentity.fileId, root.ino.toString(10));
      assert.equal(captured.repository?.gitDirectoryIdentity.deviceId, git.dev.toString(10));
      assert.equal(captured.repository?.gitDirectoryIdentity.fileId, git.ino.toString(10));
      assert.deepEqual(await recaptureLiveWorkspaceIdentity(captured.identity, workspacePath, held), captured.identity);
      await rename(workspacePath, displacedPath);
      await mkdir(workspacePath, { mode: 0o700 });
      await assert.rejects(recaptureLiveWorkspaceIdentity(captured.identity, workspacePath, held),
        /workspace root identity changed/);
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });

test('held StateOwner reads literal Git config without following aliases and binds its object format',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-git-identity-'));
    const stateRoot = path.join(parent, 'state');
    const workspacePath = path.join(parent, 'workspace');
    const gitPath = path.join(workspacePath, '.git');
    const configPath = path.join(gitPath, 'config');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspacePath, { mode: 0o700 });
    await mkdir(gitPath, { mode: 0o700 });
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      await writeFile(configPath, '[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n',
        { mode: 0o600 });
      const captured = await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
        filesystem: held });
      assert.equal(captured.repository?.objectFormat, 'sha256');
      assert.equal(held.inspectWorkspaceIdentity(workspacePath).git?.configBytes?.toString('utf8').includes('sha256'), true);

      const alias = path.join(parent, 'config-alias');
      await link(configPath, alias);
      await assert.rejects(captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
        filesystem: held }), /config.*regular file/);
      await rm(alias);

      await rm(configPath);
      await symlink(alias, configPath);
      await assert.rejects(captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
        filesystem: held }), /config.*regular file/);
      await rm(configPath);

      await writeFile(configPath, Buffer.from([0xff]), { mode: 0o600 });
      await assert.rejects(captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
        filesystem: held }), /not UTF-8/);
      await rm(configPath);
      const caseAlias = path.join(gitPath, 'Config');
      await writeFile(caseAlias, '[extensions]\n\tobjectformat = sha256\n', { mode: 0o600 });
      const caseInsensitive = await lstat(configPath).then(() => true, () => false);
      if (caseInsensitive) {
        await assert.rejects(captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
          filesystem: held }), /config.*regular file/);
      } else {
        assert.equal((await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
          filesystem: held })).repository?.objectFormat, 'sha1');
      }
      await rm(caseAlias);
      await writeFile(configPath, '[extensions "custom"]\n\tobjectformat = sha256\n', { mode: 0o600 });
      const subsection = await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
        filesystem: held });
      assert.equal(subsection.repository?.objectFormat, 'sha1');
      await writeFile(configPath, '[extensions]\n\tobjectformat = sha1\n', { mode: 0o600 });
      await assert.rejects(recaptureLiveWorkspaceIdentity(captured.identity, workspacePath, held),
        /repository identity changed/);
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });

test('held workspace observation rejects symlinked ancestors and a replaced literal .git',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-workspace-alias-'));
    const stateRoot = path.join(parent, 'state');
    const workspacePath = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspacePath, { mode: 0o700 });
    await mkdir(path.join(workspacePath, '.git'), { mode: 0o700 });
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const alias = path.join(parent, 'alias');
      await symlink(workspacePath, alias);
      await assert.rejects(captureLiveWorkspaceIdentity({ workspacePath: alias,
        ownerPrincipalId: 'principal', filesystem: held }), /no-follow directory/);
      const captured = await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
        filesystem: held });
      await rename(path.join(workspacePath, '.git'), path.join(workspacePath, '.git-old'));
      const aliasGit = path.join(workspacePath, '.Git');
      await mkdir(aliasGit, { mode: 0o700 });
      const caseInsensitive = await lstat(path.join(workspacePath, '.git')).then(() => true, () => false);
      if (caseInsensitive) {
        await assert.rejects(captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
          filesystem: held }), /literal same-user directory/);
      } else {
        assert.equal((await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: 'principal',
          filesystem: held })).repository, undefined);
      }
      await rm(aliasGit, { recursive: true });
      await mkdir(path.join(workspacePath, '.git'), { mode: 0o700 });
      await assert.rejects(recaptureLiveWorkspaceIdentity(captured.identity, workspacePath, held),
        /repository identity changed/);
      held.close();
      assert.throws(() => held.inspectWorkspaceIdentity(workspacePath),
        (error: unknown) => error instanceof Error && 'code' in error && error.code === 'RECOVERY_REQUIRED');
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });

test('saved workspace and repository identities reject rehashed shape and filesystem-id substitutions', () => {
  const repository = {
    schemaVersion: 1, format: 'cliq-repository-identity-v1', platform: 'linux',
    gitDirectoryRelativePath: '.git',
    gitDirectoryIdentity: { deviceId: '1', fileId: '18446744073709551615', ownerUid: 501 },
    objectFormat: 'sha256', repositoryIdentityDigest: ''
  };
  repository.repositoryIdentityDigest = digestOmitting(repository, 'repositoryIdentityDigest');
  assert.deepEqual(decodeRepositoryIdentity(repository), repository);
  const workspace = {
    schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: 'principal',
    platform: 'linux', kind: 'live', canonicalRootPath: '/tmp/repository',
    rootIdentity: { deviceId: '1', fileId: '2', ownerUid: 501 },
    repositoryIdentityRef: 'a'.repeat(64),
    repositoryIdentityDigest: repository.repositoryIdentityDigest,
    identityDigest: ''
  };
  workspace.identityDigest = digestOmitting(workspace, 'identityDigest');
  assert.deepEqual(decodeWorkspaceIdentity(workspace), workspace);
  const badRepository = { ...repository,
    gitDirectoryIdentity: { ...repository.gitDirectoryIdentity, fileId: '018446744073709551615' },
    repositoryIdentityDigest: '' };
  badRepository.repositoryIdentityDigest = digestOmitting(badRepository, 'repositoryIdentityDigest');
  assert.throws(() => decodeRepositoryIdentity(badRepository), /unsigned decimal/);
  const { repositoryIdentityRef: _removed, ...unpaired } = workspace;
  unpaired.identityDigest = digestOmitting(unpaired, 'identityDigest');
  assert.throws(() => decodeWorkspaceIdentity(unpaired), /closed shape/);
  const badPath = { ...workspace, canonicalRootPath: '/tmp/../repository', identityDigest: '' };
  badPath.identityDigest = digestOmitting(badPath, 'identityDigest');
  assert.throws(() => decodeWorkspaceIdentity(badPath), /not canonical/);
  const overwide = { ...workspace, rootIdentity: {
    ...workspace.rootIdentity, fileId: '18446744073709551616'
  }, identityDigest: '' };
  overwide.identityDigest = digestOmitting(overwide, 'identityDigest');
  assert.throws(() => decodeWorkspaceIdentity(overwide), /unsigned 64-bit/);
  const unknown = { ...workspace, extra: 'signed but unsupported', identityDigest: '' };
  unknown.identityDigest = digestOmitting(unknown, 'identityDigest');
  assert.throws(() => decodeWorkspaceIdentity(unknown), /closed shape/);
});
