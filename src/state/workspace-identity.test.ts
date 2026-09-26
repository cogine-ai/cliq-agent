import assert from 'node:assert/strict';
import { mkdir, mkdtemp, lstat, realpath, rename, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { digestOmitting } from '../kernel/identity.js';
import { decodeRepositoryIdentity, decodeWorkspaceIdentity } from './decoders.js';
import { captureLiveWorkspaceIdentity, recaptureLiveWorkspaceIdentity } from './workspace-identity.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('workspace and literal .git identities retain descriptor-derived bigint device and inode ids',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(await realpath(os.tmpdir()), 'cliq-workspace-id-'));
    const workspacePath = path.join(parent, 'workspace');
    const displacedPath = path.join(parent, 'workspace-displaced');
    try {
      await mkdir(workspacePath, { mode: 0o700 });
      await mkdir(path.join(workspacePath, '.git'), { mode: 0o700 });
      const principalId = 'local-principal-fixture';
      const captured = await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: principalId });
      const root = await lstat(workspacePath, { bigint: true });
      const git = await lstat(path.join(workspacePath, '.git'), { bigint: true });
      assert.equal(captured.identity.rootIdentity.deviceId, root.dev.toString(10));
      assert.equal(captured.identity.rootIdentity.fileId, root.ino.toString(10));
      assert.equal(captured.repository?.gitDirectoryIdentity.deviceId, git.dev.toString(10));
      assert.equal(captured.repository?.gitDirectoryIdentity.fileId, git.ino.toString(10));
      assert.deepEqual(await recaptureLiveWorkspaceIdentity(captured.identity, workspacePath), captured.identity);
      await rename(workspacePath, displacedPath);
      await mkdir(workspacePath, { mode: 0o700 });
      await assert.rejects(recaptureLiveWorkspaceIdentity(captured.identity, workspacePath),
        /workspace root identity changed/);
    } finally { await rm(parent, { recursive: true, force: true }); }
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
