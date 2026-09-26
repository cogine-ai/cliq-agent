import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { digestOmitting } from '../kernel/identity.js';
import { loadNativeStateOwner } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';
import { readHeldSanitizedGitConfig } from './workspace-source-config.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('source Git config is parsed only from the held matching workspace and repository',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-config-'));
    const stateRoot = path.join(parent, 'state');
    const workspacePath = path.join(parent, 'workspace');
    const gitPath = path.join(workspacePath, '.git');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspacePath, { mode: 0o700 });
    await mkdir(gitPath, { mode: 0o700 });
    const configPath = path.join(gitPath, 'config');
    await writeFile(configPath,
      '[core]\nrepositoryformatversion=1\nfilemode=true\nbare=false\n[extensions]\nobjectformat=sha256\n',
      { mode: 0o600 });
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const captured = await captureLiveWorkspaceIdentity({
        workspacePath, ownerPrincipalId: 'principal', filesystem: held
      });
      const repository = captured.repository!;
      const root = captured.identity.rootIdentity;
      const config = readHeldSanitizedGitConfig(held, workspacePath, root, repository);
      assert.equal(config.extensions?.objectFormat, 'sha256');
      assert.throws(() => readHeldSanitizedGitConfig(held, workspacePath,
        { ...root, fileId: '0' }, repository), /identity changed/);
      assert.throws(() => readHeldSanitizedGitConfig(held, workspacePath, root,
        { ...repository, objectFormat: 'sha1' }), /digest does not rehash/);
      const wrongFormat = { ...repository, objectFormat: 'sha1' as const, repositoryIdentityDigest: '' };
      wrongFormat.repositoryIdentityDigest = digestOmitting(wrongFormat, 'repositoryIdentityDigest');
      assert.throws(() => readHeldSanitizedGitConfig(held, workspacePath, root, wrongFormat),
        /object format differs/);
      await writeFile(configPath, '[include]\npath=/tmp/external\n', { mode: 0o600 });
      assert.throws(() => readHeldSanitizedGitConfig(held, workspacePath, root, repository),
        /unsupported section/);
      await rename(workspacePath, path.join(parent, 'displaced'));
      await mkdir(workspacePath, { mode: 0o700 });
      assert.throws(() => readHeldSanitizedGitConfig(held, workspacePath, root, repository),
        /identity changed/);
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });
