import assert from 'node:assert/strict';
import { mkdir, mkdtemp, lstat, realpath, rename, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

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
