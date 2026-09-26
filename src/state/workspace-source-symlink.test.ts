import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KernelStorageError } from './errors.js';
import { loadNativeStateOwner } from './native-owner.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held StateOwner observes source symlink text without following its target',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-source-link-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(path.join(workspace, 'nested'), { mode: 0o700 });
    await writeFile(path.join(workspace, 'source.txt'), 'source', { mode: 0o600 });
    await symlink('../source.txt', path.join(workspace, 'nested', 'up'));
    await symlink('../outside', path.join(workspace, 'external'));
    await symlink('.GiT/config', path.join(workspace, 'git-alias'));
    await symlink('nested/.GiT/../source.txt', path.join(workspace, 'git-traversal'));
    await symlink('/etc/passwd', path.join(workspace, 'absolute'));
    await symlink('e\u0301', path.join(workspace, 'decomposed'));
    await symlink('nested', path.join(workspace, 'nested-alias'));
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      const link = held.readWorkspaceSourceSymlink(workspace, root, 'nested/up');
      assert.equal(link.target, '../source.txt');
      assert.equal(link.linkCount, 1);
      assert.equal(link.identity.ownerUid, process.geteuid!());
      for (const source of ['external', 'git-alias', 'git-traversal', 'absolute', 'decomposed']) {
        assert.throws(() => held.readWorkspaceSourceSymlink(workspace, root, source),
          (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
      }
      assert.throws(() => held.readWorkspaceSourceSymlink(workspace, root, 'nested-alias/up'), /unsafe or changed/);
      assert.throws(() => held.readWorkspaceSourceSymlink(workspace, root, 'source.txt'), /unsafe or changed/);
      held.close();
      assert.throws(() => held.readWorkspaceSourceSymlink(workspace, root, 'nested/up'),
        (error: unknown) => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });
