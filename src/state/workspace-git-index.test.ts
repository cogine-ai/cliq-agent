import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { parseSourceGitIndex } from './git-index.js';
import { loadNativeStateOwner } from './native-owner.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held StateOwner streams only the recorded literal Git index',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-held-git-index-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    execFileSync('git', ['init', '-q', workspace]);
    await writeFile(path.join(workspace, 'tracked.txt'), 'tracked');
    execFileSync('git', ['-C', workspace, 'add', '--', 'tracked.txt']);
    const indexPath = path.join(workspace, '.git', 'index');
    const original = await readFile(indexPath);
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const inspection = held.inspectWorkspaceIdentity(workspace);
      const root = inspection.root;
      const git = inspection.git!.identity;
      const opened = held.openWorkspaceGitIndex(workspace, root, git);
      try {
        const chunks: Buffer[] = [];
        let count = 0;
        while (count < opened.size) {
          const chunk = opened.readChunk(17);
          count += chunk.byteLength;
          chunks.push(chunk);
        }
        opened.assertStable();
        const bytes = Buffer.concat(chunks);
        assert.deepEqual(bytes, original);
        assert.deepEqual(parseSourceGitIndex(bytes, 'a'.repeat(64), 'sha1').snapshot.entries
          .map((entry) => entry.canonicalRootRelativePath), ['tracked.txt']);
      } finally { opened.close(); }
      assert.throws(() => held.openWorkspaceGitIndex(workspace, { ...root, fileId: '0' }, git),
        /unsafe or changed/);
      assert.throws(() => held.openWorkspaceGitIndex(workspace, root, { ...git, fileId: '0' }),
        /unsafe or changed/);
      const alias = path.join(parent, 'index-hardlink');
      await link(indexPath, alias);
      try { assert.throws(() => held.openWorkspaceGitIndex(workspace, root, git), /unsafe or changed/); }
      finally { await rm(alias); }
      const displaced = path.join(workspace, '.git', 'index-displaced');
      await rename(indexPath, displaced);
      await symlink('index-displaced', indexPath);
      try { assert.throws(() => held.openWorkspaceGitIndex(workspace, root, git), /unsafe or changed/); }
      finally { await rm(indexPath); await rename(displaced, indexPath); }
      const changing = held.openWorkspaceGitIndex(workspace, root, git);
      try {
        assert.equal(changing.readChunk(1).byteLength, 1);
        await writeFile(indexPath, original);
        assert.throws(() => changing.readChunk(1), /changed/);
      } finally { changing.close(); }
      const movedGit = path.join(workspace, 'git-displaced');
      const replaced = held.openWorkspaceGitIndex(workspace, root, git);
      await rename(path.join(workspace, '.git'), movedGit);
      await mkdir(path.join(workspace, '.git'));
      try {
        assert.throws(() => replaced.readChunk(1), /changed/);
        assert.throws(() => held.openWorkspaceGitIndex(workspace, root, git), /unsafe or changed/);
      } finally {
        replaced.close();
        await rm(path.join(workspace, '.git'), { recursive: true });
        await rename(movedGit, path.join(workspace, '.git'));
      }
      held.close();
      assert.throws(() => held.openWorkspaceGitIndex(workspace, root, git), /RECOVERY_REQUIRED|lock changed/);
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });
