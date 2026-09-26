import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, WorkspaceEntryManifest } from '../kernel/types.js';
import { MAX_FROZEN_IGNORE_SOURCE_BYTES, parseFrozenIgnoreSourceBytes } from './frozen-ignore-sources.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';
import {
  assertLiveFrozenIgnoreSources, readHeldGitignoreFromDirectory, readHeldSourceGitInfoExclude
} from './workspace-source-ignore.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held .gitignore reader binds literal source bytes to repeated directory observations',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-gitignore-source-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    const nested = path.join(workspace, 'nested');
    const empty = path.join(workspace, 'empty');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(nested, { recursive: true, mode: 0o700 });
    await mkdir(empty, { mode: 0o700 });
    execFileSync('git', ['init', '-q', workspace]);
    await chmod(path.join(workspace, '.git', 'info', 'exclude'), 0o644);
    const rootIgnore = path.join(workspace, '.gitignore');
    const nestedIgnore = path.join(nested, '.gitignore');
    await writeFile(rootIgnore, '*.log\n', { mode: 0o600 });
    await writeFile(nestedIgnore, '!keep.log\n', { mode: 0o600 });
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const root = held.inspectWorkspaceIdentity(workspace).root;
      assert.deepEqual(readHeldGitignoreFromDirectory(held, workspace, root, ''),
        Buffer.from('*.log\n'));
      assert.deepEqual(readHeldGitignoreFromDirectory(held, workspace, root, 'nested'),
        Buffer.from('!keep.log\n'));
      const repository = (await captureLiveWorkspaceIdentity({
        workspacePath: workspace, ownerPrincipalId: 'principal', filesystem: held
      })).repository!;
      const excludeBytes = readHeldSourceGitInfoExclude(held, workspace, root, repository);
      const sources: FrozenIgnoreRulesV1['sources'] = [];
      const sourceBytes: Buffer[] = [];
      const addSource = (kind: 'git_info_exclude' | 'gitignore', sourcePath: string,
        baseDirectory: string, bytes: Buffer) => {
        const contentRef = sha256Bytes(bytes);
        sources.push({ index: sources.length, kind, canonicalRootRelativePath: sourcePath,
          baseDirectory, contentRef, contentDigest: contentRef });
        sourceBytes.push(bytes);
      };
      if (excludeBytes !== null) addSource('git_info_exclude', '.git/info/exclude', '', excludeBytes);
      addSource('gitignore', '.gitignore', '', Buffer.from('*.log\n'));
      addSource('gitignore', 'nested/.gitignore', 'nested', Buffer.from('!keep.log\n'));
      const rules: FrozenIgnoreRulesV1 = {
        schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
        matcherVersion: 'cliq-git-wildmatch-v1',
        repositoryIdentityDigest: repository.repositoryIdentityDigest,
        sources, rules: [], rulesDigest: ''
      };
      for (const [index, source] of sources.entries()) {
        rules.rules.push(...parseFrozenIgnoreSourceBytes(sourceBytes[index]!, source, rules.rules.length));
      }
      rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
      const entries: WorkspaceEntryManifest = {
        schemaVersion: 1, format: 'cliq-workspace-entries-v1',
        entries: [{ path: 'nested', kind: 'directory', mode: 0o755 }],
        entryCount: 1, byteCount: 0, treeDigest: ''
      };
      entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format,
        entries: entries.entries });
      assert.doesNotThrow(() => assertLiveFrozenIgnoreSources(held, workspace, root,
        repository, rules, entries));
      await writeFile(nestedIgnore, '!drop.log\n');
      assert.throws(() => assertLiveFrozenIgnoreSources(held, workspace, root,
        repository, rules, entries), /nested\/\.gitignore/);
      await writeFile(nestedIgnore, '!keep.log\n');
      assert.equal(readHeldGitignoreFromDirectory(held, workspace, root, 'empty'), null);
      assert.throws(() => readHeldGitignoreFromDirectory(held, workspace, root, '.git'),
        /root-relative/);
      await symlink(nested, path.join(workspace, 'nested-link'));
      assert.throws(() => readHeldGitignoreFromDirectory(held, workspace, root, 'nested-link'),
        /unsafe or changed/);

      await rm(rootIgnore);
      await symlink(nestedIgnore, rootIgnore);
      assert.throws(() => readHeldGitignoreFromDirectory(held, workspace, root, ''),
        /not a bounded regular source file/);
      await rm(rootIgnore);
      await writeFile(rootIgnore, Buffer.alloc(MAX_FROZEN_IGNORE_SOURCE_BYTES + 1), { mode: 0o600 });
      assert.throws(() => readHeldGitignoreFromDirectory(held, workspace, root, ''),
        /not a bounded regular source file/);
      await rm(rootIgnore);

      await writeFile(rootIgnore, 'old\n', { mode: 0o600 });
      const staleListing = held.listWorkspaceSourceDirectory(workspace, root, '');
      await writeFile(rootIgnore, 'new-longer\n');
      const changedDuringOpen = {
        listWorkspaceSourceDirectory: () => staleListing,
        openWorkspaceSourceFile: (...args: Parameters<HeldStateOwnerLock['openWorkspaceSourceFile']>) =>
          held.openWorkspaceSourceFile(...args)
      } as unknown as HeldStateOwnerLock;
      assert.throws(() => readHeldGitignoreFromDirectory(changedDuringOpen, workspace, root, ''),
        /changed between directory scan and source opening/);

      const currentListing = held.listWorkspaceSourceDirectory(workspace, root, '');
      let listCount = 0;
      const appeared = {
        listWorkspaceSourceDirectory: () => ++listCount === 1
          ? currentListing.filter((entry) => entry.name !== '.gitignore') : currentListing
      } as unknown as HeldStateOwnerLock;
      assert.throws(() => readHeldGitignoreFromDirectory(appeared, workspace, root, ''),
        /appeared during source capture/);

      await rename(rootIgnore, path.join(workspace, '.GITIGNORE'));
      assert.equal(readHeldGitignoreFromDirectory(held, workspace, root, ''), null);
      held.close();
      assert.throws(() => readHeldGitignoreFromDirectory(held, workspace, root, 'nested'),
        /RECOVERY_REQUIRED|changed/);
    } finally {
      held.close();
      await rm(parent, { recursive: true, force: true });
    }
  });
