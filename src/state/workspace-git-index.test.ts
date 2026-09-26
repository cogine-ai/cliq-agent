import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { encodeCanonicalGitIndex, MAX_GIT_INDEX_BYTES, parseSourceGitIndex } from './git-index.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';
import { captureHeldGitIndexSnapshot, readHeldSourceGitIndex } from './workspace-source-index.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held StateOwner streams only the recorded literal Git index',
  { skip: !supported }, async (t) => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-held-git-index-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    const casRoot = path.join(parent, 'cas');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(casRoot, { mode: 0o700 });
    execFileSync('git', ['init', '-q', workspace]);
    await writeFile(path.join(workspace, 'tracked.txt'), 'tracked');
    execFileSync('git', ['-C', workspace, 'add', '--', 'tracked.txt']);
    const indexPath = path.join(workspace, '.git', 'index');
    const original = await readFile(indexPath);
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(casRoot));
    try {
      const inspection = held.inspectWorkspaceIdentity(workspace);
      const root = inspection.root;
      const git = inspection.git!.identity;
      const captured = await captureLiveWorkspaceIdentity({
        workspacePath: workspace, ownerPrincipalId: 'principal', filesystem: held
      });
      const normalized = readHeldSourceGitIndex(held, workspace, root, captured.repository!);
      assert.deepEqual(normalized.snapshot.entries.map((entry) => entry.canonicalRootRelativePath),
        ['tracked.txt']);
      const published = await captureHeldGitIndexSnapshot(held, workspace, root,
        captured.repository!, artifacts);
      assert.deepEqual(published.snapshot, normalized.snapshot);
      assert.deepEqual(await artifacts.readBytes(published.canonicalBytesArtifact.ref),
        normalized.canonicalBytes);
      assert.deepEqual(await artifacts.readCanonical(published.snapshotArtifact.ref),
        normalized.snapshot);

      const publishCanonical = artifacts.publishCanonical.bind(artifacts);
      const injected = t.mock.method(artifacts, 'publishCanonical',
        async (value: unknown, kind: string) => {
          const artifact = await publishCanonical(value, kind);
          if (kind === 'cliq-git-index-snapshot-v1') {
            await writeFile(indexPath, encodeCanonicalGitIndex({
              ...normalized.snapshot, entries: []
            }));
          }
          return artifact;
        });
      try {
        await assert.rejects(captureHeldGitIndexSnapshot(held, workspace, root,
          captured.repository!, artifacts),
        /live Git index differs from its retained canonical source snapshot/);
      } finally {
        injected.mock.restore();
        await writeFile(indexPath, original);
      }
      let closed = 0;
      const oversizedFile = { size: MAX_GIT_INDEX_BYTES + 1, close() { closed += 1; } };
      const oversizedFilesystem = {
        inspectWorkspaceIdentity() { return inspection; },
        openWorkspaceGitIndex() { return oversizedFile; }
      } as unknown as HeldStateOwnerLock;
      assert.throws(() => readHeldSourceGitIndex(oversizedFilesystem, workspace,
        root, captured.repository!), /byte ceiling/);
      assert.equal(closed, 1);
      const opened = held.openWorkspaceGitIndex(workspace, root, git);
      assert.ok(opened);
      try {
        assert.equal(opened.linkCount, 1);
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
      assert.ok(changing);
      try {
        assert.equal(changing.readChunk(1).byteLength, 1);
        await writeFile(indexPath, original);
        assert.throws(() => changing.readChunk(1), /changed/);
      } finally { changing.close(); }
      const movedGit = path.join(workspace, 'git-displaced');
      const replaced = held.openWorkspaceGitIndex(workspace, root, git);
      assert.ok(replaced);
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

test('a descriptor-proven absent Git index normalizes to the empty v2 index',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-absent-git-index-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    execFileSync('git', ['init', '-q', workspace]);
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const captured = await captureLiveWorkspaceIdentity({
        workspacePath: workspace, ownerPrincipalId: 'principal', filesystem: held
      });
      assert.equal(held.openWorkspaceGitIndex(workspace, captured.identity.rootIdentity,
        captured.repository!.gitDirectoryIdentity), null);
      const normalized = readHeldSourceGitIndex(held, workspace,
        captured.identity.rootIdentity, captured.repository!);
      assert.equal(normalized.sourceVersion, 'absent');
      assert.deepEqual(normalized.snapshot.entries, []);
      assert.equal(normalized.snapshot.indexTreeObjectId,
        '4b825dc642cb6eb9a060e54bf8d69288fbee4904');
      let closes = 0;
      let opens = 0;
      const appearance = {
        inspectWorkspaceIdentity() { return held.inspectWorkspaceIdentity(workspace); },
        openWorkspaceGitIndex() {
          opens += 1;
          return opens === 1 ? null : { close() { closes += 1; } };
        }
      } as unknown as HeldStateOwnerLock;
      assert.throws(() => readHeldSourceGitIndex(appearance, workspace,
        captured.identity.rootIdentity, captured.repository!), /appeared/);
      assert.equal(closes, 1);
      await symlink('config', path.join(workspace, '.git', 'index'));
      assert.throws(() => held.openWorkspaceGitIndex(workspace,
        captured.identity.rootIdentity, captured.repository!.gitDirectoryIdentity), /unsafe or changed/);
      await rm(path.join(workspace, '.git', 'index'));
      await writeFile(path.join(workspace, '.git', 'config'),
        '[core]\nrepositoryformatversion = 1\nfilemode = true\nbare = false\n' +
        'logallrefupdates = true\n[extensions]\nobjectformat = sha256\n');
      const sha256 = await captureLiveWorkspaceIdentity({
        workspacePath: workspace, ownerPrincipalId: 'principal', filesystem: held
      });
      const emptySha256 = readHeldSourceGitIndex(held, workspace,
        sha256.identity.rootIdentity, sha256.repository!);
      assert.equal(emptySha256.sourceVersion, 'absent');
      assert.equal(emptySha256.canonicalBytes.byteLength, 44);
      assert.equal(emptySha256.snapshot.indexTreeObjectId,
        execFileSync('git', ['-C', workspace, 'hash-object', '-t', 'tree', '--stdin'],
          { input: '' }).toString('utf8').trim());
    } finally { held.close(); await rm(parent, { recursive: true, force: true }); }
  });
