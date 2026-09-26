import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { captureLiveWorkspaceIdentity } from './workspace-identity.js';
import { readHeldSourceGitInfoExclude } from './workspace-source-ignore.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';

test('held StateOwner reads only the literal stable Git info exclude source',
  { skip: !supported }, async () => {
    const parent = await mkdtemp(path.join(process.cwd(), '.cliq-git-exclude-'));
    const stateRoot = path.join(parent, 'state');
    const workspace = path.join(parent, 'workspace');
    await mkdir(stateRoot, { mode: 0o700 });
    await mkdir(workspace, { mode: 0o700 });
    execFileSync('git', ['init', '-q', workspace]);
    const infoPath = path.join(workspace, '.git', 'info');
    const excludePath = path.join(infoPath, 'exclude');
    await chmod(excludePath, 0o644);
    const held = (await loadNativeStateOwner()).acquireLock(stateRoot, true);
    try {
      const observed = held.inspectWorkspaceIdentity(workspace);
      assert.ok(observed.git);
      const root = observed.root;
      const git = observed.git.identity;
      const repository = (await captureLiveWorkspaceIdentity({
        workspacePath: workspace, ownerPrincipalId: 'principal', filesystem: held
      })).repository!;
      assert.deepEqual(held.readWorkspaceGitInfoExclude(workspace, root, git), await readFile(excludePath));
      assert.deepEqual(readHeldSourceGitInfoExclude(held, workspace, root, repository),
        await readFile(excludePath));
      assert.throws(() => readHeldSourceGitInfoExclude(held, workspace,
        { ...root, fileId: '0' }, repository), /changed during ignore-source capture/);
      const changedConfig = {
        ...held,
        inspectWorkspaceIdentity(workspacePath: string) {
          const inspection = held.inspectWorkspaceIdentity(workspacePath);
          return { ...inspection, git: {
            ...inspection.git!, configBytes: Buffer.from('[include]\npath=/tmp/external\n')
          } };
        }
      } as HeldStateOwnerLock;
      assert.throws(() => readHeldSourceGitInfoExclude(changedConfig, workspace, root, repository),
        /unsupported section/);
      let inspectionCount = 0;
      const changingConfig = {
        ...held,
        inspectWorkspaceIdentity(workspacePath: string) {
          const inspection = held.inspectWorkspaceIdentity(workspacePath);
          inspectionCount += 1;
          return inspectionCount === 2 ? { ...inspection, git: {
            ...inspection.git!, configBytes: Buffer.from('[core]\nfilemode=false\n')
          } } : inspection;
        },
        readWorkspaceGitInfoExclude: (...args: Parameters<HeldStateOwnerLock['readWorkspaceGitInfoExclude']>) =>
          held.readWorkspaceGitInfoExclude(...args)
      } as HeldStateOwnerLock;
      assert.throws(() => readHeldSourceGitInfoExclude(changingConfig, workspace, root, repository),
        /Git config changed during ignore-source capture/);
      let readCount = 0;
      const changingSource = {
        ...held,
        inspectWorkspaceIdentity: (workspacePath: string) => held.inspectWorkspaceIdentity(workspacePath),
        readWorkspaceGitInfoExclude(...args: Parameters<HeldStateOwnerLock['readWorkspaceGitInfoExclude']>) {
          const actual = held.readWorkspaceGitInfoExclude(...args);
          readCount += 1;
          return readCount === 2 ? Buffer.from('changed\n') : actual;
        }
      } as HeldStateOwnerLock;
      assert.throws(() => readHeldSourceGitInfoExclude(changingSource, workspace, root, repository),
        /changed during ignore-source capture/);
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, { ...root, fileId: '0' }, git),
        /unsafe or changed/);
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, { ...git, fileId: '0' }),
        /unsafe or changed/);

      await writeFile(excludePath, '*.secret\n');
      assert.deepEqual(held.readWorkspaceGitInfoExclude(workspace, root, git), Buffer.from('*.secret\n'));
      await rm(excludePath);
      assert.equal(held.readWorkspaceGitInfoExclude(workspace, root, git), null);
      assert.equal(readHeldSourceGitInfoExclude(held, workspace, root, repository), null);
      await rm(infoPath, { recursive: true });
      assert.equal(held.readWorkspaceGitInfoExclude(workspace, root, git), null);
      const displacedInfo = path.join(workspace, '.git', 'displaced-info');
      await mkdir(displacedInfo);
      await symlink(displacedInfo, infoPath);
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, git), /unsafe or changed/);
      await rm(infoPath);
      await rm(displacedInfo, { recursive: true });

      await mkdir(infoPath);
      const target = path.join(workspace, 'target');
      await writeFile(target, '*.secret\n');
      await symlink(target, excludePath);
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, git), /unsafe or changed/);
      await rm(excludePath);
      await link(target, excludePath);
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, git), /unsafe or changed/);
      await rm(excludePath);

      await writeFile(excludePath, Buffer.alloc(4 * 1024 * 1024 + 1));
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, git), /unsafe or changed/);
      await rm(excludePath);
      await writeFile(excludePath, '*.secret\n');
      await chmod(excludePath, 0o664);
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, git), /unsafe or changed/);
      await chmod(excludePath, 0o666);
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, git), /unsafe or changed/);
      await chmod(excludePath, 0o644);
      assert.deepEqual(held.readWorkspaceGitInfoExclude(workspace, root, git), Buffer.from('*.secret\n'));
      await chmod(excludePath, 0o600);
      assert.deepEqual(held.readWorkspaceGitInfoExclude(workspace, root, git), Buffer.from('*.secret\n'));

      await rename(infoPath, path.join(workspace, '.git', 'info-old'));
      assert.equal(held.readWorkspaceGitInfoExclude(workspace, root, git), null);
      held.close();
      assert.throws(() => held.readWorkspaceGitInfoExclude(workspace, root, git), /RECOVERY_REQUIRED|lock changed/);
    } finally {
      held.close();
      await rm(parent, { recursive: true, force: true });
    }
  });
