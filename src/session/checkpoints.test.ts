import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { createCheckpoint, restoreWorkspaceCheckpoint, workspaceCheckpointFilePath } from './checkpoints.js';
import { createSession, sessionFilePath } from './store.js';

const execFileAsync = promisify(execFile);

async function withCliqHome<T>(callback: (home: string) => Promise<T>) {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoints-home-'));
  const previousHome = process.env.CLIQ_HOME;
  try {
    process.env.CLIQ_HOME = home;
    return await callback(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(home, { recursive: true, force: true });
  }
}

async function git(cwd: string, args: string[]) {
  const { stdout } = await execFileAsync('git', args, { cwd });
  return stdout.trim();
}

test('createCheckpoint records a session anchor and non-git workspace metadata', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-workspace-'));
  try {
    await withCliqHome(async () => {
      const session = createSession(cwd);
      session.lifecycle.turn = 3;
      session.records.push({
        id: 'usr_1',
        ts: '2026-04-29T00:00:00.000Z',
        kind: 'user',
        role: 'user',
        content: 'inspect repo'
      });

      const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual', name: 'before risky edit' });

      assert.equal(checkpoint.kind, 'manual');
      assert.equal(checkpoint.name, 'before risky edit');
      assert.equal(checkpoint.recordIndex, 1);
      assert.equal(checkpoint.turn, 3);
      assert.equal(session.checkpoints.length, 1);
      assert.equal(session.checkpoints[0]?.id, checkpoint.id);
      assert.equal(typeof checkpoint.workspaceCheckpointId, 'string');

      const persisted = JSON.parse(await readFile(sessionFilePath(session), 'utf8')) as {
        checkpoints: Array<{ id: string }>;
      };
      assert.equal(persisted.checkpoints[0]?.id, checkpoint.id);

      const workspaceCheckpoint = JSON.parse(
        await readFile(workspaceCheckpointFilePath(checkpoint.workspaceCheckpointId!), 'utf8')
      ) as { kind: string; status: string; reason: string };
      assert.deepEqual(
        {
          kind: workspaceCheckpoint.kind,
          status: workspaceCheckpoint.status,
          reason: workspaceCheckpoint.reason
        },
        {
          kind: 'unavailable',
          status: 'unavailable',
          reason: 'not-git'
        }
      );
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createCheckpoint initializes missing checkpoint arrays before saving', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-missing-array-'));
  try {
    await withCliqHome(async () => {
      const session = createSession(cwd) as Omit<ReturnType<typeof createSession>, 'checkpoints'> & {
        checkpoints?: ReturnType<typeof createSession>['checkpoints'];
      };
      delete session.checkpoints;

      const checkpoint = await createCheckpoint(cwd, session as ReturnType<typeof createSession>);
      const mutated = session as { checkpoints?: Array<{ id: string }> };

      assert.equal(checkpoint.kind, 'manual');
      assert.equal(mutated.checkpoints?.length, 1);
      assert.equal(mutated.checkpoints?.[0]?.id, checkpoint.id);
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createCheckpoint creates a git ghost snapshot without changing the real index', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-git-'));
  try {
    await git(cwd, ['init', '--initial-branch=main']);
    await git(cwd, ['config', 'user.email', 'test@example.com']);
    await git(cwd, ['config', 'user.name', 'Test User']);
    await writeFile(path.join(cwd, 'tracked.txt'), 'initial\n', 'utf8');
    await git(cwd, ['add', 'tracked.txt']);
    await git(cwd, ['commit', '-m', 'initial']);

    await writeFile(path.join(cwd, 'staged.txt'), 'staged\n', 'utf8');
    await git(cwd, ['add', 'staged.txt']);
    await writeFile(path.join(cwd, 'tracked.txt'), 'modified\n', 'utf8');
    await writeFile(path.join(cwd, 'untracked.txt'), 'new\n', 'utf8');

    await withCliqHome(async () => {
      const session = createSession(cwd);
      const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });
      const workspaceCheckpoint = JSON.parse(
        await readFile(workspaceCheckpointFilePath(checkpoint.workspaceCheckpointId!), 'utf8')
      ) as { kind: string; status: string; commitId: string; parentCommitId?: string };

      assert.equal(workspaceCheckpoint.kind, 'git-ghost');
      assert.equal(workspaceCheckpoint.status, 'available');
      await git(cwd, ['cat-file', '-e', `${workspaceCheckpoint.commitId}^{commit}`]);
      assert.equal(await git(cwd, ['show', `${workspaceCheckpoint.commitId}:tracked.txt`]), 'modified');
      assert.equal(await git(cwd, ['show', `${workspaceCheckpoint.commitId}:untracked.txt`]), 'new');
      assert.equal(await git(cwd, ['diff', '--cached', '--name-only']), 'staged.txt');
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createCheckpoint creates a git ghost snapshot in an empty repository', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-empty-git-'));
  try {
    await git(cwd, ['init', '--initial-branch=main']);
    await writeFile(path.join(cwd, 'first.txt'), 'first\n', 'utf8');

    await withCliqHome(async () => {
      const session = createSession(cwd);
      const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });
      const workspaceCheckpoint = JSON.parse(
        await readFile(workspaceCheckpointFilePath(checkpoint.workspaceCheckpointId!), 'utf8')
      ) as { kind: string; status: string; commitId: string; parentCommitId?: string };

      assert.equal(workspaceCheckpoint.kind, 'git-ghost');
      assert.equal(workspaceCheckpoint.status, 'available');
      assert.equal(workspaceCheckpoint.parentCommitId, undefined);
      await git(cwd, ['cat-file', '-e', `${workspaceCheckpoint.commitId}^{commit}`]);
      assert.equal(await git(cwd, ['show', `${workspaceCheckpoint.commitId}:first.txt`]), 'first');
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('restoreWorkspaceCheckpoint refuses to restore over staged changes by default', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-restore-staged-'));
  try {
    await git(cwd, ['init', '--initial-branch=main']);
    await git(cwd, ['config', 'user.email', 'test@example.com']);
    await git(cwd, ['config', 'user.name', 'Test User']);
    await writeFile(path.join(cwd, 'tracked.txt'), 'initial\n', 'utf8');
    await git(cwd, ['add', 'tracked.txt']);
    await git(cwd, ['commit', '-m', 'initial']);

    await writeFile(path.join(cwd, 'tracked.txt'), 'checkpoint\n', 'utf8');
    await withCliqHome(async () => {
      const session = createSession(cwd);
      const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });

      await writeFile(path.join(cwd, 'staged.txt'), 'staged\n', 'utf8');
      await git(cwd, ['add', 'staged.txt']);
      await writeFile(path.join(cwd, 'tracked.txt'), 'after\n', 'utf8');

      await assert.rejects(
        restoreWorkspaceCheckpoint(cwd, checkpoint.workspaceCheckpointId!),
        /staged changes/i
      );
      assert.equal(await readFile(path.join(cwd, 'tracked.txt'), 'utf8'), 'after\n');
      assert.equal(await git(cwd, ['diff', '--cached', '--name-only']), 'staged.txt');
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('restoreWorkspaceCheckpoint restores the worktree without changing the real index', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-restore-worktree-'));
  try {
    await git(cwd, ['init', '--initial-branch=main']);
    await git(cwd, ['config', 'user.email', 'test@example.com']);
    await git(cwd, ['config', 'user.name', 'Test User']);
    await writeFile(path.join(cwd, 'tracked.txt'), 'initial\n', 'utf8');
    await git(cwd, ['add', 'tracked.txt']);
    await git(cwd, ['commit', '-m', 'initial']);

    await writeFile(path.join(cwd, 'staged.txt'), 'staged\n', 'utf8');
    await git(cwd, ['add', 'staged.txt']);
    await writeFile(path.join(cwd, 'tracked.txt'), 'checkpoint\n', 'utf8');
    await writeFile(path.join(cwd, 'preexisting.txt'), 'preexisting\n', 'utf8');
    await withCliqHome(async () => {
      const session = createSession(cwd);
      const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });

      await writeFile(path.join(cwd, 'tracked.txt'), 'after\n', 'utf8');
      await rm(path.join(cwd, 'preexisting.txt'));
      await writeFile(path.join(cwd, 'created-after.txt'), 'created later\n', 'utf8');

      await restoreWorkspaceCheckpoint(cwd, checkpoint.workspaceCheckpointId!, { allowStagedChanges: true });

      assert.equal(await readFile(path.join(cwd, 'tracked.txt'), 'utf8'), 'checkpoint\n');
      assert.equal(await readFile(path.join(cwd, 'preexisting.txt'), 'utf8'), 'preexisting\n');
      await assert.rejects(readFile(path.join(cwd, 'created-after.txt'), 'utf8'), /ENOENT/);
      assert.equal(await git(cwd, ['diff', '--cached', '--name-only']), 'staged.txt');
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('restoreWorkspaceCheckpoint fails clearly when a git ghost snapshot has expired', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-restore-expired-'));
  try {
    await git(cwd, ['init', '--initial-branch=main']);
    await git(cwd, ['config', 'user.email', 'test@example.com']);
    await git(cwd, ['config', 'user.name', 'Test User']);
    await writeFile(path.join(cwd, 'tracked.txt'), 'initial\n', 'utf8');
    await git(cwd, ['add', 'tracked.txt']);
    await git(cwd, ['commit', '-m', 'initial']);

    await writeFile(path.join(cwd, 'tracked.txt'), 'checkpoint\n', 'utf8');
    await withCliqHome(async () => {
      const session = createSession(cwd);
      const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual' });
      const target = workspaceCheckpointFilePath(checkpoint.workspaceCheckpointId!);
      const workspaceCheckpoint = JSON.parse(await readFile(target, 'utf8')) as { commitId: string };
      workspaceCheckpoint.commitId = '0000000000000000000000000000000000000000';
      await writeFile(target, JSON.stringify(workspaceCheckpoint, null, 2));

      await writeFile(path.join(cwd, 'tracked.txt'), 'after\n', 'utf8');

      await assert.rejects(
        restoreWorkspaceCheckpoint(cwd, checkpoint.workspaceCheckpointId!, { allowStagedChanges: true }),
        /checkpoint snapshot is no longer available/i
      );
      assert.equal(await readFile(path.join(cwd, 'tracked.txt'), 'utf8'), 'after\n');
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('workspaceCheckpointFilePath rejects unsafe checkpoint ids', () => {
  assert.throws(
    () => workspaceCheckpointFilePath('../escape'),
    /invalid workspace checkpoint id/i
  );
});

test('restoreWorkspaceCheckpoint rejects malformed checkpoint artifacts clearly', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-checkpoint-malformed-'));
  try {
    await withCliqHome(async () => {
      const target = workspaceCheckpointFilePath('wchk_malformed');
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, JSON.stringify({ id: 'wchk_malformed', kind: 'git-ghost' }), 'utf8');

      await assert.rejects(
        restoreWorkspaceCheckpoint(cwd, 'wchk_malformed', { allowStagedChanges: true }),
        /invalid workspace checkpoint/i
      );
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
