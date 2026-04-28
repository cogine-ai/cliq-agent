import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { makeId, nowIso, resolveCliqHome, saveSession } from './store.js';
import type { Session, SessionCheckpoint, WorkspaceCheckpoint } from './types.js';

const execFileAsync = promisify(execFile);
const GHOST_COMMIT_MESSAGE = 'cliq checkpoint snapshot';

export type CreateCheckpointOptions = {
  kind?: SessionCheckpoint['kind'];
  name?: string;
};

export type RestoreWorkspaceCheckpointOptions = {
  allowStagedChanges?: boolean;
};

export function workspaceCheckpointFilePath(workspaceCheckpointId: string, cliqHome = resolveCliqHome()) {
  return path.join(cliqHome, 'checkpoints', `${workspaceCheckpointId}.json`);
}

async function writeWorkspaceCheckpoint(checkpoint: WorkspaceCheckpoint) {
  const target = workspaceCheckpointFilePath(checkpoint.id);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, JSON.stringify(checkpoint, null, 2));
}

async function resolveWorkspaceRealPath(cwd: string) {
  return await fs.realpath(cwd);
}

async function resolveGitRoot(cwd: string) {
  try {
    const stdout = await runGit(cwd, ['rev-parse', '--show-toplevel']);
    const root = stdout.trim();
    return root ? await fs.realpath(root) : null;
  } catch {
    return null;
  }
}

async function runGit(cwd: string, args: string[], env: Record<string, string> = {}) {
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    env: {
      ...process.env,
      ...env
    }
  });
  return stdout.trim();
}

async function runGitRaw(cwd: string, args: string[], env: Record<string, string> = {}) {
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    env: {
      ...process.env,
      ...env
    }
  });
  return stdout;
}

function splitNullList(output: string) {
  return output.split('\0').filter(Boolean);
}

function toGitPath(value: string) {
  return value.split(path.sep).join('/');
}

async function tryResolveHead(gitRootRealPath: string) {
  try {
    return await runGit(gitRootRealPath, ['rev-parse', '--verify', 'HEAD']);
  } catch {
    return undefined;
  }
}

async function createGitGhostCheckpoint(
  id: string,
  createdAt: string,
  workspaceRealPath: string,
  gitRootRealPath: string
): Promise<WorkspaceCheckpoint> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cliq-git-index-'));
  const indexPath = path.join(tempDir, 'index');
  const env = {
    GIT_INDEX_FILE: indexPath,
    GIT_AUTHOR_NAME: 'Cliq Checkpoint',
    GIT_AUTHOR_EMAIL: 'checkpoint@cliq.local',
    GIT_COMMITTER_NAME: 'Cliq Checkpoint',
    GIT_COMMITTER_EMAIL: 'checkpoint@cliq.local'
  };

  try {
    const parentCommitId = await tryResolveHead(gitRootRealPath);
    if (parentCommitId) {
      await runGit(gitRootRealPath, ['read-tree', parentCommitId], env);
    }

    const relativeScope = path.relative(gitRootRealPath, workspaceRealPath);
    const repoRelativeScope = relativeScope ? toGitPath(relativeScope) : '.';
    const preexistingUntrackedFiles = await listUntrackedFiles(gitRootRealPath, repoRelativeScope);
    await runGit(gitRootRealPath, ['add', '--all', '--', repoRelativeScope], env);
    const treeId = await runGit(gitRootRealPath, ['write-tree'], env);
    const commitArgs = ['commit-tree', treeId];
    if (parentCommitId) {
      commitArgs.push('-p', parentCommitId);
    }
    commitArgs.push('-m', GHOST_COMMIT_MESSAGE);
    const commitId = await runGit(gitRootRealPath, commitArgs, env);

    return {
      id,
      kind: 'git-ghost',
      status: 'available',
      createdAt,
      workspaceRealPath,
      gitRootRealPath,
      repoRelativeScope,
      commitId,
      parentCommitId,
      preexistingUntrackedFiles,
      warnings: []
    };
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
}

async function createWorkspaceCheckpoint(cwd: string): Promise<WorkspaceCheckpoint> {
  const createdAt = nowIso();
  const id = makeId('wchk');
  const workspaceRealPath = await resolveWorkspaceRealPath(cwd);
  const gitRootRealPath = await resolveGitRoot(workspaceRealPath);

  if (!gitRootRealPath) {
    return {
      id,
      kind: 'unavailable',
      status: 'unavailable',
      createdAt,
      workspaceRealPath,
      reason: 'not-git'
    };
  }

  try {
    return await createGitGhostCheckpoint(id, createdAt, workspaceRealPath, gitRootRealPath);
  } catch (error) {
    return {
      id,
      kind: 'unavailable',
      status: 'unavailable',
      createdAt,
      workspaceRealPath,
      reason: 'snapshot-failed',
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

export async function createCheckpoint(
  cwd: string,
  session: Session,
  options: CreateCheckpointOptions = {}
): Promise<SessionCheckpoint> {
  const workspaceCheckpoint = await createWorkspaceCheckpoint(cwd);
  await writeWorkspaceCheckpoint(workspaceCheckpoint);

  const checkpoint: SessionCheckpoint = {
    id: makeId('chk'),
    name: options.name,
    kind: options.kind ?? 'manual',
    createdAt: nowIso(),
    recordIndex: session.records.length,
    turn: session.lifecycle.turn,
    workspaceCheckpointId: workspaceCheckpoint.id
  };

  session.checkpoints.push(checkpoint);
  await saveSession(cwd, session);
  return checkpoint;
}

async function readWorkspaceCheckpoint(workspaceCheckpointId: string): Promise<WorkspaceCheckpoint> {
  const target = workspaceCheckpointFilePath(workspaceCheckpointId);
  return JSON.parse(await fs.readFile(target, 'utf8')) as WorkspaceCheckpoint;
}

async function listUntrackedFiles(gitRootRealPath: string, repoRelativeScope: string) {
  const stdout = await runGitRaw(gitRootRealPath, [
    'ls-files',
    '--others',
    '--exclude-standard',
    '-z',
    '--',
    repoRelativeScope
  ]);
  return splitNullList(stdout);
}

async function listStagedFiles(gitRootRealPath: string, repoRelativeScope: string) {
  const stdout = await runGitRaw(gitRootRealPath, [
    'diff',
    '--cached',
    '--name-only',
    '-z',
    '--',
    repoRelativeScope
  ]);
  return splitNullList(stdout);
}

async function verifyGitCommitExists(checkpoint: Extract<WorkspaceCheckpoint, { kind: 'git-ghost' }>) {
  try {
    await runGit(checkpoint.gitRootRealPath, ['cat-file', '-e', `${checkpoint.commitId}^{commit}`]);
  } catch {
    const expired: WorkspaceCheckpoint = {
      ...checkpoint,
      status: 'expired'
    };
    await writeWorkspaceCheckpoint(expired);
    throw new Error(
      `checkpoint snapshot is no longer available: ${checkpoint.id}. The session checkpoint still exists, but the Git ghost commit cannot be restored.`
    );
  }
}

function workspaceCheckpointRestoreTarget(checkpoint: WorkspaceCheckpoint) {
  if (checkpoint.kind === 'unavailable') {
    throw new Error(`workspace checkpoint cannot be restored: ${checkpoint.reason}`);
  }

  if (checkpoint.status !== 'available') {
    throw new Error(`workspace checkpoint cannot be restored: ${checkpoint.status}`);
  }

  return checkpoint;
}

async function assertSameWorkspace(cwd: string, checkpoint: WorkspaceCheckpoint) {
  const cwdRealPath = await resolveWorkspaceRealPath(cwd);
  if (cwdRealPath !== checkpoint.workspaceRealPath) {
    throw new Error(
      `workspace checkpoint belongs to ${checkpoint.workspaceRealPath}, but restore was requested from ${cwdRealPath}`
    );
  }
}

async function removeNewUntrackedFiles(
  gitRootRealPath: string,
  repoRelativeScope: string,
  preexistingUntrackedFiles: string[]
) {
  const preexisting = new Set(preexistingUntrackedFiles);
  const current = await listUntrackedFiles(gitRootRealPath, repoRelativeScope);

  for (const file of current) {
    if (preexisting.has(file)) {
      continue;
    }

    const absolutePath = path.resolve(gitRootRealPath, ...file.split('/'));
    const rootWithSeparator = gitRootRealPath.endsWith(path.sep) ? gitRootRealPath : `${gitRootRealPath}${path.sep}`;
    if (absolutePath !== gitRootRealPath && !absolutePath.startsWith(rootWithSeparator)) {
      throw new Error(`refusing to remove untracked file outside git root: ${file}`);
    }
    await fs.rm(absolutePath, { recursive: true, force: true });
  }
}

export async function restoreWorkspaceCheckpoint(
  cwd: string,
  workspaceCheckpointId: string,
  options: RestoreWorkspaceCheckpointOptions = {}
) {
  const rawCheckpoint = await readWorkspaceCheckpoint(workspaceCheckpointId);
  await assertSameWorkspace(cwd, rawCheckpoint);
  const checkpoint = workspaceCheckpointRestoreTarget(rawCheckpoint);
  await verifyGitCommitExists(checkpoint);

  const stagedFiles = await listStagedFiles(checkpoint.gitRootRealPath, checkpoint.repoRelativeScope);
  if (stagedFiles.length > 0 && !options.allowStagedChanges) {
    throw new Error(
      `cannot restore workspace checkpoint with staged changes in scope: ${stagedFiles.join(', ')}`
    );
  }

  await runGit(checkpoint.gitRootRealPath, [
    'restore',
    '--source',
    checkpoint.commitId,
    '--worktree',
    '--',
    checkpoint.repoRelativeScope
  ]);
  await removeNewUntrackedFiles(
    checkpoint.gitRootRealPath,
    checkpoint.repoRelativeScope,
    checkpoint.preexistingUntrackedFiles
  );
}
