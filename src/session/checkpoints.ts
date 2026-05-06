import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { makeId, mutateSession, nowIso, resolveCliqHome } from './store.js';
import type { Session, SessionCheckpoint, WorkspaceCheckpoint } from './types.js';

const execFileAsync = promisify(execFile);
const GHOST_COMMIT_MESSAGE = 'cliq checkpoint snapshot';
const SAFE_WORKSPACE_CHECKPOINT_ID = /^[A-Za-z0-9_-]+$/;
const GIT_OBJECT_ID = /^[0-9a-f]{40,64}$/i;

export type CreateCheckpointOptions = {
  kind?: SessionCheckpoint['kind'];
  name?: string;
};

export type RestoreWorkspaceCheckpointOptions = {
  allowStagedChanges?: boolean;
};

export type CreatedSessionCheckpoint = SessionCheckpoint & {
  workspaceCheckpoint: WorkspaceCheckpoint;
};

export function workspaceCheckpointFilePath(workspaceCheckpointId: string, cliqHome = resolveCliqHome()) {
  if (!SAFE_WORKSPACE_CHECKPOINT_ID.test(workspaceCheckpointId)) {
    throw new Error(`invalid workspace checkpoint id: ${workspaceCheckpointId}`);
  }
  return path.join(cliqHome, 'checkpoints', `${workspaceCheckpointId}.json`);
}

async function writeWorkspaceCheckpoint(checkpoint: WorkspaceCheckpoint) {
  const target = workspaceCheckpointFilePath(checkpoint.id);
  await atomicWriteJson(target, checkpoint);
}

async function atomicWriteJson(target: string, value: unknown) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temp, JSON.stringify(value, null, 2));
    await fs.rename(temp, target);
  } catch (error) {
    await fs.rm(temp, { force: true });
    throw error;
  }
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
    env: gitEnv(env)
  });
  return stdout.trim();
}

async function runGitRaw(cwd: string, args: string[], env: Record<string, string> = {}) {
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    env: gitEnv(env)
  });
  return stdout;
}

function gitEnv(overrides: Record<string, string>) {
  const allowed = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'TMP', 'TEMP', 'USERPROFILE', 'SystemRoot', 'COMSPEC', 'PATHEXT'];
  const env: Record<string, string> = {};
  for (const name of allowed) {
    const value = process.env[name];
    if (value !== undefined) {
      env[name] = value;
    }
  }
  return { ...env, ...overrides };
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

export async function createWorkspaceCheckpoint(cwd: string): Promise<WorkspaceCheckpoint> {
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
): Promise<CreatedSessionCheckpoint> {
  const workspaceCheckpoint = await createWorkspaceCheckpoint(cwd);
  await writeWorkspaceCheckpoint(workspaceCheckpoint);

  const checkpointBase = {
    id: makeId('chk'),
    name: options.name,
    kind: options.kind ?? 'manual',
    createdAt: nowIso(),
    workspaceCheckpointId: workspaceCheckpoint.id
  };
  let checkpoint: SessionCheckpoint | undefined;

  await mutateSession(cwd, session, (current) => {
    checkpoint = {
      ...checkpointBase,
      recordIndex: current.records.length,
      turn: current.lifecycle.turn
    };
    current.checkpoints ??= [];
    current.checkpoints.push(checkpoint);
  });

  if (!checkpoint) {
    throw new Error('checkpoint creation failed before session metadata was recorded');
  }
  return { ...checkpoint, workspaceCheckpoint };
}

async function readWorkspaceCheckpoint(workspaceCheckpointId: string): Promise<WorkspaceCheckpoint> {
  const target = workspaceCheckpointFilePath(workspaceCheckpointId);
  let raw: unknown;
  try {
    raw = JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
  } catch (error) {
    throw new Error(
      `invalid workspace checkpoint ${workspaceCheckpointId}: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
  return validateWorkspaceCheckpoint(raw, workspaceCheckpointId);
}

export async function getWorkspaceCheckpoint(workspaceCheckpointId: string): Promise<WorkspaceCheckpoint> {
  return await readWorkspaceCheckpoint(workspaceCheckpointId);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isSafeAbsolutePath(value: string) {
  return path.isAbsolute(value) && path.resolve(value) === value && !value.includes('\0');
}

function isSubPathOrSame(parent: string, child: string) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function isSafeRepoRelativePath(value: string, allowDot = false) {
  if (value.includes('\0') || path.posix.isAbsolute(value)) {
    return false;
  }

  if (value === '.') {
    return allowDot;
  }

  if (!value || value.startsWith('../') || value === '..') {
    return false;
  }

  return !value.split('/').includes('..');
}

function resolveRepoRelativeScope(gitRootRealPath: string, repoRelativeScope: string) {
  if (repoRelativeScope === '.') {
    return gitRootRealPath;
  }
  return path.resolve(gitRootRealPath, ...repoRelativeScope.split('/'));
}

function invalidWorkspaceCheckpoint(id: string, reason: string): never {
  throw new Error(`invalid workspace checkpoint ${id}: ${reason}`);
}

function validateWorkspaceCheckpoint(raw: unknown, expectedId: string): WorkspaceCheckpoint {
  if (!raw || typeof raw !== 'object') {
    invalidWorkspaceCheckpoint(expectedId, 'expected object');
  }

  const checkpoint = raw as Record<string, unknown>;
  if (checkpoint.id !== expectedId) {
    invalidWorkspaceCheckpoint(expectedId, 'id mismatch');
  }
  if (typeof checkpoint.createdAt !== 'string') {
    invalidWorkspaceCheckpoint(expectedId, 'createdAt must be a string');
  }
  if (typeof checkpoint.workspaceRealPath !== 'string' || !isSafeAbsolutePath(checkpoint.workspaceRealPath)) {
    invalidWorkspaceCheckpoint(expectedId, 'workspaceRealPath must be a normalized absolute path');
  }

  if (checkpoint.kind === 'unavailable') {
    if (checkpoint.status !== 'unavailable') {
      invalidWorkspaceCheckpoint(expectedId, 'unavailable checkpoint status must be unavailable');
    }
    if (checkpoint.reason !== 'not-git' && checkpoint.reason !== 'snapshot-failed') {
      invalidWorkspaceCheckpoint(expectedId, 'unavailable checkpoint reason is invalid');
    }
    if (checkpoint.error !== undefined && typeof checkpoint.error !== 'string') {
      invalidWorkspaceCheckpoint(expectedId, 'unavailable checkpoint error must be a string');
    }
    return checkpoint as WorkspaceCheckpoint;
  }

  if (checkpoint.kind !== 'git-ghost') {
    invalidWorkspaceCheckpoint(expectedId, 'kind is invalid');
  }
  if (checkpoint.status !== 'available' && checkpoint.status !== 'expired') {
    invalidWorkspaceCheckpoint(expectedId, 'git checkpoint status is invalid');
  }
  if (typeof checkpoint.gitRootRealPath !== 'string' || !isSafeAbsolutePath(checkpoint.gitRootRealPath)) {
    invalidWorkspaceCheckpoint(expectedId, 'gitRootRealPath must be a normalized absolute path');
  }
  if (!isSubPathOrSame(checkpoint.gitRootRealPath, checkpoint.workspaceRealPath)) {
    invalidWorkspaceCheckpoint(expectedId, 'workspaceRealPath must stay inside gitRootRealPath');
  }
  if (typeof checkpoint.repoRelativeScope !== 'string' || !isSafeRepoRelativePath(checkpoint.repoRelativeScope, true)) {
    invalidWorkspaceCheckpoint(expectedId, 'repoRelativeScope must be a safe repository-relative path');
  }
  const scopeRealPath = resolveRepoRelativeScope(checkpoint.gitRootRealPath, checkpoint.repoRelativeScope);
  if (!isSubPathOrSame(checkpoint.gitRootRealPath, scopeRealPath)) {
    invalidWorkspaceCheckpoint(expectedId, 'repoRelativeScope must resolve inside gitRootRealPath');
  }
  if (!isSubPathOrSame(checkpoint.workspaceRealPath, scopeRealPath)) {
    invalidWorkspaceCheckpoint(expectedId, 'repoRelativeScope must resolve inside workspaceRealPath');
  }
  if (typeof checkpoint.commitId !== 'string' || !GIT_OBJECT_ID.test(checkpoint.commitId)) {
    invalidWorkspaceCheckpoint(expectedId, 'commitId is invalid');
  }
  if (checkpoint.parentCommitId !== undefined) {
    if (typeof checkpoint.parentCommitId !== 'string' || !GIT_OBJECT_ID.test(checkpoint.parentCommitId)) {
      invalidWorkspaceCheckpoint(expectedId, 'parentCommitId is invalid');
    }
  }
  if (!isStringArray(checkpoint.preexistingUntrackedFiles)) {
    invalidWorkspaceCheckpoint(expectedId, 'preexistingUntrackedFiles must be an array of strings');
  }
  for (const file of checkpoint.preexistingUntrackedFiles) {
    if (!isSafeRepoRelativePath(file)) {
      invalidWorkspaceCheckpoint(expectedId, `unsafe preexisting untracked file path: ${file}`);
    }
  }
  if (!isStringArray(checkpoint.warnings)) {
    invalidWorkspaceCheckpoint(expectedId, 'warnings must be an array of strings');
  }

  return checkpoint as WorkspaceCheckpoint;
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

async function resolveRestorableWorkspaceCheckpoint(
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

  return checkpoint;
}

export async function assertWorkspaceCheckpointRestorable(
  cwd: string,
  workspaceCheckpointId: string,
  options: RestoreWorkspaceCheckpointOptions = {}
) {
  await resolveRestorableWorkspaceCheckpoint(cwd, workspaceCheckpointId, options);
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
  const checkpoint = await resolveRestorableWorkspaceCheckpoint(cwd, workspaceCheckpointId, options);

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
