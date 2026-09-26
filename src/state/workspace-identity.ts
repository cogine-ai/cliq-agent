import { constants, type BigIntStats } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { digestOmitting, normalizeAbsolutePath, unsignedDecimalId } from '../kernel/identity.js';
import type { RepositoryIdentityV1, WorkspaceIdentityV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

export type HostPlatform = 'macos' | 'linux';

export function hostPlatform(): HostPlatform {
  if (process.platform === 'darwin') return 'macos';
  if (process.platform === 'linux') return 'linux';
  throw new KernelStorageError('UNSUPPORTED_PLATFORM', `workspace identity is unsupported on ${process.platform}`);
}

function requireEffectiveUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'workspace identity requires a POSIX effective uid');
  }
  return process.geteuid();
}

function sameInode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function directoryIdentity(stats: BigIntStats): { deviceId: string; fileId: string; ownerUid: number } {
  const ownerUid = Number(stats.uid);
  if (!Number.isSafeInteger(ownerUid)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace owner uid exceeds the supported range');
  }
  return {
    deviceId: unsignedDecimalId(stats.dev),
    fileId: unsignedDecimalId(stats.ino),
    ownerUid
  };
}

async function openDirectoryNoFollow(absolutePath: string): Promise<{ handle: FileHandle; stats: BigIntStats }> {
  const pathInfo = await lstat(absolutePath, { bigint: true });
  if (pathInfo.isSymbolicLink()) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', `path component is a symlink: ${absolutePath}`);
  }
  if (!pathInfo.isDirectory()) {
    throw new KernelStorageError('INVALID_REQUEST', `path is not a directory: ${absolutePath}`);
  }
  const handle = await open(absolutePath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const handleInfo = await handle.stat({ bigint: true });
    if (!handleInfo.isDirectory() || !sameInode(pathInfo, handleInfo)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `directory changed while it was opened: ${absolutePath}`);
    }
    return { handle, stats: handleInfo };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function walkNoFollowDirectory(absolutePath: string): Promise<{ handle: FileHandle; stats: BigIntStats }> {
  const normalized = normalizeAbsolutePath(absolutePath);
  const parts = normalized.split('/').filter((part) => part.length > 0);
  let current = '/';
  let opened = await openDirectoryNoFollow(current);
  let transferred = false;
  try {
    for (const part of parts) {
      const next = path.posix.join(current, part);
      const nextOpened = await openDirectoryNoFollow(next);
      const previous = opened;
      opened = nextOpened;
      current = next;
      await previous.handle.close();
    }
    transferred = true;
    return opened;
  } finally {
    if (!transferred) {
      await opened.handle.close().catch(() => undefined);
    }
  }
}

function parseGitObjectFormat(configUtf8: string): 'sha1' | 'sha256' {
  const match = /^\s*objectFormat\s*=\s*(sha1|sha256)\s*$/im.exec(configUtf8);
  return match === null ? 'sha1' : match[1] === 'sha256' ? 'sha256' : 'sha1';
}

async function captureRepositoryIdentity(
  workspacePath: string,
  rootStats: BigIntStats,
  platform: HostPlatform
): Promise<RepositoryIdentityV1 | undefined> {
  const gitPath = path.join(workspacePath, '.git');
  let gitInfo: BigIntStats;
  try {
    gitInfo = await lstat(gitPath, { bigint: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  if (gitInfo.isSymbolicLink() || gitInfo.isFile()) {
    throw new KernelStorageError('INVALID_REQUEST', 'workspace .git must be an in-root directory, not a file or symlink');
  }
  if (!gitInfo.isDirectory()) {
    throw new KernelStorageError('INVALID_REQUEST', 'workspace .git must be a directory');
  }
  if (gitInfo.uid !== rootStats.uid) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace .git owner does not match the workspace root');
  }

  const handle = await open(gitPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const handleInfo = await handle.stat({ bigint: true });
    if (!sameInode(gitInfo, handleInfo)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace .git changed while it was opened');
    }
    let objectFormat: 'sha1' | 'sha256' = 'sha1';
    try {
      const configHandle = await open(path.join(gitPath, 'config'), constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        objectFormat = parseGitObjectFormat(await configHandle.readFile('utf8'));
      } finally {
        await configHandle.close();
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        // default objectFormat
      } else if (code === 'ELOOP') {
        throw new KernelStorageError('INVALID_REQUEST', 'workspace .git/config must not be a symlink');
      } else {
        throw error;
      }
    }
    const identity: RepositoryIdentityV1 = {
      schemaVersion: 1,
      format: 'cliq-repository-identity-v1',
      platform,
      gitDirectoryRelativePath: '.git',
      gitDirectoryIdentity: directoryIdentity(handleInfo),
      objectFormat,
      repositoryIdentityDigest: ''
    };
    identity.repositoryIdentityDigest = digestOmitting(identity, 'repositoryIdentityDigest');
    return identity;
  } finally {
    await handle.close();
  }
}

export async function captureLiveWorkspaceIdentity(options: {
  workspacePath: string;
  ownerPrincipalId: string;
}): Promise<{
  identity: Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  repository?: RepositoryIdentityV1;
}> {
  const workspacePath = normalizeAbsolutePath(options.workspacePath);
  const platform = hostPlatform();
  const effectiveUid = requireEffectiveUid();
  const opened = await walkNoFollowDirectory(workspacePath);
  try {
    if (opened.stats.uid !== BigInt(effectiveUid)) {
      throw new KernelStorageError(
        'INVALID_REQUEST',
        'workspace root must be owned by the effective uid of the local principal'
      );
    }
    const repository = await captureRepositoryIdentity(workspacePath, opened.stats, platform);
    const identity: Extract<WorkspaceIdentityV1, { kind: 'live' }> = {
      schemaVersion: 1,
      format: 'cliq-workspace-identity-v1',
      ownerPrincipalId: options.ownerPrincipalId,
      platform,
      kind: 'live',
      canonicalRootPath: workspacePath,
      rootIdentity: directoryIdentity(opened.stats),
      identityDigest: ''
    };
    if (repository !== undefined) {
      identity.repositoryIdentityDigest = repository.repositoryIdentityDigest;
    }
    identity.identityDigest = digestOmitting(identity, 'identityDigest');
    return { identity, repository };
  } finally {
    await opened.handle.close();
  }
}

export async function recaptureLiveWorkspaceIdentity(
  expected: Extract<WorkspaceIdentityV1, { kind: 'live' }>,
  workspacePath: string
): Promise<Extract<WorkspaceIdentityV1, { kind: 'live' }>> {
  const captured = await captureLiveWorkspaceIdentity({
    workspacePath,
    ownerPrincipalId: expected.ownerPrincipalId
  });
  if (captured.identity.canonicalRootPath !== expected.canonicalRootPath) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace path does not match the live Session identity');
  }
  if (
    captured.identity.rootIdentity.deviceId !== expected.rootIdentity.deviceId ||
    captured.identity.rootIdentity.fileId !== expected.rootIdentity.fileId ||
    captured.identity.rootIdentity.ownerUid !== expected.rootIdentity.ownerUid
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace root identity changed; create a new Session');
  }
  if ((captured.identity.repositoryIdentityDigest ?? null) !== (expected.repositoryIdentityDigest ?? null)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace repository identity changed; create a new Session');
  }
  return captured.identity;
}
