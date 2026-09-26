import { createHash } from 'node:crypto';

import type { RepositoryIdentityV1 } from '../kernel/types.js';
import { decodeRepositoryIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { MAX_GIT_INDEX_BYTES, parseSourceGitIndex, type ParsedSourceGitIndex } from './git-index.js';
import type { DescriptorIdentity, HeldStateOwnerLock, LiveWorkspaceInspection } from './native-owner.js';

const READ_CHUNK_BYTES = 1024 * 1024;

export type HeldSourceGitIndex = Readonly<Omit<ParsedSourceGitIndex, 'sourceVersion'> & {
  sourceVersion: ParsedSourceGitIndex['sourceVersion'] | 'absent';
}>;

function sameIdentity(left: DescriptorIdentity, right: DescriptorIdentity): boolean {
  return left.deviceId === right.deviceId && left.fileId === right.fileId && left.ownerUid === right.ownerUid;
}

function assertMatchingWorkspace(
  observed: LiveWorkspaceInspection,
  root: DescriptorIdentity,
  git: DescriptorIdentity
): void {
  if (!sameIdentity(observed.root, root) || !observed.git ||
      !sameIdentity(observed.git.identity, git)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace or Git directory changed during index capture');
  }
}

function assertMatchingConfig(before: LiveWorkspaceInspection, after: LiveWorkspaceInspection): void {
  const beforeConfig = before.git?.configBytes;
  const afterConfig = after.git?.configBytes;
  if ((beforeConfig === undefined) !== (afterConfig === undefined) ||
      (beforeConfig !== undefined && !beforeConfig.equals(afterConfig!))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Git config changed during index capture');
  }
}

function emptyIndex(objectFormat: 'sha1' | 'sha256'): Buffer {
  const header = Buffer.alloc(12);
  header.write('DIRC', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  return Buffer.concat([header, createHash(objectFormat).update(header).digest()]);
}

/** Capture one existing or exactly absent index from the held workspace.
 * The caller must still close the source/object graph and revalidate it at
 * its admission commit. */
export function readHeldSourceGitIndex(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  expectedRoot: DescriptorIdentity,
  expectedRepository: RepositoryIdentityV1
): HeldSourceGitIndex {
  const repository = decodeRepositoryIdentity(expectedRepository);
  const before = filesystem.inspectWorkspaceIdentity(workspacePath);
  assertMatchingWorkspace(before, expectedRoot, repository.gitDirectoryIdentity);
  const source = filesystem.openWorkspaceGitIndex(workspacePath, expectedRoot,
    repository.gitDirectoryIdentity);
  if (source === null) {
    const parsed = parseSourceGitIndex(emptyIndex(repository.objectFormat),
      repository.repositoryIdentityDigest, repository.objectFormat);
    const after = filesystem.inspectWorkspaceIdentity(workspacePath);
    assertMatchingWorkspace(after, expectedRoot, repository.gitDirectoryIdentity);
    assertMatchingConfig(before, after);
    const second = filesystem.openWorkspaceGitIndex(workspacePath, expectedRoot,
      repository.gitDirectoryIdentity);
    if (second !== null) {
      second.close();
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'Git index appeared during empty-index capture');
    }
    return { ...parsed, sourceVersion: 'absent' };
  }
  try {
    if (!Number.isSafeInteger(source.size) || source.size < 12 ||
        source.size > MAX_GIT_INDEX_BYTES) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'source Git index exceeds the byte ceiling or is truncated');
    }
    const bytes = Buffer.alloc(source.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const requested = Math.min(READ_CHUNK_BYTES, bytes.byteLength - offset);
      const chunk = source.readChunk(requested);
      if (!Buffer.isBuffer(chunk) || chunk.byteLength === 0 || chunk.byteLength > requested) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'source Git index stream ended unexpectedly');
      }
      chunk.copy(bytes, offset);
      offset += chunk.byteLength;
    }
    source.assertStable();
    const parsed = parseSourceGitIndex(bytes, repository.repositoryIdentityDigest, repository.objectFormat);
    const after = filesystem.inspectWorkspaceIdentity(workspacePath);
    assertMatchingWorkspace(after, expectedRoot, repository.gitDirectoryIdentity);
    assertMatchingConfig(before, after);
    source.assertStable();
    return parsed;
  } finally {
    source.close();
  }
}
