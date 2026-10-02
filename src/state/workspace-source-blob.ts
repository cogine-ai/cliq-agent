import { createHash } from 'node:crypto';

import type { WorkspaceEntry } from '../kernel/types.js';
import type { HeldCasRoot } from '../runtime-bundle/native-package-reader.js';
import { publishVerifiedChunkStreamToCas } from '../runtime-bundle/native-package-reader.js';
import type { PublishedArtifact } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import type {
  DescriptorIdentity, HeldStateOwnerLock, HeldWorkspaceSourceFile, WorkspaceSourceDirectoryEntry
} from './native-owner.js';

const CHUNK_BYTES = 1024 * 1024;
const SOURCE_CHANGE_TOKEN = /^-?(?:0|[1-9][0-9]{0,18}):[0-9]{9}:-?(?:0|[1-9][0-9]{0,18}):[0-9]{9}$/;

function streamCompletePass(file: HeldWorkspaceSourceFile, consume: (chunk: Buffer) => void): string {
  const hash = createHash('sha256');
  let remaining = file.size;
  while (remaining > 0) {
    const requested = Math.min(CHUNK_BYTES, remaining);
    const chunk = file.readChunk(requested);
    if (!Buffer.isBuffer(chunk) || chunk.byteLength === 0 || chunk.byteLength > requested) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'held source file ended before its declared size');
    }
    hash.update(chunk);
    consume(chunk);
    remaining -= chunk.byteLength;
  }
  if (file.readChunk(1).byteLength !== 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'held source file has trailing bytes');
  }
  file.assertStable();
  return hash.digest('hex');
}

/** Publish source bytes through two complete passes of one no-follow, held
 * StateOwner descriptor. The returned metadata has no Run authority until
 * its source graph and artifact row commit together at admission. */
export async function publishHeldWorkspaceSourceBlob(file: HeldWorkspaceSourceFile,
  cas: HeldCasRoot): Promise<PublishedArtifact> {
  if (!Number.isSafeInteger(file.size) || file.size < 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'held source file has invalid size');
  }
  const ref = streamCompletePass(file, () => {});
  file.rewind();
  await publishVerifiedChunkStreamToCas(cas, { digest: ref, byteCount: file.size },
    (writeChunk) => {
      if (streamCompletePass(file, writeChunk) !== ref) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'held source file changed between complete passes');
      }
    },
    () => { file.assertStable(); });
  file.assertStable();
  return { ref, byteLength: file.size, mediaType: 'application/octet-stream',
    schemaKind: 'cliq-workspace-file-v1' };
}

export type CapturedWorkspaceSourceFile = Readonly<{
  entry: Extract<WorkspaceEntry, { kind: 'file' }>;
  artifact: PublishedArtifact;
  identity: DescriptorIdentity;
  linkCount: number;
}>;

export function sameSourceIdentity(left: DescriptorIdentity, right: DescriptorIdentity): boolean {
  return left.deviceId === right.deviceId && left.fileId === right.fileId &&
    left.ownerUid === right.ownerUid;
}

function listedFile(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  root: DescriptorIdentity,
  relativePath: string
): WorkspaceSourceDirectoryEntry {
  const separator = relativePath.lastIndexOf('/');
  const parent = separator === -1 ? '' : relativePath.slice(0, separator);
  const name = relativePath.slice(separator + 1);
  const matches = filesystem.listWorkspaceSourceDirectory(workspacePath, root, parent)
    .filter((item) => item.name === name);
  if (matches.length !== 1 || matches[0]?.kind !== 'file' ||
      !Number.isSafeInteger(matches[0].size) || matches[0].size! < 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      `workspace source file ${relativePath} is absent, ambiguous or not regular`);
  }
  return matches[0];
}

export function assertSameSourceObservation(
  observed: Pick<WorkspaceSourceDirectoryEntry, 'mode' | 'size' | 'linkCount' | 'changeToken' | 'identity'>,
  expected: WorkspaceSourceDirectoryEntry,
  relativePath: string
): void {
  if (typeof observed.changeToken !== 'string' || typeof expected.changeToken !== 'string' ||
      !SOURCE_CHANGE_TOKEN.test(observed.changeToken) || !SOURCE_CHANGE_TOKEN.test(expected.changeToken)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      `workspace source entry ${relativePath} has no valid native change observation`);
  }
  if (observed.mode !== expected.mode ||
      observed.size !== expected.size || observed.linkCount !== expected.linkCount ||
      observed.changeToken !== expected.changeToken ||
      !sameSourceIdentity(observed.identity, expected.identity)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      `workspace source file ${relativePath} changed during capture`);
  }
}

/** Bind a CAS blob to the literal directory entry that will appear in the
 * captured tree. The caller must repeat a live tree check inside Run admission;
 * CAS publication by itself does not authorize or commit a source path. */
export async function captureHeldWorkspaceSourceFile(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  root: DescriptorIdentity,
  relativePath: string,
  cas: HeldCasRoot
): Promise<CapturedWorkspaceSourceFile> {
  const before = listedFile(filesystem, workspacePath, root, relativePath);
  const captured = await captureObservedWorkspaceSourceFile(filesystem, workspacePath,
    root, relativePath, before, cas);
  const after = listedFile(filesystem, workspacePath, root, relativePath);
  assertSameSourceObservation(after, before, relativePath);
  return captured;
}

/** Tree capture already enumerated the parent. Avoid rescanning a wide
 * directory twice per file; the tree producer rechecks its complete inventory. */
export async function captureObservedWorkspaceSourceFile(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  root: DescriptorIdentity,
  relativePath: string,
  before: WorkspaceSourceDirectoryEntry,
  cas: HeldCasRoot
): Promise<CapturedWorkspaceSourceFile> {
  if (before.kind !== 'file') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source observation is not a regular file');
  }
  const file = filesystem.openWorkspaceSourceFile(workspacePath, root, relativePath);
  try {
    try { assertSameSourceObservation(file, before, relativePath); } catch {
      throw new KernelStorageError('ARTIFACT_MISMATCH',
        `workspace source file ${relativePath} changed before its held read`);
    }
    const artifact = await publishHeldWorkspaceSourceBlob(file, cas);
    file.assertStable();
    return {
      entry: { path: relativePath, kind: 'file', mode: file.mode & 0o111 ? 0o755 : 0o644,
        size: file.size, blobRef: artifact.ref },
      artifact, identity: file.identity, linkCount: file.linkCount
    };
  } catch (error) {
    if (error instanceof KernelStorageError) throw error;
    try { filesystem.assertHeld(); } catch {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner changed during source capture', { cause: error });
    }
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      `workspace source file ${relativePath} capture failed: ${(error as Error).message}`, { cause: error });
  } finally {
    file.close();
  }
}

/** Synchronous, complete content rehash for the final admission transaction. */
export function assertLiveWorkspaceSourceFile(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  root: DescriptorIdentity,
  entry: Extract<WorkspaceEntry, { kind: 'file' }>,
  observation: WorkspaceSourceDirectoryEntry
): void {
  const file = filesystem.openWorkspaceSourceFile(workspacePath, root, entry.path);
  try {
    assertSameSourceObservation(file, observation, entry.path);
    if (streamCompletePass(file, () => {}) !== entry.blobRef) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace source file ${entry.path} bytes changed`);
    }
    file.assertStable();
  } catch (error) {
    if (error instanceof KernelStorageError) throw error;
    try { filesystem.assertHeld(); } catch {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner changed during source validation', { cause: error });
    }
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      `workspace source file ${entry.path} validation failed: ${(error as Error).message}`, { cause: error });
  } finally { file.close(); }
}
