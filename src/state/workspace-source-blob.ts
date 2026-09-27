import { createHash } from 'node:crypto';

import type { HeldCasRoot } from '../runtime-bundle/native-package-reader.js';
import { publishVerifiedChunkStreamToCas } from '../runtime-bundle/native-package-reader.js';
import type { PublishedArtifact } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import type { HeldWorkspaceSourceFile } from './native-owner.js';

const CHUNK_BYTES = 1024 * 1024;

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
