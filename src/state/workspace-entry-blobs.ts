import type { WorkspaceEntryManifest } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { mapArtifactReads } from './bounded-artifact-reads.js';
import { KernelStorageError } from './errors.js';

/** Check every distinct file's complete CAS bytes against the declared source size. */
export async function validateWorkspaceEntryBlobs(
  artifacts: ArtifactCatalog,
  manifest: WorkspaceEntryManifest
): Promise<void> {
  const files = new Map<string, { size: number; path: string }>();
  for (const entry of manifest.entries) {
    if (entry.kind !== 'file') continue;
    const previous = files.get(entry.blobRef);
    if (previous !== undefined && previous.size !== entry.size) {
      throw new KernelStorageError(
        'ARTIFACT_MISMATCH',
        `workspace files ${previous.path} and ${entry.path} declare different sizes for one blob`
      );
    }
    if (previous === undefined) files.set(entry.blobRef, { size: entry.size, path: entry.path });
  }
  await mapArtifactReads([...files], async ([ref, file]) => {
    let bytes: Buffer;
    try {
      bytes = await artifacts.readBytes(ref);
    } catch (error) {
      throw new KernelStorageError(
        'ARTIFACT_MISMATCH',
        `workspace file ${file.path} is not readable from CAS: ${(error as Error).message}`
      );
    }
    if (bytes.byteLength !== file.size) {
      throw new KernelStorageError(
        'ARTIFACT_MISMATCH',
        `workspace file ${file.path} size does not match its complete CAS bytes`
      );
    }
  });
}
