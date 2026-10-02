import type { ArtifactRef } from './types.js';

/** RFC-owned declarative context; independent from source and tool authority. */
export type WorkspaceInstructionSourceManifestV1 = {
  schemaVersion: 1;
  format: 'cliq-workspace-instruction-source-v1';
  workspaceIdentityRef: ArtifactRef;
  workspaceIdentityDigest: string;
  entries: Array<{
    canonicalRootRelativePath: string;
    directoryDepth: number;
    fileDescriptor: {
      deviceId: string; fileId: string; ownerUid: number; mode: 384 | 420; linkCount: 1;
    };
    rawBytesRef: ArtifactRef;
    rawBytesDigest: string;
    rawByteCount: number;
    sourceEntryDigest: string;
  }>;
  capturedAt: string;
  sourceDigest: string;
};

export type WorkspaceInstructionManifestV1 = {
  schemaVersion: 1;
  format: 'cliq-workspace-instructions-v1';
  workspaceIdentityDigest: string;
  instructionSourceRef: ArtifactRef;
  instructionSourceDigest: string;
  rendering: 'cliq-all-scopes-labeled-instructions-v1';
  entries: Array<{
    order: number;
    canonicalRootRelativePath: string;
    appliesToSubtree: true;
    directoryDepth: number;
    instructionSourceEntryDigest: string;
    contentRef: ArtifactRef;
    contentDigest: string;
  }>;
  manifestDigest: string;
};
