import { canonicalJsonBytes } from './canonical.js';
import { sha256Bytes } from './identity.js';
import type { ArtifactRef } from './types.js';

export type PlannedArtifact = Readonly<{
  ref: ArtifactRef;
  mediaType: 'application/json' | 'application/octet-stream';
  schemaKind: string;
  bytes: Uint8Array;
}>;

export function planArtifactBytes(
  source: Uint8Array,
  mediaType: PlannedArtifact['mediaType'],
  schemaKind: string
): PlannedArtifact {
  const snapshot = Uint8Array.from(source);
  const ref = sha256Bytes(snapshot);
  return Object.freeze({
    ref,
    mediaType,
    schemaKind,
    get bytes(): Uint8Array {
      return snapshot.slice();
    }
  });
}

export function planCanonicalArtifact(value: unknown, schemaKind: string): PlannedArtifact {
  return planArtifactBytes(canonicalJsonBytes(value), 'application/json', schemaKind);
}
