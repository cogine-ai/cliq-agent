import { canonicalSha256 } from '../kernel/canonical.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { digestOmitting } from '../kernel/identity.js';
import type { GitIndexSnapshotV1, GitObjectClosureV1, GitObjectPackV1, PrivateGitStateManifest } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactCatalog, PublishedArtifact } from '../state/artifacts.js';
import { joinResourceOperations, KernelStorageError } from '../state/errors.js';
import { decodeSourceGitInspectionOutput } from './source-git-output.js';

type Streams = Readonly<Record<'inspection' | 'index' | 'pack' | 'packIndex', AsyncIterable<Uint8Array>>>;
type Expected = Readonly<{ repositoryIdentityDigest: string; resources: SandboxResourceSpec }>;
function invalid(): never { throw new KernelStorageError('ARTIFACT_MISMATCH', 'fixed source Git output bytes differ from their declared identity'); }

async function metadataBytes(stream: AsyncIterable<Uint8Array>, ceiling: number, signal?: AbortSignal): Promise<Buffer> {
  const chunks: Buffer[] = []; let total = 0;
  for await (const value of stream) {
    signal?.throwIfAborted();
    if (!(value instanceof Uint8Array) || value.byteLength > ceiling - total) return invalid();
    const bytes = Buffer.from(value); total += bytes.length; chunks.push(bytes);
  }
  signal?.throwIfAborted(); return Buffer.concat(chunks, total);
}
async function publishFile(artifacts: ArtifactCatalog, stream: AsyncIterable<Uint8Array>,
  expected: { sha256: string; byteCount: number }, kind: string, signal?: AbortSignal): Promise<PublishedArtifact> {
  let total = 0;
  const checked = async function* () {
    for await (const bytes of stream) {
      signal?.throwIfAborted();
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > expected.byteCount - total) return invalid();
      total += bytes.byteLength; yield bytes;
    }
    signal?.throwIfAborted(); if (total !== expected.byteCount) return invalid();
  };
  const published = await artifacts.publishChunks(checked(), 'application/octet-stream', kind, expected.byteCount);
  signal?.throwIfAborted();
  if (published.ref !== expected.sha256 || published.byteLength !== expected.byteCount) return invalid();
  return published;
}

/** Complete fixed-output data publication only. The owning source task must
 * first authenticate its genuine native result, and must join/close every
 * native reader before scope retirement. This function mints neither that
 * result nor a native/Run/authorization/generation capability; in particular
 * matching hashes alone do not prove trusted index-pack or reachability. */
export async function publishSourceGitArtifacts(artifacts: ArtifactCatalog, streams: Streams, expected: Expected,
  signal?: AbortSignal) {
  signal?.throwIfAborted();
  const bytes = await metadataBytes(streams.inspection,
    Math.min(expected.resources.maxInvocationOutputBytes, expected.resources.maxSingleFileBytes), signal);
  const output = decodeSourceGitInspectionOutput(bytes, expected);
  // Three independent byte streams. A failure is not returned until every
  // issued stream/CAS operation joins, with original retirement precedence.
  const [indexBytes, packBytes, packIndexBytes] = await joinResourceOperations([
    publishFile(artifacts, streams.index, { sha256: output.index.sha256, byteCount: output.index.byteCount },
      'cliq-git-index-bytes-v1', signal),
    publishFile(artifacts, streams.pack, { sha256: output.pack.sha256, byteCount: output.pack.byteCount },
      'cliq-git-pack-bytes-v1', signal),
    publishFile(artifacts, streams.packIndex, { sha256: output.pack.indexSha256, byteCount: output.pack.indexByteCount },
      'cliq-git-pack-index-bytes-v1', signal)
  ]);
  signal?.throwIfAborted();
  const index: GitIndexSnapshotV1 = { schemaVersion: 1, format: 'cliq-git-index-snapshot-v1',
    repositoryIdentityDigest: output.repositoryIdentityDigest, objectFormat: output.objectFormat,
    canonicalIndexVersion: 2, entries: output.index.entries, canonicalIndexBytesRef: indexBytes.ref,
    canonicalIndexBytesDigest: indexBytes.ref, canonicalIndexByteCount: indexBytes.byteLength,
    indexTreeObjectId: output.index.indexTreeObjectId, snapshotDigest: '' };
  index.snapshotDigest = digestOmitting(index, 'snapshotDigest');
  const pack: GitObjectPackV1 = { schemaVersion: 1, format: 'cliq-git-object-pack-v1', objectFormat: output.objectFormat,
    packBytesRef: packBytes.ref, packBytesDigest: packBytes.ref, packByteCount: packBytes.byteLength,
    packTrailerObjectHash: output.pack.trailerObjectHash, packIndexBytesRef: packIndexBytes.ref,
    packIndexBytesDigest: packIndexBytes.ref, packIndexByteCount: packIndexBytes.byteLength,
    packIndexVersion: 2, objectCount: output.pack.objectIds.length, objectIds: output.pack.objectIds, packDigest: '' };
  pack.packDigest = digestOmitting(pack, 'packDigest');
  const [indexArtifact, packArtifact, configArtifact] = await artifacts.publishCanonicalTriple([
    { value: index, schemaKind: index.format }, { value: pack, schemaKind: pack.format },
    { value: output.sanitizedConfig, schemaKind: output.sanitizedConfig.format }
  ]);
  signal?.throwIfAborted();
  const closure: GitObjectClosureV1 = { schemaVersion: 1, format: 'cliq-git-object-closure-v1',
    repositoryIdentityDigest: output.repositoryIdentityDigest, objectFormat: output.objectFormat,
    packs: [{ packRef: packArtifact.ref, packDigest: pack.packDigest, packTrailerObjectHash: pack.packTrailerObjectHash }],
    reachableObjectIds: output.pack.objectIds, closureDigest: '' };
  closure.closureDigest = digestOmitting(closure, 'closureDigest');
  const closureArtifact = await artifacts.publishCanonical(closure, closure.format);
  signal?.throwIfAborted();
  const manifest: PrivateGitStateManifest = { schemaVersion: 1, format: 'cliq-private-git-v1', head: output.head,
    indexRef: indexArtifact.ref, refs: output.refs, objectClosureRef: closureArtifact.ref, objectClosureDigest: closure.closureDigest,
    sanitizedConfigRef: configArtifact.ref, sanitizedConfigDigest: output.sanitizedConfig.configDigest, manifestDigest: '' };
  manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
  const [manifestArtifact, inspectionArtifact] = await artifacts.publishCanonicalPair([
    { value: manifest, schemaKind: manifest.format }, { value: output, schemaKind: output.format }
  ]);
  signal?.throwIfAborted();
  if (inspectionArtifact.ref !== canonicalSha256(output)) return invalid();
  return immutableSnapshot({ privateGitStateRef: manifestArtifact.ref, inspectionOutputRef: inspectionArtifact.ref,
    indexRef: indexArtifact.ref, manifest, index, closure, pack, output,
    metadata: [indexBytes, packBytes, packIndexBytes, indexArtifact, packArtifact, configArtifact,
      closureArtifact, manifestArtifact, inspectionArtifact] });
}
