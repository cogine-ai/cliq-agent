import { createHash } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { GitIndexSnapshotV1, GitObjectClosureV1, GitObjectPackV1, PrivateGitStateManifest,
  SanitizedGitConfigV1, SourceManifest } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactCatalog } from '../state/artifacts.js';
import { KernelStorageError } from '../state/errors.js';
import { normalizeGitIndex } from './git-index.js';
import { decodeSourceGitInspectionOutput, type SourceGitInspectionOutputV1 } from './source-git-output.js';

type Expected = Readonly<{ repositoryIdentityDigest: string; resources: SandboxResourceSpec }>;
export type PrivateGitReader = Readonly<Pick<ArtifactCatalog, 'readBoundedBytes' | 'readChunks'> & {
  withReadSignal(signal: AbortSignal): PrivateGitReader;
}>;
export type PrivateGitData = Readonly<{ manifestRef: string; manifest: PrivateGitStateManifest;
  index: GitIndexSnapshotV1; closure: GitObjectClosureV1; config: SanitizedGitConfigV1; pack?: GitObjectPackV1 }>;

export function privateGitSourceHead(data: PrivateGitData): NonNullable<SourceManifest['git']>['head'] {
  const head = data.manifest.head;
  if (head.kind !== 'symbolic') return head;
  const resolved = data.manifest.refs.find(ref => ref.name === head.ref);
  if (!resolved) return invalid();
  return Object.freeze({ kind: 'symbolic', ref: head.ref, objectId: resolved.objectId });
}

/** Same fixed metadata schema for a new CAS-only preparation. This data is
 * never an old source receipt or permission to skip the new native scope. */
export function privateGitInspectionOutput(data: PrivateGitData): SourceGitInspectionOutputV1 {
  const { index, manifest, pack } = data;
  if (!pack) return invalid();
  return immutableSnapshot({ schemaVersion: 1, format: 'cliq-source-git-inspection-output-v1',
    repositoryIdentityDigest: index.repositoryIdentityDigest, objectFormat: index.objectFormat, head: manifest.head, refs: manifest.refs,
    index: { entries: index.entries, indexTreeObjectId: index.indexTreeObjectId, byteCount: index.canonicalIndexByteCount,
      sha256: index.canonicalIndexBytesRef }, pack: { byteCount: pack.packByteCount, sha256: pack.packBytesRef,
      trailerObjectHash: pack.packTrailerObjectHash, indexByteCount: pack.packIndexByteCount, indexSha256: pack.packIndexBytesRef,
      objectIds: pack.objectIds }, sanitizedConfig: data.config });
}
function invalid(): never { throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained private Git bytes differ from their complete canonical closure'); }
function closed(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(key => !Object.hasOwn(value, key))) return invalid();
  return value as Record<string, unknown>;
}
function ref(value: unknown): string {
  if (typeof value !== 'string') return invalid();
  try { assertArtifactRef(value); } catch { return invalid(); } return value;
}
function count(value: unknown, maximum: number, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) return invalid();
  return value;
}
async function json(artifacts: PrivateGitReader, input: unknown, format: string, fields: readonly string[],
  digestField: string, maximum: number): Promise<Record<string, unknown>> {
  const bytes = await artifacts.readBoundedBytes(ref(input), maximum); let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return invalid(); }
  const data = closed(value, fields);
  if (data.schemaVersion !== 1 || data.format !== format || !canonicalJsonBytes(data).equals(bytes) ||
      data[digestField] !== digestOmitting(data, digestField)) return invalid();
  return data;
}

/** The admitted classification index is independent from a later private
 * Checkpoint index. Complete canonical bytes, not a path/stat or object list. */
export async function readGitIndexData(artifacts: PrivateGitReader, indexRef: string, expected: Expected,
  signal?: AbortSignal): Promise<GitIndexSnapshotV1> {
  signal?.throwIfAborted();
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const resources = expected.resources, maximum = Math.min(resources.maxSingleFileBytes, resources.maxInvocationOutputBytes);
  const index = await json(reads, indexRef, 'cliq-git-index-snapshot-v1', ['schemaVersion', 'format', 'repositoryIdentityDigest',
    'objectFormat', 'canonicalIndexVersion', 'entries', 'canonicalIndexBytesRef', 'canonicalIndexBytesDigest', 'canonicalIndexByteCount',
    'indexTreeObjectId', 'snapshotDigest'], 'snapshotDigest', maximum);
  if (index.repositoryIdentityDigest !== expected.repositoryIdentityDigest || index.objectFormat !== 'sha1' && index.objectFormat !== 'sha256' ||
      index.canonicalIndexVersion !== 2 || index.canonicalIndexBytesRef !== index.canonicalIndexBytesDigest) return invalid();
  const bytes = await reads.readBoundedBytes(ref(index.canonicalIndexBytesRef), count(index.canonicalIndexByteCount, resources.maxSingleFileBytes));
  signal?.throwIfAborted();
  const normalized = normalizeGitIndex(bytes, index.objectFormat, { maxBytes: resources.maxSingleFileBytes, maxEntries: 100_000 });
  if (bytes.length !== index.canonicalIndexByteCount || !normalized.canonicalBytes.equals(bytes) ||
      normalized.indexTreeObjectId !== index.indexTreeObjectId || canonicalSha256(normalized.entries) !== canonicalSha256(index.entries)) return invalid();
  return immutableSnapshot(index as GitIndexSnapshotV1);
}

/** Complete retained data only. Even a correct pack checksum and index are
 * not proof of decompression, object types or reachability: the original
 * preparing owner must freshly run the fixed trusted-Git recipe before
 * lending this data to a generation or execution. No cache or native brand. */
export async function readPrivateGitData(artifacts: PrivateGitReader, manifestRef: string, expected: Expected,
  signal?: AbortSignal): Promise<PrivateGitData> {
  ref(manifestRef); ref(expected.repositoryIdentityDigest); signal?.throwIfAborted();
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const resources = expected.resources, maximum = Math.min(resources.maxSingleFileBytes, resources.maxInvocationOutputBytes);
  const manifest = await json(reads, manifestRef, 'cliq-private-git-v1', ['schemaVersion', 'format', 'head', 'indexRef', 'refs',
    'objectClosureRef', 'objectClosureDigest', 'sanitizedConfigRef', 'sanitizedConfigDigest', 'manifestDigest'], 'manifestDigest', maximum);
  const index = await readGitIndexData(reads, ref(manifest.indexRef), expected, signal);
  const closure = await json(reads, manifest.objectClosureRef, 'cliq-git-object-closure-v1', ['schemaVersion', 'format',
    'repositoryIdentityDigest', 'objectFormat', 'packs', 'reachableObjectIds', 'closureDigest'], 'closureDigest', maximum);
  const configBytes = await reads.readBoundedBytes(ref(manifest.sanitizedConfigRef), maximum); let config: unknown;
  try { config = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(configBytes)); } catch { return invalid(); }
  if (!canonicalJsonBytes(config).equals(configBytes) || index.repositoryIdentityDigest !== expected.repositoryIdentityDigest ||
      closure.repositoryIdentityDigest !== expected.repositoryIdentityDigest || closure.objectFormat !== index.objectFormat ||
      manifest.objectClosureDigest !== closure.closureDigest || !Array.isArray(closure.packs) || closure.packs.length !== 1 ||
      index.objectFormat !== 'sha1' && index.objectFormat !== 'sha256' || index.canonicalIndexVersion !== 2 ||
      index.canonicalIndexBytesRef !== index.canonicalIndexBytesDigest) return invalid();
  const member = closed(closure.packs[0], ['packRef', 'packDigest', 'packTrailerObjectHash']);
  const pack = await json(reads, member.packRef, 'cliq-git-object-pack-v1', ['schemaVersion', 'format', 'objectFormat',
    'packBytesRef', 'packBytesDigest', 'packByteCount', 'packTrailerObjectHash', 'packIndexBytesRef', 'packIndexBytesDigest',
    'packIndexByteCount', 'packIndexVersion', 'objectCount', 'objectIds', 'packDigest'], 'packDigest', maximum);
  if (pack.objectFormat !== index.objectFormat || pack.packBytesRef !== pack.packBytesDigest ||
      pack.packIndexBytesRef !== pack.packIndexBytesDigest || pack.packIndexVersion !== 2 || pack.packDigest !== member.packDigest ||
      pack.packTrailerObjectHash !== member.packTrailerObjectHash || !Array.isArray(pack.objectIds) ||
      pack.objectCount !== pack.objectIds.length || canonicalSha256(pack.objectIds) !== canonicalSha256(closure.reachableObjectIds)) return invalid();
  const output = decodeSourceGitInspectionOutput(canonicalJsonBytes({ schemaVersion: 1, format: 'cliq-source-git-inspection-output-v1',
    repositoryIdentityDigest: expected.repositoryIdentityDigest, objectFormat: index.objectFormat, head: manifest.head, refs: manifest.refs,
    index: { entries: index.entries, indexTreeObjectId: index.indexTreeObjectId, byteCount: index.canonicalIndexByteCount,
      sha256: index.canonicalIndexBytesRef }, pack: { byteCount: pack.packByteCount, sha256: pack.packBytesRef,
      trailerObjectHash: pack.packTrailerObjectHash, indexByteCount: pack.packIndexByteCount, indexSha256: pack.packIndexBytesRef,
      objectIds: pack.objectIds }, sanitizedConfig: config }), expected);
  if (manifest.sanitizedConfigDigest !== output.sanitizedConfig.configDigest) return invalid();
  const hashSize = output.objectFormat === 'sha1' ? 20 : 32, packLength = count(pack.packByteCount, resources.maxSingleFileBytes, 12 + hashSize);
  const header = Buffer.alloc(12), trailer = Buffer.alloc(hashSize), digest = createHash(output.objectFormat); let offset = 0;
  for await (const bytes of reads.readChunks(ref(pack.packBytesRef), packLength)) {
    signal?.throwIfAborted();
    if (offset < 12) bytes.copy(header, offset, 0, Math.min(bytes.length, 12 - offset));
    const payload = Math.min(bytes.length, Math.max(0, packLength - hashSize - offset));
    if (payload) digest.update(bytes.subarray(0, payload));
    if (payload < bytes.length) bytes.copy(trailer, Math.max(0, offset - (packLength - hashSize)), payload);
    offset += bytes.length;
  }
  if (offset !== packLength || header.toString('ascii', 0, 4) !== 'PACK' || header.readUInt32BE(4) !== 2 ||
      header.readUInt32BE(8) !== pack.objectCount || trailer.toString('hex') !== pack.packTrailerObjectHash ||
      !digest.digest().equals(trailer)) return invalid();
  const packIndexBytes = await reads.readBoundedBytes(ref(pack.packIndexBytesRef),
    count(pack.packIndexByteCount, resources.maxSingleFileBytes, 8 + 1024 + hashSize * 2));
  const objectCount = count(pack.objectCount, 100_000), fixedLength = 8 + 1024 + objectCount * (hashSize + 8) + hashSize * 2;
  if (packIndexBytes.length !== pack.packIndexByteCount || packIndexBytes.length < fixedLength ||
      (packIndexBytes.length - fixedLength) % 8 || packIndexBytes.readUInt32BE() !== 0xff744f63 || packIndexBytes.readUInt32BE(4) !== 2 ||
      !createHash(output.objectFormat).update(packIndexBytes.subarray(0, -hashSize)).digest().equals(packIndexBytes.subarray(-hashSize)) ||
      !packIndexBytes.subarray(-hashSize * 2, -hashSize).equals(trailer)) return invalid();
  let previous = 0, seen = 0; const largeOffsets = new Set<number>(), largeCount = (packIndexBytes.length - fixedLength) / 8;
  for (let byte = 0; byte < 256; byte++) {
    const boundary = packIndexBytes.readUInt32BE(8 + byte * 4);
    if (boundary < previous || boundary > objectCount) return invalid();
    while (seen < objectCount && Number.parseInt(output.pack.objectIds[seen]!.slice(0, 2), 16) === byte) seen++;
    if (boundary !== seen) return invalid(); previous = boundary;
  }
  if (seen !== objectCount) return invalid();
  for (let ordinal = 0; ordinal < objectCount; ordinal++) {
    const id = packIndexBytes.subarray(8 + 1024 + ordinal * hashSize, 8 + 1024 + (ordinal + 1) * hashSize).toString('hex');
    if (id !== output.pack.objectIds[ordinal]) return invalid();
    const location = packIndexBytes.readUInt32BE(8 + 1024 + objectCount * (hashSize + 4) + ordinal * 4);
    let position: bigint;
    if (location >= 0x80000000) {
      const selected = location - 0x80000000;
      if (selected >= largeCount || largeOffsets.has(selected)) return invalid(); largeOffsets.add(selected);
      position = packIndexBytes.readBigUInt64BE(8 + 1024 + objectCount * (hashSize + 8) + selected * 8);
    } else position = BigInt(location);
    if (position < 12n || position >= BigInt(packLength - hashSize)) return invalid();
  }
  if (largeOffsets.size !== largeCount) return invalid();
  signal?.throwIfAborted();
  return immutableSnapshot({ manifestRef, manifest: manifest as PrivateGitStateManifest, index: index as GitIndexSnapshotV1,
    closure: closure as GitObjectClosureV1, config: output.sanitizedConfig, pack: pack as GitObjectPackV1 });
}
