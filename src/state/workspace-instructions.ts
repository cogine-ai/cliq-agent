import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceInstructionManifestV1, WorkspaceInstructionSourceManifestV1 } from '../kernel/instructions.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { verifyModelText } from '../model/attempt.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { mapArtifactReads } from './bounded-artifact-reads.js';
import { decodeWorkspaceIdentity } from './decoders.js';

const MAX_FILES = 64;
const MAX_RAW_BYTES = 1_048_576;
// All valid 64-entry manifests fit this bound, including JSON's six-byte
// escaping of every byte of a maximum-length 4096-byte path.
const MAX_MANIFEST_BYTES = MAX_FILES * (6 * 4096 + 2048) + 4096;
const SOURCE_ENTRY_KEYS = ['canonicalRootRelativePath', 'directoryDepth', 'fileDescriptor',
  'rawBytesRef', 'rawBytesDigest', 'rawByteCount', 'sourceEntryDigest'];
const INSTRUCTION_ENTRY_KEYS = ['order', 'canonicalRootRelativePath', 'appliesToSubtree',
  'directoryDepth', 'instructionSourceEntryDigest', 'contentRef', 'contentDigest'];
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export type WorkspaceInstructionBinding = {
  workspaceIdentityRef: string;
  workspaceIdentity: WorkspaceIdentityV1;
  admittedAt: string;
};

function record(value: unknown, keys: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) {
    throw new TypeError(`${label} does not have its closed RFC shape`);
  }
}

function ref(value: unknown): asserts value is string {
  if (typeof value !== 'string') throw new TypeError('instruction artifact ref is not a string');
  assertArtifactRef(value);
}

function pathDepth(value: unknown): number {
  if (typeof value !== 'string' || !value || normalizeCanonicalText(value) !== value ||
      value.startsWith('/') || value.includes('\\') || Buffer.byteLength(value, 'utf8') > 4096) {
    throw new TypeError('instruction path is not canonical and root-relative');
  }
  const parts = value.split('/');
  if (parts.at(-1) !== 'AGENTS.md' || parts.some((part) =>
    !part || part === '.' || part === '..' || Buffer.byteLength(part, 'utf8') > 255)) {
    throw new TypeError('instruction source is not a literal in-root AGENTS.md');
  }
  return parts.length - 1;
}

function byteCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

async function readCanonical<T>(artifacts: ArtifactCatalog, reference: string,
  maximum: number): Promise<{ value: T; metadata: PublishedArtifact }> {
  ref(reference);
  if ((await artifacts.verifyBytes(reference)).byteLength > maximum) {
    throw new TypeError('instruction artifact exceeds its complete closure byte bound');
  }
  const bytes = await artifacts.readBytes(reference);
  if (bytes.byteLength > maximum || sha256Bytes(bytes) !== reference) {
    throw new TypeError('instruction artifact bytes changed or exceed their bound');
  }
  const value: T = JSON.parse(strictUtf8.decode(bytes));
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('instruction artifact is not byte-exact canonical JSON');
  return { value, metadata: { ref: reference, byteLength: bytes.byteLength,
    mediaType: 'application/json', schemaKind: '' } };
}

/** Revalidate retained declarative context against its Session, never a live
 * repository path. Descriptor fields are capture history, not current read or
 * execution grants; the capture coordinator still needs held live provenance. */
export async function readWorkspaceInstructionClosure(artifacts: ArtifactCatalog,
  reference: { manifestRef: string; manifestDigest: string }, originalBinding: WorkspaceInstructionBinding) {
  const binding = immutableSnapshot(originalBinding);
  const selected = immutableSnapshot(reference);
  const workspace = decodeWorkspaceIdentity(binding.workspaceIdentity);
  if (workspace.kind !== 'live' || canonicalSha256(workspace) !== binding.workspaceIdentityRef) {
    throw new TypeError('workspace instructions require the exact live Session identity');
  }
  const admittedAt = parseCanonicalTime(binding.admittedAt);
  const root = await readCanonical<WorkspaceInstructionManifestV1>(artifacts, selected.manifestRef, MAX_MANIFEST_BYTES);
  const manifest = root.value;
  record(manifest, ['schemaVersion', 'format', 'workspaceIdentityDigest', 'instructionSourceRef',
    'instructionSourceDigest', 'rendering', 'entries', 'manifestDigest'], 'workspace instruction manifest');
  if (manifest.schemaVersion !== 1 || manifest.format !== 'cliq-workspace-instructions-v1' ||
      manifest.rendering !== 'cliq-all-scopes-labeled-instructions-v1' ||
      manifest.workspaceIdentityDigest !== workspace.identityDigest ||
      manifest.manifestDigest !== selected.manifestDigest ||
      digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest ||
      !Array.isArray(manifest.entries) || manifest.entries.length > MAX_FILES) {
    throw new TypeError('workspace instruction manifest identity or limits mismatch');
  }
  ref(manifest.instructionSourceDigest);
  const captured = await readCanonical<WorkspaceInstructionSourceManifestV1>(artifacts,
    manifest.instructionSourceRef, MAX_MANIFEST_BYTES);
  const source = captured.value;
  record(source, ['schemaVersion', 'format', 'workspaceIdentityRef', 'workspaceIdentityDigest',
    'entries', 'capturedAt', 'sourceDigest'], 'workspace instruction source');
  if (source.schemaVersion !== 1 || source.format !== 'cliq-workspace-instruction-source-v1' ||
      source.workspaceIdentityRef !== binding.workspaceIdentityRef ||
      source.workspaceIdentityDigest !== workspace.identityDigest ||
      source.sourceDigest !== manifest.instructionSourceDigest ||
      digestOmitting(source, 'sourceDigest') !== source.sourceDigest ||
      parseCanonicalTime(source.capturedAt) > admittedAt ||
      !Array.isArray(source.entries) || source.entries.length > MAX_FILES ||
      source.entries.length !== manifest.entries.length) {
    throw new TypeError('workspace instruction source differs from its manifest or Session');
  }
  let totalBytes = 0;
  for (const [index, entry] of source.entries.entries()) {
    record(entry, SOURCE_ENTRY_KEYS, 'workspace instruction source entry');
    const depth = pathDepth(entry.canonicalRootRelativePath);
    if (entry.directoryDepth !== depth || (index > 0 &&
        byteCompare(source.entries[index - 1]!.canonicalRootRelativePath, entry.canonicalRootRelativePath) >= 0)) {
      throw new TypeError('instruction source entries are not unique, byte-sorted paths at their exact depths');
    }
    record(entry.fileDescriptor, ['deviceId', 'fileId', 'ownerUid', 'mode', 'linkCount'], 'instruction file descriptor');
    const descriptor = entry.fileDescriptor;
    for (const field of ['deviceId', 'fileId'] as const) {
      if (typeof descriptor[field] !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/u.test(descriptor[field]) ||
          BigInt(descriptor[field]) > 18_446_744_073_709_551_615n) {
        throw new TypeError('instruction descriptor identity is not a canonical unsigned decimal');
      }
    }
    if (descriptor.ownerUid !== workspace.rootIdentity.ownerUid || descriptor.deviceId !== workspace.rootIdentity.deviceId ||
        ![0o600, 0o644].includes(descriptor.mode) || descriptor.linkCount !== 1) {
      throw new TypeError('instruction descriptor owner, literal mode or link count mismatch');
    }
    if (!Number.isSafeInteger(entry.rawByteCount) || entry.rawByteCount < 0 ||
        (totalBytes += entry.rawByteCount) > MAX_RAW_BYTES) {
      throw new TypeError('workspace instruction source exceeds its complete byte limit');
    }
    ref(entry.rawBytesRef);
    if (entry.rawBytesDigest !== entry.rawBytesRef ||
        digestOmitting(entry, 'sourceEntryDigest') !== entry.sourceEntryDigest) {
      throw new TypeError('instruction source entry or raw bytes digest mismatch');
    }
  }
  const ordered = [...source.entries].sort((left, right) =>
    left.directoryDepth - right.directoryDepth || byteCompare(left.canonicalRootRelativePath, right.canonicalRootRelativePath));
  const byPath = new Map(source.entries.map((entry) => [entry.canonicalRootRelativePath, entry]));
  for (const [index, entry] of manifest.entries.entries()) {
    record(entry, INSTRUCTION_ENTRY_KEYS, 'workspace instruction entry');
    const expected = ordered[index]!;
    if (entry.order !== index || entry.appliesToSubtree !== true ||
        entry.canonicalRootRelativePath !== expected.canonicalRootRelativePath ||
        entry.directoryDepth !== expected.directoryDepth ||
        entry.instructionSourceEntryDigest !== expected.sourceEntryDigest) {
      throw new TypeError('instruction rendering is not the exact root-to-deep source projection');
    }
    ref(entry.contentRef);
    ref(entry.contentDigest);
  }
  const material = await mapArtifactReads(manifest.entries, async (entry) => {
    const observed = byPath.get(entry.canonicalRootRelativePath)!;
    if ((await artifacts.verifyBytes(observed.rawBytesRef)).byteLength !== observed.rawByteCount) {
      throw new TypeError('instruction raw byte count differs from retained CAS bytes');
    }
    const raw = await artifacts.readBytes(observed.rawBytesRef);
    const utf8 = strictUtf8.decode(raw);
    if (raw.byteLength !== observed.rawByteCount || sha256Bytes(raw) !== observed.rawBytesDigest ||
        normalizeCanonicalText(utf8) !== utf8 || !Buffer.from(utf8).equals(raw)) {
      throw new TypeError('instruction bytes are not complete normalized UTF-8');
    }
    const content = await readCanonical<ModelTextV1>(artifacts, entry.contentRef, 6 * observed.rawByteCount + 1024);
    verifyModelText(content.value);
    if (content.value.textDigest !== entry.contentDigest || !Buffer.from(content.value.utf8).equals(raw)) {
      throw new TypeError('instruction ModelText is not byte-identical to its captured source');
    }
    return { prompt: { order: entry.order, canonicalRootRelativePath: entry.canonicalRootRelativePath,
      appliesToSubtree: true as const, instructionUtf8: utf8 },
    metadata: { ...content.metadata, schemaKind: content.value.format } };
  });
  return immutableSnapshot({ manifest, source, entries: material.map((entry) => entry.prompt),
    metadata: [{ ...root.metadata, schemaKind: manifest.format }, { ...captured.metadata, schemaKind: source.format },
      ...material.map((entry) => entry.metadata)] });
}
