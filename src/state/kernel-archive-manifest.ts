// The compact root and complete entry vector describe one already-observed
// original archive. They never grant creation, restoration or cleanup rights.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { types } from 'node:util';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef } from '../kernel/control-wire-data.js';
import { decodeKernelRollbackDrainingControl, type KernelRollbackDrainingControlV1 } from '../kernel/kernel-archive-data.js';
import { decodeKernelArchiveCasIdentity, decodeKernelArchiveCasEntry, decodeKernelArchiveDirectoryIdentity,
  assertKernelArchiveCasEntries, KERNEL_ARCHIVE_MAX_BYTES, KERNEL_ARCHIVE_MAX_MANIFEST_BYTES,
  type KernelArchiveCasIdentity, type KernelArchiveCasEntry, type KernelArchiveDirectoryIdentity } from '../kernel/kernel-archive-namespace.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeKernelArchiveSqlCut, type KernelArchiveSqlCut } from './kernel-archive-cut.js';
import { decodeKernelArchiveModelStore, type KernelArchiveModelStore } from '../kernel/kernel-archive-model-store.js';
import { decodeKernelArchiveRuntimeWitnesses, type KernelArchiveRuntimeWitnesses } from '../kernel/kernel-archive-runtime-witness.js';

export type CompleteKernelArchiveManifest = Readonly<{
  schemaVersion: 1; format: 'cliq-owned-kernel-archive-v1';
  snapshotBoundary: 'globally_quiescent_rollback_draining_original_online_copy';
  excludedTail: 'canonical_time_fence_and_post_capture_rollback_audit';
  control: KernelRollbackDrainingControlV1; archiveDirectory: KernelArchiveDirectoryIdentity;
  database: Readonly<{ file: KernelArchiveDirectoryIdentity; mode: 256; linkCount: 1; byteCount: number; sha256: string;
    copyMethod: 'original_node_sqlite_online_backup'; stateSchemaVersion: 8; signedSchemaRef: string; signedSchemaDigest: string;
    completeSqlDigest: string; productiveCut: KernelArchiveSqlCut }>;
  localInferenceRuntime: Readonly<{ kind: 'absent' }> | KernelArchiveRuntimeWitnesses;
  localModelStore: Readonly<{ kind: 'absent' }> | KernelArchiveModelStore;
  cas: KernelArchiveCasIdentity; entries: readonly KernelArchiveCasEntry[]; manifestDigest: string;
}>;
function invalid(): never { throw new TypeError('complete Kernel archive manifest is inconsistent with its fixed original capture'); }

/** Closed data validation is deliberately independent of catalog schemaKind
 * and content-purpose inference. Every ordinary artifact remains raw bytes
 * in this all-and-only namespace copy, including both temporary orphan kinds. */
export type CompleteKernelArchiveHeader = Omit<CompleteKernelArchiveManifest, 'entries'>;
export function kernelArchiveSidecarBytes(head: Pick<CompleteKernelArchiveHeader, 'localModelStore' | 'localInferenceRuntime'>): number {
  return (head.localModelStore.kind === 'captured' ? head.localModelStore.totalBytes + head.localModelStore.inventory.byteCount : 0) +
    (head.localInferenceRuntime.kind === 'captured' ? head.localInferenceRuntime.pack.byteCount : 0);
}

function manifestHead(value: unknown, digest: boolean, vector = true) {
  if (value !== null && typeof value === 'object' && types.isProxy(value)) invalid();
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'snapshotBoundary', 'excludedTail', 'control', 'archiveDirectory',
    'database', 'localInferenceRuntime', 'localModelStore', 'cas', ...(vector ? ['entries'] : []), ...(digest ? ['manifestDigest'] : [])]);
  for (const [key, member] of Object.entries(data)) if (key !== 'entries') assertControlWireJson(member);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-owned-kernel-archive-v1' ||
      data.snapshotBoundary !== 'globally_quiescent_rollback_draining_original_online_copy' ||
      data.excludedTail !== 'canonical_time_fence_and_post_capture_rollback_audit') invalid();
  const control = decodeKernelRollbackDrainingControl(data.control), archiveDirectory = decodeKernelArchiveDirectoryIdentity(data.archiveDirectory);
  let localInferenceRuntime: CompleteKernelArchiveManifest['localInferenceRuntime'];
  if ((data.localInferenceRuntime as { kind?: unknown } | null)?.kind === 'captured')
    localInferenceRuntime = decodeKernelArchiveRuntimeWitnesses(data.localInferenceRuntime);
  else {
    const runtime = controlWireRecord(data.localInferenceRuntime, ['kind']); if (runtime.kind !== 'absent') invalid();
    localInferenceRuntime = Object.freeze({ kind: 'absent' });
  }
  let localModelStore: CompleteKernelArchiveManifest['localModelStore'];
  if ((data.localModelStore as { kind?: unknown } | null)?.kind === 'captured') localModelStore = decodeKernelArchiveModelStore(data.localModelStore);
  else {
    const absent = controlWireRecord(data.localModelStore, ['kind']); if (absent.kind !== 'absent') invalid();
    localModelStore = Object.freeze({ kind: 'absent' });
  }
  const source = controlWireRecord(data.database, ['file', 'mode', 'linkCount', 'byteCount', 'sha256', 'copyMethod', 'stateSchemaVersion',
    'signedSchemaRef', 'signedSchemaDigest', 'completeSqlDigest', 'productiveCut']);
  const file = decodeKernelArchiveDirectoryIdentity(source.file), byteCount = controlWireInteger(source.byteCount, 1, KERNEL_ARCHIVE_MAX_BYTES);
  if (source.mode !== 0o400 || source.linkCount !== 1 || source.stateSchemaVersion !== 8 ||
      source.copyMethod !== 'original_node_sqlite_online_backup' || file.ownerUid !== archiveDirectory.ownerUid || file.deviceId !== archiveDirectory.deviceId) invalid();
  for (const key of ['sha256', 'signedSchemaRef', 'signedSchemaDigest', 'completeSqlDigest']) controlWireRef(source[key]);
  const productiveCut = decodeKernelArchiveSqlCut(source.productiveCut), cas = decodeKernelArchiveCasIdentity(data.cas);
  if (cas.sourceDirectory.ownerUid !== file.ownerUid || cas.archiveDirectory.ownerUid !== file.ownerUid ||
      cas.archiveDirectory.deviceId !== archiveDirectory.deviceId ||
      vector && (!Array.isArray(data.entries) || types.isProxy(data.entries) || data.entries.length !== cas.entryCount)) invalid();
  if (localModelStore.kind === 'captured' && (localModelStore.sourceDirectory.ownerUid !== file.ownerUid ||
      localModelStore.sourceDirectory.deviceId !== archiveDirectory.deviceId)) invalid();
  if (localInferenceRuntime.kind === 'captured' && (localInferenceRuntime.sourceDirectory.ownerUid !== file.ownerUid ||
      localInferenceRuntime.sourceDirectory.deviceId !== archiveDirectory.deviceId)) invalid();
  if (cas.combinedPayloadBytes > KERNEL_ARCHIVE_MAX_BYTES - kernelArchiveSidecarBytes({ localInferenceRuntime, localModelStore })) invalid();
  const head: Omit<CompleteKernelArchiveManifest, 'entries' | 'manifestDigest'> = { schemaVersion: 1, format: 'cliq-owned-kernel-archive-v1',
    snapshotBoundary: 'globally_quiescent_rollback_draining_original_online_copy',
    excludedTail: 'canonical_time_fence_and_post_capture_rollback_audit', control, archiveDirectory,
    database: Object.freeze({ file, mode: 256, linkCount: 1, byteCount, sha256: source.sha256 as string,
      copyMethod: 'original_node_sqlite_online_backup', stateSchemaVersion: 8, signedSchemaRef: source.signedSchemaRef as string,
      signedSchemaDigest: source.signedSchemaDigest as string, completeSqlDigest: source.completeSqlDigest as string, productiveCut }),
    localInferenceRuntime, localModelStore, cas };
  return { head, data };
}
/** Fixed-size header only, for the complete original-FD streaming decoder.
 * Entry count/order/hash/byte totals must additionally close at source EOF. */
export function decodeCompleteKernelArchiveHeader(value: unknown): CompleteKernelArchiveHeader {
  const { head, data } = manifestHead(value, true, false); controlWireRef(data.manifestDigest);
  return Object.freeze({ ...head, manifestDigest: data.manifestDigest as string });
}
export function decodeCompleteKernelArchiveManifest(value: unknown): CompleteKernelArchiveManifest {
  assertControlWireJson(value);
  const { head, data } = manifestHead(value, true);
  const entries = Object.freeze((data.entries as unknown[]).map(decodeKernelArchiveCasEntry));
  assertKernelArchiveCasEntries(head.cas, entries, head.database.byteCount); controlWireRef(data.manifestDigest);
  if (digestOmitting(data, 'manifestDigest') !== data.manifestDigest) invalid();
  return Object.freeze({ ...head, entries, manifestDigest: data.manifestDigest as string });
}
/** Production retains one bounded final byte buffer and only the current
 * native page. It neither retains a million JS entries nor builds a second
 * chunk vector. The fixed self-digest slot avoids a whole-buffer move. */
export async function encodeCompleteKernelArchiveManifest(core: Omit<CompleteKernelArchiveManifest, 'entries' | 'manifestDigest'>,
  pages: AsyncIterable<readonly KernelArchiveCasEntry[]>, signal?: AbortSignal):
  Promise<Readonly<{ header: CompleteKernelArchiveHeader; bytes: Buffer }>> {
  signal?.throwIfAborted();
  const { head } = manifestHead(core, false, false), cas = head.cas;
  // Closed entries are <=512 encoded bytes, including the comma. This fixed
  // upper allocation is independent of caller sizes and at most 256 MiB.
  const allocation = Math.min(KERNEL_ARCHIVE_MAX_MANIFEST_BYTES, canonicalJsonBytes(head).length + 128 + cas.entryCount * 513);
  const bytes = Buffer.allocUnsafe(allocation), hash = createHash('sha256'), entryHash = createHash('sha256');
  let offset = 0, digestOffset = -1, previous = '', total = 0, count = 0;
  const add = (part: Buffer, hashed = true) => {
    if (part.length > allocation - offset) invalid();
    offset += part.copy(bytes, offset); if (hashed) hash.update(part);
  };
  add(Buffer.from('{'));
  const fields: Record<string, unknown> = { ...head, entries: null, manifestDigest: null }, keys = Object.keys(fields).sort();
  for (const [ordinal, key] of keys.entries()) {
    signal?.throwIfAborted(); const hashed = key !== 'manifestDigest';
    if (ordinal) add(Buffer.from(','), hashed); add(canonicalJsonBytes(key), hashed); add(Buffer.from(':'), hashed);
    if (key === 'manifestDigest') {
      digestOffset = offset + 1; add(Buffer.from('"' + '0'.repeat(64) + '"'), false);
    } else if (key === 'entries') {
      add(Buffer.from('['));
      for await (const page of pages) {
        signal?.throwIfAborted();
        if (!Array.isArray(page) || types.isProxy(page) || page.length < 1 || page.length > 64) invalid();
        for (let index = 0; index < page.length; index++) {
          const property = Object.getOwnPropertyDescriptor(page, String(index));
          if (!property || !property.enumerable || !Object.hasOwn(property, 'value')) invalid();
          const entry = decodeKernelArchiveCasEntry(property.value), encoded = canonicalJsonBytes(entry);
          if (entry.name <= previous || ++count > cas.entryCount || encoded.length > 512 || entry.byteCount > KERNEL_ARCHIVE_MAX_BYTES - total) invalid();
          previous = entry.name; total += entry.byteCount;
          entryHash.update(entry.name).update('\0').update(entry.kind).update('\0').update(entry.sha256).update('\0').update(String(entry.byteCount)).update('\n');
          if (count > 1) add(Buffer.from(',')); add(encoded);
        }
        await setImmediate();
      }
      add(Buffer.from(']'));
    } else add(canonicalJsonBytes(fields[key]));
  }
  add(Buffer.from('}'));
  if (digestOffset < 0 || count !== cas.entryCount || total !== cas.totalBytes || entryHash.digest('hex') !== cas.entriesDigest ||
      cas.combinedPayloadBytes !== cas.totalBytes + head.database.byteCount ||
      cas.combinedPayloadBytes > KERNEL_ARCHIVE_MAX_BYTES - offset - kernelArchiveSidecarBytes(head)) invalid();
  const manifestDigest = hash.digest('hex'); bytes.write(manifestDigest, digestOffset, 64, 'ascii');
  signal?.throwIfAborted();
  return Object.freeze({ header: Object.freeze({ ...head, manifestDigest }), bytes: bytes.subarray(0, offset) });
}
