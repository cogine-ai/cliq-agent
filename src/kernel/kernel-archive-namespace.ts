// Fixed archive metadata. Data decoding never supplies the physical capture,
// original EX/Owner, namespace birth, producer drain or rollback authority.
import { createHash } from 'node:crypto';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';

export const KERNEL_ARCHIVE_MAX_BYTES = 53_687_091_200;
export const KERNEL_ARCHIVE_MAX_ENTRIES = 1_048_576;
export const KERNEL_ARCHIVE_MAX_MANIFEST_BYTES = 268_435_456;
export type KernelArchiveDirectoryIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
export type KernelArchiveCasEntry = Readonly<{ name: string; kind: 'published' | 'temporary_stream' | 'temporary_ref';
  sha256: string; byteCount: number; sourceFileId: string; archiveFileId: string; sourceMode: number }>;
export type KernelArchiveCasIdentity = Readonly<{ layout: 'cliq-flat-cas-v1';
  sourceDirectory: KernelArchiveDirectoryIdentity; archiveDirectory: KernelArchiveDirectoryIdentity;
  entryCount: number; totalBytes: number; entriesDigest: string; combinedPayloadBytes: number }>;

function invalid(): never { throw new TypeError('Kernel archive namespace metadata differs from its fixed complete capture contract'); }
function decimal(value: unknown): string {
  const text = controlWireText(value, 32); if (!/^(0|[1-9][0-9]*)$/u.test(text)) invalid(); return text;
}
export function decodeKernelArchiveDirectoryIdentity(value: unknown): KernelArchiveDirectoryIdentity {
  const data = controlWireRecord(value, ['deviceId', 'fileId', 'ownerUid']);
  decimal(data.deviceId); decimal(data.fileId); controlWireInteger(data.ownerUid);
  return Object.freeze({ deviceId: data.deviceId as string, fileId: data.fileId as string, ownerUid: data.ownerUid as number });
}
export function decodeKernelArchiveCasEntry(value: unknown): KernelArchiveCasEntry {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['name', 'kind', 'sha256', 'byteCount', 'sourceFileId', 'archiveFileId', 'sourceMode']);
  const name = controlWireText(data.name, 103), sha256 = controlWireRef(data.sha256);
  controlWireInteger(data.byteCount, 0, KERNEL_ARCHIVE_MAX_BYTES); decimal(data.sourceFileId); decimal(data.archiveFileId);
  if (data.kind === 'published') {
    if (!/^[0-9a-f]{64}$/u.test(name) || name !== sha256 || data.sourceMode !== 0o400) invalid();
  } else if (data.kind === 'temporary_ref') {
    if (!/^\.tmp-[0-9a-f]{64}-[0-9a-f]{32}$/u.test(name) || name.slice(5, 69) !== sha256 || data.sourceMode !== 0o400) invalid();
  } else if (data.kind === 'temporary_stream') {
    if (!/^\.tmp-stream-[0-9a-f]{32}$/u.test(name) || (data.sourceMode !== 0o400 && data.sourceMode !== 0o600)) invalid();
  } else invalid();
  return Object.freeze({ name, kind: data.kind, sha256, byteCount: data.byteCount as number,
    sourceFileId: data.sourceFileId as string, archiveFileId: data.archiveFileId as string, sourceMode: data.sourceMode as number });
}
export function decodeKernelArchiveCasIdentity(value: unknown): KernelArchiveCasIdentity {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['layout', 'sourceDirectory', 'archiveDirectory', 'entryCount', 'totalBytes', 'entriesDigest', 'combinedPayloadBytes']);
  if (data.layout !== 'cliq-flat-cas-v1') invalid();
  const sourceDirectory = decodeKernelArchiveDirectoryIdentity(data.sourceDirectory), archiveDirectory = decodeKernelArchiveDirectoryIdentity(data.archiveDirectory);
  if (sourceDirectory.ownerUid !== archiveDirectory.ownerUid) invalid();
  const entryCount = controlWireInteger(data.entryCount, 0, KERNEL_ARCHIVE_MAX_ENTRIES), totalBytes = controlWireInteger(data.totalBytes, 0, KERNEL_ARCHIVE_MAX_BYTES);
  const combinedPayloadBytes = controlWireInteger(data.combinedPayloadBytes, totalBytes + 1, KERNEL_ARCHIVE_MAX_BYTES);
  return Object.freeze({ layout: data.layout, sourceDirectory, archiveDirectory, entryCount, totalBytes,
    entriesDigest: controlWireRef(data.entriesDigest), combinedPayloadBytes });
}
/** All and only the original byte-sorted physical namespace; catalog labels,
 * DB references and hash-looking user strings never select membership. */
export function assertKernelArchiveCasEntries(identity: KernelArchiveCasIdentity, entries: readonly KernelArchiveCasEntry[], sqliteByteCount: number): void {
  const actual = decodeKernelArchiveCasIdentity(identity);
  controlWireInteger(sqliteByteCount, 1, KERNEL_ARCHIVE_MAX_BYTES);
  if (entries.length !== actual.entryCount || actual.combinedPayloadBytes !== actual.totalBytes + sqliteByteCount) invalid();
  const digest = createHash('sha256'); let previous = '', total = 0;
  for (const raw of entries) {
    const entry = decodeKernelArchiveCasEntry(raw);
    if (entry.name <= previous || entry.byteCount > KERNEL_ARCHIVE_MAX_BYTES - total) invalid();
    total += entry.byteCount; previous = entry.name;
    digest.update(entry.name).update('\0').update(entry.kind).update('\0').update(entry.sha256).update('\0').update(String(entry.byteCount)).update('\n');
  }
  if (total !== actual.totalBytes || digest.digest('hex') !== actual.entriesDigest) invalid();
}
