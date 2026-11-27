// Readonly current-observer packets. These closed values cannot establish an
// original birth, StateOwner, migration EX, committed SQL or restore authority.
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef } from './control-wire-data.js';
import { decodeKernelArchiveCasEntry, decodeKernelArchiveDirectoryIdentity, KERNEL_ARCHIVE_MAX_MANIFEST_BYTES,
  type KernelArchiveCasEntry, type KernelArchiveDirectoryIdentity } from './kernel-archive-namespace.js';
import { decodeCompleteKernelArchiveHeader, type CompleteKernelArchiveHeader } from '../state/kernel-archive-manifest.js';

function invalid(): never { throw new TypeError('current archive packet is outside its fixed original-observation contract'); }
function u64(value: string | number): bigint {
  if (typeof value === 'number' ? !Number.isSafeInteger(value) || value < 0 : !/^(0|[1-9][0-9]{0,19})$/u.test(value)) return invalid();
  const integer = BigInt(value); if (integer > (1n << 64n) - 1n) return invalid(); return integer;
}
function identity(bytes: Buffer, offset: number, value: KernelArchiveDirectoryIdentity): void {
  bytes.writeBigUInt64LE(u64(value.deviceId), offset); bytes.writeBigUInt64LE(u64(value.fileId), offset + 8);
}
export type CurrentArchiveManifestSelection = Readonly<{
  archiveCollection: KernelArchiveDirectoryIdentity; archiveDirectory: KernelArchiveDirectoryIdentity;
  manifest: Readonly<{ file: KernelArchiveDirectoryIdentity; byteCount: number; sha256: string }>;
}>;
export function encodeCurrentArchiveManifestSelection(value: CurrentArchiveManifestSelection): Buffer {
  assertControlWireJson(value); const record = controlWireRecord(value, ['archiveCollection', 'archiveDirectory', 'manifest']);
  const collection = decodeKernelArchiveDirectoryIdentity(record.archiveCollection), directory = decodeKernelArchiveDirectoryIdentity(record.archiveDirectory);
  const manifest = controlWireRecord(record.manifest, ['file', 'byteCount', 'sha256']), file = decodeKernelArchiveDirectoryIdentity(manifest.file);
  const size = controlWireInteger(manifest.byteCount, 1, KERNEL_ARCHIVE_MAX_MANIFEST_BYTES), digest = controlWireRef(manifest.sha256);
  if (collection.ownerUid !== directory.ownerUid || file.ownerUid !== directory.ownerUid) return invalid();
  const bytes = Buffer.alloc(104); bytes.write('CLQMA001', 0, 8, 'ascii');
  identity(bytes, 8, collection); identity(bytes, 24, directory); identity(bytes, 40, file);
  bytes.writeBigUInt64LE(u64(size), 56); bytes.writeUInt32LE(controlWireInteger(directory.ownerUid, 0, 0xffff_ffff), 64);
  Buffer.from(digest, 'hex').copy(bytes, 72); return bytes;
}
export function encodeCurrentArchivePayload(value: CompleteKernelArchiveHeader): Buffer {
  const head = decodeCompleteKernelArchiveHeader(value), bytes = Buffer.alloc(160), owner = head.archiveDirectory.ownerUid;
  if ([head.database.file, head.cas.sourceDirectory, head.cas.archiveDirectory].some(entry => entry.ownerUid !== owner)) return invalid();
  bytes.write('CLQMH001', 0, 8, 'ascii'); identity(bytes, 8, head.database.file);
  bytes.writeBigUInt64LE(u64(head.database.byteCount), 24); Buffer.from(head.database.sha256, 'hex').copy(bytes, 32);
  identity(bytes, 64, head.cas.sourceDirectory); identity(bytes, 80, head.cas.archiveDirectory);
  bytes.writeBigUInt64LE(u64(head.cas.entryCount), 96); bytes.writeBigUInt64LE(u64(head.cas.totalBytes), 104);
  bytes.writeBigUInt64LE(u64(head.cas.combinedPayloadBytes), 112); bytes.writeUInt32LE(controlWireInteger(owner, 0, 0xffff_ffff), 120);
  Buffer.from(head.cas.entriesDigest, 'hex').copy(bytes, 128); return bytes;
}
export function encodeCurrentArchiveCasEntry(value: KernelArchiveCasEntry): Buffer {
  const entry = decodeKernelArchiveCasEntry(value), name = Buffer.from(entry.name, 'utf8'), bytes = Buffer.alloc(80 + name.length);
  bytes.write('CLQMC001', 0, 8, 'ascii'); bytes[8] = entry.kind === 'published' ? 1 : entry.kind === 'temporary_stream' ? 2 : 3;
  bytes.writeUInt32LE(name.length, 12); bytes.writeBigUInt64LE(u64(entry.archiveFileId), 16);
  bytes.writeBigUInt64LE(u64(entry.sourceFileId), 24); bytes.writeBigUInt64LE(u64(entry.byteCount), 32);
  bytes.writeUInt32LE(entry.sourceMode, 40); Buffer.from(entry.sha256, 'hex').copy(bytes, 48); name.copy(bytes, 80); return bytes;
}
