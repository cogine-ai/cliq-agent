// Fixed private archive metadata, not model activation, registration or Run
// authority. Original Root/EX/model-store and native source/target custody are
// separate requirements. No path, FD, SQL, ledger or execution token is issued.
import { createHash } from 'node:crypto';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { decodeKernelArchiveDirectoryIdentity, KERNEL_ARCHIVE_MAX_BYTES,
  type KernelArchiveDirectoryIdentity } from './kernel-archive-namespace.js';
export const MODEL_ARCHIVE_ENTRY_BYTES = 192;
export const MODEL_ARCHIVE_HEADER_BYTES = 64;
export const MODEL_ARCHIVE_MAX_ENTRIES = 1_048_579;
export type KernelArchiveModelStore = Readonly<{ kind: 'captured'; layout: 'cliq-local-model-store-v1';
  sourceDirectory: KernelArchiveDirectoryIdentity; sourceObjectsDirectory: KernelArchiveDirectoryIdentity;
  archiveDirectory: KernelArchiveDirectoryIdentity; archiveObjectsDirectory: KernelArchiveDirectoryIdentity;
  entryCount: number; totalBytes: number;
  inventory: Readonly<{ file: KernelArchiveDirectoryIdentity; byteCount: number; sha256: string }> }>;
export type KernelArchiveModelEntry = Readonly<{ path: string;
  kind: 'registry' | 'journal' | 'lock' | 'object' | 'temporary';
  sourceMode: number; ownerUid: number; sourceDeviceId: string; sourceFileId: string;
  archiveDeviceId: string; archiveFileId: string; byteCount: number; sha256: string;
  sourceCtimeSeconds: string; sourceCtimeNanos: number }>;
const KINDS = ['registry', 'journal', 'lock', 'object', 'temporary'] as const;
const U64_MAX = (1n << 64n) - 1n;
function invalid(): never { throw new TypeError('model-store archive is outside its complete fixed inventory contract'); }
function decimal(value: unknown): string {
  const text = controlWireText(value, 20);
  if (!/^(0|[1-9][0-9]*)$/u.test(text) || BigInt(text) > U64_MAX) return invalid(); return text;
}
function signedSeconds(value: unknown): string {
  const text = controlWireText(value, 20);
  if (!/^(0|-?[1-9][0-9]*)$/u.test(text)) return invalid();
  const integer = BigInt(text); if (integer < -(1n << 63n) || integer >= 1n << 63n) return invalid(); return text;
}
export function decodeKernelArchiveModelStore(value: unknown): KernelArchiveModelStore {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['kind', 'layout', 'sourceDirectory', 'sourceObjectsDirectory', 'archiveDirectory',
    'archiveObjectsDirectory', 'entryCount', 'totalBytes', 'inventory']);
  if (data.kind !== 'captured' || data.layout !== 'cliq-local-model-store-v1') return invalid();
  const sourceDirectory = decodeKernelArchiveDirectoryIdentity(data.sourceDirectory),
    sourceObjectsDirectory = decodeKernelArchiveDirectoryIdentity(data.sourceObjectsDirectory),
    archiveDirectory = decodeKernelArchiveDirectoryIdentity(data.archiveDirectory),
    archiveObjectsDirectory = decodeKernelArchiveDirectoryIdentity(data.archiveObjectsDirectory);
  const inventory = controlWireRecord(data.inventory, ['file', 'byteCount', 'sha256']), file = decodeKernelArchiveDirectoryIdentity(inventory.file);
  for (const entry of [sourceDirectory, sourceObjectsDirectory, archiveDirectory, archiveObjectsDirectory, file]) {
    decimal(entry.deviceId); decimal(entry.fileId); controlWireInteger(entry.ownerUid, 0, 0xffff_ffff);
    if (entry.ownerUid !== sourceDirectory.ownerUid || entry.deviceId !== sourceDirectory.deviceId) return invalid();
  }
  const entryCount = controlWireInteger(data.entryCount, 3, MODEL_ARCHIVE_MAX_ENTRIES),
    totalBytes = controlWireInteger(data.totalBytes, 0, KERNEL_ARCHIVE_MAX_BYTES);
  const byteCount = controlWireInteger(inventory.byteCount, MODEL_ARCHIVE_HEADER_BYTES, KERNEL_ARCHIVE_MAX_BYTES);
  if (byteCount !== MODEL_ARCHIVE_HEADER_BYTES + MODEL_ARCHIVE_ENTRY_BYTES * entryCount || totalBytes > KERNEL_ARCHIVE_MAX_BYTES - byteCount)
    return invalid();
  return Object.freeze({ kind: 'captured', layout: data.layout, sourceDirectory, sourceObjectsDirectory, archiveDirectory,
    archiveObjectsDirectory, entryCount, totalBytes, inventory: Object.freeze({ file, byteCount, sha256: controlWireRef(inventory.sha256) }) });
}
/** Closed data witness only. Native reopens fixed paths under its genuine EX
 * holder and verifies all original IDs, bytes and the complete namespace. */
export function encodeCurrentKernelArchiveModelStore(value: KernelArchiveModelStore): Buffer {
  const store = decodeKernelArchiveModelStore(value), packet = Buffer.alloc(152);
  packet.write('CLQMM001', 0, 'ascii');
  const integers = [store.sourceDirectory.deviceId, store.sourceDirectory.fileId,
    store.sourceObjectsDirectory.deviceId, store.sourceObjectsDirectory.fileId,
    store.archiveDirectory.deviceId, store.archiveDirectory.fileId,
    store.archiveObjectsDirectory.deviceId, store.archiveObjectsDirectory.fileId,
    store.inventory.file.deviceId, store.inventory.file.fileId,
    store.entryCount, store.totalBytes, store.inventory.byteCount];
  integers.forEach((integer, index) => packet.writeBigUInt64LE(BigInt(integer), 8 + 8 * index));
  packet.writeUInt32LE(store.sourceDirectory.ownerUid, 112);
  Buffer.from(store.inventory.sha256, 'hex').copy(packet, 120); return packet;
}
export function decodeKernelArchiveModelEntry(value: unknown): KernelArchiveModelEntry {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['path', 'kind', 'sourceMode', 'ownerUid', 'sourceDeviceId', 'sourceFileId',
    'archiveDeviceId', 'archiveFileId', 'byteCount', 'sha256', 'sourceCtimeSeconds', 'sourceCtimeNanos']);
  const path = controlWireText(data.path, 95), sha256 = controlWireRef(data.sha256), kind = data.kind;
  controlWireInteger(data.ownerUid, 0, 0xffff_ffff); controlWireInteger(data.byteCount, 0, KERNEL_ARCHIVE_MAX_BYTES);
  for (const key of ['sourceDeviceId', 'sourceFileId', 'archiveDeviceId', 'archiveFileId']) decimal(data[key]);
  const sourceCtimeSeconds = signedSeconds(data.sourceCtimeSeconds), sourceCtimeNanos = controlWireInteger(data.sourceCtimeNanos, 0, 999_999_999);
  if (kind === 'registry' || kind === 'journal' || kind === 'lock') {
    const leaf = kind === 'registry' ? 'registry.sqlite3' : kind === 'journal' ? 'registry.sqlite3-journal' : 'registry.lock';
    if (path !== 'local-models/' + leaf || data.sourceMode !== 0o600) return invalid();
  } else if (kind === 'object') {
    if (!/^local-models\/objects\/[0-9a-f]{64}$/u.test(path) || path.slice(-64) !== sha256 || data.sourceMode !== 0o400) return invalid();
  } else if (kind === 'temporary') {
    if (!/^local-models\/objects\/\.model-object-v1-[0-9a-f]{32}$/u.test(path) ||
        data.sourceMode !== 0o400 && data.sourceMode !== 0o600) return invalid();
  } else return invalid();
  return Object.freeze({ path, kind, sourceMode: data.sourceMode as number, ownerUid: data.ownerUid as number,
    sourceDeviceId: data.sourceDeviceId as string, sourceFileId: data.sourceFileId as string,
    archiveDeviceId: data.archiveDeviceId as string, archiveFileId: data.archiveFileId as string, byteCount: data.byteCount as number, sha256,
    sourceCtimeSeconds, sourceCtimeNanos });
}
export function encodeKernelArchiveModelEntry(value: KernelArchiveModelEntry): Buffer {
  const entry = decodeKernelArchiveModelEntry(value), bytes = Buffer.alloc(MODEL_ARCHIVE_ENTRY_BYTES);
  bytes.write(entry.path, 0, 96, 'ascii'); bytes[96] = KINDS.indexOf(entry.kind) + 1; bytes.writeUInt16LE(entry.sourceMode, 97);
  bytes.writeUInt32LE(entry.ownerUid, 100); bytes.writeBigUInt64LE(BigInt(entry.sourceFileId), 104);
  bytes.writeBigUInt64LE(BigInt(entry.archiveFileId), 112); bytes.writeBigUInt64LE(BigInt(entry.byteCount), 120);
  Buffer.from(entry.sha256, 'hex').copy(bytes, 128); bytes.writeBigUInt64LE(BigInt(entry.sourceDeviceId), 160);
  bytes.writeBigUInt64LE(BigInt(entry.archiveDeviceId), 168); bytes.writeBigInt64LE(BigInt(entry.sourceCtimeSeconds), 176);
  bytes.writeUInt32LE(entry.sourceCtimeNanos, 184); return bytes;
}
function record(bytes: Buffer): KernelArchiveModelEntry {
  if (bytes.length !== MODEL_ARCHIVE_ENTRY_BYTES || bytes[99] || bytes.readUInt32LE(188)) return invalid();
  const end = bytes.subarray(0, 96).indexOf(0);
  if (end < 1 || bytes.subarray(end, 96).some(byte => byte !== 0) || bytes.subarray(0, end).some(byte => byte > 127)) return invalid();
  const byteCount = bytes.readBigUInt64LE(120); if (byteCount > BigInt(KERNEL_ARCHIVE_MAX_BYTES)) return invalid();
  return decodeKernelArchiveModelEntry({ path: bytes.subarray(0, end).toString('ascii'), kind: KINDS[bytes[96]! - 1],
    sourceMode: bytes.readUInt16LE(97), ownerUid: bytes.readUInt32LE(100), sourceFileId: bytes.readBigUInt64LE(104).toString(),
    archiveFileId: bytes.readBigUInt64LE(112).toString(), byteCount: Number(byteCount), sha256: bytes.subarray(128, 160).toString('hex'),
    sourceDeviceId: bytes.readBigUInt64LE(160).toString(), archiveDeviceId: bytes.readBigUInt64LE(168).toString(),
    sourceCtimeSeconds: bytes.readBigInt64LE(176).toString(), sourceCtimeNanos: bytes.readUInt32LE(184) });
}
/** Bounded data decoder only. The genuine current native reader must also
 * reach actual EOF, fsync/close and join before this finish can supply data. */
export class KernelArchiveModelInventoryStream {
  private readonly expected: KernelArchiveModelStore;
  private readonly hash = createHash('sha256');
  private pending = Buffer.alloc(0);
  private header = false;
  private bytes = 0;
  private count = 0;
  private total = 0;
  private previous = '';
  private fixed = 0;
  private failed = false;
  private finished = false;
  constructor(expected: KernelArchiveModelStore) { this.expected = decodeKernelArchiveModelStore(expected); }
  feed(input: Uint8Array): readonly KernelArchiveModelEntry[] {
    if (this.failed || this.finished) return invalid();
    try {
      if (!input.byteLength || input.byteLength > 65536 || input.byteLength > this.expected.inventory.byteCount - this.bytes) return invalid();
      this.bytes += input.byteLength; this.hash.update(input);
      const bytes = this.pending.length ? Buffer.concat([this.pending, input]) : Buffer.from(input); let offset = 0;
      if (!this.header) {
        if (bytes.length < MODEL_ARCHIVE_HEADER_BYTES) { this.pending = bytes; return []; }
        if (bytes.subarray(0, 8).toString('ascii') !== 'CLQMS001' ||
            bytes.readBigUInt64LE(8) !== BigInt(this.expected.entryCount) || bytes.readBigUInt64LE(16) !== BigInt(this.expected.totalBytes) ||
            bytes.readBigUInt64LE(24).toString() !== this.expected.sourceDirectory.deviceId ||
            bytes.readBigUInt64LE(32).toString() !== this.expected.sourceDirectory.fileId ||
            bytes.readBigUInt64LE(40).toString() !== this.expected.sourceObjectsDirectory.deviceId ||
            bytes.readBigUInt64LE(48).toString() !== this.expected.sourceObjectsDirectory.fileId ||
            bytes.readUInt32LE(56) !== this.expected.sourceDirectory.ownerUid || bytes.readUInt32LE(60) !== MODEL_ARCHIVE_ENTRY_BYTES)
          return invalid();
        this.header = true; offset = MODEL_ARCHIVE_HEADER_BYTES;
      }
      const events: KernelArchiveModelEntry[] = [];
      while (bytes.length - offset >= MODEL_ARCHIVE_ENTRY_BYTES) {
        const entry = record(bytes.subarray(offset, offset + MODEL_ARCHIVE_ENTRY_BYTES)); offset += MODEL_ARCHIVE_ENTRY_BYTES;
        if (++this.count > this.expected.entryCount || entry.path <= this.previous || entry.ownerUid !== this.expected.sourceDirectory.ownerUid ||
            entry.sourceDeviceId !== this.expected.sourceDirectory.deviceId || entry.archiveDeviceId !== this.expected.archiveDirectory.deviceId ||
            entry.byteCount > this.expected.totalBytes - this.total) return invalid();
        if (entry.kind === 'registry' || entry.kind === 'journal' || entry.kind === 'lock') {
          const bit = entry.kind === 'registry' ? 1 : entry.kind === 'journal' ? 2 : 4;
          if (this.fixed & bit) return invalid(); this.fixed |= bit;
        }
        this.total += entry.byteCount; this.previous = entry.path; events.push(entry);
      }
      this.pending = Buffer.from(bytes.subarray(offset)); return events;
    } catch { this.failed = true; return invalid(); }
  }
  finish(): void {
    if (this.failed || this.finished) return invalid(); this.finished = true;
    if (!this.header || this.pending.length || this.bytes !== this.expected.inventory.byteCount || this.count !== this.expected.entryCount ||
        this.total !== this.expected.totalBytes || this.fixed !== 7 || this.hash.digest('hex') !== this.expected.inventory.sha256) return invalid();
  }
}
