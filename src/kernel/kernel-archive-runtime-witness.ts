import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { decodeKernelArchiveDirectoryIdentity, KERNEL_ARCHIVE_MAX_BYTES, type KernelArchiveDirectoryIdentity } from './kernel-archive-namespace.js';

export const RUNTIME_WITNESS_FRAME_BYTES = 4144;
export const RUNTIME_WITNESS_MAX_FRAMES = 128;
export const RUNTIME_WITNESS_HEADER_BYTES = 64;
export const RUNTIME_WITNESS_RECORD_BYTES = 224;
export const RUNTIME_WITNESS_MAX_ENTRIES = 1_048_576;
const MAX_FRAME_BYTES = RUNTIME_WITNESS_FRAME_BYTES * RUNTIME_WITNESS_MAX_FRAMES;
const U64_MAX = (1n << 64n) - 1n;
export type KernelArchiveRuntimeWitnesses = Readonly<{ kind: 'captured'; layout: 'cliq-local-inference-witness-pack-v1';
  sourceDirectory: KernelArchiveDirectoryIdentity; entryCount: number; totalWitnessBytes: number;
  pack: Readonly<{ file: KernelArchiveDirectoryIdentity; byteCount: number; sha256: string }> }>;
export type RuntimeWitnessArchiveEntry = Readonly<{
  nativeNonce: string; launchId: string; sourceFileId: string; byteCount: number; sha256: string;
  nativeInputRef: string; retirementEvidenceRef: string; retirementKind: 'no_spawn' | 'death';
  sourceCtimeSeconds: string; sourceCtimeNanos: number;
}>;
function invalid(): never { throw new TypeError('runtime witness archive differs from its complete fixed original namespace'); }
function u64(value: string): bigint {
  if (!/^(0|[1-9][0-9]{0,19})$/u.test(value)) return invalid();
  const number = BigInt(value); if (number > U64_MAX) return invalid(); return number;
}
function i64(value: string): bigint {
  if (!/^(0|-?[1-9][0-9]{0,18})$/u.test(value)) return invalid();
  const number = BigInt(value); if (number < -(1n << 63n) || number >= 1n << 63n) return invalid(); return number;
}
function identity(value: unknown): KernelArchiveDirectoryIdentity {
  const result = decodeKernelArchiveDirectoryIdentity(value);
  u64(result.deviceId); if (!u64(result.fileId)) return invalid();
  controlWireInteger(result.ownerUid, 0, 0xffff_ffff); return result;
}
export function decodeKernelArchiveRuntimeWitnesses(value: unknown): KernelArchiveRuntimeWitnesses {
  assertControlWireJson(value);
  const record = controlWireRecord(value, ['kind', 'layout', 'sourceDirectory', 'entryCount', 'totalWitnessBytes', 'pack']);
  if (record.kind !== 'captured' || record.layout !== 'cliq-local-inference-witness-pack-v1') return invalid();
  const sourceDirectory = identity(record.sourceDirectory), data = controlWireRecord(record.pack, ['file', 'byteCount', 'sha256']);
  const file = identity(data.file), byteCount = controlWireInteger(data.byteCount, RUNTIME_WITNESS_HEADER_BYTES, KERNEL_ARCHIVE_MAX_BYTES);
  const entryCount = controlWireInteger(record.entryCount, 0, RUNTIME_WITNESS_MAX_ENTRIES);
  const totalWitnessBytes = controlWireInteger(record.totalWitnessBytes, entryCount * RUNTIME_WITNESS_FRAME_BYTES,
    Math.min(KERNEL_ARCHIVE_MAX_BYTES, entryCount * MAX_FRAME_BYTES));
  if (file.deviceId !== sourceDirectory.deviceId || file.ownerUid !== sourceDirectory.ownerUid || file.fileId === sourceDirectory.fileId ||
      totalWitnessBytes % RUNTIME_WITNESS_FRAME_BYTES !== 0 ||
      byteCount !== RUNTIME_WITNESS_HEADER_BYTES + entryCount * RUNTIME_WITNESS_RECORD_BYTES + totalWitnessBytes)
    return invalid();
  return Object.freeze({ kind: 'captured', layout: record.layout, sourceDirectory, entryCount, totalWitnessBytes,
    pack: Object.freeze({ file, byteCount, sha256: controlWireRef(data.sha256) }) });
}
export function encodeCurrentRuntimeWitnessArchive(value: KernelArchiveRuntimeWitnesses): Buffer {
  const archive = decodeKernelArchiveRuntimeWitnesses(value), bytes = Buffer.alloc(104);
  bytes.write('CLQMW001', 0, 'ascii');
  bytes.writeBigUInt64LE(u64(archive.sourceDirectory.deviceId), 8);
  bytes.writeBigUInt64LE(u64(archive.sourceDirectory.fileId), 16);
  bytes.writeBigUInt64LE(u64(archive.pack.file.deviceId), 24);
  bytes.writeBigUInt64LE(u64(archive.pack.file.fileId), 32);
  bytes.writeBigUInt64LE(BigInt(archive.entryCount), 40);
  bytes.writeBigUInt64LE(BigInt(archive.totalWitnessBytes), 48);
  bytes.writeBigUInt64LE(BigInt(archive.pack.byteCount), 56);
  bytes.writeUInt32LE(archive.sourceDirectory.ownerUid, 64);
  Buffer.from(archive.pack.sha256, 'hex').copy(bytes, 72); return bytes;
}
export function decodeRuntimeWitnessArchiveEntry(value: unknown): RuntimeWitnessArchiveEntry {
  assertControlWireJson(value);
  const record = controlWireRecord(value, ['nativeNonce', 'launchId', 'sourceFileId', 'byteCount', 'sha256', 'nativeInputRef',
    'retirementEvidenceRef', 'retirementKind', 'sourceCtimeSeconds', 'sourceCtimeNanos']);
  const launchId = controlWireText(record.launchId, 43);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(launchId)) return invalid();
  const sourceFileId = controlWireText(record.sourceFileId, 20);
  if (!u64(sourceFileId)) return invalid();
  const byteCount = controlWireInteger(record.byteCount, RUNTIME_WITNESS_FRAME_BYTES, MAX_FRAME_BYTES);
  const sourceCtimeSeconds = controlWireText(record.sourceCtimeSeconds, 20);
  i64(sourceCtimeSeconds);
  if (byteCount % RUNTIME_WITNESS_FRAME_BYTES !== 0 || (record.retirementKind !== 'no_spawn' && record.retirementKind !== 'death'))
    return invalid();
  return Object.freeze({ nativeNonce: controlWireRef(record.nativeNonce), launchId, sourceFileId, byteCount, sha256: controlWireRef(record.sha256),
    nativeInputRef: controlWireRef(record.nativeInputRef), retirementEvidenceRef: controlWireRef(record.retirementEvidenceRef),
    retirementKind: record.retirementKind, sourceCtimeSeconds, sourceCtimeNanos: controlWireInteger(record.sourceCtimeNanos, 0, 999_999_999) });
}
export function encodeRuntimeWitnessArchiveEntry(value: RuntimeWitnessArchiveEntry): Buffer {
  const record = decodeRuntimeWitnessArchiveEntry(value), bytes = Buffer.alloc(RUNTIME_WITNESS_RECORD_BYTES);
  Buffer.from(record.nativeNonce, 'hex').copy(bytes, 0);
  bytes.write(record.launchId, 32, 'ascii');
  bytes.writeBigUInt64LE(u64(record.sourceFileId), 80);
  bytes.writeBigUInt64LE(BigInt(record.byteCount), 88);
  Buffer.from(record.sha256, 'hex').copy(bytes, 96);
  Buffer.from(record.nativeInputRef, 'hex').copy(bytes, 128);
  Buffer.from(record.retirementEvidenceRef, 'hex').copy(bytes, 160);
  bytes.writeBigInt64LE(i64(record.sourceCtimeSeconds), 192);
  bytes.writeUInt32LE(record.sourceCtimeNanos, 200);
  bytes[204] = record.retirementKind === 'no_spawn' ? 1 : 2;
  return bytes;
}
