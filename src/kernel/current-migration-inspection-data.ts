// Fixed current-observer data only. Encoding does not claim the original
// source/backup still exists and never creates a native migration capability.
import { assertControlWireJson } from './control-wire-data.js';
import { decodeOwnedImportInventoryPage } from './owned-import-data.js';
import type { HeldMigrationBackupEntry } from '../state/native-owner.js';

export const CURRENT_MIGRATION_ENTRY_HEADER_BYTES = 104;
export const CURRENT_MIGRATION_ENTRY_MAGIC = 'CLQMI001';
const U64_MAX = (1n << 64n) - 1n;
function invalid(): never { throw new TypeError('current migration entry is outside its fixed original-inventory packet'); }
function u64(value: string | number): bigint {
  if (typeof value === 'number' ? !Number.isSafeInteger(value) || value < 0 : !/^(0|[1-9][0-9]{0,19})$/u.test(value)) return invalid();
  const integer = BigInt(value); if (integer > U64_MAX) return invalid(); return integer;
}
function u32(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) return invalid(); return value;
}
export function encodeCurrentMigrationExpectedEntry(input: HeldMigrationBackupEntry): Buffer {
  assertControlWireJson(input);
  const path = input.canonicalRootRelativePath;
  const page = decodeOwnedImportInventoryPage({ schemaVersion: 1, format: 'cliq-owned-import-inventory-page-v1', kind: 'leaf', height: 0,
    firstPath: path, lastPath: path, entryCount: 1, entries: [input] });
  if (page.kind !== 'leaf') return invalid();
  const entry = page.entries[0]!, name = Buffer.from(entry.canonicalRootRelativePath, 'utf8');
  const bytes = Buffer.alloc(CURRENT_MIGRATION_ENTRY_HEADER_BYTES + name.length);
  bytes.write(CURRENT_MIGRATION_ENTRY_MAGIC, 0, 8, 'ascii');
  bytes[8] = entry.kind === 'directory' ? 1 : entry.kind === 'regular_file' ? 2 : 3;
  bytes[9] = entry.purpose === 'backup_only' ? 1 : entry.purpose === 'portable_context' ? 2 : 3;
  bytes.writeUInt32LE(name.length, 12); bytes.writeUInt32LE(u32(entry.mode), 16);
  bytes.writeUInt32LE(u32(entry.sourceIdentity.ownerUid), 20); bytes.writeUInt32LE(u32(entry.backupIdentity.ownerUid), 24);
  bytes.writeUInt32LE(entry.kind === 'regular_file' ? entry.linkCount : 0, 28);
  bytes.writeBigUInt64LE(u64(entry.sourceIdentity.deviceId), 32); bytes.writeBigUInt64LE(u64(entry.sourceIdentity.fileId), 40);
  bytes.writeBigUInt64LE(u64(entry.backupIdentity.deviceId), 48); bytes.writeBigUInt64LE(u64(entry.backupIdentity.fileId), 56);
  bytes.writeBigUInt64LE(entry.kind === 'regular_file' ? u64(entry.byteCount) : 0n, 64);
  if (entry.kind !== 'directory') Buffer.from(entry.kind === 'regular_file' ? entry.contentDigest : entry.linkTextDigest, 'hex').copy(bytes, 72);
  name.copy(bytes, CURRENT_MIGRATION_ENTRY_HEADER_BYTES); return bytes;
}
