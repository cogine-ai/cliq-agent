// Finite packet data only; no StateOwner, source copy, native holder or proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeCurrentMigrationExpectedEntry, CURRENT_MIGRATION_ENTRY_HEADER_BYTES } from './current-migration-inspection-data.js';
import type { HeldMigrationBackupEntry } from '../state/native-owner.js';
const sourceIdentity = { deviceId: '18446744073709551615', fileId: '2', ownerUid: 501 };
const backupIdentity = { deviceId: '3', fileId: '4', ownerUid: 501 };
const entry = { canonicalRootRelativePath: 'sessions/e\u0301/session.json', sourceIdentity, backupIdentity, mode: 0o644,
  purpose: 'portable_context' as const, kind: 'regular_file' as const, contentDigest: 'a'.repeat(64), byteCount: 65537, linkCount: 1 as const };
test('current inspector packet preserves exact original path bytes and full unsigned identity/digest/size', () => {
  const bytes = encodeCurrentMigrationExpectedEntry(entry);
  assert.equal(bytes.subarray(0, 8).toString(), 'CLQMI001'); assert.equal(bytes[8], 2); assert.equal(bytes[9], 2);
  assert.equal(bytes.readUInt16LE(10), 0); assert.equal(bytes.readUInt32LE(12), Buffer.byteLength(entry.canonicalRootRelativePath));
  assert.equal(bytes.readUInt32LE(16), 0o644); assert.equal(bytes.readUInt32LE(20), 501); assert.equal(bytes.readUInt32LE(24), 501);
  assert.equal(bytes.readUInt32LE(28), 1); assert.equal(bytes.readBigUInt64LE(32), (1n << 64n) - 1n);
  assert.equal(bytes.readBigUInt64LE(40), 2n); assert.equal(bytes.readBigUInt64LE(48), 3n); assert.equal(bytes.readBigUInt64LE(56), 4n);
  assert.equal(bytes.readBigUInt64LE(64), 65537n); assert.equal(bytes.subarray(72, 104).toString('hex'), entry.contentDigest);
  assert.equal(bytes.subarray(CURRENT_MIGRATION_ENTRY_HEADER_BYTES).toString(), entry.canonicalRootRelativePath);
  assert.notEqual(bytes.subarray(CURRENT_MIGRATION_ENTRY_HEADER_BYTES).toString(), entry.canonicalRootRelativePath.normalize('NFC'));
});
test('directory and unfollowed link packets cannot carry file length or single-link assertions', () => {
  const { contentDigest: _digest, byteCount: _bytes, linkCount: _links, ...base } = entry;
  const directory = encodeCurrentMigrationExpectedEntry({ ...base, kind: 'directory' });
  assert.equal(directory[8], 1); assert.equal(directory.readUInt32LE(28), 0); assert.equal(directory.readBigUInt64LE(64), 0n);
  assert(directory.subarray(72, 104).equals(Buffer.alloc(32)));
  const link = encodeCurrentMigrationExpectedEntry({ ...base, kind: 'unfollowed_link_metadata', linkTextDigest: 'b'.repeat(64) });
  assert.equal(link[8], 3); assert.equal(link.readUInt32LE(28), 0); assert.equal(link.readBigUInt64LE(64), 0n);
  assert.equal(link.subarray(72, 104).toString('hex'), 'b'.repeat(64));
});
test('original full 4096-byte relative path profile is preserved and unsupported closed fields/identities reject', () => {
  const path = [...Array<string>(16).fill('a'.repeat(254)), 'b'.repeat(16)].join('/'); assert.equal(Buffer.byteLength(path), 4096);
  assert.equal(encodeCurrentMigrationExpectedEntry({ ...entry, canonicalRootRelativePath: path }).length, 4200);
  for (const change of [{ canonicalRootRelativePath: '../outside' }, { canonicalRootRelativePath: 'auth.json' },
    { canonicalRootRelativePath: path + 'b' }, { sourceIdentity: { ...sourceIdentity, deviceId: '18446744073709551616' } },
    { backupIdentity: { ...backupIdentity, ownerUid: 0x1_0000_0000 } }, { linkCount: 2 }, { byteCount: Number.MAX_SAFE_INTEGER + 1 },
    { verified: true }, { nativeHandle: {} }])
    assert.throws(() => encodeCurrentMigrationExpectedEntry({ ...entry, ...change } as HeldMigrationBackupEntry), TypeError);
  let calls = 0; const proxy = new Proxy(entry, { get() { calls++; throw new Error('caller trap'); } });
  assert.throws(() => encodeCurrentMigrationExpectedEntry(proxy), TypeError); assert.equal(calls, 0);
});
