// Finite inert byte fixtures only; no real store, signed model, native capture,
// original descriptor, StateOwner or migration/restoration authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { decodeKernelArchiveModelStore, encodeKernelArchiveModelEntry, KernelArchiveModelInventoryStream,
  type KernelArchiveModelEntry } from './kernel-archive-model-store.js';
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
function fixture() {
  const identity = (id: number) => ({ deviceId: '1', fileId: String(id), ownerUid: 1000 });
  const payload = Buffer.from('inert archived model object'), objectHash = sha(payload), empty = sha(Buffer.alloc(0));
  const original: KernelArchiveModelEntry[] = [
    ...(['registry', 'journal', 'lock'] as const).map((kind, index) => ({
      path: 'local-models/' + (kind === 'registry' ? 'registry.sqlite3' : kind === 'journal' ? 'registry.sqlite3-journal' : 'registry.lock'),
      kind, sourceMode: 0o600, ownerUid: 1000, sourceDeviceId: '1', sourceFileId: String(index + 10),
      archiveDeviceId: '1', archiveFileId: String(index + 20), byteCount: 0, sha256: empty, sourceCtimeSeconds: '0', sourceCtimeNanos: index
    })),
    { path: 'local-models/objects/' + objectHash, kind: 'object', sourceMode: 0o400, ownerUid: 1000,
      sourceDeviceId: '1', sourceFileId: '30', archiveDeviceId: '1', archiveFileId: '40', byteCount: payload.length, sha256: objectHash,
      sourceCtimeSeconds: '-9223372036854775808', sourceCtimeNanos: 999_999_999 },
    { path: 'local-models/objects/.model-object-v1-' + 'a'.repeat(32), kind: 'temporary', sourceMode: 0o600, ownerUid: 1000,
      sourceDeviceId: '1', sourceFileId: '31', archiveDeviceId: '1', archiveFileId: '41', byteCount: 0, sha256: empty,
      sourceCtimeSeconds: '9223372036854775807', sourceCtimeNanos: 0 }
  ];
  original.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const header = Buffer.alloc(64); header.write('CLQMS001'); header.writeBigUInt64LE(BigInt(original.length), 8);
  header.writeBigUInt64LE(BigInt(payload.length), 16); header.writeBigUInt64LE(1n, 24); header.writeBigUInt64LE(2n, 32);
  header.writeBigUInt64LE(1n, 40); header.writeBigUInt64LE(3n, 48); header.writeUInt32LE(1000, 56); header.writeUInt32LE(192, 60);
  const bytes = Buffer.concat([header, ...original.map(encodeKernelArchiveModelEntry)]);
  const expected = decodeKernelArchiveModelStore({ kind: 'captured', layout: 'cliq-local-model-store-v1', sourceDirectory: identity(2),
    sourceObjectsDirectory: identity(3), archiveDirectory: identity(4), archiveObjectsDirectory: identity(5), entryCount: original.length,
    totalBytes: payload.length, inventory: { file: identity(6), byteCount: bytes.length, sha256: sha(bytes) } });
  return { original, bytes, expected };
}
test('bounded model inventory closes all fixed files, orphan objects and temporary data across chunk boundaries', () => {
  for (const size of [1, 7, 192, 65536]) {
    const { original, bytes, expected } = fixture(), stream = new KernelArchiveModelInventoryStream(expected), actual: KernelArchiveModelEntry[] = [];
    for (let offset = 0; offset < bytes.length; offset += size) actual.push(...stream.feed(bytes.subarray(offset, offset + size)));
    stream.finish(); assert.deepEqual(actual, original); assert.throws(() => stream.finish(), TypeError);
    assert.throws(() => stream.feed(Buffer.from([0])), TypeError);
  }
});
test('fixed model inventory preserves U64 identifiers and requires zero canonical padding', () => {
  const { original } = fixture(), value = { ...original[0]!, sourceFileId: '18446744073709551615', archiveFileId: '18446744073709551615' };
  const encoded = encodeKernelArchiveModelEntry(value); assert.equal(encoded.length, 192);
  assert.equal(encoded.readBigUInt64LE(104), (1n << 64n) - 1n); assert.equal(encoded.readBigUInt64LE(112), (1n << 64n) - 1n);
  assert(encoded.subarray(Buffer.byteLength(value.path), 96).equals(Buffer.alloc(96 - Buffer.byteLength(value.path))));
  assert.equal(encoded[99], 0); assert.equal(encoded.readUInt32LE(188), 0);
  assert.equal(encoded.readBigInt64LE(176), BigInt(value.sourceCtimeSeconds)); assert.equal(encoded.readUInt32LE(184), value.sourceCtimeNanos);
  for (const change of [{ path: '../outside' }, { path: 'local-models/objects/not-a-hash' }, { sourceMode: 0o777 },
    { sourceFileId: '18446744073709551616' }, { kind: 'future-purpose' }, { ownerUid: 0x1_0000_0000 }, { authority: true },
    { sourceCtimeSeconds: '-0' }, { sourceCtimeSeconds: '9223372036854775808' }, { sourceCtimeNanos: 1_000_000_000 }])
    assert.throws(() => encodeKernelArchiveModelEntry({ ...value, ...change } as KernelArchiveModelEntry), TypeError);
});
test('inventory rejects changed, missing, duplicated or trailing records even when a caller rehashes those bytes', () => {
  const { bytes, expected } = fixture();
  const mutations = [
    Buffer.from(bytes), Buffer.from(bytes), Buffer.from(bytes), Buffer.from(bytes),
    Buffer.concat([bytes, Buffer.alloc(192)]), bytes.subarray(0, bytes.length - 1)
  ];
  mutations[0]![64 + 99] = 1; mutations[1]![64 + 188] = 1; mutations[2]!.writeUInt32LE(1001, 56);
  bytes.subarray(64, 256).copy(mutations[3]!, 256);
  for (const input of mutations) {
    const stream = new KernelArchiveModelInventoryStream({ ...expected, inventory: { ...expected.inventory, sha256: sha(input) } });
    assert.throws(() => { stream.feed(input); stream.finish(); }, TypeError);
  }
  const wrongHash = new KernelArchiveModelInventoryStream({ ...expected, inventory: { ...expected.inventory, sha256: 'a'.repeat(64) } });
  wrongHash.feed(bytes); assert.throws(() => wrongHash.finish(), TypeError);
});
test('inventory header closes the original directories and exact byte profile without accepting structural flags', () => {
  const { expected } = fixture();
  for (const change of [{ extra: true }, { inventory: { ...expected.inventory, byteCount: expected.inventory.byteCount + 1 } },
    { sourceObjectsDirectory: { ...expected.sourceObjectsDirectory, ownerUid: 1001 } },
    { archiveObjectsDirectory: { ...expected.archiveObjectsDirectory, deviceId: '2' } },
    { entryCount: 2 }, { layout: 'unverified-future-layout' }])
    assert.throws(() => decodeKernelArchiveModelStore({ ...expected, ...change }), TypeError);
  let calls = 0; const proxy = new Proxy(expected, { get() { calls++; throw new Error('caller trap'); } });
  assert.throws(() => decodeKernelArchiveModelStore(proxy), TypeError); assert.equal(calls, 0);
});
