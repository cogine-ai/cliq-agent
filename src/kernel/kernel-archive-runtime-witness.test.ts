import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeKernelArchiveRuntimeWitnesses, encodeCurrentRuntimeWitnessArchive, encodeRuntimeWitnessArchiveEntry } from './kernel-archive-runtime-witness.js';

const source = { deviceId: '17', fileId: '42', ownerUid: 123 };
const sha256 = 'a'.repeat(64);
const summary = {
  kind: 'captured', layout: 'cliq-local-inference-witness-pack-v1', sourceDirectory: source,
  entryCount: 1, totalWitnessBytes: 8288,
  pack: { file: { ...source, fileId: '43' }, byteCount: 8576, sha256 }
} as const;

test('runtime witness pack selection binds exact source, target, totals and digest', () => {
  const header = encodeCurrentRuntimeWitnessArchive(decodeKernelArchiveRuntimeWitnesses(summary));
  assert.equal(header.length, 104);
  assert.equal(header.subarray(0, 8).toString('ascii'), 'CLQMW001');
  assert.deepEqual(Array.from({ length: 7 }, (_, index) => header.readBigUInt64LE(8 + 8 * index)),
    [17n, 42n, 17n, 43n, 1n, 8288n, 8576n]);
  assert.equal(header.readUInt32LE(64), 123);
  assert.equal(header.readUInt32LE(68), 0);
  assert.equal(header.subarray(72).toString('hex'), sha256);
  for (const other of [
    { ...summary, totalWitnessBytes: 8289 },
    { ...summary, entryCount: 2 },
    { ...summary, pack: { ...summary.pack, byteCount: 8575 } },
    { ...summary, pack: { ...summary.pack, file: source } },
    { ...summary, pack: { ...summary.pack, file: { ...source, deviceId: '18', fileId: '43' } } },
    { ...summary, extra: true }
  ]) assert.throws(() => decodeKernelArchiveRuntimeWitnesses(other), TypeError);
});

test('runtime witness pack entry is closed and retains both exact typed source references', () => {
  const entry = { nativeNonce: 'b'.repeat(64), launchId: 'x'.repeat(43), sourceFileId: '104', byteCount: 4144,
    sha256, nativeInputRef: 'c'.repeat(64), retirementEvidenceRef: 'd'.repeat(64), retirementKind: 'death',
    sourceCtimeSeconds: '-42', sourceCtimeNanos: 71 } as const;
  const bytes = encodeRuntimeWitnessArchiveEntry(entry);
  assert.equal(bytes.length, 224);
  assert.equal(bytes.subarray(0, 32).toString('hex'), entry.nativeNonce);
  assert.equal(bytes.subarray(32, 75).toString('ascii'), entry.launchId);
  assert.deepEqual(bytes.subarray(75, 80), Buffer.alloc(5));
  assert.equal(bytes.readBigUInt64LE(80), 104n);
  assert.equal(bytes.readBigUInt64LE(88), 4144n);
  assert.equal(bytes.subarray(96, 128).toString('hex'), sha256);
  assert.equal(bytes.subarray(128, 160).toString('hex'), entry.nativeInputRef);
  assert.equal(bytes.subarray(160, 192).toString('hex'), entry.retirementEvidenceRef);
  assert.equal(bytes.readBigInt64LE(192), -42n);
  assert.equal(bytes.readUInt32LE(200), 71);
  assert.equal(bytes[204], 2);
  assert.deepEqual(bytes.subarray(205), Buffer.alloc(19));
  assert.equal(encodeRuntimeWitnessArchiveEntry({ ...entry, retirementKind: 'no_spawn' })[204], 1);
  for (const other of [
    { ...entry, byteCount: 4143 },
    { ...entry, sourceFileId: '0' },
    { ...entry, sourceCtimeSeconds: '9223372036854775808' },
    { ...entry, sourceCtimeNanos: 1_000_000_000 },
    { ...entry, launchId: entry.launchId + 'y' },
    { ...entry, otherRef: sha256 }
  ]) assert.throws(() => encodeRuntimeWitnessArchiveEntry(other), TypeError);
});
