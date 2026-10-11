import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectWal } from './endpoint-wal-proof.js';

// Worked from SQLite's published WAL checksum recurrence using independent
// BigInt arithmetic. Headers/checksums are literals, never emitted by inspectWal.
// https://www.sqlite.org/fileformat2.html#wal_file_format
const littleHeader = '377f0682002de218000002000000000711223344556677881ffe2524674f631e';
function littleWal(): Buffer {
  return Buffer.concat([
    Buffer.from(littleHeader, 'hex'),
    Buffer.from('00000001000000011122334455667788678c41f28d1fa4a6', 'hex'),
    Buffer.from(Array.from({ length: 512 }, (_, i) => i & 255)),
    Buffer.from('00000002000000001122334455667788dac4413992493396', 'hex'),
    Buffer.alloc(512, 0xab),
    Buffer.from('00000001000000021122334455667788a4fb66593597d863', 'hex'),
    Buffer.alloc(512, 0xcd),
  ]);
}

test('a little-endian WAL exposes only checksum-verified commit frames', () => {
  assert.deepEqual(inspectWal(littleWal()), {
    generation: littleHeader, pageSize: 512, validFrames: 3,
    commits: [
      { frame: 1, end: 568, databaseSize: 1, checksum: [0x678c41f2, 0x8d1fa4a6] },
      { frame: 3, end: 1640, databaseSize: 2, checksum: [0xa4fb6659, 0x3597d863] },
    ],
  });
});

test('WAL magic selects big-endian checksum input, while stored checksums remain big-endian', () => {
  const header = '377f0683002de218000002000000000711223344556677882726fe2223664f6a';
  const wal = Buffer.concat([
    Buffer.from(header, 'hex'),
    Buffer.from('00000001000000011122334455667788b307570c8409047f', 'hex'),
    Buffer.from(Array.from({ length: 512 }, (_, i) => i & 255)),
    Buffer.from('0000000200000000112233445566778830bb2f80f06ccffb', 'hex'),
    Buffer.alloc(512, 0xab),
    Buffer.from('00000001000000021122334455667788562e96562888392c', 'hex'),
    Buffer.alloc(512, 0xcd),
  ]);
  assert.deepEqual(inspectWal(wal), {
    generation: header, pageSize: 512, validFrames: 3,
    commits: [
      { frame: 1, end: 568, databaseSize: 1, checksum: [0xb307570c, 0x8409047f] },
      { frame: 3, end: 1640, databaseSize: 2, checksum: [0x562e9656, 0x2888392c] },
    ],
  });
});

test('WAL page size is a literal power of two from 512 through 65536, not the database-header sentinel', () => {
  // These invalid page-size headers still carry correct header checksums.
  for (const header of [
    '377f0682002de218000000000000000711223344556677881ffa25246749631e',
    '377f0682002de2180000000100000007112233445566778821fa25246a49631e',
    '377f0682002de218000001ff0000000711223344556677881dfc2524644c631e',
    '377f0682002de2180000020100000007112233445566778821fe25246a4f631e',
    '377f0682002de218000200000000000711223344556677881ffa29246749691e',
  ]) assert.equal(inspectWal(Buffer.from(header, 'hex')), null);
  const header = '377f0682002de218000100000000000711223344556677881ffa27246749661e';
  assert.deepEqual(inspectWal(Buffer.concat([
    Buffer.from(header, 'hex'),
    Buffer.from('000000010000000111223344556677883b11833caf3836ac', 'hex'),
    Buffer.alloc(65536, 0x5a),
  ])), {
    generation: header, pageSize: 65536, validFrames: 1,
    commits: [{ frame: 1, end: 65592, databaseSize: 1, checksum: [0x3b11833c, 0xaf3836ac] }],
  });
});

test('torn pages, foreign salts and bad rolling checksums cannot complete a new commit', () => {
  const original = littleWal();
  const prefix = inspectWal(original)!;
  for (const end of [1104, 1127, original.length - 1]) {
    const cut = inspectWal(original.subarray(0, end))!;
    assert.equal(cut.commits.length, 1); assert.equal(cut.validFrames, 2);
  }
  for (const offset of [1104 + 8, 1104 + 16, 1104 + 24]) {
    const corrupt = Buffer.from(original); corrupt[offset] = corrupt[offset]! ^ 1;
    const cut = inspectWal(corrupt)!;
    assert.deepEqual(cut.commits, prefix.commits.slice(0, 1)); assert.equal(cut.validFrames, 2);
  }
  const corrupt = Buffer.from(original); corrupt[24] = corrupt[24]! ^ 1;
  assert.equal(inspectWal(corrupt), null);
});

test('a checksum-valid frame for page zero is not a valid SQLite commit', () => {
  const wal = Buffer.concat([Buffer.from(littleHeader, 'hex'),
    Buffer.from('00000000000000011122334455667788858c41f2e61fa4a6', 'hex'),
    Buffer.from(Array.from({ length: 512 }, (_, i) => i & 255))]);
  assert.deepEqual(inspectWal(wal), { generation: littleHeader, pageSize: 512, validFrames: 0, commits: [] });
});
