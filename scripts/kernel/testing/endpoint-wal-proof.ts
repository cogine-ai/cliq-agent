// Test-private WAL prefix observation, not SQLite/endpoint authority or a
// durability assertion. Format: https://www.sqlite.org/fileformat2.html#wal_file_format
export type WalCommit = { frame: number; end: number; databaseSize: number; checksum: [number, number] };
export type WalProof = { generation: string; pageSize: number; validFrames: number; commits: WalCommit[] };

function checksum(bytes: Buffer, previous: [number, number], bigEndian: boolean): [number, number] {
  let [first, second] = previous;
  for (let offset = 0; offset < bytes.length; offset += 8) {
    first = (first + (bigEndian ? bytes.readUInt32BE(offset) : bytes.readUInt32LE(offset)) + second) >>> 0;
    second = (second + (bigEndian ? bytes.readUInt32BE(offset + 4) : bytes.readUInt32LE(offset + 4)) + first) >>> 0;
  }
  return [first, second];
}

export function inspectWal(bytes: Uint8Array): WalProof | null {
  const wal = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (wal.length < 32) return null;
  const magic = wal.readUInt32BE(0);
  if ((magic !== 0x377f0682 && magic !== 0x377f0683) || wal.readUInt32BE(4) !== 3007000) return null;
  // Unlike the database's 2-byte header, the WAL uses literal 65536; 1 is invalid.
  const pageSize = wal.readUInt32BE(8);
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1))) return null;
  const bigEndian = magic === 0x377f0683;
  let state = checksum(wal.subarray(0, 24), [0, 0], bigEndian);
  if (state[0] !== wal.readUInt32BE(24) || state[1] !== wal.readUInt32BE(28)) return null;
  const proof: WalProof = { generation: wal.subarray(0, 32).toString('hex'), pageSize, validFrames: 0, commits: [] };
  const frameSize = 24 + proof.pageSize;
  for (let offset = 32; offset + frameSize <= wal.length; offset += frameSize) {
    if (wal.readUInt32BE(offset) === 0) break;
    if (!wal.subarray(offset + 8, offset + 16).equals(wal.subarray(16, 24))) break;
    const headerState = checksum(wal.subarray(offset, offset + 8), state, bigEndian);
    const next = checksum(wal.subarray(offset + 24, offset + frameSize), headerState, bigEndian);
    if (next[0] !== wal.readUInt32BE(offset + 16) || next[1] !== wal.readUInt32BE(offset + 20)) break;
    state = next;
    proof.validFrames++;
    const databaseSize = wal.readUInt32BE(offset + 4);
    if (databaseSize) proof.commits.push({ frame: proof.validFrames, end: offset + frameSize,
      databaseSize, checksum: next });
  }
  return proof;
}
