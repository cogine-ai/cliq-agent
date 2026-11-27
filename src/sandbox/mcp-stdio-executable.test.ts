// Synthetic ELF bytes only. No file is executed or promoted to a signed image.
import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectMcpStaticLinuxExecutable } from './mcp-stdio-executable.js';
function staticElf() {
  const bytes = Buffer.alloc(512);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(bytes);
  bytes.writeUInt16LE(2, 16); bytes.writeUInt16LE(62, 18); bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(0x400080n, 24); bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52); bytes.writeUInt16LE(56, 54); bytes.writeUInt16LE(1, 56);
  bytes.writeUInt32LE(1, 64); bytes.writeUInt32LE(5, 68); bytes.writeBigUInt64LE(0x400000n, 80);
  bytes.writeBigUInt64LE(512n, 96); bytes.writeBigUInt64LE(512n, 104); bytes.writeBigUInt64LE(0x1000n, 112);
  return bytes;
}
test('the first stdio image requires a complete static x64 ELF with a retained executable entry', () => {
  const bytes = staticElf(), before = Buffer.from(bytes), facts = inspectMcpStaticLinuxExecutable(bytes);
  assert.deepEqual(facts, { format: 'cliq-mcp-static-linux-executable-v1', architecture: 'x86_64', byteCount: 512, entryAddress: '400080' });
  assert(Object.isFrozen(facts)); assert.deepEqual(bytes, before);
  for (const mutate of [
    (data: Buffer) => data.writeUInt16LE(3, 16), (data: Buffer) => data.writeUInt16LE(183, 18),
    (data: Buffer) => data.writeUInt32LE(2, 64), (data: Buffer) => data.writeUInt32LE(3, 64),
    (data: Buffer) => data.writeBigUInt64LE(513n, 96), (data: Buffer) => data.writeBigUInt64LE(511n, 104),
    (data: Buffer) => data.writeUInt32LE(4, 68), (data: Buffer) => data.writeBigUInt64LE(0x500000n, 24),
    (data: Buffer) => data.writeBigUInt64LE(0xffffffffffffffffn, 32), (data: Buffer) => data.writeBigUInt64LE(3n, 112),
  ]) { const changed = staticElf(); mutate(changed); assert.throws(() => inspectMcpStaticLinuxExecutable(changed)); }
  assert.throws(() => inspectMcpStaticLinuxExecutable(bytes.subarray(0, 100)));
  let traps = 0;
  assert.throws(() => inspectMcpStaticLinuxExecutable(new Proxy(bytes, { get() { traps++; throw 0; } })));
  assert.equal(traps, 0);
});
