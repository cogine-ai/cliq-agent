import assert from 'node:assert/strict';
import test from 'node:test';
import { planGuestElfStringFixtures } from './guest-elf-fixtures.js';

// Ordinary ELF byte fixtures only. They are neither executable release images
// nor native owners, StateOwners, admissions, permissions or recovery proofs.
function elf(): Buffer {
  const bytes = Buffer.alloc(2 * 1024 * 1024 + 4096);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(2, 16); bytes.writeUInt16LE(62, 18); bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32); bytes.writeUInt16LE(64, 52); bytes.writeUInt16LE(56, 54); bytes.writeUInt16LE(4, 56);
  const ph = (index: number, type: number, offset: number, address: number, size: number) => {
    const at = 64 + index * 56; bytes.writeUInt32LE(type, at); bytes.writeUInt32LE(4, at + 4);
    bytes.writeBigUInt64LE(BigInt(offset), at + 8); bytes.writeBigUInt64LE(BigInt(address), at + 16);
    bytes.writeBigUInt64LE(BigInt(size), at + 32); bytes.writeBigUInt64LE(BigInt(size), at + 40); bytes.writeBigUInt64LE(1n, at + 48);
  };
  ph(0, 1, 0, 0x400000, bytes.length); ph(1, 2, 512, 0x400200, 640);
  ph(2, 3, 320, 0x400140, 28); ph(3, 4, 400, 0x400190, 16);
  bytes.write('/lib64/ld-linux-x86-64.so.2\0', 320, 'ascii');
  const entry = (index: number, tag: bigint, value: bigint) => {
    bytes.writeBigInt64LE(tag, 512 + index * 16); bytes.writeBigUInt64LE(value, 520 + index * 16);
  };
  entry(0, 5n, 0x400000n + 2048n); entry(1, 10n, BigInt(2 * 1024 * 1024));
  entry(2, 1n, 1n); entry(3, 21n, 0n); entry(4, 0n, 0n);
  bytes.write('libc.so.6\0', 2049, 'ascii'); return bytes;
}

test('ELF malformed plans preserve the source bytes and target exact independent guard branches', () => {
  const original = elf(), before = Buffer.from(original), plan = planGuestElfStringFixtures(original);
  assert.equal(plan.stringTableBytes, 2 * 1024 * 1024);
  assert.equal(plan.neededCount, 1);
  assert.deepEqual(plan.cases.map(value => value.id), ['missing_strtab', 'missing_strsz', 'duplicate_strtab', 'duplicate_strsz',
    'zero_strsz', 'missing_dynamic_null', 'string_address_overflow', 'string_extent_outside_load', 'string_extent_outside_file',
    'load_extent_outside_file', 'duplicate_string_load', 'overlapping_string_load', 'aliased_string_file_range',
    'needed_offset_outside', 'needed_name_unterminated', 'needed_name_path', 'needed_name_empty', 'needed_count_overflow']);
  for (const scenario of plan.cases) {
    assert(scenario.patches.length > 0);
    for (const patch of scenario.patches) assert(patch.offset >= 0 && patch.bytes.length > 0 && patch.offset + patch.bytes.length <= original.length);
  }
  assert.deepEqual(original, before);
  const apply = (id: string) => {
    const mutated = Buffer.from(original);
    for (const patch of plan.cases.find(value => value.id === id)!.patches) patch.bytes.copy(mutated, patch.offset);
    return mutated;
  };
  assert.equal(apply('zero_strsz').readBigUInt64LE(536), 0n);
  assert.equal(apply('needed_offset_outside').readBigUInt64LE(552), 2n * 1024n * 1024n);
  assert.equal(apply('needed_name_unterminated').subarray(2048, 2304).includes(0), false);
  assert.equal(apply('needed_name_path').subarray(2048, 2061).toString('ascii'), '../libc.so.6\0');
  const overflow = apply('needed_count_overflow');
  assert.equal(Array.from({ length: 33 }, (_, index) => overflow.readBigInt64LE(512 + (index + 2) * 16)).every(tag => tag === 1n), true);
  assert.equal(overflow.readBigInt64LE(512 + 35 * 16), 0n);
});

test('ELF byte-plan construction rejects malformed originals rather than inventing a matching layout', () => {
  const wrongClass = elf(); wrongClass[4] = 1;
  const noTable = elf(); noTable.writeBigInt64LE(21n, 512);
  const outside = elf(); outside.writeBigUInt64LE(0xffffffffffffffffn, 32);
  for (const bytes of [Buffer.alloc(63), wrongClass, noTable, outside]) assert.throws(() => planGuestElfStringFixtures(bytes));
});
