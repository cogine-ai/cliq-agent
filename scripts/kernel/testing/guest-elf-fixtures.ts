import assert from 'node:assert/strict';

export interface GuestElfPatch { offset: number; bytes: Buffer }
export interface GuestElfStringCase {
  id: string;
  expectedCode: 'guest_elf_strings' | 'guest_elf_string_alias' | 'guest_elf_segment' |
    'guest_needed_bounds' | 'guest_needed_name' | 'guest_needed_count';
  patches: GuestElfPatch[];
}

/** Byte mutations of an already measured ELF, not a loader or execution proof.
 * The actual native owner must independently reject every complete ext4 input. */
export function planGuestElfStringFixtures(input: Uint8Array): {
  stringTableBytes: number; neededCount: number; cases: GuestElfStringCase[];
} {
  const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  assert(bytes.length >= 64 && bytes.subarray(0, 7).equals(Buffer.from([0x7f, 69, 76, 70, 2, 1, 1])));
  assert([2, 3].includes(bytes.readUInt16LE(16)) && bytes.readUInt16LE(18) === 62 && bytes.readUInt32LE(20) === 1);
  assert.equal(bytes.readUInt16LE(52), 64); assert.equal(bytes.readUInt16LE(54), 56);
  function bounded(value: bigint) { assert(value <= BigInt(bytes.length)); return Number(value); }
  const phoff = bounded(bytes.readBigUInt64LE(32)), phnum = bytes.readUInt16LE(56);
  assert(phnum > 0 && phnum <= 128 && phoff + phnum * 56 <= bytes.length);
  const headers = Array.from({ length: phnum }, (_, index) => {
    const at = phoff + index * 56;
    return { at, type: bytes.readUInt32LE(at), offset: bounded(bytes.readBigUInt64LE(at + 8)),
      address: bytes.readBigUInt64LE(at + 16), size: bounded(bytes.readBigUInt64LE(at + 32)),
      memory: bytes.readBigUInt64LE(at + 40) };
  });
  for (const header of headers) assert(header.offset + header.size <= bytes.length);
  const dynamics = headers.filter(header => header.type === 2);
  assert.equal(dynamics.length, 1); const dynamic = dynamics[0]!;
  assert(dynamic.size >= 36 * 16 && dynamic.size % 16 === 0 && dynamic.size / 16 <= 4096);
  const allEntries = Array.from({ length: dynamic.size / 16 }, (_, index) => {
    const at = dynamic.offset + index * 16;
    return { at, tag: bytes.readBigInt64LE(at), value: bytes.readBigUInt64LE(at + 8) };
  });
  const end = allEntries.findIndex(entry => entry.tag === 0n); assert(end >= 0);
  const entries = allEntries.slice(0, end), addresses = entries.filter(entry => entry.tag === 5n), sizes = entries.filter(entry => entry.tag === 10n);
  assert.equal(addresses.length, 1); assert.equal(sizes.length, 1);
  const address = addresses[0]!, size = sizes[0]!, stringBytes = bounded(size.value); assert(stringBytes >= 256);
  const needed = entries.filter(entry => entry.tag === 1n); assert(needed.length > 0 && needed.length <= 32);
  assert(needed.every(entry => entry.value < size.value));
  const loads = headers.filter(header => header.type === 1);
  const containing = loads.filter(header => address.value >= header.address && address.value - header.address <= BigInt(header.size) &&
    size.value <= BigInt(header.size) - (address.value - header.address));
  assert.equal(containing.length, 1); const load = containing[0]!;
  const tableOffset = load.offset + Number(address.value - load.address); assert(tableOffset + stringBytes <= bytes.length);
  const spare = headers.find(header => ![1, 2, 3].includes(header.type)); assert(spare);
  const spareEntry = entries.find(entry => ![1n, 5n, 10n].includes(entry.tag)); assert(spareEntry);
  const u64 = (offset: number, value: bigint): GuestElfPatch => {
    const result = Buffer.alloc(8); result.writeBigUInt64LE(value); return { offset, bytes: result };
  };
  const tag = (offset: number, value: bigint) => u64(offset, value);
  function alias(offset: bigint, virtual: bigint, extent: bigint): GuestElfPatch {
    const result = Buffer.alloc(56); result.writeUInt32LE(1); result.writeUInt32LE(4, 4);
    result.writeBigUInt64LE(offset, 8); result.writeBigUInt64LE(virtual, 16);
    result.writeBigUInt64LE(extent, 32); result.writeBigUInt64LE(extent, 40); result.writeBigUInt64LE(1n, 48);
    return { offset: spare!.at, bytes: result };
  }
  const cases: GuestElfStringCase[] = [];
  function add(id: string, expectedCode: GuestElfStringCase['expectedCode'], ...patches: GuestElfPatch[]) {
    for (const patch of patches) assert(patch.offset >= 0 && patch.bytes.length > 0 && patch.offset + patch.bytes.length <= bytes.length);
    cases.push({ id, expectedCode, patches });
  }
  add('missing_strtab', 'guest_elf_strings', tag(address.at, 21n));
  add('missing_strsz', 'guest_elf_strings', tag(size.at, 21n));
  add('duplicate_strtab', 'guest_elf_strings', tag(spareEntry.at, 5n), u64(spareEntry.at + 8, address.value));
  add('duplicate_strsz', 'guest_elf_strings', tag(spareEntry.at, 10n), u64(spareEntry.at + 8, size.value));
  add('zero_strsz', 'guest_elf_strings', u64(size.at + 8, 0n));
  add('missing_dynamic_null', 'guest_elf_strings', ...allEntries.filter(entry => entry.tag === 0n).map(entry => tag(entry.at, 21n)));
  add('string_address_overflow', 'guest_elf_strings', u64(address.at + 8, 0xffffffffffffffffn));
  add('string_extent_outside_load', 'guest_elf_strings', u64(size.at + 8, BigInt(load.size) - (address.value - load.address) + 1n));
  add('string_extent_outside_file', 'guest_elf_strings', u64(size.at + 8, BigInt(bytes.length - tableOffset + 1)));
  add('load_extent_outside_file', 'guest_elf_segment', u64(load.at + 32, BigInt(bytes.length - load.offset + 1)));
  add('duplicate_string_load', 'guest_elf_string_alias', alias(BigInt(load.offset), load.address, BigInt(load.size)));
  add('overlapping_string_load', 'guest_elf_string_alias', alias(0n, address.value + 1n, 1n));
  const finalAddress = loads.reduce((max, header) => header.address + header.memory > max ? header.address + header.memory : max, 0n);
  add('aliased_string_file_range', 'guest_elf_string_alias', alias(BigInt(tableOffset + 1), finalAddress + 4096n, 1n));
  add('needed_offset_outside', 'guest_needed_bounds', u64(needed[0]!.at + 8, size.value));
  add('needed_name_unterminated', 'guest_needed_name', u64(needed[0]!.at + 8, 0n), { offset: tableOffset, bytes: Buffer.alloc(256, 65) });
  add('needed_name_path', 'guest_needed_name', u64(needed[0]!.at + 8, 0n), { offset: tableOffset, bytes: Buffer.from('../libc.so.6\0', 'ascii') });
  add('needed_name_empty', 'guest_needed_name', u64(needed[0]!.at + 8, 0n), { offset: tableOffset, bytes: Buffer.from([0]) });
  const overflow = Buffer.alloc(dynamic.size);
  overflow.writeBigInt64LE(5n); overflow.writeBigUInt64LE(address.value, 8);
  overflow.writeBigInt64LE(10n, 16); overflow.writeBigUInt64LE(size.value, 24);
  for (let index = 0; index < 33; index++) {
    overflow.writeBigInt64LE(1n, (index + 2) * 16); overflow.writeBigUInt64LE(needed[0]!.value, (index + 2) * 16 + 8);
  }
  add('needed_count_overflow', 'guest_needed_count', { offset: dynamic.offset, bytes: overflow });
  return { stringTableBytes: stringBytes, neededCount: needed.length, cases };
}
