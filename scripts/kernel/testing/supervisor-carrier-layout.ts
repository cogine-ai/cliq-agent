// Fixed Linux-x64 carrier experiment only, not an ELF loader or authority.
// This module never edits executable bytes. Production loader checks remain
// independent, as do actual Node/SEA/guest/installed qualification.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const MAX_BYTES = 268_435_456, FUSE = Buffer.from('NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:0');
type Section = Readonly<{ name: string; type: number; flags: bigint; address: bigint; offset: number; size: number }>;
type Program = Readonly<{ type: number; offset: number; size: number }>;
type Layout = Readonly<{ bytes: Buffer; header: Buffer; programs: readonly Program[];
  programBytes: Buffer; sections: readonly Section[] }>;
function layout(bytes: Buffer): Layout {
  assert(Buffer.isBuffer(bytes) && bytes.length >= 64 && bytes.length <= MAX_BYTES, 'carrier ELF size is outside the fixed experiment bound');
  assert(bytes.subarray(0, 7).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1])) &&
    bytes.readUInt16LE(16) === 2 && bytes.readUInt16LE(18) === 62 && bytes.readUInt32LE(20) === 1 &&
    bytes.readUInt16LE(52) === 64, 'carrier must be the fixed ELF64 little-endian Linux x64 executable');
  const integer = (at: number): number => {
    const value = bytes.readBigUInt64LE(at);
    assert(value <= BigInt(Number.MAX_SAFE_INTEGER), 'carrier ELF integer exceeds the bounded parser');
    return Number(value);
  };
  const extent = (offset: number, size: number): Buffer => {
    assert(offset >= 0 && size >= 0 && offset <= bytes.length && size <= bytes.length - offset, 'carrier ELF extent is outside the complete file');
    return bytes.subarray(offset, offset + size);
  };
  const phoff = integer(32), shoff = integer(40), phnum = bytes.readUInt16LE(56), shnum = bytes.readUInt16LE(60), namesIndex = bytes.readUInt16LE(62);
  assert(bytes.readUInt16LE(54) === 56 && bytes.readUInt16LE(58) === 64 && phnum > 0 && phnum <= 64 &&
    shnum > 0 && shnum <= 512 && namesIndex > 0 && namesIndex < shnum, 'carrier ELF tables exceed the fixed non-extended format');
  const programBytes = extent(phoff, phnum * 56); extent(shoff, shnum * 64);
  const programs = Array.from({ length: phnum }, (_, index): Program => {
    const at = phoff + index * 56, type = bytes.readUInt32LE(at), offset = integer(at + 8), size = integer(at + 32);
    extent(offset, size);
    assert(type !== 1 || bytes.readBigUInt64LE(at + 40) >= BigInt(size), 'carrier LOAD memory extent is smaller than its file extent');
    return { type, offset, size };
  });
  assert(programs.some(program => program.type === 1), 'carrier has no LOAD extent');
  const namesAt = shoff + namesIndex * 64;
  assert(bytes.readUInt32LE(namesAt + 4) === 3, 'carrier section names must be a string table');
  const names = extent(integer(namesAt + 24), integer(namesAt + 32));
  assert(names.length > 0 && names.length <= 65_536 && names[0] === 0, 'carrier section names exceed the fixed bound');
  const sections = Array.from({ length: shnum }, (_, index): Section => {
    const at = shoff + index * 64, start = bytes.readUInt32LE(at), end = names.indexOf(0, start);
    assert(start < names.length && end >= start && end - start <= 128, 'carrier section name is incomplete');
    const name = names.subarray(start, end).toString('latin1');
    assert(/^[A-Za-z0-9_.-]*$/u.test(name), 'carrier section name is not a fixed ASCII identifier');
    const type = bytes.readUInt32LE(at + 4), flags = bytes.readBigUInt64LE(at + 8), address = bytes.readBigUInt64LE(at + 16);
    const offset = integer(at + 24), size = integer(at + 32);
    if (type !== 8) extent(offset, size);
    return { name, type, flags, address, offset, size };
  });
  assert(sections[0]!.name === '' && sections[0]!.type === 0 && new Set(sections.map(section => section.name)).size === sections.length,
    'carrier section identities are not unique');
  const fuse = bytes.indexOf(FUSE);
  assert(fuse >= 0 && bytes.indexOf(FUSE, fuse + 1) === -1 && programs.some(program => program.type === 1 &&
    fuse >= program.offset && FUSE.length <= program.offset + program.size - fuse), 'carrier must preserve its unique original SEA fuse inside LOAD');
  // These are exactly e_shoff, e_shnum and e_shstrndx. No program-header,
  // entrypoint, architecture or other loaded-header field may change.
  const header = Buffer.from(bytes.subarray(0, 64)); header.fill(0, 40, 48); header.fill(0, 60, 64);
  return { bytes, header, programs, programBytes, sections };
}
const removable = (name: string) => name.startsWith('.debug_') || name === '.symtab' || name === '.strtab';
function normalizedExtent(input: Layout, program: Program): Buffer {
  const value = Buffer.from(input.bytes.subarray(program.offset, program.offset + program.size));
  for (const [start, end] of [[40, 48], [60, 64]]) {
    const left = Math.max(start!, program.offset), right = Math.min(end!, program.offset + program.size);
    if (left < right) value.fill(0, left - program.offset, right - program.offset);
  }
  return value;
}

/** Only a smaller, structurally preserved experiment may be executed. This
 * does not verify signatures, Node behavior, SEA injection or guest loading. */
export function compareSupervisorCarrierLayout(original: Buffer, candidate: Buffer, mode: 'debug' | 'static') {
  assert(mode === 'debug' || mode === 'static', 'unknown fixed carrier experiment');
  const before = layout(original), after = layout(candidate);
  assert(candidate.length < original.length, 'strip must actually reduce the carrier, not silently copy an unsupported input');
  assert(before.header.equals(after.header) && before.programBytes.equals(after.programBytes), 'carrier runtime header or program headers changed');
  for (const program of before.programs)
    assert(normalizedExtent(before, program).equals(normalizedExtent(after, program)), 'carrier LOAD, interpreter, notes or dynamic extent changed');
  const removedSections: string[] = [];
  for (const section of before.sections) {
    const current = after.sections.find(value => value.name === section.name);
    if (removable(section.name)) {
      assert(!(section.flags & 2n) && !before.programs.some(program => program.size && section.size &&
        section.offset < program.offset + program.size && program.offset < section.offset + section.size),
      'removable carrier metadata intersects a runtime extent');
      if (!current) removedSections.push(section.name);
      continue;
    }
    assert(current && current.type === section.type && current.flags === section.flags && current.address === section.address,
      'strip removed or changed a retained carrier section');
    if (section.name !== '.shstrtab') {
      assert(current.size === section.size, 'strip resized a retained carrier section');
      if (section.type !== 8) assert(before.bytes.subarray(section.offset, section.offset + section.size).equals(
        after.bytes.subarray(current.offset, current.offset + current.size)), 'strip changed retained section bytes');
    }
  }
  assert(after.sections.every(section => before.sections.some(value => value.name === section.name)), 'strip added an unexpected section');
  assert(before.sections.some(section => section.name.startsWith('.debug_')) && !after.sections.some(section => section.name.startsWith('.debug_')),
    'strip-debug did not remove all original debug sections');
  if (mode === 'static') assert(!after.sections.some(section => section.name === '.symtab' || section.name === '.strtab'),
    'strip-all did not remove the static symbol and string tables');
  return Object.freeze({ structureOnly: true as const, originalByteCount: original.length, candidateByteCount: candidate.length,
    savedBytes: original.length - candidate.length, unchangedLoadBytes: before.programs.filter(program => program.type === 1).reduce((sum, program) => sum + program.size, 0),
    programHeaders: before.programs.length, removedSections: Object.freeze(removedSections),
    originalSha256: createHash('sha256').update(original).digest('hex'), candidateSha256: createHash('sha256').update(candidate).digest('hex') });
}
