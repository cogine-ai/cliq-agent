// ELF bytes only. These values are not executable images, loader acceptance,
// signatures, installed runtime authority or evidence of a READY deadline.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

async function compare(original: Buffer, candidate: Buffer, mode: 'debug' | 'static' = 'static') {
  const module = await import('./supervisor-carrier-layout.js').catch(() => undefined);
  assert.equal(typeof module?.compareSupervisorCarrierLayout, 'function', 'the experiment must compare the preserved ELF layout before execution');
  return module!.compareSupervisorCarrierLayout(original, candidate, mode);
}
function fixture(stripped: boolean): Buffer {
  const names = stripped ? ['', '.text', '.note.test', '.dynamic', '.shstrtab']
    : ['', '.text', '.note.test', '.dynamic', '.debug_info', '.symtab', '.strtab', '.shstrtab'];
  const strings = Buffer.from(names.join('\0') + '\0'), shoff = stripped ? 512 : 640;
  const bytes = Buffer.alloc(shoff + names.length * 64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(2, 16); bytes.writeUInt16LE(62, 18); bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(256n, 24); bytes.writeBigUInt64LE(64n, 32); bytes.writeBigUInt64LE(BigInt(shoff), 40);
  bytes.writeUInt16LE(64, 52); bytes.writeUInt16LE(56, 54); bytes.writeUInt16LE(3, 56);
  bytes.writeUInt16LE(64, 58); bytes.writeUInt16LE(names.length, 60); bytes.writeUInt16LE(names.length - 1, 62);
  for (const [index, type, offset, length, flags] of [[0, 1, 0, 448, 5], [1, 4, 384, 32, 4], [2, 2, 416, 32, 6]]) {
    const at = 64 + index! * 56;
    bytes.writeUInt32LE(type!, at); bytes.writeUInt32LE(flags!, at + 4);
    bytes.writeBigUInt64LE(BigInt(offset!), at + 8); bytes.writeBigUInt64LE(BigInt(0x400000 + offset!), at + 16);
    bytes.writeBigUInt64LE(BigInt(0x400000 + offset!), at + 24);
    bytes.writeBigUInt64LE(BigInt(length!), at + 32); bytes.writeBigUInt64LE(BigInt(length!), at + 40);
    bytes.writeBigUInt64LE(type === 1 ? 4096n : 8n, at + 48);
  }
  bytes.fill(0x11, 256, 384); bytes.fill(0x22, 384, 416); bytes.fill(0x33, 416, 448);
  bytes.write('NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:0', 264, 'ascii');
  const stringOffset = stripped ? 448 : 528; strings.copy(bytes, stringOffset);
  const layout: Record<string, [number, number, number, number]> = {
    '.text': [1, 6, 256, 128], '.note.test': [7, 2, 384, 32], '.dynamic': [6, 3, 416, 32],
    '.debug_info': [1, 0, 448, 32], '.symtab': [2, 0, 480, 24], '.strtab': [3, 0, 504, 24],
    '.shstrtab': [3, 0, stringOffset, strings.length],
  };
  for (const [index, name] of names.entries()) {
    if (!index) continue;
    const at = shoff + index * 64, [type, flags, offset, length] = layout[name]!;
    bytes.writeUInt32LE(strings.indexOf(Buffer.from(name + '\0')), at);
    bytes.writeUInt32LE(type, at + 4); bytes.writeBigUInt64LE(BigInt(flags), at + 8);
    bytes.writeBigUInt64LE(BigInt(flags & 2 ? 0x400000 + offset : 0), at + 16);
    bytes.writeBigUInt64LE(BigInt(offset), at + 24); bytes.writeBigUInt64LE(BigInt(length), at + 32);
    bytes.writeBigUInt64LE(1n, at + 48);
  }
  return bytes;
}

test('a smaller experimental carrier preserves all LOAD, notes, dynamic bytes and the SEA fuse', async () => {
  const result = await compare(fixture(false), fixture(true));
  assert.equal(result.originalByteCount, 1152);
  assert.equal(result.candidateByteCount, 832);
  assert.equal(result.savedBytes, 320);
  assert.equal(result.unchangedLoadBytes, 448);
  assert.equal(result.structureOnly, true);
  assert.deepEqual(result.removedSections, ['.debug_info', '.symtab', '.strtab']);
  assert(Object.isFrozen(result) && Object.isFrozen(result.removedSections));
});

test('unchanged copies and every runtime byte or runtime header mutation fail before execution', async () => {
  const original = fixture(false);
  await assert.rejects(compare(original, Buffer.from(original)), /actually reduce/u);
  for (const offset of [24, 32, 54, 56, 64 + 4, 64 + 8, 256, 384, 416]) {
    const candidate = fixture(true); candidate[offset] = candidate[offset]! ^ 1;
    await assert.rejects(compare(original, candidate), { name: 'AssertionError' }, 'runtime mutation must never pass the structural gate');
  }
  const fuse = fixture(true); fuse[264 + 44] = 0x31;
  await assert.rejects(compare(original, fuse), /fuse|extent changed/u);
});

test('truncated, foreign, oversized-table and malformed section data are rejected', async () => {
  const original = fixture(false);
  for (const candidate of [Buffer.alloc(0), fixture(true).subarray(0, 63), fixture(true).subarray(0, 700)])
    await assert.rejects(compare(original, candidate), { name: 'AssertionError' });
  for (const [offset, width, value] of [[18, 2, 183], [56, 2, 65], [60, 2, 513], [62, 2, 0], [58, 2, 0]]) {
    const candidate = fixture(true); candidate.writeUIntLE(value!, offset!, width!);
    await assert.rejects(compare(original, candidate), { name: 'AssertionError' });
  }
  const outOfFile = fixture(true); outOfFile.writeBigUInt64LE(0xffffffffffffffffn, 40);
  await assert.rejects(compare(original, outOfFile), { name: 'AssertionError' });
  const duplicate = fixture(true); duplicate.writeUInt32LE(1, 512 + 2 * 64);
  await assert.rejects(compare(original, duplicate), /identities/u);
  const renamed = fixture(true); renamed.write('.badx', 449, 'ascii');
  await assert.rejects(compare(original, renamed), /retained/u);
  const highBit = fixture(true); highBit[449] = 0xae;
  await assert.rejects(compare(original, highBit), /ASCII/u, 'high-bit section names must not alias ASCII identifiers');
});

test('metadata removal may never remove a non-LOAD note or mark original removable metadata as runtime data', async () => {
  const original = fixture(false), renamed = Buffer.from(original);
  const at = renamed.indexOf(Buffer.from('.debug_info\0')); assert(at > 0);
  renamed.write('.note.other', at, 'ascii'); renamed.writeUInt32LE(7, 640 + 4 * 64 + 4);
  await assert.rejects(compare(renamed, fixture(true)), /retained/u);
  const allocated = Buffer.from(original); allocated.writeBigUInt64LE(2n, 640 + 5 * 64 + 8);
  await assert.rejects(compare(allocated, fixture(true)), /metadata intersects/u);
});

test('the actual experimental entry rejects invalid provisioning before creating an output or downloading', async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'cliq-carrier-entry-'));
  const output = path.join(parent, 'must-not-exist');
  try {
    const child = spawnSync(process.execPath, ['--import', 'tsx', fileURLToPath(new URL('../qualify-supervisor-carrier-size.ts', import.meta.url)),
      output, '/absolute-unused-cache', 'unsupported-extra'], { encoding: 'utf8', timeout: 5_000, maxBuffer: 16_384 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 1);
    assert.match(child.stderr, /this experiment requires the standard Linux runner|usage: qualify-supervisor-carrier-size/u);
    assert.equal(child.stdout, '');
    await assert.rejects(lstat(output), { code: 'ENOENT' });
    assert.deepEqual(await readdir(parent), []);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

// Source wiring, not GNU strip/SEA execution or installed qualification. The
// immutable CT projection preserves every original job, condition and budget.
test('carrier experiments are isolated beside the original image qualifier and retain only their bounded report', async () => {
  const workflow = await readFile(new URL('../../../.github/workflows/kernel-foundation.yml', import.meta.url), 'utf8');
  const experiment = [
    '      - name: Measure fixed carrier metadata reduction without selecting it',
    "        if: ${{ !cancelled() && steps.build.outcome == 'success' }}",
    '        run: >-',
    '          node --import tsx scripts/kernel/qualify-supervisor-carrier-size.ts',
    '          "$RUNNER_TEMP/cliq-supervisor-carrier-size"',
    '          "$RUNNER_TEMP/cliq-supervisor-image/node-v24.21.0-linux-x64.tar.xz"',
    '',
  ].join('\n');
  const retain = [
    '      - name: Retain bounded carrier experiment metadata only',
    '        if: always()',
    '        uses: actions/upload-artifact@v4',
    '        with:',
    '          name: supervisor-carrier-size-${{ github.run_id }}-${{ github.run_attempt }}',
    '          path: ${{ runner.temp }}/cliq-supervisor-carrier-size/carrier-size-experiment.json',
    '          if-no-files-found: warn',
    '          retention-days: 7',
    '',
  ].join('\n');
  assert.equal(workflow.split(experiment).length, 2, 'exactly one fixed experiment step must exist');
  assert.equal(workflow.split(retain).length, 2, 'exactly one metadata-only artifact must exist');
  const adjacent = '        run: node --import tsx scripts/kernel/qualify-supervisor-image.ts "$RUNNER_TEMP/cliq-supervisor-image"\n' + experiment + retain;
  assert(workflow.includes(adjacent), 'the independent experiment belongs immediately after the original complete-image qualifier');
  const projected = workflow.replace(experiment, '').replace(retain, '');
  assert.equal(createHash('sha256').update(projected).digest('hex'), '346af80a56060feace86c309b316c67560f68c512207d6cd3c95ab965cb225f5',
    'all original CT jobs, runner groups, timeouts, qualifiers and conditions must remain byte-identical');
  assert.equal(workflow.split('qualify-supervisor-carrier-size.ts').length, 2, 'no production job may select the experimental carrier');
});
