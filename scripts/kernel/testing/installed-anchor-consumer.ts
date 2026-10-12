// Independent observation of the actual Supervisor's destination anchor FD.
// No production helper result, injected descriptor, or execution authority.
import assert from 'node:assert/strict';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, readlink, stat } from 'node:fs/promises';

import { descriptorInventory, qualifyInstalledAnchorSource } from './installed-anchor-source.js';

const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const rootFields = ['dev', 'ino', 'uid', 'gid', 'mode'] as const;
const oPath = 0o10000000n;
type SourceInput = Parameters<typeof qualifyInstalledAnchorSource>[0];
type SourceCut = { stateRoot: Record<string, string>;
  namespaces: Record<string, { device: string; inode: string }>; bootId: string };
type Descriptor = Awaited<ReturnType<typeof descriptorInventory>>['descriptors'][number];

function identity(metadata: BigIntStats, fields: readonly (typeof imageFields)[number][]) {
  return Object.fromEntries(fields.map(field => [field, metadata[field].toString()]));
}

async function procBytes(filename: string, limit = 64 * 1024): Promise<Buffer> {
  const file = await open(filename, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    assert((await file.stat()).isFile());
    const buffer = Buffer.alloc(limit + 1);
    let used = 0;
    while (used < buffer.length) {
      const { bytesRead } = await file.read(buffer, used, buffer.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    assert(used <= limit, 'actual Supervisor observation exceeded its byte bound');
    return buffer.subarray(0, used);
  } finally { await file.close(); }
}

async function procText(filename: string, limit?: number): Promise<string> {
  return new TextDecoder('utf-8', { fatal: true }).decode(await procBytes(filename, limit));
}

export async function qualifyInstalledAnchorConsumer(input: {
  source: SourceInput; pid: number; report: Record<string, unknown>;
}): Promise<void> {
  assert.equal(process.platform, 'linux');
  assert(Number.isSafeInteger(input.pid) && input.pid > 0 && input.pid <= 0x7fffffff);
  assert.notEqual(input.pid, input.source.pid);
  input.report.qualified = false;
  const sourceBefore: Record<string, unknown> = {};
  input.report.sourceBefore = sourceBefore;
  await qualifyInstalledAnchorSource({ ...input.source, report: sourceBefore });
  assert.equal(sourceBefore.qualified, true);
  const sourceCut = sourceBefore.before as SourceCut;
  const source = sourceBefore.source as Descriptor;
  const proc = `/proc/${input.pid}`;
  const cut = async () => {
    const rawStat = await procText(`${proc}/stat`);
    assert(rawStat.startsWith(`${input.pid} (`));
    const fields = rawStat.slice(rawStat.lastIndexOf(')') + 2).trim().split(/\s+/u);
    assert(fields.length >= 20 && !['Z', 'X', 'x'].includes(fields[0]!));
    assert.match(fields[19]!, /^(?:0|[1-9][0-9]*)$/u);
    const credentials: Record<string, string[]> = {};
    const status = await procText(`${proc}/status`);
    for (const [field, expected] of [['Uid', input.source.uid], ['Gid', input.source.gid]] as const) {
      const matches = [...status.matchAll(new RegExp(`^${field}:[ \\t]+([0-9]+)[ \\t]+([0-9]+)[ \\t]+([0-9]+)[ \\t]+([0-9]+)$`, 'gmu'))];
      assert.equal(matches.length, 1); credentials[field] = matches[0]!.slice(1);
      assert(credentials[field]!.every(value => value === String(expected)));
    }
    const state = await lstat(input.source.stateRoot, { bigint: true });
    assert(state.isDirectory() && !state.isSymbolicLink());
    assert.equal(state.uid, BigInt(input.source.uid)); assert.equal(state.mode & 0o7777n, 0o700n);
    assert.deepEqual(identity(state, rootFields), sourceCut.stateRoot);
    const argv = [input.source.selectedImage, '--installed-supervisor', input.source.stateRoot, input.source.bundleDigest,
      `${state.dev}:${state.ino}:${state.uid}`];
    assert.deepEqual(await procBytes(`${proc}/cmdline`), Buffer.from(argv.join('\0') + '\0'));
    const selected = await lstat(input.source.selectedImage, { bigint: true });
    assert(selected.isFile() && !selected.isSymbolicLink());
    const image = await stat(`${proc}/exe`, { bigint: true });
    assert(image.isFile()); assert.equal(await readlink(`${proc}/exe`), input.source.selectedImage);
    assert.deepEqual(identity(image, imageFields), identity(input.source.selectedMetadata, imageFields));
    assert.deepEqual(identity(selected, imageFields), identity(input.source.selectedMetadata, imageFields));
    const namespaces: SourceCut['namespaces'] = {};
    for (const name of ['pid', 'mnt', 'cgroup', 'user', 'time']) {
      const actual = await stat(`${proc}/ns/${name}`, { bigint: true });
      namespaces[name] = { device: actual.dev.toString(), inode: actual.ino.toString() };
    }
    assert.deepEqual(namespaces, sourceCut.namespaces);
    const bootId = (await procText('/proc/sys/kernel/random/boot_id', 128)).trim();
    assert.equal(bootId, sourceCut.bootId);
    return { pid: input.pid, startTicks: fields[19], credentials, argv,
      image: identity(image, imageFields), stateRoot: identity(state, rootFields), namespaces, bootId,
      membership: (await procText(`${proc}/cgroup`)).trim() };
  };
  const matchesRoot = (descriptor: Descriptor) => (BigInt(descriptor.flags) & (oPath | 3n)) === 0n &&
    descriptor.mountId === source.mountId && descriptor.inode === source.inode &&
    rootFields.every(field => descriptor.target[field] === source.target[field]);
  const before = await cut(); input.report.before = before;
  const inventory = await descriptorInventory(input.pid); input.report.inventory = inventory;
  const matchingRootFDs = inventory.descriptors.filter(matchesRoot);
  input.report.matchingRootFDs = matchingRootFDs;
  const afterInventory = await descriptorInventory(input.pid); input.report.afterInventory = afterInventory;
  const afterMatchingRootFDs = afterInventory.descriptors.filter(matchesRoot);
  input.report.afterMatchingRootFDs = afterMatchingRootFDs;
  const after = await cut(); input.report.after = after;
  const sourceAfter: Record<string, unknown> = {};
  input.report.sourceAfter = sourceAfter;
  await qualifyInstalledAnchorSource({ ...input.source, report: sourceAfter });
  assert.equal(sourceAfter.qualified, true);
  assert.deepEqual(after, before);
  assert.deepEqual(sourceAfter.after, sourceBefore.before);
  assert.deepEqual(sourceAfter.source, sourceBefore.source);
  assert.deepEqual(sourceAfter.ready, sourceBefore.ready);
  assert.equal(sourceAfter.readyBytes, sourceBefore.readyBytes);
  assert.deepEqual(sourceAfter.locator, sourceBefore.locator);
  assert.deepEqual(afterMatchingRootFDs, matchingRootFDs);
  assert.equal(matchingRootFDs.length, 1, 'actual Supervisor must hold exactly one read-only original root directory FD');
  input.report.qualified = true;
}
