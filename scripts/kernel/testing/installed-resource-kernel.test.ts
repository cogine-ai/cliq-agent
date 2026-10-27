import assert from 'node:assert/strict';
import test from 'node:test';
import fs, { constants, closeSync, fstatSync, openSync, readFileSync, readlinkSync, readdirSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { RESOURCE_BITS, resourceDecimal, resourceMembership, resourceNofile, resourceCounters, resourceProcess, resourceStart,
  sampleHeldResourceGroup } from '../../../src/state/installed-resource-kernel.js';
import { observeInstalledResources, noteInstalledResourceBoundary } from '../../../src/state/installed-resource-diagnostics.js';

test('fixed resource data rejects coercion, overflow, duplicate counters, multimap and live-state substitution', () => {
  for (const value of ['-1', '+1', '01', '1 ', '1e3', '9007199254740992']) assert.throws(() => resourceDecimal(value));
  assert.equal(resourceDecimal('0'), 0);
  for (const value of ['0::/\n0::/elsewhere\n', '0::/../other\n', '0::/x\u0000\n', '1:cpu:/\n'])
    assert.throws(() => resourceMembership(Buffer.from(value)));
  assert.equal(resourceMembership(Buffer.from('0::/\n')), '/');
  assert.throws(() => resourceCounters(Buffer.from('usage_usec 1\nusage_usec 2\n')));
  assert.throws(() => resourceCounters(Buffer.from('usage_usec 1.5\n')));
  assert.throws(() => resourceNofile(Buffer.from('Max open files 1024 unlimited files\n')));
  assert.throws(() => resourceNofile(Buffer.from('Max open files 2048 1024 files\n')));
  assert.deepEqual(resourceNofile(Buffer.from('Max open files 64 8192 files\n')), [64, 8192]);
  if (process.platform === 'linux') {
    const own = readFileSync(`/proc/${process.pid}/stat`, 'utf8');
    assert.throws(() => resourceStart(Buffer.from(own.replace(/\) [A-Z]/u, ') Z')), process.pid));
  }
});
test('resource data never evaluates getters or Proxy traps; unsubscribed boundary does no reads', () => {
  let calls = 0;
  const getter = { get pid() { calls++; return 1; }, start: 'linux-proc-start-ticks:1', uid: 0 };
  const proxy = new Proxy({}, { getPrototypeOf() { calls++; throw Error('not data'); }, ownKeys() { calls++; return []; } });
  assert.throws(() => resourceProcess(getter)); assert.throws(() => resourceProcess(proxy)); assert.equal(calls, 0);
  noteInstalledResourceBoundary('preparation_ready', () => { calls++; throw Error('must not borrow'); }); assert.equal(calls, 0);
});
test('one observer cannot alter the current emission set or replace a failed original observation', () => {
  const seen: string[] = []; let closeLate: (() => void) | undefined;
  const closeFirst = observeInstalledResources(() => { seen.push('first'); closeLate ??= observeInstalledResources(() => seen.push('late')); throw Error('sink'); });
  const closeSecond = observeInstalledResources(value => { assert.equal(value.numbers.mask, 0); seen.push('second'); });
  try { noteInstalledResourceBoundary('preparation_ready', () => { throw Error('unavailable'); }); assert.deepEqual(seen, ['first', 'second']); }
  finally { closeFirst(); closeSecond(); closeLate?.(); }
});

const linux = { skip: process.platform !== 'linux' };
const descriptorInventory = () => new Map(readdirSync('/proc/self/fd').flatMap(value => {
  try { return [[value, readlinkSync('/proc/self/fd/' + value)] as const]; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
}));
function actual() {
  const membership = resourceMembership(readFileSync('/proc/self/cgroup'));
  // A hosted runner may put this real process in a nested group. Borrow that
  // exact kernel-reported directory, rather than pretending the mount root is
  // its owner. Production still independently checks filesystem/PID/start/UID,
  // membership, original group identity and every actual reader close.
  const root = openSync('/sys/fs/cgroup' + (membership === '/' ? '' : membership),
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW), info = fstatSync(root, { bigint: true });
  const identity = { device: String(info.dev), inode: String(info.ino) };
  const processIdentity = { pid: process.pid, uid: process.geteuid!(), start: resourceStart(readFileSync('/proc/self/stat'), process.pid) };
  return { root, identity, membership, processIdentity };
}
test('real Linux procfs/cgroup observation binds live PID/start/group and joins all actual readers', linux, () => {
  const value = actual();
  try {
    const before = descriptorInventory(), observed = sampleHeldResourceGroup(value.root, value.identity, value.processIdentity, value.membership);
    assert.equal(observed.joined, 1); assert.equal(observed.unavailable, 0);
    for (const bit of [RESOURCE_BITS.group, RESOURCE_BITS.process, RESOURCE_BITS.memory, RESOURCE_BITS.cpu, RESOURCE_BITS.tasks, RESOURCE_BITS.descriptors, RESOURCE_BITS.nofile])
      assert(observed.mask & bit, 'real Linux kernel field is observed');
    assert(observed.memory > 0 && observed.tasks > 0 && observed.descriptors > 0);
    assert(observed.nofileSoft <= observed.nofileHard); assert.deepEqual(descriptorInventory(), before);
    const payload = sampleHeldResourceGroup(value.root, value.identity, value.processIdentity, value.membership, 'skip');
    assert(payload.mask & RESOURCE_BITS.process); assert(payload.mask & RESOURCE_BITS.memory);
    assert.equal(payload.mask & (RESOURCE_BITS.descriptors | RESOURCE_BITS.nofile), 0);
    assert.equal(payload.descriptors, 0); assert.equal(payload.nofileHard, 0);
    for (const changed of [{ ...value.processIdentity, start: 'linux-proc-start-ticks:1' }, { ...value.processIdentity, uid: value.processIdentity.uid + 1 }])
      assert.equal(sampleHeldResourceGroup(value.root, value.identity, changed, value.membership).mask, 0);
    assert.equal(sampleHeldResourceGroup(value.root, { ...value.identity, inode: String(BigInt(value.identity.inode) + 1n) }).mask, 0);
    assert.equal(sampleHeldResourceGroup(value.root, value.identity, value.processIdentity, '/foreign').mask, 0);
    assert.deepEqual(descriptorInventory(), before);
  } finally { closeSync(value.root); }
});
test('unavailable real Linux peak remains unavailable, and actual reader close errors never claim a join', linux, t => {
  const value = actual(), before = descriptorInventory(), originalOpen = fs.openSync, originalClose = fs.closeSync;
  try {
    t.mock.method(fs, 'openSync', ((name: fs.PathLike, ...args: unknown[]) => {
      if (String(name).endsWith('/memory.peak') || String(name).endsWith('/pids.peak')) throw Object.assign(Error('absent'), { code: 'ENOENT' });
      return Reflect.apply(originalOpen, fs, [name, ...args]);
    }) as typeof fs.openSync); syncBuiltinESMExports();
    const observed = sampleHeldResourceGroup(value.root, value.identity, value.processIdentity, value.membership);
    assert.equal(observed.unavailable, 0); assert(observed.mask & RESOURCE_BITS.memory);
    assert.equal(observed.mask & (RESOURCE_BITS.memoryPeak | RESOURCE_BITS.tasksPeak), 0);
    assert.equal(observed.memoryPeak, 0); assert.equal(observed.tasksPeak, 0); assert.deepEqual(descriptorInventory(), before);
    t.mock.restoreAll(); syncBuiltinESMExports();
    let fail = true;
    t.mock.method(fs, 'closeSync', ((fd: number) => { originalClose(fd); if (fail) { fail = false; throw Object.assign(Error('reported close error'), { code: 'EIO' }); } }) as typeof fs.closeSync);
    syncBuiltinESMExports();
    const failed = sampleHeldResourceGroup(value.root, value.identity, value.processIdentity, value.membership);
    assert.equal(failed.joined, 0); assert.equal(failed.unavailable, 3); assert.equal(failed.mask, 0);
    assert.deepEqual(descriptorInventory(), before);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); closeSync(value.root); }
  // All real closes above still ran; the diagnostic refused to infer this from
  // an error return, and the test independently checks actual descriptor join.
});
