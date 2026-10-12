// Test-only syscall-result fault at a real controller's final leaf retirement.
// Actual HELLO, child join and cgroup observations are never substituted. This
// is not an installed signed Supervisor or whole-worker death qualification.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import { Module } from 'node:module';
import { constants as osConstants, tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

assert.equal(process.platform, 'linux', 'real Linux required; this regression is never skipped');
assert.ok(process.getuid() > 0 && process.getuid() === process.geteuid(), 'actual non-root delegation required');
const script = fileURLToPath(import.meta.url);
const directoryFlags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
const fdPath = fd => `/proc/self/fd/${fd}`;
const identity = stat => Object.fromEntries(['dev', 'ino', 'uid', 'gid', 'mode'].map(key => [key, String(stat[key])]));
const resource = name => {
  const value = process.env[name];
  assert.ok(value && path.isAbsolute(value) && path.normalize(value) === value, `missing absolute ${name}`);
  return value;
};
const parent = resource('CLIQ_I1_CGROUP_PARENT');
const installation = resource('CLIQ_I1_INSTALLATION');

function processFact(pid) {
  const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8'), end = stat.lastIndexOf(')');
  assert.ok(end > 0);
  const fields = stat.slice(end + 2).trim().split(/\s+/u);
  assert.match(fields[19], /^[0-9]+$/u);
  const membership = fs.readFileSync(`/proc/${pid}/cgroup`, 'utf8').trim();
  assert.match(membership, /^0::\/[^\n]*$/u);
  const relative = membership.slice(3);
  assert.equal(path.posix.normalize(relative), relative);
  return { token: `linux-proc-start-ticks:${fields[19]}`, parentPid: Number(fields[1]),
    cgroup: `/sys/fs/cgroup${relative === '/' ? '' : relative}` };
}
assert.equal(processFact(process.pid).cgroup, path.join(parent, 'supervisor'), 'caller must occupy the real Supervisor leaf');

function directory(fd, namedPath, expected) {
  const held = fs.fstatSync(fd, { bigint: true }), named = fs.lstatSync(namedPath, { bigint: true });
  assert.ok(held.isDirectory() && named.isDirectory() && !named.isSymbolicLink());
  assert.deepEqual(identity(named), identity(held));
  if (expected) assert.deepEqual(identity(held), expected);
  assert.equal(held.uid, BigInt(process.getuid())); assert.equal(held.gid, BigInt(process.getgid()));
  assert.equal(held.mode & 0o7777n, 0o700n);
  assert.equal(fs.statfsSync(fdPath(fd)).type, 0x63677270, 'real cgroup2 required');
  return identity(held);
}
function references(expected) {
  let count = 0;
  for (const name of fs.readdirSync('/proc/self/fd')) {
    try {
      const actual = fs.fstatSync(Number(name), { bigint: true });
      if (String(actual.dev) === expected.dev && String(actual.ino) === expected.ino) count++;
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'EBADF') throw error;
    }
  }
  return count;
}
function emptyLeaf(fd) {
  assert.equal(fs.readFileSync(`${fdPath(fd)}/cgroup.type`, 'utf8'), 'domain\n');
  assert.equal(fs.readFileSync(`${fdPath(fd)}/cgroup.procs`, 'utf8').trim(), '');
  assert.equal(fs.readFileSync(`${fdPath(fd)}/cgroup.subtree_control`, 'utf8').trim(), '');
  assert.match(fs.readFileSync(`${fdPath(fd)}/cgroup.events`, 'utf8'), /(?:^|\n)populated 0\n/u);
}
function inventory(fd) {
  return fs.readdirSync(fdPath(fd)).filter(name => fs.lstatSync(`${fdPath(fd)}/${name}`).isDirectory()).sort();
}
async function bounded(operation, milliseconds = 10_000) {
  let timer;
  try {
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('real controller operation timed out')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}
async function settlement(controller) {
  try { await bounded(controller.close()); return { state: 'resolved' }; }
  catch (error) { return { state: 'rejected', code: error.code, message: String(error.message) }; }
}

async function runCase() {
  const [mode, errorName, binary, rootPath] = process.argv.slice(2);
  assert.equal(mode, '--case'); assert.equal(process.argv.length, 6);
  assert.ok(['EBUSY', 'ENOTEMPTY'].includes(errorName));
  assert.equal(path.dirname(rootPath), parent); assert.match(path.basename(rootPath), /^retirement-[0-9a-f]{32}$/u);
  const loaded = new Module(binary); process.dlopen(loaded, binary);
  const binding = loaded.exports;
  const held = [];
  let helper, controller, next, observed, primary, rootIdentity, parentIdentity, leafIdentity, joined = false;
  let root, controllers, leaf, originalPath, originalName;
  try {
    root = fs.openSync(rootPath, directoryFlags); held.push(root);
    rootIdentity = directory(root, rootPath);
    assert.equal(fs.readFileSync(`${fdPath(root)}/cgroup.procs`, 'utf8').trim(), '');
    assert.equal(references(rootIdentity), 1);
    const source = fs.openSync(path.join(installation, 'cliq-linux-worker-controller'), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    held.push(source); helper = binding.sealImage(source);
    controller = binding.openController(helper, root);
    assert.ok(Number.isSafeInteger(controller.pid) && controller.pid > 0, 'actual clone3 child required');
    await bounded((async () => { while (!controller.pollReady()) await delay(5); })());
    const pid = controller.pid, token = controller.processStartToken, fact = processFact(pid);
    assert.equal(fact.parentPid, process.pid); assert.equal(fact.token, token);
    const controllersPath = path.join(rootPath, 'controllers');
    assert.equal(path.dirname(fact.cgroup), controllersPath);
    originalPath = fact.cgroup; originalName = path.basename(originalPath);
    assert.match(originalName, /^controller-[0-9a-f]{32}$/u);
    controllers = fs.openSync(controllersPath, directoryFlags); held.push(controllers);
    leaf = fs.openSync(originalPath, directoryFlags); held.push(leaf);
    parentIdentity = directory(controllers, controllersPath); leafIdentity = directory(leaf, originalPath);
    assert.deepEqual(inventory(controllers), [originalName]);
    assert.equal(fs.readFileSync(`${fdPath(leaf)}/cgroup.procs`, 'utf8').trim(), String(pid));
    assert.equal(references(rootIdentity), 2, 'native controller must actually hold its own root FD');
    binding.armLeafRemovalFault(controller, osConstants.errno[errorName]);
    const selected = binding.leafRemovalFaultState(controller);
    assert.equal(selected.leafPath, originalPath); assert.equal(selected.leafName, originalName);
    assert.equal(selected.parentDev, parentIdentity.dev); assert.equal(selected.parentIno, parentIdentity.ino);
    assert.equal(selected.leafDev, leafIdentity.dev); assert.equal(selected.leafIno, leafIdentity.ino);

    const first = await settlement(controller);
    const fault = binding.leafRemovalFaultState(controller);
    joined = fault.cleanupDone === 1;
    // Establish the physical cut before testing the failure policy. These are
    // the real native cleanup result and independent kernel observations.
    assert.equal(fault.cleanupDone, 1); assert.equal(fault.childReaped, true);
    assert.equal(fault.matched, 1); assert.equal(fault.error, osConstants.errno[errorName]);
    assert.throws(() => fs.lstatSync(`/proc/${pid}`), { code: 'ENOENT' });
    directory(leaf, originalPath, leafIdentity); emptyLeaf(leaf);
    assert.equal(references(rootIdentity), 1); assert.equal(references(parentIdentity), 1); assert.equal(references(leafIdentity), 1);
    binding.disarmLeafRemovalFault();
    const repeated = await settlement(controller);
    const before = { leaves: inventory(controllers), rootReferences: references(rootIdentity),
      parentReferences: references(parentIdentity), leafReferences: references(leafIdentity), queueCalls: binding.queueCalls() };
    let nextCode;
    try { next = binding.openController(helper, root); } catch (error) { nextCode = error.code; }
    // Freeze fresh admission before cleaning up an incorrectly granted RED
    // receiver. Its eventual join cannot turn a grant into an earlier refusal.
    const admission = { granted: next !== undefined, code: nextCode,
      leaves: inventory(controllers), rootReferences: references(rootIdentity),
      parentReferences: references(parentIdentity), leafReferences: references(leafIdentity), queueCalls: binding.queueCalls() };
    observed = { scenario: 'actual-controller-leaf-removal-failure', injectedErrno: errorName,
      pid, token, first, repeated, fault, before, admission,
      note: 'test-only unlinkat result; real HELLO and exact child join, not whole-worker death or installed I1' };
    if (next) { assert.equal((await settlement(next)).state, 'resolved', 'RED receiver must actually join'); next = undefined; }
  } catch (error) { primary = error; }
  finally {
    const failures = [];
    try { binding.disarmLeafRemovalFault(); } catch (error) { failures.push(error); }
    if (next) { try { await bounded(next.close()); } catch (error) { failures.push(error); } }
    if (controller && !joined) {
      try { await bounded(controller.close()); } catch (error) { failures.push(error); }
    }
    // This is only exact fixture cleanup after the result is frozen, never a
    // successful controller close or a recovery/containment death receipt.
    if (leaf !== undefined) {
      try {
        // An earlier setup failure may have allowed normal production close
        // to remove the leaf already. Only ENOENT permits no manual removal.
        let named;
        try { named = fs.lstatSync(originalPath, { bigint: true }); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
        if (named) { directory(leaf, originalPath, leafIdentity); emptyLeaf(leaf); fs.rmdirSync(originalPath); }
      }
      catch (error) { failures.push(error); }
    }
    try { helper?.close(); } catch (error) { failures.push(error); }
    for (const fd of held.reverse()) { try { fs.closeSync(fd); } catch (error) { failures.push(error); } }
    try {
      if (rootIdentity) assert.equal(references(rootIdentity), 0, 'all test/native root FDs must actually retire');
      if (parentIdentity) assert.equal(references(parentIdentity), 0);
      if (leafIdentity) assert.equal(references(leafIdentity), 0);
      if (rootIdentity) {
        assert.deepEqual(identity(fs.lstatSync(rootPath, { bigint: true })), rootIdentity);
        try {
          const controllersPath = path.join(rootPath, 'controllers');
          if (parentIdentity) assert.deepEqual(identity(fs.lstatSync(controllersPath, { bigint: true })), parentIdentity);
          fs.rmdirSync(controllersPath);
        }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
      }
      if (rootIdentity) { assert.deepEqual(identity(fs.lstatSync(rootPath, { bigint: true })), rootIdentity); fs.rmdirSync(rootPath); }
    } catch (error) { failures.push(error); }
    if (primary || failures.length) throw new AggregateError([...(primary ? [primary] : []), ...failures], 'controller retirement regression/cleanup failed');
  }
  console.log(JSON.stringify(observed));
  assert.equal(observed.first.state, 'rejected', 'attempted leaf-removal failure cannot resolve controller close');
  assert.equal(observed.first.code, 'RECOVERY_REQUIRED');
  assert.equal(observed.repeated.state, 'rejected'); assert.equal(observed.repeated.code, 'RECOVERY_REQUIRED');
  assert.equal(observed.fault.retirementFailed, true); assert.equal(observed.fault.nativeSticky, 1);
  assert.equal(observed.admission.granted, false, 'fresh controller must refuse before resource allocation');
  assert.equal(observed.admission.code, 'RECOVERY_REQUIRED');
  const { granted, code, ...resources } = observed.admission;
  assert.deepEqual(resources, observed.before, 'fresh refusal cannot allocate a leaf, duplicate FDs or queue native work');
}

function runJob() {
  assert.equal(process.argv.length, 2, 'fixed job entry required');
  assert.ok(parent.startsWith('/sys/fs/cgroup/'));
  const staging = fs.mkdtempSync(path.join(tmpdir(), 'cliq-controller-retirement-'));
  const binary = path.join(staging, 'fault.node'), failures = [];
  try {
    const includes = JSON.parse(execFileSync(process.execPath,
      [fileURLToPath(new URL('../build-state-owner-native.mjs', import.meta.url)), '--print-includes'], { encoding: 'utf8', timeout: 30_000 }));
    const compile = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
      ...includes.flatMap(include => ['-I', include]),
      fileURLToPath(new URL('../../../src/sandbox/testing/controller-queue-fault-native.c', import.meta.url)), '-o', binary],
    { encoding: 'utf8', timeout: 30_000 });
    assert.equal(compile.status, 0, compile.stderr || String(compile.error));
    for (const errorName of ['EBUSY', 'ENOTEMPTY']) {
      const rootPath = path.join(parent, `retirement-${randomBytes(16).toString('hex')}`);
      fs.mkdirSync(rootPath, { mode: 0o700 }); fs.chmodSync(rootPath, 0o700);
      const child = spawnSync(process.execPath, [script, '--case', errorName, binary, rootPath],
        { encoding: 'utf8', timeout: 45_000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024 });
      if (child.stdout) process.stdout.write(child.stdout);
      if (child.stderr) process.stderr.write(child.stderr);
      if (child.status !== 0) failures.push(new Error(`${errorName} child failed: ${child.error ?? `status=${child.status} signal=${child.signal}`}`));
      try { assert.throws(() => fs.lstatSync(rootPath), { code: 'ENOENT' }, 'child must clean its exact disposable cgroup'); }
      catch (error) { failures.push(error); }
    }
  } finally { fs.rmSync(staging, { recursive: true, force: true }); }
  if (failures.length) throw new AggregateError(failures, 'real controller leaf retirement regression failed');
}

if (process.argv[2] === '--case') await runCase();
else runJob();
