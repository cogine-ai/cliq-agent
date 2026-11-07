import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmod, link, lstat, mkdir, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { PlatformProcessIdentityV1, StateRootIdentityV1 } from '../kernel/types.js';
import { loadNativeStateOwner, stateRootIdentityFromDescriptor } from './native-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { openStateStore } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';
import { childFor, ownerAt } from './testing/state-owner-process.js';

const native = await loadNativeStateOwner();
const busy = /StateOwner OS lock is already held/;

async function rootFor(t: TestContext) {
  const root = await makePrivateDir('.cliq-native-owner-');
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('stateRootIdentityFromDescriptor matches the held native lock and store bootstrap artifact', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  try {
    const projected = stateRootIdentityFromDescriptor(root, held.root);
    assert.ok(Object.isFrozen(projected));
    assert.equal(projected.platform, process.platform === 'linux' ? 'linux' : 'macos');
    assert.equal(projected.canonicalAbsolutePath, root);
    assert.equal(projected.ownerUid, held.root.ownerUid);
    assert.equal(projected.deviceId, held.root.deviceId);
    assert.equal(projected.directoryFileId, held.root.fileId);
    assert.equal(projected.mode, 448);
    assert.equal(projected.openedNoFollow, true);
    assert.equal(projected.layoutVersion, 1);
    assert.equal(projected.identityDigest, digestOmitting(projected, 'identityDigest'));
    assert.equal(canonicalSha256(projected), canonicalSha256(structuredClone(projected) as StateRootIdentityV1));
  } finally { held.close(); }

  const store = await openStateStore(root);
  const published = await store.artifacts.readCanonical<StateRootIdentityV1>(store.stateRootIdentity.ref);
  assert.equal(published.identityDigest, store.stateRootIdentity.digest);
  await store.close();
  const successor = native.acquireLock(root, false);
  try {
    assert.deepEqual(stateRootIdentityFromDescriptor(root, successor.root), published);
  } finally { successor.close(); }
});

test('stateRootIdentityFromDescriptor changes digest when descriptor identity drifts', () => {
  const root = '/tmp/example-state-root';
  const base = { deviceId: '1', fileId: '2', ownerUid: process.geteuid!() };
  const first = stateRootIdentityFromDescriptor(root, base);
  for (const drift of [{ fileId: '3' }, { deviceId: '9' }, { ownerUid: base.ownerUid + 1 }]) {
    assert.notEqual(stateRootIdentityFromDescriptor(root, { ...base, ...drift }).identityDigest, first.identityDigest);
  }
});

test('native StateOwner lock holds exact descriptor identities until explicit close', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  try {
    for (const [identity, locator] of [[held.root, root], [held.runtime, path.join(root, 'runtime')],
      [held.lock, path.join(root, 'runtime/state-owner.lock')]] as const) {
      const stat = await lstat(locator, { bigint: true });
      assert.deepEqual(identity, { deviceId: String(stat.dev), fileId: String(stat.ino), ownerUid: Number(stat.uid) });
      assert.ok(Object.isFrozen(identity));
    }
    held.assertHeld();
    assert.throws(() => native.acquireLock(root, false), busy);
    assert.throws(() => held.close.call({}), /invalid StateOwner lock handle/);
    held.assertHeld();
  } finally { held.close(); }
  held.close();
  assert.throws(() => held.assertHeld(), /changed or closed/);
  const successor = native.acquireLock(root, false);
  try {
    assert.throws(() => held.assertHeld(), /changed or closed/);
    successor.assertHeld();
  } finally { successor.close(); }
});

test('native process start identity is stable and independent of wall clock and uptime estimates', async (t) => {
  const token = native.processStartToken();
  t.mock.method(Date, 'now', () => 0);
  t.mock.method(process, 'uptime', () => Number.MAX_SAFE_INTEGER);
  assert.equal(native.processStartToken(), token);
  if (process.platform === 'linux') {
    const stat = await readFile('/proc/self/stat', 'utf8');
    assert.equal(token, `linux-proc-start-ticks:${stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/u)[19]}`);
  } else {
    assert.match(token, /^darwin-proc-start-time:[1-9]\d*:\d{6}$/u);
  }
});

test('StateOwner rejects symlink ancestors and noncanonical roots before creating layout', async (t) => {
  const container = await rootFor(t);
  const real = path.join(container, 'real');
  const alias = path.join(container, 'alias');
  await mkdir(real, { mode: 0o700 });
  await mkdir(path.join(real, 'state'), { mode: 0o700 });
  await symlink(real, alias);
  for (const candidate of [alias, path.join(alias, 'state'), `${real}/`, `${real}/./state`, `${real}//state`, `${real}\0ignored`]) {
    assert.throws(() => native.acquireLock(candidate, true));
  }
  await assert.rejects(openStateStore(path.join(alias, 'state')), /without following symlinks/);
  assert.deepEqual(await readdir(path.join(real, 'state')), []);
  assert.deepEqual(await readdir(real), ['state']);
});

test('held owner rejects root, runtime and lock replacement or permission drift without reacquiring', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  try {
    for (const [locator, isDirectory, mode] of [[root, true, 0o700], [path.join(root, 'runtime'), true, 0o700],
      [path.join(root, 'runtime/state-owner.lock'), false, 0o600]] as const) {
      await chmod(locator, 0o755);
      try { assert.throws(() => held.assertHeld(), /changed or closed/); }
      finally { await chmod(locator, mode); }
      held.assertHeld();
      const saved = `${locator}.saved`;
      await rename(locator, saved);
      try {
        if (isDirectory) await mkdir(locator, { mode }); else await writeFile(locator, '', { mode });
        assert.throws(() => held.assertHeld(), /changed or closed/);
      } finally {
        await rm(locator, { recursive: true, force: true });
        await rename(saved, locator);
      }
      held.assertHeld();
      assert.throws(() => native.acquireLock(root, false), busy);
    }
  } finally { held.close(); }
});

test('native acquisition rejects unsafe lock files without repairing them', async (t) => {
  const root = await rootFor(t);
  native.acquireLock(root, true).close();
  const lock = path.join(root, 'runtime/state-owner.lock');
  const saved = path.join(root, 'saved-lock');
  await link(lock, saved);
  try { assert.throws(() => native.acquireLock(root, false), /link count 1/); }
  finally { await rm(saved); }
  await chmod(lock, 0o644);
  assert.throws(() => native.acquireLock(root, false), /0600/);
  assert.equal((await lstat(lock)).mode & 0o777, 0o644);
  await chmod(lock, 0o600);
  await rename(lock, saved);
  try {
    await symlink(saved, lock);
    assert.throws(() => native.acquireLock(root, false), /regular file/);
    await rm(lock);
    await mkdir(lock, { mode: 0o700 });
    assert.throws(() => native.acquireLock(root, false), /regular file/);
    await rm(lock, { recursive: true });
    execFileSync('mkfifo', ['-m', '600', lock]);
    assert.throws(() => native.acquireLock(root, false), /regular file/);
  } finally { await rm(lock, { recursive: true, force: true }); await rename(saved, lock); }
  native.acquireLock(root, false).close();
});

test('a competing process cannot open SQLite or CAS until the actual owner lock is released', async (t) => {
  const root = await rootFor(t);
  const held = native.acquireLock(root, true);
  const child = await childFor(t, root);
  try {
    const denied = await child.request('acquire');
    assert.equal(denied.state, 'error');
    assert.match(denied.message!, busy);
    assert.deepEqual(await readdir(root), ['runtime']);
  } finally { held.close(); }
  const acquired = await child.request('acquire');
  assert.equal(acquired.state, 'held');
  assert.equal(acquired.epoch, 1);
  await assert.rejects(openStateStore(root), busy);
  assert.equal((await child.request('close')).state, 'released');
  const successor = await openStateStore(root);
  try {
    assert.equal(successor.ownerEpoch, 2);
    const identity = await successor.artifacts.readCanonical<PlatformProcessIdentityV1>(ownerAt(root).processIdentityRef);
    assert.equal(identity.pid, process.pid);
    assert.notEqual(identity.pid, acquired.pid);
    assert.equal(identity.processStartToken, native.processStartToken());
  } finally { await successor.close(); }
});

test('simultaneous fresh processes create one owner and leave a cleanly reacquirable generation', async (t) => {
  const root = await rootFor(t);
  const children = await Promise.all([childFor(t, root), childFor(t, root)]);
  const results = await Promise.all(children.map(child => child.request('acquire')));
  assert.equal(results.filter(result => result.state === 'held').length, 1, JSON.stringify(results));
  assert.equal(results.filter(result => result.state === 'error' && busy.test(result.message!)).length, 1, JSON.stringify(results));
  assert.equal(ownerAt(root).ownerEpoch, 1);
  await children[results.findIndex(result => result.state === 'held')]!.request('close');
  const successor = await openStateStore(root);
  try { assert.equal(successor.ownerEpoch, 2); } finally { await successor.close(); }
});

test('simultaneous native acquisitions exclude each other before any SQLite access', async (t) => {
  const root = await rootFor(t);
  const children = await Promise.all([childFor(t, root, 'native'), childFor(t, root, 'native')]);
  const results = await Promise.all(children.map(child => child.request('acquire')));
  assert.equal(results.filter(result => result.state === 'held').length, 1, JSON.stringify(results));
  assert.equal(results.filter(result => result.state === 'error' && busy.test(result.message!)).length, 1, JSON.stringify(results));
  assert.deepEqual(await readdir(root), ['runtime']);
  await children[results.findIndex(result => result.state === 'held')]!.request('close');
});

test('native death inspection requires a held lock and positive PID/start-token absence or mismatch', async (t) => {
  const root = await rootFor(t);
  const child = await childFor(t, root);
  const acquired = await child.request('acquire');
  assert.equal(acquired.state, 'held');
  assert.equal((await child.request('drop-lock')).state, 'released');
  const held = native.acquireLock(root, false);
  try {
    assert.throws(() => held.assertPriorProcessDead(acquired.pid!, acquired.token!), /still present/);
    assert.throws(() => held.assertPriorProcessDead(process.pid, native.processStartToken()), /still present/);
    assert.notEqual(acquired.token, native.processStartToken());
    // Retaining another process's start token exercises the PID-reuse branch.
    held.assertPriorProcessDead(process.pid, acquired.token!);
    for (const pid of [0, -1, 1.5, NaN, Infinity, 2 ** 32 + process.pid]) {
      assert.throws(() => held.assertPriorProcessDead(pid, acquired.token!), /invalid prior/);
    }
    for (const token of ['', 'unknown-token', 'x'.repeat(128), `${acquired.token}\0ignored`]) {
      assert.throws(() => held.assertPriorProcessDead(acquired.pid!, token), /invalid prior/);
    }
    assert.throws(() => held.assertPriorProcessDead.call({} as never, acquired.pid!, acquired.token!), /invalid StateOwner lock handle/);
  } finally { held.close(); }
  child.child.kill('SIGKILL');
  const [, signal] = await child.exited;
  assert.equal(signal, 'SIGKILL');
  assert.throws(() => held.assertPriorProcessDead(acquired.pid!, acquired.token!), /changed or closed/);
  const successor = native.acquireLock(root, false);
  try { successor.assertPriorProcessDead(acquired.pid!, acquired.token!); } finally { successor.close(); }
});

test('native prior-process death observations require actual lifetime absence and a fresh native time under the original lock', async t => {
  const root = await rootFor(t);
  const child = await childFor(t, root, 'native');
  const acquired = await child.request('acquire');
  assert.equal(acquired.state, 'held');
  assert.equal((await child.request('close')).state, 'released');
  const held = native.acquireLock(root, false);
  try {
    const observe = Reflect.get(held, 'observePriorProcessDeath') as unknown;
    assert.equal(typeof observe, 'function', 'prior-process death requires its real native observation, not a caller clock');
    const read = (pid: number, token: string): unknown => Reflect.apply(observe as (...args: unknown[]) => unknown, held, [pid, token]);
    assert.throws(() => read(acquired.pid!, acquired.token!), /still present/);
    assert.throws(() => read(process.pid, native.processStartToken()), /still present/);
    for (const pid of [0, -1, 1.5, NaN, Infinity, 2 ** 32 + process.pid])
      assert.throws(() => read(pid, acquired.token!), /invalid prior/);
    const foreignToken = process.platform === 'linux' ? 'darwin-proc-start-time:1:000001' : 'linux-proc-start-ticks:1';
    const prefix = process.platform === 'linux' ? 'linux-proc-start-ticks:' : 'darwin-proc-start-time:';
    const suffix = process.platform === 'linux' ? '' : ':000001';
    for (const token of ['', 'unknown-token', foreignToken, 'x'.repeat(128), `${acquired.token}\0ignored`,
      `${prefix}0${suffix}`, `${prefix}+1${suffix}`, `${prefix}01${suffix}`,
      `${prefix}18446744073709551616${suffix}`])
      assert.throws(() => read(acquired.pid!, token), /invalid prior/);
    assert.throws(() => Reflect.apply(observe as (...args: unknown[]) => unknown, {}, [acquired.pid, acquired.token]),
      /invalid StateOwner lock handle/);
    const mismatch = read(process.pid, acquired.token!);
    assert.equal(typeof mismatch, 'number', 'a genuine different start lifetime exercises the positive PID-reuse branch');
    child.child.disconnect();
    const [code, signal] = await child.exited;
    assert.equal(code, 0); assert.equal(signal, null);
    const wallClock = Date.now.bind(Date);
    t.mock.method(Date, 'now', () => 0);
    let previous = 0;
    for (let index = 0; index < 2; index++) {
      if (index) await delay(5);
      const before = wallClock(), observed = read(acquired.pid!, acquired.token!), after = wallClock();
      assert.equal(typeof observed, 'number');
      assert.ok(Number.isSafeInteger(observed));
      assert.ok((observed as number) >= before && (observed as number) <= after,
        'each observation must sample the actual native wall clock after inspecting the dead original process');
      assert.ok((observed as number) > previous); previous = observed as number;
    }
  } finally { held.close(); }
  assert.throws(() => Reflect.apply(Reflect.get(held, 'observePriorProcessDeath'), held, [acquired.pid, acquired.token]),
    /changed or closed/);
});

test('uncertain prior-process observation close retains its original OS lock and never closes a reused descriptor', async t => {
  const container = await rootFor(t), binary = path.join(container, 'fault.node');
  const includes = JSON.parse(execFileSync(process.execPath, [
    fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'
  ], { encoding: 'utf8' })) as string[];
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']),
    ...includes.flatMap(include => ['-I', include]),
    fileURLToPath(new URL('./testing/current-process-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr);
  const subjectRoot = path.join(container, 'subject'); await mkdir(subjectRoot, { mode: 0o700 });
  const subject = await childFor(t, subjectRoot, 'native');
  const lifetime = await subject.request('acquire'); assert.equal(lifetime.state, 'held');
  assert.equal((await subject.request('close')).state, 'released'); subject.child.disconnect();
  const [code, signal] = await subject.exited; assert.equal(code, 0); assert.equal(signal, null);
  const points = ['after_directory_close', ...(process.platform === 'linux' ? ['after_fclose'] : [])];
  for (const point of points) await t.test(point, async () => {
    const stateRoot = path.join(container, point); await mkdir(stateRoot, { mode: 0o700 });
    const child = spawnSync(process.execPath, ['--expose-gc', '--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import { Module } from 'node:module';
      import { openSync, writeFileSync, fstatSync, readSync } from 'node:fs';
      import { constants } from 'node:os';
      import { setImmediate as nextTurn } from 'node:timers/promises';
      const [binary, root, point, priorPid, priorToken] = process.argv.slice(1);
      const loaded = new Module(binary); process.dlopen(loaded, binary); const binding = loaded.exports;
      let lock = binding.acquireLock(root, true); const sentinel = root + '/sentinel';
      // The dead subject has no proc stat stream to close. Linux's fclose
      // case inspects this actual live lifetime and must retain the close
      // uncertainty instead of reporting only the ordinary alive refusal.
      const inspectedPid = point === 'after_fclose' ? process.pid : Number(priorPid);
      const inspectedToken = point === 'after_fclose' ? binding.processStartToken() : priorToken;
      const bytes = Buffer.from('unrelated reused descriptor must survive');
      writeFileSync(sentinel, bytes, { mode: 0o600 });
      let faulted = 0, retiredFd = -1, reusedFd = -1;
      binding.setFault(point, 1, fd => {
        faulted++; retiredFd = fd;
        for (let count = 0; count < 256; count++) {
          const opened = openSync(sentinel, 'r');
          assert(opened <= fd);
          if (opened === fd) { reusedFd = opened; break; }
        }
        assert.equal(reusedFd, fd);
        return constants.errno.EIO;
      });
      let observation, observationCode, heldCode, heldMessage, firstCode, firstMessage, secondCode;
      try { observation = lock.observePriorProcessDeath(inspectedPid, inspectedToken); } catch (error) { observationCode = error.code; }
      try { lock.assertHeld(); } catch (error) { heldCode = error.code; heldMessage = error.message; }
      let generation, generationGranted = false, generationClosed = true;
      try { generation = lock.createGenerationTree('observation-fatal', 'g'.repeat(43)); generationGranted = true; }
      catch {}
      finally {
        // Even RED must retire the actual accidentally minted child and drop
        // its JS reference before the later real lock-GC observation.
        try { generation?.close(); } catch { generationClosed = false; }
        generation = undefined;
      }
      try { lock.close(); } catch (error) { firstCode = error.code; firstMessage = error.message; }
      try { lock.close(); } catch (error) { secondCode = error.code; }
      const kernelLockBusy = () => {
        let competing, busy = false;
        try { competing = binding.acquireLock(root, false); }
        catch (error) { busy = /StateOwner OS lock is already held/.test(error.message); }
        try { competing?.close(); } catch {}
        return busy;
      };
      const intact = () => {
        const read = Buffer.alloc(bytes.length);
        return fstatSync(reusedFd).isFile() && readSync(reusedFd, read, 0, read.length, 0) === bytes.length && read.equals(bytes);
      };
      const kernelBusy = kernelLockBusy(), sentinelIntactBeforeGc = intact();
      let collected = false, gcProbeCount = 0, kernelBusyAfterGc = true;
      const registry = new FinalizationRegistry(() => { collected = true; });
      const weak = new WeakRef(lock); registry.register(lock, 'original-lock'); lock = undefined;
      for (let round = 0; round < 32 && gcProbeCount < 3; round++) {
        await nextTurn(); global.gc(); await nextTurn();
        if (collected && weak.deref() === undefined) {
          // JS collection is not a C-finalizer attestation. These are repeated
          // actual flock acquisitions after the original handle was collected.
          const busy = kernelLockBusy(); kernelBusyAfterGc = kernelBusyAfterGc && busy; gcProbeCount++;
        }
      }
      console.log(JSON.stringify({ faulted, retiredFdReused: retiredFd === reusedFd, sentinelIntact: intact(), sentinelIntactBeforeGc,
        observationGranted: observation !== undefined, observationCode, heldCode, heldMessage,
        firstCode, firstMessage, secondCode, kernelBusy, collected, gcProbeCount, kernelBusyAfterGc, generationGranted, generationClosed }));
      // Actual process exit, not a successful close assertion, releases the lock.
    `, binary, stateRoot, point, String(lifetime.pid), lifetime.token!], { encoding: 'utf8', timeout: 10000 });
    assert.equal(child.error, undefined); assert.equal(child.status, 0, child.stderr); assert.equal(child.signal, null);
    const observed = JSON.parse(child.stdout.trim()) as { faulted: number; retiredFdReused: boolean; sentinelIntact: boolean;
      sentinelIntactBeforeGc: boolean; collected: boolean; gcProbeCount: number; kernelBusyAfterGc: boolean;
      generationGranted: boolean; generationClosed: boolean;
      observationGranted: boolean; observationCode?: string; heldCode?: string; heldMessage?: string;
      firstCode?: string; firstMessage?: string; secondCode?: string; kernelBusy: boolean };
    assert.equal(observed.faulted, 1); assert.equal(observed.retiredFdReused, true); assert.equal(observed.sentinelIntact, true);
    assert.equal(observed.sentinelIntactBeforeGc, true);
    assert.equal(observed.observationGranted, false); assert.equal(observed.observationCode, 'ERR_CLIQ_RESOURCE_RETIREMENT');
    assert.equal(observed.heldCode, 'ERR_CLIQ_RESOURCE_RETIREMENT', 'uncertain process observation must poison this exact lock');
    assert.match(observed.heldMessage!, /prior process observation.*StateOwner remains held/);
    assert.equal(observed.firstCode, 'ERR_CLIQ_RESOURCE_RETIREMENT');
    assert.match(observed.firstMessage!, /prior process observation.*StateOwner remains held/);
    assert.equal(observed.secondCode, 'ERR_CLIQ_RESOURCE_RETIREMENT');
    assert.equal(observed.kernelBusy, true, 'the actual OS lock must remain held through both refused closes');
    assert.equal(observed.collected, true, 'the original JS handle must actually be garbage-collected');
    assert.equal(observed.gcProbeCount, 3, 'bounded GC must include three real kernel lock probes after collection');
    assert.equal(observed.kernelBusyAfterGc, true, 'collecting the poisoned handle must not release its actual OS lock');
    assert.equal(observed.generationClosed, true, 'even an unexpected native child must positively close before GC');
    assert.equal(observed.generationGranted, false, 'a poisoned lock must not mint new productive generation resources');
    const successor = native.acquireLock(stateRoot, false); successor.close();
  });
});

test('failed graceful release keeps the OS lock until durable terminalization succeeds', async (t) => {
  const root = await rootFor(t);
  const store = await openStateStore(root);
  const publication = t.mock.method(store.artifacts, 'publishCanonical', async () => { throw new Error('injected CAS publication failure'); });
  try {
    await assert.rejects(store.close(), /injected CAS publication failure/);
    assert.equal(ownerAt(root).state, 'active');
    assert.throws(() => native.acquireLock(root, false), busy);
  } finally { publication.mock.restore(); await store.close(); }
  assert.equal(ownerAt(root).state, 'terminal');
  const successor = await openStateStore(root);
  try { assert.equal(successor.ownerEpoch, 2); } finally { await successor.close(); }
});

test('failed SQLite close retains the lock and retries without a second graceful transition', async (t) => {
  const root = await rootFor(t);
  const store = await openStateStore(root);
  const driver = (store as unknown as { driver: SqliteDriver }).driver;
  const closing = t.mock.method(driver, 'close', () => { throw new Error('injected SQLite close failure'); });
  try {
    await assert.rejects(store.close(), /injected SQLite close failure/);
    assert.equal(ownerAt(root).state, 'terminal');
    assert.throws(() => native.acquireLock(root, false), busy);
  } finally { closing.mock.restore(); await store.close(); }
  const successor = await openStateStore(root);
  try { assert.equal(successor.ownerEpoch, 2); } finally { await successor.close(); }
});
