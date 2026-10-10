import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

async function faultFixture(t: TestContext) {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-controller-queue-fault-'));
  t.after(() => rm(container, { recursive: true, force: true }));
  const binary = path.join(container, 'fault.node');
  const includes = JSON.parse(execFileSync(process.execPath, [
    fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'
  ], { encoding: 'utf8' })) as string[];
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']),
    ...includes.flatMap(include => ['-I', include]),
    fileURLToPath(new URL('./testing/controller-queue-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr);
  return { binary, container };
}

type Settlement = { state: 'resolved' | 'rejected' | 'timeout'; code?: string };
type QueueObservation = {
  interfaceVersion: number; pid: number; processStartToken: string;
  constructorQueueCalls: number; first: Settlement; second: Settlement;
  queueCallsBeforeCleanup: number; queueCallsAfterCleanup: number;
  rootReferencesBefore: number; rootReferencesHeld: number; rootReferencesAfter: number;
  cleanup: Settlement; rescueUsed: boolean; helperStillHeld: boolean;
};
type CloseFaultObservation = {
  pid: number; processStartToken: string; first: Settlement; repeated: Settlement;
  faulted: number; retiredFdReused: boolean; openedDescriptors: number;
  sentinelAfterFirst: boolean; sentinelAfterRepeat: boolean; sentinelAfterNext: boolean;
  rootReferencesBefore: number; rootReferencesAfterFirst: number;
  rootReferencesAfterCleanup: number; helperStillHeld: boolean;
  next: { granted: boolean; code?: string; pid?: number; processStartToken?: string;
    queueCallsBefore: number; queueCallsAfter: number; rootReferences: number };
  nextCleanup: Settlement | null;
};

if (process.platform === 'linux') {
  test('native controller close can retry a failed join queue without returning a permanently pending promise', async t => {
    const { binary, container } = await faultFixture(t);
    const rootPath = path.join(container, 'ordinary-directory');
    const helperPath = path.join(container, 'never-executed-image');
    await mkdir(rootPath, { mode: 0o700 });
    await chmod(rootPath, 0o700);
    // The real directory is not cgroup2, so construction must refuse before
    // any child birth. These sealed bytes are deliberately not an executable.
    await writeFile(helperPath, 'queue-fault fixture: must never execute\n', { mode: 0o500 });
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import { constants, openSync, closeSync, fstatSync, readdirSync } from 'node:fs';
      import { Module } from 'node:module';
      const [binary, rootPath, helperPath] = process.argv.slice(1);
      const module = new Module(binary); process.dlopen(module, binary);
      const binding = module.exports;
      const root = openSync(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      const source = openSync(helperPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      const helper = binding.sealImage(source);
      const rootIdentity = fstatSync(root);
      const helperIdentity = fstatSync(helper.descriptor());
      function rootReferences() {
        let count = 0;
        for (const entry of readdirSync('/proc/self/fd')) {
          try {
            const identity = fstatSync(Number(entry));
            if (identity.isDirectory() && identity.dev === rootIdentity.dev && identity.ino === rootIdentity.ino) count++;
          } catch (error) {
            // readdir's own temporary directory descriptor is already closed.
            if (error.code !== 'EBADF' && error.code !== 'ENOENT') throw error;
          }
        }
        return count;
      }
      async function bounded(promise, milliseconds) {
        let timer;
        try {
          return await Promise.race([
            Promise.resolve(promise).then(() => ({ state: 'resolved' }), error => ({ state: 'rejected', code: error.code })),
            new Promise(resolve => { timer = setTimeout(() => resolve({ state: 'timeout' }), milliseconds); })
          ]);
        } finally { clearTimeout(timer); }
      }
      const rootReferencesBefore = rootReferences();
      binding.armQueueFault();
      const controller = binding.openController(helper, root);
      const pid = controller.pid, processStartToken = controller.processStartToken;
      const rootReferencesHeld = rootReferences();
      const constructorQueueCalls = binding.queueCalls();
      let first;
      try { first = await bounded(controller.close(), 250); }
      catch (error) { first = { state: 'rejected', code: error.code }; }
      let secondPromise, second;
      try { secondPromise = controller.close(); second = await bounded(secondPromise, 250); }
      catch (error) { second = { state: 'rejected', code: error.code }; }
      // Freeze the tested result before cleanup. Rescue is never an alternate
      // successful close and cannot change the parent's RED/GREEN assertion.
      second = Object.freeze({ ...second });
      const queueCallsBeforeCleanup = binding.queueCalls();
      const rescueUsed = second.state !== 'resolved';
      let cleanup = second;
      if (rescueUsed) {
        binding.resumeJoin(controller);
        cleanup = await bounded(secondPromise ?? controller.close(), 3000);
      }
      const rootReferencesAfter = rootReferences();
      const actualHelper = fstatSync(helper.descriptor());
      const helperStillHeld = actualHelper.dev === helperIdentity.dev && actualHelper.ino === helperIdentity.ino &&
        actualHelper.size === helperIdentity.size;
      const observation = { interfaceVersion: binding.interfaceVersion, pid, processStartToken,
        constructorQueueCalls, first, second, queueCallsBeforeCleanup,
        queueCallsAfterCleanup: binding.queueCalls(), rootReferencesBefore, rootReferencesHeld,
        rootReferencesAfter, cleanup, rescueUsed, helperStillHeld };
      assert.equal(cleanup.state, 'resolved', 'the actual receiver must join even when its behavior is RED');
      assert.equal(rootReferencesAfter, rootReferencesBefore, 'the native-owned duplicate must actually close');
      helper.close(); closeSync(source); closeSync(root);
      console.log(JSON.stringify(observation));
      // Natural exit runs the actual N-API lifecycle; no process.exit shortcut.
    `, binary, rootPath, helperPath], { encoding: 'utf8', timeout: 10000 });
    assert.equal(child.status, 0, child.stderr);
    const observed = JSON.parse(child.stdout.trim()) as QueueObservation;
    // Qualify the real resource cleanup before asserting the frozen behavior.
    assert.equal(observed.cleanup.state, 'resolved');
    assert.equal(observed.rootReferencesBefore, 1);
    assert.equal(observed.rootReferencesHeld, 2, 'construction must hold an actual duplicated directory FD');
    assert.equal(observed.rootReferencesAfter, 1, 'cleanup must retire only its own directory FD');
    assert.equal(observed.helperStillHeld, true, 'controller cleanup must not retire the caller-owned image');
    assert.equal(observed.interfaceVersion, 3);
    assert.equal(observed.pid, 0, 'ordinary directory rejection must occur before child birth');
    assert.equal(observed.processStartToken, '');
    assert.equal(observed.constructorQueueCalls, 1, 'construction cleanup must hit the first real queue fault');
    assert.equal(observed.first.state, 'rejected');
    assert.equal(observed.first.code, 'RECOVERY_REQUIRED', 'the second queue fault must reject the first explicit close');
    assert.equal(observed.second.state, 'resolved', 'retrying close must queue and finish the actual join');
    assert.equal(observed.queueCallsBeforeCleanup, 3, 'the close retry must attempt the real queue without rescue');
    assert.equal(observed.queueCallsAfterCleanup, 3);
    assert.equal(observed.rescueUsed, false);
  });

  test('native controller retirement failure survives repeat close and refuses a fresh controller before allocation', async t => {
    const { binary, container } = await faultFixture(t);
    const rootPath = path.join(container, 'ordinary-directory');
    const helperPath = path.join(container, 'never-executed-image');
    const sentinelPath = path.join(container, 'sentinel');
    const sentinelBytes = 'unrelated reused descriptor must survive\n';
    await mkdir(rootPath, { mode: 0o700 });
    await chmod(rootPath, 0o700);
    await writeFile(helperPath, 'close-fault fixture: must never execute\n', { mode: 0o500 });
    await writeFile(sentinelPath, sentinelBytes, { mode: 0o600 });
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import { constants, openSync, closeSync, fstatSync, statSync, readdirSync, readSync } from 'node:fs';
      import { Module } from 'node:module';
      const [binary, rootPath, helperPath, sentinelPath] = process.argv.slice(1);
      const module = new Module(binary); process.dlopen(module, binary);
      const binding = module.exports;
      const root = openSync(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      const source = openSync(helperPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      const helper = binding.sealImage(source);
      const rootIdentity = fstatSync(root), helperIdentity = fstatSync(helper.descriptor());
      const sentinelIdentity = statSync(sentinelPath), bytes = Buffer.from(${JSON.stringify(sentinelBytes)});
      function rootReferences() {
        let count = 0;
        for (const entry of readdirSync('/proc/self/fd')) {
          try {
            const identity = fstatSync(Number(entry));
            if (identity.isDirectory() && identity.dev === rootIdentity.dev && identity.ino === rootIdentity.ino) count++;
          } catch (error) {
            if (error.code !== 'EBADF' && error.code !== 'ENOENT') throw error;
          }
        }
        return count;
      }
      async function bounded(promise) {
        let timer;
        try {
          return await Promise.race([
            Promise.resolve(promise).then(() => ({ state: 'resolved' }), error => ({ state: 'rejected', code: error.code })),
            new Promise(resolve => { timer = setTimeout(() => resolve({ state: 'timeout' }), 3000); })
          ]);
        } finally { clearTimeout(timer); }
      }
      function sentinelIntact(fd) {
        try {
          const identity = fstatSync(fd), read = Buffer.alloc(bytes.length);
          return identity.isFile() && identity.dev === sentinelIdentity.dev && identity.ino === sentinelIdentity.ino &&
            identity.size === bytes.length && readSync(fd, read, 0, read.length, 0) === bytes.length && read.equals(bytes);
        } catch { return false; }
      }
      const rootReferencesBefore = rootReferences();
      // Queue faults remain disarmed. Native close actually consumes its own
      // root duplicate, reopens the sentinel at that FD, then reports EIO.
      binding.setCloseFault(root, sentinelPath);
      const original = binding.openController(helper, root);
      const pid = original.pid, processStartToken = original.processStartToken;
      let first;
      try { first = await bounded(original.close()); }
      catch (error) { first = { state: 'rejected', code: error.code }; }
      const fault = binding.closeFaultState();
      const rootReferencesAfterFirst = rootReferences();
      const sentinelAfterFirst = sentinelIntact(fault.reusedFd);
      binding.disarmCloseFault();
      let repeated;
      try { repeated = await bounded(original.close()); }
      catch (error) { repeated = { state: 'rejected', code: error.code }; }
      const sentinelAfterRepeat = sentinelIntact(fault.reusedFd);
      const queueCallsBefore = binding.queueCalls();
      let nextReceiver, nextCode;
      try { nextReceiver = binding.openController(helper, root); }
      catch (error) { nextCode = error.code; }
      // Freeze the admission result before joining any receiver incorrectly
      // returned by the old implementation. That real cleanup cannot turn a
      // granted admission into the required pre-allocation refusal.
      const next = Object.freeze({ granted: nextReceiver !== undefined, code: nextCode,
        pid: nextReceiver?.pid, processStartToken: nextReceiver?.processStartToken,
        queueCallsBefore, queueCallsAfter: binding.queueCalls(), rootReferences: rootReferences() });
      let nextCleanup = null;
      if (nextReceiver) {
        try { nextCleanup = await bounded(nextReceiver.close()); }
        catch (error) { nextCleanup = { state: 'rejected', code: error.code }; }
      }
      const rootReferencesAfterCleanup = rootReferences();
      const sentinelAfterNext = sentinelIntact(fault.reusedFd);
      const actualHelper = fstatSync(helper.descriptor());
      const helperStillHeld = actualHelper.dev === helperIdentity.dev && actualHelper.ino === helperIdentity.ino &&
        actualHelper.size === helperIdentity.size;
      const observation = { pid, processStartToken, first, repeated,
        faulted: fault.faulted, retiredFdReused: fault.retiredFd >= 0 && fault.retiredFd === fault.reusedFd,
        openedDescriptors: fault.opened.length, sentinelAfterFirst, sentinelAfterRepeat, sentinelAfterNext,
        rootReferencesBefore, rootReferencesAfterFirst, rootReferencesAfterCleanup,
        helperStillHeld, next, nextCleanup };
      // First verify and retire every actual test-owned open. No reused FD is
      // closed blindly, and the child exits naturally after all native work.
      if (nextReceiver) assert.equal(nextCleanup.state, 'resolved', 'the incorrectly returned receiver must really join');
      assert.equal(rootReferencesAfterCleanup, rootReferencesBefore, 'all native-owned directory duplicates must close');
      for (const descriptor of fault.opened) {
        assert.equal(sentinelIntact(descriptor), true, 'cleanup must not close an unrelated reused descriptor');
        closeSync(descriptor);
      }
      helper.close(); closeSync(source); closeSync(root);
      console.log(JSON.stringify(observation));
    `, binary, rootPath, helperPath, sentinelPath], { encoding: 'utf8', timeout: 10000 });
    assert.equal(child.status, 0, child.stderr);
    const observed = JSON.parse(child.stdout.trim()) as CloseFaultObservation;
    assert.equal(observed.faulted, 1, 'the real close must complete and report exactly one injected EIO');
    assert.equal(observed.retiredFdReused, true, 'actual open must reuse the just-closed native-owned FD');
    assert.ok(observed.openedDescriptors >= 1);
    assert.equal(observed.sentinelAfterFirst, true);
    assert.equal(observed.sentinelAfterRepeat, true, 'repeat close cannot retry the consumed reused FD');
    assert.equal(observed.sentinelAfterNext, true);
    assert.equal(observed.rootReferencesBefore, 1);
    assert.equal(observed.rootReferencesAfterFirst, 1);
    assert.equal(observed.rootReferencesAfterCleanup, 1);
    assert.equal(observed.helperStillHeld, true);
    assert.equal(observed.pid, 0, 'ordinary-directory refusal must precede any child birth');
    assert.equal(observed.processStartToken, '');
    assert.equal(observed.first.state, 'rejected');
    assert.equal(observed.first.code, 'RECOVERY_REQUIRED');
    assert.equal(observed.repeated.state, 'rejected', 'disarming the test fault must not clear retirement uncertainty');
    assert.equal(observed.repeated.code, 'RECOVERY_REQUIRED');
    if (observed.next.granted) {
      assert.equal(observed.next.pid, 0);
      assert.equal(observed.next.processStartToken, '');
      assert.equal(observed.nextCleanup?.state, 'resolved', 'the RED receiver must not leak actual resources');
    }
    assert.equal(observed.next.granted, false, 'a fresh controller must refuse the process-wide retirement failure');
    assert.equal(observed.next.code, 'RECOVERY_REQUIRED');
    assert.equal(observed.next.queueCallsBefore, 1);
    assert.equal(observed.next.queueCallsAfter, 1, 'refusal must precede allocation of another native join');
    assert.equal(observed.next.rootReferences, 1, 'refusal must precede duplication of the anchor root');
    assert.equal(observed.nextCleanup, null);
  });
} else {
  test('native Linux controller factory rejects unsupported platforms before allocating a controller', async t => {
    const { binary } = await faultFixture(t);
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import assert from 'node:assert/strict';
      import { Module } from 'node:module';
      const [binary] = process.argv.slice(1);
      const module = new Module(binary); process.dlopen(module, binary);
      assert.throws(() => module.exports.openController(), { code: 'UNSUPPORTED_PLATFORM' });
      assert.equal(module.exports.sealImage, undefined);
      assert.equal(module.exports.queueCalls, undefined);
      assert.equal(module.exports.resumeJoin, undefined);
    `, binary], { encoding: 'utf8', timeout: 10000 });
    assert.equal(child.status, 0, child.stderr);
  });
}
