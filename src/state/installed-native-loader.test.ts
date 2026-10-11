import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { sha256Bytes } from '../kernel/identity.js';
import { KernelStorageError } from './errors.js';
import { createInstalledRuntime, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { STATE_OWNER_NATIVE_RELATIVE_PATH, type NativeStateOwner } from './native-owner.js';
import { writeInstalledControlPackage } from './testing/installed-control-fixture.js';

// Retain the real holders and their root if actual descriptor retirement fails.
const unretiredLoaderFixtures = new Set<{ selected: HeldInstalledRuntime; fixture: string }>();

// Real signed Node/addon files, not SEA startup or worker/I1 qualification.
if (process.platform === 'linux') test('the installed producer loads its exact held helper repeatedly and joins an unawaited load before close', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-native-')));
  await chmod(fixture, 0o700);
  let selected: HeldInstalledRuntime | undefined;
  try {
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    const signed = await writeInstalledControlPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installed = await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    let native!: NativeStateOwner;
    let escapedLoader!: () => Promise<NativeStateOwner>;
    await withHeldInstalledRuntime(selected, async observation => {
      escapedLoader = observation.loadStateOwner;
      native = await observation.loadStateOwner();
      // The same owned descriptor is reused: reading from its shared EOF would
      // fail this actual second load instead of merely exercising a mock cache.
      assert.equal(await observation.loadStateOwner(), native);
      const image = await native.observeCurrentProcess();
      assert.equal(image.pid, process.pid);
      assert.equal(image.uid, process.geteuid!());
      assert.equal(image.executableImageDigest, sha256Bytes(await readFile(process.execPath)));
    });
    const helper = path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, STATE_OWNER_NATIVE_RELATIVE_PATH);
    assert((await readFile('/proc/self/maps', 'utf8')).includes(helper),
      'dlopen must map the actual installed version helper, not the checkout helper');
    await assert.rejects(async () => escapedLoader(),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    await withHeldInstalledRuntime(selected, async observation => {
      assert.equal(await observation.loadStateOwner(), native);
    });

    let pending!: Promise<NativeStateOwner>;
    const borrowing = withHeldInstalledRuntime(selected, async observation => {
      pending = observation.loadStateOwner(); // Deliberately not awaited by this callback.
    });
    const closing = selected.close();
    await borrowing;
    assert.equal(await pending, native);
    await closing;
    selected = undefined;
    await assert.rejects(async () => escapedLoader(),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  } finally {
    if (selected) {
      try { await selected.close(); }
      catch (error) { unretiredLoaderFixtures.add({ selected, fixture }); throw error; }
    }
    await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') test('selected execution rejects untrusted inputs without consuming the handle, then refuses a real non-bootstrap process', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-exec-contract-')));
  await chmod(fixture, 0o700);
  let selected: HeldInstalledRuntime | undefined;
  let releaseBorrow = () => {};
  try {
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    const signed = await writeInstalledControlPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    const held = selected;
    // Keep this public contract test runnable while the new API is genuinely
    // absent: its RED is the missing method, not a compiler diagnostic.
    const execute = Reflect.get(runtime, 'executeSelected') as
      (this: typeof runtime, held: HeldInstalledRuntime, role: 'keeper' | 'supervisor') => Promise<never>;
    assert.equal(typeof execute, 'function', 'the installed producer must expose fixed-role selected execution');
    const otherRuntime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const otherExecute = Reflect.get(otherRuntime, 'executeSelected') as typeof execute;
    let observedCallerProperties = 0;
    const untrustedObservation = () => {
      observedCallerProperties++;
      throw new Error('untrusted caller properties must not be observed');
    };
    const traps: ProxyHandler<object> = { get: untrustedObservation, getPrototypeOf: untrustedObservation,
      ownKeys: untrustedObservation, getOwnPropertyDescriptor: untrustedObservation };
    const lookalike = Object.defineProperties({}, Object.fromEntries(
      ['bundle', 'bundleDigest', 'assertHeld', 'close'].map(key => [key, { get: untrustedObservation }])));
    const mismatch = (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH';
    const rejectsUntrusted = async (receiver: unknown, candidate: unknown, role: unknown, method = execute) => {
      await assert.rejects(async () => Reflect.apply(method, receiver, [candidate, role]), mismatch);
      assert.equal(observedCallerProperties, 0);
      await held.assertHeld();
    };
    await rejectsUntrusted(undefined, held, 'supervisor');
    await rejectsUntrusted({ ...runtime }, held, 'supervisor');
    await rejectsUntrusted(new Proxy(runtime, traps), held, 'supervisor');
    await rejectsUntrusted(runtime, lookalike, 'supervisor');
    await rejectsUntrusted(runtime, { ...held }, 'supervisor');
    await rejectsUntrusted(runtime, new Proxy(held, traps), 'supervisor');
    await rejectsUntrusted(otherRuntime, held, 'supervisor', otherExecute);
    await rejectsUntrusted(runtime, held, 'worker');
    await rejectsUntrusted(runtime, held, undefined);
    await rejectsUntrusted(runtime, held, new Proxy(new String('supervisor'), traps));

    let endedBorrow!: () => Promise<void>;
    await withHeldInstalledRuntime(held, async observation => { endedBorrow = observation.revalidate; });
    let entered!: () => void;
    const borrowingEntered = new Promise<void>(resolve => { entered = resolve; });
    const permitBorrowToFinish = new Promise<void>(resolve => { releaseBorrow = resolve; });
    const borrowing = withHeldInstalledRuntime(held, async observation => {
      entered();
      await permitBorrowToFinish;
      // The real borrow must retain its original descriptors even after a
      // later terminal execution and close have consumed the public handle.
      await observation.loadStateOwner();
      await observation.revalidate();
    });
    void borrowing.catch(() => undefined);
    await Promise.race([borrowingEntered, borrowing]);
    // The real current Node is signed into this fixture, but is not running
    // from its fixed StateRoot/runtime/bootstrap inode. It must never exec.
    const execution = execute.call(runtime, held, 'supervisor');
    void execution.catch(() => undefined);
    // Observe consumption before asking close to join; an implementation that
    // merely rejects while leaving this valid handle reusable must fail here.
    const consumption = assert.rejects(async () => held.assertHeld(), mismatch);
    void consumption.catch(() => undefined);
    let borrowedAfterConsumption = false;
    const rejectsNewBorrow = assert.rejects(async () => withHeldInstalledRuntime(held,
      async () => { borrowedAfterConsumption = true; }), mismatch);
    void rejectsNewBorrow.catch(() => undefined);
    await assert.rejects(async () => endedBorrow(), mismatch);
    const closing = held.close();
    assert.equal(held.close(), closing);
    let closeJoined = false;
    void closing.then(() => { closeJoined = true; }, () => { closeJoined = true; });
    await Promise.resolve();
    assert.equal(closeJoined, false, 'close must wait for the real in-flight borrow');
    releaseBorrow();
    await borrowing;
    // If consumption regresses, these attempted operations queue behind the
    // genuine borrow. Release it before awaiting their rejection assertions.
    await consumption;
    await rejectsNewBorrow;
    assert.equal(borrowedAfterConsumption, false);
    await assert.rejects(execution, mismatch);
    await closing;
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/state-owner.lock')), { code: 'ENOENT' });
    selected = undefined;
  } finally {
    releaseBorrow();
    if (selected) {
      try { await selected.close(); }
      catch (error) { unretiredLoaderFixtures.add({ selected, fixture }); throw error; }
    }
    await rm(fixture, { recursive: true, force: true });
  }
});
