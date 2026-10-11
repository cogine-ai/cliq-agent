import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

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
