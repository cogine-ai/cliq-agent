import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { KernelStorageError } from './errors.js';
import * as installation from './installed-runtime.js';
import { writeInstalledControlPackage } from './testing/installed-control-fixture.js';

test('ordinary credential scope refuses unverified selections before observing caller properties', async () => {
  const enter = Reflect.get(installation, 'withCredentialAuthorityLock') as
    (selected: unknown, callback: unknown) => Promise<unknown>;
  assert.equal(typeof enter, 'function', 'ordinary credential operations must enter through the verified installed producer');
  let observed = 0;
  const read = () => { observed++; throw new Error('untrusted property'); };
  const traps: ProxyHandler<object> = { get: read, ownKeys: read, getPrototypeOf: read, getOwnPropertyDescriptor: read };
  for (const selected of [undefined, null, {}, new Proxy({}, traps),
    Object.defineProperty({}, 'bundle', { get: read })]) {
    await assert.rejects(async () => enter(selected, new Proxy(() => {}, traps)),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    assert.equal(observed, 0);
  }
});

// A signed fixture package does not turn the ambient client Node into the
// fixed signed SEA backend; no version bump is imposed on ordinary clients.
if (process.platform === 'linux') test('an ordinary client cannot activate credential storage using its ambient SQLite engine', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-client-')));
  await chmod(fixture, 0o700);
  let selected: installation.HeldInstalledRuntime | undefined;
  try {
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    const signed = await writeInstalledControlPackage(packageRoot);
    const runtime = installation.createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    let entered = false;
    for (let retry = 0; retry < 2; retry++) {
      await assert.rejects(installation.withCredentialAuthorityLock(selected, async () => { entered = true; }),
        error => error instanceof KernelStorageError && error.code === 'UNSUPPORTED_PLATFORM');
      await selected.assertHeld();
    }
    assert.equal(entered, false);
    await assert.rejects(lstat(path.join(stateRoot, 'credentials')), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/kernel-global.lock')), { code: 'ENOENT' });
  } finally {
    if (selected) await selected.close();
    await rm(fixture, { recursive: true, force: true });
  }
});
