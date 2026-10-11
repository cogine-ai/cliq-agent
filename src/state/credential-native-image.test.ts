import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { chmod, copyFile, mkdtemp, open, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { KernelStorageError } from './errors.js';
import * as owner from './native-owner.js';

// Actual held-helper seam, not installed credential or SQLite qualification.
test('credential bridge requires the first physically loaded helper, not another inode with identical signed bytes', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-image-')));
  try {
    const original = path.join(fixture, 'original.node'), identical = path.join(fixture, 'identical.node');
    for (const filename of [original, identical]) {
      await copyFile(owner.STATE_OWNER_NATIVE_PATH, filename, constants.COPYFILE_EXCL);
      await chmod(filename, 0o500);
    }
    const first = await open(original, constants.O_RDONLY | constants.O_NOFOLLOW);
    const second = await open(identical, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const native = await owner.loadHeldStateOwnerImage(first);
      // The existing StateOwner byte cache deliberately remains unchanged.
      assert.equal(await owner.loadHeldStateOwnerImage(second), native);
      const assertImage = Reflect.get(owner, 'assertHeldCredentialNativeImage') as
        (native: owner.NativeStateOwner, image: typeof first) => Promise<void>;
      assert.equal(typeof assertImage, 'function', 'the private credential bridge must bind actual first dlopen provenance');
      await assertImage(native, first);
      const mismatch = (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH';
      await assert.rejects(assertImage(native, second), mismatch);
      await assertImage(native, first);
      let observations = 0;
      const forged = new Proxy(native, { get() { observations++; throw new Error('untrusted getter'); } });
      await assert.rejects(assertImage(forged, first), mismatch);
      assert.equal(observations, 0);
      await first.close();
      await assert.rejects(assertImage(native, first), mismatch);
    } finally {
      await Promise.all([first.close(), second.close()]);
    }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
