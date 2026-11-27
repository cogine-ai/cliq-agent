import assert from 'node:assert/strict';
import { test } from 'node:test';

import { KernelStorageError } from './errors.js';
import * as installedRuntime from './installed-runtime.js';
import { checkHeldInstalledUpgradeKeeper, type NativeStateOwner } from './native-owner.js';

test('keeper initialization rejects structural selections before observing caller properties', async () => {
  const initialize = Reflect.get(installedRuntime, 'initializeInstalledKeeper') as (held: unknown) => Promise<unknown>;
  assert.equal(typeof initialize, 'function', 'keeper startup must use the verified installed producer');
  let observed = 0;
  const untrusted = () => { observed++; throw new Error('untrusted selection property'); };
  const lookalike = Object.defineProperties({}, Object.fromEntries(
    ['bundle', 'bundleDigest', 'assertHeld', 'close'].map(key => [key, { get: untrusted }])));
  const proxy = new Proxy({}, { get: untrusted, getPrototypeOf: untrusted, ownKeys: untrusted,
    getOwnPropertyDescriptor: untrusted });
  for (const candidate of [undefined, null, {}, lookalike, proxy]) {
    await assert.rejects(async () => initialize(candidate),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  }
  assert.equal(observed, 0, 'a structural selection cannot reach the trusted native producer');
});

test('current keeper checks reject foreign native owners before reading metadata', () => {
  let observed = false;
  const input = new Proxy({}, { get() { observed = true; throw new Error('foreign observation metadata'); } });
  assert.throws(() => checkHeldInstalledUpgradeKeeper({} as NativeStateOwner,
    input as Parameters<typeof checkHeldInstalledUpgradeKeeper>[1]), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(observed, false);
});
