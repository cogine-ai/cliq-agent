import assert from 'node:assert/strict';
import { test } from 'node:test';

import { KernelStorageError } from './errors.js';
import * as installedRuntime from './installed-runtime.js';

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
