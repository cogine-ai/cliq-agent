import assert from 'node:assert/strict';
import test from 'node:test';
import * as installation from './installed-runtime.js';
import { KernelStorageError } from './errors.js';

test('locked endpoint methods refuse forged tokens before observing caller data', () => {
  const read = Reflect.get(installation, 'readEndpointAuthority') as (token: unknown, id: unknown) => unknown;
  const commit = Reflect.get(installation, 'commitEndpointAuthority') as (token: unknown, requestId: unknown, core: unknown) => unknown;
  assert.equal(typeof read, 'function'); assert.equal(typeof commit, 'function');
  let observed = 0;
  const trap = () => { observed++; throw new Error('untrusted caller property'); };
  const traps: ProxyHandler<object> = { get: trap, ownKeys: trap, getPrototypeOf: trap, getOwnPropertyDescriptor: trap };
  for (const token of [undefined, null, {}, new Proxy({}, traps), Object.defineProperty({}, 'assertHeld', { get: trap })]) {
    assert.throws(() => read(token, new Proxy({}, traps)),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    assert.throws(() => commit(token, new Proxy({}, traps), new Proxy({}, traps)),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    assert.equal(observed, 0);
  }
});
