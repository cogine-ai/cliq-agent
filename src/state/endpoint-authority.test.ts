import assert from 'node:assert/strict';
import test from 'node:test';
import * as installation from './installed-runtime.js';
import { KernelStorageError } from './errors.js';

test('locked endpoint read refuses forged and escaped-lookalike tokens before observing caller data', () => {
  const read = Reflect.get(installation, 'readEndpointAuthority') as (token: unknown, id: unknown) => unknown;
  assert.equal(typeof read, 'function');
  let observed = 0;
  const trap = () => { observed++; throw new Error('untrusted caller property'); };
  const traps: ProxyHandler<object> = { get: trap, ownKeys: trap, getPrototypeOf: trap, getOwnPropertyDescriptor: trap };
  for (const token of [undefined, null, {}, new Proxy({}, traps), Object.defineProperty({}, 'assertHeld', { get: trap })]) {
    assert.throws(() => read(token, new Proxy({}, traps)),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    assert.equal(observed, 0);
  }
});
