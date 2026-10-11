import assert from 'node:assert/strict';
import test from 'node:test';

import { KernelStorageError } from './errors.js';
import { openStateStore } from './store.js';

test('installed Store refuses an unpaired anchor before observing bootstrap data or opening state', async () => {
  let observed = 0;
  const untrusted = () => { observed++; throw new Error('untrusted bootstrap property'); };
  const proxy = new Proxy({}, { get: untrusted, getPrototypeOf: untrusted, ownKeys: untrusted,
    getOwnPropertyDescriptor: untrusted });
  const open = openStateStore as (root: string, authority: unknown, selected: unknown, anchor: unknown) => Promise<unknown>;
  for (const selected of [undefined, null, {}, proxy]) {
    await assert.rejects(() => open('/unavailable-installed-state', proxy, selected, proxy),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  }
  assert.equal(observed, 0, 'a supplied anchor cannot be ignored or cloned into bootstrap data');
});
