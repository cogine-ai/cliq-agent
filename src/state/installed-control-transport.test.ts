import assert from 'node:assert/strict';
import test from 'node:test';
import { openInstalledControlTransport } from './installed-control-transport.js';
import type { HeldInstalledRuntime } from './installed-runtime.js';
import { openInstalledSupervisorClient } from './installed-control-client.js';

test('shared installed transport refuses structural selections before reading supplied properties', async () => {
  let accessed = false;
  const supplied = new Proxy({}, { get() { accessed = true; throw new Error('caller data was inspected'); } });
  await assert.rejects(openInstalledControlTransport(supplied as HeldInstalledRuntime, 'control'));
  assert.equal(accessed, false);
  await assert.rejects(openInstalledSupervisorClient(supplied as HeldInstalledRuntime));
  assert.equal(accessed, false);
});
