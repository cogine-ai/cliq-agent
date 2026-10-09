import assert from 'node:assert/strict';
import test from 'node:test';

import { openLinuxWorkerLauncher, releaseLinuxInvocation, type LinuxInvocationClaim } from './linux-worker.js';

test('worker launcher refuses an unavailable production execution identity before creating a worker', async () => {
  await assert.rejects(openLinuxWorkerLauncher(), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal((error as Error & { code: string }).code,
      process.platform === 'linux' ? 'UNSUPPORTED_EXECUTION_IDENTITY' : 'UNSUPPORTED_PLATFORM');
    return true;
  });
});

test('invocation release rejects a caller-shaped capability without invoking its release function', () => {
  let released = false;
  assert.throws(() => releaseLinuxInvocation({ release() { released = true; } }, {} as LinuxInvocationClaim), /opaque invocation/u);
  assert.equal(released, false);
});
