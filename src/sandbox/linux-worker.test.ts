import assert from 'node:assert/strict';
import test from 'node:test';

import { assertNativeVerifierResult, captureNativeVerifierResult, openLinuxWorkerLauncher, releaseLinuxInvocation, type LinuxInvocationClaim } from './linux-worker.js';
import * as linuxWorker from './linux-worker.js';
import { KernelStorageError } from '../state/errors.js';

test('installed worker opening rejects structural selections and anchors before observing caller properties', async () => {
  const openInstalled = Reflect.get(linuxWorker, 'openInstalledLinuxWorkerLauncher') as
    (selected: unknown, anchor: unknown) => Promise<unknown>;
  assert.equal(typeof openInstalled, 'function', 'installed workers require the held selection and original anchor');
  let observed = 0;
  const untrusted = () => { observed++; throw new Error('untrusted installed input'); };
  const lookalike = Object.defineProperties({}, Object.fromEntries(
    ['bundle', 'bundleDigest', 'assertHeld', 'close'].map(key => [key, { get: untrusted }])));
  const proxy = new Proxy({}, { get: untrusted, getPrototypeOf: untrusted, ownKeys: untrusted,
    getOwnPropertyDescriptor: untrusted });
  const copied = { bundle: {}, bundleDigest: '0'.repeat(64), assertHeld() {}, close() {} };
  for (const candidate of [undefined, null, {}, lookalike, proxy, { ...copied }, structuredClone({ bundleDigest: copied.bundleDigest })]) {
    await assert.rejects(() => openInstalled(candidate, proxy),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    await assert.rejects(() => openInstalled(proxy, candidate),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  }
  assert.equal(observed, 0, 'caller shapes must not reach image loading or root borrowing');
});

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

test('verifier completion rejects structural process results without observing caller data', () => {
  let observed = 0;
  const untrusted = () => { observed++; throw new Error('caller result is not native authority'); };
  const proxy = new Proxy({}, { get: untrusted, getPrototypeOf: untrusted, ownKeys: untrusted });
  const result = { terminationReason: 'exit', exitCode: 0, startedAt: '2026-01-01T00:00:00.000Z',
    endedAt: '2026-01-01T00:00:00.001Z', durationMs: 1, stdout: new Uint8Array(), stderr: new Uint8Array(),
    stdoutTruncated: false, stderrTruncated: false, death: { cgroupPopulated: 0 } };
  const getters = Object.defineProperties({}, Object.fromEntries(Object.keys(result).map(key => [key, { get: untrusted }])));
  const stopped = { ...result, terminationReason: 'controller_stop' }; delete (stopped as { exitCode?: number }).exitCode;
  for (const value of [undefined, null, 0, {}, proxy, getters, result, stopped, structuredClone(result), Object.freeze({ ...result })]) {
    assert.throws(() => assertNativeVerifierResult(value), TypeError);
    assert.throws(() => captureNativeVerifierResult(value), TypeError);
  }
  assert.equal(observed, 0, 'only the original completed native result may enter its durable completion owner');
});
