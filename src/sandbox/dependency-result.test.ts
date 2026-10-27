import assert from 'node:assert/strict';
import test from 'node:test';
import { assertDependencyLaunchClosure } from '../state/execution-closure.js';
import { assertNativeDependencyResult, captureNativeDependencyResult, acknowledgeNativeDependencyResult,
  type LinuxBlockedDependency, type NativeDependencyResult } from './linux-worker.js';

test('dependency launch/result/ACK reject all copied or foreign purpose shapes before observing caller data', async () => {
  let observed = 0;
  const trap = () => { observed++; throw new Error('untrusted getter'); };
  const result = { terminationReason: 'exit', exitCode: 0, startedAt: '2026-10-27T00:00:00.000Z', endedAt: '2026-10-27T00:00:00.001Z',
    durationMs: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutTruncated: false, stderrTruncated: false,
    death: { cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 } };
  const getter = Object.defineProperties({}, Object.fromEntries(Object.keys(result).map(key => [key, { enumerable: true, get: trap }])));
  const proxy = new Proxy({}, { get: trap, ownKeys: trap, getPrototypeOf: trap });
  for (const value of [null, undefined, 0, {}, result, structuredClone(result), Object.freeze({ ...result }), getter, proxy]) {
    assert.throws(() => assertDependencyLaunchClosure(value)); assert.throws(() => assertNativeDependencyResult(value));
    assert.throws(() => captureNativeDependencyResult(value));
    await assert.rejects(acknowledgeNativeDependencyResult(proxy as LinuxBlockedDependency, value as NativeDependencyResult));
  }
  assert.equal(observed, 0);
});
