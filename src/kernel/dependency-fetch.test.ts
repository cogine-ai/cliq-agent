import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { decodeDependencyPackageFetchObservation, type DependencyPackageFetchObservationV1 } from './dependency-fetch.js';
const core = { schemaVersion: 1 as const, format: 'cliq-dependency-package-fetch-observation-v1' as const, runId: 'run', opId: 'op',
  invocationAttempt: 0, dispatchId: 'dispatch', brokerFenceTokenDigest: canonicalSha256('native token'), packageIndex: 0, attempt: 1 as const,
  receivedBytes: 2 * 1024 ** 2, eof: true, observedAt: '2026-10-27T00:00:01.000Z' };
test('dependency fetch data preserves larger-than-wire bytes and only the original joined retry exception', () => {
  for (const input of [{ ...core, kind: 'complete', status: 200 }, { ...core, kind: 'integrity_mismatch', status: 200 },
    { ...core, kind: 'http_error', status: 503 }, { ...core, kind: 'transport_failed', receivedBytes: 12, eof: false,
      brokerCode: 'transport_interrupted', networkStarted: true, requestStarted: true, ioJoined: true, retryableTransport: true }])
    assert.deepEqual(decodeDependencyPackageFetchObservation(input), input);
  const value: DependencyPackageFetchObservationV1 = { ...core, kind: 'transport_failed', brokerCode: 'transport_interrupted',
    networkStarted: true, requestStarted: true, ioJoined: true, retryableTransport: true };
  for (const change of [{ brokerCode: 'cancelled_or_expired' }, { attempt: 3 }, { ioJoined: false }, { retryableTransport: false },
    { networkStarted: false }, { requestStarted: false }, { receivedBytes: 67_108_865 }, { extra: 'value' }])
    assert.throws(() => decodeDependencyPackageFetchObservation({ ...value, ...change }));
  assert.throws(() => decodeDependencyPackageFetchObservation({ ...core, kind: 'complete', status: 200, eof: false }));
  assert.throws(() => decodeDependencyPackageFetchObservation({ ...core, kind: 'http_error', status: 200 }));
  let accessed = 0; const foreign = new Proxy({}, { get() { accessed++; throw new Error('foreign'); }, ownKeys() { accessed++; throw new Error('foreign'); } });
  assert.throws(() => decodeDependencyPackageFetchObservation(foreign)); assert.equal(accessed, 0);
});
