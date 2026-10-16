import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertInstalledModelNoReleaseFence } from './installed-runtime.js';
import type { ModelBrokerBinding } from './model-broker-native.js';

test('a no-release facade or closed report cannot supply the original signed native mutex owner', () => {
  const binding: ModelBrokerBinding = { runId: 'data-run', opId: 'data-model', attempt: 0, dispatchId: 'data-dispatch',
    dispatchJournalSeq: 2, requestRef: canonicalSha256('request'), requestDigest: canonicalSha256('body'),
    targetRef: canonicalSha256('target'), targetDigest: canonicalSha256('endpoint'), grantRef: canonicalSha256('grant'),
    supervisorInstanceId: 'data-owner', stateOwnerEpoch: 1, leaseEpoch: 1, brokerFenceTokenDigest: canonicalSha256('token') };
  let assertions = 0;
  const facade = Object.freeze({ assertHeld() { assertions++; }, close() {} });
  assert.throws(() => assertInstalledModelNoReleaseFence(facade, binding), { code: 'ARTIFACT_MISMATCH' });
  const closed = Object.freeze({ ...facade, kind: 'broker_transport_closed', brokerFenceTokenDigest: binding.brokerFenceTokenDigest,
    networkStarted: false, requestStarted: false, tokenRevoked: true, matchingActiveReleaseCount: 0 });
  assert.throws(() => assertInstalledModelNoReleaseFence(closed, binding), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(assertions, 0, 'private brand validation precedes any structural assertion');
});
