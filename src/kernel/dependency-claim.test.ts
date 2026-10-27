import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import { decodeDependencyClaimEvidence, type DependencyClaimEvidenceV1 } from './dependency-claim.js';

test('dependency claim data closes the original broker claim and separate offline process specification', () => {
  const ref = canonicalSha256;
  const value: DependencyClaimEvidenceV1 = { schemaVersion: 1, format: 'cliq-dependency-claim-evidence-v1', runId: 'run', opId: 'whole-operation',
    attempt: 0, dispatchId: 'dispatch', sourceCheckpointId: 'original-source-checkpoint', workerLaunchId: 'original-parent', leaseEpoch: 2,
    stateOwnerEpoch: 1, supervisorInstanceId: 'owner', dependencyPlanRef: ref('full plan bytes'), dependencyPlanDigest: ref('plan meaning'),
    requestRef: ref('request bytes'), requestDigest: ref('request meaning'), targetRef: ref('target bytes'), targetDigest: ref('target meaning'),
    grantRef: ref('grant'), sandboxLaunchSpecRef: ref('spec bytes'), sandboxLaunchSpecDigest: ref('spec meaning'),
    brokerFenceTokenDigest: ref('real token comes only from producer'), createdAt: '2026-10-27T00:00:00.000Z', evidenceDigest: '' };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); assert.deepEqual(decodeDependencyClaimEvidence(value), value);
  assert.notEqual(value.dependencyPlanRef, value.dependencyPlanDigest); assert.notEqual(value.requestRef, value.requestDigest);
  for (const changed of [{ ...value, attempt: 2 }, { ...value, leaseEpoch: 0 }, { ...value, stateOwnerEpoch: 0 },
    { ...value, arbitraryFileDescriptor: 4 }, { ...value, sourceCheckpointId: '' }, { ...value, createdAt: 'today' }])
    assert.throws(() => decodeDependencyClaimEvidence({ ...changed, evidenceDigest: digestOmitting(changed, 'evidenceDigest') }));
  assert.throws(() => decodeDependencyClaimEvidence({ ...value, sandboxLaunchSpecRef: ref('substitution') }));
  let reads = 0; const fake = { get schemaVersion() { reads++; return 1; } };
  assert.throws(() => decodeDependencyClaimEvidence(fake)); assert.equal(reads, 0);
});
