import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import { decodeDependencyAcquisitionClosure, decodeDependencyAcquisitionRetirement, type DependencyAcquisitionClosureV1,
  type DependencyAcquisitionRetirementV1, decodeDependencyBrokerDispatchClosure, type DependencyBrokerDispatchClosureV1 } from './dependency-acquisition.js';

const ref = (name: string) => canonicalSha256({ inertData: name });
function closure(): DependencyAcquisitionClosureV1 {
  const data: DependencyAcquisitionClosureV1 = { schemaVersion: 1, format: 'cliq-dependency-acquisition-closure-v1', runId: 'run', opId: 'operation',
    attempt: 0, claimEvidenceRef: ref('wholeclaim'), dispatchId: 'dispatch', dispatchJournalSeq: 2, brokerFenceTokenDigest: ref('fence'),
    inspectorIdentityRef: ref('inspector'), inspectorIdentityDigest: ref('inspector meaning'), observedAt: '2026-10-27T00:00:00.000Z',
    closure: { kind: 'dependency_transport_closed', tokenRevoked: true, networkStarted: true, requestStarted: true,
      connectionCount: 3, requestCount: 2, transferredBytes: 2_000_001, processClaimed: false, processJoined: false,
      processResultAvailable: false, processResultAcknowledged: false, processResultCustodyRetired: false, processResultCustodyOrigin: 'none',
      fenceAction: 'original_token_revoked_io_joined_worker_never_acquired' }, evidenceDigest: '' };
  data.evidenceDigest = digestOmitting(data, 'evidenceDigest'); return data;
}
test('acquisition failure data preserves partial real traffic and cannot label it a process result, death, ACK or retry', () => {
  const data = closure(); assert.deepEqual(decodeDependencyAcquisitionClosure(data), data);
  for (const update of [{ processClaimed: true }, { processJoined: true }, { processResultAvailable: true }, { processResultAcknowledged: true },
    { processResultCustodyRetired: true }, { processResultCustodyOrigin: 'controller_joined' }, { retryable: true }, { tokenRevoked: false },
    { connectionCount: 1 }, { transferredBytes: 21_474_836_481 }, { requestStarted: false }, { networkStarted: false }]) {
    const changed = { ...data, closure: { ...data.closure, ...update }, evidenceDigest: '' };
    changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest'); assert.throws(() => decodeDependencyAcquisitionClosure(changed));
  }
  const zero = { ...data, closure: { ...data.closure, networkStarted: false, requestStarted: false,
    connectionCount: 0, requestCount: 0, transferredBytes: 0 }, evidenceDigest: '' };
  zero.evidenceDigest = digestOmitting(zero, 'evidenceDigest'); assert.doesNotThrow(() => decodeDependencyAcquisitionClosure(zero));
  assert.throws(() => decodeDependencyAcquisitionClosure({ ...data, evidenceDigest: ref('changed') }));
  let traps = 0;
  assert.throws(() => decodeDependencyAcquisitionClosure(new Proxy({}, { get() { traps++; throw 0; }, ownKeys() { traps++; throw 0; } })));
  assert.equal(traps, 0);
});

test('UNKNOWN broker closure distinguishes original I/O and controller retirement from result consumption', () => {
  const value: DependencyBrokerDispatchClosureV1 = { schemaVersion: 1, format: 'cliq-dependency-broker-dispatch-closure-v1',
    runId: 'run', opId: 'original', attempt: 0, dispatchId: 'dispatch', claimJournalSeq: 2, claimEvidenceRef: ref('claim'),
    brokerFenceTokenDigest: ref('token'), inspectorIdentityRef: ref('inspector'), inspectorIdentityDigest: ref('meaning'),
    observedAt: '2026-10-27T00:00:00.000Z', io: { networkStarted: true, requestStarted: true, connectionCount: 1, requestCount: 1,
      transferredBytes: 1_048_577, processClaimed: true, processJoined: true, processResultAcknowledged: false,
      processResultCustodyRetired: true, processResultCustodyOrigin: 'controller_joined' },
    fenceAction: 'original_matching_token_revoked_all_io_joined_native_mutex_held', evidenceDigest: '' };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); assert.deepEqual(decodeDependencyBrokerDispatchClosure(value), value);
  for (const change of [{ processJoined: false }, { processResultAcknowledged: true }, { processResultCustodyRetired: false },
    { processResultCustodyOrigin: 'acknowledged' }, { processClaimed: false }, { networkStarted: false }, { requestCount: 2 },
    { transferredBytes: 21_474_836_481 }, { closeEqualsDeath: true }]) {
    const changed = { ...value, io: { ...value.io, ...change }, evidenceDigest: '' };
    changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest'); assert.throws(() => decodeDependencyBrokerDispatchClosure(changed));
  }
  const consumed = { ...value, io: { ...value.io, processResultAcknowledged: true, processResultCustodyOrigin: 'acknowledged' }, evidenceDigest: '' };
  consumed.evidenceDigest = digestOmitting(consumed, 'evidenceDigest'); assert.doesNotThrow(() => decodeDependencyBrokerDispatchClosure(consumed));
  assert.throws(() => decodeDependencyBrokerDispatchClosure({ ...value, releasePermission: true }));
});
test('acquisition retirement data requires the original closure and real parent snapshot but has no fake output fields', () => {
  const observation = closure();
  const value: DependencyAcquisitionRetirementV1 = { schemaVersion: 1, format: 'cliq-dependency-acquisition-retirement-v1',
    runId: 'run', opId: 'operation', attempt: 0, dependencyPlanRef: ref('plan'), acquisitionClosureRef: canonicalSha256(observation),
    acquisitionClosureDigest: observation.evidenceDigest, checkpointId: 'checkpoint', workspaceStateRef: ref('M'),
    snapshotEvidenceRef: ref('actual snapshot'), parentRetirementEvidenceRef: ref('original parent death'), evidenceDigest: '' };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); assert.deepEqual(decodeDependencyAcquisitionRetirement(value), value);
  for (const changed of [{ ...value, captureRef: ref('fake output') }, { ...value, packageCacheManifestRef: ref('fake success') },
    { ...value, attempt: 1 }, { ...value, acquisitionClosureRef: undefined }, { ...value, parentRetirementEvidenceRef: 'path' }]) {
    assert.throws(() => { changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest'); decodeDependencyAcquisitionRetirement(changed); });
  }
});
