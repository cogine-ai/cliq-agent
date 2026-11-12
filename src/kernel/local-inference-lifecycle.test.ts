import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeInstalledControlEnvelope } from './control-wire.js';
import { addCanonicalDuration, digestOmitting } from './identity.js';
import { decodeLocalInferenceCycle, decodeLocalInferenceFailure, decodeLocalInferenceLaunch,
  decodeLocalInferenceParticipant, localInferenceFailureSources, localInferenceLaunchId } from './local-inference.js';
import { LOCAL_AT, localCycleFixture, localLaunchFixture, localRef } from '../state/testing/local-inference-data.js';

test('local activation binds original control channel and keeps retry timing independent of later joins', () => {
  const cycle = localCycleFixture(), original = cycle.participants[0]!;
  assert.equal(original.kind, 'run_submission');
  if (original.kind !== 'run_submission') assert.fail();
  const { channelIdentityRef: _ref, ...unbound } = original;
  assert.throws(() => decodeLocalInferenceParticipant(unbound), TypeError);
  const { currentLaunchId: _current, ...prior } = cycle;
  const retry = { ...prior, phase: 'retry_wait', retryNotBeforeAt: addCanonicalDuration(LOCAL_AT, 1000),
    participants: [original, { ...original, requestId: '019a3c00-0000-7000-8000-000000000002',
      joinedAt: addCanonicalDuration(LOCAL_AT, 1500) }], rowVersion: 3 };
  assert.equal(decodeLocalInferenceCycle({ ...retry, cycleDigest: digestOmitting(retry, 'cycleDigest') }).phase, 'retry_wait');
});

test('later positive retirement cannot replace a retained unresolved attempt source', () => {
  const cycle = localCycleFixture(), launch = localLaunchFixture();
  const unresolved = { schemaVersion: 1, activationCycleId: cycle.activationCycleId, ownerPrincipalId: cycle.ownerPrincipalId,
    serviceId: cycle.serviceId, serviceSpecRef: cycle.serviceSpecRef, serviceSpecDigest: cycle.serviceSpecDigest, finalAttempt: 1,
    reason: 'containment_unprovable', launchIds: cycle.launchIds, evidenceRefs: [launch.nativeInputRef],
    observedAt: addCanonicalDuration(LOCAL_AT, 20), failureDigest: '' };
  const failure = decodeLocalInferenceFailure({ ...unresolved, failureDigest: digestOmitting(unresolved, 'failureDigest') });
  const { currentLaunchId: _current, ...original } = cycle;
  const finished = { ...original, phase: 'failed', finishedAt: addCanonicalDuration(LOCAL_AT, 50),
    failureDetailRef: localRef(failure), rowVersion: 2 };
  const terminal = decodeLocalInferenceCycle({ ...finished, cycleDigest: digestOmitting(finished, 'cycleDigest') });
  const retired = decodeLocalInferenceLaunch({ ...launch, phase: 'retired', retirementKind: 'no_spawn',
    retirementEvidenceRef: localRef('actual retired proof'), retiredAt: addCanonicalDuration(LOCAL_AT, 100), rowVersion: 2 });
  const originalSource = [{ ref: launch.nativeInputRef, purpose: 'local_inference_native_input' }];
  assert.deepEqual(localInferenceFailureSources(terminal, failure, [launch]), originalSource);
  assert.deepEqual(localInferenceFailureSources(terminal, failure, [retired]), originalSource);
  const replacement = { ...unresolved, reason: 'sandbox_launch_failed', evidenceRefs: [localRef('actual retired proof')],
    observedAt: addCanonicalDuration(LOCAL_AT, 100) };
  assert.throws(() => localInferenceFailureSources(cycle,
    decodeLocalInferenceFailure({ ...replacement, failureDigest: digestOmitting(replacement, 'failureDigest') }), [retired]), TypeError);
});

test('v1 accepts only exact local activation failure and capacity responses', () => {
  const failure = { protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1, code: 'RECOVERY_REQUIRED',
    retryable: false, recoveryKind: 'local_inference_service', messageCode: 'run.local_inference_unavailable',
    detailRef: localRef('typed failure') } };
  assert.deepEqual(decodeInstalledControlEnvelope(failure, 'run.submit'), failure);
  assert.throws(() => decodeInstalledControlEnvelope({ ...failure, method: 'run.apply' }, 'run.apply'), TypeError);
  assert.throws(() => decodeInstalledControlEnvelope({ ...failure, error: { ...failure.error, retryable: true } }, 'run.submit'), TypeError);
  const capacity = { protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1, code: 'RESOURCE_EXHAUSTED',
    retryable: true, resourceKind: 'local_inference_activation_cycle', messageCode: 'run.local_inference_activation_capacity', retryAfterMs: 1000 } };
  assert.deepEqual(decodeInstalledControlEnvelope(capacity, 'run.submit'), capacity);
  assert.throws(() => decodeInstalledControlEnvelope({ ...capacity, error: { ...capacity.error, retryAfterMs: 500 } }, 'run.submit'), TypeError);
});

test('migration cancellation retains both ordered original retirements', () => {
  const before = localCycleFixture(), first = localLaunchFixture();
  const secondId = localInferenceLaunchId(before.activationCycleId, 2);
  const cycle = { ...before, activationAttempt: 2, currentLaunchId: secondId,
    launchIds: [first.launchId, secondId], rowVersion: 3 };
  const starting = decodeLocalInferenceCycle({ ...cycle, cycleDigest: digestOmitting(cycle, 'cycleDigest') });
  const firstRetirement = decodeLocalInferenceLaunch({ ...first, phase: 'retired', retirementKind: 'no_spawn',
    retirementEvidenceRef: localRef('first exact proof'), retiredAt: addCanonicalDuration(LOCAL_AT, 20), rowVersion: 2 });
  const second = { ...first, launchId: secondId, activationAttempt: 2, createdAt: addCanonicalDuration(LOCAL_AT, 1020),
    activationDeadlineAt: addCanonicalDuration(LOCAL_AT, 121020), nativeInputRef: localRef('second input') };
  const secondRetirement = decodeLocalInferenceLaunch({ ...second, phase: 'retired', retirementKind: 'no_spawn',
    retirementEvidenceRef: localRef('second exact proof'), retiredAt: addCanonicalDuration(LOCAL_AT, 1040), rowVersion: 2 });
  const input = { schemaVersion: 1, activationCycleId: before.activationCycleId, ownerPrincipalId: before.ownerPrincipalId,
    serviceId: before.serviceId, serviceSpecRef: before.serviceSpecRef, serviceSpecDigest: before.serviceSpecDigest,
    finalAttempt: 2, reason: 'activation_cancelled_for_migration', launchIds: cycle.launchIds,
    evidenceRefs: [localRef('first exact proof'), localRef('second exact proof')], observedAt: addCanonicalDuration(LOCAL_AT, 1040), failureDigest: '' };
  const failure = decodeLocalInferenceFailure({ ...input, failureDigest: digestOmitting(input, 'failureDigest') });
  assert.deepEqual(localInferenceFailureSources(starting, failure, [firstRetirement, secondRetirement]),
    input.evidenceRefs.map(ref => ({ ref, purpose: 'process_containment_no_spawn' })));
  assert.throws(() => localInferenceFailureSources(starting, failure, [firstRetirement, decodeLocalInferenceLaunch(second)]), TypeError);
  assert.throws(() => localInferenceFailureSources(starting, failure, [secondRetirement, firstRetirement]), TypeError);
});
