import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { decodeMcpStatusRetirement, decodeMcpStatusProbeClosure } from './mcp-status-proof.js';

// Data decoding never supplies native resources, death, fence or authority.
const ref = (name: string) => canonicalSha256(name), started = Date.parse('2026-11-04T01:00:00.000Z'), nonce = '1'.repeat(64);
function binding() {
  const texts = { runId: 'run', principalId: 'principal', probeKind: 'automatic', brokerDispatchId: 'probe', inspectorSupervisorInstanceId: 'original',
    originalOpId: 'effect', originalDispatchId: 'original-dispatch', effectServerToolName: 'effect', adapterExecutableId: 'adapter', profileId: 'profile', statusOperationName: 'status' };
  const refs = ['previousWaitingSubjectRef', 'waitingSubjectRef', 'reconciliationSubjectDigest', 'probeNonceDigest', 'probeDispatchDigest',
    'brokerRequestDigest', 'brokerTargetDigest', 'brokerFenceTokenDigest', 'originalInstanceIdentityRef', 'originalInstanceIdentityDigest',
    'registryRevisionRef', 'registryManifestDigest', 'adapterRef', 'adapterDigest', 'adapterExecutableDigest', 'profileDigest',
    'statusRequestTemplateRef', 'statusRequestTemplateDigest', 'statusRequestDigest', 'plannedContainmentRef', 'plannedContainmentDigest',
    'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest'];
  return { ...texts, ...Object.fromEntries(refs.map(key => [key, ref(key)])), nonce, probeNonceDigest: sha256Bytes(Buffer.from(nonce)), probeOrdinal: 1, probeStartedAtMs: started,
    probeDeadlineAtMs: started + 30_000, inspectorStateOwnerEpoch: 1, originalAttempt: 0, originalDispatchJournalSeq: 2 };
}
function retirement(successor = false) {
  const original = binding(), core = { schemaVersion: 1, format: 'cliq-mcp-stdio-recovery-retirement-v1', binding: original,
    retirementEvidenceRef: ref('physical'), observedAt: new Date(started + 31_000).toISOString(),
    nativeClosure: { kind: successor ? 'linux_successor_cleanup' : 'linux_original_join', lifecycleRawRef: ref('raw'), lifecycleProjectionRef: ref('projection'),
      ...(successor ? { cleanupRawRef: ref('cleanup'), cleanupProjectionRef: ref('cleanup-projection') } : {}) },
    ...(successor ? { creatorProcessDomain: { authorityDomain: 'linux_installed_native_creator_process_v1', processObservation: 'absent_or_start_token_mismatch',
      creatorSupervisorInstanceId: original.inspectorSupervisorInstanceId, creatorStateOwnerEpoch: original.inspectorStateOwnerEpoch,
      creatorProcessIdentityRef: ref('original-process'), creatorProcessIdentityDigest: ref('original-process-data'), inspectorStateOwnerEpoch: 2,
      observedAt: new Date(started + 31_000).toISOString() } } : { joined: { kind: 'mcp_stdio_recovery_owner_joined', purpose: 'recovery', execReleased: true,
      setupReleased: true, statusReleased: true, releaseFenceTokenDigest: ref('brokerFenceTokenDigest'), completedStages: ['initialize', 'initialized', 'tools_list', 'tools_call'],
      tokenRevoked: true, matchingActiveReleaseCount: 0, processJoined: true, pipesJoined: true, tasksJoined: true, outputCustodyRetired: true } }) };
  return { ...core, retirementDigest: canonicalSha256(core) };
}
const reseal = (value: Record<string, unknown>) => { const { retirementDigest: _digest, ...core } = value; return { ...core, retirementDigest: canonicalSha256(core) }; };
test('original native join and strictly newer creator-death cleanup remain a closed XOR, never mutual substitutes', () => {
  const original = retirement(), successor = retirement(true);
  if (!('joined' in original) || !original.joined || !('creatorProcessDomain' in successor) || !successor.creatorProcessDomain)
    assert.fail('the data fixtures must retain their distinct original-join and successor-death branches');
  assert.deepEqual(decodeMcpStatusRetirement(original), original); assert.deepEqual(decodeMcpStatusRetirement(successor), successor);
  assert.throws(() => decodeMcpStatusRetirement(reseal({ ...successor, joined: original.joined })));
  assert.throws(() => decodeMcpStatusRetirement(reseal({ ...original, creatorProcessDomain: successor.creatorProcessDomain })));
  for (const change of [{ inspectorStateOwnerEpoch: 1 }, { creatorStateOwnerEpoch: 2 }, { creatorSupervisorInstanceId: 'foreign' },
    { authorityDomain: 'transport_closed' }, { processObservation: 'path_absent' }])
    assert.throws(() => decodeMcpStatusRetirement(reseal({ ...successor, creatorProcessDomain: { ...successor.creatorProcessDomain, ...change } })));
});
test('a status-only join rejects effect/Admin aliases, live releases, missing custody and a manufactured phase prefix', () => {
  const original = retirement();
  if (!('joined' in original) || !original.joined) assert.fail('the original data fixture must contain its actual join branch');
  for (const change of [{ purpose: 'run' }, { effectReleased: true }, { tokenRevoked: false }, { matchingActiveReleaseCount: 1 },
    { processJoined: false }, { pipesJoined: false }, { tasksJoined: false }, { outputCustodyRetired: false },
    { completedStages: ['initialize', 'tools_call'] }, { releaseFenceTokenDigest: ref('foreign') }])
    assert.throws(() => decodeMcpStatusRetirement(reseal({ ...original, joined: { ...original.joined, ...change } })));
});
test('timeout and owning cancellation require the exact retirement root and preserve the original deadline', () => {
  const core = { schemaVersion: 1, format: 'cliq-reconciliation-probe-timeout-closure-v1', runId: 'run', waitingSubjectRef: ref('wait'),
    probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: ref('nonce'), probeDispatchDigest: ref('dispatch'),
    probeDeadlineAt: new Date(started + 30_000).toISOString(), inspectorIdentityRef: ref('inspector'), inspectorIdentityDigest: ref('inspector-data'),
    closedAt: new Date(started + 31_000).toISOString(), subjectKind: 'mcp_recovery', brokerDispatchId: 'probe', brokerTargetDigest: ref('target'),
    brokerFenceTokenDigest: ref('token'), noActiveReleaseForNonce: true, retirementRef: ref('retirement'), retirementDigest: ref('retirement-data') };
  const seal = (data: Record<string, unknown>) => ({ ...data, closureDigest: canonicalSha256(data) });
  assert.deepEqual(decodeMcpStatusProbeClosure(seal(core)), seal(core));
  for (const change of [{ noActiveReleaseForNonce: false }, { taskClosure: { closureKind: 'cancelled_and_joined', inspectorTaskCancelledAndJoined: true } },
    { lateStatusCaptureRef: ref('late') }, { lateStatusCaptureDigest: ref('late-data') }, { closedAt: new Date(started + 29_999).toISOString() }])
    assert.throws(() => decodeMcpStatusProbeClosure(seal({ ...core, ...change })));
  const cancel = { ...core, format: 'cliq-reconciliation-probe-cancellation-closure-v1', closedAt: new Date(started + 1_000).toISOString(), reason: 'owning_supervisor_shutdown' };
  assert.deepEqual(decodeMcpStatusProbeClosure(seal(cancel)), seal(cancel));
  assert.throws(() => decodeMcpStatusProbeClosure(seal({ ...cancel, reason: 'timeout' })));
});
