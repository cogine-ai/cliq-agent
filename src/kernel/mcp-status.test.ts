import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import { decodeMcpInvocationWait, decodeMcpRecoveryProbeEvidence, decodeMcpReconciledEffectResult, mcpUnresolvedProbeState } from './mcp-status.js';

const ref = (name: string) => canonicalSha256(name), at = (n: number) => new Date(Date.parse('2026-11-04T00:00:00.000Z') + n).toISOString();
const subject = { kind: 'invocation', recovery: 'mcp_reconcile', opKind: 'mcp', opId: 'original-op', attempt: 0,
  registryRevisionRef: ref('registry'), registryManifestDigest: ref('registry-data'), serverToolName: 'effect', profileId: 'signed-profile',
  profileDigest: ref('profile-data'), statusRequestTemplateRef: ref('template'), statusRequestTemplateDigest: ref('template-data'),
  completedPredicateRef: ref('yes'), completedPredicateDigest: ref('yes-data'), failedPredicateRef: ref('no'), failedPredicateDigest: ref('no-data') };
const wait = { schemaVersion: 1, kind: 'reconciliation', runId: 'run', createdFromRevision: 7, createdAt: at(0), frontierRef: ref('frontier'), subject,
  probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: at(0) } };
const signed = <T extends Record<string, unknown>>(value: T, member: string) => ({ ...value, [member]: digestOmitting(value, member) });

test('signed MCP wait has bounded persisted probes and never borrows a manual or productive owner', () => {
  assert.deepEqual(decodeMcpInvocationWait(wait), wait);
  const dispatch = signed({ schemaVersion: 1, format: 'cliq-reconciliation-probe-dispatch-v1', runId: 'run',
    reconciliationSubjectDigest: canonicalSha256(subject), probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: ref('nonce'),
    probeStartedAt: at(0), probeDeadlineAt: at(30_000), owningSupervisorInstanceId: 'supervisor', dispatchDigest: '', subjectKind: 'mcp_recovery',
    brokerDispatchId: 'probe', brokerRequestDigest: ref('readonly-request'), brokerTargetDigest: ref('original-server-target'), brokerFenceTokenDigest: ref('probe-token'),
    previousWaitingSubjectRef: canonicalSha256(wait), preparationRef: ref('original-source-intent'), preparationDigest: ref('original-source-intent-data') }, 'dispatchDigest');
  const inFlight = { ...wait, probeState: { phase: 'automatic_in_flight', automaticProbeCount: 1, userProbeCount: 0, dispatch } };
  assert.deepEqual(decodeMcpInvocationWait(inFlight), inFlight);
  const observed = mcpUnresolvedProbeState(decodeMcpInvocationWait(inFlight), ref('observed'), ref('observed-data'), at(100), 'observation');
  assert.deepEqual(observed, { phase: 'automatic_pending', automaticProbeCount: 1, userProbeCount: 0, nextProbeAt: at(1_100),
    lastProbeEvidenceRef: ref('observed'), lastProbeEvidenceDigest: ref('observed-data') });
  const cancelled = mcpUnresolvedProbeState(decodeMcpInvocationWait(inFlight), ref('joined-cancel'), ref('joined-cancel-data'), at(100), 'shutdown_cancel');
  assert.equal(cancelled.phase, 'automatic_pending');
  if (cancelled.phase === 'automatic_pending') assert.equal(cancelled.nextProbeAt, at(31_000), 'real early shutdown cannot advance the original deadline/backoff');
  assert.throws(() => mcpUnresolvedProbeState(decodeMcpInvocationWait(inFlight), ref('false-timeout'), ref('false-timeout-data'), at(29_999), 'timeout'));
  assert.throws(() => mcpUnresolvedProbeState(decodeMcpInvocationWait(inFlight), ref('late'), ref('late-data'), at(30_000), 'observation'));
  for (const changed of [{ ...wait, subject: { ...subject, recovery: 'manual' } },
    { ...wait, probeState: { phase: 'manual_only', automaticProbeCount: 0, userProbeCount: 0 } },
    { ...inFlight, probeState: { ...inFlight.probeState, automaticProbeCount: 9 } },
    { ...inFlight, probeState: { ...inFlight.probeState, userProbeCount: 1 } },
    { ...inFlight, probeState: { ...inFlight.probeState, dispatch: signed({ ...dispatch, probeDeadlineAt: at(30_001) }, 'dispatchDigest') } },
    { ...inFlight, probeState: { ...inFlight.probeState, dispatch: signed({ ...dispatch, effectGrantRef: ref('forbidden') }, 'dispatchDigest') } }])
    assert.throws(() => decodeMcpInvocationWait(changed));
});

test('status observation roots exact response and real capture separately without asserting effect authority', () => {
  const evidence = signed({ schemaVersion: 1, format: 'cliq-mcp-recovery-probe-evidence-v1', runId: 'run', waitingSubjectRef: ref('inflight-wait'),
    opId: subject.opId, attempt: 0, probeKind: 'automatic', probeOrdinal: 1, probeNonceDigest: ref('nonce'), probeDispatchDigest: ref('dispatch'),
    registryRevisionRef: subject.registryRevisionRef, registryManifestDigest: subject.registryManifestDigest, serverToolName: subject.serverToolName,
    profileId: subject.profileId, profileDigest: subject.profileDigest, statusRequestTemplateRef: subject.statusRequestTemplateRef,
    statusRequestTemplateDigest: subject.statusRequestTemplateDigest, statusRequestDigest: ref('exact-status-frame'), brokerDispatchId: 'probe',
    brokerTargetDigest: ref('readonly-target'), statusResponseRef: ref('canonical-real-status-response'), statusResponseDigest: ref('canonical-real-status-response'),
    statusCaptureRef: ref('native-original-capture'), statusCaptureDigest: ref('native-original-capture-data'),
    completedPredicateRef: subject.completedPredicateRef, completedPredicateDigest: subject.completedPredicateDigest,
    failedPredicateRef: subject.failedPredicateRef, failedPredicateDigest: subject.failedPredicateDigest, disposition: 'completed', observedAt: at(100), evidenceDigest: '' }, 'evidenceDigest');
  assert.deepEqual(decodeMcpRecoveryProbeEvidence(evidence), evidence);
  for (const changed of [{ ...evidence, statusCaptureRef: undefined }, { ...evidence, disposition: 'succeeded' },
    { ...evidence, probeOrdinal: 9 }, { ...evidence, originalEffectCancelled: true }])
    assert.throws(() => decodeMcpRecoveryProbeEvidence(signed(changed, 'evidenceDigest')));
});

test('confirmed completion with unavailable original payload remains completion and cannot fabricate a provider result', () => {
  const completed = signed({ schemaVersion: 1, format: 'cliq-mcp-reconciled-effect-result-v1', runId: 'run', opId: subject.opId, attempt: 0,
    originalDispatchId: 'original-dispatch', unknownJournalSeq: 3, budgetSettlementRef: ref('original whole-once charge'),
    probeEvidenceRef: ref('real signed status evidence'), probeEvidenceDigest: ref('real status evidence-data'), disposition: 'completed',
    originalResponse: 'unavailable', code: 'TOOL_RESULT_UNAVAILABLE', effect: 'confirmed_completed', observedAt: at(100), resultDigest: '' }, 'resultDigest');
  assert.deepEqual(decodeMcpReconciledEffectResult(completed), completed);
  const failed = signed({ ...completed, disposition: 'failed', effect: 'confirmed_failed', code: 'TOOL_EXECUTION_FAILED' }, 'resultDigest');
  assert.deepEqual(decodeMcpReconciledEffectResult(failed), failed);
  for (const changed of [{ ...completed, code: 'TOOL_EXECUTION_FAILED' }, { ...completed, disposition: 'failed' },
    { ...completed, originalResponse: { content: 'invented output' } }, { ...completed, retry: true }, { ...failed, effect: 'confirmed_completed' }])
    assert.throws(() => decodeMcpReconciledEffectResult(signed(changed, 'resultDigest')));
});

test('all eight automatic probes retain their original nonce deadline and exact backoff, then only user probes remain', () => {
  const delays = [1_000, 5_000, 30_000, 120_000, 600_000, 1_800_000, 3_600_000];
  function inFlight(ordinal: number, user = false) {
    const dispatch = signed({ schemaVersion: 1, format: 'cliq-reconciliation-probe-dispatch-v1', runId: 'run',
      reconciliationSubjectDigest: canonicalSha256(subject), probeKind: user ? 'user_requested' : 'automatic', probeOrdinal: ordinal,
      probeNonceDigest: ref(`nonce-${ordinal}-${user}`), probeStartedAt: at(0), probeDeadlineAt: at(30_000),
      owningSupervisorInstanceId: 'supervisor', subjectKind: 'mcp_recovery', brokerDispatchId: `probe-${ordinal}-${user}`,
      brokerRequestDigest: ref('readonly-request'), brokerTargetDigest: ref('original-target'), brokerFenceTokenDigest: ref('original-token'),
      previousWaitingSubjectRef: ref(`original-wait-${ordinal}-${user}`), preparationRef: ref('source-intent'), preparationDigest: ref('source-intent-data'),
      ...(user ? { controlRequestId: `original-user-request-${ordinal}`, controlRequestDigest: ref(`original-user-request-${ordinal}-data`) } : {}) }, 'dispatchDigest');
    return decodeMcpInvocationWait({ ...wait, probeState: { phase: user ? 'user_in_flight' : 'automatic_in_flight',
      automaticProbeCount: user ? 8 : ordinal, userProbeCount: user ? ordinal : 0, dispatch } });
  }
  for (let ordinal = 1; ordinal <= 8; ordinal++) {
    const current = inFlight(ordinal), observed = mcpUnresolvedProbeState(current, ref('actual-evidence'), ref('actual-evidence-data'), at(100), 'observation');
    const cancelled = mcpUnresolvedProbeState(current, ref('actual-cancellation'), ref('actual-cancellation-data'), at(100), 'shutdown_cancel');
    assert.equal(observed.automaticProbeCount, ordinal); assert.equal(cancelled.automaticProbeCount, ordinal);
    assert.equal(observed.userProbeCount, 0); assert.equal(cancelled.userProbeCount, 0);
    if (ordinal < 8) {
      assert.equal(observed.phase, 'automatic_pending'); assert.equal(cancelled.phase, 'automatic_pending');
      if (observed.phase !== 'automatic_pending' || cancelled.phase !== 'automatic_pending') assert.fail('missing original pending backoff');
      const delay = delays[ordinal - 1]; if (delay === undefined) assert.fail('missing original automatic delay');
      assert.equal(observed.nextProbeAt, at(100 + delay));
      assert.equal(cancelled.nextProbeAt, at(30_000 + delay), 'owning cancellation never advances the original deadline');
    } else { assert.equal(observed.phase, 'automatic_exhausted'); assert.equal(cancelled.phase, 'automatic_exhausted'); }
    assert.throws(() => mcpUnresolvedProbeState(current, ref('too-early-timeout'), ref('data'), at(29_999), 'timeout'));
    assert.throws(() => mcpUnresolvedProbeState(current, ref('late-response'), ref('data'), at(30_000), 'observation'));
  }
  for (const count of [1, 2, 17]) {
    const unresolved = mcpUnresolvedProbeState(inFlight(count, true), ref('user-evidence'), ref('user-evidence-data'), at(100), 'observation');
    assert.deepEqual(unresolved, { phase: 'automatic_exhausted', automaticProbeCount: 8, userProbeCount: count,
      lastProbeEvidenceRef: ref('user-evidence'), lastProbeEvidenceDigest: ref('user-evidence-data') });
  }
});
