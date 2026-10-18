// Pure StopIntent data and precedence, not proof of a verifier/claim or death.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ContinuationItem, Run, StopIntent } from '../kernel/types.js';
import { agentStopDetail, decodeAgentStop, openStopBatch, selectAgentStop } from './stop.js';

const reference = 'a'.repeat(64), createdAt = '2026-10-18T00:00:01.000Z';
const run: Run = { id: 'run', sessionId: 'session', specRef: reference, status: 'queued', nextStep: 'verify', frontierRef: reference,
  revision: 2, leaseEpoch: 0, latestCheckpointId: 'checkpoint', budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
  budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0, cancelRequested: true,
  createdAt: '2026-10-18T00:00:00.000Z', updatedAt: '2026-10-18T00:00:02.000Z', deadlineAt: createdAt };

test('verifier stop branches retain closed reason detail and integrity outranks cancellation without clearing its fence', () => {
  const base = { schemaVersion: 1 as const, runId: run.id, createdAt, targetStatus: 'failed' as const };
  const integrity: StopIntent = { ...base, origin: 'kernel_integrity', reason: 'verifier_mutated_source', verifierOpId: 'verify',
    integrityEvidenceRef: reference, integrityEvidenceDigest: reference };
  const verification: StopIntent = { ...base, origin: 'verification', reason: 'verification_failed', candidateItemId: 'candidate', verifierPlanRef: reference };
  const infrastructure: StopIntent = { ...verification, reason: 'verifier_infrastructure_failed' };
  const policy: StopIntent = { ...base, origin: 'policy_deny', reason: 'verification_failed', subjectKind: 'verifier', opId: 'verify',
    policyChannelEvidenceRef: reference, policyChannelEvidenceDigest: reference };
  const cancellation: StopIntent = { ...base, origin: 'user_cancel', targetStatus: 'cancelled', reason: 'cancelled_by_user',
    principalId: 'principal', requestId: '019eae02-0000-7000-8000-000000000001' };
  const deadline: StopIntent = { ...base, origin: 'deadline', reason: 'budget_exhausted', deadlineAt: run.deadlineAt };
  const runtime: StopIntent = { ...base, origin: 'runtime', reason: 'runtime_failed', runtimeSubtype: 'runtime',
    failingOpId: 'model', runtimeFailureRef: reference, runtimeFailureDigest: reference };
  for (const intent of [integrity, verification, infrastructure, policy]) assert.deepEqual(decodeAgentStop(intent, run), intent);
  const priority = [integrity, cancellation, deadline, verification, infrastructure, runtime];
  for (const [index, prior] of priority.entries()) for (const later of priority.slice(index + 1)) {
    assert.strictEqual(selectAgentStop(prior, later), prior);
    assert.strictEqual(selectAgentStop(later, prior), prior);
  }
  assert.strictEqual(selectAgentStop(policy, verification), policy, 'equal-priority stops retain the first committed fact');
  assert.deepEqual(agentStopDetail(integrity, reference, createdAt).reasonDetail,
    { kind: 'verifier_source_mutation', verifierOpId: 'verify', violationOrDigestEvidenceRef: reference, violationOrDigestEvidenceDigest: reference });
  assert.equal(agentStopDetail(integrity, 'b'.repeat(64), createdAt).primaryEvidenceRef, reference);
  assert.deepEqual(agentStopDetail(policy, 'b'.repeat(64), createdAt).reasonDetail,
    { kind: 'policy_denied', subjectKind: 'verifier', opId: 'verify', policyChannelEvidenceRef: reference, policyChannelEvidenceDigest: reference });
  assert.deepEqual(agentStopDetail(verification, reference, createdAt).reasonDetail,
    { kind: 'verification', candidateItemId: 'candidate', verifierPlanRef: reference });
  for (const changed of [{ ...integrity, source: 'unowned' }, { ...integrity, verifierOpId: 1 },
    { ...verification, candidateItemId: { id: 'candidate' } }, { ...verification, reason: 'runtime_failed' },
    { ...policy, opId: '\0operation' }, { ...policy, subjectKind: 'delivery' }])
    assert.throws(() => decodeAgentStop(changed, run));
});

test('verifier and repair control items never hide an open tool batch during terminal draining', () => {
  const end: ContinuationItem = { schemaVersion: 1, kind: 'model_turn', itemId: 'turn', runId: run.id, modelOpId: 'model',
    modelAttempt: 0, modelTurnRef: reference, stopReason: 'end', textRef: reference, createdAt };
  const result: ContinuationItem = { schemaVersion: 1, kind: 'verifier_result', itemId: 'result', runId: run.id,
    candidateItemId: 'candidate', verifierPlanRef: reference, verifierIndex: 0, verifierId: 'tests', opId: 'verifier', attempt: 0,
    outcome: 'assertion_failed', receiptRef: reference, createdAt };
  const stopped: ContinuationItem = { schemaVersion: 1, kind: 'verifier_stop', itemId: 'stopped', runId: run.id,
    candidateItemId: 'candidate', verifierPlanRef: reference, verifierIndex: 0, verifierId: 'tests', opId: 'verifier', attempt: 0,
    stopIntent: 'cancelled_by_user', stopIntentRef: reference, containmentEvidenceRef: reference, createdAt };
  const repair: ContinuationItem = { schemaVersion: 1, kind: 'repair_diagnostic', itemId: 'repair', runId: run.id,
    candidateItemId: 'candidate', verifierPlanRef: reference, failedVerifierResultItemIds: ['result'], diagnostics: [{ verifierId: 'tests',
      diagnosticRef: reference, diagnosticDigest: reference, modelContentRef: reference, modelContentDigest: reference }], repairOrdinal: 1, createdAt };
  for (const control of [result, stopped, repair]) {
    assert.equal(openStopBatch([end, control]), undefined);
    assert.throws(() => openStopBatch([{ ...end, stopReason: 'tool_calls' }, control]));
  }
});
