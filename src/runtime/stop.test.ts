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

test('delivery merge conflict retains typed evidence and cannot outrank cancellation or deadline', () => {
  const conflict: StopIntent = { schemaVersion: 1, runId: run.id, createdAt, origin: 'runtime', targetStatus: 'failed',
    reason: 'runtime_failed', runtimeSubtype: 'delivery_merge_conflict', deliveryMergeConflictItemRef: reference, conflictRef: 'b'.repeat(64) };
  assert.deepEqual(decodeAgentStop(conflict, run), conflict);
  assert.deepEqual(agentStopDetail(conflict, 'c'.repeat(64), createdAt).reasonDetail,
    { kind: 'delivery_merge_conflict', deliveryMergeConflictItemRef: reference, conflictRef: 'b'.repeat(64) });
  assert.equal(agentStopDetail(conflict, 'c'.repeat(64), createdAt).primaryEvidenceRef, 'c'.repeat(64));
  const deadline: StopIntent = { schemaVersion: 1, runId: run.id, createdAt, origin: 'deadline', targetStatus: 'failed',
    reason: 'budget_exhausted', deadlineAt: run.deadlineAt };
  assert.strictEqual(selectAgentStop(decodeAgentStop(conflict, run), decodeAgentStop(deadline, run)), deadline);
  assert.strictEqual(selectAgentStop(decodeAgentStop(deadline, run), decodeAgentStop(conflict, run)), deadline);
  for (const invalid of [{ ...conflict, conflictRef: reference, ignored: true }, { ...conflict, conflictRef: undefined },
    { ...conflict, runtimeSubtype: 'delivery_publication_failed' }]) assert.throws(() => decodeAgentStop(invalid, run));
});

test('delivery merge resource stops retain exact original sources and closed measurements, not model producer evidence', () => {
  const cause = { sourceCheckpointId: 'initial', workspaceStateRef: reference, sourceRunResultRef: 'b'.repeat(64),
    sourceBaseRef: 'c'.repeat(64), sourceDesiredRef: 'd'.repeat(64), capturedWorkspaceRef: 'e'.repeat(64),
    sourceProjectionRef: 'f'.repeat(64), sandboxProfileRef: '0'.repeat(64), mergeAlgorithm: 'cliq-diff3-v1' as const,
    limitKind: 'changed_paths' as const, observed: 2, limit: 1 };
  const intent = { schemaVersion: 1 as const, runId: run.id, createdAt, origin: 'runtime' as const, targetStatus: 'failed' as const,
    reason: 'runtime_failed' as const, runtimeSubtype: 'delivery_merge_limit_exceeded' as const, ...cause };
  assert.deepEqual(decodeAgentStop(intent, run), intent);
  assert.deepEqual(agentStopDetail(decodeAgentStop(intent, run), reference, createdAt).reasonDetail,
    { kind: 'delivery_merge_limit_exceeded', ...cause, evidenceRef: reference });
  for (const limitKind of ['changed_paths', 'changed_bytes', 'generation_bytes', 'single_file_bytes', 'merged_entries'])
    assert.equal(decodeAgentStop({ ...intent, limitKind }, run).origin, 'runtime');
  for (const changed of [{ ...intent, observed: 1 }, { ...intent, limit: -1 }, { ...intent, observed: 1.1 },
    { ...intent, limit: true }, { ...intent, limitKind: 'memory' }, { ...intent, sourceCheckpointId: '' },
    { ...intent, sandboxProfileRef: undefined }, { ...intent, sourceBaseRef: 'not-a-ref' }, { ...intent, mergeAlgorithm: 'guess' },
    { ...intent, modelOpId: 'pretend-final-model' }, { ...intent, sourceCheckpointId: '\0initial' }])
    assert.throws(() => decodeAgentStop(changed, run));
});

test('delivery policy denial keeps its closed runtime-failure subject', () => {
  const intent: StopIntent = { schemaVersion: 1, runId: run.id, createdAt, origin: 'policy_deny',
    targetStatus: 'failed', reason: 'runtime_failed', subjectKind: 'delivery', opId: 'delivery',
    policyChannelEvidenceRef: reference, policyChannelEvidenceDigest: 'b'.repeat(64) };
  assert.deepEqual(decodeAgentStop(intent, run), intent);
  assert.deepEqual(agentStopDetail(decodeAgentStop(intent, run), 'c'.repeat(64), createdAt).reasonDetail,
    { kind: 'policy_denied', subjectKind: 'delivery', opId: 'delivery', policyChannelEvidenceRef: reference, policyChannelEvidenceDigest: 'b'.repeat(64) });
  assert.throws(() => decodeAgentStop({ ...intent, reason: 'verification_failed' }, run));
  assert.throws(() => decodeAgentStop({ ...intent, subjectKind: 'dependency_install_scripts_future' }, run));
});

test('dependency script denial has its own closed runtime-failure subject and original channel evidence', () => {
  const intent: StopIntent = { schemaVersion: 1, runId: run.id, createdAt, origin: 'policy_deny',
    targetStatus: 'failed', reason: 'runtime_failed', subjectKind: 'dependency_install_scripts', opId: 'scripts',
    policyChannelEvidenceRef: reference, policyChannelEvidenceDigest: 'b'.repeat(64) };
  assert.deepEqual(decodeAgentStop(intent, run), intent);
  assert.deepEqual(agentStopDetail(decodeAgentStop(intent, run), 'c'.repeat(64), createdAt).reasonDetail,
    { kind: 'policy_denied', subjectKind: 'dependency_install_scripts', opId: 'scripts',
      policyChannelEvidenceRef: reference, policyChannelEvidenceDigest: 'b'.repeat(64) });
  for (const changed of [{ reason: 'verification_failed' }, { targetStatus: 'succeeded' },
    { subjectKind: 'dependency_install_scripts_future' }, { policyChannelEvidenceRef: undefined },
    { policyChannelEvidenceDigest: 'invalid' }, { dependencyPlanRef: reference }])
    assert.throws(() => decodeAgentStop({ ...intent, ...changed }, run));
});

test('delivery merge control facts cannot hide a live model tool batch or permit unknown kinds', () => {
  const merge: ContinuationItem = { schemaVersion: 1, kind: 'delivery_merge', itemId: 'merge', runId: run.id,
    sourceRunResultRef: reference, sourceBaseRef: reference, sourceDesiredRef: reference, capturedWorkspaceRef: reference,
    resultSourceRef: reference, diffRef: reference, summaryRef: reference, deliveryPlanRef: reference, createdAt };
  const conflict: ContinuationItem = { schemaVersion: 1, kind: 'delivery_merge_conflict', itemId: 'conflict', runId: run.id,
    sourceRunResultRef: reference, sourceBaseRef: reference, sourceDesiredRef: reference, capturedWorkspaceRef: reference,
    mergeAlgorithm: 'cliq-diff3-v1', conflictRef: reference, createdAt };
  const open: ContinuationItem = { schemaVersion: 1, kind: 'model_turn', itemId: 'model', runId: run.id, modelOpId: 'model',
    modelAttempt: 0, modelTurnRef: reference, stopReason: 'tool_calls', textRef: reference, createdAt };
  const decision: ContinuationItem = { schemaVersion: 1, kind: 'delivery_decision', itemId: 'decision', runId: run.id,
    deliveryPlanRef: reference, approvalOpId: 'approval', decision: 'deny', decisionRef: reference, createdAt };
  for (const item of [merge, conflict, decision]) {
    assert.equal(openStopBatch([item]), undefined);
    assert.throws(() => openStopBatch([open, item]));
  }
  assert.throws(() => openStopBatch([{ ...merge, kind: 'unknown_delivery_fact' } as unknown as ContinuationItem]));
});
