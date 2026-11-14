import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { InvocationJournalEntry } from '../kernel/types.js';
import type { ToolRequestV1 } from '../kernel/tool-authorization.js';
import { ref } from '../model/testing/fixtures.js';
import { decodePrivateToolRollback, hasOnlySettledPrivateToolUnknowns, planPrivateRollbackResult, type PrivateToolRollbackV1 } from './private-tool-rollback.js';

function privateUnknown(opId = 'edit-call'): InvocationJournalEntry[] {
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
  const prepared: InvocationJournalEntry = { seq: 1, runId: 'run-1', opId, opKind: 'tool', attempt: 0, leaseEpoch: 1,
    phase: 'prepared', target: ref(10), requestRef: ref(11), grantRef: ref(12), replayClass: 'manual',
    budgetDelta: budget, timestamp: '2026-09-05T00:00:01.000Z' };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'dispatch-1',
    supervisorInstanceId: 'supervisor-1', stateOwnerEpoch: 1, sandboxLaunchSpecRef: ref(13),
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
  return [prepared, claim, { ...claim, seq: 3, phase: 'unknown', budgetDelta: { ...budget },
    budgetSettlementRef: ref(14), evidenceRef: ref(15), evidenceDigest: ref(16) }];
}

function evidence(overrides: Partial<PrivateToolRollbackV1> = {}): PrivateToolRollbackV1 {
  const value: PrivateToolRollbackV1 = { schemaVersion: 1, format: 'cliq-private-tool-rollback-v1', code: 'TOOL_EXECUTION_FAILED',
    failureKind: 'private_effect_rolled_back', runId: 'run-1', opId: 'edit-call', attempt: 0, dispatchId: 'dispatch-1',
    preparedJournalSeq: 1, claimJournalSeq: 2, unknownJournalSeq: 3, requestRef: ref(11), targetRef: ref(10), grantRef: ref(12),
    sandboxLaunchSpecRef: ref(13), workerLaunchId: 'launch-1', leaseEpoch: 1, generationRef: ref(20), generationIdentityDigest: ref(21),
    checkpointId: 'checkpoint-1', workspaceStateRef: ref(22), quarantineEvidenceRef: ref(23), quarantineEvidenceDigest: ref(24),
    retirementEvidenceRef: ref(25), retirementEvidenceDigest: ref(26), inspectorIdentityRef: ref(27), inspectorIdentityDigest: ref(28),
    observedAt: '2026-09-05T00:00:05.000Z', evidenceDigest: '', ...overrides };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
  return value;
}

const toolRequest: ToolRequestV1 = {
  schemaVersion: 1, format: 'cliq-tool-request-v1', runId: 'run-1', opId: 'edit-call', frontierRef: ref(30),
  assemblyRef: ref(31), batchItemId: 'batch', callId: 'call', callIndex: 0, toolName: 'edit',
  inputRef: ref(32), inputDigest: ref(33), targetRef: ref(10), targetDigest: ref(34),
  requestDigest: ''
};
toolRequest.requestDigest = canonicalSha256(toolRequest);

test('hasOnlySettledPrivateToolUnknowns accepts one fully charged manual edit unknown', () => {
  const journal = privateUnknown();
  assert.equal(hasOnlySettledPrivateToolUnknowns(journal), true);
});

for (const [label, mutate] of [
  ['a second open attempt', (j: InvocationJournalEntry[]) => [...j, { ...j[0]!, seq: 4, opId: 'other' }]],
  ['retry replay class', (j: InvocationJournalEntry[]) => j.map(entry => entry.seq === 1 ? { ...entry, replayClass: 'retry' as const } : entry)],
  ['model operation kind', (j: InvocationJournalEntry[]) => j.map(entry => entry.seq === 1 ? { ...entry, opKind: 'model' as const } : entry)],
  ['missing settlement', (j: InvocationJournalEntry[]) => j.map(entry => entry.seq === 3 ? { ...entry, budgetSettlementRef: undefined } : entry)],
  ['drifted charge', (j: InvocationJournalEntry[]) => j.map(entry => entry.seq === 3 ? { ...entry, budgetDelta: { ...entry.budgetDelta!, toolCalls: 0 } } : entry)]
] as const) {
  test(`hasOnlySettledPrivateToolUnknowns rejects ${label}`, () => {
    assert.equal(hasOnlySettledPrivateToolUnknowns(mutate(privateUnknown())), false);
  });
}

test('decodePrivateToolRollback rehashes and rejects sequence or digest substitutions', () => {
  const valid = evidence();
  assert.deepEqual(decodePrivateToolRollback(valid), valid);
  for (const change of [
    { claimJournalSeq: 1 }, { unknownJournalSeq: 2 }, { failureKind: 'other' as never },
    { dispatchId: '' }, { grantRef: ref(99) }, { evidenceDigest: ref(100) }
  ]) assert.throws(() => decodePrivateToolRollback({ ...valid, ...change }), TypeError);
});

test('planPrivateRollbackResult binds diagnostic and model content digests to the original rollback evidence', () => {
  const rollback = evidence();
  const result = planPrivateRollbackResult(toolRequest, rollback, '2026-09-05T00:00:06.000Z');
  assert.equal(result.item.outcome, 'error');
  assert.equal(result.artifacts.length, 2);
  const model = JSON.parse(Buffer.from(result.artifacts[0]!.bytes).toString('utf8'));
  const payload = JSON.parse(Buffer.from(result.artifacts[1]!.bytes).toString('utf8'));
  assert.equal(model.content.failureKind, 'private_effect_rolled_back');
  assert.equal(payload.diagnosticRef, canonicalSha256(rollback));
  assert.equal(payload.diagnosticDigest, rollback.evidenceDigest);
  assert.equal(payload.journalErrorRef, payload.diagnosticRef);
});