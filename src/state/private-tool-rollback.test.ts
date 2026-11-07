import assert from 'node:assert/strict';
import { test } from 'node:test';
import { digestOmitting } from '../kernel/identity.js';
import type { InvocationJournalEntry } from '../kernel/types.js';
import type { PrivateToolRollbackV1 } from './private-tool-rollback.js';
import { decodePrivateToolRollback, hasOnlySettledPrivateToolUnknowns } from './private-tool-rollback.js';
import { digest } from './testing/fixtures.js';

const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
const TS = '2026-09-08T00:00:00.000Z';
const REF = digest('private-tool-rollback-ref');

function settledPrivateToolUnknown(opId = 'edit-call'): InvocationJournalEntry[] {
  const prepared: InvocationJournalEntry = { seq: 1, runId: 'run-1', opId, opKind: 'tool', attempt: 0,
    leaseEpoch: 1, phase: 'prepared', target: 'builtin.edit', requestRef: REF, grantRef: REF, replayClass: 'manual',
    budgetDelta: ZERO, timestamp: TS };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'dispatch-1',
    supervisorInstanceId: 'supervisor', stateOwnerEpoch: 1, sandboxLaunchSpecRef: REF,
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
  return [prepared, claim, { ...claim, seq: 3, phase: 'unknown', budgetDelta: { ...prepared.budgetDelta },
    budgetSettlementRef: REF, evidenceRef: REF, evidenceDigest: REF }];
}

test('hasOnlySettledPrivateToolUnknowns accepts one fully charged manual tool unknown', () => {
  const journal = settledPrivateToolUnknown();
  const before = structuredClone(journal);
  assert.equal(hasOnlySettledPrivateToolUnknowns(journal), true);
  assert.deepEqual(journal, before);
});

for (const variant of [
  ['model attempts', (journal: InvocationJournalEntry[]) => journal.map(entry => ({ ...entry, opKind: 'model' as const }))],
  ['retry replay class', (journal: InvocationJournalEntry[]) => journal.map(entry => ({ ...entry, replayClass: 'retry' as const }))],
  ['missing settlement ref', (journal: InvocationJournalEntry[]) => journal.map(entry =>
    entry.phase === 'unknown' ? { ...entry, budgetSettlementRef: undefined } : entry)],
  ['budget delta drift', (journal: InvocationJournalEntry[]) => journal.map(entry =>
    entry.phase === 'unknown' ? { ...entry, budgetDelta: { ...entry.budgetDelta, toolCalls: 2 } } : entry)],
] as const) {
  test(`hasOnlySettledPrivateToolUnknowns rejects private rollback eligibility after ${variant[0]}`, () => {
    assert.equal(hasOnlySettledPrivateToolUnknowns(variant[1](settledPrivateToolUnknown())), false);
  });
}

test('hasOnlySettledPrivateToolUnknowns requires exactly one unresolved attempt', () => {
  const journal = settledPrivateToolUnknown();
  const pending = settledPrivateToolUnknown('pending').slice(0, 1).map(entry => ({ ...entry, seq: entry.seq + 3 }));
  assert.equal(hasOnlySettledPrivateToolUnknowns([...journal, ...pending]), false);
  assert.equal(hasOnlySettledPrivateToolUnknowns([]), false);
});

function validRollback(overrides: Partial<PrivateToolRollbackV1> = {}): PrivateToolRollbackV1 {
  const value = {
    schemaVersion: 1 as const,
    format: 'cliq-private-tool-rollback-v1' as const,
    code: 'TOOL_EXECUTION_FAILED' as const,
    failureKind: 'private_effect_rolled_back' as const,
    runId: 'run-1',
    opId: 'edit-call',
    attempt: 0,
    dispatchId: 'dispatch-1',
    preparedJournalSeq: 1,
    claimJournalSeq: 2,
    unknownJournalSeq: 3,
    requestRef: REF,
    targetRef: REF,
    grantRef: REF,
    sandboxLaunchSpecRef: REF,
    workerLaunchId: 'launch-1',
    leaseEpoch: 1,
    generationRef: REF,
    generationIdentityDigest: REF,
    checkpointId: 'checkpoint-1',
    workspaceStateRef: REF,
    quarantineEvidenceRef: REF,
    quarantineEvidenceDigest: REF,
    retirementEvidenceRef: REF,
    retirementEvidenceDigest: REF,
    inspectorIdentityRef: REF,
    inspectorIdentityDigest: REF,
    observedAt: TS,
    evidenceDigest: ''
  };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
  return { ...value, ...overrides };
}

test('decodePrivateToolRollback accepts a closed evidence identity', () => {
  const evidence = validRollback();
  assert.deepEqual(decodePrivateToolRollback(evidence), evidence);
  assert.equal(evidence.evidenceDigest, digestOmitting(evidence, 'evidenceDigest'));
});

for (const [name, mutate] of [
  ['nonmonotonic journal sequence', (v: PrivateToolRollbackV1) => ({ ...v, unknownJournalSeq: v.claimJournalSeq })],
  ['digest tamper', (v: PrivateToolRollbackV1) => ({ ...v, evidenceDigest: digest('foreign-digest') })],
  ['forbidden failure kind', (v: PrivateToolRollbackV1) => ({ ...v, failureKind: 'other' as 'private_effect_rolled_back' })],
] as const) {
  test(`decodePrivateToolRollback rejects ${name}`, () => {
    assert.throws(() => decodePrivateToolRollback(mutate(validRollback())), TypeError);
  });
}
