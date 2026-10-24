import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import {
  addBudget,
  assertBudgetWithin,
  decodeInvocationJournalEntry,
  decodeWorkspaceGenerationState,
  subtractBudget
} from './invariants.js';
import { digest } from './testing/fixtures.js';

const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const REF = digest('invariants-journal-ref');
const TS = '2026-09-08T00:00:00.000Z';

function fencedGeneration(overrides: Record<string, unknown> = {}): WorkspaceGenerationStateV1 {
  const generation = {
    schemaVersion: 1,
    generationId: 'generation-1',
    runId: 'run-1',
    generationRef: REF,
    generationIdentityDigest: REF,
    rowVersion: 2,
    sourceCheckpointId: 'checkpoint-1',
    sourceWorkspaceStateRef: REF,
    sourceWorkspaceStateDigest: REF,
    lastVerifiedTreeDigest: REF,
    updatedAt: TS,
    phase: 'fenced_reconciling',
    snapshotEvidenceRef: REF,
    snapshotEvidenceDigest: REF,
    activeWorkerLaunchId: 'launch-1',
    leaseEpoch: 1,
    waitingSubjectRef: REF,
    waitingSubjectDigest: REF,
    fencedFromPhase: 'active',
    fencedJournalSeq: 3,
    ...overrides
  };
  return generation as WorkspaceGenerationStateV1;
}

function journalEntry(overrides: Record<string, unknown> = {}) {
  return {
    seq: 1,
    runId: 'run-1',
    opId: 'op-1',
    opKind: 'tool',
    attempt: 0,
    leaseEpoch: 1,
    phase: 'prepared',
    target: 'test.read',
    requestRef: REF,
    replayClass: 'manual',
    budgetDelta: ZERO,
    timestamp: TS,
    ...overrides
  };
}

const claim = {
  dispatchId: 'dispatch-1',
  supervisorInstanceId: 'supervisor-1',
  stateOwnerEpoch: 1
};

test('decodeWorkspaceGenerationState requires fencedJournalSeq on fenced_reconciling generations', () => {
  assert.equal(decodeWorkspaceGenerationState(fencedGeneration()).fencedJournalSeq, 3);
  for (const fencedJournalSeq of [undefined, null, -1, 0.5, '3', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => decodeWorkspaceGenerationState(fencedGeneration({ fencedJournalSeq })), KernelStorageError);
  }
});

test('budget arithmetic rejects overflow and negative balances', () => {
  const large = { ...ZERO, toolCalls: Number.MAX_SAFE_INTEGER };
  assert.throws(() => addBudget(large, { ...ZERO, toolCalls: 1 }), KernelStorageError);
  assert.throws(() => subtractBudget(ZERO, { ...ZERO, toolCalls: 1 }), KernelStorageError);
  assert.deepEqual(subtractBudget({ ...ZERO, toolCalls: 2 }, { ...ZERO, toolCalls: 1 }), { ...ZERO, toolCalls: 1 });
  assert.deepEqual(addBudget({ ...ZERO, toolCalls: 1 }, { ...ZERO, toolCalls: 2 }), { ...ZERO, toolCalls: 3 });
});

test('assertBudgetWithin rejects reservations that exceed admitted ceilings', () => {
  assertBudgetWithin(ZERO, ZERO, { ...ZERO, toolCalls: 1 }, { ...ZERO, toolCalls: 5 });
  assert.throws(
    () => assertBudgetWithin({ ...ZERO, toolCalls: 4 }, ZERO, { ...ZERO, toolCalls: 2 }, { ...ZERO, toolCalls: 5 }),
    (error: unknown) => error instanceof KernelStorageError && error.code === 'BUDGET_EXHAUSTED'
  );
});

test('decodeInvocationJournalEntry enforces prepared-phase key closure', () => {
  assert.equal(decodeInvocationJournalEntry(journalEntry()).phase, 'prepared');
  for (const extra of ['dispatchId', 'resultRef', 'errorRef', 'evidenceRef']) {
    assert.throws(() => decodeInvocationJournalEntry(journalEntry({ [extra]: extra === 'dispatchId' ? 'dispatch-1' : REF })), KernelStorageError);
  }
});

test('decodeInvocationJournalEntry enforces dispatch_claimed invariants', () => {
  const claimed = journalEntry({ phase: 'dispatch_claimed', ...claim });
  assert.equal(decodeInvocationJournalEntry(claimed).phase, 'dispatch_claimed');
  assert.throws(
    () => decodeInvocationJournalEntry(journalEntry({ phase: 'dispatch_claimed', ...claim, budgetDelta: { ...ZERO, toolCalls: 1 } })),
    KernelStorageError
  );
  assert.throws(
    () => decodeInvocationJournalEntry(journalEntry({ phase: 'dispatch_claimed', budgetDelta: ZERO })),
    KernelStorageError
  );
  assert.throws(
    () => decodeInvocationJournalEntry(journalEntry({ phase: 'dispatch_claimed', ...claim, resultRef: REF })),
    KernelStorageError
  );
});

test('decodeInvocationJournalEntry enforces completed, unknown and failed phase contracts', () => {
  const completed = journalEntry({ phase: 'completed', ...claim, resultRef: REF, budgetSettlementRef: REF });
  assert.equal(decodeInvocationJournalEntry(completed).phase, 'completed');
  assert.throws(() => decodeInvocationJournalEntry(journalEntry({ phase: 'completed', ...claim, budgetSettlementRef: REF })), KernelStorageError);

  const unknown = journalEntry({
    phase: 'unknown', ...claim, evidenceRef: REF, evidenceDigest: REF, budgetSettlementRef: REF
  });
  assert.equal(decodeInvocationJournalEntry(unknown).phase, 'unknown');
  assert.throws(() => decodeInvocationJournalEntry(journalEntry({ phase: 'unknown', ...claim, budgetSettlementRef: REF })), KernelStorageError);

  const preDispatchFailed = journalEntry({ phase: 'failed', errorRef: REF, budgetSettlementRef: REF });
  assert.equal(decodeInvocationJournalEntry(preDispatchFailed).phase, 'failed');
  assert.throws(
    () => decodeInvocationJournalEntry(journalEntry({ phase: 'failed', errorRef: REF, budgetSettlementRef: REF, budgetDelta: { ...ZERO, toolCalls: 1 } })),
    KernelStorageError
  );

  const postClaimFailed = journalEntry({
    phase: 'failed', ...claim, errorRef: REF, budgetSettlementRef: REF, evidenceRef: REF, evidenceDigest: REF
  });
  assert.equal(decodeInvocationJournalEntry(postClaimFailed).phase, 'failed');
  assert.throws(
    () => decodeInvocationJournalEntry(journalEntry({ phase: 'failed', opKind: 'tool', ...claim, errorRef: REF, budgetSettlementRef: REF })),
    KernelStorageError
  );
});
