import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import { addBudget, decodeWorkspaceGenerationState, subtractBudget } from './invariants.js';

const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const REF = 'a'.repeat(64);

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
    updatedAt: '2026-09-08T00:00:00.000Z',
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
