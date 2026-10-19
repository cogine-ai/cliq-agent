// Pure cache-delta equations only. These records are never admitted, committed
// or presented as StateOwner, native, cleanup or successful recovery authority.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import type { PublicationPathProgressItem } from '../kernel/publication.js';
import type { Checkpoint, InvocationJournalEntry, RecoveryClosureV1, Run } from '../kernel/types.js';
import { ZERO_BUDGET } from './rows.js';
import { projectPublicationProbeProgress } from './publication-reconciliation-progress.js';

function data() {
  const ref = 'a'.repeat(64), operationId = 'b'.repeat(43), at = '2026-10-19T00:00:00.000Z';
  const run: Run = { id: 'data-run', sessionId: 'data-session', specRef: ref, status: 'waiting', nextStep: 'delivery',
    frontierRef: ref, waitingReason: 'reconciliation', waitingOnRef: ref, revision: 7, leaseEpoch: 1,
    latestCheckpointId: 'data-unknown-checkpoint', budgetReserved: ZERO_BUDGET, budgetConsumed: { ...ZERO_BUDGET, toolCalls: 4 },
    repairCount: 0, cancelRequested: false, createdAt: at, updatedAt: at, deadlineAt: '2026-10-19T00:01:00.000Z' };
  const checkpoint: Checkpoint = { id: run.latestCheckpointId, schemaVersion: 1, runId: run.id, basedOnRunRevision: 5,
    runItemSeq: 0, contextManifestRef: ref, journalSeq: 3, workspaceStateRef: ref, createdAt: at, reason: 'auto' };
  const prepared: InvocationJournalEntry = { runId: run.id, opId: 'data-op', opKind: 'publish', seq: 1, phase: 'prepared',
    attempt: 0, leaseEpoch: 1, target: ref, requestRef: ref, grantRef: ref, replayClass: 'reconcile', budgetDelta: ZERO_BUDGET, timestamp: at };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'data-dispatch' };
  const unknown: InvocationJournalEntry = { ...claim, seq: 3, phase: 'unknown', evidenceRef: ref, evidenceDigest: ref, budgetSettlementRef: ref };
  const cut: Pick<RecoveryClosureV1, 'run' | 'latestCheckpoint' | 'items' | 'journal'> = { run, latestCheckpoint: checkpoint,
    items: [], journal: [prepared, claim, unknown] };
  const progressItem: PublicationPathProgressItem = { schemaVersion: 1, kind: 'publication_path_progress',
    itemId: identityHash('cliq-publication-progress-item-v1', run.id, prepared.opId, '0'), runId: run.id,
    deliveryPlanRef: ref, operationIndex: 0, operationId, opId: prepared.opId, attempt: 0,
    state: 'desired_committed_cleanup_pending', beforeObservationRef: ref, destinationEvidenceRef: ref,
    createdAt: '2026-10-19T00:00:00.001Z' };
  const cp: Checkpoint = { ...checkpoint, id: identityHash('cliq-publication-progress-checkpoint-v1', run.id, prepared.opId, '0'),
    basedOnRunRevision: 7, runItemSeq: 1, contextManifestRef: 'c'.repeat(64), createdAt: '2026-10-19T00:00:00.002Z' };
  const delta = { beforeRun: run, run: { ...run, revision: 8, latestCheckpointId: cp.id, updatedAt: cp.createdAt }, checkpoint: cp,
    item: { itemId: progressItem.itemId, itemSeq: 1, payloadRef: canonicalSha256(progressItem), createdAt: progressItem.createdAt }, progressItem };
  return { cut, source: { prepared, claim, planRef: ref, operation: { operationId, index: 0 } }, delta };
}

test('a producer progress delta preserves the original nonce, Journal and once-accounted budget', () => {
  const { cut, source, delta } = data(), result = projectPublicationProbeProgress(cut, source, delta);
  assert.equal(result.run.revision, 8);
  assert.equal(result.run.waitingOnRef, 'a'.repeat(64));
  assert.deepEqual(result.run.budgetConsumed, { modelTokens: 0, costMicros: 0, toolCalls: 4, repairAttempts: 0 });
  assert.equal(result.items.length, 1); assert.equal(result.items[0]!.itemSeq, 1);
  assert.deepEqual(result.latestCheckpoint, delta.checkpoint);
  assert.equal(cut.items.length, 0); assert.equal(cut.run.revision, 7);
  assert.equal(cut.journal.length, 3);
});

test('a progress delta cannot drift the nonce, accounting, original claim, W_M or Journal cursor', () => {
  const { cut, source, delta } = data();
  for (const run of [
    { ...delta.run, waitingOnRef: 'd'.repeat(64) },
    { ...delta.run, frontierRef: 'd'.repeat(64) },
    { ...delta.run, leaseEpoch: 2 },
    { ...delta.run, revision: 9 },
    { ...delta.run, stopIntentRef: 'd'.repeat(64) },
    { ...delta.run, budgetConsumed: { ...delta.run.budgetConsumed, toolCalls: 5 } },
    { ...delta.run, budgetReserved: { ...ZERO_BUDGET, toolCalls: 1 } }
  ]) assert.throws(() => projectPublicationProbeProgress(cut, source, { ...delta, run }), TypeError);
  for (const checkpoint of [
    { ...delta.checkpoint, id: 'another-checkpoint' },
    { ...delta.checkpoint, journalSeq: 4 },
    { ...delta.checkpoint, workspaceStateRef: 'd'.repeat(64) },
    { ...delta.checkpoint, basedOnRunRevision: 6 },
    { ...delta.checkpoint, runItemSeq: 2 },
    { ...delta.checkpoint, reason: 'handoff' as const }
  ]) assert.throws(() => projectPublicationProbeProgress(cut, source, { ...delta, checkpoint }), TypeError);
  assert.throws(() => projectPublicationProbeProgress(cut, { ...source, claim: { ...source.claim, dispatchId: 'another-dispatch' } }, delta), TypeError);
  assert.throws(() => projectPublicationProbeProgress(cut, source, { ...delta, item: { ...delta.item, itemSeq: 2 } }), TypeError);
  const installed = projectPublicationProbeProgress(cut, source, delta);
  assert.throws(() => projectPublicationProbeProgress({ ...cut, ...installed }, source, delta), TypeError);
});
