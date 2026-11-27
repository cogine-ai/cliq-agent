import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodePublicationPathProgressItem, type PublicationPathProgressItem } from '../kernel/publication.js';
import type { Checkpoint, InvocationJournalEntry, RecoveryClosureV1, Run } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';

type Cut = Pick<RecoveryClosureV1, 'run' | 'latestCheckpoint' | 'items' | 'journal'>;
export type PublicationProbeProgressSource = { planRef: string; prepared: InvocationJournalEntry; claim: InvocationJournalEntry;
  operation: { operationId: string; index: number } };
export type PublicationProbeProgressDelta = { beforeRun: Run; run: Run; checkpoint: Checkpoint;
  item: { itemId: string; payloadRef: string; itemSeq: number; createdAt: string }; progressItem: PublicationPathProgressItem };
const same = (actual: unknown, expected: unknown, message: string) => {
  if (canonicalSha256(actual) !== canonicalSha256(expected)) throw new TypeError(message);
};

/** Necessary cache-delta equations only, never a full recovery reader, native
 * observation or permission. The caller first verifies the genuine producer
 * token, its complete pre-I/O provenance, current SQL and any monotonic Stop.
 * No caller-supplied cut can cross that separate original-owner gate. */
export function projectPublicationProbeProgress(cut: Cut, source: PublicationProbeProgressSource, delta: PublicationProbeProgressDelta) {
  const { beforeRun, run, checkpoint, item } = delta, progress = decodePublicationPathProgressItem(delta.progressItem);
  const stable = ({ revision: _revision, updatedAt: _time, cancelRequested: _cancel, stopIntentRef: _stop, ...value }: Run) => value;
  same(stable(beforeRun), stable(cut.run), 'publication progress changed its original waiting Run');
  if (canonicalSha256(beforeRun) !== canonicalSha256(cut.run) &&
      (beforeRun.revision <= cut.run.revision || beforeRun.updatedAt < cut.run.updatedAt || !beforeRun.stopIntentRef ||
        cut.run.cancelRequested && !beforeRun.cancelRequested ||
        beforeRun.stopIntentRef === cut.run.stopIntentRef && beforeRun.cancelRequested === cut.run.cancelRequested))
    throw new TypeError('publication progress did not retain its already verified monotonic Stop');
  if (beforeRun.status !== 'waiting' || beforeRun.waitingReason !== 'reconciliation' || !beforeRun.waitingOnRef ||
      beforeRun.nextStep !== 'delivery' || !Number.isSafeInteger(beforeRun.revision + 1) ||
      source.prepared.phase !== 'prepared' || source.claim.phase !== 'dispatch_claimed' || source.claim.opKind !== 'publish' ||
      !source.claim.dispatchId || source.prepared.runId !== beforeRun.id || source.claim.runId !== beforeRun.id ||
      source.prepared.opId !== source.claim.opId || source.prepared.attempt !== source.claim.attempt)
    throw new TypeError('publication progress has no original persisted probe and permanent claim');
  same(cut.journal.find(row => row.seq === source.prepared.seq), source.prepared, 'publication progress changed its original preparation');
  same(cut.journal.find(row => row.seq === source.claim.seq), source.claim, 'publication progress changed its original permanent claim');
  const unknown = cut.journal.at(-1);
  if (!unknown || unknown.phase !== 'unknown' || unknown.opId !== source.claim.opId || unknown.attempt !== source.claim.attempt ||
      !unknown.budgetSettlementRef || !unknown.evidenceRef || progress.state !== 'desired_committed_cleanup_pending' ||
      progress.runId !== beforeRun.id || progress.deliveryPlanRef !== source.planRef || progress.operationId !== source.operation.operationId ||
      progress.operationIndex !== source.operation.index || progress.opId !== source.prepared.opId || progress.attempt !== source.prepared.attempt ||
      progress.itemId !== identityHash('cliq-publication-progress-item-v1', beforeRun.id, source.prepared.opId, String(source.prepared.attempt)) ||
      item.itemId !== progress.itemId || item.payloadRef !== canonicalSha256(progress) || item.createdAt !== progress.createdAt ||
      item.itemSeq !== cut.items.length + 1 || cut.latestCheckpoint.runItemSeq !== cut.items.length)
    throw new TypeError('publication progress replaced its exact original UNKNOWN or single excluded-control item');
  parseCanonicalTime(progress.createdAt); parseCanonicalTime(checkpoint.createdAt); parseCanonicalTime(run.updatedAt);
  if (checkpoint.id !== identityHash('cliq-publication-progress-checkpoint-v1', beforeRun.id, source.prepared.opId, String(source.prepared.attempt)) ||
      checkpoint.runId !== beforeRun.id || checkpoint.schemaVersion !== 1 || checkpoint.reason !== 'auto' ||
      checkpoint.basedOnRunRevision !== beforeRun.revision || checkpoint.runItemSeq !== item.itemSeq ||
      checkpoint.journalSeq !== cut.journal.length || checkpoint.workspaceStateRef !== cut.latestCheckpoint.workspaceStateRef ||
      checkpoint.contextManifestRef === cut.latestCheckpoint.contextManifestRef || checkpoint.createdAt !== run.updatedAt ||
      checkpoint.createdAt < beforeRun.updatedAt || checkpoint.createdAt < progress.createdAt || progress.createdAt < cut.latestCheckpoint.createdAt)
    throw new TypeError('publication progress replaced its original W_M, Journal cursor or exact resource-free Checkpoint');
  same(run, { ...beforeRun, latestCheckpointId: checkpoint.id, revision: beforeRun.revision + 1, updatedAt: checkpoint.createdAt },
    'publication progress changed more than its one committed item and Checkpoint');
  return { run: immutableSnapshot(run), latestCheckpoint: immutableSnapshot(checkpoint), items: [...cut.items,
    Object.freeze({ schemaVersion: 1 as const, itemId: item.itemId, itemSeq: item.itemSeq,
      payloadRef: item.payloadRef, payloadDigest: item.payloadRef, createdAt: item.createdAt })] };
}
