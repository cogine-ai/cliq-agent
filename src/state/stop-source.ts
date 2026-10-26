import type { RecoveryClosureV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import { readCheckpoint } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

/** Original cause data only. A later child/Stop cleanup Checkpoint cannot
 * become the original model/resource producer, nor supply physical authority. */
export function readStopSourceData(driver: SqliteDriver, cut: RecoveryClosureV1, observedAt: string, checkpointId?: string, sourceRunRevision?: number, registeredJournalSeq?: number) {
  const checkpoint = checkpointId === undefined ? cut.latestCheckpoint : readCheckpoint(driver, checkpointId);
  if (checkpoint.runId !== cut.run.id || checkpoint.createdAt > observedAt || checkpoint.runItemSeq > cut.items.length ||
      checkpoint.basedOnRunRevision >= cut.run.revision || checkpoint.journalSeq > cut.journal.length)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Stop source is not its original retained Checkpoint prefix');
  if (checkpointId !== undefined) {
    if (!Number.isSafeInteger(sourceRunRevision) || sourceRunRevision! < 1 || sourceRunRevision! >= cut.run.revision ||
        !Number.isSafeInteger(registeredJournalSeq) || registeredJournalSeq! < checkpoint.journalSeq || registeredJournalSeq! > cut.journal.length)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Stop source lost its original Run revision');
    // The real birth transaction creates revision 1 and its initial
    // Checkpoint together. Later Checkpoints always precede their Run cut;
    // do not pretend that a fresh child's registered cancellation had a
    // nonexistent revision-0 Checkpoint.
    const latest = driver.prepare("SELECT id FROM checkpoints WHERE run_id=? AND (based_on_run_revision<? OR (?=1 AND reason='initial' AND based_on_run_revision=1)) ORDER BY based_on_run_revision DESC,rowid DESC LIMIT 1")
      .get<{ id: string }>(cut.run.id, sourceRunRevision!, sourceRunRevision!);
    if (latest?.id !== checkpoint.id) throw new KernelStorageError('RECOVERY_REQUIRED', 'Stop source was not the actual latest Checkpoint at its original revision');

  }
  const journal = registeredJournalSeq === undefined ? cut.journal : cut.journal.slice(0, registeredJournalSeq);
  if (journal.some((row, index) => row.seq !== index + 1 || row.timestamp > observedAt))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Stop source Journal is not its complete original registered prefix');
  return { checkpoint, items: cut.items.slice(0, checkpoint.runItemSeq), journal };
}
