import type { InvocationJournalEntry } from '../../kernel/types.js';
import { requiredSafeInteger } from '../../kernel/identity.js';
import { KernelStorageError } from '../errors.js';
import { decodeInvocationJournalEntry } from '../invariants.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';

type JournalSqlRow = {
  run_id: string;
  seq: unknown;
  op_id: string;
  op_kind: string;
  attempt: unknown;
  phase: string;
  entry_json: string;
};

export function journalEntryFromRow(row: JournalSqlRow): InvocationJournalEntry {
  let value: unknown;
  try {
    value = JSON.parse(row.entry_json);
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Run Journal row is not valid JSON');
  }
  let entry: InvocationJournalEntry;
  try {
    entry = decodeInvocationJournalEntry(value);
  } catch (error) {
    if (error instanceof KernelStorageError) {
      throw new KernelStorageError('RECOVERY_REQUIRED', `invalid Run Journal row: ${error.message}`);
    }
    throw error;
  }
  let sequence: number;
  let attempt: number;
  try {
    sequence = requiredSafeInteger(row.seq, 'Run Journal row sequence');
    attempt = requiredSafeInteger(row.attempt, 'Run Journal row attempt');
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Run Journal numeric columns are invalid', { cause: error });
  }
  if (entry.runId !== row.run_id || entry.seq !== sequence || entry.opId !== row.op_id ||
      entry.opKind !== row.op_kind || entry.attempt !== attempt || entry.phase !== row.phase) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Run Journal columns do not match entry_json');
  }
  return entry;
}
export function readInvocationJournal(
  connection: SqliteConnection | SqliteDriver,
  runId: string
): InvocationJournalEntry[] {
  return connection
    .prepare(
      `SELECT run_id, seq, op_id, op_kind, attempt, phase, entry_json
       FROM run_journal WHERE run_id = ? ORDER BY seq`
    )
    .all<JournalSqlRow>(runId)
    .map(journalEntryFromRow);
}

export function readInvocationAttempt(
  connection: SqliteConnection | SqliteDriver,
  runId: string,
  opId: string,
  attempt: number
): InvocationJournalEntry[] {
  return connection
    .prepare(
      `SELECT run_id, seq, op_id, op_kind, attempt, phase, entry_json
       FROM run_journal WHERE run_id = ? AND op_id = ? AND attempt = ? ORDER BY seq`
    )
    .all<JournalSqlRow>(runId, opId, BigInt(attempt))
    .map(journalEntryFromRow);
}

export function readOperationJournal(connection: SqliteConnection | SqliteDriver, runId: string, opId: string): InvocationJournalEntry[] {
  return connection.prepare(`SELECT run_id, seq, op_id, op_kind, attempt, phase, entry_json
    FROM run_journal WHERE run_id = ? AND op_id = ? ORDER BY seq`)
    .all<JournalSqlRow>(runId, opId).map(journalEntryFromRow);
}

export function readHighestPreparedAttempt(
  connection: SqliteConnection | SqliteDriver,
  runId: string,
  opId: string
): InvocationJournalEntry | undefined {
  const row = connection
    .prepare(
      `SELECT run_id, seq, op_id, op_kind, attempt, phase, entry_json
       FROM run_journal
       WHERE run_id = ? AND op_id = ? AND phase = 'prepared'
       ORDER BY attempt DESC LIMIT 1`
    )
    .get<JournalSqlRow>(runId, opId);
  return row === undefined ? undefined : journalEntryFromRow(row);
}

export function nextJournalSequence(connection: SqliteConnection, runId: string): number {
  const row = connection
    .prepare('SELECT COALESCE(max(seq), 0) + 1 AS next_seq FROM run_journal WHERE run_id = ?')
    .get<{ next_seq: unknown }>(runId);
  const next = Number(row?.next_seq);
  if (!Number.isSafeInteger(next) || next < 1) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Run Journal sequence overflowed');
  }
  return next;
}

export function appendInvocationJournalEntry(
  connection: SqliteConnection,
  entry: InvocationJournalEntry
): void {
  decodeInvocationJournalEntry(entry);
  const expectedSequence = nextJournalSequence(connection, entry.runId);
  if (entry.seq !== expectedSequence) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run Journal sequence is not contiguous');
  }
  connection
    .prepare(
      `INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      entry.runId,
      BigInt(entry.seq),
      entry.opId,
      entry.opKind,
      BigInt(entry.attempt),
      entry.phase,
      JSON.stringify(entry)
    );
}
