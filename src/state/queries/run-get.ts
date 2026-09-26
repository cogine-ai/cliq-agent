import { canonicalJsonBytes } from '../../kernel/canonical.js';
import { assertArtifactRef, parseCanonicalTime, requiredSafeInteger } from '../../kernel/identity.js';
import type { Checkpoint, InvocationJournalEntry, RunItemReferenceV1, RunSnapshotV1 } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../artifacts.js';
import { decodeRunSpec } from '../decoders.js';
import { KernelStorageError } from '../errors.js';
import { journalEntryFromRow } from '../repositories/journal.js';
import { checkpointFromRow, readRun } from '../rows.js';
import type { SqliteDriver, SqliteRow } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';

export type GetRunInput = {
  principalId: string;
  runId: string;
  afterItemSeq?: number;
  afterJournalSeq?: number;
  checkpointCursor?: string;
  itemLimit?: number;
  journalLimit?: number;
  checkpointLimit?: number;
};

export type GetRunResult = {
  method: 'run.get';
  snapshot: RunSnapshotV1;
  items: RunItemReferenceV1[];
  journal: InvocationJournalEntry[];
  checkpoints: Checkpoint[];
  highWaterItemSeq: number;
  highWaterJournalSeq: number;
  highWaterCheckpointCursor?: string;
  nextItemSeq: number;
  nextJournalSeq: number;
  nextCheckpointCursor?: string;
};

type CheckpointPosition = { schemaVersion: 1; runId: string; createdAt: string; checkpointId: string };

const ID = /^[A-Za-z0-9_-]{43}$/u;
const MAX_METADATA_BYTES = 1_048_576;
const CHECKPOINT_REASONS = new Set<Checkpoint['reason']>(['initial', 'auto', 'manual', 'pre-effect', 'handoff']);

function queryBound(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new KernelStorageError('INVALID_REQUEST', `${label} is outside its allowed bounds`);
  }
  return value as number;
}

function storedSequence(value: unknown, label: string): number {
  try {
    const seq = requiredSafeInteger(value, label);
    if (seq < 0) throw new TypeError('negative sequence');
    return seq;
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', `${label} is invalid`, { cause: error });
  }
}

function positionCursor(position: CheckpointPosition): string {
  return canonicalJsonBytes(position).toString('base64url');
}

function parsePositionCursor(cursor: string, runId: string): CheckpointPosition {
  if (typeof cursor !== 'string' || cursor.length < 1 || cursor.length > 512 ||
      !/^[A-Za-z0-9_-]+$/u.test(cursor)) {
    throw new KernelStorageError('INVALID_REQUEST', 'Checkpoint cursor is malformed');
  }
  try {
    const bytes = Buffer.from(cursor, 'base64url');
    if (bytes.toString('base64url') !== cursor) throw new TypeError('noncanonical base64url');
    const value: unknown = JSON.parse(bytes.toString('utf8'));
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).length !== 4 ||
        !['schemaVersion', 'runId', 'createdAt', 'checkpointId'].every((key) => Object.hasOwn(value, key)) ||
        !canonicalJsonBytes(value).equals(bytes)) throw new TypeError('noncanonical checkpoint cursor');
    const position = value as CheckpointPosition;
    if (position.schemaVersion !== 1 || position.runId !== runId ||
        typeof position.checkpointId !== 'string' || !ID.test(position.checkpointId) ||
        typeof position.createdAt !== 'string') throw new TypeError('wrong checkpoint identity');
    parseCanonicalTime(position.createdAt);
    return position;
  } catch (error) {
    throw new KernelStorageError('INVALID_REQUEST', 'Checkpoint cursor is malformed or belongs to another Run', { cause: error });
  }
}

function itemFromRow(row: SqliteRow, runId: string): RunItemReferenceV1 {
  try {
    const itemSeq = requiredSafeInteger(row.item_seq, 'Run item sequence');
    if (row.run_id !== runId || itemSeq < 1 || typeof row.item_id !== 'string' ||
        !/^[A-Za-z0-9_-]{1,128}$/u.test(row.item_id) ||
        typeof row.payload_ref !== 'string' || typeof row.created_at !== 'string') {
      throw new TypeError('invalid Run item columns');
    }
    assertArtifactRef(row.payload_ref);
    parseCanonicalTime(row.created_at);
    return { schemaVersion: 1, itemId: row.item_id, itemSeq,
      payloadRef: row.payload_ref, payloadDigest: row.payload_ref, createdAt: row.created_at };
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained Run item is invalid', { cause: error });
  }
}

function checkpointFromValidatedRow(row: SqliteRow, runId: string,
  itemHighWater: number, journalHighWater: number, runRevision: number): Checkpoint {
  try {
    if (row.run_id !== runId || requiredSafeInteger(row.schema_version, 'Checkpoint schema') !== 1 ||
        typeof row.id !== 'string' || !ID.test(row.id) ||
        typeof row.created_at !== 'string' || typeof row.reason !== 'string' ||
        !CHECKPOINT_REASONS.has(row.reason as Checkpoint['reason']) ||
        typeof row.context_manifest_ref !== 'string' || typeof row.workspace_state_ref !== 'string') {
      throw new TypeError('invalid Checkpoint columns');
    }
    parseCanonicalTime(row.created_at);
    assertArtifactRef(row.context_manifest_ref);
    assertArtifactRef(row.workspace_state_ref);
    const checkpoint = checkpointFromRow(row);
    if (checkpoint.basedOnRunRevision < 0 || checkpoint.basedOnRunRevision > runRevision ||
        checkpoint.runItemSeq < 0 || checkpoint.runItemSeq > itemHighWater ||
        checkpoint.journalSeq < 0 || checkpoint.journalSeq > journalHighWater) {
      throw new TypeError('Checkpoint frontier exceeds the captured Run');
    }
    return checkpoint;
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained Checkpoint is invalid', { cause: error });
  }
}

/** One owner-gated read cut with independent exclusive cursors and one combined JCS cap. */
export async function getRun(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, input: GetRunInput): Promise<GetRunResult> {
  if (typeof input.principalId !== 'string' || !input.principalId ||
      typeof input.runId !== 'string' || !ID.test(input.runId)) {
    throw new KernelStorageError('INVALID_REQUEST', 'invalid Run query identity');
  }
  const afterItem = queryBound(input.afterItemSeq === undefined ? 0 : input.afterItemSeq,
    'afterItemSeq', 0, Number.MAX_SAFE_INTEGER);
  const afterJournal = queryBound(input.afterJournalSeq === undefined ? 0 : input.afterJournalSeq,
    'afterJournalSeq', 0, Number.MAX_SAFE_INTEGER);
  const itemLimit = queryBound(input.itemLimit === undefined ? 100 : input.itemLimit, 'itemLimit', 1, 1000);
  const journalLimit = queryBound(input.journalLimit === undefined ? 100 : input.journalLimit,
    'journalLimit', 1, 1000);
  const checkpointLimit = queryBound(input.checkpointLimit === undefined ? 100 : input.checkpointLimit,
    'checkpointLimit', 1, 1000);
  const afterCheckpoint = input.checkpointCursor === undefined ? undefined :
    parsePositionCursor(input.checkpointCursor, input.runId);
  assertActiveStateOwner(driver, owner);
  const initial = driver.prepare('SELECT principal_id, spec_ref FROM runs WHERE id = ?')
    .get<{ principal_id: string; spec_ref: string }>(input.runId);
  if (!initial || initial.principal_id !== input.principalId) {
    throw new KernelStorageError('NOT_FOUND', 'Run does not exist for this principal');
  }
  let operation: RunSnapshotV1['operation'];
  try {
    operation = decodeRunSpec(await artifacts.readCanonical(initial.spec_ref)).operation;
  } catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'RunSpec required for get is invalid', { cause: error });
  }
  return driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const row = connection.prepare('SELECT principal_id, spec_ref FROM runs WHERE id = ?')
      .get<{ principal_id: string; spec_ref: string }>(input.runId);
    if (!row || row.principal_id !== input.principalId) {
      throw new KernelStorageError('NOT_FOUND', 'Run does not exist for this principal');
    }
    if (row.spec_ref !== initial.spec_ref) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'RunSpec changed during get');
    }
    let run: RunSnapshotV1['run'];
    try {
      run = readRun(connection, input.runId);
    } catch (error) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained Run snapshot is invalid', { cause: error });
    }
    const itemMax = connection.prepare('SELECT max(item_seq) AS seq FROM items WHERE run_id = ?')
      .get<{ seq: unknown }>(input.runId);
    const journalMax = connection.prepare('SELECT max(seq) AS seq FROM run_journal WHERE run_id = ?')
      .get<{ seq: unknown }>(input.runId);
    const highWaterItemSeq = itemMax?.seq === null || itemMax?.seq === undefined
      ? 0 : storedSequence(itemMax.seq, 'Run item high-water');
    const highWaterJournalSeq = journalMax?.seq === null || journalMax?.seq === undefined
      ? 0 : storedSequence(journalMax.seq, 'Run Journal high-water');
    if (afterItem > highWaterItemSeq || afterJournal > highWaterJournalSeq) {
      throw new KernelStorageError('INVALID_REQUEST', 'Run sequence cursor exceeds captured high-water');
    }
    const snapshot: RunSnapshotV1 = { schemaVersion: 1, operation, run, latestRunItemSeq: highWaterItemSeq };
    const checkpointHigh = connection.prepare(
      'SELECT * FROM checkpoints WHERE run_id = ? ORDER BY created_at DESC, id DESC LIMIT 1'
    ).get(input.runId);
    if (!checkpointHigh) throw new KernelStorageError('RECOVERY_REQUIRED', 'Run has no retained initial Checkpoint');
    const latestCheckpoint = checkpointFromValidatedRow(checkpointHigh, input.runId,
      highWaterItemSeq, highWaterJournalSeq, run.revision);
    const highPosition: CheckpointPosition = { schemaVersion: 1, runId: input.runId,
      createdAt: latestCheckpoint.createdAt, checkpointId: latestCheckpoint.id };
    const highWaterCheckpointCursor = positionCursor(highPosition);
    if (afterCheckpoint) {
      const retained = connection.prepare(
        'SELECT id FROM checkpoints WHERE run_id = ? AND id = ? AND created_at = ?'
      ).get(input.runId, afterCheckpoint.checkpointId, afterCheckpoint.createdAt);
      if (!retained || afterCheckpoint.createdAt > highPosition.createdAt ||
          (afterCheckpoint.createdAt === highPosition.createdAt &&
            afterCheckpoint.checkpointId > highPosition.checkpointId)) {
        throw new KernelStorageError('INVALID_REQUEST', 'Checkpoint cursor does not name a retained Run row');
      }
    }

    const items: RunItemReferenceV1[] = [];
    const journal: InvocationJournalEntry[] = [];
    const checkpoints: Checkpoint[] = [];
    let metadataBytes = canonicalJsonBytes({ items, journal, checkpoints }).byteLength;
    let stopped = false;
    const append = <T>(target: T[], candidate: T): void => {
      const extra = (target.length ? 1 : 0) + canonicalJsonBytes(candidate).byteLength;
      if (metadataBytes + extra > MAX_METADATA_BYTES) {
        if (items.length + journal.length + checkpoints.length === 0) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'one Run metadata row exceeds the page bound');
        }
        stopped = true;
        return;
      }
      target.push(candidate);
      metadataBytes += extra;
    };

    const itemRows = connection.prepare(
      'SELECT item_id, run_id, item_seq, payload_ref, created_at FROM items ' +
      'WHERE run_id = ? AND item_seq > ? AND item_seq <= ? ORDER BY item_seq LIMIT ?'
    ).all(input.runId, afterItem, highWaterItemSeq, itemLimit);
    let nextItemSeq = afterItem;
    for (const itemRow of itemRows) {
      const item = itemFromRow(itemRow, input.runId);
      if (item.itemSeq !== nextItemSeq + 1) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'Run item sequence has a gap');
      }
      append(items, item);
      if (stopped) break;
      nextItemSeq = item.itemSeq;
    }
    if (!stopped && itemRows.length < itemLimit && nextItemSeq < highWaterItemSeq) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Run item is missing before high-water');
    }

    let nextJournalSeq = afterJournal;
    if (!stopped) {
      const journalPage = connection.prepare(
        'SELECT run_id, seq, op_id, op_kind, attempt, phase, entry_json FROM run_journal ' +
        'WHERE run_id = ? AND seq > ? AND seq <= ? ' +
        'AND length(CAST(entry_json AS BLOB)) <= ? ORDER BY seq LIMIT ?'
      );
      let remaining = journalLimit;
      while (remaining > 0 && nextJournalSeq < highWaterJournalSeq && !stopped) {
        // A retained Journal row can be large. Never materialize the
        // entire 1,000-row page before the combined response cap is applied.
        const batchLimit = Math.min(remaining, 16);
        const journalRows = journalPage.all(input.runId, nextJournalSeq,
          highWaterJournalSeq, MAX_METADATA_BYTES, batchLimit);
        for (const journalRow of journalRows) {
          const entry = journalEntryFromRow(journalRow as Parameters<typeof journalEntryFromRow>[0]);
          if (entry.seq !== nextJournalSeq + 1) {
            throw new KernelStorageError('RECOVERY_REQUIRED', 'Run Journal sequence has a gap');
          }
          append(journal, entry);
          if (stopped) break;
          nextJournalSeq = entry.seq;
        }
        if (stopped) break;
        remaining -= journalRows.length;
        if (journalRows.length < batchLimit && nextJournalSeq < highWaterJournalSeq) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'Run Journal row is missing or exceeds the page bound');
        }
      }
    }

    let nextCheckpointCursor = input.checkpointCursor;
    if (!stopped) {
      const checkpointRows = connection.prepare(
        'SELECT * FROM checkpoints WHERE run_id = ? ' +
        'AND (created_at > ? OR (created_at = ? AND id > ?)) ' +
        'AND (created_at < ? OR (created_at = ? AND id <= ?)) ' +
        'ORDER BY created_at, id LIMIT ?'
      ).all(input.runId, afterCheckpoint?.createdAt ?? '', afterCheckpoint?.createdAt ?? '',
        afterCheckpoint?.checkpointId ?? '', highPosition.createdAt, highPosition.createdAt,
        highPosition.checkpointId, checkpointLimit);
      for (const checkpointRow of checkpointRows) {
        const checkpoint = checkpointFromValidatedRow(checkpointRow, input.runId,
          highWaterItemSeq, highWaterJournalSeq, run.revision);
        append(checkpoints, checkpoint);
        if (stopped) break;
        nextCheckpointCursor = positionCursor({ schemaVersion: 1, runId: input.runId,
          createdAt: checkpoint.createdAt, checkpointId: checkpoint.id });
      }
      if (!stopped && checkpointRows.length < checkpointLimit &&
          nextCheckpointCursor !== highWaterCheckpointCursor) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'Checkpoint is missing before high-water');
      }
    }
    return {
      method: 'run.get' as const, snapshot, items, journal, checkpoints,
      highWaterItemSeq, highWaterJournalSeq, highWaterCheckpointCursor,
      nextItemSeq, nextJournalSeq, nextCheckpointCursor
    };
  });
}
