import { canonicalJsonBytes } from '../../kernel/canonical.js';
import { assertArtifactRef, parseCanonicalTime, requiredSafeInteger } from '../../kernel/identity.js';
import type { SessionItem, SessionSnapshotV1 } from '../../kernel/types.js';
import { KernelStorageError } from '../errors.js';
import { readSession, readSessionPrincipalId } from '../rows.js';
import type { SqliteDriver, SqliteRow } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';

export type GetSessionInput = {
  principalId: string;
  sessionId: string;
  afterItemSeq?: number;
  limit?: number;
};

export type GetSessionResult = {
  method: 'session.get';
  snapshot: SessionSnapshotV1;
  items: SessionItem[];
  highWaterItemSeq: number;
  nextItemSeq: number;
};

const SESSION_ITEM_KINDS = new Set<SessionItem['kind']>([
  'compaction', 'run_terminal', 'legacy_record', 'legacy_compaction',
  'legacy_plan', 'legacy_handoff', 'legacy_bookmark'
]);
const MAX_PAGE_BYTES = 1024 * 1024;

function itemFromRow(row: SqliteRow, sessionId: string): SessionItem {
  const itemSeq = requiredSafeInteger(row.item_seq, 'SessionItem.itemSeq');
  const kind = row.kind;
  if (itemSeq < 1 || row.session_id !== sessionId ||
      typeof row.item_id !== 'string' || row.item_id.length === 0 || row.item_id.length > 128 ||
      typeof kind !== 'string' || !SESSION_ITEM_KINDS.has(kind as SessionItem['kind']) ||
      typeof row.payload_ref !== 'string' || typeof row.created_at !== 'string') {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Session item row is invalid');
  }
  try {
    assertArtifactRef(row.payload_ref);
    parseCanonicalTime(row.created_at);
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'Session item metadata is invalid');
  }
  return {
    schemaVersion: 1,
    itemId: row.item_id,
    sessionId,
    itemSeq,
    kind: kind as SessionItem['kind'],
    payloadRef: row.payload_ref,
    createdAt: row.created_at
  };
}

/** One owner-gated SQLite snapshot; a following call captures a fresh high-water. */
export function getSession(
  driver: SqliteDriver,
  owner: StateOwnerContext,
  input: GetSessionInput
): GetSessionResult {
  if (typeof input.sessionId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.sessionId) ||
      typeof input.principalId !== 'string' || input.principalId.length === 0) {
    throw new KernelStorageError('INVALID_REQUEST', 'invalid Session query identity');
  }
  const after = input.afterItemSeq ?? 0;
  const limit = input.limit ?? 100;
  if (!Number.isSafeInteger(after) || after < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new KernelStorageError('INVALID_REQUEST', 'invalid Session page bounds');
  }
  assertActiveStateOwner(driver, owner);
  return driver.transaction((connection) => {
    assertActiveStateOwner(connection, owner);
    const session = readSession(connection, input.sessionId);
    if (readSessionPrincipalId(connection, input.sessionId) !== input.principalId) {
      throw new KernelStorageError('NOT_FOUND', 'Session does not exist for this principal');
    }
    const highWaterItemSeq = session.latestItemSeq;
    if (after > highWaterItemSeq) {
      throw new KernelStorageError('INVALID_REQUEST', 'Session cursor exceeds the captured high-water');
    }
    const rows = connection.prepare(
      'SELECT item_id, session_id, item_seq, kind, payload_ref, created_at FROM items ' +
      'WHERE session_id = ? AND item_seq > ? AND item_seq <= ? ORDER BY item_seq LIMIT ?'
    ).all(input.sessionId, after, highWaterItemSeq, limit);
    const items: SessionItem[] = [];
    let bytes = 2; // The canonical JSON brackets, including for an empty page.
    let expectedSeq = after + 1;
    for (const row of rows) {
      const item = itemFromRow(row, input.sessionId);
      if (item.itemSeq !== expectedSeq) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'Session item sequence has a gap');
      }
      const nextBytes = bytes + (items.length === 0 ? 0 : 1) + canonicalJsonBytes(item).length;
      if (nextBytes > MAX_PAGE_BYTES) {
        if (items.length === 0) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'Session item exceeds the metadata page bound');
        }
        break;
      }
      bytes = nextBytes;
      items.push(item);
      expectedSeq += 1;
    }
    if (items.length === 0 && after < highWaterItemSeq) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Session item is missing before high-water');
    }
    return {
      method: 'session.get' as const,
      snapshot: { schemaVersion: 1 as const, session },
      items,
      highWaterItemSeq,
      nextItemSeq: items.at(-1)?.itemSeq ?? after
    };
  });
}
