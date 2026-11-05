// One immutable Session source cursor, shared by v2 context consumers. It owns
// no StateOwner/Run and never keeps a SQLite statement/transaction across await.
import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, parseCanonicalTime, requiredSafeInteger } from '../kernel/identity.js';
import { controlWireText, decodeWireSession, decodeWireSessionItem } from '../kernel/control-wire-data.js';
import type { Session, SessionItem } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KernelStorageError } from './errors.js';
import { assertSqliteConnectionOwnedBy, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';

export const SESSION_CONTEXT_INDEX_PAGE_ROWS = 64;
type ItemRow = Readonly<{ item_id: string; session_id: string; item_seq: bigint; kind: SessionItem['kind'];
  payload_ref: string; created_at: string }>;
export type SessionContextImmutableLine = Readonly<{ id: string; workspaceIdentityRef: string;
  parentSessionId?: string; forkedThroughItemSeq?: number; createdAt: string; principalId: string; limit: number;
  /** Captured physical cursor is only an immutable metadata bound. It never
   * enters the frozen logical/model prefix or changes its fork cursor. */
  physicalLimit: number }>;
export type SessionContextIndexCut = Readonly<{ session: Session; principalId: string;
  lineage: readonly SessionContextImmutableLine[]; itemCount: number; indexDigest: string; compactionIndexDigest: string }>;
function corrupt(message = 'Session source index differs from its exact immutable lineage'): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message);
}
function decodeItem(row: ItemRow): SessionItem {
  const itemSeq = requiredSafeInteger(row.item_seq, 'Session source sequence');
  return decodeWireSessionItem({ schemaVersion: 1, itemId: row.item_id, sessionId: row.session_id,
    itemSeq, kind: row.kind, payloadRef: row.payload_ref, createdAt: row.created_at });
}
function captureLineage(connection: SqliteConnection, session: Session, principalId: string): readonly SessionContextImmutableLine[] {
  const lines: SessionContextImmutableLine[] = [], seen = new Set<string>();
  let id = session.id, limit = session.latestItemSeq;
  for (;;) {
    if (seen.has(id)) return corrupt(); seen.add(id);
    const row = connection.prepare(`SELECT id,workspace_identity_ref,parent_session_id,forked_through_item_seq,created_at,principal_id
      FROM sessions WHERE id=?`).get<{ id: string; workspace_identity_ref: string; parent_session_id: string | null;
        forked_through_item_seq: bigint | null; created_at: string; principal_id: string }>(id);
    if (!row) return corrupt();
    controlWireText(row.id); controlWireText(row.principal_id); assertArtifactRef(row.workspace_identity_ref); parseCanonicalTime(row.created_at);
    const fork = row.forked_through_item_seq === null ? undefined : requiredSafeInteger(row.forked_through_item_seq, 'Session fork cursor');
    if ((row.parent_session_id === null) !== (fork === undefined) || fork !== undefined && fork < 0) return corrupt();
    if (row.parent_session_id !== null) controlWireText(row.parent_session_id);
    const child = lines.at(-1);
    if (row.principal_id !== principalId || child && (row.workspace_identity_ref !== child.workspaceIdentityRef || row.created_at > child.createdAt)) return corrupt();
    const last = connection.prepare('SELECT MAX(item_seq) AS last FROM items WHERE session_id=?').get<{ last: bigint | null }>(id);
    const physicalLimit = last?.last === null || last?.last === undefined ? (fork ?? 0) : requiredSafeInteger(last.last, 'Session physical source cursor');
    if (physicalLimit < Math.max(limit, fork ?? 0)) return corrupt();
    lines.push({ id, workspaceIdentityRef: row.workspace_identity_ref, principalId: row.principal_id, createdAt: row.created_at, limit, physicalLimit,
      ...(row.parent_session_id === null ? {} : { parentSessionId: row.parent_session_id, forkedThroughItemSeq: fork! }) });
    if (row.parent_session_id === null) break;
    id = row.parent_session_id; limit = Math.min(limit, fork!);
  }
  const first = lines[0]!;
  if (first.workspaceIdentityRef !== session.workspaceIdentityRef || first.createdAt !== session.createdAt ||
      first.parentSessionId !== session.parentSessionId || first.forkedThroughItemSeq !== session.forkedThroughItemSeq) return corrupt();
  return immutableSnapshot(lines);
}
export function assertSessionImmutableLineage(connection: SqliteConnection, cut: Pick<SessionContextIndexCut, 'lineage'>): void {
  for (const line of cut.lineage) {
    const row = connection.prepare(`SELECT workspace_identity_ref,parent_session_id,forked_through_item_seq,created_at,principal_id
      FROM sessions WHERE id=?`).get(line.id);
    if (!row || row.workspace_identity_ref !== line.workspaceIdentityRef || row.created_at !== line.createdAt ||
        row.parent_session_id !== (line.parentSessionId ?? null) || row.principal_id !== line.principalId ||
        row.forked_through_item_seq !== (line.forkedThroughItemSeq === undefined ? null : BigInt(line.forkedThroughItemSeq))) return corrupt();
  }
}
function page(connection: SqliteConnection, line: SessionContextImmutableLine, after: number, through: number,
  sessionUpdatedAt: string): readonly SessionItem[] {
  const rows = connection.prepare(`SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items
    WHERE session_id=? AND item_seq>? AND item_seq<=? ORDER BY item_seq LIMIT 64`).all<ItemRow>(line.id, after, through);
  let next = after;
  return Object.freeze(rows.map(raw => {
    const value = decodeItem(raw);
    if (value.sessionId !== line.id || value.itemSeq !== ++next || value.createdAt < line.createdAt || value.createdAt > sessionUpdatedAt) return corrupt();
    return immutableSnapshot(value);
  }));
}
/** Every page is a new actual read cut over immutable fields, checked against
 * the captured lineage. The final full digest/recheck detects any intervening
 * edit; today's mutable Session revision is never used for a frozen Run. */
export async function* readSessionContextIndexItems(driver: SqliteDriver,
  cut: Pick<SessionContextIndexCut, 'session' | 'lineage'>, options: Readonly<{ from?: number; through?: number; signal?: AbortSignal }> = {}): AsyncIterableIterator<SessionItem> {
  assertSqliteConnectionOwnedBy(driver, driver);
  const from = options.from ?? 1, through = options.through ?? cut.session.latestItemSeq;
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(through) || from < 1 || through < from - 1 || through > cut.session.latestItemSeq) return corrupt();
  let next = from;
  for (const line of [...cut.lineage].reverse()) {
    let after = Math.max(line.forkedThroughItemSeq ?? 0, from - 1);
    const end = Math.min(line.limit, through);
    while (after < end) {
      options.signal?.throwIfAborted();
      const rows = driver.readSnapshot(connection => { assertSqliteConnectionOwnedBy(driver, connection);
        assertSessionImmutableLineage(connection, cut); return page(connection, line, after, end, cut.session.updatedAt); });
      if (!rows.length) return corrupt('Session source index has a missing logical page');
      for (const value of rows) {
        options.signal?.throwIfAborted(); if (value.itemSeq !== next++) return corrupt(); yield value;
      }
      after = rows.at(-1)!.itemSeq;
      await setImmediate(); options.signal?.throwIfAborted();
    }
  }
  if (next - 1 !== through) return corrupt('Session source index does not cover its complete logical range');
}
function indexHash() { return createHash('sha256').update('cliq-session-immutable-index-v1\n').update('['); }
function hashItem(hash: ReturnType<typeof indexHash>, value: SessionItem, count: number): void {
  if (count) hash.update(','); hash.update(canonicalJsonBytes(value));
}
async function compactionDigest(driver: SqliteDriver, cut: Pick<SessionContextIndexCut, 'lineage'>, signal?: AbortSignal): Promise<string> {
  const hash = createHash('sha256').update('cliq-session-immutable-compaction-index-v1\n').update('['); let count = 0;
  for (const line of [...cut.lineage].reverse()) {
    let after = line.forkedThroughItemSeq ?? 0;
    while (after < line.physicalLimit) {
      signal?.throwIfAborted();
      const rows = driver.readSnapshot(connection => {
        assertSessionImmutableLineage(connection, cut);
        return connection.prepare(`SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items
          WHERE session_id=? AND item_seq>? AND item_seq<=? ORDER BY item_seq LIMIT 64`).all<ItemRow>(line.id, after, line.physicalLimit);
      });
      if (!rows.length) return corrupt();
      for (const row of rows) {
        if (row.item_seq !== BigInt(++after)) return corrupt();
        if (row.kind === 'compaction') hashItem(hash, decodeItem(row), count++);
      }
      await setImmediate(); signal?.throwIfAborted();
    }
  }
  return hash.update(']').digest('hex');
}
/** Captures/validates the complete physical source stream without retaining
 * it. Its digest is an internal immutable-cut checksum, not an artifact ref or
 * replacement for per-payload typed validation. */
export async function captureSessionContextIndex(driver: SqliteDriver, principalId: string, input: Session,
  signal?: AbortSignal): Promise<SessionContextIndexCut> {
  assertSqliteConnectionOwnedBy(driver, driver); const session = decodeWireSession(input);
  const lineage = driver.readSnapshot(connection => captureLineage(connection, session, principalId));
  const cut = { session, principalId, lineage }, hash = indexHash(); let count = 0;
  for await (const value of readSessionContextIndexItems(driver, cut, { signal })) hashItem(hash, value, count++);
  if (count !== session.latestItemSeq) return corrupt();
  return immutableSnapshot({ ...cut, itemCount: count, indexDigest: hash.update(']').digest('hex'),
    compactionIndexDigest: await compactionDigest(driver, cut, signal) });
}
/** Original final-transaction protection is preserved. This scan is bounded
 * in memory, not claimed bounded in wall time: DatabaseSync has no verified
 * same-connection progress/interrupt contract yet. Stop2/scale qualification
 * must exercise it; callers must not fake close with a JavaScript timeout. */
export function assertSessionContextIndex(connection: SqliteConnection, cut: SessionContextIndexCut): void {
  assertSessionImmutableLineage(connection, cut);
  const hash = indexHash(); let count = 0;
  for (const line of [...cut.lineage].reverse()) {
    let after = line.forkedThroughItemSeq ?? 0;
    while (after < line.limit) {
      const rows = page(connection, line, after, line.limit, cut.session.updatedAt);
      if (!rows.length) return corrupt();
      for (const value of rows) { if (value.itemSeq !== count + 1) return corrupt(); hashItem(hash, value, count++); }
      after = rows.at(-1)!.itemSeq;
    }
  }
  if (count !== cut.itemCount || hash.update(']').digest('hex') !== cut.indexDigest) return corrupt();
  const justifications = createHash('sha256').update('cliq-session-immutable-compaction-index-v1\n').update('['); let justificationCount = 0;
  for (const line of [...cut.lineage].reverse()) {
    let after = line.forkedThroughItemSeq ?? 0;
    while (after < line.physicalLimit) {
      const rows = connection.prepare(`SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items
        WHERE session_id=? AND item_seq>? AND item_seq<=? ORDER BY item_seq LIMIT 64`).all<ItemRow>(line.id, after, line.physicalLimit);
      if (!rows.length) return corrupt();
      for (const row of rows) {
        if (row.item_seq !== BigInt(++after)) return corrupt();
        if (row.kind === 'compaction') hashItem(justifications, decodeItem(row), justificationCount++);
      }
    }
  }
  if (justifications.update(']').digest('hex') !== cut.compactionIndexDigest) return corrupt();
}
export function sessionContextIndexJustification(driver: SqliteDriver, cut: SessionContextIndexCut, itemId: string) {
  return driver.readSnapshot(connection => {
    assertSessionImmutableLineage(connection, cut);
    const row = connection.prepare('SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items WHERE item_id=?').get<ItemRow>(itemId);
    const line = row && cut.lineage.find(line => line.id === row.session_id);
    if (!row || !line || row.kind !== 'compaction' || row.item_seq > BigInt(line.physicalLimit) ||
        row.created_at < line.createdAt || row.created_at > cut.session.updatedAt) return corrupt();
    return { item: decodeItem(row), sourceThroughItemSeq: line.limit };
  });
}
/** Checks the current mutable head only when the operation owns that head.
 * Frozen historical/admitted readers deliberately call only the immutable
 * source checker above, never substitute this current revision. */
export function assertCurrentSessionContextIndex(connection: SqliteConnection, cut: SessionContextIndexCut,
  current: Session): void {
  if (canonicalSha256(current) !== canonicalSha256(cut.session))
    throw new KernelStorageError('REVISION_CONFLICT', 'Session changed during its complete context read');
  assertSessionContextIndex(connection, cut);
}
