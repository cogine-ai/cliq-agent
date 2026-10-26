import { decodeSessionContextData } from '../kernel/session-context-data.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { Session, SessionContextProjection, SessionContextSegment, SessionItem } from '../kernel/types.js';
import type { SessionCompactionItem, SessionHandoffEntryV1 } from '../kernel/session-continuity.js';
import { decodeWireSession, decodeWireSessionItem, decodeWirePublicState, controlWireInteger, controlWireRecord, controlWireText } from '../kernel/control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyModelText } from '../model/attempt.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { sessionFromRow } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

type Reader = Pick<ArtifactCatalog, 'readCanonical'>;
type ItemRow = { item_id: string; session_id: string; item_seq: bigint; kind: SessionItem['kind']; payload_ref: string; created_at: string };
type ImmutableLine = Readonly<{ id: string; workspaceIdentityRef: string; parentSessionId?: string; forkedThroughItemSeq?: number;
  createdAt: string; principalId: string; limit: number }>;
type CompactionJustification = Readonly<{ item: SessionItem; sourceThroughItemSeq: number }>;
export type SessionContextCut = Readonly<{ session: Session; principalId: string; lineage: readonly ImmutableLine[];
  items: readonly SessionItem[]; justifications: readonly CompactionJustification[] }>;
type RawSource = Extract<SessionContextSegment, { kind: 'raw' }>['items'][number];
export type SessionCompactionIndex = (itemId: string, sources?: readonly RawSource[]) => CompactionJustification;
export type SessionContextEntry = SessionHandoffEntryV1 & Readonly<{ sourceItemId: string }>;
function corrupt(message = 'Session context differs from its original immutable graph and index'): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message);
}
function item(row: ItemRow): SessionItem {
  if (row.item_seq > BigInt(Number.MAX_SAFE_INTEGER)) return corrupt();
  return decodeWireSessionItem({ schemaVersion: 1, itemId: row.item_id, sessionId: row.session_id, itemSeq: Number(row.item_seq),
    kind: row.kind, payloadRef: row.payload_ref, createdAt: row.created_at });
}
async function read<T>(artifacts: Reader, ref: string): Promise<T> {
  assertArtifactRef(ref);
  const data = await artifacts.readCanonical<T>(ref);
  if (canonicalSha256(data) !== ref) return corrupt();
  return data;
}
export function sessionSourceItemsDigest(items: readonly Pick<SessionItem, 'itemSeq' | 'kind' | 'payloadRef'>[]): string {
  return canonicalSha256(items.map(value => ({ itemSeq: value.itemSeq, kind: value.kind, payloadRef: value.payloadRef })));
}
export function decodeSessionContext(value: unknown): SessionContextProjection {
  try { return decodeSessionContextData(value); }
  catch (error) { if (error instanceof TypeError) return corrupt(); throw error; }
}

function lineage(connection: SqliteConnection | SqliteDriver, session: Session, principalId: string, through: number): ImmutableLine[] {
  const lines = immutableLineage(connection, session.id, through), first = lines[0]!;
  if (first.principalId !== principalId || first.workspaceIdentityRef !== session.workspaceIdentityRef || first.createdAt !== session.createdAt ||
      first.parentSessionId !== session.parentSessionId || first.forkedThroughItemSeq !== session.forkedThroughItemSeq) return corrupt();
  return lines;
}
function lookupJustification(connection: SqliteConnection | SqliteDriver, lines: readonly ImmutableLine[], itemId: string): CompactionJustification {
  const row = connection.prepare('SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items WHERE item_id=?').get<ItemRow>(itemId);
  if (!row || row.kind !== 'compaction') return corrupt();
  const source = lines.find(line => line.id === row.session_id);
  if (!source || row.created_at < source.createdAt) return corrupt();
  // The justification may follow a forked summary's cursor. It is not an
  // inherited logical item; its exact source range is verified below.
  return { item: item(row), sourceThroughItemSeq: source.limit };
}
/** Uses only committed immutable Session lineage/index fields. It never
 * consults today's Session revision/projection or grants current permission. */
function immutableLineage(connection: SqliteConnection | SqliteDriver, sessionId: string, through: number): ImmutableLine[] {
    const captured: ImmutableLine[] = [], seen = new Set<string>(); let id = sessionId, limit = through;
    for (;;) {
      if (seen.has(id)) return corrupt(); seen.add(id);
      const row = connection.prepare('SELECT id,workspace_identity_ref,parent_session_id,forked_through_item_seq,created_at,principal_id FROM sessions WHERE id=?')
        .get<{ id: string; workspace_identity_ref: string; parent_session_id: string | null; forked_through_item_seq: bigint | null; created_at: string; principal_id: string }>(id);
      if (!row) return corrupt();
      controlWireText(row.id); assertArtifactRef(row.workspace_identity_ref); controlWireText(row.principal_id);
      parseCanonicalTime(row.created_at);
      const fork = row.forked_through_item_seq === null ? undefined : Number(row.forked_through_item_seq);
      if ((row.parent_session_id === null) !== (fork === undefined) || fork !== undefined && (!Number.isSafeInteger(fork) || fork < 0)) return corrupt();
      if (row.parent_session_id !== null) controlWireText(row.parent_session_id);
      const child = captured.at(-1);
      if (child && (row.workspace_identity_ref !== child.workspaceIdentityRef || row.principal_id !== child.principalId || row.created_at > child.createdAt)) return corrupt();
      captured.push({ id: row.id, workspaceIdentityRef: row.workspace_identity_ref, createdAt: row.created_at, principalId: row.principal_id, limit,
        ...(row.parent_session_id === null ? {} : { parentSessionId: row.parent_session_id, forkedThroughItemSeq: fork! }) });
      if (row.parent_session_id === null) return captured;
      id = row.parent_session_id; limit = Math.min(limit, fork!);
    }
}
export function frozenSessionCompactionIndex(driver: SqliteDriver, sessionId: string, through: number): SessionCompactionIndex {
  const lines = driver.readSnapshot(connection => immutableLineage(connection, sessionId, through));
  return (itemId, sources) => driver.readSnapshot(connection => {
    for (const line of lines) {
      const row = connection.prepare('SELECT workspace_identity_ref,parent_session_id,forked_through_item_seq,created_at,principal_id FROM sessions WHERE id=?').get(line.id);
      if (!row) return corrupt();
      if (row.workspace_identity_ref !== line.workspaceIdentityRef || row.parent_session_id !== (line.parentSessionId ?? null) ||
          row.forked_through_item_seq !== (line.forkedThroughItemSeq === undefined ? null : BigInt(line.forkedThroughItemSeq)) || row.created_at !== line.createdAt || row.principal_id !== line.principalId) return corrupt();
    }
    for (const source of sources ?? []) {
      const line = lines.find(line => line.id === source.sourceSessionId);
      const row = connection.prepare('SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items WHERE item_id=?').get<ItemRow>(source.itemId);
      if (!line || source.itemSeq <= (line.forkedThroughItemSeq ?? 0) || source.itemSeq > line.limit || !row) return corrupt();
      const actual = item(row);
      if (actual.sessionId !== source.sourceSessionId || actual.itemSeq !== source.itemSeq || actual.kind !== source.kind || actual.payloadRef !== source.payloadRef) return corrupt();
    }
    return lookupJustification(connection, lines, itemId);
  });
}
export async function readSessionContextCut(driver: SqliteDriver, artifacts: Reader, principalId: string,
  sessionId: string, expectedContextRevision?: number) {
  const before = driver.readSnapshot(connection => {
    const row = connection.prepare('SELECT * FROM sessions WHERE id=? AND principal_id=?').get(sessionId, principalId);
    if (!row) throw new KernelStorageError('NOT_FOUND', 'Session is unavailable');
    return decodeWireSession(sessionFromRow(row));
  });
  if (expectedContextRevision !== undefined && before.contextRevision !== expectedContextRevision)
    throw new KernelStorageError('REVISION_CONFLICT', 'Session context revision changed');
  const projection = decodeSessionContext(await read(artifacts, before.contextProjectionRef));
  const cut = driver.readSnapshot(connection => {
    const row = connection.prepare('SELECT * FROM sessions WHERE id=? AND principal_id=?').get(sessionId, principalId);
    if (!row || canonicalSha256(sessionFromRow(row)) !== canonicalSha256(before))
      throw new KernelStorageError('REVISION_CONFLICT', 'Session changed during its immutable graph read');
    const lines = lineage(connection, before, principalId, before.latestItemSeq), logical: SessionItem[] = [];
    for (const source of [...lines].reverse()) {
      const from = source.forkedThroughItemSeq ?? 0;
      if (source.limit <= from) continue;
      const rows = connection.prepare('SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items WHERE session_id=? AND item_seq>? AND item_seq<=? ORDER BY item_seq')
        .all<ItemRow>(source.id, from, source.limit);
      for (const raw of rows) {
        const checked = item(raw);
        if (checked.itemSeq !== logical.length + 1 || checked.createdAt < source.createdAt || checked.createdAt > before.updatedAt) return corrupt();
        logical.push(checked);
      }
    }
    if (logical.length !== before.latestItemSeq) return corrupt('Session logical source index has a sequence gap');
    const justifications = projection.segments.filter(segment => segment.kind === 'summary')
      .map(segment => lookupJustification(connection, lines, segment.compactionItemId));
    return immutableSnapshot({ session: before, principalId, lineage: lines, items: logical, justifications }) as SessionContextCut;
  });
  if (projection.sessionId !== before.id || projection.contextRevision !== before.contextRevision || projection.throughItemSeq !== before.latestItemSeq) return corrupt();
  const entries = await readSessionContextEntries(artifacts, projection, id => cut.justifications.find(row => row.item.itemId === id) ?? corrupt(), cut);
  return { cut, projection, entries };
}
export function assertSessionContextCut(connection: SqliteConnection, cut: SessionContextCut): void {
  const row = connection.prepare('SELECT * FROM sessions WHERE id=? AND principal_id=?').get(cut.session.id, cut.principalId);
  if (!row || canonicalSha256(sessionFromRow(row)) !== canonicalSha256(cut.session))
    throw new KernelStorageError('REVISION_CONFLICT', 'Session changed before context commit');
  assertImmutableCut(connection, cut);
}
function assertImmutableCut(connection: SqliteConnection, cut: SessionContextCut): void {
  for (const source of cut.lineage) {
    const current = connection.prepare('SELECT workspace_identity_ref,parent_session_id,forked_through_item_seq,created_at FROM sessions WHERE id=? AND principal_id=?').get(source.id, cut.principalId);
    if (!current || current.workspace_identity_ref !== source.workspaceIdentityRef || current.parent_session_id !== (source.parentSessionId ?? null) ||
        current.forked_through_item_seq !== (source.forkedThroughItemSeq === undefined ? null : BigInt(source.forkedThroughItemSeq)) || current.created_at !== source.createdAt) return corrupt();
  }
  for (const expected of [...cut.items, ...cut.justifications.map(value => value.item)]) {
    const current = connection.prepare('SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items WHERE item_id=?').get<ItemRow>(expected.itemId);
    if (!current || canonicalSha256(item(current)) !== canonicalSha256(expected)) return corrupt();
  }
}

/** Historical response/admitted snapshot closure: original CAS graph and
 * immutable index only. Today's mutable Session head is neither sampled nor
 * used as a substitute for the original response snapshot. */
export async function readFrozenSessionContextCut(driver: SqliteDriver, artifacts: Reader, principalId: string, snapshot: Session,
  check?: (connection: SqliteConnection) => void) {
  const session = decodeWireSession(snapshot), projection = decodeSessionContext(await read(artifacts, session.contextProjectionRef));
  if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq) return corrupt();
  const cut = driver.readSnapshot(connection => {
    check?.(connection);
    const lines = lineage(connection, session, principalId, session.latestItemSeq), logical: SessionItem[] = [];
    for (const source of [...lines].reverse()) {
      const from = source.forkedThroughItemSeq ?? 0;
      if (source.limit <= from) continue;
      const rows = connection.prepare('SELECT item_id,session_id,item_seq,kind,payload_ref,created_at FROM items WHERE session_id=? AND item_seq>? AND item_seq<=? ORDER BY item_seq')
        .all<ItemRow>(source.id, from, source.limit);
      for (const raw of rows) {
        const checked = item(raw);
        if (checked.itemSeq !== logical.length + 1 || checked.createdAt < source.createdAt || checked.createdAt > session.updatedAt) return corrupt();
        logical.push(checked);
      }
    }
    if (logical.length !== session.latestItemSeq) return corrupt();
    const justifications = projection.segments.filter(segment => segment.kind === 'summary').map(segment => lookupJustification(connection, lines, segment.compactionItemId));
    if (justifications.some(value => value.item.createdAt > session.updatedAt)) return corrupt();
    return immutableSnapshot({ session, principalId, lineage: lines, items: logical, justifications }) as SessionContextCut;
  });
  const entries = await readSessionContextEntries(artifacts, projection, id => cut.justifications.find(value => value.item.itemId === id) ?? corrupt(), cut);
  driver.readSnapshot(connection => { check?.(connection); assertImmutableCut(connection, cut); });
  return { cut, projection, entries };
}

/** A later compaction changes context visibility, never the atomic terminal
 * item. Keep the original exact one-item raw proof, through its immutable
 * compaction justification when that range is now summarized. */
export async function assertSessionTerminalProjection(driver: SqliteDriver, artifacts: Reader, sessionId: string,
  expected: { itemSeq: number; itemId: string; payloadRef: string }): Promise<void> {
  const selected = driver.readSnapshot(connection => {
    const row = connection.prepare('SELECT * FROM sessions WHERE id=?').get(sessionId);
    if (!row) return corrupt(); return { session: decodeWireSession(sessionFromRow(row)), principalId: String(row.principal_id) };
  });
  const context = await readFrozenSessionContextCut(driver, artifacts, selected.principalId, selected.session);
  const actual = context.cut.items[expected.itemSeq - 1];
  if (!actual || actual.sessionId !== sessionId || actual.kind !== 'run_terminal' || actual.itemId !== expected.itemId || actual.payloadRef !== expected.payloadRef) return corrupt();
  const original = { kind: 'raw', fromItemSeq: expected.itemSeq, throughItemSeq: expected.itemSeq,
    items: [{ sourceSessionId: sessionId, itemSeq: expected.itemSeq, itemId: expected.itemId, kind: 'run_terminal', payloadRef: expected.payloadRef }] };
  let segment = context.projection.segments.find(value => value.fromItemSeq <= expected.itemSeq && value.throughItemSeq >= expected.itemSeq);
  if (segment?.kind === 'summary') {
    const compactionItemId = segment.compactionItemId;
    const justification = context.cut.justifications.find(value => value.item.itemId === compactionItemId);
    if (!justification) return corrupt();
    const payload = await read<SessionCompactionItem>(artifacts, justification.item.payloadRef);
    const previous = decodeSessionContext(await read(artifacts, payload.previousProjectionRef));
    segment = previous.segments.find(value => value.fromItemSeq <= expected.itemSeq && value.throughItemSeq >= expected.itemSeq);
  }
  if (!segment || canonicalSha256(segment) !== canonicalSha256(original)) return corrupt('terminal Session item lost its original exact one-item raw proof');
}

async function terminalEntry(artifacts: Reader, source: { sourceSessionId: string; itemSeq: number; itemId: string; payloadRef: string }, index: number): Promise<SessionContextEntry> {
  const data = controlWireRecord(await read(artifacts, source.payloadRef), ['schemaVersion', 'format', 'kind', 'itemKey', 'runId', 'operation', 'admittedSessionItemSeq', 'status', 'terminalReason'], ['resultRef', 'summaryRef', 'summaryDigest', 'terminalDetailRef']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-session-run-terminal-v1' || data.kind !== 'run_terminal' ||
      !['agent', 'delivery'].includes(data.operation as string) || !['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(data.status as string)) return corrupt();
  controlWireText(data.runId); controlWireText(data.terminalReason); controlWireInteger(data.admittedSessionItemSeq);
  if (data.itemKey !== `run-terminal:${data.runId}` || (data.admittedSessionItemSeq as number) >= source.itemSeq ||
      source.itemId !== identityHash('cliq-session-run-terminal-item-v1', source.sourceSessionId, data.runId as string) ||
      Object.hasOwn(data, 'summaryRef') !== Object.hasOwn(data, 'summaryDigest')) return corrupt();
  for (const key of ['resultRef', 'summaryRef', 'summaryDigest', 'terminalDetailRef']) if (Object.hasOwn(data, key)) assertArtifactRef(data[key] as string);
  decodeWirePublicState({ status: data.status, nextStep: null, terminalReason: data.terminalReason,
    ...(data.resultRef === undefined ? {} : { resultRef: data.resultRef }), ...(data.terminalDetailRef === undefined ? {} : { terminalDetailRef: data.terminalDetailRef }) });
  const visible = { kind: data.kind, runId: data.runId, operation: data.operation, status: data.status, terminalReason: data.terminalReason,
    ...(data.resultRef === undefined ? {} : { resultRef: data.resultRef }), ...(data.summaryRef === undefined ? {} : { summaryRef: data.summaryRef }) };
  return { index, sourceItemId: source.itemId, sourceKind: 'run_terminal', fromItemSeq: source.itemSeq, throughItemSeq: source.itemSeq,
    sourceRef: source.payloadRef, sourceDigest: canonicalSha256(data), contentUtf8: canonicalJsonBytes(visible).toString('utf8') };
}
/** Original immutable projection + committed immutable compaction index.
 * Legacy/control payloads are never read as model/handoff prose. */
export async function readSessionContextEntries(artifacts: Reader, projection: SessionContextProjection,
  compactionIndex?: SessionCompactionIndex, cut?: SessionContextCut): Promise<readonly SessionContextEntry[]> {
  const entries: SessionContextEntry[] = [];
  for (const segment of projection.segments) {
    const rows = cut?.items.slice(segment.fromItemSeq - 1, segment.throughItemSeq);
    if (segment.kind === 'raw') {
      for (const source of segment.items) {
        const actual = rows?.find(row => row.itemSeq === source.itemSeq);
        if (actual && (actual.sessionId !== source.sourceSessionId || actual.itemId !== source.itemId || actual.kind !== source.kind || actual.payloadRef !== source.payloadRef)) return corrupt();
        entries.push(await terminalEntry(artifacts, source, entries.length));
      }
    } else if (segment.kind === 'excluded_control') {
      if (rows && (rows.some(row => row.kind === 'run_terminal') || sessionSourceItemsDigest(rows) !== segment.sourceItemsDigest)) return corrupt();
    } else {
      if (!compactionIndex) return corrupt('Session summary requires its original committed immutable justification index');
      const justification = compactionIndex(segment.compactionItemId), metadata = justification.item;
      const data = controlWireRecord(await read(artifacts, metadata.payloadRef), ['schemaVersion', 'kind', 'fromItemSeq', 'throughItemSeq', 'sourceItemsDigest',
        'summaryRef', 'summaryDigest', 'retainedItemIds', 'previousProjectionRef', 'createdAt']) as unknown as SessionCompactionItem;
      if (data.schemaVersion !== 1 || data.kind !== 'compaction' || metadata.kind !== 'compaction' || metadata.itemId !== segment.compactionItemId ||
          metadata.createdAt !== data.createdAt || data.fromItemSeq !== segment.fromItemSeq || data.throughItemSeq !== segment.throughItemSeq ||
          data.sourceItemsDigest !== segment.sourceItemsDigest || data.summaryRef !== segment.summaryRef || data.summaryDigest !== segment.summaryDigest ||
          data.throughItemSeq > justification.sourceThroughItemSeq ||
          canonicalSha256(data.retainedItemIds) !== canonicalSha256(segment.retainedItemIds)) return corrupt();
      const previous = decodeSessionContext(await read(artifacts, data.previousProjectionRef));
      if (previous.sessionId !== metadata.sessionId || previous.throughItemSeq !== metadata.itemSeq - 1) return corrupt();
      const selected = previous.segments.filter(value => value.throughItemSeq >= segment.fromItemSeq && value.fromItemSeq <= segment.throughItemSeq);
      if (!selected.length || selected[0]!.fromItemSeq !== segment.fromItemSeq || selected.at(-1)!.throughItemSeq !== segment.throughItemSeq ||
          selected.some(value => value.kind !== 'raw')) return corrupt();
      const sources = selected.flatMap(value => value.kind === 'raw' ? value.items : []);
      if (sessionSourceItemsDigest(sources) !== segment.sourceItemsDigest || rows && sessionSourceItemsDigest(rows) !== segment.sourceItemsDigest) return corrupt();
      compactionIndex(segment.compactionItemId, sources);
      if (rows && sources.some((source, index) => { const actual = rows[index]; return !actual || actual.sessionId !== source.sourceSessionId || actual.itemId !== source.itemId || actual.itemSeq !== source.itemSeq || actual.kind !== source.kind || actual.payloadRef !== source.payloadRef; })) return corrupt();
      const retained = sources.filter(source => segment.retainedItemIds.includes(source.itemId));
      if (retained.length !== segment.retainedItemIds.length || canonicalSha256(retained.map(value => value.itemId)) !== canonicalSha256(segment.retainedItemIds)) return corrupt();
      const text = await read<ModelTextV1>(artifacts, segment.summaryRef); verifyModelText(text);
      if (text.textDigest !== segment.summaryDigest || text.byteCount < 1 || text.byteCount > 262_144) return corrupt();
      entries.push({ index: entries.length, sourceKind: 'summary', fromItemSeq: segment.fromItemSeq, throughItemSeq: segment.throughItemSeq,
        sourceRef: metadata.payloadRef, sourceDigest: segment.summaryDigest, sourceItemId: segment.compactionItemId, contentUtf8: text.utf8 });
      for (const source of retained) entries.push(await terminalEntry(artifacts, source, entries.length));
    }
  }
  return immutableSnapshot(entries);
}

export function wholeSessionPrefix(projection: SessionContextProjection, through: number): SessionContextSegment[] {
  if (through !== 0 && !projection.segments.some(segment => segment.throughItemSeq === through))
    throw new KernelStorageError('INVALID_REQUEST', 'Session cursor must end a whole current context segment');
  return projection.segments.filter(segment => segment.throughItemSeq <= through);
}
