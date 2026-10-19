import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeReadControlRequest, encodeControlCheckpointCursor as encodeCheckpoint, decodeControlCheckpointCursor,
  CONTROL_FRAME_BYTES, type ReadControlRequest } from '../kernel/control-wire.js';
import { decodeWireSession, decodeWireRun, decodeWireCheckpoint, decodeWireEvent,
  decodeWireRunItemReference, decodeWireSessionItem, decodeWireArtifactDescriptor } from '../kernel/control-wire-data.js';
export type { ReadControlRequest } from '../kernel/control-wire.js';
import { assertArtifactRef, normalizeBoundedText, requiredSafeInteger } from '../kernel/identity.js';
import { MAX_JSON_CONTAINER_ENTRIES, MAX_JSON_DEPTH, measureBoundedJsonValue, parseJsonStrict } from '../kernel/json.js';
import type { ArtifactDescriptorV1, Checkpoint, ControlResultV1, ResultUnavailableControlErrorV1, Run, RunEvent, RunItemReferenceV1, RunSnapshotV1, Session, SessionItem } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { assertCurrentControlFrame, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeRunSpec } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { isRecord } from './invariants.js';
import { journalEntryFromRow, type JournalSqlRow } from './repositories/journal.js';
import { checkpointFromRow, runFromRow, sessionFromRow } from './rows.js';
import type { SqliteConnection, SqliteDriver, SqliteRow } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readCanonicalArtifact } from './agent-context.js';
import { decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';

export type ReadControlResult = Extract<ControlResultV1, { method: 'session.get' | 'run.get' | 'run.attach' | 'run.result' | 'run.diff' | 'artifact.get' }>;
type SessionResult = Extract<ReadControlResult, { method: 'session.get' }>;
type RunResult = Extract<ReadControlResult, { method: 'run.get' | 'run.attach' }>;
type CapturedRead = { result: SessionResult } | {
  result: Omit<Extract<RunResult, { method: 'run.get' }>, 'snapshot'> | Omit<Extract<RunResult, { method: 'run.attach' }>, 'snapshot'>;
  run: Run; latestRunItemSeq: number; expired?: { earliest: number; latest: number };
};
type ItemRow = { item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string; session_id: string };
type CheckpointPosition = { createdAt: string; checkpointId: string };
const METADATA_BYTES = 1024 * 1024;
const ARTIFACT_PAGE_BYTES = 64 * 1024;
const CHECKPOINT_TEXT_BOUNDS = { id: 128, run_id: 128, context_manifest_ref: 64,
  workspace_state_ref: 64, created_at: 24, reason: 10 };
const CHECKPOINT_COLUMNS = ['schema_version', 'based_on_run_revision', 'run_item_seq', 'journal_seq',
  ...Object.entries(CHECKPOINT_TEXT_BOUNDS).map(([column, bound]) =>
    `CASE WHEN length(CAST(${column} AS BLOB)) <= ${bound} THEN ${column} ELSE NULL END AS ${column}`)].join(', ');

export class EventCursorExpiredError extends KernelStorageError {
  constructor(readonly earliestEventSeq: number, readonly latestEventSeq: number, readonly snapshot: RunSnapshotV1) {
    super('EVENT_CURSOR_EXPIRED', 'Run event cursor precedes the retained display stream');
  }
}

/** The exact unavailable cut, not a generic failed transition or a candidate
 * selected as a substitute result. Query errors never create replay rows. */
export class ResultUnavailableError extends KernelStorageError {
  readonly controlError: ResultUnavailableControlErrorV1;
  constructor(run: Run) {
    super('STATE_TRANSITION_INVALID', 'this Run has no committed immutable result');
    const base = { schemaVersion: 1 as const, code: 'RESULT_UNAVAILABLE' as const, messageCode: 'run.result_unavailable', runId: run.id };
    if (run.status === 'queued' || run.status === 'running' || run.status === 'waiting')
      this.controlError = { ...base, retryable: true, status: run.status, currentRevision: run.revision };
    else if ((run.status === 'failed' || run.status === 'cancelled') && run.terminalDetailRef)
      this.controlError = { ...base, retryable: false, status: run.status, terminalDetailRef: run.terminalDetailRef };
    else throw new TypeError('unavailable result has an invalid Run cut');
  }
}

function invalid(message: string): never { throw new KernelStorageError('INVALID_REQUEST', message); }
function corrupt(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function checkedData<T>(decode: () => T): T {
  try { return decode(); }
  catch (error) { if (error instanceof TypeError) corrupt(error.message); throw error; }
}
function id(value: unknown): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, 128) !== value) throw new TypeError('id must be bounded NFC UTF-8');
  return value;
}
function artifactRef(value: unknown): void {
  if (typeof value !== 'string') throw new TypeError('ArtifactRef must be a string');
  assertArtifactRef(value);
}
function integer(value: unknown, minimum = 0): number {
  const result = requiredSafeInteger(value, 'sequence');
  if (result < minimum) throw new TypeError('sequence is below its minimum');
  return result;
}

function validateRequest(request: ReadControlRequest): ReadControlRequest {
  try { return decodeReadControlRequest(request); }
  catch (error) {
    if (error instanceof TypeError) invalid('read request is not canonical or within its bounds');
    throw error;
  }
}
function requireOwnedRow(connection: SqliteConnection, table: 'sessions' | 'runs', entityId: string, principalId: string): SqliteRow {
  const row = connection.prepare(`SELECT * FROM ${table} WHERE id = ? AND principal_id = ?`).get(entityId, principalId);
  if (!row) throw new KernelStorageError('NOT_FOUND', 'requested entity does not exist for this principal');
  return row;
}
function checkedSession(row: SqliteRow): Session {
  if (row.name !== null) {
    if (typeof row.name !== 'string' || normalizeBoundedText(row.name, 1, 256) !== row.name) corrupt('Session name is not canonical');
  }
  if (row.parent_session_id !== null) id(row.parent_session_id);
  return checkedData(() => decodeWireSession(sessionFromRow(row)));
}
function metadataItem(row: ItemRow, expectedSequence: number): RunItemReferenceV1 {
  if (integer(row.item_seq, 1) !== expectedSequence) corrupt('retained item stream has a sequence gap');
  return checkedData(() => decodeWireRunItemReference({ schemaVersion: 1, itemId: row.item_id, itemSeq: expectedSequence, payloadRef: row.payload_ref,
    payloadDigest: row.payload_ref, createdAt: row.created_at }));
}
/** The strict parser sees the complete application envelope, including snapshot
 * and changing cursors. Only row bytes/member counts are accumulated; fixed
 * metadata is measured at each proposed cursor without serializing old rows. */
function pageBudget() {
  let bytes = 0, entries = 0;
  return <T>(stream: T[], candidate: T, emptyResult: unknown): boolean => {
    const envelope = { protocolVersion: 1, ok: true, result: emptyResult };
    const fixedBytes = canonicalJsonBytes(envelope).byteLength;
    const fixed = measureBoundedJsonValue(envelope);
    const candidateBytes = canonicalJsonBytes(candidate).byteLength;
    const candidateShape = measureBoundedJsonValue(candidate);
    // Every returned stream array is at container depth three: envelope,
    // result, array. Each row also contributes its parent array element.
    const candidateEntries = candidateShape.containerEntries + 1;
    if (fixedBytes + candidateBytes > CONTROL_FRAME_BYTES ||
        fixed.containerEntries + candidateEntries > MAX_JSON_CONTAINER_ENTRIES ||
        candidateShape.maxContainerDepth + 3 > MAX_JSON_DEPTH)
      corrupt('retained metadata row exceeds a complete bounded control frame');
    const nextBytes = bytes + candidateBytes + (stream.length === 0 ? 0 : 1);
    const nextEntries = entries + candidateEntries;
    if (fixedBytes + nextBytes > CONTROL_FRAME_BYTES || fixed.containerEntries + nextEntries > MAX_JSON_CONTAINER_ENTRIES) return false;
    stream.push(candidate); bytes = nextBytes; entries = nextEntries; return true;
  };
}
function sessionCut(connection: SqliteConnection, request: Extract<ReadControlRequest, { method: 'session.get' }>, principalId: string): SessionResult {
  const session = checkedSession(requireOwnedRow(connection, 'sessions', request.sessionId, principalId));
  const after = request.afterItemSeq!;
  if (after > session.latestItemSeq) invalid('Session item cursor exceeds the captured high-water');
  const ranges: Array<{ sessionId: string; from: number; through: number }> = [];
  const seen = new Set<string>();
  let source = session; let through = session.latestItemSeq;
  // Physical rows are not copied on fork. Each ancestor is clipped by every intervening fork cursor.
  for (;;) {
    if (seen.has(source.id)) corrupt('Session lineage contains a cycle');
    seen.add(source.id);
    const fork = source.forkedThroughItemSeq ?? 0;
    if (through > source.latestItemSeq) corrupt('Session lineage exceeds the ancestor stream');
    if (through > Math.max(fork, after)) ranges.unshift({ sessionId: source.id, from: Math.max(fork, after), through });
    if (source.parentSessionId === undefined) break;
    through = Math.min(through, fork);
    const parentRow = connection.prepare('SELECT * FROM sessions WHERE id = ? AND principal_id = ?').get(source.parentSessionId, principalId);
    if (!parentRow) corrupt('Session lineage has no same-principal ancestor');
    const parent = checkedSession(parentRow);
    if (fork > parent.latestItemSeq) corrupt('Session fork cursor exceeds its parent stream');
    if (parent.workspaceIdentityRef !== session.workspaceIdentityRef) corrupt('Session lineage changes workspace identity');
    source = parent;
  }
  const statement = connection.prepare(`SELECT item_id, item_seq, kind, payload_ref, created_at, session_id FROM items
    WHERE session_id = ? AND item_seq > ? AND item_seq <= ? ORDER BY item_seq LIMIT 1`);
  const items: SessionItem[] = []; const append = pageBudget();
  let next = after;
  page: for (const range of ranges) {
    while (next < range.through && items.length < request.limit!) {
      const row = statement.get<ItemRow>(range.sessionId, BigInt(Math.max(next, range.from)), BigInt(range.through));
      if (!row) corrupt('Session logical item stream has a sequence gap');
      const metadata = metadataItem(row, next + 1);
      if (row.session_id !== range.sessionId) corrupt('Session item ownership or kind is invalid');
      const item = checkedData(() => decodeWireSessionItem({ schemaVersion: 1, itemId: metadata.itemId, sessionId: range.sessionId,
        itemSeq: metadata.itemSeq, kind: row.kind, payloadRef: metadata.payloadRef, createdAt: metadata.createdAt }));
      if (!append(items, item, { method: 'session.get', snapshot: { schemaVersion: 1, session }, items: [],
        highWaterItemSeq: session.latestItemSeq, nextItemSeq: item.itemSeq })) break page;
      next = item.itemSeq;
    }
    if (items.length === request.limit) break;
  }
  return { method: 'session.get', snapshot: { schemaVersion: 1, session }, items, highWaterItemSeq: session.latestItemSeq, nextItemSeq: next };
}

function decodeCheckpointCursor(cursor: string, runId: string): CheckpointPosition {
  try { return decodeControlCheckpointCursor(cursor, runId); }
  catch { invalid('Checkpoint cursor is invalid for this Run'); }
}
function checkedCheckpoint(row: SqliteRow): Checkpoint {
  if (Object.keys(CHECKPOINT_TEXT_BOUNDS).some(column => typeof row[column] !== 'string')) corrupt('Checkpoint metadata exceeds its bounds or is unavailable');
  const checkpoint = checkpointFromRow(row);
  if (row.schema_version !== 1n && row.schema_version !== 1) corrupt('Checkpoint schema version is invalid');
  return checkedData(() => decodeWireCheckpoint(checkpoint));
}
function highSequence(connection: SqliteConnection, table: 'items' | 'run_journal', column: 'item_seq' | 'seq', runId: string): number {
  const row = connection.prepare(`SELECT COALESCE(max(${column}), 0) AS high FROM ${table} WHERE run_id = ?`).get<{ high: unknown }>(runId);
  return integer(row?.high);
}

function checkedRun(row: SqliteRow): Run {
  for (const field of ['parent_run_id', 'active_worker_launch_id']) if (row[field] !== null) id(row[field]);
  for (const field of ['frontier_ref', 'waiting_on_ref', 'result_ref', 'terminal_detail_ref', 'stop_intent_ref']) {
    if (row[field] !== null) artifactRef(row[field]);
  }
  return checkedData(() => decodeWireRun(runFromRow(row)));
}
function runGetCut(connection: SqliteConnection, request: Extract<ReadControlRequest, { method: 'run.get' }>, run: Run, itemHigh: number,
  operation: RunSnapshotV1['operation']): CapturedRead {
  const journalHigh = highSequence(connection, 'run_journal', 'seq', run.id);
  const highRow = connection.prepare(`SELECT ${CHECKPOINT_COLUMNS} FROM checkpoints WHERE run_id = ? ORDER BY checkpoints.created_at DESC, checkpoints.id DESC LIMIT 1`).get(run.id);
  if (!highRow) corrupt('admitted Run has no retained Checkpoint');
  const high = checkedCheckpoint(highRow);
  const cursor = request.checkpointCursor === undefined ? undefined : decodeCheckpointCursor(request.checkpointCursor, run.id);
  if (request.afterItemSeq! > itemHigh || request.afterJournalSeq! > journalHigh) invalid('Run sequence cursor exceeds the captured high-water');
  if (cursor && !connection.prepare('SELECT id FROM checkpoints WHERE run_id = ? AND created_at = ? AND id = ?')
    .get(run.id, cursor.createdAt, cursor.checkpointId)) invalid('Checkpoint cursor names no retained row');
  const items: RunItemReferenceV1[] = []; const journal: ReturnType<typeof journalEntryFromRow>[] = []; const checkpoints: Checkpoint[] = [];
  const append = pageBudget();
  let nextItem = request.afterItemSeq!; let nextJournal = request.afterJournalSeq!; let nextCheckpoint = cursor;
  const highWaterCheckpointCursor = encodeCheckpoint(run.id, { createdAt: high.createdAt, checkpointId: high.id });
  const emptyResult = (itemSeq: number, journalSeq: number, checkpoint = nextCheckpoint) => ({ method: 'run.get',
    snapshot: { schemaVersion: 1, operation, run, latestRunItemSeq: itemHigh }, items: [], journal: [], checkpoints: [],
    highWaterItemSeq: itemHigh, highWaterJournalSeq: journalHigh, highWaterCheckpointCursor,
    nextItemSeq: itemSeq, nextJournalSeq: journalSeq,
    ...(checkpoint === undefined ? {} : { nextCheckpointCursor: encodeCheckpoint(run.id, checkpoint) }) });
  const itemStatement = connection.prepare(`SELECT item_id, item_seq, payload_ref, created_at FROM items
    WHERE run_id = ? AND item_seq > ? AND item_seq <= ? ORDER BY item_seq LIMIT 1`);
  const journalStatement = connection.prepare(`SELECT run_id, seq, op_id, op_kind, attempt, phase,
    CASE WHEN length(CAST(entry_json AS BLOB)) <= ${METADATA_BYTES} THEN entry_json ELSE NULL END AS entry_json FROM run_journal
    WHERE run_id = ? AND seq > ? AND seq <= ? ORDER BY seq LIMIT 1`);
  const checkpointStatement = connection.prepare(`SELECT ${CHECKPOINT_COLUMNS} FROM checkpoints WHERE run_id = ?
    AND (created_at > ? OR (created_at = ? AND id > ?))
    AND (created_at < ? OR (created_at = ? AND id <= ?)) ORDER BY checkpoints.created_at, checkpoints.id LIMIT ?`);
  page: {
    while (nextItem < itemHigh && items.length < request.itemLimit!) {
      const row = itemStatement.get<ItemRow>(run.id, BigInt(nextItem), BigInt(itemHigh));
      if (!row) corrupt('Run item stream has a sequence gap');
      const item = metadataItem(row, nextItem + 1);
      if (!append(items, item, emptyResult(item.itemSeq, nextJournal))) break page;
      nextItem = item.itemSeq;
    }
    while (nextJournal < journalHigh && journal.length < request.journalLimit!) {
      const row = journalStatement.get<Omit<JournalSqlRow, 'entry_json'> & { entry_json: string | null }>(run.id, BigInt(nextJournal), BigInt(journalHigh));
      if (!row) corrupt('Run Journal stream has a sequence gap');
      if (row.entry_json === null) corrupt('retained Run Journal row exceeds its metadata bound');
      const entry = journalEntryFromRow({ ...row, entry_json: row.entry_json });
      if (entry.seq !== nextJournal + 1) corrupt('Run Journal stream has a sequence gap');
      if (!append(journal, entry, emptyResult(nextItem, entry.seq))) break page;
      nextJournal = entry.seq;
    }
    // Checkpoints contain fixed-size metadata, not Journal payloads. Fetch one
    // bounded batch so an unindexed time-order cut is sorted once, not per row.
    const start = nextCheckpoint ?? { createdAt: '', checkpointId: '' };
    const rows = checkpointStatement.all(run.id, start.createdAt, start.createdAt, start.checkpointId,
      high.createdAt, high.createdAt, high.id, BigInt(request.checkpointLimit!));
    for (const row of rows) {
      const checkpoint = checkedCheckpoint(row);
      if (!append(checkpoints, checkpoint, emptyResult(nextItem, nextJournal, { createdAt: checkpoint.createdAt, checkpointId: checkpoint.id }))) break page;
      nextCheckpoint = { createdAt: checkpoint.createdAt, checkpointId: checkpoint.id };
    }
  }
  return { run, latestRunItemSeq: itemHigh, result: { method: 'run.get', items, journal, checkpoints,
    highWaterItemSeq: itemHigh, highWaterJournalSeq: journalHigh, highWaterCheckpointCursor,
    nextItemSeq: nextItem, nextJournalSeq: nextJournal,
    ...(nextCheckpoint === undefined ? {} : { nextCheckpointCursor: encodeCheckpoint(run.id, nextCheckpoint) }) } };
}

function checkedEvent(row: { event_seq: unknown; payload_json: string | null; occurred_at: string }, run: Run, itemHigh: number): RunEvent {
  if (row.payload_json === null) corrupt('retained Run event row exceeds its metadata bound');
  const value = parseJsonStrict(row.payload_json);
  if (!isRecord(value) || value.schemaVersion !== 1 || value.runId !== run.id || value.eventSeq !== integer(row.event_seq, 1) ||
      value.occurredAt !== row.occurred_at) corrupt('Run event columns do not match their exact payload');
  return checkedData(() => decodeWireEvent(value, { run, latestRunItemSeq: itemHigh }));
}
function runAttachCut(connection: SqliteConnection, request: Extract<ReadControlRequest, { method: 'run.attach' }>, run: Run, itemHigh: number,
  operation: RunSnapshotV1['operation']): CapturedRead {
  const bounds = connection.prepare('SELECT min(event_seq) AS earliest, max(event_seq) AS latest FROM run_events WHERE run_id = ?')
    .get<{ earliest: unknown; latest: unknown }>(run.id);
  const earliest = integer(bounds?.earliest, 1); const latest = integer(bounds?.latest, 1);
  if (request.afterEventSeq > latest) invalid('Run event cursor exceeds the captured high-water');
  const expired = request.afterEventSeq < Math.max(0, earliest - 1);
  const events: RunEvent[] = []; const append = pageBudget();
  if (!expired) {
    const statement = connection.prepare(`SELECT event_seq,
      CASE WHEN length(CAST(payload_json AS BLOB)) <= ${METADATA_BYTES} THEN payload_json ELSE NULL END AS payload_json, occurred_at FROM run_events
      WHERE run_id = ? AND event_seq > ? AND event_seq <= ? ORDER BY event_seq LIMIT 1`);
    let next = request.afterEventSeq;
    while (next < latest && events.length < request.limit!) {
      const row = statement.get<{ event_seq: unknown; payload_json: string | null; occurred_at: string }>(run.id, BigInt(next), BigInt(latest));
      if (!row) corrupt('retained Run event bounds contain no next row');
      const event = checkedEvent(row, run, itemHigh);
      if (event.eventSeq !== next + 1) corrupt('retained Run event stream has a sequence gap');
      if (!append(events, event, { method: 'run.attach', snapshot: { schemaVersion: 1, operation, run, latestRunItemSeq: itemHigh },
        earliestRetainedEventSeq: earliest, latestRetainedEventSeq: latest, highWaterEventSeq: latest, events: [], nextEventSeq: event.eventSeq })) break;
      next = event.eventSeq;
    }
  }
  return { run, latestRunItemSeq: itemHigh, ...(expired ? { expired: { earliest, latest } } : {}),
    result: { method: 'run.attach', earliestRetainedEventSeq: earliest, latestRetainedEventSeq: latest, highWaterEventSeq: latest,
      events, nextEventSeq: events.at(-1)?.eventSeq ?? request.afterEventSeq } };
}

/** Inspect only the immutable refs already selected by the successful terminal
 * transaction. No failed candidate fallback, raw CAS access or live authority
 * is returned. A delivery consumer must independently validate its full
 * result/receipt/death graph, never treat a query descriptor as permission. */
async function readResultQuery(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  request: Extract<ReadControlRequest, { method: 'run.result' | 'run.diff' }>, identity: AuthenticatedControlIdentity,
  signal?: AbortSignal): Promise<ReadControlResult> {
  const run = driver.readSnapshot(connection => {
    assertActiveStateOwner(connection, owner);
    return checkedRun(requireOwnedRow(connection, 'runs', request.runId, identity.principalId));
  });
  if (run.status !== 'succeeded' && run.status !== 'completed_unverified') throw new ResultUnavailableError(run);
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  signal?.throwIfAborted();
  const result = decodeRunResult(await readCanonicalArtifact(artifacts, run.resultRef!));
  signal?.throwIfAborted();
  const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, result.verificationClosureRef));
  signal?.throwIfAborted();
  if (result.runId !== run.id || closure.runId !== run.id || result.resultSourceRef !== closure.resultSourceRef ||
      result.createdAt > run.updatedAt || closure.createdAt > result.createdAt ||
      (spec.operation === 'agent' && (result.deliveryTerminalProjectionEvidenceRef !== undefined || result.verificationProvenanceRef !== undefined)) ||
      (spec.operation === 'delivery' && (run.status !== 'succeeded' || result.deliveryTerminalProjectionEvidenceRef === undefined)))
    corrupt('result inspection lost its exact successful terminal selection');
  const verification = closure.verification;
  const selected = verification.kind === 'local'
    ? verification.outcome === (run.status === 'succeeded' ? 'verified' : 'unverified') && result.verificationProvenanceRef === undefined
    : spec.operation === 'delivery' && run.status === 'succeeded' && result.verificationProvenanceRef === verification.inheritedProvenanceRef;
  if (!selected)
    corrupt('result inspection lost its exact successful terminal selection');
  const ref = request.method === 'run.result' ? run.resultRef! : result.diffRef;
  const descriptor = driver.readSnapshot(connection => {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(checkedRun(requireOwnedRow(connection, 'runs', request.runId, identity.principalId))) !== canonicalSha256(run))
      corrupt('immutable result selection changed while being inspected');
    const metadata = connection.prepare('SELECT byte_length, media_type FROM artifacts WHERE ref = ?')
      .get<{ byte_length: bigint; media_type: string }>(ref);
    if (!metadata) corrupt('selected result descriptor has no retained catalog entry');
    const sizeBytes = Number(metadata.byte_length);
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0 || typeof metadata.media_type !== 'string' ||
        normalizeBoundedText(metadata.media_type, 1, 128) !== metadata.media_type) corrupt('selected result descriptor is invalid');
    return { schemaVersion: 1 as const, ref, digest: ref, sizeBytes, mediaType: metadata.media_type } satisfies ArtifactDescriptorV1;
  });
  await validateControlChannelClosure(artifacts, owner, identity);
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  return request.method === 'run.result'
    ? { method: request.method, runId: run.id, result: descriptor, verificationClosureRef: result.verificationClosureRef }
    : { method: request.method, runId: run.id, diff: descriptor };
}

/** This StateRoot has one genuine principal, derived from its exact root,
 * platform and owner uid. Registration is read membership, not a typed-use or
 * execution grant. Orphan CAS bytes are never exposed by this method. */
async function readArtifactQuery(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  request: Extract<ReadControlRequest, { method: 'artifact.get' }>, identity: AuthenticatedControlIdentity,
  frameIdentity: AuthenticatedControlIdentity, signal?: AbortSignal): Promise<Extract<ReadControlResult, { method: 'artifact.get' }>> {
  const descriptor = () => driver.readSnapshot(connection => {
    assertActiveStateOwner(connection, owner);
    const metadata = connection.prepare(`SELECT byte_length,
      CASE WHEN length(CAST(media_type AS BLOB)) <= 128 THEN media_type ELSE NULL END AS media_type
      FROM artifacts WHERE ref = ?`).get<{ byte_length: unknown; media_type: unknown }>(request.digest);
    if (!metadata) throw new KernelStorageError('NOT_FOUND', 'artifact is not registered in this StateRoot');
    const sizeBytes = Number(metadata.byte_length);
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0 || typeof metadata.media_type !== 'string') corrupt('artifact descriptor is invalid');
    return checkedData(() => decodeWireArtifactDescriptor({ schemaVersion: 1, ref: request.digest, digest: request.digest, sizeBytes, mediaType: metadata.media_type }));
  });
  const artifact = descriptor();
  if (request.offset > artifact.sizeBytes) invalid('artifact offset exceeds its complete byte count');
  const length = Math.min(request.length, ARTIFACT_PAGE_BYTES, artifact.sizeBytes - request.offset);
  const bytes = Buffer.alloc(length);
  let observed = 0, copied = 0;
  try {
    // Selected bytes remain private staging until the *whole* original stream
    // has verified its digest/identity and closed both held descriptors. This
    // intentionally has no cached integrity or authorization shortcut.
    for await (const chunk of artifacts.readChunks(request.digest, artifact.sizeBytes)) {
      signal?.throwIfAborted();
      if (chunk.byteLength > artifact.sizeBytes - observed) corrupt('artifact stream exceeds its registered byte count');
      const from = Math.max(0, request.offset - observed);
      const through = Math.min(chunk.byteLength, request.offset + length - observed);
      if (through > from) {
        chunk.copy(bytes, copied, from, through);
        copied += through - from;
      }
      observed += chunk.byteLength;
    }
  } catch (cause) {
    if (cause instanceof ResourceRetirementError || (signal?.aborted && cause === signal.reason)) throw cause;
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'registered artifact failed complete integrity validation', { cause });
  }
  signal?.throwIfAborted();
  if (observed !== artifact.sizeBytes || copied !== length) corrupt('artifact stream did not reproduce its registered byte count');
  const current = await validateControlChannelClosure(artifacts, owner, identity);
  signal?.throwIfAborted();
  if (current.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, frameIdentity);
  if (canonicalSha256(descriptor()) !== canonicalSha256(artifact)) corrupt('artifact registration changed during the read');
  const nextOffset = request.offset + bytes.byteLength;
  return { method: 'artifact.get', artifact, offset: request.offset, bytesBase64: bytes.toString('base64'),
    nextOffset, eof: nextOffset === artifact.sizeBytes };
}

export async function readControl(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  request: ReadControlRequest, identity: AuthenticatedControlIdentity, signal?: AbortSignal): Promise<ReadControlResult> {
  signal?.throwIfAborted();
  const normalized = validateRequest(request);
  const authenticated = { principalId: identity.principalId, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest };
  await validateControlChannelClosure(artifacts, owner, authenticated);
  signal?.throwIfAborted();
  if (normalized.method === 'artifact.get') return readArtifactQuery(driver, artifacts, owner, normalized, authenticated, identity, signal);
  if (normalized.method === 'run.result' || normalized.method === 'run.diff')
    return readResultQuery(driver, artifacts, owner, normalized, authenticated, signal);
  // RunSpec is immutable data. Select and validate its exact bytes first so the
  // final snapshot transaction can budget the actual operation spelling. Only
  // that final transaction supplies Run truth, stream rows and high-waters.
  let selectedSpec: { ref: string; operation: RunSnapshotV1['operation'] } | undefined;
  if (normalized.method !== 'session.get') {
    const specRef = driver.readSnapshot(connection => {
      assertActiveStateOwner(connection, owner);
      try { return checkedRun(requireOwnedRow(connection, 'runs', normalized.runId, authenticated.principalId)).specRef; }
      catch (error) {
        if (error instanceof TypeError || error instanceof SyntaxError) corrupt('retained control metadata is invalid');
        throw error;
      }
    });
    const value = await artifacts.readCanonical(specRef);
    if (canonicalSha256(value) !== specRef) throw new KernelStorageError('ARTIFACT_MISMATCH', 'RunSpec is not canonical JSON');
    selectedSpec = { ref: specRef, operation: decodeRunSpec(value).operation };
    signal?.throwIfAborted();
  }
  const cut = driver.readSnapshot(connection => {
    assertActiveStateOwner(connection, owner);
    try {
      if (normalized.method === 'session.get') return { result: sessionCut(connection, normalized, authenticated.principalId) };
      const run = checkedRun(requireOwnedRow(connection, 'runs', normalized.runId, authenticated.principalId));
      if (!selectedSpec || run.specRef !== selectedSpec.ref) corrupt('RunSpec selection changed before its control read snapshot');
      const itemHigh = highSequence(connection, 'items', 'item_seq', run.id);
      return normalized.method === 'run.get' ? runGetCut(connection, normalized, run, itemHigh, selectedSpec.operation)
        : runAttachCut(connection, normalized, run, itemHigh, selectedSpec.operation);
    } catch (error) {
      if (error instanceof TypeError || error instanceof SyntaxError) corrupt('retained control metadata is invalid');
      throw error;
    }
  });
  let result: ReadControlResult;
  let expired: EventCursorExpiredError | undefined;
  if ('run' in cut) {
    const snapshot: RunSnapshotV1 = { schemaVersion: 1, operation: selectedSpec!.operation, run: cut.run, latestRunItemSeq: cut.latestRunItemSeq };
    result = { ...cut.result, snapshot };
    if (cut.expired) expired = new EventCursorExpiredError(cut.expired.earliest, cut.expired.latest, snapshot);
  } else result = cut.result;
  await validateControlChannelClosure(artifacts, owner, authenticated);
  signal?.throwIfAborted();
  assertActiveStateOwner(driver, owner);
  if (expired) throw expired;
  return result;
}
