import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, normalizeBoundedText, parseCanonicalTime, requiredSafeInteger } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { Checkpoint, ControlResultV1, Run, RunEvent, RunItemReferenceV1, RunSnapshotV1, Session, SessionItem } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeRunSpec } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { decodeBudgetUsage, isRecord } from './invariants.js';
import { journalEntryFromRow, type JournalSqlRow } from './repositories/journal.js';
import { checkpointFromRow, runFromRow, sessionFromRow } from './rows.js';
import type { SqliteConnection, SqliteDriver, SqliteRow } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

export type ReadControlRequest =
  | { protocolVersion: 1; method: 'session.get'; sessionId: string; afterItemSeq?: number; limit?: number }
  | { protocolVersion: 1; method: 'run.get'; runId: string; afterItemSeq?: number; afterJournalSeq?: number;
      checkpointCursor?: string; itemLimit?: number; journalLimit?: number; checkpointLimit?: number }
  | { protocolVersion: 1; method: 'run.attach'; runId: string; afterEventSeq: number; limit?: number };
export type ReadControlResult = Extract<ControlResultV1, { method: 'session.get' | 'run.get' | 'run.attach' }>;
type SessionResult = Extract<ReadControlResult, { method: 'session.get' }>;
type RunResult = Extract<ReadControlResult, { method: 'run.get' | 'run.attach' }>;
type CapturedRead = { result: SessionResult } | {
  result: Omit<Extract<RunResult, { method: 'run.get' }>, 'snapshot'> | Omit<Extract<RunResult, { method: 'run.attach' }>, 'snapshot'>;
  run: Run; latestRunItemSeq: number; expired?: { earliest: number; latest: number };
};
type ItemRow = { item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string; session_id: string };
type CheckpointPosition = { createdAt: string; checkpointId: string };
const METADATA_BYTES = 1024 * 1024;
const CHECKPOINT_TEXT_BOUNDS = { id: 128, run_id: 128, context_manifest_ref: 64,
  workspace_state_ref: 64, created_at: 24, reason: 10 };
const CHECKPOINT_COLUMNS = ['schema_version', 'based_on_run_revision', 'run_item_seq', 'journal_seq',
  ...Object.entries(CHECKPOINT_TEXT_BOUNDS).map(([column, bound]) =>
    `CASE WHEN length(CAST(${column} AS BLOB)) <= ${bound} THEN ${column} ELSE NULL END AS ${column}`)].join(', ');
const SESSION_KINDS = ['compaction', 'run_terminal', 'legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark'];
const RUN_STATUSES = ['queued', 'running', 'waiting', 'succeeded', 'completed_unverified', 'failed', 'cancelled'];
const NEXT_STEPS = ['agent', 'tool', 'verify', 'finalize', 'delivery', null];
const WAITING_REASONS = ['approval', 'input', 'child', 'reconciliation'];
const TERMINAL_REASONS: Partial<Record<Run['status'], readonly string[]>> = {
  succeeded: ['verified'], completed_unverified: ['no_required_verifier'],
  failed: ['verification_failed', 'verifier_infrastructure_failed', 'verifier_mutated_source', 'budget_exhausted', 'runtime_failed'],
  cancelled: ['cancelled_by_user', 'parent_cancelled']
};
type PublicState = Pick<Run, 'status' | 'nextStep' | 'frontierRef' | 'waitingReason' | 'waitingOnRef' | 'resultRef' | 'terminalReason' | 'terminalDetailRef'>;

export class EventCursorExpiredError extends KernelStorageError {
  constructor(readonly earliestEventSeq: number, readonly latestEventSeq: number, readonly snapshot: RunSnapshotV1) {
    super('EVENT_CURSOR_EXPIRED', 'Run event cursor precedes the retained display stream');
  }
}

function invalid(message: string): never { throw new KernelStorageError('INVALID_REQUEST', message); }
function corrupt(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
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
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).some(key => !keys.includes(key))) throw new TypeError('read request has an unknown field');
}
function requestInteger(value: unknown, fallback?: number): number {
  if (value === undefined && fallback !== undefined) return fallback;
  if (typeof value !== 'number') throw new TypeError('read cursor or limit must be a number');
  return integer(value);
}
function limit(value: unknown): number {
  const result = requestInteger(value, 100);
  if (result < 1 || result > 1000) throw new TypeError('read limit must be in 1..1000');
  return result;
}
function validateRequest(request: ReadControlRequest): ReadControlRequest {
  try {
    if (!isRecord(request) || request.protocolVersion !== 1 || Object.values(request).some(value => value === undefined)) {
      throw new TypeError('read request requires an exact protocolVersion=1 JSON object');
    }
    // Copy the exact normalized request before any asynchronous authentication.
    if (request.method === 'session.get') {
      exactKeys(request, ['protocolVersion', 'method', 'sessionId', 'afterItemSeq', 'limit']);
      return { protocolVersion: 1, method: request.method, sessionId: id(request.sessionId),
        afterItemSeq: requestInteger(request.afterItemSeq, 0), limit: limit(request.limit) };
    }
    if (request.method === 'run.get') {
      exactKeys(request, ['protocolVersion', 'method', 'runId', 'afterItemSeq', 'afterJournalSeq', 'checkpointCursor', 'itemLimit', 'journalLimit', 'checkpointLimit']);
      const normalized: Extract<ReadControlRequest, { method: 'run.get' }> = { protocolVersion: 1, method: request.method,
        runId: id(request.runId), afterItemSeq: requestInteger(request.afterItemSeq, 0), afterJournalSeq: requestInteger(request.afterJournalSeq, 0),
        itemLimit: limit(request.itemLimit), journalLimit: limit(request.journalLimit), checkpointLimit: limit(request.checkpointLimit) };
      if (Object.hasOwn(request, 'checkpointCursor')) {
        if (typeof request.checkpointCursor !== 'string' || request.checkpointCursor.length > 1024) throw new TypeError('Checkpoint cursor must be a bounded string');
        normalized.checkpointCursor = request.checkpointCursor;
      }
      return normalized;
    }
    if (request.method === 'run.attach') {
      exactKeys(request, ['protocolVersion', 'method', 'runId', 'afterEventSeq', 'limit']);
      return { protocolVersion: 1, method: request.method, runId: id(request.runId),
        afterEventSeq: requestInteger(request.afterEventSeq), limit: limit(request.limit) };
    }
    throw new TypeError('unsupported read method');
  } catch (error) {
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
  const session = sessionFromRow(row);
  id(session.id); assertArtifactRef(session.workspaceIdentityRef); assertArtifactRef(session.contextProjectionRef);
  integer(session.contextRevision, 1); integer(session.latestItemSeq);
  parseCanonicalTime(session.createdAt); parseCanonicalTime(session.updatedAt);
  if ((session.parentSessionId === undefined) !== (session.forkedThroughItemSeq === undefined)) corrupt('Session lineage is incomplete');
  if (session.parentSessionId !== undefined) {
    id(session.parentSessionId);
    if (integer(session.forkedThroughItemSeq) > session.latestItemSeq) corrupt('Session fork cursor exceeds its stream');
  }
  return session;
}
function metadataItem(row: ItemRow, expectedSequence: number): RunItemReferenceV1 {
  if (integer(row.item_seq, 1) !== expectedSequence) corrupt('retained item stream has a sequence gap');
  id(row.item_id); assertArtifactRef(row.payload_ref); parseCanonicalTime(row.created_at);
  return { schemaVersion: 1, itemId: row.item_id, itemSeq: expectedSequence, payloadRef: row.payload_ref,
    payloadDigest: row.payload_ref, createdAt: row.created_at };
}
/** Exact incremental JCS size: array punctuation belongs to the fixed empty envelope. */
function byteBudget(emptyEnvelope: unknown) {
  const initial = canonicalJsonBytes(emptyEnvelope).byteLength;
  let bytes = initial;
  return <T>(stream: T[], candidate: T): boolean => {
    const candidateBytes = canonicalJsonBytes(candidate).byteLength;
    if (initial + candidateBytes > METADATA_BYTES) corrupt('retained metadata row exceeds a complete bounded page');
    const next = bytes + candidateBytes + (stream.length === 0 ? 0 : 1);
    if (next > METADATA_BYTES) return false;
    stream.push(candidate); bytes = next; return true;
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
  const items: SessionItem[] = []; const append = byteBudget(items);
  let next = after;
  page: for (const range of ranges) {
    while (next < range.through && items.length < request.limit!) {
      const row = statement.get<ItemRow>(range.sessionId, BigInt(Math.max(next, range.from)), BigInt(range.through));
      if (!row) corrupt('Session logical item stream has a sequence gap');
      const metadata = metadataItem(row, next + 1);
      if (row.session_id !== range.sessionId || !SESSION_KINDS.includes(row.kind)) corrupt('Session item ownership or kind is invalid');
      const item: SessionItem = { schemaVersion: 1, itemId: metadata.itemId, sessionId: range.sessionId,
        itemSeq: metadata.itemSeq, kind: row.kind as SessionItem['kind'], payloadRef: metadata.payloadRef, createdAt: metadata.createdAt };
      if (!append(items, item)) break page;
      next = item.itemSeq;
    }
    if (items.length === request.limit) break;
  }
  return { method: 'session.get', snapshot: { schemaVersion: 1, session }, items, highWaterItemSeq: session.latestItemSeq, nextItemSeq: next };
}

function encodeCheckpoint(runId: string, position: CheckpointPosition): string {
  return canonicalJsonBytes({ schemaVersion: 1, runId, createdAt: position.createdAt, checkpointId: position.checkpointId }).toString('base64url');
}
function decodeCheckpointCursor(cursor: string, runId: string): CheckpointPosition {
  try {
    if (cursor.length > 1024 || !/^[A-Za-z0-9_-]+$/u.test(cursor)) throw new TypeError('invalid cursor encoding');
    const bytes = Buffer.from(cursor, 'base64url');
    const value = parseJsonStrict(bytes.toString('utf8'));
    if (!isRecord(value)) throw new TypeError('invalid cursor object');
    exactKeys(value, ['schemaVersion', 'runId', 'createdAt', 'checkpointId']);
    if (value.schemaVersion !== 1 || value.runId !== runId || typeof value.createdAt !== 'string') throw new TypeError('invalid cursor identity');
    parseCanonicalTime(value.createdAt); id(value.checkpointId);
    const position = { createdAt: value.createdAt, checkpointId: value.checkpointId as string };
    if (encodeCheckpoint(runId, position) !== cursor) throw new TypeError('noncanonical cursor bytes');
    return position;
  } catch { invalid('Checkpoint cursor is invalid for this Run'); }
}
function checkedCheckpoint(row: SqliteRow): Checkpoint {
  if (Object.keys(CHECKPOINT_TEXT_BOUNDS).some(column => typeof row[column] !== 'string')) corrupt('Checkpoint metadata exceeds its bounds or is unavailable');
  const checkpoint = checkpointFromRow(row);
  if (row.schema_version !== 1n && row.schema_version !== 1) corrupt('Checkpoint schema version is invalid');
  id(checkpoint.id); id(checkpoint.runId); parseCanonicalTime(checkpoint.createdAt);
  integer(checkpoint.basedOnRunRevision); integer(checkpoint.runItemSeq); integer(checkpoint.journalSeq);
  assertArtifactRef(checkpoint.contextManifestRef); assertArtifactRef(checkpoint.workspaceStateRef);
  if (!['initial', 'auto', 'manual', 'pre-effect', 'handoff'].includes(checkpoint.reason)) corrupt('Checkpoint reason is invalid');
  return checkpoint;
}
function highSequence(connection: SqliteConnection, table: 'items' | 'run_journal', column: 'item_seq' | 'seq', runId: string): number {
  const row = connection.prepare(`SELECT COALESCE(max(${column}), 0) AS high FROM ${table} WHERE run_id = ?`).get<{ high: unknown }>(runId);
  return integer(row?.high);
}
/** The historical event's own state follows the same metadata matrix; it never determines current Run truth. */
function checkedPublicState(state: PublicState): void {
  if (!RUN_STATUSES.includes(state.status) || !NEXT_STEPS.includes(state.nextStep)) corrupt('Run state discriminator is invalid');
  if (state.waitingReason !== undefined && !WAITING_REASONS.includes(state.waitingReason)) corrupt('Run waiting reason is invalid');
  if (state.status === 'waiting') {
    if (state.waitingReason === undefined || state.waitingOnRef === undefined) corrupt('waiting Run has no exact waiting subject');
  } else if (state.waitingReason !== undefined || state.waitingOnRef !== undefined) corrupt('nonwaiting Run retains waiting metadata');
  const reasons = TERMINAL_REASONS[state.status];
  if (reasons !== undefined) {
    if (state.nextStep !== null || state.frontierRef !== undefined || !reasons.includes(state.terminalReason as string)) corrupt('terminal Run state/reason is inconsistent');
    const success = state.status === 'succeeded' || state.status === 'completed_unverified';
    if (success ? state.resultRef === undefined || state.terminalDetailRef !== undefined : state.resultRef !== undefined || state.terminalDetailRef === undefined) {
      corrupt('terminal Run result/detail metadata is inconsistent');
    }
  } else if (state.nextStep === null || state.frontierRef === undefined || state.resultRef !== undefined || state.terminalReason !== undefined || state.terminalDetailRef !== undefined) {
    corrupt('nonterminal Run metadata is inconsistent');
  }
}
function checkedRun(row: SqliteRow): Run {
  for (const field of ['parent_run_id', 'active_worker_launch_id']) if (row[field] !== null) id(row[field]);
  for (const field of ['frontier_ref', 'waiting_on_ref', 'result_ref', 'terminal_detail_ref', 'stop_intent_ref']) {
    if (row[field] !== null) artifactRef(row[field]);
  }
  const run = runFromRow(row);
  id(run.id); id(run.sessionId); assertArtifactRef(run.specRef); id(run.latestCheckpointId);
  integer(run.revision, 1); integer(run.leaseEpoch); integer(run.repairCount);
  parseCanonicalTime(run.createdAt); parseCanonicalTime(run.updatedAt); parseCanonicalTime(run.deadlineAt);
  try { decodeBudgetUsage(run.budgetReserved); decodeBudgetUsage(run.budgetConsumed); }
  catch { corrupt('Run snapshot budget metadata is invalid'); }
  for (const field of ['parentRunId', 'activeWorkerLaunchId'] as const) if (run[field] !== undefined) id(run[field]);
  for (const field of ['frontierRef', 'waitingOnRef', 'resultRef', 'terminalDetailRef', 'stopIntentRef'] as const) {
    if (run[field] !== undefined) assertArtifactRef(run[field]);
  }
  checkedPublicState(run);
  if ((run.status === 'running') !== (run.activeWorkerLaunchId !== undefined)) corrupt('Run active launch metadata is inconsistent');
  if ((run.status === 'succeeded' || run.status === 'completed_unverified') && (run.stopIntentRef !== undefined || run.cancelRequested)) corrupt('successful Run retains stop metadata');
  if ((run.status === 'failed' || run.status === 'cancelled') && run.stopIntentRef === undefined) corrupt('stopped Run has no winning stop intent');
  return run;
}
function runGetCut(connection: SqliteConnection, request: Extract<ReadControlRequest, { method: 'run.get' }>, run: Run, itemHigh: number): CapturedRead {
  const journalHigh = highSequence(connection, 'run_journal', 'seq', run.id);
  const highRow = connection.prepare(`SELECT ${CHECKPOINT_COLUMNS} FROM checkpoints WHERE run_id = ? ORDER BY checkpoints.created_at DESC, checkpoints.id DESC LIMIT 1`).get(run.id);
  if (!highRow) corrupt('admitted Run has no retained Checkpoint');
  const high = checkedCheckpoint(highRow);
  const cursor = request.checkpointCursor === undefined ? undefined : decodeCheckpointCursor(request.checkpointCursor, run.id);
  if (request.afterItemSeq! > itemHigh || request.afterJournalSeq! > journalHigh) invalid('Run sequence cursor exceeds the captured high-water');
  if (cursor && !connection.prepare('SELECT id FROM checkpoints WHERE run_id = ? AND created_at = ? AND id = ?')
    .get(run.id, cursor.createdAt, cursor.checkpointId)) invalid('Checkpoint cursor names no retained row');
  const items: RunItemReferenceV1[] = []; const journal: ReturnType<typeof journalEntryFromRow>[] = []; const checkpoints: Checkpoint[] = [];
  const append = byteBudget({ items, journal, checkpoints });
  let nextItem = request.afterItemSeq!; let nextJournal = request.afterJournalSeq!; let nextCheckpoint = cursor;
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
      if (!append(items, item)) break page;
      nextItem = item.itemSeq;
    }
    while (nextJournal < journalHigh && journal.length < request.journalLimit!) {
      const row = journalStatement.get<Omit<JournalSqlRow, 'entry_json'> & { entry_json: string | null }>(run.id, BigInt(nextJournal), BigInt(journalHigh));
      if (!row) corrupt('Run Journal stream has a sequence gap');
      if (row.entry_json === null) corrupt('retained Run Journal row exceeds its metadata bound');
      const entry = journalEntryFromRow({ ...row, entry_json: row.entry_json });
      if (entry.seq !== nextJournal + 1) corrupt('Run Journal stream has a sequence gap');
      if (!append(journal, entry)) break page;
      nextJournal = entry.seq;
    }
    // Checkpoints contain fixed-size metadata, not Journal payloads. Fetch one
    // bounded batch so an unindexed time-order cut is sorted once, not per row.
    const start = nextCheckpoint ?? { createdAt: '', checkpointId: '' };
    const rows = checkpointStatement.all(run.id, start.createdAt, start.createdAt, start.checkpointId,
      high.createdAt, high.createdAt, high.id, BigInt(request.checkpointLimit!));
    for (const row of rows) {
      const checkpoint = checkedCheckpoint(row);
      if (!append(checkpoints, checkpoint)) break page;
      nextCheckpoint = { createdAt: checkpoint.createdAt, checkpointId: checkpoint.id };
    }
  }
  return { run, latestRunItemSeq: itemHigh, result: { method: 'run.get', items, journal, checkpoints,
    highWaterItemSeq: itemHigh, highWaterJournalSeq: journalHigh, highWaterCheckpointCursor: encodeCheckpoint(run.id, { createdAt: high.createdAt, checkpointId: high.id }),
    nextItemSeq: nextItem, nextJournalSeq: nextJournal,
    ...(nextCheckpoint === undefined ? {} : { nextCheckpointCursor: encodeCheckpoint(run.id, nextCheckpoint) }) } };
}

function checkedEvent(row: { event_seq: unknown; payload_json: string | null; occurred_at: string }, run: Run, itemHigh: number): RunEvent {
  if (row.payload_json === null) corrupt('retained Run event row exceeds its metadata bound');
  const value = parseJsonStrict(row.payload_json);
  if (!isRecord(value) || value.schemaVersion !== 1 || value.runId !== run.id || value.eventSeq !== integer(row.event_seq, 1) ||
      value.occurredAt !== row.occurred_at) corrupt('Run event columns do not match their exact payload');
  parseCanonicalTime(row.occurred_at);
  if (value.kind === 'state_changed') {
    exactKeys(value, ['schemaVersion', 'kind', 'runId', 'eventSeq', 'runRevision', 'status', 'nextStep', 'waitingReason', 'waitingOnRef', 'frontierRef',
      'latestRunItemSeq', 'resultRef', 'terminalReason', 'terminalDetailRef', 'occurredAt']);
    if (integer(value.runRevision, 1) > run.revision) corrupt('Run event revision exceeds its snapshot');
    if (integer(value.latestRunItemSeq) > itemHigh) corrupt('Run event item cursor exceeds its snapshot');
    for (const key of ['waitingOnRef', 'frontierRef', 'resultRef', 'terminalDetailRef']) if (Object.hasOwn(value, key)) artifactRef(value[key]);
    checkedPublicState(value as PublicState);
  } else if (value.kind === 'progress') {
    exactKeys(value, ['schemaVersion', 'kind', 'runId', 'eventSeq', 'observedRunRevision', 'phase', 'opId', 'messageRef', 'completedUnits', 'totalUnits', 'occurredAt']);
    if (!['agent', 'tool', 'verify', 'recovery', 'delivery'].includes(value.phase as string) || integer(value.observedRunRevision, 1) > run.revision) corrupt('Run progress observation is invalid');
    if (Object.hasOwn(value, 'opId')) id(value.opId);
    if (Object.hasOwn(value, 'messageRef')) artifactRef(value.messageRef);
    for (const key of ['completedUnits', 'totalUnits']) if (Object.hasOwn(value, key)) integer(value[key]);
  } else corrupt('Run event kind is not closed');
  return value as RunEvent;
}
function runAttachCut(connection: SqliteConnection, request: Extract<ReadControlRequest, { method: 'run.attach' }>, run: Run, itemHigh: number): CapturedRead {
  const bounds = connection.prepare('SELECT min(event_seq) AS earliest, max(event_seq) AS latest FROM run_events WHERE run_id = ?')
    .get<{ earliest: unknown; latest: unknown }>(run.id);
  const earliest = integer(bounds?.earliest, 1); const latest = integer(bounds?.latest, 1);
  if (request.afterEventSeq > latest) invalid('Run event cursor exceeds the captured high-water');
  const expired = request.afterEventSeq < Math.max(0, earliest - 1);
  const events: RunEvent[] = [];
  if (!expired) {
    const statement = connection.prepare(`SELECT event_seq,
      CASE WHEN length(CAST(payload_json AS BLOB)) <= ${METADATA_BYTES} THEN payload_json ELSE NULL END AS payload_json, occurred_at FROM run_events
      WHERE run_id = ? AND event_seq > ? AND event_seq <= ? ORDER BY event_seq LIMIT 1`);
    let next = request.afterEventSeq;
    while (next < latest && events.length < request.limit!) {
      const row = statement.get<{ event_seq: unknown; payload_json: string | null; occurred_at: string }>(run.id, BigInt(next), BigInt(latest));
      if (!row) corrupt('retained Run event bounds contain no next row');
      const event = checkedEvent(row, run, itemHigh);
      events.push(event); next = event.eventSeq;
    }
  }
  return { run, latestRunItemSeq: itemHigh, ...(expired ? { expired: { earliest, latest } } : {}),
    result: { method: 'run.attach', earliestRetainedEventSeq: earliest, latestRetainedEventSeq: latest, highWaterEventSeq: latest,
      events, nextEventSeq: events.at(-1)?.eventSeq ?? request.afterEventSeq } };
}

export async function readControl(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  request: ReadControlRequest, identity: AuthenticatedControlIdentity): Promise<ReadControlResult> {
  const normalized = validateRequest(request);
  const authenticated = { principalId: identity.principalId, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest };
  await validateControlChannelClosure(artifacts, owner, authenticated);
  const cut = driver.readSnapshot(connection => {
    assertActiveStateOwner(connection, owner);
    try {
      if (normalized.method === 'session.get') return { result: sessionCut(connection, normalized, authenticated.principalId) };
      const run = checkedRun(requireOwnedRow(connection, 'runs', normalized.runId, authenticated.principalId));
      const itemHigh = highSequence(connection, 'items', 'item_seq', run.id);
      return normalized.method === 'run.get' ? runGetCut(connection, normalized, run, itemHigh) : runAttachCut(connection, normalized, run, itemHigh);
    } catch (error) {
      if (error instanceof TypeError || error instanceof SyntaxError) corrupt('retained control metadata is invalid');
      throw error;
    }
  });
  let result: ReadControlResult;
  let expired: EventCursorExpiredError | undefined;
  if ('run' in cut) {
    const value = await artifacts.readCanonical(cut.run.specRef);
    if (canonicalSha256(value) !== cut.run.specRef) throw new KernelStorageError('ARTIFACT_MISMATCH', 'RunSpec is not canonical JSON');
    const spec = decodeRunSpec(value);
    const snapshot: RunSnapshotV1 = { schemaVersion: 1, operation: spec.operation, run: cut.run, latestRunItemSeq: cut.latestRunItemSeq };
    result = { ...cut.result, snapshot };
    if (cut.expired) expired = new EventCursorExpiredError(cut.expired.earliest, cut.expired.latest, snapshot);
  } else result = cut.result;
  await validateControlChannelClosure(artifacts, owner, authenticated);
  assertActiveStateOwner(driver, owner);
  if (expired) throw expired;
  return result;
}
