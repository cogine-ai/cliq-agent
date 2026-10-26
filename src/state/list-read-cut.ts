import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { setImmediate as yieldTurn } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, normalizeAbsolutePath, parseCanonicalTime } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { controlWireInteger, controlWireRecord } from '../kernel/control-wire-data.js';
import { decodeSessionSummary, type SessionListRequestV1, type SessionSummaryV1 } from '../kernel/session-continuity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { advanceTimeFence, readTimeFence } from './canonical-time.js';
import { assertCurrentControlFrame, validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import type { ArtifactCatalog } from './artifacts.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import type { SqliteConnection, SqliteDriver, SqliteInputValue } from './sqlite-driver.js';

const TTL_MS = 15 * 60 * 1000, MAX_ROWS = 100_000, MAX_BYTES = 64 * 1024 * 1024, BATCH = 128;
// One complete list preparation in this process, across all Stores. The SQL
// capture is capped to 100001 rows and each source field's public byte bound;
// retained payloads total at most 64 MiB. One connection-private source/entry
// scratch can exist; typed return values retain only the requested page.
let preparing = false, scratchFailure: ResourceRetirementError | undefined;
type Cut = { schemaVersion: 1; cutId: string; ownerPrincipalId: string; method: 'session.list'; normalizedFilterDigest: string;
  normalizedLimit: number; createdAt: string; expiresAt: string; cursorSecretBase64url: string; entryCount: number; entriesDigest: string; cutDigest: string };
type Entry = { schemaVersion: 1; cutId: string; ordinal: number; sortCreatedAt: string; stableId: string;
  payload: { method: 'session.list'; value: SessionSummaryV1 }; rowDigest: string };
type CutRow = { cut_id: string; owner_principal_id: string; method: string; normalized_filter_digest: string; normalized_limit: bigint;
  created_at: string; expires_at: string; entries_digest: string; cut_digest: string; cursor_secret_base64url: string };
type EntryRow = { cut_id: Uint8Array; ordinal: bigint; stable_id: Uint8Array | null; row_digest: Uint8Array | null; payload_json: Uint8Array };
type SourceRow = { id: Uint8Array | null; workspace_identity_ref: Uint8Array | null; name: Uint8Array | null; parent_session_id: Uint8Array | null;
  context_revision: bigint; latest_item_seq: bigint; created_at: Uint8Array | null; updated_at: Uint8Array | null };
type Cursor = { schemaVersion: 1; cutId: string; afterOrdinal: number; macBase64url: string };
export class ListCursorError extends KernelStorageError {
  readonly controlError = Object.freeze({ schemaVersion: 1 as const, code: 'INVALID_REQUEST' as const, retryable: false as const,
    messageCode: 'control.invalid_list_cursor', issues: [{ path: 'cursor', issueCode: 'invalid_list_cursor' }] });
  constructor() { super('INVALID_REQUEST', 'list cursor is unavailable or invalid'); }
}
export class ListCutCapacityError extends Error {
  readonly controlError = Object.freeze({ schemaVersion: 1 as const, code: 'RESOURCE_EXHAUSTED' as const, retryable: true as const,
    resourceKind: 'state_storage' as const, retryAfterMs: 1000 as const, messageCode: 'control.list_cut_capacity' });
  constructor() { super('materialized list cut exceeds its fixed storage capacity'); }
}
export class ListCutBusyError extends Error {
  readonly controlError = Object.freeze({ schemaVersion: 1 as const, code: 'RATE_LIMITED' as const, retryable: true as const,
    retryAfterMs: 1000 as const, messageCode: 'control.list_cut_busy' });
  constructor() { super('the bounded list preparation scratch is already owned'); }
}
function corrupt(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'materialized list cut failed complete integrity validation'); }
function secret(value: string): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return corrupt();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) return corrupt();
  return bytes;
}
function cutDigest(cut: Cut): string {
  const { cursorSecretBase64url: _secret, cutDigest: _digest, ...data } = cut;
  return canonicalSha256(data);
}
function cursorMac(cut: Cut, afterOrdinal: number): string {
  return createHmac('sha256', secret(cut.cursorSecretBase64url)).update('cliq-list-cursor-v1\0', 'ascii')
    .update(canonicalJsonBytes({ schemaVersion: 1, cutId: cut.cutId, afterOrdinal })).digest('base64url');
}
function encodeCursor(cut: Cut, afterOrdinal: number): string {
  return canonicalJsonBytes({ schemaVersion: 1, cutId: cut.cutId, afterOrdinal, macBase64url: cursorMac(cut, afterOrdinal) }).toString('base64url');
}
function decodeCursor(value: string): Cursor {
  try {
    if (Buffer.byteLength(value) > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) throw 0;
    const bytes = Buffer.from(value, 'base64url');
    const data = controlWireRecord(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), ['schemaVersion', 'cutId', 'afterOrdinal', 'macBase64url']);
    if (bytes.toString('base64url') !== value || !canonicalJsonBytes(data).equals(bytes) || data.schemaVersion !== 1) throw 0;
    secret(data.cutId as string); secret(data.macBase64url as string); controlWireInteger(data.afterOrdinal, 1);
    return data as Cursor;
  } catch { throw new ListCursorError(); }
}
function filterDigest(principalId: string, request: SessionListRequestV1, limit: number): string {
  return canonicalSha256({ ownerPrincipalId: principalId, method: 'session.list', workspacePath: request.workspacePath === undefined ? null :
    normalizeAbsolutePath(request.workspacePath), normalizedLimit: limit });
}
function page(cut: Cut, entries: readonly Entry[], after: number) {
  const last = after + entries.length;
  return immutableSnapshot({ method: 'session.list' as const, sessions: entries.map(entry => entry.payload.value),
    ...(last < cut.entryCount ? { nextCursor: encodeCursor(cut, last) } : {}) });
}
function workspaceRefDigest(connection: SqliteConnection, principalId: string): string {
  const hash = createHash('sha256'); hash.update('['); let after = '', comma = false;
  for (const row of connection.prepare('SELECT DISTINCT CASE WHEN length(CAST(workspace_identity_ref AS BLOB))<=64 THEN workspace_identity_ref END AS ref FROM sessions WHERE principal_id=? ORDER BY workspace_identity_ref').iterate<{ ref: string }>(principalId)) {
    if (!/^[0-9a-f]{64}$/u.test(row.ref) || row.ref <= after) return corrupt();
    if (comma) hash.update(','); hash.update(canonicalJsonBytes(row.ref)); comma = true; after = row.ref;
  }
  return hash.update(']').digest('hex');
}
const sourceColumns = 'id,workspace_identity_ref,name,parent_session_id,context_revision,latest_item_seq,created_at,updated_at';
const sourceProjection = 'CASE WHEN length(CAST(id AS BLOB))<=128 THEN id END AS id,' +
  'CASE WHEN length(CAST(workspace_identity_ref AS BLOB))<=64 THEN workspace_identity_ref END AS workspace_identity_ref,' +
  'CASE WHEN name IS NULL OR length(CAST(name AS BLOB))<=256 THEN name END AS name,' +
  'CASE WHEN parent_session_id IS NULL OR length(CAST(parent_session_id AS BLOB))<=128 THEN parent_session_id END AS parent_session_id,' +
  'context_revision,latest_item_seq,CASE WHEN length(CAST(created_at AS BLOB))=24 THEN created_at END AS created_at,' +
  'CASE WHEN length(CAST(updated_at AS BLOB))=24 THEN updated_at END AS updated_at,' +
  '(name IS NOT NULL AND length(CAST(name AS BLOB))>256 OR parent_session_id IS NOT NULL AND length(CAST(parent_session_id AS BLOB))>128) AS overlong';
const entryColumns = 'ordinal,stable_id,row_digest,payload_json';
// Node's ordinary SQLite TEXT conversion replaces malformed UTF-8. Keep the
// original bounded bytes across this boundary, and reject before any JSON or
// digest could accidentally describe replacement characters instead.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
function capturedText(bytes: Uint8Array | null): string {
  if (!(bytes instanceof Uint8Array)) return corrupt();
  try {
    const text = utf8.decode(bytes);
    if (!Buffer.from(text, 'utf8').equals(bytes)) return corrupt();
    return text;
  } catch { return corrupt(); }
}
function decodedSource(row: SourceRow & { overlong?: bigint }): SessionSummaryV1 {
  try {
    if (row.overlong !== 0n) return corrupt();
    return decodeSessionSummary({ schemaVersion: 1, id: capturedText(row.id), workspaceIdentityRef: capturedText(row.workspace_identity_ref),
      ...(row.name === null ? {} : { name: capturedText(row.name) }), ...(row.parent_session_id === null ? {} : { parentSessionId: capturedText(row.parent_session_id) }),
      contextRevision: Number(row.context_revision), latestItemSeq: Number(row.latest_item_seq), createdAt: capturedText(row.created_at), updatedAt: capturedText(row.updated_at) });
  } catch { return corrupt(); }
}
function sameSource(connection: SqliteConnection, principalId: string, workspaceJson?: string): boolean {
  const filter = workspaceJson === undefined ? '' : ' AND workspace_identity_ref IN (SELECT value FROM json_each(?))';
  const values: SqliteInputValue[] = [principalId, ...(workspaceJson === undefined ? [] : [workspaceJson])];
  const capacity = connection.prepare('SELECT count(*) AS n FROM (SELECT 1 FROM sessions WHERE principal_id=?' + filter + ' LIMIT 100001)').get<{ n: bigint }>(...values)!;
  const prepared = connection.prepare('SELECT count(*) AS n FROM temp.cliq_list_source').get<{ n: bigint }>()!;
  if (capacity.n !== prepared.n) return false;
  // Unique ids plus exact cardinality and every original tuple's indexed
  // equality prove both directions of set equality without two full sorts.
  const row = connection.prepare('SELECT EXISTS(SELECT 1 FROM temp.cliq_list_source p LEFT JOIN sessions s ON s.id=p.id AND s.principal_id=? WHERE ' +
    's.id IS NULL OR CAST(s.workspace_identity_ref AS BLOB) IS NOT CAST(p.workspace_identity_ref AS BLOB) OR ' +
    'CAST(s.name AS BLOB) IS NOT CAST(p.name AS BLOB) OR CAST(s.parent_session_id AS BLOB) IS NOT CAST(p.parent_session_id AS BLOB) OR ' +
    's.context_revision IS NOT p.context_revision OR s.latest_item_seq IS NOT p.latest_item_seq OR ' +
    'CAST(s.created_at AS BLOB) IS NOT CAST(p.created_at AS BLOB) OR CAST(s.updated_at AS BLOB) IS NOT CAST(p.updated_at AS BLOB) LIMIT 1) AS changed')
    .get<{ changed: bigint }>(principalId);
  return row?.changed === 0n;
}
function sameEntries(connection: SqliteConnection, cutId: string): boolean {
  const capacity = connection.prepare('SELECT count(*) AS n,coalesce(sum(length(CAST(payload_json AS BLOB))),0) AS bytes FROM list_read_cut_entries WHERE cut_id=?')
    .get<{ n: bigint; bytes: bigint }>(cutId)!;
  if (capacity.n > BigInt(MAX_ROWS) || capacity.bytes > BigInt(MAX_BYTES)) return false;
  const prepared = connection.prepare('SELECT count(*) AS n FROM temp.cliq_list_entries').get<{ n: bigint }>()!;
  if (capacity.n !== prepared.n) return false;
  const row = connection.prepare('SELECT EXISTS(SELECT 1 FROM temp.cliq_list_entries p LEFT JOIN list_read_cut_entries e ON e.cut_id=? AND e.ordinal=p.ordinal WHERE ' +
    'e.ordinal IS NULL OR CAST(e.stable_id AS BLOB) IS NOT CAST(p.stable_id AS BLOB) OR CAST(e.row_digest AS BLOB) IS NOT CAST(p.row_digest AS BLOB) OR ' +
    'CAST(e.payload_json AS BLOB) IS NOT CAST(p.payload_json AS BLOB) LIMIT 1) AS changed').get<{ changed: bigint }>(cutId);
  return row?.changed === 0n;
}
function rowFingerprint(row: CutRow): string { return canonicalSha256({ ...row, normalized_limit: Number(row.normalized_limit) }); }
const cutSelect = 'SELECT cut_id,owner_principal_id,method,' +
  'CASE WHEN length(normalized_filter_digest)=64 THEN normalized_filter_digest END AS normalized_filter_digest,normalized_limit,' +
  'CASE WHEN length(created_at)=24 THEN created_at END AS created_at,CASE WHEN length(expires_at)=24 THEN expires_at END AS expires_at,' +
  'CASE WHEN length(entries_digest)=64 THEN entries_digest END AS entries_digest,CASE WHEN length(cut_digest)=64 THEN cut_digest END AS cut_digest,' +
  'CASE WHEN length(cursor_secret_base64url)=43 THEN cursor_secret_base64url END AS cursor_secret_base64url FROM list_read_cuts ';

/** Complete snapshots are copied under SQL, pure verification yields outside
 * SQL, and the sole final transaction verifies exact full source/value equality
 * before publishing. No transaction, statement iterator or authority escapes. */
export async function readSessionList(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  request: SessionListRequestV1, identity: AuthenticatedControlIdentity, signal?: AbortSignal) {
  signal?.throwIfAborted();
  const channel = await validateControlChannelClosure(artifacts, owner, identity);
  const current = () => { signal?.throwIfAborted(); if (channel.channel.transport.kind === 'uds_peer') assertCurrentControlFrame(owner, identity); };
  current(); assertActiveStateOwner(driver, owner);
  if (scratchFailure) throw scratchFailure;
  if (preparing) throw new ListCutBusyError();
  preparing = true;
  const pause = async () => { current(); assertActiveStateOwner(driver, owner); await yieldTurn(); current(); assertActiveStateOwner(driver, owner); };
  let ownsScratch = false, primary: unknown;
  try {
    let regressedAtEntry = false;
    driver.transaction(connection => {
      current(); assertActiveStateOwner(connection, owner);
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') regressedAtEntry = true;
    });
    if (regressedAtEntry) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; Session list is paused');
    if (driver.prepare("SELECT 1 FROM sqlite_temp_master WHERE name IN ('cliq_list_source','cliq_list_entries') LIMIT 1").get()) return corrupt();
    ownsScratch = true;
    driver.exec('CREATE TEMP TABLE cliq_list_source(ordinal INTEGER PRIMARY KEY,id TEXT UNIQUE,workspace_identity_ref TEXT,name TEXT,parent_session_id TEXT,' +
      'context_revision INTEGER,latest_item_seq INTEGER,created_at TEXT,updated_at TEXT,overlong INTEGER NOT NULL) STRICT;' +
      'CREATE TEMP TABLE cliq_list_entries(ordinal INTEGER PRIMARY KEY,stable_id TEXT,row_digest TEXT,payload_json TEXT NOT NULL,source_cut_id TEXT) STRICT');
    const stageEntry = driver.prepare('INSERT INTO temp.cliq_list_entries(ordinal,stable_id,row_digest,payload_json) VALUES(?,?,?,?)');
    const limit = request.limit ?? 50, normalizedFilterDigest = filterDigest(identity.principalId, request, limit);
    const cursor = request.cursor === undefined ? undefined : decodeCursor(request.cursor);
    if (cursor) {
      const retained = driver.transaction(connection => {
        current(); assertActiveStateOwner(connection, owner);
        const row = connection.prepare(cutSelect + "WHERE cut_id=? AND owner_principal_id=? AND method='session.list'").get<CutRow>(cursor.cutId, identity.principalId);
        if (!row) throw new ListCursorError();
        const capacity = connection.prepare('SELECT count(*) AS n,coalesce(sum(length(CAST(payload_json AS BLOB))),0) AS bytes FROM list_read_cut_entries WHERE cut_id=?')
          .get<{ n: bigint; bytes: bigint }>(cursor.cutId)!;
        if (capacity.n > BigInt(MAX_ROWS) || capacity.bytes > BigInt(MAX_BYTES)) return corrupt();
        // Freeze the original complete cut in SQLite, not a 64-MiB/100000-row
        // JS array. Only this request owns this connection-private scratch.
        connection.prepare('INSERT INTO temp.cliq_list_entries(source_cut_id,ordinal,stable_id,row_digest,payload_json) ' +
          'SELECT cut_id,ordinal,CASE WHEN length(CAST(stable_id AS BLOB))<=128 THEN stable_id END,' +
          'CASE WHEN length(CAST(row_digest AS BLOB))=64 THEN row_digest END,payload_json FROM list_read_cut_entries WHERE cut_id=? ORDER BY ordinal LIMIT 100001').run(cursor.cutId);
        if (connection.prepare('SELECT count(*) AS n FROM temp.cliq_list_entries').get<{ n: bigint }>()!.n !== capacity.n) return corrupt();
        return { row, entryCount: Number(capacity.n) };
      });
      const cut: Cut = { schemaVersion: 1, cutId: retained.row.cut_id, ownerPrincipalId: retained.row.owner_principal_id, method: 'session.list',
        normalizedFilterDigest: retained.row.normalized_filter_digest, normalizedLimit: Number(retained.row.normalized_limit), createdAt: retained.row.created_at,
        expiresAt: retained.row.expires_at, cursorSecretBase64url: retained.row.cursor_secret_base64url, entryCount: retained.entryCount,
        entriesDigest: retained.row.entries_digest, cutDigest: retained.row.cut_digest };
      secret(cut.cutId); secret(cut.cursorSecretBase64url);
      if (cut.normalizedLimit !== limit || cut.normalizedFilterDigest !== normalizedFilterDigest ||
          parseCanonicalTime(cut.expiresAt) - parseCanonicalTime(cut.createdAt) !== TTL_MS) throw new ListCursorError();
      const expected = Buffer.from(cursorMac(cut, cursor.afterOrdinal), 'base64url'), received = Buffer.from(cursor.macBase64url, 'base64url');
      if (received.length !== expected.length || !timingSafeEqual(expected, received) || cursor.afterOrdinal >= cut.entryCount || cursor.afterOrdinal % limit !== 0) throw new ListCursorError();
      const hash = createHash('sha256'); hash.update('['); const selected: Entry[] = [];
      let previousTime = '', previousId = '';
      const retainedBatch = driver.prepare('SELECT CAST(source_cut_id AS BLOB) AS cut_id,ordinal,CAST(stable_id AS BLOB) AS stable_id,' +
        'CAST(row_digest AS BLOB) AS row_digest,CAST(payload_json AS BLOB) AS payload_json FROM temp.cliq_list_entries WHERE ordinal>? ORDER BY ordinal LIMIT 128');
      for (let offset = 0; offset < retained.entryCount; offset += BATCH) {
        await pause();
        const rows = retainedBatch.all<EntryRow>(offset);
        if (rows.length !== Math.min(BATCH, retained.entryCount - offset)) return corrupt();
        for (let part = 0; part < rows.length; part++) {
          const index = offset + part, raw = rows[part]!;
          const originalCutId = capturedText(raw.cut_id), stableId = capturedText(raw.stable_id), rowDigest = capturedText(raw.row_digest);
          let payload: Entry['payload'];
          try {
            const data = controlWireRecord(parseJsonStrict(capturedText(raw.payload_json)), ['method', 'value']);
            if (data.method !== 'session.list' || !canonicalJsonBytes(data).equals(raw.payload_json)) return corrupt();
            payload = { method: 'session.list', value: decodeSessionSummary(data.value) };
          } catch { return corrupt(); }
          const entry: Entry = { schemaVersion: 1, cutId: cut.cutId, ordinal: index + 1, stableId,
            sortCreatedAt: payload.value.createdAt, payload, rowDigest };
          if (originalCutId !== cut.cutId || raw.ordinal !== BigInt(index + 1) || stableId !== payload.value.id ||
              digestOmitting(entry, 'rowDigest') !== rowDigest || previousTime > entry.sortCreatedAt ||
              previousTime === entry.sortCreatedAt && Buffer.compare(Buffer.from(previousId), Buffer.from(entry.stableId)) >= 0) return corrupt();
          previousTime = entry.sortCreatedAt; previousId = entry.stableId;
          if (index) hash.update(','); hash.update(canonicalJsonBytes(entry.rowDigest));
          if (index >= cursor.afterOrdinal && selected.length < limit) selected.push(entry);
          // The complete original raw bytes stay in TEMP for the final equality
          // check. Only one fixed batch and the requested page cross into JS.
        }
      }
      if (hash.update(']').digest('hex') !== cut.entriesDigest || cutDigest(cut) !== cut.cutDigest) return corrupt();
      const fingerprint = rowFingerprint(retained.row);
      let rejected: unknown, regressed = false;
      driver.transaction(connection => {
        current(); assertActiveStateOwner(connection, owner);
        if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { regressed = true; return; }
        const now = readTimeFence(connection)!.lastAcceptedAt;
        try {
          const row = connection.prepare(cutSelect + "WHERE cut_id=? AND owner_principal_id=? AND method='session.list'").get<CutRow>(cursor.cutId, identity.principalId);
          if (!row || rowFingerprint(row) !== fingerprint || now >= cut.expiresAt || now < cut.createdAt) throw new ListCursorError();
          if (!sameEntries(connection, cut.cutId)) return corrupt();
        } catch (error) { rejected = error; }
      });
      if (regressed) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; Session list is paused');
      if (rejected !== undefined) throw rejected;
      return page(cut, selected, cursor.afterOrdinal);
    }
    let prepared: { refsDigest: string; workspaceJson: string } | undefined;
    for (;;) {
      if (request.workspacePath !== undefined && !prepared) {
        const hash = createHash('sha256'), matching: string[] = []; hash.update('['); let after = '', comma = false;
        for (;;) {
          current();
          const rows = driver.readSnapshot(connection => {
            assertActiveStateOwner(connection, owner);
            return connection.prepare('SELECT DISTINCT CASE WHEN length(CAST(workspace_identity_ref AS BLOB))<=64 THEN workspace_identity_ref END AS ref FROM sessions WHERE principal_id=? AND workspace_identity_ref>? ORDER BY workspace_identity_ref LIMIT 1000')
              .all<{ ref: string }>(identity.principalId, after);
          });
          if (!rows.length) break;
          for (const row of rows) {
            current();
            if (!/^[0-9a-f]{64}$/u.test(row.ref) || row.ref <= after) return corrupt();
            const value = await artifacts.readCanonical(row.ref); if (canonicalSha256(value) !== row.ref) return corrupt();
            const workspace = decodeWorkspaceIdentity(value);
            if (workspace.ownerPrincipalId !== identity.principalId) return corrupt();
            const locator = workspace.kind === 'live' ? workspace.canonicalRootPath : workspace.legacyCanonicalRootPath;
            if (locator === normalizeAbsolutePath(request.workspacePath)) matching.push(row.ref);
            if (matching.length > MAX_ROWS) throw new ListCutCapacityError();
            if (comma) hash.update(','); hash.update(canonicalJsonBytes(row.ref)); comma = true; after = row.ref;
          }
        }
        prepared = { refsDigest: hash.update(']').digest('hex'), workspaceJson: canonicalJsonBytes(matching).toString('utf8') };
      }
      const workspaceJson = prepared?.workspaceJson;
      const captured = driver.transaction(connection => {
        current(); assertActiveStateOwner(connection, owner);
        if (prepared && workspaceRefDigest(connection, identity.principalId) !== prepared.refsDigest) return;
        const filter = workspaceJson === undefined ? '' : ' AND workspace_identity_ref IN (SELECT value FROM json_each(?))';
        const values = [identity.principalId, ...(workspaceJson === undefined ? [] : [workspaceJson])];
        const count = connection.prepare('SELECT count(*) AS n FROM (SELECT 1 FROM sessions WHERE principal_id=?' + filter + ' LIMIT 100001)')
          .get<{ n: bigint }>(...values)!.n;
        if (count > BigInt(MAX_ROWS)) throw new ListCutCapacityError();
        // The projection caps every field before the native copy. NULL/overlong
        // markers remain rejection data for the original complete decoder;
        // no arbitrarily large raw column is retained in scratch.
        connection.prepare('INSERT INTO temp.cliq_list_source(ordinal,' + sourceColumns + ',overlong) ' +
          'SELECT row_number() OVER(ORDER BY created_at COLLATE BINARY,id COLLATE BINARY),' + sourceColumns + ',overlong FROM (' +
          'SELECT ' + sourceProjection + ' FROM sessions WHERE principal_id=?' + filter + ' LIMIT 100001)' +
          ' ORDER BY created_at COLLATE BINARY,id COLLATE BINARY').run(...values);
        if (connection.prepare('SELECT count(*) AS n FROM temp.cliq_list_source').get<{ n: bigint }>()!.n !== count) return corrupt();
        return Number(count);
      });
      if (captured === undefined) { prepared = undefined; continue; }
      const cutId = randomBytes(32).toString('base64url'), cursorSecretBase64url = randomBytes(32).toString('base64url');
      const hash = createHash('sha256'); hash.update('[');
      const selected: Entry[] = []; let byteCount = 0;
      const sourceBatch = driver.prepare('SELECT ' + sourceColumns.split(',').map(column => ['context_revision', 'latest_item_seq'].includes(column)
        ? column : 'CAST(' + column + ' AS BLOB) AS ' + column).join(',') + ',overlong FROM temp.cliq_list_source WHERE ordinal>? ORDER BY ordinal LIMIT 128');
      for (let offset = 0; offset < captured; offset += BATCH) {
        await pause();
        const rows = sourceBatch.all<SourceRow & { overlong: bigint }>(offset);
        if (rows.length !== Math.min(BATCH, captured - offset)) return corrupt();
        for (let part = 0; part < rows.length; part++) {
          const index = offset + part, raw = rows[part]!, value = decodedSource(raw), payload = { method: 'session.list' as const, value };
          const encodedPayload = canonicalJsonBytes(payload).toString('utf8'); byteCount += Buffer.byteLength(encodedPayload);
          if (byteCount > MAX_BYTES) throw new ListCutCapacityError();
          const entry: Entry = { schemaVersion: 1, cutId, ordinal: index + 1, stableId: value.id, sortCreatedAt: value.createdAt, payload, rowDigest: '' };
          entry.rowDigest = digestOmitting(entry, 'rowDigest');
          stageEntry.run(entry.ordinal, entry.stableId, entry.rowDigest, encodedPayload);
          if (index) hash.update(','); hash.update(canonicalJsonBytes(entry.rowDigest));
          if (selected.length < limit) selected.push(entry);
        }
      }
      const entriesDigest = hash.update(']').digest('hex'), entryCount = captured;
      let result: ReturnType<typeof page> | undefined, regressed = false, changed = false;
      driver.transaction(connection => {
        current(); assertActiveStateOwner(connection, owner);
        if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { regressed = true; return; }
        if (prepared && workspaceRefDigest(connection, identity.principalId) !== prepared.refsDigest ||
            !sameSource(connection, identity.principalId, workspaceJson)) { changed = true; return; }
        const now = readTimeFence(connection)!.lastAcceptedAt, at = parseCanonicalTime(now);
        if (!Number.isSafeInteger(at + TTL_MS)) return corrupt();
        const cut: Cut = { schemaVersion: 1, cutId, ownerPrincipalId: identity.principalId, method: 'session.list', normalizedFilterDigest,
          normalizedLimit: limit, createdAt: now, expiresAt: new Date(at + TTL_MS).toISOString(), cursorSecretBase64url,
          entryCount, entriesDigest, cutDigest: '' };
        cut.cutDigest = cutDigest(cut);
        // Bounded expiry maintenance, not an unbounded cascade while Stop is
        // waiting. Large expired cuts can be collected across later queries.
        connection.prepare('DELETE FROM list_read_cut_entries WHERE rowid IN (SELECT e.rowid FROM list_read_cut_entries e JOIN list_read_cuts c ON c.cut_id=e.cut_id WHERE c.expires_at<=? ORDER BY c.expires_at,c.cut_id,e.ordinal LIMIT 256)').run(now);
        connection.prepare('DELETE FROM list_read_cuts WHERE cut_id IN (SELECT c.cut_id FROM list_read_cuts c WHERE c.expires_at<=? AND NOT EXISTS(SELECT 1 FROM list_read_cut_entries e WHERE e.cut_id=c.cut_id) ORDER BY c.expires_at,c.cut_id LIMIT 32)').run(now);
        connection.prepare('INSERT INTO list_read_cuts(cut_id,owner_principal_id,method,normalized_filter_digest,normalized_limit,created_at,expires_at,entries_digest,cut_digest,cursor_secret_base64url) VALUES(?,?,?,?,?,?,?,?,?,?)')
          .run(cutId, identity.principalId, cut.method, normalizedFilterDigest, limit, now, cut.expiresAt, entriesDigest, cut.cutDigest, cursorSecretBase64url);
        connection.prepare('INSERT INTO list_read_cut_entries(cut_id,ordinal,stable_id,row_digest,payload_json) SELECT ?,' +
          entryColumns + ' FROM temp.cliq_list_entries ORDER BY ordinal').run(cutId);
        if (connection.prepare('SELECT count(*) AS n FROM list_read_cut_entries WHERE cut_id=?').get<{ n: bigint }>(cutId)?.n !== BigInt(entryCount)) return corrupt();
        result = page(cut, selected, 0);
      });
      if (regressed) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; Session list is paused');
      if (result) return result;
      if (!changed) return corrupt();
      driver.exec('DELETE FROM temp.cliq_list_source; DELETE FROM temp.cliq_list_entries');
      prepared = undefined; await pause();
    }
  } catch (error) { primary = error; throw error;
  } finally {
    const failures: unknown[] = [];
    if (ownsScratch) for (const table of ['cliq_list_entries', 'cliq_list_source']) {
      try { driver.exec('DROP TABLE IF EXISTS temp.' + table); } catch (error) { failures.push(error); }
    }
    if (failures.length) {
      scratchFailure ??= new ResourceRetirementError('owned Session list query scratch did not retire',
        new AggregateError([primary, ...failures].filter(value => value !== undefined)));
      throw scratchFailure;
    }
    // DROP completed on the original SQLite connection. Its own original
    // database lifetime remains owned/joined by Store, never a new authority.
    preparing = false;
  }
}
