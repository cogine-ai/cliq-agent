import { DatabaseSync, constants as sqlite } from 'node:sqlite';
import { setImmediate } from 'node:timers/promises';
import type { FileHandle } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SignedKernelSchemaV1 } from '../kernel/runtime-upgrade.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertKernelSchemaVersion, KERNEL_AUTHORITY_TABLES, applyKernelSchema } from './schema.js';
import { decodeSignedKernelSchema } from './signed-schema.js';
import { assertContiguousStateOwnerHistory, readActiveStateOwner, readStateOwner } from './state-owner.js';
import { requiredSafeInteger } from '../kernel/identity.js';
import { readTimeFence } from './canonical-time.js';
import { assertSqliteConnectionOwnedBy, iterateNodeSqliteStatement, type SqliteConnection, type SqliteDriver,
  type SqliteInputValue, type SqliteRow, type SqliteRunResult, type SqliteStatement } from './sqlite-driver.js';
import { assertHeldCredentialNativeImage, openHeldPreparedImportCandidate,
  type HeldMigrationFilesystem, type NativeStateOwner, type PreparedImportImageObservation, type PreparedImportWriterSummary } from './native-owner.js';

export type PreparedImportTable = typeof KERNEL_AUTHORITY_TABLES[number];
type CandidateValue = string | bigint | null;
export type PreparedImportRow = Readonly<Record<string, CandidateValue>>;
export type PreparedLegacySessionRow = Readonly<{
  id: string; workspace_identity_ref: string; name: string | null; parent_session_id: string | null;
  forked_through_item_seq: bigint | null; context_revision: bigint; latest_item_seq: bigint;
  context_projection_ref: string; created_at: string; updated_at: string; principal_id: string;
  admission_method: string; admission_key: string; admission_intent_digest: string; admission_request_id: string | null;
}>;
export type PreparedLegacyItemRow = Readonly<{
  item_id: string; session_id: string; run_id: null; item_seq: bigint;
  kind: 'legacy_record' | 'legacy_compaction' | 'legacy_plan' | 'legacy_handoff' | 'legacy_bookmark';
  payload_ref: string; created_at: string;
}>;
export type PreparedImportArtifactRow = Readonly<{
  ref: string; media_type: string; schema_kind: string; byte_length: bigint; created_at: string;
}>;
export type PreparedLegacyImportRows = Readonly<{
  sessions: readonly PreparedLegacySessionRow[];
  items: readonly PreparedLegacyItemRow[];
  artifacts: readonly PreparedImportArtifactRow[];
}>;
export type PreparedImportBaseline = Readonly<{
  canonicalTimeFence: readonly PreparedImportRow[];
  stateOwners: readonly PreparedImportRow[];
  artifacts: readonly PreparedImportRow[];
  digest: string;
}>;
export type PreparedImportAppendCounts = Readonly<{ sessions: number; items: number; newArtifacts: number }>;
const order: Record<PreparedImportTable, string> = {
  canonical_time_fence: 'id', state_owners: 'owner_epoch', artifacts: 'ref COLLATE BINARY', sessions: 'id COLLATE BINARY',
  items: 'item_id COLLATE BINARY', runs: 'id COLLATE BINARY', checkpoints: 'id COLLATE BINARY',
  run_journal: 'run_id COLLATE BINARY,seq', run_events: 'run_id COLLATE BINARY,event_seq',
  worker_launches: 'launch_id COLLATE BINARY', workspace_generations: 'generation_id COLLATE BINARY',
  local_inference_activation_cycles: 'activation_cycle_id COLLATE BINARY', local_inference_launches: 'launch_id COLLATE BINARY',
  control_requests: 'principal_id COLLATE BINARY,method COLLATE BINARY,request_id COLLATE BINARY',
  list_read_cuts: 'cut_id COLLATE BINARY', list_read_cut_entries: 'cut_id COLLATE BINARY,ordinal',
  child_allocations: 'parent_run_id COLLATE BINARY,child_run_id COLLATE BINARY', authorization_grants: 'grant_id COLLATE BINARY',
  source_inspection_attempts: 'inspection_id COLLATE BINARY',
  mcp_registrations: 'owner_principal_id COLLATE BINARY,registration_id COLLATE BINARY',
  admin_operations: 'principal_id COLLATE BINARY,method COLLATE BINARY,request_id COLLATE BINARY,attempt'
};
const sourceTables = new Set<PreparedImportTable>(['canonical_time_fence', 'state_owners', 'artifacts']);
const importedTables = new Set<PreparedImportTable>(['sessions', 'items', 'artifacts']);
const legacyKinds = new Set(['legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark']);
// Uncertain close must not become a later unobserved GC close/retry.
const unretiredPreparedImportConnections = new Set<DatabaseSync>();
function mismatch(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function columnsFor(connection: SqliteConnection, table: PreparedImportTable): readonly string[] {
  return connection.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>().map(row => row.name);
}
function losslessQuery(table: PreparedImportTable, columns: readonly string[], primary?: 'item_id' | 'ref' | 'id'): string {
  return `SELECT ${columns.join(',')},${columns.map((column, index) => `CAST(${column} AS BLOB) AS __cliq_raw_${index}`).join(',')}
    FROM ${table}${primary ? ` WHERE ${primary}=?` : ''} ORDER BY ${order[table]}`;
}
function losslessRow(row: SqliteRow, columns: readonly string[]): PreparedImportRow {
  const original: SqliteRow = Object.create(null);
  for (const [index, column] of columns.entries()) {
    const value = row[column], bytes = row[`__cliq_raw_${index}`];
    if (value === null ? bytes !== null :
        (typeof value !== 'string' && typeof value !== 'bigint') || !(bytes instanceof Uint8Array) ||
        !Buffer.from(value.toString(), 'utf8').equals(bytes))
      mismatch('candidate SQL TEXT/INTEGER bytes cannot be decoded losslessly');
    original[column] = value!;
  }
  return rowSnapshot(original);
}
function rowSnapshot(row: SqliteRow): PreparedImportRow {
  if (types.isProxy(row)) return mismatch('candidate rows must be original scalar data');
  const result: Record<string, CandidateValue> = Object.create(null);
  for (const [key, property] of Object.entries(Object.getOwnPropertyDescriptors(row))) {
    if (!('value' in property)) return mismatch('candidate row accessors are unsupported');
    const value: unknown = property.value;
    if (value !== null && typeof value !== 'string' && typeof value !== 'bigint')
      return mismatch('candidate requires lossless original SQLite TEXT/INTEGER/NULL values');
    if (typeof value === 'string' && Buffer.from(value, 'utf8').toString('utf8') !== value)
      return mismatch('candidate cannot silently replace an unpaired surrogate during SQLite UTF-8 encoding');
    result[key] = value;
  }
  return Object.freeze(result);
}
function encodedRow(row: PreparedImportRow) {
  return Object.keys(row).sort().map(key => [key, typeof row[key] === 'bigint'
    ? { integer: row[key]!.toString() } : row[key]]);
}
/** Pure data cut of the genuine original driver. It supplies no authority:
 * Store still repeats the original owner/root/schema/empty-business checks in
 * its final transaction. No new SQL path, owner, clock or persistent cut. */
export function capturePreparedImportBaseline(driver: SqliteDriver, signedSchema: SignedKernelSchemaV1): PreparedImportBaseline {
  decodeSignedKernelSchema(signedSchema); assertSqliteConnectionOwnedBy(driver, driver);
  return driver.readSnapshot(connection => {
    assertSqliteConnectionOwnedBy(driver, connection); assertKernelSchemaVersion(connection, 8);
    assertContiguousStateOwnerHistory(connection);
    const owner = readActiveStateOwner(connection), fence = readTimeFence(connection);
    if (!owner || !fence || fence.state !== 'healthy' || fence.stateOwnerEpoch !== owner.ownerEpoch)
      mismatch('import baseline requires its real active original StateOwner and healthy matching time fence');
    for (const table of KERNEL_AUTHORITY_TABLES) if (!sourceTables.has(table) &&
        connection.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get() !== undefined)
      mismatch('owned import requires every one of the eighteen business tables empty');
    const originalRows = (table: PreparedImportTable) => {
      // Fixed read-only eponymous pragma table is valid inside the genuine
      // original snapshot. Its connection-settings guard remains unchanged;
      // the separate original candidate authorizer keeps its known PRAGMA path.
      const columns = connection.prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid')
        .all<{ name: string }>(table).map(row => row.name);
      return Object.freeze(connection.prepare(losslessQuery(table, columns)).all<SqliteRow>().map(row => losslessRow(row, columns))); };
    const canonicalTimeFence = originalRows('canonical_time_fence');
    const stateOwners = originalRows('state_owners');
    for (const row of stateOwners) if (!readStateOwner(connection, requiredSafeInteger(row.owner_epoch, 'candidate original owner epoch')))
      mismatch('candidate original owner history is incomplete');
    const artifacts = originalRows('artifacts');
    if (canonicalTimeFence.length !== 1 || stateOwners.length < 1) mismatch('import baseline lacks the complete original owner/fence');
    const digest = canonicalSha256({ canonicalTimeFence: canonicalTimeFence.map(encodedRow),
      stateOwners: stateOwners.map(encodedRow), artifacts: artifacts.map(encodedRow) });
    return Object.freeze({ canonicalTimeFence, stateOwners, artifacts, digest });
  });
}
/** Final original-connection friend. No nested transaction or caller SQL is
 * accepted; every original source-cut row and every empty family is rechecked. */
export function assertPreparedImportSourceSqlCut(driver: SqliteDriver, connection: SqliteConnection,
  baseline: PreparedImportBaseline, signedSchema: SignedKernelSchemaV1): void {
  assertSqliteConnectionOwnedBy(driver, connection);
  // The owning caller already obtained the exact fixed schema through its
  // actual signed installed reader. Recompare that complete catalog here;
  // do not construct another SQLite connection inside the live transaction.
  if (connection.prepare('SELECT user_version FROM pragma_user_version').get<{ user_version: bigint }>()?.user_version !== 8n ||
      connection.prepare('SELECT application_id FROM pragma_application_id').get<{ application_id: bigint }>()?.application_id !== BigInt(signedSchema.applicationId) ||
      canonicalSha256(connection.prepare('SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name').all()) !== signedSchema.catalogDigest)
    mismatch('final owned import source schema differs from its exact verified signed catalog');
  const groups = { canonical_time_fence: baseline.canonicalTimeFence, state_owners: baseline.stateOwners,
    artifacts: baseline.artifacts };
  for (const table of KERNEL_AUTHORITY_TABLES) {
    if (!sourceTables.has(table)) {
      if (connection.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get() !== undefined)
        mismatch('final owned import source SQL cut has a populated business family');
      continue;
    }
    const columns = connection.prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid')
      .all<{ name: string }>(table).map(row => row.name);
    const expected = groups[table as keyof typeof groups]; let index = 0;
    for (const raw of connection.prepare(losslessQuery(table, columns)).iterate<SqliteRow>()) {
      const row = losslessRow(raw, columns), prior = expected[index++];
      if (!prior || canonicalSha256(encodedRow(row)) !== canonicalSha256(encodedRow(prior)))
        mismatch('final owned import source SQL cut changed an original complete row');
    }
    if (index !== expected.length) mismatch('final owned import source SQL cut omitted an original complete row');
  }
}
function assertCompleteIntegrity(connection: SqliteConnection): void {
  const integrity = connection.prepare('PRAGMA integrity_check').iterate<SqliteRow>();
  let rows = 0;
  for (const row of integrity) { rows++; if (Object.keys(row).length !== 1 || Object.values(row)[0] !== 'ok')
    mismatch('candidate full integrity_check failed'); }
  if (rows !== 1 || connection.prepare('PRAGMA foreign_key_check').get() !== undefined)
    mismatch('candidate full integrity or foreign-key validation failed');
}
function candidateRows(baseline: PreparedImportBaseline, imported: PreparedLegacyImportRows) {
  const original = new Map(baseline.artifacts.map(row => [row.ref, row]));
  const artifacts = [...baseline.artifacts];
  for (const row of imported.artifacts) {
    const existing = original.get(row.ref);
    // Match original insertArtifactMetadata: the first declaration survives
    // different later typed uses. A ref identifies complete bytes, not a kind
    // or permission; each actual use still needs its own strict CAS decoder.
    if (existing && existing.byte_length !== row.byte_length)
      mismatch('candidate artifact bytes cannot have two different lengths');
    if (!existing) { original.set(row.ref, row); artifacts.push(row); }
  }
  return { canonical_time_fence: baseline.canonicalTimeFence, state_owners: baseline.stateOwners,
    artifacts, sessions: imported.sessions, items: imported.items };
}
/** Whole fixed preview, including every empty nonimported family. Neither a
 * first-page match nor a schema label can hide extra candidate business rows. */
export function assertPreparedImportPreview(projection: PreparedImportProjection, baseline: PreparedImportBaseline,
  imported: PreparedLegacyImportRows): void {
  projection.assertHeld(); assertPreparedImportRowSet(table => projection.rows(table), baseline, imported); projection.assertHeld();
}
/** Pure complete-row comparison, with no filesystem/native/SQL authority. */
export function assertPreparedImportRowSet(readRows: (table: PreparedImportTable) => Iterable<PreparedImportRow>,
  baseline: PreparedImportBaseline, imported: PreparedLegacyImportRows): void {
  const expected = candidateRows(baseline, imported);
  for (const table of KERNEL_AUTHORITY_TABLES) {
    const expectedRows: readonly PreparedImportRow[] = Object.hasOwn(expected, table) ? expected[table as keyof typeof expected] : [];
    const unmatched = new Map<string, number>();
    for (const row of expectedRows) { const digest = canonicalSha256(encodedRow(row)); unmatched.set(digest, (unmatched.get(digest) ?? 0) + 1); }
    for (const row of readRows(table)) {
      const digest = canonicalSha256(encodedRow(row)), count = unmatched.get(digest);
      if (!count) mismatch('candidate complete projection has an extra or changed row');
      if (count === 1) unmatched.delete(digest); else unmatched.set(digest, count - 1);
    }
    if (unmatched.size) mismatch('candidate complete projection omitted an original or imported row');
  }
}
/** Streaming stage guard: every fixed family is independently traversed after
 * seal. Actual per-batch readback supplied exact values; this catches missing
 * or extra rows without retaining the whole imported history in memory. */
export function assertPreparedImportStageCounts(projection: PreparedImportProjection, baseline: PreparedImportBaseline,
  staged: PreparedImportWriterSummary): void {
  const expected = { canonical_time_fence: baseline.canonicalTimeFence.length, state_owners: baseline.stateOwners.length,
    artifacts: baseline.artifacts.length + staged.newArtifacts, sessions: staged.sessions, items: staged.items };
  for (const table of KERNEL_AUTHORITY_TABLES) {
    let actual = 0;
    for (const _row of projection.rows(table)) { if (!Number.isSafeInteger(++actual)) mismatch('candidate row count exceeded exact range'); }
    if (actual !== (Object.hasOwn(expected, table) ? expected[table as keyof typeof expected] : 0))
      mismatch('candidate whole sealed projection differs from its original baseline and complete typed stage');
  }
  projection.assertHeld();
}
/** Fixed baseline only. The eighteen original business tables were verified
 * empty under the original source driver's real synchronous snapshot. */
export function initializePreparedImportPreview(driver: SqliteDriver, signedSchema: SignedKernelSchemaV1,
  baseline: PreparedImportBaseline): void {
  decodeSignedKernelSchema(signedSchema); assertSqliteConnectionOwnedBy(driver, driver);
  if (canonicalSha256({ canonicalTimeFence: baseline.canonicalTimeFence.map(encodedRow),
      stateOwners: baseline.stateOwners.map(encodedRow), artifacts: baseline.artifacts.map(encodedRow) }) !== baseline.digest)
    mismatch('candidate baseline complete original bytes changed');
  if (driver.prepare('SELECT name FROM sqlite_schema LIMIT 1').get() !== undefined)
    mismatch('candidate SQL producer requires its newly-created empty image');
  applyKernelSchema(driver);
  const groups = candidateRows(baseline, { sessions: [], items: [], artifacts: [] });
  driver.transaction(connection => {
    for (const table of KERNEL_AUTHORITY_TABLES) {
      if (!sourceTables.has(table) && !importedTables.has(table)) continue;
      const columns = columnsFor(connection, table);
      const insert = connection.prepare(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})`);
      for (const input of groups[table as keyof typeof groups]) {
        const row = rowSnapshot(input as SqliteRow);
        if (Object.keys(row).length !== columns.length || columns.some(column => !Object.hasOwn(row, column)))
          mismatch('candidate requires every exact signed-schema column, without injected or omitted fields');
        insert.run(...columns.map(column => row[column] as SqliteInputValue));
      }
    }
  });
  assertKernelSchemaVersion(driver, 8);
}
/** One bounded non-authoritative stage batch. No arbitrary table/SQL callback;
 * original metadata declarations survive later typed uses of identical bytes.
 * No completed-source or authority claim is made by a successful append. */
export function appendPreparedImportRows(driver: SqliteDriver, batch: PreparedLegacyImportRows): PreparedImportAppendCounts {
  assertSqliteConnectionOwnedBy(driver, driver);
  if (batch.sessions.length + batch.items.length + batch.artifacts.length > 256)
    throw new TypeError('candidate stage batches contain at most 256 fixed rows');
  return driver.transaction(connection => {
    const counts = { sessions: 0, items: 0, newArtifacts: 0 };
    for (const table of ['artifacts', 'sessions', 'items'] as const) {
      const columns = columnsFor(connection, table), primary = table === 'items' ? 'item_id' : table === 'artifacts' ? 'ref' : 'id';
      const insert = connection.prepare(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})${table === 'artifacts' ? ' ON CONFLICT(ref) DO NOTHING' : ''}`);
      const readback = connection.prepare(losslessQuery(table, columns, primary));
      for (const original of batch[table]) {
        const row = rowSnapshot(original);
        if (Object.keys(row).length !== columns.length || columns.some(column => !Object.hasOwn(row, column)))
          mismatch('candidate stage requires every fixed signed-schema column');
        if (table === 'items' && (row.run_id !== null || typeof row.session_id !== 'string' || !legacyKinds.has(String(row.kind))))
          mismatch('candidate imports only the five context-only Legacy item kinds');
        const inserted = insert.run(...columns.map(column => row[column] as SqliteInputValue));
        const raw = readback.get<SqliteRow>(row[primary]!);
        if (!raw) mismatch('candidate stage lacks its actual inserted/read-back row');
        const actual = losslessRow(raw, columns);
        if (table === 'artifacts' && inserted.changes === 0n) {
          if (actual.byte_length !== row.byte_length) mismatch('candidate reused artifact content has a different length');
        } else if (inserted.changes !== 1n || canonicalSha256(encodedRow(row)) !== canonicalSha256(encodedRow(actual)))
          mismatch('candidate stage did not preserve the entire exact original row');
        if (table === 'artifacts') counts.newArtifacts += Number(inserted.changes);
        else counts[table]++;
      }
    }
    return Object.freeze(counts);
  });
}
export function finishPreparedImportPreview(driver: SqliteDriver): void {
  assertSqliteConnectionOwnedBy(driver, driver); assertKernelSchemaVersion(driver, 8); assertCompleteIntegrity(driver);
  for (const table of KERNEL_AUTHORITY_TABLES) if (!sourceTables.has(table) && !importedTables.has(table) &&
      driver.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get() !== undefined)
    mismatch('candidate staging may not populate execution or final-response audit-tail families');
}
/** Fixed data cursor for streaming initial ContextProjection construction.
 * Materialize at most 64 exact scalar rows and finish the statement before
 * the caller can await. This is not an execution/source authority or SQL seam. */
export function readPreparedImportSessionItemsPage(driver: SqliteDriver, sessionId: string,
  afterItemSeq: bigint): readonly PreparedLegacyItemRow[] {
  assertSqliteConnectionOwnedBy(driver, driver);
  if (typeof sessionId !== 'string' || !sessionId || afterItemSeq < 0n)
    throw new TypeError('candidate context cursor requires its Session id and original nonnegative item cursor');
  const columns = ['item_id', 'session_id', 'run_id', 'item_seq', 'kind', 'payload_ref', 'created_at'];
  const select = `${columns.join(',')},${columns.map((column, index) => `CAST(${column} AS BLOB) AS __cliq_raw_${index}`).join(',')}`;
  const rows = driver.prepare(`SELECT ${select} FROM items WHERE session_id=? AND run_id IS NULL AND item_seq>?
    ORDER BY item_seq LIMIT 64`).all<SqliteRow>(sessionId, afterItemSeq);
  let next = afterItemSeq;
  return Object.freeze(rows.map(raw => {
    const row = losslessRow(raw, columns);
    if (row.session_id !== sessionId || row.run_id !== null || row.item_seq !== next + 1n ||
        !legacyKinds.has(String(row.kind))) mismatch('candidate Session context items are not a complete contiguous Legacy prefix');
    next = row.item_seq as bigint;
    return row as PreparedLegacyItemRow;
  }));
}

/** The real candidate's existing Session rows hold the bounded import header.
 * No parallel metadata ledger or one-JS-object-per-Session inventory is needed.
 * This fixed cursor is complete before an asynchronous caller receives a row. */
export function readPreparedImportSessionsPage(driver: SqliteDriver, afterId: string): readonly PreparedLegacySessionRow[] {
  assertSqliteConnectionOwnedBy(driver, driver);
  if (typeof afterId !== 'string') throw new TypeError('candidate Session cursor requires its original scalar id');
  const columns = columnsFor(driver, 'sessions');
  const select = `${columns.join(',')},${columns.map((column, index) => `CAST(${column} AS BLOB) AS __cliq_raw_${index}`).join(',')}`;
  return Object.freeze(driver.prepare(`SELECT ${select} FROM sessions WHERE id>? COLLATE BINARY ORDER BY id COLLATE BINARY LIMIT 64`)
    .all<SqliteRow>(afterId).map(row => losslessRow(row, columns) as PreparedLegacySessionRow));
}

/** Lookup is data-only and fixed to the existing preview. It never supplies a
 * caller-selected SQL statement, path, connection or authority-producing row. */
export function readPreparedImportSessionHeader(driver: SqliteDriver, sessionId: string): PreparedLegacySessionRow | undefined {
  assertSqliteConnectionOwnedBy(driver, driver);
  return preparedImportSessionHeader(driver, sessionId);
}
function preparedImportSessionHeader(connection: SqliteConnection, sessionId: string): PreparedLegacySessionRow | undefined {
  const columns = columnsFor(connection, 'sessions');
  const raw = connection.prepare(losslessQuery('sessions', columns, 'id')).get<SqliteRow>(sessionId);
  return raw === undefined ? undefined : losslessRow(raw, columns) as PreparedLegacySessionRow;
}
export function readPreparedImportSessionItemTail(driver: SqliteDriver, sessionId: string): bigint {
  assertSqliteConnectionOwnedBy(driver, driver);
  return preparedImportSessionItemTail(driver, sessionId);
}
function preparedImportSessionItemTail(connection: SqliteConnection, sessionId: string): bigint {
  const row = connection.prepare('SELECT item_seq FROM items WHERE session_id=? AND run_id IS NULL ORDER BY item_seq DESC LIMIT 1')
    .get<{ item_seq: bigint }>(sessionId);
  return row?.item_seq ?? 0n;
}

/** Only the non-authoritative preview's initial empty root is replaced. The
 * original captured empty root, complete source cursor and all scalar header
 * values remain predicates; live Kernel Sessions never call this function. */
export function finalizePreparedImportSession(driver: SqliteDriver, original: PreparedLegacySessionRow,
  input: Readonly<{ contextProjectionRef: string; throughItemSeq: bigint }>): void {
  assertSqliteConnectionOwnedBy(driver, driver);
  if (original.context_revision !== 1n || original.latest_item_seq !== 0n || input.throughItemSeq < 0n ||
      !/^[0-9a-f]{64}$/u.test(input.contextProjectionRef)) return mismatch('candidate Session finalization requires its exact initial preview');
  driver.transaction(connection => {
    assertSqliteConnectionOwnedBy(driver, connection);
    const actual = preparedImportSessionHeader(connection, original.id);
    if (!actual || canonicalSha256(encodedRow(actual)) !== canonicalSha256(encodedRow(original)) ||
        preparedImportSessionItemTail(connection, original.id) !== input.throughItemSeq)
      mismatch('candidate Session header or complete item tail changed before finalization');
    const update = connection.prepare('UPDATE sessions SET latest_item_seq=?,context_projection_ref=? WHERE id=? AND context_revision=1 AND latest_item_seq=0 AND context_projection_ref=?')
      .run(input.throughItemSeq, input.contextProjectionRef, original.id, original.context_projection_ref);
    if (update.changes !== 1n) mismatch('candidate Session finalization did not update its original row');
    const expected = { ...original, latest_item_seq: input.throughItemSeq, context_projection_ref: input.contextProjectionRef };
    const retained = preparedImportSessionHeader(connection, original.id);
    if (!retained || canonicalSha256(encodedRow(retained)) !== canonicalSha256(encodedRow(expected)))
      mismatch('candidate Session finalization changed fields outside its fixed context projection');
  });
}

/** Stable across batch partitioning. Pure data digest only, not source EOF,
 * parent custody or permission. Its original source manifest supplies those. */
export function updatePreparedImportInputDigests(hashes: Readonly<Record<'artifacts' | 'sessions' | 'items', ReturnType<typeof createHash>>>,
  batch: PreparedLegacyImportRows): void {
  for (const table of ['artifacts', 'sessions', 'items'] as const)
    for (const row of batch[table]) hashes[table].update(canonicalJsonBytes(encodedRow(rowSnapshot(row)))).update('\n');
}

export type PreparedImportProjection = Readonly<{
  image: PreparedImportImageObservation;
  rows(table: PreparedImportTable): IterableIterator<PreparedImportRow>;
  /** Fixed preview-only lookups. No caller SQL, path, FD or driver escapes. */
  session(id: string): PreparedLegacySessionRow | undefined;
  sessionItems(id: string): IterableIterator<PreparedImportRow>;
  artifact(ref: string): PreparedImportArtifactRow | undefined;
  digest(): string;
  assertHeld(): void;
}>;
/** Pure fixed SQLite policy; it supplies no handle, connection or authority. */
export function preparedImportReadonlyAuthorizer(action: number, first: string | null, second: string | null,
  database: string | null, cause: string | null): number {
  if (cause !== null) return sqlite.SQLITE_DENY;
  if (action === sqlite.SQLITE_SELECT) return sqlite.SQLITE_OK;
  if (action === sqlite.SQLITE_READ && database === 'main') return sqlite.SQLITE_OK;
  if (action === sqlite.SQLITE_PRAGMA && second === null &&
      ['application_id', 'user_version', 'integrity_check', 'foreign_key_check'].includes(first ?? '')) return sqlite.SQLITE_OK;
  if (action === sqlite.SQLITE_PRAGMA && first === 'table_info' && KERNEL_AUTHORITY_TABLES.includes(second as PreparedImportTable))
    return sqlite.SQLITE_OK;
  return sqlite.SQLITE_DENY;
}
/** Internal fixed signed installed role only. Node >=22.13 clients retain
 * their existing contract; no weak Node22 reader fallback is supplied. */
export async function withPreparedImportProjection<T>(native: NativeStateOwner, input: Readonly<{
  image: FileHandle; filesystem: HeldMigrationFilesystem; schema: SignedKernelSchemaV1; signal?: AbortSignal;
}>, operation: (projection: PreparedImportProjection) => T | Promise<T>): Promise<T> {
  if (process.platform !== 'linux' || process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'prepared import requires its fixed signed installed Node 24.21.0 role');
  decodeSignedKernelSchema(input.schema);
  await assertHeldCredentialNativeImage(native, input.image); input.signal?.throwIfAborted();
  const held = openHeldPreparedImportCandidate(native, input.filesystem);
  let database: DatabaseSync | undefined, begun = false, active = false, failed = false, failure: unknown, result!: T;
  const iterators = new Set<IterableIterator<PreparedImportRow>>();
  const current = () => { if (!active) mismatch('prepared candidate projection scope has ended');
    input.signal?.throwIfAborted(); held.assertHeld(); };
  const verify = async () => { for (;;) { input.signal?.throwIfAborted(); if (held.verifyNext()) return; await setImmediate(); } };
  try {
    await verify(); held.beginRead(); begun = true;
    const bootstrap = new DatabaseSync(':memory:', { allowExtension: true });
    try {
      await assertHeldCredentialNativeImage(native, input.image);
      (bootstrap.loadExtension as (image: string, entry: string) => void).call(bootstrap,
        `/proc/self/fd/${input.image.fd}`, 'sqlite3_cliqownedimportpreview_init');
      bootstrap.enableLoadExtension(false);
    } finally { try { bootstrap.close(); } catch (error) { unretiredPreparedImportConnections.add(bootstrap);
      throw new ResourceRetirementError('candidate SQLite bootstrap did not retire', error); } }
    database = new DatabaseSync('file:cliq-owned-import-preview?vfs=cliq-owned-import-preview-v1&mode=ro&immutable=1',
      { readOnly: true, allowExtension: false, enableDoubleQuotedStringLiterals: false, enableForeignKeyConstraints: true });
    database.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA query_only=ON; PRAGMA trusted_schema=OFF');
    database.enableDefensive(true); database.setAuthorizer(preparedImportReadonlyAuthorizer);
    const original = database;
    // Fixed validators consume this private adapter; it never leaves the module.
    const validation: SqliteConnection = {
      exec() { throw new TypeError('candidate validators cannot execute mutation SQL'); },
      prepare(sql): SqliteStatement {
        const statement = original.prepare(sql); statement.setReadBigInts(true);
        return { run(): SqliteRunResult { throw new TypeError('candidate validator is read-only'); },
          get: (...parameters) => statement.get(...parameters) as never,
          all: (...parameters) => statement.all(...parameters) as never,
          iterate: (...parameters) => iterateNodeSqliteStatement(statement, ...parameters) as never };
      }
    };
    assertKernelSchemaVersion(validation, 8); assertCompleteIntegrity(validation);
    const columns = new Map(KERNEL_AUTHORITY_TABLES.map(table => [table, columnsFor(validation, table)]));
    active = true;
    const cursor = (table: PreparedImportTable, query: string, parameters: readonly SqliteInputValue[] = []): IterableIterator<PreparedImportRow> => {
      current();
      const originalColumns = columns.get(table)!;
      const statement = original.prepare(query); statement.setReadBigInts(true);
      // A construction failure has no registered iterator to retire. Once
      // assigned, the original generator remains strongly tracked until its
      // actual finally runs; closing it still joins the nested native iterator.
      let iterator: IterableIterator<PreparedImportRow> | undefined = undefined;
      iterator = (function* () {
        try { current(); for (const row of iterateNodeSqliteStatement(statement, ...parameters)) { current(); yield losslessRow(row, originalColumns); } current(); }
        finally { if (iterator !== undefined) iterators.delete(iterator); }
      })();
      iterators.add(iterator); return iterator;
    };
    const rows = (table: PreparedImportTable): IterableIterator<PreparedImportRow> => {
      current(); if (!Object.hasOwn(order, table)) throw new TypeError('unsupported prepared candidate projection family');
      return cursor(table, losslessQuery(table, columns.get(table)!));
    };
    const lookup = (table: 'sessions' | 'artifacts', primary: 'id' | 'ref', value: string): PreparedImportRow | undefined => {
      current(); if (typeof value !== 'string') throw new TypeError('candidate lookup requires its scalar fixed key');
      const iterator = cursor(table, losslessQuery(table, columns.get(table)!, primary), [value]);
      try { const found = iterator.next(); return found.done ? undefined : found.value; }
      finally { iterator.return?.(); }
    };
    const projection: PreparedImportProjection = Object.freeze({ image: held.identity(), rows, assertHeld: current,
      session(id: string) { return lookup('sessions', 'id', id) as PreparedLegacySessionRow | undefined; },
      artifact(ref: string) { return lookup('artifacts', 'ref', ref) as PreparedImportArtifactRow | undefined; },
      sessionItems(id: string) {
        current(); if (typeof id !== 'string') throw new TypeError('candidate Session cursor requires its scalar id');
        const selected = columns.get('items')!;
        return cursor('items', `SELECT ${selected.join(',')},${selected.map((column, index) =>
          `CAST(${column} AS BLOB) AS __cliq_raw_${index}`).join(',')} FROM items WHERE session_id=? ORDER BY item_seq`, [id]);
      },
      digest() {
        current(); const hash = createHash('sha256').update('cliq-owned-import-preview-projection-v1\n');
        for (const table of KERNEL_AUTHORITY_TABLES) { hash.update(canonicalJsonBytes(table)).update('\n');
          for (const row of rows(table)) hash.update(canonicalJsonBytes(encodedRow(row))).update('\n'); }
        return hash.digest('hex');
      } });
    result = await operation(projection);
  } catch (error) { failed = true; failure = error; }
  active = false;
  // Return every actual active iterator before asking SQLite/native to close.
  try { for (const iterator of [...iterators]) { iterator.return?.(); iterators.delete(iterator); } }
  catch (error) { if (database) unretiredPreparedImportConnections.add(database);
    throw new ResourceRetirementError('candidate projection iterator did not join', error); }
  if (failure instanceof ResourceRetirementError) { if (database) unretiredPreparedImportConnections.add(database); throw failure; }
  try { database?.close(); }
  catch (error) { if (database) unretiredPreparedImportConnections.add(database);
    throw new ResourceRetirementError('candidate SQLite connection did not actually close', error); }
  try { if (begun) held.endRead(); }
  catch (error) { throw new ResourceRetirementError('prepared candidate SQLite lease did not join', error); }
  // Cancellation after SQL close still joins the genuine parent borrow. It
  // returns no qualified result and does not pretend the closing hash finished.
  if (!failed) try { await verify(); } catch (error) { failed = true; failure = error; }
  try { held.close(); }
  catch (error) { throw new ResourceRetirementError('prepared candidate custody did not retire',
    new AggregateError(failed ? [failure, error] : [error])); }
  if (failed) throw failure;
  return result;
}

