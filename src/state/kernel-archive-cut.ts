// Complete scalar cuts of the actual original database and its fixed archive.
// The digest is audit data. It grants no drain, Owner or resource authority.
import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { controlWireInteger, controlWireRecord, controlWireRef, assertControlWireJson } from '../kernel/control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KERNEL_AUTHORITY_TABLES } from './schema.js';
import { KernelStorageError } from './errors.js';
import type { KernelArchiveProjection } from './kernel-archive.js';
import { assertHeldKernelArchive, type HeldKernelArchive } from './native-owner.js';
import { assertOriginalKernelArchiveSource, type SqliteDriver, type SqliteRow } from './sqlite-driver.js';
import type { PreparedImportRow, PreparedImportTable } from './prepared-import-candidate.js';

export const KERNEL_ARCHIVE_SQL_ORDER: Readonly<Record<PreparedImportTable, string>> = Object.freeze({
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
});
export type KernelArchiveSqlCut = Readonly<{ schemaVersion: 1; format: 'cliq-kernel-archive-productive-cut-v1';
  stateSchemaVersion: 8; excludedTable: 'canonical_time_fence';
  tables: readonly Readonly<{ table: PreparedImportTable; rowCount: number; rowsDigest: string }>[]; cutDigest: string }>;
const PRODUCTIVE = KERNEL_AUTHORITY_TABLES.filter(table => table !== 'canonical_time_fence');
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'archive productive SQL cut is incomplete or changed'); }

/** All twenty productive/audit families, including every original owner row.
 * Only the sole canonical fence may advance during the online copy. */
export function decodeKernelArchiveSqlCut(value: unknown): KernelArchiveSqlCut {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'stateSchemaVersion', 'excludedTable', 'tables', 'cutDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-kernel-archive-productive-cut-v1' || data.stateSchemaVersion !== 8 ||
      data.excludedTable !== 'canonical_time_fence' || !Array.isArray(data.tables) || data.tables.length !== PRODUCTIVE.length) invalid();
  for (const [index, value] of data.tables.entries()) {
    const row = controlWireRecord(value, ['table', 'rowCount', 'rowsDigest']);
    if (row.table !== PRODUCTIVE[index]) invalid(); controlWireInteger(row.rowCount); controlWireRef(row.rowsDigest);
  }
  controlWireRef(data.cutDigest);
  const { cutDigest: _, ...core } = data;
  if (canonicalSha256(core) !== data.cutDigest) invalid();
  return immutableSnapshot(data) as KernelArchiveSqlCut;
}
export function assertSameKernelArchiveSqlCut(expected: KernelArchiveSqlCut, actual: KernelArchiveSqlCut): void {
  if (canonicalSha256(decodeKernelArchiveSqlCut(expected)) !== canonicalSha256(decodeKernelArchiveSqlCut(actual))) invalid();
}
function encodeRow(row: PreparedImportRow): Buffer {
  return canonicalJsonBytes(Object.keys(row).sort().map(key => [key,
    typeof row[key] === 'bigint' ? { integer: row[key]!.toString() } : row[key]]));
}
async function cut(rows: (table: PreparedImportTable) => AsyncIterable<PreparedImportRow>, signal?: AbortSignal): Promise<KernelArchiveSqlCut> {
  const tables: { table: PreparedImportTable; rowCount: number; rowsDigest: string }[] = [];
  for (const table of PRODUCTIVE) {
    signal?.throwIfAborted(); let rowCount = 0;
    const hash = createHash('sha256').update('cliq-kernel-archive-table-v1\n').update(table).update('\n');
    for await (const row of rows(table)) {
      signal?.throwIfAborted(); if (!Number.isSafeInteger(++rowCount)) invalid();
      hash.update(encodeRow(row)).update('\n');
    }
    tables.push({ table, rowCount, rowsDigest: hash.digest('hex') });
  }
  const core = { schemaVersion: 1 as const, format: 'cliq-kernel-archive-productive-cut-v1' as const,
    stateSchemaVersion: 8 as const, excludedTable: 'canonical_time_fence' as const, tables };
  return decodeKernelArchiveSqlCut({ ...core, cutDigest: canonicalSha256(core) });
}
export function readArchivedKernelProductiveCut(projection: KernelArchiveProjection, signal?: AbortSignal): Promise<KernelArchiveSqlCut> {
  projection.assertHeld(); return cut(table => projection.rows(table), signal);
}

/** Genuine source registry and original archive issuer are checked before
 * each actual query and after every yield. No source connection escapes. */
export function readOriginalKernelProductiveCut(driver: SqliteDriver, scope: HeldKernelArchive,
  signal?: AbortSignal): Promise<KernelArchiveSqlCut> {
  const current = () => { signal?.throwIfAborted(); assertOriginalKernelArchiveSource(driver, scope); assertHeldKernelArchive(scope); };
  current();
  const rows = async function* (table: PreparedImportTable): AsyncIterableIterator<PreparedImportRow> {
    current();
    const columns = driver.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>().map(row => row.name);
    if (!columns.length) invalid();
    // The exact schema has already been selected by the original installed
    // holder. Check scalars in SQLite before allocating their Node values.
    const bad = columns.map(column => `(typeof(${column}) NOT IN ('text','integer','null') OR
      (typeof(${column})='text' AND length(CAST(${column} AS BLOB))>1048576))`).join(' OR ');
    if (driver.prepare(`SELECT 1 FROM ${table} WHERE ${bad} LIMIT 1`).get() !== undefined) invalid();
    const iterator = driver.prepare(`SELECT ${columns.join(',')},${columns.map((column, index) =>
      `CAST(${column} AS BLOB) AS __cliq_raw_${index}`).join(',')} FROM ${table} ORDER BY ${KERNEL_ARCHIVE_SQL_ORDER[table]}`).iterate<SqliteRow>();
    let count = 0;
    try {
      for (const raw of iterator) {
        current(); const row: Record<string, string | bigint | null> = Object.create(null);
        for (const [index, column] of columns.entries()) {
          const value = raw[column], bytes = raw[`__cliq_raw_${index}`];
          if (value === null ? bytes !== null : (typeof value !== 'string' && typeof value !== 'bigint') ||
              !(bytes instanceof Uint8Array) || bytes.byteLength > 1_048_576 || !Buffer.from(value.toString(), 'utf8').equals(bytes)) invalid();
          row[column] = value as string | bigint | null;
        }
        yield Object.freeze(row);
        if (++count % 64 === 0) { await setImmediate(); current(); }
      }
      current();
    } finally { iterator.return?.(); }
  };
  return cut(rows, signal);
}
