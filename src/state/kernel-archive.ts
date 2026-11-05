// The archived connection is a closed snapshot, never a replacement for the
// live driver. This fixed reader exposes only the original 21 authority tables
// with lossless scalar data, complete original-FD validation and joined close.
import { createHash } from 'node:crypto';
import type { FileHandle } from 'node:fs/promises';
import type { KernelRollbackDrainingControlV1 } from '../kernel/kernel-archive-data.js';
import { DatabaseSync } from 'node:sqlite';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SignedKernelSchemaV1 } from '../kernel/runtime-upgrade.js';
import { decodeSignedKernelSchema } from './signed-schema.js';
import { assertKernelSchemaVersion, KERNEL_AUTHORITY_TABLES } from './schema.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { beginHeldKernelArchiveRead, endHeldKernelArchiveRead, sealHeldKernelArchive,
  assertHeldKernelArchive, describeHeldKernelArchiveBirth,
  createHeldKernelArchive, type NativeStateOwner, type HeldMigrationCredentialGate,
  type HeldKernelArchive, type KernelArchiveBirthObservation, type KernelArchiveImageObservation } from './native-owner.js';
import { backupOriginalSqliteToKernelArchive, iterateNodeSqliteStatement,
  type SqliteDriver, type SqliteConnection, type SqliteRow, type SqliteStatement, type SqliteRunResult } from './sqlite-driver.js';
import { preparedImportReadonlyAuthorizer, type PreparedImportTable, type PreparedImportRow } from './prepared-import-candidate.js';
import { KERNEL_ARCHIVE_SQL_ORDER as TABLE_ORDER, readOriginalKernelProductiveCut, readArchivedKernelProductiveCut,
  assertSameKernelArchiveSqlCut } from './kernel-archive-cut.js';
import { captureHeldKernelArchiveCas, sealHeldKernelArchiveManifest, type KernelArchiveManifestObservation } from './native-owner.js';
import { encodeCompleteKernelArchiveManifest, type CompleteKernelArchiveManifest, type CompleteKernelArchiveHeader } from './kernel-archive-manifest.js';

const unretiredArchiveReaders = new Set<Readonly<{ database: DatabaseSync; scope: HeldKernelArchive }>>();
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function rowData(row: SqliteRow, columns: readonly string[]): PreparedImportRow {
  const result: Record<string, string | bigint | null> = Object.create(null);
  for (const [index, column] of columns.entries()) {
    const value = row[column], bytes = row[`__cliq_raw_${index}`];
    if (value === null ? bytes !== null : (typeof value !== 'string' && typeof value !== 'bigint') ||
        !(bytes instanceof Uint8Array) || bytes.byteLength > 1_048_576 || !Buffer.from(value.toString(), 'utf8').equals(bytes))
      invalid('archive SQL values cannot be decoded as exact bounded original scalars');
    result[column] = value as string | bigint | null;
  }
  return Object.freeze(result);
}
export type KernelArchiveProjection = Readonly<{
  birth: KernelArchiveBirthObservation; image: KernelArchiveImageObservation;
  rows(table: PreparedImportTable): AsyncIterableIterator<PreparedImportRow>;
  digest(): Promise<string>;
  assertHeld(): void;
}>;

/** One actual original-source online backup and full physical seal precedes
 * the readonly scope. Caller cannot select a source connection, SQL, URI,
 * path, VFS or validation policy. It must separately close the scope's complete
 * typed roots/CAS namespace and publish the final archive manifest. */
export async function withKernelArchiveProjection<T>(driver: SqliteDriver, scope: HeldKernelArchive,
  schema: SignedKernelSchemaV1, operation: (projection: KernelArchiveProjection) => Promise<T>, signal?: AbortSignal):
  Promise<Readonly<{ value: T; birth: KernelArchiveBirthObservation; image: KernelArchiveImageObservation }>> {
  decodeSignedKernelSchema(schema); assertHeldKernelArchive(scope); signal?.throwIfAborted();
  const birth = describeHeldKernelArchiveBirth(scope);
  await backupOriginalSqliteToKernelArchive(driver, scope, signal);
  const image = await sealHeldKernelArchive(scope, signal);
  let database: DatabaseSync | undefined, begun = false, active = false, failed = false, failure: unknown, result!: T;
  const iterators = new Set<AsyncIterableIterator<PreparedImportRow>>();
  const current = () => {
    if (!active) invalid('archive readonly projection has ended'); signal?.throwIfAborted(); assertHeldKernelArchive(scope);
  };
  try {
    const uri = beginHeldKernelArchiveRead(scope); begun = true;
    database = new DatabaseSync(uri, { readOnly: true, allowExtension: false,
      enableDoubleQuotedStringLiterals: false, enableForeignKeyConstraints: true });
    database.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA query_only=ON; PRAGMA trusted_schema=OFF');
    database.enableDefensive(true); database.setAuthorizer(preparedImportReadonlyAuthorizer);
    const original = database;
    const validation: SqliteConnection = { exec() { throw new TypeError('archive validators cannot execute mutation SQL'); },
      prepare(sql): SqliteStatement {
        const statement = original.prepare(sql); statement.setReadBigInts(true);
        return { run(): SqliteRunResult { throw new TypeError('archive validators are read-only'); },
          get: (...parameters) => statement.get(...parameters) as never,
          all: (...parameters) => statement.all(...parameters) as never,
          iterate: (...parameters) => iterateNodeSqliteStatement(statement, ...parameters) as never };
      }
    };
    assertKernelSchemaVersion(validation, 8);
    if (validation.prepare('PRAGMA application_id').get<{ application_id: bigint }>()?.application_id !== BigInt(schema.applicationId) ||
        canonicalSha256(validation.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').all()) !== schema.catalogDigest)
      invalid('archive SQL catalog differs from its exact original signed schema');
    let checks = 0;
    for (const row of validation.prepare('PRAGMA integrity_check').iterate<SqliteRow>()) {
      signal?.throwIfAborted(); if (++checks !== 1 || Object.keys(row).length !== 1 || Object.values(row)[0] !== 'ok')
        invalid('archived database full integrity check failed');
    }
    if (checks !== 1 || validation.prepare('PRAGMA foreign_key_check').get() !== undefined)
      invalid('archive complete integrity/foreign-key checks failed');
    const columns = new Map(KERNEL_AUTHORITY_TABLES.map(table => [table,
      validation.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>().map(row => row.name)]));
    active = true;
    const rows = (table: PreparedImportTable): AsyncIterableIterator<PreparedImportRow> => {
      current(); if (!Object.hasOwn(TABLE_ORDER, table)) throw new TypeError('unsupported archive SQL family');
      const selected = columns.get(table)!;
      // Reject oversized or unsupported scalar types in SQLite before a Node
      // step could allocate a giant field. This is a fixed supported profile,
      // not proof that a small file implies a bounded parsed object.
      const bad = selected.map(column => `(typeof(${column}) NOT IN ('text','integer','null') OR
        (typeof(${column})='text' AND length(CAST(${column} AS BLOB))>1048576))`).join(' OR ');
      if (!selected.length || validation.prepare(`SELECT 1 FROM ${table} WHERE ${bad} LIMIT 1`).get() !== undefined)
        invalid('archive table has an unsupported or oversized scalar');
      const statement = original.prepare(`SELECT ${selected.join(',')},${selected.map((column, index) =>
        `CAST(${column} AS BLOB) AS __cliq_raw_${index}`).join(',')} FROM ${table} ORDER BY ${TABLE_ORDER[table]}`);
      statement.setReadBigInts(true);
      let iterator: AsyncIterableIterator<PreparedImportRow> | undefined;
      iterator = (async function* () {
        let count = 0;
        try { current(); for (const row of iterateNodeSqliteStatement(statement)) {
          current(); yield rowData(row, selected); if (++count % 64 === 0) { await setImmediate(); current(); }
        } current(); }
        finally { if (iterator) iterators.delete(iterator); }
      })(); iterators.add(iterator); return iterator;
    };
    const projection: KernelArchiveProjection = Object.freeze({ birth, image, assertHeld: current, rows,
      async digest() {
        current(); const hash = createHash('sha256').update('cliq-kernel-archive-sql-projection-v1\n');
        for (const table of KERNEL_AUTHORITY_TABLES) {
          hash.update(canonicalJsonBytes(table)).update('\n');
          for await (const row of rows(table)) hash.update(canonicalJsonBytes(Object.keys(row).sort().map(key => [key,
            typeof row[key] === 'bigint' ? { integer: row[key]!.toString() } : row[key]]))).update('\n');
        }
        current(); return hash.digest('hex');
      } });
    result = await operation(projection); current();
  } catch (error) { failed = true; failure = error; }
  active = false;
  try { for (const iterator of [...iterators]) { await iterator.return?.(); iterators.delete(iterator); } }
  catch (error) {
    if (database) unretiredArchiveReaders.add({ database, scope });
    throw new ResourceRetirementError('archive original SQL iterator did not actually join', error);
  }
  if (failure instanceof ResourceRetirementError) { if (database) unretiredArchiveReaders.add({ database, scope }); throw failure; }
  try { database?.close(); }
  catch (error) { if (database) unretiredArchiveReaders.add({ database, scope });
    throw new ResourceRetirementError('archive original readonly SQLite connection did not close', error); }
  if (begun) endHeldKernelArchiveRead(scope);
  // EndRead only observes real xClose. This second complete original-FD hash
  // remains independently mandatory; a valid SQL result is not enough.
  if (!failed) try {
    const final = await sealHeldKernelArchive(scope, signal);
    if (canonicalSha256(final) !== canonicalSha256(image)) invalid('archive original image changed during its complete SQL audit');
  } catch (error) { failed = true; failure = error; }
  if (failed) throw failure;
  return Object.freeze({ value: result, birth, image });
}

export type CompleteOriginalKernelArchive<T> = Readonly<{ value: T; birth: KernelArchiveBirthObservation;
  image: KernelArchiveImageObservation; manifest: CompleteKernelArchiveHeader; manifestObservation: KernelArchiveManifestObservation }>;
const completedOriginalKernelArchives = new WeakMap<object, Readonly<{
  native: NativeStateOwner; gate: HeldMigrationCredentialGate; driver: SqliteDriver;
}>>();
/** Same-process producer origin only, minted after its real original scope
 * closed. A copied record/boolean/schema label cannot claim this branch.
 * Restart consumers still need their separate complete persisted history. */
export function assertOriginalCompletedKernelArchive<T>(value: CompleteOriginalKernelArchive<T>, native: NativeStateOwner,
  gate: HeldMigrationCredentialGate, driver: SqliteDriver): void {
  const original = completedOriginalKernelArchives.get(value);
  if (!original || original.native !== native || original.gate !== gate || original.driver !== driver)
    throw new TypeError('current archive consumer requires its genuine completed original producer');
  gate.assertHeld();
}

/** One original create→online SQL copy→complete productive-cut comparison→
 * full CAS namespace copy→private canonical manifest seal→actual close.
 * No archive data is published into the namespace being captured. */
export async function archiveOriginalKernel<T>(native: NativeStateOwner, gate: HeldMigrationCredentialGate, image: FileHandle,
  control: KernelRollbackDrainingControlV1, driver: SqliteDriver, schema: SignedKernelSchemaV1,
  operation: (projection: KernelArchiveProjection) => Promise<T>, signal?: AbortSignal): Promise<CompleteOriginalKernelArchive<T>> {
  decodeSignedKernelSchema(schema);
  const archive = await createHeldKernelArchive(native, gate, image, control);
  let result: CompleteOriginalKernelArchive<T> | undefined, failed = false, failure: unknown;
  try {
    const before = await readOriginalKernelProductiveCut(driver, archive, signal);
    const captured = await withKernelArchiveProjection(driver, archive, schema, async projection => {
      const productiveCut = await readArchivedKernelProductiveCut(projection, signal);
      assertSameKernelArchiveSqlCut(before, productiveCut);
      const value = await operation(projection), completeSqlDigest = await projection.digest();
      return Object.freeze({ value, productiveCut, completeSqlDigest });
    }, signal);
    const cas = await captureHeldKernelArchiveCas(archive, captured.image.byteCount, signal);
    assertSameKernelArchiveSqlCut(before, await readOriginalKernelProductiveCut(driver, archive, signal));
    const core: Omit<CompleteKernelArchiveManifest, 'entries' | 'manifestDigest'> = {
      schemaVersion: 1, format: 'cliq-owned-kernel-archive-v1',
      snapshotBoundary: 'globally_quiescent_rollback_draining_original_online_copy',
      excludedTail: 'canonical_time_fence_and_post_capture_rollback_audit', control,
      archiveDirectory: captured.birth.archiveDirectory,
      database: { file: captured.image.file, mode: 0o400, linkCount: 1, byteCount: captured.image.byteCount,
        sha256: captured.image.sha256, copyMethod: 'original_node_sqlite_online_backup', stateSchemaVersion: 8,
        signedSchemaRef: canonicalSha256(schema), signedSchemaDigest: schema.profileDigest,
        completeSqlDigest: captured.value.completeSqlDigest, productiveCut: captured.value.productiveCut },
      localModelStore: { kind: captured.image.localModelStore }, cas: cas.identity
    };
    const encoded = await encodeCompleteKernelArchiveManifest(core, cas.entries, signal);
    const manifestObservation = await sealHeldKernelArchiveManifest(archive, encoded.bytes, signal);
    assertSameKernelArchiveSqlCut(before, await readOriginalKernelProductiveCut(driver, archive, signal));
    result = Object.freeze({ value: captured.value.value, birth: captured.birth, image: captured.image,
      manifest: encoded.header, manifestObservation });
  } catch (error) { failed = true; failure = error; }
  if (failure instanceof ResourceRetirementError) throw failure;
  try { archive.close(); }
  catch (error) { throw new ResourceRetirementError('original installed archive scope did not retire',
    failed ? new AggregateError([failure, error]) : error); }
  if (failed) throw failure;
  if (result === undefined) throw new KernelStorageError('RECOVERY_REQUIRED', 'original archive has no complete result');
  completedOriginalKernelArchives.set(result, { native, gate, driver });
  return result;
}
