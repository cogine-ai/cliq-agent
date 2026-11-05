import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { closeSync, constants, fstatSync, lstatSync, openSync, type Stats } from 'node:fs';
import path from 'node:path';
import { channel } from 'node:diagnostics_channel';
import { beginHeldKernelArchiveBackup, assertHeldKernelArchive, assertHeldKernelArchiveSource, type HeldKernelArchive, type KernelArchiveBackupJoin } from './native-owner.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

export type SqliteInputValue = null | number | bigint | string | NodeJS.ArrayBufferView;
export type SqliteOutputValue = null | number | bigint | string | Uint8Array;
export type SqliteRow = Record<string, SqliteOutputValue>;

/** Keep the actual native statement alive until its iterator closes. Node
 * 22.13's iterator retains only a native pointer, not the JS statement owner.
 * This primitive owns no database, transaction, scope or authority. */
export function* iterateNodeSqliteStatement(statement: StatementSync, ...parameters: SqliteInputValue[]): IterableIterator<SqliteRow> {
  const query = statement.sourceSQL;
  try { yield* statement.iterate(...parameters); }
  finally {
    if (statement.sourceSQL !== query) throw new TypeError('SQLite iterator statement changed');
  }
}

export type SqliteRunResult = {
  changes: bigint;
  lastInsertRowid: bigint;
};

export interface SqliteStatement {
  run(...parameters: SqliteInputValue[]): SqliteRunResult;
  get<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row | undefined;
  all<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row[];
  iterate<Row = SqliteRow>(...parameters: SqliteInputValue[]): IterableIterator<Row>;
}

export interface SqliteConnection {
  exec(sql: string): void;
  prepare(sql: string): SqliteStatement;
}

type SqliteTransactionOperation = (connection: SqliteConnection) => unknown;
type SynchronousOperation<Operation extends SqliteTransactionOperation> =
  [ReturnType<Operation>] extends [never]
    ? Operation
    : ReturnType<Operation> extends PromiseLike<unknown>
      ? never
      : Operation;

export interface SqliteDriver extends SqliteConnection {
  transaction<Operation extends SqliteTransactionOperation>(
    operation: SynchronousOperation<Operation>
  ): ReturnType<Operation>;
  /** One synchronous, read-only cut. No writer reservation or async scope escape. */
  readSnapshot<Operation extends SqliteTransactionOperation>(
    operation: SynchronousOperation<Operation>
  ): ReturnType<Operation>;
  close(): void;
}

/** Actual Node backup page observations only. The diagnostic grants no
 * authority, source handle, timing, cancellation permission or retry. Trusted
 * subscribers catch their own errors, as with existing installed diagnostics. */
export const KERNEL_ARCHIVE_PROGRESS_CHANNEL = 'cliq.installed.archive.progress.v1';
const archiveProgress = channel(KERNEL_ARCHIVE_PROGRESS_CHANNEL);
function observeArchiveSqliteStep(value: Readonly<{ totalPages: number; remainingPages: number }>): void {
  if (!archiveProgress.hasSubscribers || !Number.isSafeInteger(value.totalPages) || !Number.isSafeInteger(value.remainingPages) ||
      value.totalPages < 1 || value.remainingPages < 0 || value.remainingPages > value.totalPages) return;
  try { archiveProgress.publish(Object.freeze({ phase: 'sqlite_step', totalPages: value.totalPages, remainingPages: value.remainingPages })); }
  catch { /* Observation never changes the actual backup or its native join. */ }
}

type OriginalArchiveSource = { database: DatabaseSync; databasePath: string; readOnly: boolean; assertCurrent(): void; liveBackups: number };
const originalArchiveSources = new WeakMap<SqliteDriver, OriginalArchiveSource>();
// A failed actual native join must keep both the original source connection
// and destination holder alive after the rejecting Promise has settled.
const unretiredArchiveSources = new Set<Readonly<{ driver: SqliteDriver; source: OriginalArchiveSource; archive: HeldKernelArchive }>>();

/** Source authentication shared by the complete productive-cut audit. It
 * returns no handle and accepts only the same genuine original destination. */
export function assertOriginalKernelArchiveSource(driver: SqliteDriver, archive: HeldKernelArchive): void {
  const source = originalArchiveSources.get(driver);
  if (!source || source.readOnly || connectionIssuers.get(driver)?.driver !== driver)
    throw new TypeError('archive requires its genuine writable original source driver');
  source.assertCurrent(); assertHeldKernelArchiveSource(archive, source.databasePath);
}

/** Fixed original-source friend, not a generic backup/path API. Only the
 * genuine archive issuer can provide the one native nonce-bound destination.
 * Node22 shared imports remain valid; builtin backup is resolved lazily only
 * in the fixed installed Linux Node24 branch. */
export async function backupOriginalSqliteToKernelArchive(driver: SqliteDriver, archive: HeldKernelArchive,
  signal?: AbortSignal): Promise<KernelArchiveBackupJoin> {
  const source = originalArchiveSources.get(driver);
  if (!source || source.readOnly || source.liveBackups !== 0 || connectionIssuers.get(driver)?.driver !== driver)
    throw new TypeError('archive source requires its genuine writable original driver without another backup');
  source.assertCurrent(); assertHeldKernelArchiveSource(archive, source.databasePath); signal?.throwIfAborted();
  if (process.platform !== 'linux' || process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'original online archive requires the fixed installed Linux Node24 backend');
  source.liveBackups++;
  let target: Awaited<ReturnType<typeof beginHeldKernelArchiveBackup>> | undefined;
  let joined: KernelArchiveBackupJoin | undefined, failure: unknown, failed = false, cancellationFailure: unknown;
  const cancel = () => { try { target?.requestCancel(); } catch (error) { cancellationFailure ??= error; } };
  try {
    const sqlite = await import('node:sqlite');
    const backup: unknown = Reflect.get(sqlite, 'backup');
    if (typeof backup !== 'function') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'fixed Node24 builtin online backup is unavailable');
    source.assertCurrent(); signal?.throwIfAborted();
    target = await beginHeldKernelArchiveBackup(archive);
    signal?.addEventListener('abort', cancel, { once: true });
    if (signal?.aborted) cancel();
    if (!signal?.aborted) {
      // No source reconnect/checkpoint/rename, caller progress callback/SQL,
      // alternate path or timeout. Fixed progress only emits actual Node page
      // observations; it never decides a backup outcome or replaces cancel/join.
      // The actual live source remains available to
      // its original maintenance/time-fence code, whose latency needs physical
      // qualification under real backup-update/fsync contention.
      await (backup as (source: DatabaseSync, path: string, options: Readonly<{
        source: 'main'; target: 'main'; rate: 64;
        progress(value: Readonly<{ totalPages: number; remainingPages: number }>): void;
      }>) => Promise<unknown>)(source.database, target.uri,
        { source: 'main', target: 'main', rate: 64, progress: observeArchiveSqliteStep });
    }
  } catch (error) { failed = true; failure = error; cancel(); }
  finally {
    // This finally runs only after the actual Node operation settled, never
    // after a JS race/timeout. The native observation also requires every
    // real xClose and retired journal. Keep source.close refused if uncertain.
    signal?.removeEventListener('abort', cancel);
    try { if (target) joined = target.join(); }
    catch (error) {
      unretiredArchiveSources.add({ driver, source, archive });
      throw new ResourceRetirementError('original SQLite archive callbacks did not actually join',
        failed ? new AggregateError([failure, error]) : error);
    }
    if (!target && failure instanceof ResourceRetirementError) {
      unretiredArchiveSources.add({ driver, source, archive }); throw failure;
    }
    source.liveBackups--;
  }
  if (cancellationFailure !== undefined) throw new ResourceRetirementError('original archive cancellation was not observed', cancellationFailure);
  // Only a real cancelled native join can classify a simultaneously
  // rejected SQLite task as cancellation. Preserve both original reasons;
  // transport close, signal state or SQLITE_IOERR alone proves no join.
  if (failed && signal?.aborted && joined?.outcome === 'cancelled')
    throw new AggregateError([signal.reason, failure], signal.reason instanceof Error ? signal.reason.message :
      'Kernel archive cancellation joined', { cause: signal.reason });
  if (failed) throw failure;
  signal?.throwIfAborted(); source.assertCurrent(); assertHeldKernelArchive(archive);
  if (!joined || joined.outcome !== 'commit_phase_two_observed' || joined.mainOpens !== 1 || joined.mainCloses !== 1)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'online archive lacks its actual single main lease and commit-phase-two observation');
  return joined;
}

const rolledBackTransactionFailures = new WeakMap<SqliteDriver, WeakSet<Error>>();
const connectionIssuers = new WeakMap<SqliteConnection, { driver: SqliteDriver; assertUsable?(): void }>();

/** Internal SQL friend: a structural, foreign or expired connection cannot
 * replace this driver's genuine current scope. This grants no Run authority. */
export function assertSqliteConnectionOwnedBy(driver: SqliteDriver, connection: SqliteConnection): void {
  const issuer = connectionIssuers.get(connection);
  if (!issuer || issuer.driver !== driver || connectionIssuers.get(driver)?.driver !== driver)
    throw new TypeError('SQLite connection requires its genuine active issuing driver');
  issuer.assertUsable?.();
}

/** Exact native mutation failure after this driver's successful rollback and
 * scope cleanup. It grants no authority to replay an invocation or callback. */
export function isRolledBackSqliteTransactionFailure(driver: SqliteDriver, error: unknown): error is Error {
  return error instanceof Error && rolledBackTransactionFailures.get(driver)?.has(error) === true;
}

class NodeSqliteStatement implements SqliteStatement {
  constructor(
    private readonly statement: StatementSync,
    private readonly requireUsable: () => void = () => undefined,
    private readonly onRunFailure?: (error: unknown) => void
  ) {
    statement.setReadBigInts(true);
  }

  run(...parameters: SqliteInputValue[]): SqliteRunResult {
    this.requireUsable();
    try { return this.statement.run(...parameters) as SqliteRunResult; }
    catch (error) { this.onRunFailure?.(error); throw error; }
  }

  get<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row | undefined {
    this.requireUsable();
    return this.statement.get(...parameters) as Row | undefined;
  }

  all<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row[] {
    this.requireUsable();
    return this.statement.all(...parameters) as Row[];
  }
  *iterate<Row = SqliteRow>(...parameters: SqliteInputValue[]): IterableIterator<Row> {
    this.requireUsable();
    for (const row of iterateNodeSqliteStatement(this.statement, ...parameters)) {
      this.requireUsable(); yield row as Row;
    }
    this.requireUsable();
  }
}

class TransactionScopedStatement implements SqliteStatement {
  constructor(
    private readonly statement: SqliteStatement,
    private readonly requireActive: () => void
  ) {}

  run(...parameters: SqliteInputValue[]): SqliteRunResult {
    this.requireActive();
    return this.statement.run(...parameters);
  }

  get<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row | undefined {
    this.requireActive();
    return this.statement.get<Row>(...parameters);
  }

  all<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row[] {
    this.requireActive();
    return this.statement.all<Row>(...parameters);
  }
  *iterate<Row = SqliteRow>(...parameters: SqliteInputValue[]): IterableIterator<Row> {
    this.requireActive();
    for (const row of this.statement.iterate<Row>(...parameters)) {
      this.requireActive(); yield row;
    }
    this.requireActive();
  }
}

const TRANSACTION_CONTROL_KEYWORDS = new Set([
  'BEGIN',
  'COMMIT',
  'END',
  'RELEASE',
  'ROLLBACK',
  'SAVEPOINT'
]);

function assertNoTransactionControl(sql: string, readOnly = false): void {
  let index = 0;
  let statementStart = true;
  let triggerBody = false;
  let statementKeywords: string[] = [];
  while (index < sql.length) {
    const character = sql[index];
    if (/\s/u.test(character)) {
      index += 1;
      continue;
    }
    if (character === '-' && sql[index + 1] === '-') {
      index = sql.indexOf('\n', index + 2);
      if (index === -1) return;
      continue;
    }
    if (character === '/' && sql[index + 1] === '*') {
      const end = sql.indexOf('*/', index + 2);
      if (end === -1) return;
      index = end + 2;
      continue;
    }
    if (character === ';') {
      statementStart = true;
      if (!triggerBody) statementKeywords = [];
      index += 1;
      continue;
    }
    if (character === "'" || character === '"' || character === '`' || character === '[') {
      const close = character === '[' ? ']' : character;
      const supportsDoubledCloseEscape = character !== '[';
      index += 1;
      while (index < sql.length) {
        if (sql[index] !== close) {
          index += 1;
          continue;
        }
        if (supportsDoubledCloseEscape && sql[index + 1] === close) {
          index += 2;
          continue;
        }
        index += 1;
        break;
      }
      statementStart = false;
      continue;
    }
    if (/[A-Za-z_]/u.test(character)) {
      const start = index;
      index += 1;
      while (index < sql.length && /[A-Za-z0-9_]/u.test(sql[index])) index += 1;
      const keyword = sql.slice(start, index).toUpperCase();
      if (triggerBody && statementStart && keyword === 'END') {
        triggerBody = false;
        statementStart = false;
        continue;
      }
      if (statementStart && TRANSACTION_CONTROL_KEYWORDS.has(keyword)) {
        throw new TypeError('SQLite transaction control SQL is reserved for the driver');
      }
      if (readOnly && statementStart && ['PRAGMA', 'ATTACH', 'DETACH'].includes(keyword)) {
        throw new TypeError('SQLite connection settings are reserved during a read snapshot');
      }
      if (!triggerBody) {
        statementKeywords.push(keyword);
        const prefix = statementKeywords.filter((entry) => entry !== 'TEMP' && entry !== 'TEMPORARY');
        if (prefix.length === 2 && prefix[0] === 'CREATE' && prefix[1] === 'TRIGGER') {
          triggerBody = true;
        }
      }
      statementStart = false;
      continue;
    }
    statementStart = false;
    index += 1;
  }
}

class TransactionScopedConnection implements SqliteConnection {
  private active = true;

  constructor(private readonly database: DatabaseSync, private readonly readOnly = false,
    private readonly onRunFailure?: (error: unknown) => void) {}

  deactivate(): void {
    this.active = false;
  }

  exec(sql: string): void {
    this.requireActive();
    assertNoTransactionControl(sql, this.readOnly);
    this.database.exec(sql);
  }

  prepare(sql: string): SqliteStatement {
    this.requireActive();
    assertNoTransactionControl(sql, this.readOnly);
    return new TransactionScopedStatement(
      new NodeSqliteStatement(this.database.prepare(sql), undefined, this.onRunFailure),
      this.requireActive
    );
  }

  private readonly requireActive = (): void => {
    if (!this.active) {
      throw new Error('SQLite transaction scope is no longer active');
    }
  };
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  if ((typeof value !== 'object' || value === null) && typeof value !== 'function') return false;
  return typeof (value as { then?: unknown }).then === 'function';
}

function observeRejectedThenable(value: PromiseLike<unknown>): void {
  // Promise.resolve assimilates foreign thenables and attaching the rejection
  // handler here prevents a rejected async callback from becoming unhandled.
  void Promise.resolve(value).catch(() => undefined);
}

class NodeSqliteDriver implements SqliteDriver {
  private readonly database: DatabaseSync;
  private transactionActive = false;
  private poisoned = false;

  constructor(databasePath: string, readOnly = false) {
    this.database = new DatabaseSync(databasePath, {
      allowExtension: false,
      readOnly,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true
    });
    connectionIssuers.set(this, { driver: this, assertUsable: this.requireNoActiveTransaction });
    originalArchiveSources.set(this, { database: this.database, databasePath, readOnly, assertCurrent: this.requireNoActiveTransaction, liveBackups: 0 });
  }

  exec(sql: string): void {
    this.requireNoActiveTransaction();
    this.database.exec(sql);
  }

  prepare(sql: string): SqliteStatement {
    this.requireNoActiveTransaction();
    return new NodeSqliteStatement(this.database.prepare(sql), this.requireNoActiveTransaction);
  }

  transaction<Operation extends SqliteTransactionOperation>(
    operation: SynchronousOperation<Operation>
  ): ReturnType<Operation> {
    return this.scopedTransaction(operation, false);
  }

  readSnapshot<Operation extends SqliteTransactionOperation>(
    operation: SynchronousOperation<Operation>
  ): ReturnType<Operation> {
    return this.scopedTransaction(operation, true);
  }

  private scopedTransaction<Operation extends SqliteTransactionOperation>(
    operation: SynchronousOperation<Operation>, readOnly: boolean
  ): ReturnType<Operation> {
    this.requireNoActiveTransaction();
    const restoreQueryOnly = readOnly && this.database.prepare('PRAGMA query_only').get()?.query_only === 0;
    if (restoreQueryOnly) this.database.exec('PRAGMA query_only=ON');
    try { this.database.exec(readOnly ? 'BEGIN' : 'BEGIN IMMEDIATE'); }
    catch (error) {
      if (error instanceof Error) rolledBackTransactionFailures.get(this)?.delete(error);
      if (restoreQueryOnly) this.restoreWritableConnection(error);
      throw error;
    }
    this.transactionActive = true;
    let nativeFailure: Error | undefined;
    const recordNativeFailure = (error: unknown) => {
      if (error instanceof Error) rolledBackTransactionFailures.get(this)?.delete(error);
      nativeFailure = !readOnly && error instanceof Error &&
        Object.getOwnPropertyDescriptor(error, 'code')?.value === 'ERR_SQLITE_ERROR' ? error : undefined;
    };
    const scopedConnection = new TransactionScopedConnection(this.database, readOnly, recordNativeFailure);
    connectionIssuers.set(scopedConnection, { driver: this });
    const deactivateScope = () => {
      connectionIssuers.delete(scopedConnection);
      scopedConnection.deactivate();
    };
    let primaryError: unknown, rolledBack = false;
    try {
      const result = operation(scopedConnection) as ReturnType<Operation>;
      deactivateScope();
      if (isThenable(result)) {
        observeRejectedThenable(result);
        throw new TypeError(`SQLite ${readOnly ? 'read snapshot' : 'transaction'} callback must be synchronous`);
      }
      try { this.database.exec('COMMIT'); }
      catch (error) { recordNativeFailure(error); throw error; }
      return result;
    } catch (error) {
      primaryError = error;
      if (error instanceof Error) rolledBackTransactionFailures.get(this)?.delete(error);
      deactivateScope();
      try {
        this.database.exec('ROLLBACK');
        rolledBack = true;
      } catch (rollbackError) {
        this.poisoned = true;
        rolledBackTransactionFailures.delete(this);
        try {
          if ((originalArchiveSources.get(this)?.liveBackups ?? 0) === 0) this.database.close();
        } catch {
          // The transaction outcome is already uncertain. Closing is best
          // effort; the public connection remains permanently unusable.
        }
        throw new AggregateError([error, rollbackError], 'SQLite transaction and rollback both failed');
      }
      throw error;
    } finally {
      deactivateScope();
      this.transactionActive = false;
      if (restoreQueryOnly && !this.poisoned) this.restoreWritableConnection(primaryError);
      if (rolledBack && !this.poisoned && nativeFailure !== undefined && primaryError === nativeFailure) {
        const failures = rolledBackTransactionFailures.get(this) ?? new WeakSet<Error>();
        failures.add(nativeFailure); rolledBackTransactionFailures.set(this, failures);
      }
    }
  }

  private restoreWritableConnection(primaryError?: unknown): void {
    try { this.database.exec('PRAGMA query_only=OFF'); }
    catch (error) {
      this.poisoned = true;
      rolledBackTransactionFailures.delete(this);
      try { if ((originalArchiveSources.get(this)?.liveBackups ?? 0) === 0) this.database.close(); }
      catch { /* Permanently refuse the uncertain connection. */ }
      throw new AggregateError(primaryError === undefined ? [error] : [primaryError, error],
        'SQLite read snapshot could not restore connection settings');
    }
  }

  close(): void {
    this.requireNoActiveTransaction();
    if ((originalArchiveSources.get(this)?.liveBackups ?? 0) !== 0)
      throw new ResourceRetirementError('original SQLite source has a live or unjoined archive backup', undefined);
    try { this.database.close(); }
    finally { rolledBackTransactionFailures.delete(this); connectionIssuers.delete(this); originalArchiveSources.delete(this); }
  }

  private readonly requireNoActiveTransaction = (): void => {
    if (this.poisoned) {
      throw new Error('The SQLite connection was abandoned after a failed rollback');
    }
    if (this.transactionActive) {
      throw new Error('The outer SQLite connection is unavailable during an active transaction');
    }
  };
}

const SQLITE_SIDECAR_SUFFIXES = ['-journal', '-wal', '-shm'] as const;

function requireEffectiveUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new TypeError('SQLite driver requires a POSIX effective uid');
  }
  return process.geteuid();
}

function assertPrivateRegularFile(info: Stats, label: string, effectiveUid: number): void {
  if (!info.isFile()) {
    throw new Error(`${label} must be a regular file`);
  }
  if (info.nlink !== 1) {
    throw new Error(`${label} link count must be exactly 1`);
  }
  if (info.uid !== effectiveUid) {
    throw new Error(`${label} must be owned by the effective uid`);
  }
  if ((info.mode & 0o7777) !== 0o600) {
    throw new Error(`${label} mode must be exactly 0600`);
  }
}

function isErrnoCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

/**
 * Validates a path immediately before SQLite opens it. This reduces obvious
 * symlink/link/permission hazards but is intentionally not an authority proof:
 * Node's SQLite API reopens by pathname, so a descriptor-relative native
 * helper is still required to close the remaining replacement race.
 */
function validateExistingPrivateFile(filename: string, label: string, effectiveUid: number): boolean {
  let pathInfo: Stats;
  try {
    pathInfo = lstatSync(filename);
  } catch (error) {
    if (isErrnoCode(error, 'ENOENT')) return false;
    throw error;
  }

  if (pathInfo.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link`);
  }
  assertPrivateRegularFile(pathInfo, label, effectiveUid);

  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    assertPrivateRegularFile(fstatSync(descriptor), label, effectiveUid);
  } finally {
    closeSync(descriptor);
  }
  return true;
}

function precreatePrivateDatabase(databasePath: string, effectiveUid: number): void {
  let descriptor: number;
  try {
    descriptor = openSync(
      databasePath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600
    );
  } catch (error) {
    if (isErrnoCode(error, 'EEXIST')) {
      if (validateExistingPrivateFile(databasePath, 'SQLite database file', effectiveUid)) return;
    }
    throw error;
  }

  try {
    assertPrivateRegularFile(fstatSync(descriptor), 'SQLite database file', effectiveUid);
  } finally {
    closeSync(descriptor);
  }
}

function prepareDatabasePath(databasePath: string, allowCreate = true): void {
  const effectiveUid = requireEffectiveUid();
  const databaseExists = validateExistingPrivateFile(
    databasePath,
    'SQLite database file',
    effectiveUid
  );

  for (const suffix of SQLITE_SIDECAR_SUFFIXES) {
    validateExistingPrivateFile(
      `${databasePath}${suffix}`,
      `SQLite ${suffix} file`,
      effectiveUid
    );
  }

  if (!databaseExists) {
    if (!allowCreate) throw new Error('read-only kernel database is missing');
    precreatePrivateDatabase(databasePath, effectiveUid);
  }
}

export function openSqliteDriver(databasePath: string): SqliteDriver {
  if (!path.isAbsolute(databasePath) || path.normalize(databasePath) !== databasePath) {
    throw new TypeError('SQLite driver requires a normalized absolute file-backed database path');
  }
  prepareDatabasePath(databasePath);
  return new NodeSqliteDriver(databasePath);
}

/** Data-only installed selection/history cut. It cannot create a missing DB or
 * mutate the original database even if a caller submits a writing statement. */
export function openReadOnlySqliteDriver(databasePath: string): SqliteDriver {
  if (!path.isAbsolute(databasePath) || path.normalize(databasePath) !== databasePath)
    throw new TypeError('SQLite reader requires a normalized absolute file-backed database path');
  prepareDatabasePath(databasePath, false);
  return new NodeSqliteDriver(databasePath, true);
}
