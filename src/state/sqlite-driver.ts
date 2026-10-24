import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { closeSync, constants, fstatSync, lstatSync, openSync, type Stats } from 'node:fs';
import path from 'node:path';

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

  constructor(databasePath: string) {
    this.database = new DatabaseSync(databasePath, {
      allowExtension: false,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true
    });
    connectionIssuers.set(this, { driver: this, assertUsable: this.requireNoActiveTransaction });
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
          this.database.close();
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
      try { this.database.close(); } catch { /* Permanently refuse the uncertain connection. */ }
      throw new AggregateError(primaryError === undefined ? [error] : [primaryError, error],
        'SQLite read snapshot could not restore connection settings');
    }
  }

  close(): void {
    this.requireNoActiveTransaction();
    try { this.database.close(); }
    finally { rolledBackTransactionFailures.delete(this); connectionIssuers.delete(this); }
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

function prepareDatabasePath(databasePath: string): void {
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
