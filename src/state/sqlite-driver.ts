import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { closeSync, constants, fstatSync, lstatSync, openSync, type Stats } from 'node:fs';
import path from 'node:path';

export type SqliteInputValue = null | number | bigint | string | NodeJS.ArrayBufferView;
export type SqliteOutputValue = null | number | bigint | string | Uint8Array;
export type SqliteRow = Record<string, SqliteOutputValue>;

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
  close(): void;
}

class NodeSqliteStatement implements SqliteStatement {
  constructor(
    private readonly statement: StatementSync,
    private readonly requireUsable: () => void = () => undefined
  ) {
    statement.setReadBigInts(true);
  }

  run(...parameters: SqliteInputValue[]): SqliteRunResult {
    this.requireUsable();
    return this.statement.run(...parameters) as SqliteRunResult;
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

function assertNoTransactionControl(sql: string): void {
  let index = 0;
  let statementStart = true;
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
      index += 1;
      continue;
    }
    if (character === "'" || character === '"' || character === '`' || character === '[') {
      const close = character === '[' ? ']' : character;
      index += 1;
      while (index < sql.length) {
        if (sql[index] !== close) {
          index += 1;
          continue;
        }
        if (sql[index + 1] === close) {
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
      if (statementStart && TRANSACTION_CONTROL_KEYWORDS.has(keyword)) {
        throw new TypeError('SQLite transaction control SQL is reserved for the driver');
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

  constructor(private readonly database: DatabaseSync) {}

  deactivate(): void {
    this.active = false;
  }

  exec(sql: string): void {
    this.requireActive();
    assertNoTransactionControl(sql);
    this.database.exec(sql);
  }

  prepare(sql: string): SqliteStatement {
    this.requireActive();
    assertNoTransactionControl(sql);
    return new TransactionScopedStatement(
      new NodeSqliteStatement(this.database.prepare(sql)),
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

  constructor(databasePath: string) {
    this.database = new DatabaseSync(databasePath, {
      allowExtension: false,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true
    });
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
    this.requireNoActiveTransaction();
    this.database.exec('BEGIN IMMEDIATE');
    this.transactionActive = true;
    const scopedConnection = new TransactionScopedConnection(this.database);
    try {
      const result = operation(scopedConnection) as ReturnType<Operation>;
      scopedConnection.deactivate();
      if (isThenable(result)) {
        observeRejectedThenable(result);
        throw new TypeError('SQLite transaction callback must be synchronous');
      }
      this.database.exec('COMMIT');
      return result;
    } catch (error) {
      scopedConnection.deactivate();
      try {
        this.database.exec('ROLLBACK');
      } catch (rollbackError) {
        throw new AggregateError([error, rollbackError], 'SQLite transaction and rollback both failed');
      }
      throw error;
    } finally {
      scopedConnection.deactivate();
      this.transactionActive = false;
    }
  }

  close(): void {
    this.requireNoActiveTransaction();
    this.database.close();
  }

  private readonly requireNoActiveTransaction = (): void => {
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
