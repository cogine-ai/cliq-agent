import { DatabaseSync, type StatementSync } from 'node:sqlite';
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

export interface SqliteDriver extends SqliteConnection {
  transaction<Result>(operation: (connection: SqliteConnection) => Result): Result;
  close(): void;
}

class NodeSqliteStatement implements SqliteStatement {
  constructor(private readonly statement: StatementSync) {
    statement.setReadBigInts(true);
  }

  run(...parameters: SqliteInputValue[]): SqliteRunResult {
    return this.statement.run(...parameters) as SqliteRunResult;
  }

  get<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row | undefined {
    return this.statement.get(...parameters) as Row | undefined;
  }

  all<Row = SqliteRow>(...parameters: SqliteInputValue[]): Row[] {
    return this.statement.all(...parameters) as Row[];
  }
}

class NodeSqliteDriver implements SqliteDriver {
  private readonly database: DatabaseSync;

  constructor(databasePath: string) {
    this.database = new DatabaseSync(databasePath, {
      allowExtension: false,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true
    });
  }

  exec(sql: string): void {
    this.database.exec(sql);
  }

  prepare(sql: string): SqliteStatement {
    return new NodeSqliteStatement(this.database.prepare(sql));
  }

  transaction<Result>(operation: (connection: SqliteConnection) => Result): Result {
    this.database.exec('BEGIN IMMEDIATE');
    try {
      const result = operation(this);
      this.database.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.database.exec('ROLLBACK');
      } catch (rollbackError) {
        throw new AggregateError([error, rollbackError], 'SQLite transaction and rollback both failed');
      }
      throw error;
    }
  }

  close(): void {
    this.database.close();
  }
}

export function openSqliteDriver(databasePath: string): SqliteDriver {
  if (!path.isAbsolute(databasePath) || path.normalize(databasePath) !== databasePath) {
    throw new TypeError('SQLite driver requires a normalized absolute file-backed database path');
  }
  return new NodeSqliteDriver(databasePath);
}
