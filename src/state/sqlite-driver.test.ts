import test from 'node:test';
import assert from 'node:assert/strict';
import { lstatSync } from 'node:fs';
import { chmod, link, lstat, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  openSqliteDriver,
  type SqliteConnection,
  type SqliteDriver,
  type SqliteStatement
} from './sqlite-driver.js';

test('executes caller-owned schema and prepared statements against a file database', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-driver-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT');

    const inserted = driver.prepare('INSERT INTO records (id, value) VALUES (?, ?)').run(1n, 'first');
    const selected = driver.prepare('SELECT id, value FROM records WHERE id = ?').get(1n);
    const all = driver.prepare('SELECT id, value FROM records ORDER BY id').all();

    assert.deepEqual(inserted, { changes: 1n, lastInsertRowid: 1n });
    assert.equal(selected?.id, 1n);
    assert.equal(selected?.value, 'first');
    assert.deepEqual(
      all.map((row) => ({ ...row })),
      [{ id: 1n, value: 'first' }]
    );

    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('BEGIN IMMEDIATE transaction rolls back every write when the callback fails', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-rollback-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT');
    const abort = new Error('abort transaction');

    assert.throws(
      () =>
        driver.transaction((connection) => {
          connection.prepare('INSERT INTO records (id, value) VALUES (?, ?)').run(1n, 'discarded');
          throw abort;
        }),
      (error) => error === abort
    );

    const count = driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>();
    assert.equal(count?.count, 0n);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('read snapshots keep one WAL cut without blocking a concurrent writer', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-read-cut-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');
  const reader = openSqliteDriver(databasePath);
  let writer: SqliteDriver | undefined;
  try {
    reader.exec('PRAGMA journal_mode=WAL; CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');
    reader.prepare('INSERT INTO records (id) VALUES (?)').run(1n);
    writer = openSqliteDriver(databasePath);
    const cut = reader.readSnapshot(connection => {
      const count = () => connection.prepare('SELECT count(*) AS n FROM records').get<{ n: bigint }>()!.n;
      assert.equal(count(), 1n);
      writer!.transaction(other => other.prepare('INSERT INTO records (id) VALUES (?)').run(2n));
      assert.equal(count(), 1n, 'all reads stay on the captured cut despite the committed writer');
      return count();
    });
    assert.equal(cut, 1n);
    assert.equal(reader.readSnapshot(connection => connection.prepare('SELECT count(*) AS n FROM records').get<{ n: bigint }>()!.n), 2n);
  } finally {
    writer?.close(); reader.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('read snapshots forbid writes and setting escapes, then restore the writer connection', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-read-only-'));
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');
    let escapedConnection!: SqliteConnection;
    let escapedStatement!: SqliteStatement;
    driver.readSnapshot(connection => {
      escapedConnection = connection;
      escapedStatement = connection.prepare('SELECT count(*) AS n FROM records');
      assert.throws(() => driver.prepare('SELECT 1'), /outer SQLite connection is unavailable/);
      assert.throws(() => driver.transaction(() => undefined), /outer SQLite connection is unavailable/);
      assert.throws(() => driver.readSnapshot(() => undefined), /outer SQLite connection is unavailable/);
      assert.throws(() => connection.exec('INSERT INTO records (id) VALUES (1)'), /readonly database/);
      assert.throws(() => connection.prepare('INSERT INTO records (id) VALUES (2) RETURNING id').get(), /readonly database/);
      for (const sql of ['/* comment */ PRAGMA query_only=OFF', '-- comment\n ATTACH DATABASE \'anything\' AS extra',
        'SELECT 1; PRAGMA query_only=OFF', 'DETACH DATABASE extra']) {
        assert.throws(() => connection.prepare(sql), /connection settings are reserved/);
      }
      assert.equal(connection.prepare("SELECT 'PRAGMA query_only=OFF' AS value").get<{ value: string }>()!.value, 'PRAGMA query_only=OFF');
    });
    assert.throws(() => escapedConnection.prepare('SELECT 1'), /scope is no longer active/);
    assert.throws(() => escapedStatement.all(), /scope is no longer active/);
    const abort = new Error('abort read cut');
    assert.throws(() => driver.readSnapshot(() => { throw abort; }), error => error === abort);
    driver.transaction(connection => connection.prepare('INSERT INTO records (id) VALUES (3)').run());
    assert.equal(driver.prepare('SELECT count(*) AS n FROM records').get<{ n: bigint }>()!.n, 1n);
    driver.exec('PRAGMA query_only=ON');
    driver.readSnapshot(connection => connection.prepare('SELECT 1').get());
    assert.equal(driver.prepare('PRAGMA query_only').get<{ query_only: bigint }>()!.query_only, 1n, 'preexisting read-only setting is preserved');
    driver.exec('PRAGMA query_only=OFF');
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('read snapshot async callbacks and thenables cannot outlive their SQL cut', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-read-async-'));
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    let late!: Promise<unknown>;
    assert.throws(() => {
      // @ts-expect-error Read snapshot callbacks must be synchronous.
      driver.readSnapshot(async connection => {
        late = Promise.resolve().then(() => connection.prepare('SELECT 1').get());
        await late;
      });
    }, /read snapshot callback must be synchronous/);
    await assert.rejects(late, /scope is no longer active/);
    assert.throws(() => driver.readSnapshot(() => ({ then() {} }) as unknown as number), /read snapshot callback must be synchronous/);
    assert.equal(driver.prepare('PRAGMA query_only').get<{ query_only: bigint }>()!.query_only, 0n);
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('failure restoring read-snapshot settings permanently abandons the connection', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-read-restore-'));
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    const internals = driver as unknown as { database: { exec(sql: string): void } };
    const originalExec = internals.database.exec.bind(internals.database);
    const restoreError = new Error('injected settings restoration failure');
    internals.database.exec = sql => {
      if (sql === 'PRAGMA query_only=OFF') throw restoreError;
      originalExec(sql);
    };
    assert.throws(() => driver.readSnapshot(connection => connection.prepare('SELECT 1').get()),
      error => error instanceof AggregateError && error.errors[0] === restoreError);
    assert.throws(() => driver.prepare('SELECT 1'), /abandoned/);
    assert.throws(() => driver.transaction(() => undefined), /abandoned/);
    assert.throws(() => driver.readSnapshot(() => undefined), /abandoned/);
  } finally {
    // The failed restoration already closed the native database.
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction callbacks cannot commit through the outer driver and leave partial writes', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-transaction-owner-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');

    assert.throws(
      () =>
        driver.transaction((connection) => {
          connection.prepare('INSERT INTO records (id) VALUES (?)').run(1n);
          driver.exec('COMMIT');
          throw new Error('callback failed after an illicit commit');
        }),
      /outer SQLite connection is unavailable during an active transaction/
    );

    assert.equal(driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>()?.count, 0n);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('a failed rollback permanently poisons the uncertain SQLite connection', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-rollback-poison-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    const internals = driver as unknown as {
      database: { exec(sql: string): void; close(): void };
    };
    const originalExec = internals.database.exec.bind(internals.database);
    const primaryError = new Error('injected transaction failure');
    const rollbackError = new Error('injected rollback failure');

    assert.throws(
      () =>
        driver.transaction(() => {
          internals.database.exec = (sql) => {
            if (sql === 'ROLLBACK') throw rollbackError;
            originalExec(sql);
          };
          throw primaryError;
        }),
      (error) =>
        error instanceof AggregateError &&
        error.errors[0] === primaryError &&
        error.errors[1] === rollbackError
    );

    assert.throws(() => driver.exec('SELECT 1'), /abandoned after a failed rollback/);
    assert.throws(() => driver.prepare('SELECT 1'), /abandoned after a failed rollback/);
    assert.throws(() => driver.transaction(() => undefined), /abandoned after a failed rollback/);
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('statements prepared on the outer driver cannot escape into an active transaction', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-statement-owner-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');
    const escapedStatement = driver.prepare('INSERT INTO records (id) VALUES (?)');

    assert.throws(
      () =>
        driver.transaction((connection) => {
          connection.prepare('INSERT INTO records (id) VALUES (?)').run(1n);
          escapedStatement.run(2n);
        }),
      /outer SQLite connection is unavailable during an active transaction/
    );

    assert.equal(driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>()?.count, 0n);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction-scoped exec rejects transaction control before any statement runs', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-scoped-control-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');

    assert.throws(
      () =>
        driver.transaction((connection) => {
          connection.exec('INSERT INTO records (id) VALUES (1); COMMIT');
        }),
      /transaction control SQL is reserved for the driver/
    );

    assert.equal(driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>()?.count, 0n);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction-scoped SQL reserves every control verb without rejecting quoted text', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-control-verbs-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);

    driver.transaction((connection) => {
      for (const sql of [
        'BEGIN',
        'COMMIT',
        'END',
        'RELEASE savepoint_name',
        'ROLLBACK',
        'SAVEPOINT savepoint_name',
        '/* leading comment */ SAVEPOINT savepoint_name'
      ]) {
        assert.throws(() => connection.prepare(sql), /transaction control SQL is reserved for the driver/);
      }

      const row = connection.prepare("SELECT 'COMMIT; ROLLBACK' AS value").get<{ value: string }>();
      assert.equal(row?.value, 'COMMIT; ROLLBACK');
      assert.throws(
        () => connection.exec('SELECT [a]]; COMMIT'),
        /transaction control SQL is reserved for the driver/
      );
    });

    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction-scoped schema may create a trigger without exposing transaction control', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-trigger-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.transaction((connection) => {
      connection.exec(`
        CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT;
        CREATE TRIGGER records_no_delete BEFORE DELETE ON records BEGIN
          SELECT RAISE(ABORT, 'immutable');
        END;
      `);
    });
    driver.prepare('INSERT INTO records (id) VALUES (1)').run();
    assert.throws(() => driver.prepare('DELETE FROM records').run(), /immutable/);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction rejects an async callback, rolls back immediately, and consumes its late rejection', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-async-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');
  const unhandledRejections: unknown[] = [];
  const captureUnhandledRejection = (reason: unknown) => unhandledRejections.push(reason);
  process.on('unhandledRejection', captureUnhandledRejection);

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT');
    let lateContinuationRan = false;

    assert.throws(
      () =>
        // Async transaction callbacks are a compile-time error as well as a runtime error.
        // @ts-expect-error SQLite transactions must complete synchronously.
        driver.transaction(async (connection) => {
          connection.prepare('INSERT INTO records (id, value) VALUES (?, ?)').run(1n, 'rolled-back');
          await Promise.resolve();
          lateContinuationRan = true;
          connection.prepare('INSERT INTO records (id, value) VALUES (?, ?)').run(2n, 'too-late');
        }),
      /transaction callback must be synchronous/
    );

    const immediateCount = driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>();
    assert.equal(immediateCount?.count, 0n, 'the synchronous prefix is rolled back before returning');

    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(lateContinuationRan, true);
    assert.deepEqual(unhandledRejections, [], 'the rejected async continuation is observed internally');
    const finalCount = driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>();
    assert.equal(finalCount?.count, 0n, 'an escaped scoped connection cannot write after rollback');
    driver.close();
  } finally {
    process.off('unhandledRejection', captureUnhandledRejection);
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction rejects non-Promise thenables and rolls back their synchronous writes', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-thenable-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');

    assert.throws(
      () =>
        driver.transaction((connection) => {
          connection.prepare('INSERT INTO records (id) VALUES (?)').run(1n);
          return { then() {} } as unknown as number;
        }),
      /transaction callback must be synchronous/
    );

    assert.equal(driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>()?.count, 0n);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction-scoped connections and statements expire when the callback returns', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-scope-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');
    let escapedConnection: SqliteConnection | undefined;
    let escapedStatement: SqliteStatement | undefined;

    driver.transaction((connection) => {
      escapedConnection = connection;
      escapedStatement = connection.prepare('INSERT INTO records (id) VALUES (?)');
      escapedStatement.run(1n);
    });

    assert.throws(() => escapedConnection?.exec('INSERT INTO records (id) VALUES (2)'), /scope is no longer active/);
    assert.throws(() => escapedConnection?.prepare('SELECT 1'), /scope is no longer active/);
    assert.throws(() => escapedStatement?.run(3n), /scope is no longer active/);
    assert.equal(driver.prepare('SELECT count(*) AS count FROM records').get<{ count: bigint }>()?.count, 1n);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('transaction reserves the write lock before its first write', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-immediate-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const owner = openSqliteDriver(databasePath);
    owner.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');
    const contender = openSqliteDriver(databasePath);

    owner.transaction(() => {
      assert.throws(() => contender.transaction(() => undefined), /database is locked/);
    });

    contender.close();
    owner.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('rejects in-memory, relative, and non-normalized database paths', () => {
  assert.throws(() => openSqliteDriver(':memory:'), {
    name: 'TypeError',
    message: 'SQLite driver requires a normalized absolute file-backed database path'
  });
  assert.throws(() => openSqliteDriver(''), {
    name: 'TypeError',
    message: 'SQLite driver requires a normalized absolute file-backed database path'
  });
  assert.throws(() => openSqliteDriver('relative.sqlite'), /normalized absolute file-backed/);
  assert.throws(
    () => openSqliteDriver(`${os.tmpdir()}/cliq/../kernel.sqlite3`),
    /normalized absolute file-backed/
  );
});

test('pre-creates a new database as a private single-link regular file owned by the effective uid', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-private-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    const info = await lstat(databasePath);
    const effectiveUid = process.geteuid?.();

    assert.equal(info.isFile(), true);
    assert.equal(info.isSymbolicLink(), false);
    assert.equal(info.mode & 0o7777, 0o600);
    assert.equal(info.nlink, 1);
    assert.equal(info.uid, effectiveUid);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('rejects unsafe existing database file types, links, permissions, and ownership before SQLite opens', async (t) => {
  await t.test('symbolic link', async () => {
    const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-unsafe-'));
    const target = path.join(stateRoot, 'target.sqlite3');
    const databasePath = path.join(stateRoot, 'kernel.sqlite3');
    try {
      await writeFile(target, '', { mode: 0o600 });
      await symlink(target, databasePath);
      assertOpenRejects(databasePath, /must not be a symbolic link/);
    } finally {
      await rm(stateRoot, { recursive: true, force: true });
    }
  });

  await t.test('directory', async () => {
    const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-unsafe-'));
    const databasePath = path.join(stateRoot, 'kernel.sqlite3');
    try {
      await mkdir(databasePath, { mode: 0o700 });
      assertOpenRejects(databasePath, /must be a regular file/);
    } finally {
      await rm(stateRoot, { recursive: true, force: true });
    }
  });

  await t.test('multiple hard links', async () => {
    const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-unsafe-'));
    const target = path.join(stateRoot, 'target.sqlite3');
    const databasePath = path.join(stateRoot, 'kernel.sqlite3');
    try {
      await writeFile(target, '', { mode: 0o600 });
      await link(target, databasePath);
      assertOpenRejects(databasePath, /link count must be exactly 1/);
    } finally {
      await rm(stateRoot, { recursive: true, force: true });
    }
  });

  await t.test('non-private mode', async () => {
    const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-unsafe-'));
    const databasePath = path.join(stateRoot, 'kernel.sqlite3');
    try {
      await writeFile(databasePath, '', { mode: 0o600 });
      await chmod(databasePath, 0o640);
      assertOpenRejects(databasePath, /mode must be exactly 0600/);
    } finally {
      await rm(stateRoot, { recursive: true, force: true });
    }
  });

  await t.test('effective uid mismatch', async () => {
    const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-unsafe-'));
    const databasePath = path.join(stateRoot, 'kernel.sqlite3');
    const getEffectiveUid = process.geteuid;
    if (typeof getEffectiveUid !== 'function') assert.fail('POSIX test requires process.geteuid');
    try {
      await writeFile(databasePath, '', { mode: 0o600 });
      process.geteuid = () => getEffectiveUid() + 1;
      assertOpenRejects(databasePath, /must be owned by the effective uid/);
    } finally {
      process.geteuid = getEffectiveUid;
      await rm(stateRoot, { recursive: true, force: true });
    }
  });
});

test('rejects unsafe pre-existing journal, WAL, and shared-memory files before SQLite opens', async (t) => {
  for (const suffix of ['-journal', '-wal', '-shm'] as const) {
    await t.test(`${suffix} permissions`, async () => {
      const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-sidecar-'));
      const databasePath = path.join(stateRoot, 'kernel.sqlite3');
      try {
        await writeFile(databasePath, '', { mode: 0o600 });
        await writeFile(`${databasePath}${suffix}`, 'unsafe', { mode: 0o600 });
        await chmod(`${databasePath}${suffix}`, 0o640);
        assertOpenRejects(databasePath, /mode must be exactly 0600/);
      } finally {
        await rm(stateRoot, { recursive: true, force: true });
      }
    });

    await t.test(`${suffix} type`, async () => {
      const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-sidecar-'));
      const databasePath = path.join(stateRoot, 'kernel.sqlite3');
      const target = path.join(stateRoot, 'sidecar-target');
      try {
        await writeFile(databasePath, '', { mode: 0o600 });
        await writeFile(target, 'target', { mode: 0o600 });
        await symlink(target, `${databasePath}${suffix}`);
        assertOpenRejects(databasePath, /must not be a symbolic link/);
      } finally {
        await rm(stateRoot, { recursive: true, force: true });
      }
    });
  }
});

test('an active rollback journal inherits exact 0600 ownership and link invariants', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-journal-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec('CREATE TABLE records (id INTEGER PRIMARY KEY) STRICT');
    driver.transaction((connection) => {
      connection.prepare('INSERT INTO records (id) VALUES (?)').run(1n);
      const journalInfo = lstatSync(`${databasePath}-journal`);
      assert.equal(journalInfo.isFile(), true);
      assert.equal(journalInfo.isSymbolicLink(), false);
      assert.equal(journalInfo.mode & 0o7777, 0o600);
      assert.equal(journalInfo.nlink, 1);
      assert.equal(journalInfo.uid, process.geteuid?.());
    });
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('committed rows survive close and reopen of the file database', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-reopen-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const first = openSqliteDriver(databasePath);
    first.exec('CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT');
    first.transaction((connection) => {
      connection.prepare('INSERT INTO records (id, value) VALUES (?, ?)').run(7n, 'durable');
    });
    first.close();

    const reopened = openSqliteDriver(databasePath);
    const selected = reopened.prepare('SELECT id, value FROM records WHERE id = ?').get(7n);
    assert.equal(selected?.id, 7n);
    assert.equal(selected?.value, 'durable');
    reopened.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('reads every SQLite INTEGER as bigint without precision loss', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-bigint-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    const beyondSafeInteger = 9_007_199_254_740_993n;
    driver.exec('CREATE TABLE counters (value INTEGER NOT NULL) STRICT');
    driver.prepare('INSERT INTO counters (value) VALUES (?)').run(beyondSafeInteger);

    const selected = driver.prepare('SELECT value FROM counters').get<{ value: bigint }>();
    assert.equal(selected?.value, beyondSafeInteger);
    assert.equal(typeof selected?.value, 'bigint');
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('enforces foreign keys and preserves diagnostic constraint errors', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-constraints-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    driver.exec(`
      CREATE TABLE parents (id INTEGER PRIMARY KEY) STRICT;
      CREATE TABLE children (
        id INTEGER PRIMARY KEY,
        parent_id INTEGER NOT NULL REFERENCES parents(id),
        label TEXT NOT NULL UNIQUE CHECK (length(label) > 0)
      ) STRICT;
    `);
    const insertChild = driver.prepare('INSERT INTO children (id, parent_id, label) VALUES (?, ?, ?)');

    assert.throws(() => insertChild.run(1n, 404n, 'orphan'), /FOREIGN KEY constraint failed/);

    driver.prepare('INSERT INTO parents (id) VALUES (?)').run(1n);
    insertChild.run(1n, 1n, 'first');
    assert.throws(() => insertChild.run(2n, 1n, 'first'), /UNIQUE constraint failed: children.label/);
    assert.throws(() => insertChild.run(3n, 1n, ''), /CHECK constraint failed/);
    driver.close();
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('close makes the driver and its prepared statements unusable', async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-sqlite-close-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');

  try {
    const driver = openSqliteDriver(databasePath);
    const statement = driver.prepare('SELECT 1 AS value');
    driver.close();

    assert.throws(() => driver.exec('SELECT 1'), /database is not open/);
    assert.throws(() => statement.get(), /statement has been finalized/);
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

function assertOpenRejects(databasePath: string, expected: RegExp): void {
  let unexpectedlyOpened: SqliteDriver | undefined;
  try {
    assert.throws(() => {
      unexpectedlyOpened = openSqliteDriver(databasePath);
    }, expected);
  } finally {
    unexpectedlyOpened?.close();
  }
}
