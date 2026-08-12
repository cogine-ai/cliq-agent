import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { openSqliteDriver } from './sqlite-driver.js';

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
