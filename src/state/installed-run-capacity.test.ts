import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { assertInstalledRunAdmissionCapacity, InstalledRunCapacityError } from './installed-run-capacity.js';
import { openSqliteDriver } from './sqlite-driver.js';

// Approved read-only SQL seam: these are data rows in a real SQLite database,
// not Runs, StateOwner, installed authority or native qualification evidence.
function fixture(context: TestContext) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'cliq-installed-capacity-'));
  const database = path.join(directory, 'capacity.sqlite');
  const driver = openSqliteDriver(database);
  context.after(() => { driver.close(); rmSync(directory, { recursive: true, force: true }); });
  driver.exec('CREATE TABLE runs (id INTEGER PRIMARY KEY, status TEXT NOT NULL)');
  const add = (count: number, status: string) => driver.transaction(connection => {
    const insert = connection.prepare('INSERT INTO runs(status) VALUES (?)');
    for (let index = 0; index < count; index++) insert.run(status);
  });
  const check = () => driver.readSnapshot(assertInstalledRunAdmissionCapacity);
  return { driver, database, add, check };
}

test('installed admission has room at 999 active rows and refuses a new Run at 1000 without mutation', context => {
  const { driver, database, add, check } = fixture(context);
  add(999, 'queued');
  assert.doesNotThrow(check);
  add(1, 'queued');
  const before = driver.prepare('SELECT * FROM runs ORDER BY id').all();
  const changes = driver.prepare('SELECT total_changes() AS changes').get();
  const bytes = readFileSync(database);
  driver.exec('PRAGMA query_only=ON');
  assert.throws(check, error => {
    assert(error instanceof InstalledRunCapacityError);
    assert(Object.isFrozen(error.controlError));
    // The server returns this exact fixed projection; this is SQL/wire data
    // conformance, not a real installed 1000-Run UDS qualification.
    assert.deepEqual(parseJsonStrict(canonicalJsonBytes(error.controlError).toString('utf8')), Object.assign(Object.create(null), {
      schemaVersion: 1, code: 'RESOURCE_EXHAUSTED', retryable: true,
      messageCode: 'run.queue_capacity', resourceKind: 'run_queue', retryAfterMs: 1000
    }));
    return true;
  });
  assert.deepEqual(driver.prepare('SELECT * FROM runs ORDER BY id').all(), before);
  assert.deepEqual(driver.prepare('SELECT total_changes() AS changes').get(), changes);
  assert.deepEqual(readFileSync(database), bytes);
});

test('queued, running and waiting rows each occupy the same installed capacity', context => {
  const { driver, add, check } = fixture(context);
  for (const status of ['queued', 'running', 'waiting']) {
    driver.exec('DELETE FROM runs');
    add(999, status); assert.doesNotThrow(check);
    add(1, status);
    assert.throws(check, error => error instanceof InstalledRunCapacityError);
  }
});

test('each terminal state releases capacity without deleting retained history', context => {
  const { driver, add, check } = fixture(context);
  add(1000, 'queued');
  for (const status of ['succeeded', 'completed_unverified', 'failed', 'cancelled']) {
    add(10, status);
    assert.throws(check, error => error instanceof InstalledRunCapacityError);
    driver.prepare('UPDATE runs SET status=? WHERE id=1').run(status);
    assert.doesNotThrow(check);
    driver.prepare("UPDATE runs SET status='queued' WHERE id=1").run();
    assert.throws(check, error => error instanceof InstalledRunCapacityError);
  }
  assert.equal(driver.prepare('SELECT COUNT(*) AS count FROM runs').get<{ count: bigint }>()!.count, 1040n);
});

test('a retained inventory already beyond the bound cannot admit more work', context => {
  const { driver, add, check } = fixture(context);
  add(1001, 'waiting');
  const before = driver.prepare('SELECT * FROM runs ORDER BY id').all();
  driver.exec('PRAGMA query_only=ON');
  assert.throws(check, error => error instanceof InstalledRunCapacityError);
  assert.deepEqual(driver.prepare('SELECT * FROM runs ORDER BY id').all(), before);
});
