import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { openSqliteDriver } from './sqlite-driver.js';
import { installedWorkerSlotAvailable, InstalledWorkerCapacityError } from './worker-capacity.js';

// Real SQLite data only. These rows create no WorkerLaunch, StateOwner or native proof.
function fixture(t: TestContext) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'cliq-worker-capacity-'));
  const file = path.join(root, 'data.sqlite'), driver = openSqliteDriver(file);
  t.after(() => { driver.close(); rmSync(root, { recursive: true, force: true }); });
  driver.exec('CREATE TABLE worker_launches(id INTEGER PRIMARY KEY,run_id TEXT NOT NULL,phase TEXT NOT NULL)');
  const add = (runId: string, phase: string) => driver.prepare('INSERT INTO worker_launches(run_id,phase) VALUES (?,?)').run(runId, phase);
  return { driver, file, add };
}

test('all unretired resources occupy their Run slot, including preparation and recovery, while retired history releases it', t => {
  const { driver, add } = fixture(t);
  for (const phase of ['preparing', 'reserved', 'preactivated', 'activated', 'unrecognized_retained_phase']) {
    driver.exec('DELETE FROM worker_launches'); add('original', phase);
    assert.equal(installedWorkerSlotAvailable(driver, 'new', 1), false);
    assert.equal(installedWorkerSlotAvailable(driver, 'new', 2), true);
    add('original', phase); // Retained records of one Run do not invent a second slot.
    assert.equal(installedWorkerSlotAvailable(driver, 'new', 2), true);
    assert.equal(installedWorkerSlotAvailable(driver, 'original', 1), true);
    driver.prepare("UPDATE worker_launches SET phase='retired'").run();
    assert.equal(installedWorkerSlotAvailable(driver, 'new', 1), true);
  }
});

test('the final SQLite transaction rejects a filled slot without committing a partial preparing row', t => {
  const { driver, file, add } = fixture(t); add('one', 'activated');
  assert.equal(installedWorkerSlotAvailable(driver, 'three', 2), true);
  const concurrent = openSqliteDriver(file);
  try {
    concurrent.prepare("INSERT INTO worker_launches(run_id,phase) VALUES ('two','preparing')").run();
    const before = driver.prepare('SELECT * FROM worker_launches ORDER BY id').all();
    assert.throws(() => driver.transaction(connection => {
      if (!installedWorkerSlotAvailable(connection, 'three', 2)) throw new InstalledWorkerCapacityError();
      connection.prepare("INSERT INTO worker_launches(run_id,phase) VALUES ('three','preparing')").run();
    }), InstalledWorkerCapacityError);
    assert.deepEqual(driver.prepare('SELECT * FROM worker_launches ORDER BY id').all(), before);
    concurrent.prepare("UPDATE worker_launches SET phase='retired' WHERE run_id='two'").run();
    driver.transaction(connection => {
      assert.equal(installedWorkerSlotAvailable(connection, 'three', 2), true);
      connection.prepare("INSERT INTO worker_launches(run_id,phase) VALUES ('three','preparing')").run();
    });
    assert.equal(installedWorkerSlotAvailable(driver, 'four', 2), false);
    assert.equal(installedWorkerSlotAvailable(driver, 'four', 1), false); // A lowered target does not revoke existing owners.
  } finally { concurrent.close(); }
});
