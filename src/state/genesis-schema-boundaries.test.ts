// Real SQLite/native StateOwner boundary. This portable bootstrap regression
// creates no Run, worker, signed-installation qualification or death evidence.
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { KernelStorageError } from './errors.js';
import { loadNativeStateOwner } from './native-owner.js';
import { applyKernelSchema, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, type StateStore } from './store.js';

async function unownedDatabase(container: string, name: string) {
  const stateRoot = path.join(container, name);
  await mkdir(stateRoot, { mode: 0o700 });
  await chmod(stateRoot, 0o700);
  await mkdir(path.join(stateRoot, 'runtime'), { mode: 0o700 });
  await writeFile(path.join(stateRoot, 'runtime', 'state-owner.lock'), '', { flag: 'wx', mode: 0o600 });
  const databasePath = path.join(stateRoot, KERNEL_DATABASE_FILENAME);
  const driver = openSqliteDriver(databasePath);
  try {
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    const tables = driver.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all<{ name: string }>();
    for (const { name: table } of tables) {
      assert.match(table, /^[a-z_]+$/u);
      assert.equal(driver.prepare(`SELECT count(*) AS count FROM ${table}`).get<{ count: bigint }>()!.count, 0n);
    }
  } finally { driver.close(); }
  return { stateRoot, databasePath };
}

function audit(databasePath: string) {
  const inspector = openSqliteDriver(databasePath);
  try {
    return {
      owners: inspector.prepare('SELECT owner_epoch, state FROM state_owners ORDER BY owner_epoch')
        .all<{ owner_epoch: bigint; state: string }>().map(row => ({ ...row })),
      pollution: inspector.prepare('SELECT * FROM mcp_registrations ORDER BY owner_principal_id, registration_id')
        .all().map(row => ({ ...row })),
      artifacts: inspector.prepare('SELECT count(*) AS count FROM artifacts').get<{ count: bigint }>()!.count,
      fences: inspector.prepare('SELECT count(*) AS count FROM canonical_time_fence').get<{ count: bigint }>()!.count,
      trigger: inspector.prepare("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = 'genesis_business_poison'")
        .get<{ sql: string }>()?.sql,
    };
  } finally { inspector.close(); }
}

test('genesis refuses a non-pristine schema whose extra trigger mutates business state during initial owner publication', async () => {
  const container = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-genesis-schema-')));
  await chmod(container, 0o700);
  let controlStore: StateStore | undefined;
  let alteredStore: StateStore | undefined;
  try {
    // A real canonical schema-v4 database is legal. Qualify the native owner
    // path first so an unrelated platform/lock failure cannot make RED green.
    const control = await unownedDatabase(container, 'canonical');
    controlStore = await openStateStore(control.stateRoot);
    assert.equal(controlStore.ownerEpoch, 1);
    const native = await loadNativeStateOwner();
    assert.throws(() => native.acquireLock(control.stateRoot, false), /OS lock is already held/u,
      'the successful Store must hold the actual native lock, not fixture ownership');
    await controlStore.close(); controlStore = undefined;
    assert.deepEqual(audit(control.databasePath).owners, [{ owner_epoch: 1n, state: 'terminal' }]);

    const altered = await unownedDatabase(container, 'extra-trigger');
    const writer = openSqliteDriver(altered.databasePath);
    try {
      writer.exec(`
        CREATE TRIGGER genesis_business_poison AFTER INSERT ON state_owners
        BEGIN
          INSERT INTO mcp_registrations
            (owner_principal_id, registration_id, current_revision, current_revision_ref)
          VALUES ('trigger-principal', 'unexpected-genesis-registration', 1, 'non-authoritative-trigger-data');
        END;
      `);
    } finally { writer.close(); }
    const before = audit(altered.databasePath);
    assert.deepEqual(before.owners, []);
    assert.deepEqual(before.pollution, []);
    assert.equal(before.artifacts, 0n); assert.equal(before.fences, 0n);
    assert.ok(before.trigger, 'the adversarial trigger must exist in the real SQLite schema');

    let rejection: unknown;
    let granted = false;
    try { alteredStore = await openStateStore(altered.stateRoot); granted = true; }
    catch (error) { rejection = error; }
    // Freeze the admission result, then actually join any incorrectly opened
    // Store before independently auditing the durable first-transaction result.
    if (alteredStore) { await alteredStore.close(); alteredStore = undefined; }
    const after = audit(altered.databasePath);
    assert.equal(after.trigger, before.trigger, 'opening must not silently repair the unowned schema');
    if (granted) {
      assert.deepEqual(after.owners, [{ owner_epoch: 1n, state: 'terminal' }], 'RED must really acquire and gracefully join epoch one');
      assert.deepEqual(after.pollution, [{ owner_principal_id: 'trigger-principal',
        registration_id: 'unexpected-genesis-registration', current_revision: 1n,
        current_revision_ref: 'non-authoritative-trigger-data' }], 'the real trigger must demonstrate business-state pollution');
      assert.ok(after.artifacts > 0n); assert.equal(after.fences, 1n);
    }
    const diagnostic = JSON.stringify(after, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value);
    assert.equal(granted, false, `genesis must reject a non-pristine schema before epoch one; durable audit=${diagnostic}`);
    assert(rejection instanceof KernelStorageError, 'refusal must report the kernel bootstrap boundary');
    assert.notEqual(rejection.code, 'UNSUPPORTED_PLATFORM');
    assert.deepEqual(after.owners, [], 'refusal must publish no initial StateOwner');
    assert.deepEqual(after.pollution, [], 'refusal must preserve the originally empty business table');
    assert.equal(after.artifacts, 0n); assert.equal(after.fences, 0n);
  } finally {
    await alteredStore?.close(); await controlStore?.close();
    await rm(container, { recursive: true, force: true });
  }
});
