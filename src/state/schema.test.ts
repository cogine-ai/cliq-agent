import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_SQLITE_APPLICATION_ID, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import {
  applyKernelSchema,
  KERNEL_SCHEMA_SQL,
  KERNEL_SCHEMA_V1_SQL,
  KERNEL_SCHEMA_V2_SQL,
  KERNEL_SCHEMA_V3_SQL,
  KERNEL_SCHEMA_V4_SQL,
  readSchemaUserVersion
} from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';

test('schema version is readable within the same read-only WAL snapshot as owner state', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-schema-read-cut-'));
  const databasePath = path.join(stateRoot, 'kernel.sqlite3');
  const reader = openSqliteDriver(databasePath);
  const writer = openSqliteDriver(databasePath);
  try {
    applyKernelSchema(reader);
    reader.exec('PRAGMA journal_mode=WAL');
    const version = reader.readSnapshot(connection => {
      // Capture a real database cut before the concurrent writer commits.
      connection.prepare('SELECT count(*) FROM state_owners').get();
      assert.equal(readSchemaUserVersion(connection), KERNEL_STATE_SCHEMA_VERSION);
      writer.transaction(other => other.exec(`PRAGMA user_version=${KERNEL_STATE_SCHEMA_VERSION + 1}`));
      assert.equal(readSchemaUserVersion(connection), KERNEL_STATE_SCHEMA_VERSION);
      assert.throws(() => connection.exec(`PRAGMA user_version=${KERNEL_STATE_SCHEMA_VERSION + 2}`), /connection settings are reserved/);
      return readSchemaUserVersion(connection);
    });
    assert.equal(version, KERNEL_STATE_SCHEMA_VERSION);
    assert.equal(reader.readSnapshot(readSchemaUserVersion), KERNEL_STATE_SCHEMA_VERSION + 1);
    assert.equal(readSchemaUserVersion(writer), KERNEL_STATE_SCHEMA_VERSION + 1);
  } finally {
    writer.close(); reader.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('applyKernelSchema includes pre-admission source inspection in the authority layout', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-m1-schema-'));
  await chmod(stateRoot, 0o700);
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    const tables = driver
      .prepare(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
      .all<{ name: string }>()
      .map((row) => row.name);
    assert.deepEqual(tables, [
      'admin_operations',
      'artifacts',
      'authorization_grants',
      'canonical_time_fence',
      'checkpoints',
      'child_allocations',
      'control_requests',
      'items',
      'list_read_cut_entries',
      'list_read_cuts',
      'local_inference_activation_cycles',
      'local_inference_launches',
      'mcp_registrations',
      'run_events',
      'run_journal',
      'runs',
      'sessions',
      'source_inspection_attempts',
      'state_owners',
      'worker_launches',
      'workspace_generations'
    ]);
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    const activeOwnerIndex = driver
      .prepare(`SELECT name FROM sqlite_schema WHERE type = 'index' AND name = 'state_owners_one_active'`)
      .get<{ name: string }>();
    assert.equal(activeOwnerIndex?.name, 'state_owners_one_active');
    const guardNames = driver
      .prepare(`SELECT name FROM sqlite_schema WHERE type = 'trigger' ORDER BY name`)
      .all<{ name: string }>()
      .map((row) => row.name);
    assert.ok(guardNames.includes('run_journal_validate_insert'));
    assert.ok(guardNames.includes('worker_launches_validate_update'));
    assert.ok(guardNames.includes('workspace_generations_validate_update'));
    assert.ok(guardNames.includes('state_owners_immutable_delete'));
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('schema v1 upgrades atomically to the M2 invariant layer', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-m2-schema-upgrade-'));
  await chmod(stateRoot, 0o700);
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    driver.transaction((connection) => {
      connection.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
      connection.exec(KERNEL_SCHEMA_V1_SQL);
      connection.exec('PRAGMA user_version=1');
    });
    assert.equal(readSchemaUserVersion(driver), 1);
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    assert.equal(
      driver
        .prepare(`SELECT count(*) AS count FROM sqlite_schema WHERE type = 'trigger'`)
        .get<{ count: unknown }>()?.count,
      21n
    );
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('schema v4 migration adds preparing to the same WorkerLaunch spine without changing other schema history', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-worker-preparing-schema-'));
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  const readCatalog = () => driver.prepare('SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name')
    .all<{ type: string; name: string; tbl_name: string; sql: string | null }>();
  try {
    driver.transaction(connection => {
      connection.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
      connection.exec(`${KERNEL_SCHEMA_V1_SQL}\n${KERNEL_SCHEMA_V2_SQL}\n${KERNEL_SCHEMA_V3_SQL}\n${KERNEL_SCHEMA_V4_SQL}`);
      connection.exec('PRAGMA user_version=4');
    });
    assert.equal(readSchemaUserVersion(driver), 4);
    const before = readCatalog();
    const insertName = 'worker_launches_validate_insert', updateName = 'worker_launches_validate_update';
    assert.doesNotMatch(before.find(row => row.name === insertName)!.sql!, /'preparing'/u);

    // This reads the actual SQLite layout, not a launch, StateOwner or native proof.
    applyKernelSchema(driver);
    const after = readCatalog();
    const insert = after.find(row => row.name === insertName)!.sql!;
    const update = after.find(row => row.name === updateName)!.sql!;
    assert.match(insert, /NEW\.phase NOT IN \('preparing', 'reserved', 'preactivated', 'activated', 'reconciling', 'retired'\)/u);
    assert.match(update, /OLD\.phase = 'preparing' AND NEW\.phase IN \('preparing', 'reserved', 'retired'\)/u);
    for (const edge of [
      "OLD.phase = 'reserved' AND NEW.phase IN ('preactivated', 'retired')",
      "OLD.phase = 'preactivated' AND NEW.phase IN ('activated', 'retired')",
      "OLD.phase = 'activated' AND NEW.phase IN ('activated', 'reconciling', 'retired')",
      "OLD.phase = 'reconciling' AND NEW.phase = 'retired'"
    ]) assert.ok(update.includes(edge), `retained WorkerLaunch edge: ${edge}`);
    for (const trigger of [insert, update]) assert.ok(trigger.includes("WHEN (NEW.phase = 'retired') != (NEW.retired_at IS NOT NULL)"));
    assert.ok(update.includes('WHEN NEW.launch_id != OLD.launch_id OR NEW.run_id != OLD.run_id'));
    assert.equal(readSchemaUserVersion(driver), 5);
    const unchanged = (rows: ReturnType<typeof readCatalog>) => rows.filter(row => row.name !== insertName && row.name !== updateName);
    assert.deepEqual(unchanged(after), unchanged(before), 'every table, index and other trigger must remain unchanged');
    const unretiredIndex = after.find(row => row.name === 'worker_launches_one_unretired_per_run');
    assert.equal(unretiredIndex?.type, 'index');
    assert.match(unretiredIndex!.sql!, /CREATE UNIQUE INDEX worker_launches_one_unretired_per_run\s+ON worker_launches\(run_id\) WHERE retired_at IS NULL/u);
    assert.equal(after.filter(row => row.type === 'trigger').length, 21);
    applyKernelSchema(driver);
    assert.deepEqual(readCatalog(), after, 'schema v5 application is idempotent');
    assert.equal(readSchemaUserVersion(driver), 5);
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('SQLite fences source inspection phase, admission key and workspace reservations', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-source-inspection-schema-'));
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    applyKernelSchema(driver);
    // This exercises the SQL invariant seam, not a native resource receipt.
    const capturing = { inspectionId: 'inspection', principalId: 'principal', method: 'run.submit',
      admissionKey: 'abcdefghijklmnopqrstuv', admissionIntentDigest: 'a'.repeat(64), workspaceIdentityDigest: 'b'.repeat(64),
      phase: 'capturing', rowVersion: 1, cancelRequested: false };
    const originalRequestId = '0199b011-1111-7111-8111-111111111111';
    driver.prepare(`INSERT INTO source_inspection_attempts
      (inspection_id, principal_id, method, admission_key, admission_intent_digest, original_request_id, original_request_digest,
       workspace_identity_digest, phase, row_version, row_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(capturing.inspectionId, capturing.principalId, capturing.method,
      capturing.admissionKey, capturing.admissionIntentDigest, originalRequestId,
      'a'.repeat(64), capturing.workspaceIdentityDigest, capturing.phase, 1n, JSON.stringify(capturing));
    assert.throws(() => driver.prepare(`UPDATE source_inspection_attempts SET phase = 'active', row_version = 2, row_json = ?
      WHERE inspection_id = 'inspection'`).run(JSON.stringify({ ...capturing, phase: 'active', rowVersion: 2 })),
    /source inspection phase transition is invalid/);
    const insert = (next: typeof capturing, originalId = next.inspectionId) => driver.prepare(`INSERT INTO source_inspection_attempts
      (inspection_id, principal_id, method, admission_key, admission_intent_digest, original_request_id, original_request_digest,
       workspace_identity_digest, phase, row_version, row_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(next.inspectionId, next.principalId, next.method,
      next.admissionKey, next.admissionIntentDigest, originalId, 'a'.repeat(64), next.workspaceIdentityDigest, next.phase, 1n, JSON.stringify(next));
    assert.throws(() => insert({ ...capturing, inspectionId: 'same-key', workspaceIdentityDigest: 'c'.repeat(64) }), /UNIQUE constraint/);
    assert.throws(() => insert({ ...capturing, inspectionId: 'same-workspace', admissionKey: 'zyxwvutsrqponmlkjihgfe' }), /UNIQUE constraint/);
    assert.throws(() => insert({ ...capturing, inspectionId: 'same-request', admissionKey: 'different-admission-key',
      workspaceIdentityDigest: 'c'.repeat(64) }, originalRequestId), /UNIQUE constraint/);
    assert.throws(() => driver.prepare('DELETE FROM source_inspection_attempts').run(), /source inspection history is retained/);
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('a failed schema transaction leaves user_version at 0 and no kernel tables', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-m1-schema-rollback-'));
  await chmod(stateRoot, 0o700);
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    assert.throws(() => {
      driver.transaction((connection) => {
        connection.exec(KERNEL_SCHEMA_SQL);
        throw new Error('boom');
      });
    }, /boom/);
    assert.equal(readSchemaUserVersion(driver), 0);
    const tables = driver
      .prepare(`SELECT count(*) AS count FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
      .get<{ count: unknown }>();
    assert.equal(Number(tables?.count), 0);
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('schema application refuses to relabel a foreign versioned database', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-m2-schema-foreign-'));
  await chmod(stateRoot, 0o700);
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    driver.exec('PRAGMA application_id=1234; PRAGMA user_version=2');
    assert.throws(() => applyKernelSchema(driver), /foreign application_id/);
    assert.equal(
      driver.prepare('PRAGMA application_id').get<{ application_id: unknown }>()?.application_id,
      1234n
    );
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});
