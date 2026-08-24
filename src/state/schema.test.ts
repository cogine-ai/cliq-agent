import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_SQLITE_APPLICATION_ID, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import {
  applyKernelSchema,
  KERNEL_SCHEMA_SQL,
  KERNEL_SCHEMA_V1_SQL,
  readSchemaUserVersion
} from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';

test('applyKernelSchema creates the twenty-table M2 authority layout and state-machine guards', async () => {
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
      16n
    );
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
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
