import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { applyKernelSchema, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';

test('applyKernelSchema creates the twenty-table M1 authority layout', async () => {
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
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});
