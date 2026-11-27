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
  KERNEL_SCHEMA_V5_SQL,
  KERNEL_SCHEMA_V6_SQL,
  readSchemaUserVersion
} from './schema.js';
import { openSqliteDriver } from './sqlite-driver.js';

const childV8Changes = new Set(['authorization_grants_list_order_v1', 'child_allocations_one_parent', 'child_allocations_one_admission',
  'child_allocations_one_delegate', 'child_allocations_one_call_index', 'child_allocations_one_call_id',
  'child_allocations_validate_insert', 'child_allocations_validate_update', 'child_allocations_immutable_delete',
  'run_journal_validate_insert', 'runs_parent_cancellation_unseeded', 'runs_parent_cancellation_immutable',
  'runs_parent_cancellation_register', 'runs_parent_cancellation_fenced']);
const parentCancellationColumn = ", parent_cancellation_ref TEXT\n  CHECK(parent_cancellation_ref IS NULL OR (typeof(parent_cancellation_ref)='text' AND length(parent_cancellation_ref)=64 AND parent_cancellation_ref NOT GLOB '*[^0-9a-f]*'))";
function originalRunColumns<T extends Record<string, unknown>>(row: T): T {
  if (row.name !== 'runs' || typeof row.sql !== 'string' || !row.sql.includes('parent_cancellation_ref')) return { ...row };
  assert.equal(row.sql.split(parentCancellationColumn).length, 2, 'only the exact schema-8 registered-parent column may be projected out');
  return { ...row, sql: row.sql.replace(parentCancellationColumn, '') };
}

test('schema v5 retains exact source history while adding only the apply method to its owning table', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-delivery-schema-upgrade-'));
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  const catalog = () => driver.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').all<{type: string;name: string;tbl_name: string;sql: string|null}>();
  const row = { inspectionId: 'original', principalId: 'principal', method: 'run.submit', admissionKey: 'retained', admissionIntentDigest: 'intent',
    workspaceIdentityDigest: 'workspace', phase: 'capturing', rowVersion: 1, cancelRequested: false };
  const insert = (method: string, id: string, workspace: string) => driver.prepare(`INSERT INTO source_inspection_attempts
    (inspection_id,principal_id,method,admission_key,admission_intent_digest,original_request_id,original_request_digest,
     workspace_identity_digest,phase,row_version,row_json) VALUES (?,'principal',?,'retained','intent',?,'digest',?,'capturing',1,?)`)
    .run(id, method, id, workspace, JSON.stringify({ ...row, inspectionId: id, method, workspaceIdentityDigest: workspace }));
  try {
    driver.transaction(connection => {
      connection.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
      connection.exec([KERNEL_SCHEMA_V1_SQL, KERNEL_SCHEMA_V2_SQL, KERNEL_SCHEMA_V3_SQL, KERNEL_SCHEMA_V4_SQL, KERNEL_SCHEMA_V5_SQL].join('\n'));
      connection.exec('PRAGMA user_version=5');
    });
    insert('run.submit', 'original', 'workspace');
    const original = driver.prepare('SELECT * FROM source_inspection_attempts').all();
    assert.throws(() => insert('run.apply', 'fresh-apply', 'other-workspace'), /CHECK constraint failed/);
    const before = catalog();
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    assert.deepEqual(driver.prepare('SELECT * FROM source_inspection_attempts').all(), original);
    const expected = before.map(entry => ({ ...entry, sql: entry.name === 'source_inspection_attempts'
      ? entry.sql!.replace("method = 'run.submit'", "method IN ('run.submit', 'run.apply')") : entry.sql }));
    const exceptHandoff = (entries: typeof expected) => entries.filter(entry => entry.name !== 'source_inspections_validate_update' && !childV8Changes.has(entry.name)).map(originalRunColumns);
    assert.deepEqual(exceptHandoff(catalog()), exceptHandoff(expected), 'no unrelated table, trigger, index or retained history may change');
    assert.match(catalog().find(entry => entry.name === 'source_inspections_validate_update')!.sql!, /source inspection handoff permits cleanup only/u);
    insert('run.apply', 'fresh-apply', 'other-workspace');
    assert.throws(() => insert('run.other', 'not-allowed', 'third-workspace'), /CHECK constraint failed/);
    assert.throws(() => driver.prepare('DELETE FROM source_inspection_attempts WHERE inspection_id=?').run('original'), /history is retained/);
    assert.throws(() => driver.prepare('UPDATE source_inspection_attempts SET method=? WHERE inspection_id=?').run('run.apply', 'original'), /identity is immutable/);
    const after = catalog(); applyKernelSchema(driver); assert.deepEqual(catalog(), after);
  } finally { driver.close(); await rm(stateRoot, { recursive: true, force: true }); }
});

test('failed apply schema migration rolls back original history, dropped guards and schema version together', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-delivery-schema-rollback-'));
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  const snapshot = () => ({ version: readSchemaUserVersion(driver),
    catalog: driver.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').all(),
    history: driver.prepare('SELECT * FROM source_inspection_attempts').all() });
  try {
    driver.transaction(connection => {
      connection.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
      connection.exec([KERNEL_SCHEMA_V1_SQL, KERNEL_SCHEMA_V2_SQL, KERNEL_SCHEMA_V3_SQL, KERNEL_SCHEMA_V4_SQL, KERNEL_SCHEMA_V5_SQL].join('\n'));
      connection.exec('PRAGMA user_version=5');
      // A real SQLite name collision fails after the migration drops its
      // guards. No mocked transaction or manufactured recovery fact is used.
      connection.exec('CREATE TABLE source_inspection_attempts_v5 (sentinel TEXT) STRICT');
    });
    const before = snapshot();
    assert.throws(() => applyKernelSchema(driver), /already another table|already exists/);
    assert.deepEqual(snapshot(), before);
    driver.exec('DROP TABLE source_inspection_attempts_v5'); applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
  } finally { driver.close(); await rm(stateRoot, { recursive: true, force: true }); }
});

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
      28n
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
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    const unchanged = (rows: ReturnType<typeof readCatalog>) => rows.filter(row => !childV8Changes.has(row.name) && row.name !== insertName && row.name !== updateName &&
      row.name !== 'source_inspections_validate_update')
      .map(row => originalRunColumns({ ...row, sql: row.name === 'source_inspection_attempts'
        ? row.sql!.replace("method = 'run.submit'", "method IN ('run.submit', 'run.apply')") : row.sql }));
    assert.deepEqual(unchanged(after), unchanged(before), 'every table, index and unrelated trigger must remain unchanged');
    assert.match(after.find(row => row.name === 'source_inspections_validate_update')!.sql!, /source inspection handoff permits cleanup only/u);
    const unretiredIndex = after.find(row => row.name === 'worker_launches_one_unretired_per_run');
    assert.equal(unretiredIndex?.type, 'index');
    assert.match(unretiredIndex!.sql!, /CREATE UNIQUE INDEX worker_launches_one_unretired_per_run\s+ON worker_launches\(run_id\) WHERE retired_at IS NULL/u);
    assert.equal(after.filter(row => row.type === 'trigger').length, 28);
    applyKernelSchema(driver);
    assert.deepEqual(readCatalog(), after, 'schema v5 application is idempotent');
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('schema v7 preserves original source rows and makes a once-only handoff cleanup-only at every prefix', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.cliq-source-handoff-schema-'));
  const driver = openSqliteDriver(path.join(directory, 'kernel.sqlite3'));
  try {
    driver.transaction(connection => {
      connection.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
      connection.exec(`${KERNEL_SCHEMA_V1_SQL}\n${KERNEL_SCHEMA_V2_SQL}\n${KERNEL_SCHEMA_V3_SQL}\n${KERNEL_SCHEMA_V4_SQL}\n${KERNEL_SCHEMA_V5_SQL}\n${KERNEL_SCHEMA_V6_SQL}`);
      connection.exec('PRAGMA user_version=6');
    });
    const catalog = () => driver.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').all();
    const before = catalog();
    // These are actual SQLite invariant fixtures only. They are not decoded
    // native source inputs, a signed handoff, or retirement evidence.
    for (const phase of ['capturing', 'prepared', 'active'] as const) {
      const base = { inspectionId: `inspection-${phase}`, principalId: 'principal', method: 'run.submit',
        admissionKey: `admission-${phase}`, admissionIntentDigest: 'a'.repeat(64), workspaceIdentityDigest: `workspace-${phase}`,
        phase: 'capturing', rowVersion: 1, cancelRequested: false, inputRef: '1'.repeat(64), inputDigest: '2'.repeat(64) };
      driver.prepare(`INSERT INTO source_inspection_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(base.inspectionId,
        base.principalId, base.method, base.admissionKey, base.admissionIntentDigest,
        `request-${phase}`, '3'.repeat(64), base.workspaceIdentityDigest, base.phase, base.rowVersion, JSON.stringify(base));
    }
    const original = driver.prepare('SELECT row_json FROM source_inspection_attempts ORDER BY inspection_id').all();
    applyKernelSchema(driver);
    assert.equal(readSchemaUserVersion(driver), KERNEL_STATE_SCHEMA_VERSION);
    assert.deepEqual(driver.prepare('SELECT row_json FROM source_inspection_attempts ORDER BY inspection_id').all(), original);
    const exceptUpdate = (values: typeof before) => values.filter(value => value.name !== 'source_inspections_validate_update' &&
      !(typeof value.name === 'string' && childV8Changes.has(value.name))).map(originalRunColumns);
    assert.deepEqual(exceptUpdate(catalog()), exceptUpdate(before), 'the existing table, rows, indexes and unrelated triggers are unchanged');
    for (const phase of ['capturing', 'prepared', 'active'] as const) {
      let row = JSON.parse(driver.prepare('SELECT row_json FROM source_inspection_attempts WHERE inspection_id=?')
        .get<{ row_json: string }>(`inspection-${phase}`)!.row_json) as Record<string, unknown>;
      const update = (next: Record<string, unknown>) => driver.prepare(`UPDATE source_inspection_attempts
        SET phase=?,row_version=?,row_json=? WHERE inspection_id=?`).run(next.phase as string, next.rowVersion as number,
        JSON.stringify(next), row.inspectionId as string);
      assert.throws(() => update({ ...row, inputRef: '9'.repeat(64), phase: 'prepared', plan: {}, rowVersion: 2 }),
        /first input is immutable/u);
      if (phase !== 'capturing') {
        row = { ...row, phase: 'prepared', plan: { fixture: 'data-only' }, rowVersion: 2 }; update(row);
      }
      if (phase === 'active') { row = { ...row, phase: 'active', processContainmentRef: '4'.repeat(64), rowVersion: 3 }; update(row); }
      assert.throws(() => update({ ...row, retirementHandoffRef: 'A'.repeat(64), rowVersion: Number(row.rowVersion) + 1 }), /handoff must be installed once/u);
      const handed = { ...row, retirementHandoffRef: '5'.repeat(64), rowVersion: Number(row.rowVersion) + 1 };
      update(handed); row = handed;
      for (const edit of [{ retirementHandoffRef: '6'.repeat(64) }, { retirementHandoffRef: null }, { inputRef: '6'.repeat(64) },
        ...(phase === 'capturing' ? [{ phase: 'prepared', plan: {} }] : phase === 'prepared' ? [{ phase: 'active', processContainmentRef: '6'.repeat(64) }] : [])])
        assert.throws(() => update({ ...row, ...edit, rowVersion: Number(row.rowVersion) + 1 }));
      const cancelled = { ...row, cancelRequested: true, rowVersion: Number(row.rowVersion) + 1 };
      update(cancelled); row = cancelled;
      const retired = { ...row, phase: 'retired', rowVersion: Number(row.rowVersion) + 1,
        retirementEvidenceRef: '7'.repeat(64), retiredAt: '2026-10-25T16:00:00.000Z', outcome: { kind: 'cancelled', errorResponseRef: '8'.repeat(64) } };
      update(retired); row = retired;
      assert.throws(() => update({ ...row, rowVersion: Number(row.rowVersion) + 1 }), /phase transition is invalid/u);
    }
    const migrated = catalog(); applyKernelSchema(driver); assert.deepEqual(catalog(), migrated);
  } finally { driver.close(); await rm(directory, { recursive: true, force: true }); }
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
