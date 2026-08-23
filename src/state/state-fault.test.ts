import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { applyKernelSchema } from './schema.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';

const NOW = '2026-08-24T00:00:00.000Z';
const ZERO = JSON.stringify({ modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 });

function seedRun(driver: SqliteDriver): void {
  driver.transaction((connection) => {
    connection
      .prepare(
        `INSERT INTO sessions (
           id, workspace_identity_ref, name, parent_session_id, forked_through_item_seq,
           context_revision, latest_item_seq, context_projection_ref, created_at, updated_at,
           principal_id, admission_method, admission_key, admission_intent_digest
         ) VALUES ('session-1', 'workspace-ref', NULL, NULL, NULL, 1, 0, 'context-ref', ?, ?,
                   'principal-1', 'session.create', 'session-key', 'session-intent')`
      )
      .run(NOW, NOW);
    connection
      .prepare(
        `INSERT INTO checkpoints (
           id, schema_version, run_id, based_on_run_revision, run_item_seq,
           context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason
         ) VALUES ('checkpoint-1', 1, 'run-1', 0, 0, 'context-manifest-ref', 0,
                   'workspace-state-ref', ?, 'initial')`
      )
      .run(NOW);
    connection
      .prepare(
        `INSERT INTO runs (
           id, session_id, parent_run_id, spec_ref, status, next_step, frontier_ref,
           waiting_reason, waiting_on_ref, revision, lease_epoch, active_worker_launch_id,
           latest_checkpoint_id, budget_reserved_json, budget_consumed_json, repair_count,
           result_ref, terminal_reason, terminal_detail_ref, stop_intent_ref, cancel_requested,
           created_at, deadline_at, updated_at, principal_id, admission_method, admission_key,
           admission_intent_digest, admitted_request_digest
         ) VALUES ('run-1', 'session-1', NULL, 'spec-ref', 'queued', 'agent', 'frontier-ref',
                   NULL, NULL, 1, 0, NULL, 'checkpoint-1', ?, ?, 0, NULL, NULL, NULL, NULL, 0,
                   ?, '2026-08-25T00:00:00.000Z', ?, 'principal-1', 'run.submit', 'run-key',
                   'run-intent', 'run-request')`
      )
      .run(ZERO, ZERO, NOW, NOW);
  });
}

test('forced reducer failure rolls back Journal and Run budget together', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-m2-fault-rollback-'));
  await chmod(stateRoot, 0o700);
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    applyKernelSchema(driver);
    seedRun(driver);
    const reservation = JSON.stringify({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
    assert.throws(
      () => driver.transaction((connection) => {
        connection
          .prepare(
            `INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json)
             VALUES ('run-1', 1, 'op-1', 'tool', 0, 'prepared', '{}')`
          )
          .run();
        connection
          .prepare(`UPDATE runs SET budget_reserved_json = ?, revision = 2 WHERE id = 'run-1'`)
          .run(reservation);
        throw new Error('injected crash before commit');
      }),
      /injected crash/
    );
    assert.equal(
      driver.prepare(`SELECT count(*) AS count FROM run_journal`).get<{ count: unknown }>()?.count,
      0n
    );
    const run = driver
      .prepare(`SELECT revision, budget_reserved_json FROM runs WHERE id = 'run-1'`)
      .get<{ revision: unknown; budget_reserved_json: string }>();
    assert.equal(run?.revision, 1n);
    assert.equal(run?.budget_reserved_json, ZERO);
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('physical guards reject history rewrites and direct lifecycle skips', async () => {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-m2-fault-guards-'));
  await chmod(stateRoot, 0o700);
  const driver = openSqliteDriver(path.join(stateRoot, 'kernel.sqlite3'));
  try {
    applyKernelSchema(driver);
    seedRun(driver);
    driver
      .prepare(
        `INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json)
         VALUES ('run-1', 1, 'op-1', 'tool', 0, 'prepared', '{}')`
      )
      .run();
    assert.throws(
      () => driver.prepare(`UPDATE run_journal SET entry_json = '{"changed":true}'`).run(),
      /append-only/
    );
    assert.throws(() => driver.prepare(`DELETE FROM run_journal`).run(), /append-only/);

    driver
      .prepare(
        `INSERT INTO workspace_generations (generation_id, run_id, phase, row_version, row_json)
         VALUES ('generation-1', 'run-1', 'materializing', 1, '{}')`
      )
      .run();
    assert.throws(
      () => driver
        .prepare(
          `UPDATE workspace_generations SET phase = 'sealed', row_version = 2, row_json = '{}'
           WHERE generation_id = 'generation-1'`
        )
        .run(),
      /phase transition is invalid/
    );
    assert.throws(
      () => driver
        .prepare(
          `UPDATE workspace_generations SET phase = 'preactivated_readonly', row_version = 3,
             row_json = '{}' WHERE generation_id = 'generation-1'`
        )
        .run(),
      /row version must increment by one/
    );
    driver
      .prepare(
        `INSERT INTO workspace_generations (generation_id, run_id, phase, row_version, row_json)
         VALUES ('generation-2', 'run-1', 'materializing', 1, '{"generationRef":"same-ref"}')`
      )
      .run();
    assert.throws(
      () => driver
        .prepare(
          `INSERT INTO workspace_generations (generation_id, run_id, phase, row_version, row_json)
           VALUES ('generation-3', 'run-1', 'materializing', 1, '{"generationRef":"same-ref"}')`
        )
        .run(),
      /UNIQUE constraint failed/
    );

    driver
      .prepare(
        `INSERT INTO worker_launches (launch_id, run_id, phase, row_json, retired_at)
         VALUES ('launch-1', 'run-1', 'reserved', '{}', NULL)`
      )
      .run();
    assert.throws(
      () => driver
        .prepare(
          `UPDATE worker_launches SET phase = 'activated', row_json = '{}'
           WHERE launch_id = 'launch-1'`
        )
        .run(),
      /phase transition is invalid/
    );
  } finally {
    driver.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});
