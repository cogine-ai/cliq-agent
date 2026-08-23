import type { WorkerLaunch } from '../../kernel/types.js';
import { KernelStorageError } from '../errors.js';
import { decodeWorkerLaunch } from '../invariants.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';

type WorkerLaunchSqlRow = {
  launch_id: string;
  run_id: string;
  phase: string;
  row_json: string;
  retired_at: string | null;
};

function workerLaunchFromRow(row: WorkerLaunchSqlRow): WorkerLaunch {
  let value: unknown;
  try {
    value = JSON.parse(row.row_json);
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'WorkerLaunch row is not valid JSON');
  }
  let launch: WorkerLaunch;
  try {
    launch = decodeWorkerLaunch(value);
  } catch (error) {
    if (error instanceof KernelStorageError) {
      throw new KernelStorageError('RECOVERY_REQUIRED', `invalid WorkerLaunch row: ${error.message}`);
    }
    throw error;
  }
  if (
    launch.launchId !== row.launch_id ||
    launch.runId !== row.run_id ||
    launch.phase !== row.phase ||
    (launch.retiredAt ?? null) !== row.retired_at
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'WorkerLaunch columns do not match row_json');
  }
  return launch;
}
export function readWorkerLaunch(
  connection: SqliteConnection | SqliteDriver,
  launchId: string
): WorkerLaunch | undefined {
  const row = connection
    .prepare('SELECT launch_id, run_id, phase, row_json, retired_at FROM worker_launches WHERE launch_id = ?')
    .get<WorkerLaunchSqlRow>(launchId);
  return row === undefined ? undefined : workerLaunchFromRow(row);
}

export function readRequiredWorkerLaunch(
  connection: SqliteConnection | SqliteDriver,
  launchId: string
): WorkerLaunch {
  const launch = readWorkerLaunch(connection, launchId);
  if (launch === undefined) throw new KernelStorageError('NOT_FOUND', `worker launch ${launchId} does not exist`);
  return launch;
}

export function readWorkerLaunchesForRun(
  connection: SqliteConnection | SqliteDriver,
  runId: string,
  unretiredOnly = false
): WorkerLaunch[] {
  const rows = connection
    .prepare(
      `SELECT launch_id, run_id, phase, row_json, retired_at FROM worker_launches
       WHERE run_id = ? ${unretiredOnly ? 'AND retired_at IS NULL' : ''}
       ORDER BY rowid`
    )
    .all<WorkerLaunchSqlRow>(runId);
  return rows.map(workerLaunchFromRow);
}

export function insertWorkerLaunch(connection: SqliteConnection, launch: WorkerLaunch): void {
  decodeWorkerLaunch(launch);
  connection
    .prepare(
      `INSERT INTO worker_launches (launch_id, run_id, phase, row_json, retired_at)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(launch.launchId, launch.runId, launch.phase, JSON.stringify(launch), launch.retiredAt ?? null);
}

export function updateWorkerLaunch(
  connection: SqliteConnection,
  expected: WorkerLaunch,
  next: WorkerLaunch
): void {
  decodeWorkerLaunch(next);
  if (next.launchId !== expected.launchId || next.runId !== expected.runId) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'WorkerLaunch identity cannot change');
  }
  const result = connection
    .prepare(
      `UPDATE worker_launches SET phase = ?, row_json = ?, retired_at = ?
       WHERE launch_id = ? AND phase = ? AND row_json = ?`
    )
    .run(
      next.phase,
      JSON.stringify(next),
      next.retiredAt ?? null,
      expected.launchId,
      expected.phase,
      JSON.stringify(expected)
    );
  if (result.changes !== 1n) throw new KernelStorageError('LEASE_FENCED', 'WorkerLaunch CAS failed');
}
