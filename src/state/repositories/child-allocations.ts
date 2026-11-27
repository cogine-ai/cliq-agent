import { parseJsonStrict } from '../../kernel/json.js';
import type { ChildAllocationV1 } from '../../kernel/types.js';
import { KernelStorageError } from '../errors.js';
import { decodeChildAllocation } from '../invariants.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';

type ChildAllocationSqlRow = {
  parent_run_id: string;
  child_run_id: string;
  state: string;
  row_json: string;
};

function childAllocationFromRow(row: ChildAllocationSqlRow): ChildAllocationV1 {
  let value: unknown;
  try {
    value = parseJsonStrict(row.row_json);
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'ChildAllocation row is not valid JSON');
  }
  let allocation: ChildAllocationV1;
  try {
    allocation = decodeChildAllocation(value);
  } catch (error) {
    if (error instanceof KernelStorageError) {
      throw new KernelStorageError('RECOVERY_REQUIRED', `invalid ChildAllocation row: ${error.message}`);
    }
    throw error;
  }
  if (
    allocation.parentRunId !== row.parent_run_id ||
    allocation.childRunId !== row.child_run_id ||
    allocation.state !== row.state
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'ChildAllocation columns do not match row_json');
  }
  return allocation;
}
export function readChildAllocationsForRun(
  connection: SqliteConnection | SqliteDriver,
  runId: string
): ChildAllocationV1[] {
  return connection
    .prepare(
      `SELECT parent_run_id, child_run_id, state, row_json FROM child_allocations
       WHERE parent_run_id = ? OR child_run_id = ?
       ORDER BY parent_run_id, child_run_id`
    )
    .all<ChildAllocationSqlRow>(runId, runId)
    .map(childAllocationFromRow);
}

/** One immutable parent link; multiple incoming rows never become a choice. */
export function readIncomingChildAllocation(connection: SqliteConnection | SqliteDriver, childRunId: string): ChildAllocationV1 | undefined {
  const rows = connection.prepare(`SELECT parent_run_id, child_run_id, state, row_json FROM child_allocations WHERE child_run_id = ? LIMIT 2`)
    .all<ChildAllocationSqlRow>(childRunId);
  if (rows.length > 1) throw new KernelStorageError('RECOVERY_REQUIRED', 'child Run has more than one registered parent');
  return rows[0] === undefined ? undefined : childAllocationFromRow(rows[0]);
}
