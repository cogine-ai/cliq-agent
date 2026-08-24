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
    value = JSON.parse(row.row_json);
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
