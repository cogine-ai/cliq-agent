import type { WorkspaceGenerationStateV1 } from '../../kernel/types.js';
import { KernelStorageError } from '../errors.js';
import { decodeWorkspaceGenerationState } from '../invariants.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';

type WorkspaceGenerationSqlRow = {
  generation_id: string;
  run_id: string;
  phase: string;
  row_version: unknown;
  row_json: string;
};

function workspaceGenerationFromRow(row: WorkspaceGenerationSqlRow): WorkspaceGenerationStateV1 {
  let value: unknown;
  try {
    value = JSON.parse(row.row_json);
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'workspace generation row is not valid JSON');
  }
  let generation: WorkspaceGenerationStateV1;
  try {
    generation = decodeWorkspaceGenerationState(value);
  } catch (error) {
    if (error instanceof KernelStorageError) {
      throw new KernelStorageError('RECOVERY_REQUIRED', `invalid workspace generation row: ${error.message}`);
    }
    throw error;
  }
  if (
    generation.generationId !== row.generation_id ||
    generation.runId !== row.run_id ||
    generation.phase !== row.phase ||
    generation.rowVersion !== Number(row.row_version)
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'workspace generation columns do not match row_json');
  }
  return generation;
}

export function readWorkspaceGeneration(
  connection: SqliteConnection | SqliteDriver,
  generationId: string
): WorkspaceGenerationStateV1 | undefined {
  const row = connection
    .prepare(
      `SELECT generation_id, run_id, phase, row_version, row_json
       FROM workspace_generations WHERE generation_id = ?`
    )
    .get<WorkspaceGenerationSqlRow>(generationId);
  return row === undefined ? undefined : workspaceGenerationFromRow(row);
}

export function readRequiredWorkspaceGeneration(
  connection: SqliteConnection | SqliteDriver,
  generationId: string
): WorkspaceGenerationStateV1 {
  const generation = readWorkspaceGeneration(connection, generationId);
  if (generation === undefined) {
    throw new KernelStorageError('NOT_FOUND', `workspace generation ${generationId} does not exist`);
  }
  return generation;
}

export function readRequiredWorkspaceGenerationByRef(
  connection: SqliteConnection | SqliteDriver,
  generationRef: string
): WorkspaceGenerationStateV1 {
  const rows = connection
    .prepare(
      `SELECT generation_id, run_id, phase, row_version, row_json
       FROM workspace_generations
       WHERE json_extract(row_json, '$.generationRef') = ?`
    )
    .all<WorkspaceGenerationSqlRow>(generationRef);
  if (rows.length !== 1) {
    throw new KernelStorageError(
      'RECOVERY_REQUIRED',
      rows.length === 0
        ? 'workspace generation reference has no authoritative row'
        : 'workspace generation reference resolves to multiple authoritative rows'
    );
  }
  return workspaceGenerationFromRow(rows[0]!);
}

export function readWorkspaceGenerationsForRun(
  connection: SqliteConnection | SqliteDriver,
  runId: string,
  unretiredOnly = false
): WorkspaceGenerationStateV1[] {
  return connection
    .prepare(
      `SELECT generation_id, run_id, phase, row_version, row_json
       FROM workspace_generations WHERE run_id = ? ${unretiredOnly ? "AND phase != 'retired'" : ''}
       ORDER BY rowid`
    )
    .all<WorkspaceGenerationSqlRow>(runId)
    .map(workspaceGenerationFromRow);
}

export function insertWorkspaceGeneration(
  connection: SqliteConnection,
  generation: WorkspaceGenerationStateV1
): void {
  decodeWorkspaceGenerationState(generation);
  connection
    .prepare(
      `INSERT INTO workspace_generations (generation_id, run_id, phase, row_version, row_json)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(
      generation.generationId,
      generation.runId,
      generation.phase,
      BigInt(generation.rowVersion),
      JSON.stringify(generation)
    );
}

export function updateWorkspaceGeneration(
  connection: SqliteConnection,
  expected: WorkspaceGenerationStateV1,
  next: WorkspaceGenerationStateV1
): void {
  decodeWorkspaceGenerationState(next);
  if (
    next.generationId !== expected.generationId ||
    next.runId !== expected.runId ||
    next.rowVersion !== expected.rowVersion + 1
  ) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'workspace generation CAS identity/version is invalid');
  }
  const result = connection
    .prepare(
      `UPDATE workspace_generations SET phase = ?, row_version = ?, row_json = ?
       WHERE generation_id = ? AND phase = ? AND row_version = ? AND row_json = ?`
    )
    .run(
      next.phase,
      BigInt(next.rowVersion),
      JSON.stringify(next),
      expected.generationId,
      expected.phase,
      BigInt(expected.rowVersion),
      JSON.stringify(expected)
    );
  if (result.changes !== 1n) {
    throw new KernelStorageError('LEASE_FENCED', 'workspace generation CAS failed');
  }
}
