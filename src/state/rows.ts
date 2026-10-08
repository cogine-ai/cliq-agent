import { requiredSafeInteger } from '../kernel/identity.js';
import type {
  BudgetUsage,
  Checkpoint,
  Run,
  RunEvent,
  RunNextStep,
  RunStatus,
  RunTerminalReason,
  Session,
  WaitingReason
} from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import type { SqliteConnection, SqliteDriver, SqliteRow } from './sqlite-driver.js';

export const ZERO_BUDGET: BudgetUsage = {
  modelTokens: 0,
  costMicros: 0,
  toolCalls: 0,
  repairAttempts: 0
};

export const DEFAULT_RUN_BUDGETS: {
  wallTimeMs: number;
  modelTokens: number;
  costMicros: number;
  toolCalls: number;
  repairAttempts: number;
  childDepth: number;
  childConcurrency: number;
} = {
  wallTimeMs: 86_400_000,
  modelTokens: 2_000_000,
  costMicros: 10_000_000,
  toolCalls: 1_000,
  repairAttempts: 2,
  childDepth: 2,
  childConcurrency: 4
};

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export function sessionFromRow(row: SqliteRow): Session {
  const session: Session = {
    schemaVersion: 1,
    id: String(row.id),
    workspaceIdentityRef: String(row.workspace_identity_ref),
    contextRevision: requiredSafeInteger(row.context_revision, 'contextRevision'),
    latestItemSeq: requiredSafeInteger(row.latest_item_seq, 'latestItemSeq'),
    contextProjectionRef: String(row.context_projection_ref),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at)
  };
  const name = optionalString(row.name);
  if (name !== undefined) session.name = name;
  const parent = optionalString(row.parent_session_id);
  if (parent !== undefined) session.parentSessionId = parent;
  if (row.forked_through_item_seq !== null && row.forked_through_item_seq !== undefined) {
    session.forkedThroughItemSeq = requiredSafeInteger(row.forked_through_item_seq, 'forkedThroughItemSeq');
  }
  return session;
}

export function runFromRow(row: SqliteRow): Run {
  const run: Run = {
    id: String(row.id),
    sessionId: String(row.session_id),
    specRef: String(row.spec_ref),
    status: String(row.status) as RunStatus,
    nextStep: row.next_step === null ? null : (String(row.next_step) as RunNextStep),
    revision: requiredSafeInteger(row.revision, 'revision'),
    leaseEpoch: requiredSafeInteger(row.lease_epoch, 'leaseEpoch'),
    latestCheckpointId: String(row.latest_checkpoint_id),
    budgetReserved: JSON.parse(String(row.budget_reserved_json)) as BudgetUsage,
    budgetConsumed: JSON.parse(String(row.budget_consumed_json)) as BudgetUsage,
    repairCount: requiredSafeInteger(row.repair_count, 'repairCount'),
    cancelRequested: requiredSafeInteger(row.cancel_requested, 'cancelRequested') === 1,
    createdAt: String(row.created_at),
    deadlineAt: String(row.deadline_at),
    updatedAt: String(row.updated_at)
  };
  const parent = optionalString(row.parent_run_id);
  if (parent !== undefined) run.parentRunId = parent;
  const frontier = optionalString(row.frontier_ref);
  if (frontier !== undefined) run.frontierRef = frontier;
  const waitingReason = optionalString(row.waiting_reason);
  if (waitingReason !== undefined) run.waitingReason = waitingReason as WaitingReason;
  const waitingOn = optionalString(row.waiting_on_ref);
  if (waitingOn !== undefined) run.waitingOnRef = waitingOn;
  const launch = optionalString(row.active_worker_launch_id);
  if (launch !== undefined) run.activeWorkerLaunchId = launch;
  const result = optionalString(row.result_ref);
  if (result !== undefined) run.resultRef = result;
  const terminalReason = optionalString(row.terminal_reason);
  if (terminalReason !== undefined) run.terminalReason = terminalReason as RunTerminalReason;
  const terminalDetail = optionalString(row.terminal_detail_ref);
  if (terminalDetail !== undefined) run.terminalDetailRef = terminalDetail;
  const stopIntent = optionalString(row.stop_intent_ref);
  if (stopIntent !== undefined) run.stopIntentRef = stopIntent;
  return run;
}

export function checkpointFromRow(row: SqliteRow): Checkpoint {
  return {
    id: String(row.id),
    schemaVersion: 1,
    runId: String(row.run_id),
    basedOnRunRevision: requiredSafeInteger(row.based_on_run_revision, 'basedOnRunRevision'),
    runItemSeq: requiredSafeInteger(row.run_item_seq, 'runItemSeq'),
    contextManifestRef: String(row.context_manifest_ref),
    journalSeq: requiredSafeInteger(row.journal_seq, 'journalSeq'),
    workspaceStateRef: String(row.workspace_state_ref),
    createdAt: String(row.created_at),
    reason: String(row.reason) as Checkpoint['reason']
  };
}

export function readSession(connection: SqliteConnection | SqliteDriver, sessionId: string): Session {
  const row = connection.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
  if (row === undefined) {
    throw new KernelStorageError('NOT_FOUND', `session ${sessionId} does not exist`);
  }
  return sessionFromRow(row);
}

export function readSessionPrincipalId(connection: SqliteConnection | SqliteDriver, sessionId: string): string {
  const row = connection.prepare('SELECT principal_id FROM sessions WHERE id = ?').get<{ principal_id: string }>(sessionId);
  if (row === undefined) {
    throw new KernelStorageError('NOT_FOUND', `session ${sessionId} does not exist`);
  }
  return String(row.principal_id);
}

export function readRun(connection: SqliteConnection | SqliteDriver, runId: string): Run {
  const row = connection.prepare('SELECT * FROM runs WHERE id = ?').get(runId);
  if (row === undefined) {
    throw new KernelStorageError('NOT_FOUND', `run ${runId} does not exist`);
  }
  return runFromRow(row);
}

export function readCheckpoint(connection: SqliteConnection | SqliteDriver, checkpointId: string): Checkpoint {
  const row = connection.prepare('SELECT * FROM checkpoints WHERE id = ?').get(checkpointId);
  if (row === undefined) {
    throw new KernelStorageError('NOT_FOUND', `checkpoint ${checkpointId} does not exist`);
  }
  return checkpointFromRow(row);
}

export type AdmissionReplayRow = {
  admissionIntentDigest: string;
  admissionRequestId: string | null;
  id: string;
};

export function readAdmissionReplay(
  connection: SqliteConnection | SqliteDriver,
  table: 'sessions' | 'runs',
  principalId: string,
  method: string,
  admissionKey: string
): AdmissionReplayRow | undefined {
  const row = connection
    .prepare(
      `SELECT id, admission_intent_digest, admission_request_id FROM ${table}
       WHERE principal_id = ? AND admission_method = ? AND admission_key = ?`
    )
    .get<{ id: string; admission_intent_digest: string; admission_request_id: string | null }>(principalId, method, admissionKey);
  return row === undefined
    ? undefined
    : { id: row.id, admissionIntentDigest: row.admission_intent_digest, admissionRequestId: row.admission_request_id };
}

export function readControlRequest(
  connection: SqliteConnection | SqliteDriver,
  principalId: string,
  method: string,
  requestId: string
): { requestDigest: string; responseRef: string; channelIdentityRef: string; channelIdentityDigest: string; committedAt: string } | undefined {
  const row = connection
    .prepare(
      `SELECT request_digest, response_ref, channel_identity_ref, channel_identity_digest, committed_at FROM control_requests
       WHERE principal_id = ? AND method = ? AND request_id = ?`
    )
    .get<{ request_digest: string; response_ref: string; channel_identity_ref: string; channel_identity_digest: string; committed_at: string }>(principalId, method, requestId);
  return row === undefined
    ? undefined
    : { requestDigest: row.request_digest, responseRef: row.response_ref, channelIdentityRef: row.channel_identity_ref,
      channelIdentityDigest: row.channel_identity_digest, committedAt: row.committed_at };
}

export function insertControlRequest(
  connection: SqliteConnection,
  input: {
    principalId: string;
    method: string;
    requestId: string;
    channelIdentityRef: string;
    channelIdentityDigest: string;
    requestDigest: string;
    responseRef: string;
    committedAt: string;
  }
): void {
  connection
    .prepare(
      `INSERT INTO control_requests (
         principal_id, method, request_id, channel_identity_ref, channel_identity_digest,
         request_digest, response_ref, response_revision, committed_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`
    )
    .run(
      input.principalId,
      input.method,
      input.requestId,
      input.channelIdentityRef,
      input.channelIdentityDigest,
      input.requestDigest,
      input.responseRef,
      input.committedAt
    );
}

export function insertRunEvent(connection: SqliteConnection, event: Extract<RunEvent, { kind: 'state_changed' }>): void {
  connection
    .prepare('INSERT INTO run_events (run_id, event_seq, payload_json, occurred_at) VALUES (?, ?, ?, ?)')
    .run(event.runId, BigInt(event.eventSeq), JSON.stringify(event), event.occurredAt);
}

function requireBudgetField(value: number, label: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new KernelStorageError('INVALID_REQUEST', `${label} is outside ${min}..${max}`);
  }
  return value;
}

export function mergeBudgets(
  overrides?: Partial<typeof DEFAULT_RUN_BUDGETS>
): typeof DEFAULT_RUN_BUDGETS {
  const budgets = { ...DEFAULT_RUN_BUDGETS, ...overrides };
  return {
    wallTimeMs: requireBudgetField(budgets.wallTimeMs, 'wallTimeMs', 1_000, 2_592_000_000),
    modelTokens: requireBudgetField(budgets.modelTokens, 'modelTokens', 1, 100_000_000),
    costMicros: requireBudgetField(budgets.costMicros, 'costMicros', 1, 1_000_000_000_000),
    toolCalls: requireBudgetField(budgets.toolCalls, 'toolCalls', 1, 1_000_000),
    repairAttempts: requireBudgetField(budgets.repairAttempts, 'repairAttempts', 0, 64),
    childDepth: requireBudgetField(budgets.childDepth, 'childDepth', 0, 8),
    childConcurrency: requireBudgetField(budgets.childConcurrency, 'childConcurrency', 1, 64)
  };
}
