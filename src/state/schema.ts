import {
  KERNEL_SQLITE_APPLICATION_ID,
  KERNEL_SQLITE_BUSY_TIMEOUT_MS,
  KERNEL_STATE_SCHEMA_VERSION
} from '../config.js';
import { requiredSafeInteger } from '../kernel/identity.js';
import type { SqliteDriver } from './sqlite-driver.js';

export const KERNEL_SCHEMA_V1_SQL = `
CREATE TABLE canonical_time_fence (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state_owner_epoch INTEGER NOT NULL,
  last_accepted_at TEXT NOT NULL,
  observed_wall_clock_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('healthy', 'clock_regressed')),
  updated_at TEXT NOT NULL,
  fence_digest TEXT NOT NULL
) STRICT;

CREATE TABLE state_owners (
  owner_epoch INTEGER PRIMARY KEY,
  supervisor_instance_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'terminal')),
  row_digest TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX state_owners_one_active ON state_owners(state) WHERE state = 'active';

CREATE TABLE artifacts (
  ref TEXT PRIMARY KEY,
  media_type TEXT NOT NULL,
  schema_kind TEXT NOT NULL,
  byte_length INTEGER NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  workspace_identity_ref TEXT NOT NULL,
  name TEXT,
  parent_session_id TEXT,
  forked_through_item_seq INTEGER,
  context_revision INTEGER NOT NULL,
  latest_item_seq INTEGER NOT NULL,
  context_projection_ref TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  admission_method TEXT NOT NULL,
  admission_key TEXT NOT NULL,
  admission_intent_digest TEXT NOT NULL,
  UNIQUE (principal_id, admission_method, admission_key)
) STRICT;

CREATE TABLE items (
  item_id TEXT PRIMARY KEY,
  session_id TEXT,
  run_id TEXT,
  item_seq INTEGER NOT NULL CHECK (item_seq >= 1),
  kind TEXT NOT NULL,
  payload_ref TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK ((session_id IS NULL) != (run_id IS NULL)),
  UNIQUE (session_id, item_seq),
  UNIQUE (run_id, item_seq)
) STRICT;

CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  parent_run_id TEXT,
  spec_ref TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'waiting', 'succeeded', 'completed_unverified', 'failed', 'cancelled')),
  next_step TEXT,
  frontier_ref TEXT,
  waiting_reason TEXT,
  waiting_on_ref TEXT,
  revision INTEGER NOT NULL,
  lease_epoch INTEGER NOT NULL,
  active_worker_launch_id TEXT,
  latest_checkpoint_id TEXT NOT NULL,
  budget_reserved_json TEXT NOT NULL,
  budget_consumed_json TEXT NOT NULL,
  repair_count INTEGER NOT NULL,
  result_ref TEXT,
  terminal_reason TEXT,
  terminal_detail_ref TEXT,
  stop_intent_ref TEXT,
  cancel_requested INTEGER NOT NULL CHECK (cancel_requested IN (0, 1)),
  created_at TEXT NOT NULL,
  deadline_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  admission_method TEXT NOT NULL,
  admission_key TEXT NOT NULL,
  admission_intent_digest TEXT NOT NULL,
  admitted_request_digest TEXT NOT NULL,
  UNIQUE (principal_id, admission_method, admission_key),
  FOREIGN KEY (session_id) REFERENCES sessions(id),
  FOREIGN KEY (latest_checkpoint_id) REFERENCES checkpoints(id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE checkpoints (
  id TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  run_id TEXT NOT NULL,
  based_on_run_revision INTEGER NOT NULL,
  run_item_seq INTEGER NOT NULL,
  context_manifest_ref TEXT NOT NULL,
  journal_seq INTEGER NOT NULL,
  workspace_state_ref TEXT NOT NULL,
  created_at TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('initial', 'auto', 'manual', 'pre-effect', 'handoff')),
  FOREIGN KEY (run_id) REFERENCES runs(id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE run_journal (
  run_id TEXT NOT NULL,
  seq INTEGER NOT NULL CHECK (seq >= 1),
  op_id TEXT NOT NULL,
  op_kind TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  phase TEXT NOT NULL,
  entry_json TEXT NOT NULL,
  PRIMARY KEY (run_id, seq),
  UNIQUE (run_id, op_id, attempt, phase),
  FOREIGN KEY (run_id) REFERENCES runs(id)
) STRICT;

CREATE TABLE run_events (
  run_id TEXT NOT NULL,
  event_seq INTEGER NOT NULL CHECK (event_seq >= 1),
  payload_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  PRIMARY KEY (run_id, event_seq),
  FOREIGN KEY (run_id) REFERENCES runs(id)
) STRICT;

CREATE TABLE worker_launches (
  launch_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  row_json TEXT NOT NULL,
  retired_at TEXT,
  FOREIGN KEY (run_id) REFERENCES runs(id)
) STRICT;

CREATE TABLE workspace_generations (
  generation_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  row_version INTEGER NOT NULL,
  row_json TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES runs(id)
) STRICT;

CREATE TABLE local_inference_activation_cycles (
  activation_cycle_id TEXT PRIMARY KEY,
  owner_principal_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  cycle_ordinal INTEGER NOT NULL,
  phase TEXT NOT NULL,
  row_json TEXT NOT NULL,
  UNIQUE (owner_principal_id, service_id, cycle_ordinal)
) STRICT;

CREATE TABLE local_inference_launches (
  launch_id TEXT PRIMARY KEY,
  activation_cycle_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  retired_at TEXT,
  row_json TEXT NOT NULL,
  FOREIGN KEY (activation_cycle_id) REFERENCES local_inference_activation_cycles(activation_cycle_id)
) STRICT;

CREATE TABLE control_requests (
  principal_id TEXT NOT NULL,
  method TEXT NOT NULL,
  request_id TEXT NOT NULL,
  channel_identity_ref TEXT NOT NULL,
  channel_identity_digest TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  response_ref TEXT NOT NULL,
  response_revision INTEGER NOT NULL,
  committed_at TEXT NOT NULL,
  PRIMARY KEY (principal_id, method, request_id)
) STRICT;

CREATE TABLE list_read_cuts (
  cut_id TEXT PRIMARY KEY,
  owner_principal_id TEXT NOT NULL,
  method TEXT NOT NULL,
  normalized_filter_digest TEXT NOT NULL,
  normalized_limit INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  entries_digest TEXT NOT NULL,
  cut_digest TEXT NOT NULL,
  cursor_secret_base64url TEXT NOT NULL
) STRICT;

CREATE TABLE list_read_cut_entries (
  cut_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  stable_id TEXT NOT NULL,
  row_digest TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (cut_id, ordinal),
  UNIQUE (cut_id, stable_id),
  FOREIGN KEY (cut_id) REFERENCES list_read_cuts(cut_id)
) STRICT;

CREATE TABLE child_allocations (
  parent_run_id TEXT NOT NULL,
  child_run_id TEXT NOT NULL,
  state TEXT NOT NULL,
  row_json TEXT NOT NULL,
  PRIMARY KEY (parent_run_id, child_run_id),
  FOREIGN KEY (parent_run_id) REFERENCES runs(id),
  FOREIGN KEY (child_run_id) REFERENCES runs(id)
) STRICT;

CREATE TABLE authorization_grants (
  grant_id TEXT PRIMARY KEY,
  owner_principal_id TEXT NOT NULL,
  state TEXT NOT NULL,
  row_json TEXT NOT NULL
) STRICT;

CREATE TABLE mcp_registrations (
  owner_principal_id TEXT NOT NULL,
  registration_id TEXT NOT NULL,
  current_revision INTEGER NOT NULL,
  current_revision_ref TEXT NOT NULL,
  PRIMARY KEY (owner_principal_id, registration_id)
) STRICT;

CREATE TABLE admin_operations (
  principal_id TEXT NOT NULL,
  method TEXT NOT NULL,
  request_id TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  state TEXT NOT NULL,
  row_json TEXT NOT NULL,
  PRIMARY KEY (principal_id, method, request_id, attempt)
) STRICT;
`;

export const KERNEL_SCHEMA_V2_SQL = `
CREATE UNIQUE INDEX worker_launches_one_unretired_per_run
  ON worker_launches(run_id) WHERE retired_at IS NULL;

CREATE UNIQUE INDEX workspace_generations_unique_generation_ref
  ON workspace_generations(json_extract(row_json, '$.generationRef'))
  WHERE json_extract(row_json, '$.generationRef') IS NOT NULL;

CREATE TRIGGER checkpoints_immutable_update
BEFORE UPDATE ON checkpoints BEGIN
  SELECT RAISE(ABORT, 'checkpoints are immutable');
END;
CREATE TRIGGER checkpoints_immutable_delete
BEFORE DELETE ON checkpoints BEGIN
  SELECT RAISE(ABORT, 'checkpoints are immutable');
END;

CREATE TRIGGER items_immutable_update
BEFORE UPDATE ON items BEGIN
  SELECT RAISE(ABORT, 'items are immutable');
END;
CREATE TRIGGER items_immutable_delete
BEFORE DELETE ON items BEGIN
  SELECT RAISE(ABORT, 'items are immutable');
END;

CREATE TRIGGER run_journal_validate_insert
BEFORE INSERT ON run_journal BEGIN
  SELECT CASE
    WHEN NEW.seq != COALESCE((SELECT max(seq) + 1 FROM run_journal WHERE run_id = NEW.run_id), 1)
      THEN RAISE(ABORT, 'run journal sequence must be contiguous')
    WHEN NEW.attempt < 0
      THEN RAISE(ABORT, 'run journal attempt must be nonnegative')
    WHEN NEW.op_kind NOT IN ('model', 'tool', 'mcp-server', 'mcp', 'verifier', 'publish')
      THEN RAISE(ABORT, 'run journal op_kind is invalid')
    WHEN NEW.phase NOT IN ('prepared', 'dispatch_claimed', 'completed', 'failed', 'unknown', 'abandoned')
      THEN RAISE(ABORT, 'run journal phase is invalid')
    WHEN NEW.phase = 'prepared' AND NEW.attempt != COALESCE(
      (SELECT max(attempt) + 1 FROM run_journal WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND phase = 'prepared'),
      0
    ) THEN RAISE(ABORT, 'run journal attempts must be contiguous from zero')
    WHEN NEW.phase != 'prepared' AND NOT EXISTS (
      SELECT 1 FROM run_journal
      WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt AND phase = 'prepared'
    ) THEN RAISE(ABORT, 'run journal phase requires a prepared attempt')
    WHEN NEW.phase = 'dispatch_claimed' AND EXISTS (
      SELECT 1 FROM run_journal
      WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt
        AND phase IN ('dispatch_claimed', 'completed', 'failed', 'unknown', 'abandoned')
    ) THEN RAISE(ABORT, 'run journal attempt already has a claim or terminal phase')
    WHEN NEW.phase IN ('completed', 'failed', 'unknown', 'abandoned') AND EXISTS (
      SELECT 1 FROM run_journal
      WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt
        AND phase IN ('completed', 'failed', 'abandoned')
    ) THEN RAISE(ABORT, 'run journal attempt already has a final phase')
    WHEN NEW.phase IN ('completed', 'failed', 'abandoned') AND EXISTS (
      SELECT 1 FROM run_journal
      WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt AND phase = 'unknown'
    ) AND (
      json_type(NEW.entry_json, '$.budgetSettlementRef') IS NOT 'text'
      OR (
        SELECT json_type(entry_json, '$.budgetSettlementRef') FROM run_journal
        WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt AND phase = 'unknown'
      ) IS NOT 'text'
      OR json_extract(NEW.entry_json, '$.budgetSettlementRef') IS NOT (
        SELECT json_extract(entry_json, '$.budgetSettlementRef') FROM run_journal
        WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt AND phase = 'unknown'
      )
    ) THEN RAISE(ABORT, 'run journal resolution must reuse the unknown settlement')
    WHEN NEW.phase IN ('completed', 'unknown') AND NOT EXISTS (
      SELECT 1 FROM run_journal
      WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt AND phase = 'dispatch_claimed'
    ) THEN RAISE(ABORT, 'run journal terminal phase requires a claim')
    WHEN NEW.phase = 'abandoned' AND NOT EXISTS (
      SELECT 1 FROM run_journal
      WHERE run_id = NEW.run_id AND op_id = NEW.op_id AND attempt = NEW.attempt AND phase = 'unknown'
    ) THEN RAISE(ABORT, 'run journal abandonment requires unknown')
  END;
END;
CREATE TRIGGER run_journal_immutable_update
BEFORE UPDATE ON run_journal BEGIN
  SELECT RAISE(ABORT, 'run journal is append-only');
END;
CREATE TRIGGER run_journal_immutable_delete
BEFORE DELETE ON run_journal BEGIN
  SELECT RAISE(ABORT, 'run journal is append-only');
END;

CREATE TRIGGER worker_launches_validate_insert
BEFORE INSERT ON worker_launches BEGIN
  SELECT CASE
    WHEN NEW.phase NOT IN ('reserved', 'preactivated', 'activated', 'reconciling', 'retired')
      THEN RAISE(ABORT, 'worker launch phase is invalid')
    WHEN (NEW.phase = 'retired') != (NEW.retired_at IS NOT NULL)
      THEN RAISE(ABORT, 'worker launch retired_at does not match phase')
  END;
END;
CREATE TRIGGER worker_launches_validate_update
BEFORE UPDATE ON worker_launches BEGIN
  SELECT CASE
    WHEN NEW.launch_id != OLD.launch_id OR NEW.run_id != OLD.run_id
      THEN RAISE(ABORT, 'worker launch identity is immutable')
    WHEN NOT (
      (OLD.phase = 'reserved' AND NEW.phase IN ('preactivated', 'retired')) OR
      (OLD.phase = 'preactivated' AND NEW.phase IN ('activated', 'retired')) OR
      (OLD.phase = 'activated' AND NEW.phase IN ('activated', 'reconciling', 'retired')) OR
      (OLD.phase = 'reconciling' AND NEW.phase = 'retired')
    ) THEN RAISE(ABORT, 'worker launch phase transition is invalid')
    WHEN (NEW.phase = 'retired') != (NEW.retired_at IS NOT NULL)
      THEN RAISE(ABORT, 'worker launch retired_at does not match phase')
  END;
END;
CREATE TRIGGER worker_launches_immutable_delete
BEFORE DELETE ON worker_launches BEGIN
  SELECT RAISE(ABORT, 'worker launch history is retained');
END;

CREATE TRIGGER workspace_generations_validate_insert
BEFORE INSERT ON workspace_generations BEGIN
  SELECT CASE
    WHEN NEW.phase != 'materializing'
      THEN RAISE(ABORT, 'workspace generation must begin materializing')
    WHEN NEW.row_version != 1
      THEN RAISE(ABORT, 'workspace generation must begin at row version one')
  END;
END;
CREATE TRIGGER workspace_generations_validate_update
BEFORE UPDATE ON workspace_generations BEGIN
  SELECT CASE
    WHEN NEW.generation_id != OLD.generation_id OR NEW.run_id != OLD.run_id
      THEN RAISE(ABORT, 'workspace generation identity is immutable')
    WHEN NEW.row_version != OLD.row_version + 1
      THEN RAISE(ABORT, 'workspace generation row version must increment by one')
    WHEN NOT (
      (OLD.phase = 'materializing' AND NEW.phase IN ('preactivated_readonly', 'quarantined')) OR
      (OLD.phase = 'preactivated_readonly' AND NEW.phase IN ('active', 'quarantined')) OR
      (OLD.phase = 'active' AND NEW.phase IN ('revoking', 'fenced_reconciling')) OR
      (OLD.phase = 'revoking' AND NEW.phase IN ('checkpointing', 'fenced_reconciling', 'quarantined')) OR
      (OLD.phase = 'checkpointing' AND NEW.phase IN ('sealed', 'fenced_reconciling', 'quarantined')) OR
      (OLD.phase = 'fenced_reconciling' AND NEW.phase = 'quarantined') OR
      (OLD.phase IN ('sealed', 'quarantined') AND NEW.phase = 'retired')
    ) THEN RAISE(ABORT, 'workspace generation phase transition is invalid')
  END;
END;
CREATE TRIGGER workspace_generations_immutable_delete
BEFORE DELETE ON workspace_generations BEGIN
  SELECT RAISE(ABORT, 'workspace generation history is retained');
END;

CREATE TRIGGER state_owners_validate_update
BEFORE UPDATE ON state_owners BEGIN
  SELECT CASE
    WHEN NEW.owner_epoch != OLD.owner_epoch OR NEW.supervisor_instance_id != OLD.supervisor_instance_id
      THEN RAISE(ABORT, 'state owner identity is immutable')
    WHEN OLD.state != 'active' OR NEW.state != 'terminal'
      THEN RAISE(ABORT, 'state owner transition must be active to terminal')
  END;
END;
CREATE TRIGGER state_owners_immutable_delete
BEFORE DELETE ON state_owners BEGIN
  SELECT RAISE(ABORT, 'state owner history is retained');
END;

CREATE TRIGGER canonical_time_fence_immutable_delete
BEFORE DELETE ON canonical_time_fence BEGIN
  SELECT RAISE(ABORT, 'canonical time fence cannot be deleted');
END;
`;

export const KERNEL_SCHEMA_SQL = `${KERNEL_SCHEMA_V1_SQL}\n${KERNEL_SCHEMA_V2_SQL}`;

const REQUIRED_TABLES = [
  'canonical_time_fence',
  'state_owners',
  'artifacts',
  'sessions',
  'items',
  'runs',
  'checkpoints',
  'run_journal',
  'run_events',
  'worker_launches',
  'workspace_generations',
  'local_inference_activation_cycles',
  'local_inference_launches',
  'control_requests',
  'list_read_cuts',
  'list_read_cut_entries',
  'child_allocations',
  'authorization_grants',
  'mcp_registrations',
  'admin_operations'
] as const;

function pragmaScalar(driver: SqliteDriver, name: string): unknown {
  const row = driver.prepare(`PRAGMA ${name}`).get();
  if (typeof row !== 'object' || row === null) return undefined;
  return Object.values(row)[0];
}

export function applyKernelSchema(driver: SqliteDriver): void {
  const userVersion = requiredSafeInteger(pragmaScalar(driver, 'user_version'), 'user_version');
  const applicationId = requiredSafeInteger(pragmaScalar(driver, 'application_id'), 'application_id');
  if (![0, 1, KERNEL_STATE_SCHEMA_VERSION].includes(userVersion)) {
    throw new Error(`unsupported kernel schema version ${userVersion}`);
  }
  if (applicationId !== 0 && applicationId !== KERNEL_SQLITE_APPLICATION_ID) {
    throw new Error(`kernel database has foreign application_id ${applicationId}`);
  }
  if (userVersion !== 0 && applicationId !== KERNEL_SQLITE_APPLICATION_ID) {
    throw new Error('versioned kernel database is missing the Cliq application_id');
  }

  driver.exec(`
    PRAGMA foreign_keys=ON;
    PRAGMA synchronous=FULL;
    PRAGMA busy_timeout=${KERNEL_SQLITE_BUSY_TIMEOUT_MS};
    PRAGMA journal_mode=DELETE;
  `);

  if (userVersion === 0) {
    driver.transaction((connection) => {
      connection.exec(`PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID}`);
      connection.exec(KERNEL_SCHEMA_SQL);
      connection.exec(`PRAGMA user_version=${KERNEL_STATE_SCHEMA_VERSION}`);
    });
  } else if (userVersion === 1 && KERNEL_STATE_SCHEMA_VERSION === 2) {
    driver.transaction((connection) => {
      connection.exec(KERNEL_SCHEMA_V2_SQL);
      connection.exec(`PRAGMA user_version=${KERNEL_STATE_SCHEMA_VERSION}`);
    });
  }

  const names = new Set(
    driver
      .prepare(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
      .all<{ name: string }>()
      .map((row) => row.name)
  );
  for (const table of REQUIRED_TABLES) {
    if (!names.has(table)) {
      throw new Error(`kernel schema is missing table ${table}`);
    }
  }
}

export function readSchemaUserVersion(driver: SqliteDriver): number {
  return requiredSafeInteger(pragmaScalar(driver, 'user_version'), 'user_version');
}
