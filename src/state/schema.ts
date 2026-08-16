import {
  KERNEL_SQLITE_APPLICATION_ID,
  KERNEL_SQLITE_BUSY_TIMEOUT_MS,
  KERNEL_STATE_SCHEMA_VERSION
} from '../config.js';
import { requiredSafeInteger } from '../kernel/identity.js';
import type { SqliteDriver } from './sqlite-driver.js';

export const KERNEL_SCHEMA_SQL = `
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
  driver.exec(`
    PRAGMA foreign_keys=ON;
    PRAGMA synchronous=FULL;
    PRAGMA busy_timeout=${KERNEL_SQLITE_BUSY_TIMEOUT_MS};
    PRAGMA application_id=${KERNEL_SQLITE_APPLICATION_ID};
    PRAGMA journal_mode=DELETE;
  `);

  const userVersion = requiredSafeInteger(pragmaScalar(driver, 'user_version'), 'user_version');
  if (userVersion === 0) {
    driver.transaction((connection) => {
      connection.exec(KERNEL_SCHEMA_SQL);
      connection.exec(`PRAGMA user_version=${KERNEL_STATE_SCHEMA_VERSION}`);
    });
  } else if (userVersion !== KERNEL_STATE_SCHEMA_VERSION) {
    throw new Error(`unsupported kernel schema version ${userVersion}`);
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
