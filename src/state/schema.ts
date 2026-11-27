import { DatabaseSync } from 'node:sqlite';

import {
  KERNEL_SQLITE_APPLICATION_ID,
  KERNEL_SQLITE_BUSY_TIMEOUT_MS,
  KERNEL_STATE_SCHEMA_VERSION
} from '../config.js';
import { requiredSafeInteger, sha256Bytes } from '../kernel/identity.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { KernelStorageError } from './errors.js';
import { decodeChildAllocation } from './invariants.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

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

// Recovery probes only replace the installed wait. The original fence cut and identity stay frozen.
export const KERNEL_SCHEMA_V3_SQL = `
DROP TRIGGER workspace_generations_validate_update;
CREATE TRIGGER workspace_generations_validate_update
BEFORE UPDATE ON workspace_generations BEGIN
  SELECT CASE
    WHEN NEW.generation_id != OLD.generation_id OR NEW.run_id != OLD.run_id
      THEN RAISE(ABORT, 'workspace generation identity is immutable')
    WHEN NEW.row_version != OLD.row_version + 1
      THEN RAISE(ABORT, 'workspace generation row version must increment by one')
    WHEN OLD.phase = 'fenced_reconciling' AND NEW.phase = 'fenced_reconciling' AND (
      json_remove(NEW.row_json, '$.rowVersion', '$.updatedAt', '$.waitingSubjectRef', '$.waitingSubjectDigest')
        IS NOT json_remove(OLD.row_json, '$.rowVersion', '$.updatedAt', '$.waitingSubjectRef', '$.waitingSubjectDigest') OR
      json_extract(NEW.row_json, '$.rowVersion') IS NOT NEW.row_version OR
      json_type(NEW.row_json, '$.waitingSubjectRef') IS NOT 'text' OR
      json_type(NEW.row_json, '$.waitingSubjectDigest') IS NOT 'text' OR
      length(json_extract(NEW.row_json, '$.waitingSubjectRef')) != 64 OR
      json_extract(NEW.row_json, '$.waitingSubjectRef') GLOB '*[^0-9a-f]*' OR
      json_extract(NEW.row_json, '$.waitingSubjectRef') IS NOT json_extract(NEW.row_json, '$.waitingSubjectDigest') OR
      json_extract(NEW.row_json, '$.waitingSubjectRef') IS json_extract(OLD.row_json, '$.waitingSubjectRef') OR
      json_type(NEW.row_json, '$.updatedAt') IS NOT 'text' OR
      json_extract(NEW.row_json, '$.updatedAt') < json_extract(OLD.row_json, '$.updatedAt')
    ) THEN RAISE(ABORT, 'workspace generation recovery fence fields are frozen')
    WHEN NOT (
      (OLD.phase = 'materializing' AND NEW.phase IN ('preactivated_readonly', 'quarantined')) OR
      (OLD.phase = 'preactivated_readonly' AND NEW.phase IN ('active', 'quarantined')) OR
      (OLD.phase = 'active' AND NEW.phase IN ('revoking', 'fenced_reconciling')) OR
      (OLD.phase = 'revoking' AND NEW.phase IN ('checkpointing', 'fenced_reconciling', 'quarantined')) OR
      (OLD.phase = 'checkpointing' AND NEW.phase IN ('sealed', 'fenced_reconciling', 'quarantined')) OR
      (OLD.phase = 'fenced_reconciling' AND NEW.phase IN ('fenced_reconciling', 'quarantined')) OR
      (OLD.phase IN ('sealed', 'quarantined') AND NEW.phase = 'retired')
    ) THEN RAISE(ABORT, 'workspace generation phase transition is invalid')
  END;
END;
`;

// Existing admissions without a direct original request link cannot be safely
// backfilled from mutable snapshots or inferred by commit order.
export const KERNEL_SCHEMA_V4_SQL = `
ALTER TABLE sessions ADD COLUMN admission_request_id TEXT;
ALTER TABLE runs ADD COLUMN admission_request_id TEXT;

CREATE TABLE source_inspection_attempts (
  inspection_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  method TEXT NOT NULL CHECK (method = 'run.submit'),
  admission_key TEXT NOT NULL,
  admission_intent_digest TEXT NOT NULL,
  original_request_id TEXT NOT NULL,
  original_request_digest TEXT NOT NULL,
  workspace_identity_digest TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN ('capturing', 'prepared', 'active', 'retired')),
  row_version INTEGER NOT NULL CHECK (row_version >= 1),
  row_json TEXT NOT NULL CHECK (json_valid(row_json) AND length(CAST(row_json AS BLOB)) <= 1048576),
  UNIQUE (principal_id, method, admission_key),
  UNIQUE (principal_id, method, original_request_id)
) STRICT;
CREATE UNIQUE INDEX source_inspections_one_unretired_per_workspace
  ON source_inspection_attempts(workspace_identity_digest) WHERE phase != 'retired';

CREATE TRIGGER source_inspections_validate_insert
BEFORE INSERT ON source_inspection_attempts BEGIN
  SELECT CASE
    WHEN NEW.phase != 'capturing' OR NEW.row_version != 1
      THEN RAISE(ABORT, 'source inspection must begin capturing at row version one')
    WHEN json_extract(NEW.row_json, '$.inspectionId') IS NOT NEW.inspection_id OR
      json_extract(NEW.row_json, '$.principalId') IS NOT NEW.principal_id OR
      json_extract(NEW.row_json, '$.method') IS NOT NEW.method OR
      json_extract(NEW.row_json, '$.admissionKey') IS NOT NEW.admission_key OR
      json_extract(NEW.row_json, '$.admissionIntentDigest') IS NOT NEW.admission_intent_digest OR
      json_extract(NEW.row_json, '$.workspaceIdentityDigest') IS NOT NEW.workspace_identity_digest OR
      json_extract(NEW.row_json, '$.phase') IS NOT NEW.phase OR
      json_extract(NEW.row_json, '$.rowVersion') IS NOT NEW.row_version
      THEN RAISE(ABORT, 'source inspection columns must equal row_json')
  END;
END;
CREATE TRIGGER source_inspections_validate_update
BEFORE UPDATE ON source_inspection_attempts BEGIN
  SELECT CASE
    WHEN NEW.inspection_id IS NOT OLD.inspection_id OR NEW.principal_id IS NOT OLD.principal_id OR
      NEW.method IS NOT OLD.method OR NEW.admission_key IS NOT OLD.admission_key OR
      NEW.admission_intent_digest IS NOT OLD.admission_intent_digest OR
      NEW.original_request_id IS NOT OLD.original_request_id OR NEW.original_request_digest IS NOT OLD.original_request_digest OR
      NEW.workspace_identity_digest IS NOT OLD.workspace_identity_digest
      THEN RAISE(ABORT, 'source inspection identity is immutable')
    WHEN NEW.row_version != OLD.row_version + 1
      THEN RAISE(ABORT, 'source inspection row version must increment by one')
    WHEN NOT (
      (OLD.phase = 'capturing' AND NEW.phase IN ('capturing', 'prepared', 'retired')) OR
      (OLD.phase = 'prepared' AND NEW.phase IN ('prepared', 'active', 'retired')) OR
      (OLD.phase = 'active' AND NEW.phase IN ('active', 'retired'))
    ) THEN RAISE(ABORT, 'source inspection phase transition is invalid')
    WHEN json_extract(NEW.row_json, '$.inspectionId') IS NOT NEW.inspection_id OR
      json_extract(NEW.row_json, '$.principalId') IS NOT NEW.principal_id OR
      json_extract(NEW.row_json, '$.method') IS NOT NEW.method OR
      json_extract(NEW.row_json, '$.admissionKey') IS NOT NEW.admission_key OR
      json_extract(NEW.row_json, '$.admissionIntentDigest') IS NOT NEW.admission_intent_digest OR
      json_extract(NEW.row_json, '$.workspaceIdentityDigest') IS NOT NEW.workspace_identity_digest OR
      json_extract(NEW.row_json, '$.phase') IS NOT NEW.phase OR
      json_extract(NEW.row_json, '$.rowVersion') IS NOT NEW.row_version
      THEN RAISE(ABORT, 'source inspection columns must equal row_json')
    WHEN json_extract(NEW.row_json, '$.cancelRequested') < json_extract(OLD.row_json, '$.cancelRequested')
      THEN RAISE(ABORT, 'source inspection cancellation is monotonic')
    WHEN json_remove(NEW.row_json, '$.phase', '$.rowVersion', '$.rowDigest', '$.updatedAt', '$.cancelRequested',
        '$.inputRef', '$.inputDigest', '$.plan', '$.processContainmentRef', '$.retirementEvidenceRef', '$.retiredAt', '$.outcome')
      IS NOT json_remove(OLD.row_json, '$.phase', '$.rowVersion', '$.rowDigest', '$.updatedAt', '$.cancelRequested',
        '$.inputRef', '$.inputDigest', '$.plan', '$.processContainmentRef', '$.retirementEvidenceRef', '$.retiredAt', '$.outcome')
      THEN RAISE(ABORT, 'source inspection target and reservation are frozen')
    WHEN OLD.phase = NEW.phase AND json_remove(NEW.row_json, '$.rowVersion', '$.rowDigest', '$.updatedAt', '$.cancelRequested')
      IS NOT json_remove(OLD.row_json, '$.rowVersion', '$.rowDigest', '$.updatedAt', '$.cancelRequested')
      THEN RAISE(ABORT, 'source inspection unchanged phase may only request cancellation')
    WHEN OLD.phase IN ('prepared', 'active') AND (
      json_extract(NEW.row_json, '$.inputRef') IS NOT json_extract(OLD.row_json, '$.inputRef') OR
      json_extract(NEW.row_json, '$.inputDigest') IS NOT json_extract(OLD.row_json, '$.inputDigest') OR
      json_extract(NEW.row_json, '$.plan') IS NOT json_extract(OLD.row_json, '$.plan')
    ) THEN RAISE(ABORT, 'source inspection frozen input and plan are immutable')
    WHEN OLD.phase = 'active' AND
      json_extract(NEW.row_json, '$.processContainmentRef') IS NOT json_extract(OLD.row_json, '$.processContainmentRef')
      THEN RAISE(ABORT, 'source inspection actual containment is immutable')
  END;
END;
CREATE TRIGGER source_inspections_immutable_delete
BEFORE DELETE ON source_inspection_attempts BEGIN
  SELECT RAISE(ABORT, 'source inspection history is retained');
END;

CREATE TRIGGER sessions_admission_identity_immutable
BEFORE UPDATE ON sessions WHEN
  NEW.id IS NOT OLD.id OR NEW.principal_id IS NOT OLD.principal_id OR
  NEW.admission_method IS NOT OLD.admission_method OR NEW.admission_key IS NOT OLD.admission_key OR
  NEW.admission_intent_digest IS NOT OLD.admission_intent_digest OR
  NEW.admission_request_id IS NOT OLD.admission_request_id
BEGIN
  SELECT RAISE(ABORT, 'session admission identity is immutable');
END;

CREATE TRIGGER runs_admission_identity_immutable
BEFORE UPDATE ON runs WHEN
  NEW.id IS NOT OLD.id OR NEW.principal_id IS NOT OLD.principal_id OR
  NEW.admission_method IS NOT OLD.admission_method OR NEW.admission_key IS NOT OLD.admission_key OR
  NEW.admission_intent_digest IS NOT OLD.admission_intent_digest OR
  NEW.admitted_request_digest IS NOT OLD.admitted_request_digest OR
  NEW.admission_request_id IS NOT OLD.admission_request_id
BEGIN
  SELECT RAISE(ABORT, 'Run admission identity is immutable');
END;
`;

export const KERNEL_SCHEMA_V5_SQL = `
DROP TRIGGER worker_launches_validate_insert;
DROP TRIGGER worker_launches_validate_update;

CREATE TRIGGER worker_launches_validate_insert
BEFORE INSERT ON worker_launches BEGIN
  SELECT CASE
    WHEN NEW.phase NOT IN ('preparing', 'reserved', 'preactivated', 'activated', 'reconciling', 'retired')
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
      (OLD.phase = 'preparing' AND NEW.phase IN ('preparing', 'reserved', 'retired')) OR
      (OLD.phase = 'reserved' AND NEW.phase IN ('preactivated', 'retired')) OR
      (OLD.phase = 'preactivated' AND NEW.phase IN ('activated', 'retired')) OR
      (OLD.phase = 'activated' AND NEW.phase IN ('activated', 'reconciling', 'retired')) OR
      (OLD.phase = 'reconciling' AND NEW.phase = 'retired')
    ) THEN RAISE(ABORT, 'worker launch phase transition is invalid')
    WHEN (NEW.phase = 'retired') != (NEW.retired_at IS NOT NULL)
      THEN RAISE(ABORT, 'worker launch retired_at does not match phase')
  END;
END;
`;

// Reuse the fixed historical DDL, not sqlite_schema text from the database.
// Only this table's method CHECK changes. Copy before recreating its insertion
// trigger so retained prepared/active/retired rows remain byte-for-byte intact.
const sourceInspectionSchema = KERNEL_SCHEMA_V4_SQL.slice(KERNEL_SCHEMA_V4_SQL.indexOf('CREATE TABLE source_inspection_attempts'),
  KERNEL_SCHEMA_V4_SQL.indexOf('CREATE TRIGGER sessions_admission_identity_immutable'));
const sourceInspectionIndexes = sourceInspectionSchema.indexOf('CREATE UNIQUE INDEX');
export const KERNEL_SCHEMA_V6_SQL = `
DROP TRIGGER source_inspections_validate_insert;
DROP TRIGGER source_inspections_validate_update;
DROP TRIGGER source_inspections_immutable_delete;
DROP INDEX source_inspections_one_unretired_per_workspace;
ALTER TABLE source_inspection_attempts RENAME TO source_inspection_attempts_v5;
${sourceInspectionSchema.slice(0, sourceInspectionIndexes).replace("method = 'run.submit'", "method IN ('run.submit', 'run.apply')")}
INSERT INTO source_inspection_attempts SELECT * FROM source_inspection_attempts_v5;
DROP TABLE source_inspection_attempts_v5;
${sourceInspectionSchema.slice(sourceInspectionIndexes)}
`;
// Same row and phase spine. A once-only handoff can be installed while the
// original phase is unchanged; afterwards only cancellation/retirement remain.
// Derive from our fixed historical DDL, never from database-supplied SQL.
const sourceInspectionUpdate = sourceInspectionSchema.slice(sourceInspectionSchema.indexOf('CREATE TRIGGER source_inspections_validate_update'),
  sourceInspectionSchema.indexOf('CREATE TRIGGER source_inspections_immutable_delete'));
const sourceInspectionHandoffUpdate = sourceInspectionUpdate
  .replaceAll("'$.retiredAt', '$.outcome')", "'$.retiredAt', '$.outcome', '$.retirementHandoffRef')")
  .replaceAll("'$.updatedAt', '$.cancelRequested')", "'$.updatedAt', '$.cancelRequested', '$.retirementHandoffRef')")
  .replace("    WHEN OLD.phase IN ('prepared', 'active') AND (", `    WHEN json_type(NEW.row_json, '$.retirementHandoffRef') IS NOT NULL AND (
      json_type(NEW.row_json, '$.retirementHandoffRef') IS NOT 'text' OR
      length(json_extract(NEW.row_json, '$.retirementHandoffRef')) != 64 OR
      json_extract(NEW.row_json, '$.retirementHandoffRef') GLOB '*[^0-9a-f]*' OR
      (json_type(OLD.row_json, '$.retirementHandoffRef') IS NULL AND NEW.phase IS NOT OLD.phase)
    ) THEN RAISE(ABORT, 'source inspection handoff must be installed once at its original phase')
    WHEN json_type(OLD.row_json, '$.retirementHandoffRef') IS NOT NULL AND (
      json_extract(NEW.row_json, '$.retirementHandoffRef') IS NOT json_extract(OLD.row_json, '$.retirementHandoffRef') OR
      (NEW.phase IS NOT OLD.phase AND NEW.phase != 'retired')
    ) THEN RAISE(ABORT, 'source inspection handoff permits cleanup only')
    WHEN json_type(OLD.row_json, '$.inputRef') IS NOT NULL AND (
      json_extract(NEW.row_json, '$.inputRef') IS NOT json_extract(OLD.row_json, '$.inputRef') OR
      json_extract(NEW.row_json, '$.inputDigest') IS NOT json_extract(OLD.row_json, '$.inputDigest')
    ) THEN RAISE(ABORT, 'source inspection first input is immutable')
    WHEN OLD.phase IN ('prepared', 'active') AND (`);
export const KERNEL_SCHEMA_V7_SQL = `
DROP TRIGGER source_inspections_validate_update;
${sourceInspectionHandoffUpdate}
`;
// Preserve the exact old physical Journal guards. Only these two closed local
// operation kinds have no process/broker dispatch; their complete triplet and
// business effect must still commit in the same original owner transaction.
const localJournalKind = "NEW.op_kind IN ('child_admission', 'child_merge')";
const localRefFields = ['target', 'requestRef', 'grantRef'];
const localPhasePaths = "'$.seq', '$.phase', '$.budgetDelta', '$.dispatchId', '$.supervisorInstanceId', '$.stateOwnerEpoch', '$.resultRef', '$.budgetSettlementRef'";
const localJournalGuard = `    WHEN ${localJournalKind} AND (NOT json_valid(NEW.entry_json))
      THEN RAISE(ABORT, 'local child journal must contain valid JSON')
    WHEN ${localJournalKind} AND (
      json_type(NEW.entry_json) IS NOT 'object' OR NEW.attempt != 0 OR
      NEW.phase NOT IN ('prepared', 'dispatch_claimed', 'completed') OR
      json_extract(NEW.entry_json, '$.runId') IS NOT NEW.run_id OR
      json_extract(NEW.entry_json, '$.opId') IS NOT NEW.op_id OR
      json_extract(NEW.entry_json, '$.opKind') IS NOT NEW.op_kind OR
      json_extract(NEW.entry_json, '$.seq') IS NOT NEW.seq OR
      json_type(NEW.entry_json, '$.seq') IS NOT 'integer' OR
      json_extract(NEW.entry_json, '$.phase') IS NOT NEW.phase OR
      json_extract(NEW.entry_json, '$.attempt') IS NOT 0 OR
      json_type(NEW.entry_json, '$.attempt') IS NOT 'integer' OR
      json_type(NEW.entry_json, '$.leaseEpoch') IS NOT 'integer' OR
      json_extract(NEW.entry_json, '$.leaseEpoch') IS NOT 0 OR
      json_extract(NEW.entry_json, '$.replayClass') IS NOT 'retry' OR
      json_type(NEW.entry_json, '$.idempotencyKey') IS NOT 'text' OR
      length(json_extract(NEW.entry_json, '$.idempotencyKey')) < 1 OR
      ${localRefFields.map(field => `(json_type(NEW.entry_json, '$.${field}') IS NOT 'text' OR
        length(json_extract(NEW.entry_json, '$.${field}')) != 64 OR json_extract(NEW.entry_json, '$.${field}') GLOB '*[^0-9a-f]*')`).join(' OR ')} OR
      json_type(NEW.entry_json, '$.timestamp') IS NOT 'text' OR
      length(json_extract(NEW.entry_json, '$.timestamp')) != 24 OR
      json_type(NEW.entry_json, '$.localCommittedAt') IS NOT 'text' OR
      length(json_extract(NEW.entry_json, '$.localCommittedAt')) != 24 OR
      json_extract(NEW.entry_json, '$.timestamp') > json_extract(NEW.entry_json, '$.localCommittedAt') OR
      json_type(NEW.entry_json, '$.budgetDelta') IS NOT 'object' OR
      (SELECT count(*) FROM json_each(NEW.entry_json, '$.budgetDelta')) != 4 OR
      ${['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts'].map(field => `json_type(NEW.entry_json, '$.budgetDelta.${field}') IS NOT 'integer'`).join(' OR ')} OR
      ${['modelTokens', 'costMicros', 'repairAttempts'].map(field => `json_extract(NEW.entry_json, '$.budgetDelta.${field}') IS NOT 0`).join(' OR ')} OR
      json_extract(NEW.entry_json, '$.budgetDelta.toolCalls') IS NOT CASE NEW.phase WHEN 'dispatch_claimed' THEN 0 ELSE 1 END OR
      (SELECT count(*) FROM json_each(NEW.entry_json)) != CASE NEW.phase WHEN 'prepared' THEN 15 WHEN 'dispatch_claimed' THEN 18 ELSE 20 END OR
      ${['sandboxLaunchSpecRef', 'brokerFenceTokenDigest', 'receiptRef', 'errorRef', 'evidenceRef', 'evidenceDigest', 'attestationRef']
        .map(field => `json_type(NEW.entry_json, '$.${field}') IS NOT NULL`).join(' OR ')} OR
      (NEW.phase != 'prepared' AND (json_type(NEW.entry_json, '$.dispatchId') IS NOT 'text' OR
        json_type(NEW.entry_json, '$.supervisorInstanceId') IS NOT 'text' OR
        json_type(NEW.entry_json, '$.stateOwnerEpoch') IS NOT 'integer' OR json_extract(NEW.entry_json, '$.stateOwnerEpoch') < 1)) OR
      (NEW.phase = 'completed' AND (${['resultRef', 'budgetSettlementRef'].map(field => `(json_type(NEW.entry_json, '$.${field}') IS NOT 'text' OR
        length(json_extract(NEW.entry_json, '$.${field}')) != 64 OR json_extract(NEW.entry_json, '$.${field}') GLOB '*[^0-9a-f]*')`).join(' OR ')}))
    ) THEN RAISE(ABORT, 'local child journal cannot carry physical dispatch or incomplete local data')
    WHEN ${localJournalKind} AND NEW.phase != 'prepared' AND
      json_remove(NEW.entry_json,${localPhasePaths}) IS NOT (
        SELECT json_remove(entry_json,${localPhasePaths}) FROM run_journal
        WHERE run_id=NEW.run_id AND op_id=NEW.op_id AND attempt=NEW.attempt AND phase='prepared')
      THEN RAISE(ABORT, 'local child journal must preserve its original request grant and commit cut')
    WHEN ${localJournalKind} AND NEW.phase='completed' AND (
      ${['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch'].map(field => `json_extract(NEW.entry_json,'$.${field}') IS NOT (
        SELECT json_extract(entry_json,'$.${field}') FROM run_journal
        WHERE run_id=NEW.run_id AND op_id=NEW.op_id AND attempt=NEW.attempt AND phase='dispatch_claimed')`).join(' OR ')})
      THEN RAISE(ABORT, 'local child journal completion must preserve its original local claim')
`;
const runJournalInsert = KERNEL_SCHEMA_V2_SQL.slice(KERNEL_SCHEMA_V2_SQL.indexOf('CREATE TRIGGER run_journal_validate_insert'),
  KERNEL_SCHEMA_V2_SQL.indexOf('CREATE TRIGGER run_journal_immutable_update'));
if (!runJournalInsert.startsWith('CREATE TRIGGER run_journal_validate_insert') ||
    !runJournalInsert.includes("'verifier', 'publish')")) throw new Error('compiled original Journal schema is incomplete');
// Await registration is a distinct local control accounting operation. Keep
// the original two local grant guards byte-for-byte and add a separate closed
// no-grant variant, rather than making a flag an alternate grant authority.
const localGrantRefGuard = `(json_type(NEW.entry_json, '$.grantRef') IS NOT 'text' OR
        length(json_extract(NEW.entry_json, '$.grantRef')) != 64 OR json_extract(NEW.entry_json, '$.grantRef') GLOB '*[^0-9a-f]*')`;
if (!localJournalGuard.includes(localGrantRefGuard)) throw new Error('compiled local child grant guard is incomplete');
const childAwaitJournalGuard = localJournalGuard.replaceAll(localJournalKind, "NEW.op_kind = 'child_await'")
  .replace(localGrantRefGuard, "json_type(NEW.entry_json, '$.grantRef') IS NOT NULL")
  .replace("THEN 15 WHEN 'dispatch_claimed' THEN 18 ELSE 20 END", "THEN 14 WHEN 'dispatch_claimed' THEN 17 ELSE 19 END");
// The fixed CAS-only read has its own local kind. It cannot borrow a physical
// lease or the no-grant await variant; the old branches remain byte-identical.
const skillResourceJournalGuard = localJournalGuard.replaceAll(localJournalKind, "NEW.op_kind = 'skill_resource'");
const childJournalInsert = runJournalInsert
  .replace("'verifier', 'publish')", "'verifier', 'publish', 'child_admission', 'child_merge', 'child_await', 'skill_resource')")
  .replace('    WHEN NEW.attempt < 0', localJournalGuard + childAwaitJournalGuard + skillResourceJournalGuard + '    WHEN NEW.attempt < 0');
const allocationMutablePaths = "'$.state', '$.terminal', '$.inclusiveBudgetUsage', '$.terminalAt', '$.childResultItemId', '$.parentSettlementRevision', '$.releasedUnusedBudget', '$.settledAt'";
export const KERNEL_SCHEMA_V8_SQL = `
ALTER TABLE runs ADD COLUMN parent_cancellation_ref TEXT
  CHECK(parent_cancellation_ref IS NULL OR (typeof(parent_cancellation_ref)='text' AND length(parent_cancellation_ref)=64 AND parent_cancellation_ref NOT GLOB '*[^0-9a-f]*'));
CREATE TRIGGER runs_parent_cancellation_unseeded
BEFORE INSERT ON runs WHEN NEW.parent_cancellation_ref IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'parent cancellation must be observed after child birth'); END;
CREATE TRIGGER runs_parent_cancellation_immutable
BEFORE UPDATE OF parent_cancellation_ref ON runs WHEN OLD.parent_cancellation_ref IS NOT NULL AND NEW.parent_cancellation_ref IS NOT OLD.parent_cancellation_ref
BEGIN SELECT RAISE(ABORT, 'parent cancellation registration is immutable'); END;
CREATE TRIGGER runs_parent_cancellation_register
BEFORE UPDATE OF parent_cancellation_ref ON runs WHEN OLD.parent_cancellation_ref IS NULL AND NEW.parent_cancellation_ref IS NOT NULL
BEGIN SELECT CASE WHEN OLD.status IN ('succeeded','completed_unverified','failed','cancelled') OR NEW.status IN ('succeeded','completed_unverified','failed','cancelled') OR
  OLD.parent_run_id IS NULL OR NEW.parent_run_id IS NOT OLD.parent_run_id OR NEW.cancel_requested IS NOT 1 OR NEW.stop_intent_ref IS NULL OR NEW.revision IS NOT OLD.revision+1
  THEN RAISE(ABORT, 'parent cancellation requires its nonterminal child fence transaction') END; END;
CREATE TRIGGER runs_parent_cancellation_fenced
BEFORE UPDATE ON runs WHEN NEW.parent_cancellation_ref IS NOT NULL AND
  (NEW.parent_run_id IS NULL OR NEW.parent_run_id IS NOT OLD.parent_run_id OR NEW.cancel_requested IS NOT 1 OR NEW.stop_intent_ref IS NULL OR NEW.status IN ('succeeded','completed_unverified'))
BEGIN SELECT RAISE(ABORT, 'parent cancellation dispatch fence cannot be cleared'); END;
CREATE UNIQUE INDEX child_allocations_one_parent ON child_allocations(child_run_id);
CREATE UNIQUE INDEX child_allocations_one_admission ON child_allocations(parent_run_id,json_extract(row_json,'$.admissionKey'));
CREATE UNIQUE INDEX child_allocations_one_delegate ON child_allocations(parent_run_id,json_extract(row_json,'$.delegateOpId'));
CREATE UNIQUE INDEX child_allocations_one_call_index ON child_allocations(parent_run_id,json_extract(row_json,'$.delegateBatchItemId'),json_extract(row_json,'$.delegateCallIndex'));
CREATE UNIQUE INDEX child_allocations_one_call_id ON child_allocations(parent_run_id,json_extract(row_json,'$.delegateBatchItemId'),json_extract(row_json,'$.delegateCallId'));
CREATE TRIGGER child_allocations_validate_insert
BEFORE INSERT ON child_allocations BEGIN
  SELECT CASE
    WHEN NOT json_valid(NEW.row_json) THEN RAISE(ABORT, 'child allocation must contain valid JSON')
    WHEN NEW.state != 'reserved' OR json_type(NEW.row_json) IS NOT 'object' OR
      json_extract(NEW.row_json,'$.schemaVersion') IS NOT 1 OR
      json_extract(NEW.row_json,'$.state') IS NOT NEW.state OR
      json_extract(NEW.row_json,'$.parentRunId') IS NOT NEW.parent_run_id OR
      json_extract(NEW.row_json,'$.childRunId') IS NOT NEW.child_run_id OR NEW.parent_run_id = NEW.child_run_id OR
      ${['admissionKey', 'delegateOpId', 'delegateBatchItemId', 'delegateCallId'].map(field => `(json_type(NEW.row_json,'$.${field}') IS NOT 'text' OR length(json_extract(NEW.row_json,'$.${field}')) < 1)`).join(' OR ')} OR
      json_type(NEW.row_json,'$.delegateCallIndex') IS NOT 'integer' OR json_extract(NEW.row_json,'$.delegateCallIndex') < 0 OR
      ${['terminal', 'inclusiveBudgetUsage', 'terminalAt', 'childResultItemId', 'parentSettlementRevision', 'releasedUnusedBudget', 'settledAt'].map(field => `json_type(NEW.row_json,'$.${field}') IS NOT NULL`).join(' OR ')}
      THEN RAISE(ABORT, 'child allocation must begin with its original reserved identity')
  END;
END;
CREATE TRIGGER child_allocations_validate_update
BEFORE UPDATE ON child_allocations BEGIN
  SELECT CASE
    WHEN NOT json_valid(NEW.row_json) THEN RAISE(ABORT, 'child allocation must contain valid JSON')
    WHEN NEW.parent_run_id IS NOT OLD.parent_run_id OR NEW.child_run_id IS NOT OLD.child_run_id OR
      json_extract(NEW.row_json,'$.state') IS NOT NEW.state OR
      json_remove(NEW.row_json,${allocationMutablePaths}) IS NOT json_remove(OLD.row_json,${allocationMutablePaths})
      THEN RAISE(ABORT, 'child allocation original identity is immutable')
    WHEN NOT ((OLD.state = 'reserved' AND NEW.state = 'child_terminal') OR
      (OLD.state = 'child_terminal' AND NEW.state = 'settled'))
      THEN RAISE(ABORT, 'child allocation transition is not monotonic')
    WHEN json_type(NEW.row_json,'$.terminal') IS NOT 'object' OR
      json_type(NEW.row_json,'$.inclusiveBudgetUsage') IS NOT 'object' OR json_type(NEW.row_json,'$.terminalAt') IS NOT 'text'
      THEN RAISE(ABORT, 'child allocation terminal data is incomplete')
    WHEN OLD.state = 'child_terminal' AND (
      json_extract(NEW.row_json,'$.terminal') IS NOT json_extract(OLD.row_json,'$.terminal') OR
      json_extract(NEW.row_json,'$.inclusiveBudgetUsage') IS NOT json_extract(OLD.row_json,'$.inclusiveBudgetUsage') OR
      json_extract(NEW.row_json,'$.terminalAt') IS NOT json_extract(OLD.row_json,'$.terminalAt'))
      THEN RAISE(ABORT, 'child allocation original terminal and usage are immutable')
    WHEN NEW.state = 'settled' AND (json_type(NEW.row_json,'$.childResultItemId') IS NOT 'text' OR
      json_type(NEW.row_json,'$.parentSettlementRevision') IS NOT 'integer' OR json_extract(NEW.row_json,'$.parentSettlementRevision') < 1 OR
      json_type(NEW.row_json,'$.releasedUnusedBudget') IS NOT 'object' OR json_type(NEW.row_json,'$.settledAt') IS NOT 'text')
      THEN RAISE(ABORT, 'child allocation settlement data is incomplete')
  END;
END;
CREATE TRIGGER child_allocations_immutable_delete
BEFORE DELETE ON child_allocations BEGIN
  SELECT RAISE(ABORT, 'child allocation history is retained');
END;
DROP TRIGGER run_journal_validate_insert;
${childJournalInsert}
CREATE INDEX authorization_grants_list_order_v1 ON authorization_grants(owner_principal_id,json_extract(row_json,'$.createdAt') COLLATE BINARY,grant_id COLLATE BINARY);
`;
const pristineSchemaV6 = [KERNEL_SCHEMA_V1_SQL, KERNEL_SCHEMA_V2_SQL, KERNEL_SCHEMA_V3_SQL,
  KERNEL_SCHEMA_V4_SQL, KERNEL_SCHEMA_V5_SQL, KERNEL_SCHEMA_V6_SQL].join('\n');
const pristineSchemaV7 = `${pristineSchemaV6}\n${KERNEL_SCHEMA_V7_SQL}`;
const pristineSchemaV8 = `${pristineSchemaV7}\n${KERNEL_SCHEMA_V8_SQL}`;
export const KERNEL_SCHEMA_SQL = pristineSchemaV8;

/** Historical birth data only. Upgrading a database cannot rewrite the
 * original generation's version, DDL digest or empty-database identity.
 * These three birth recipes have exactly 21 authority tables;
 * today's table inventory must never change their retained identities. */
export function kernelSchemaBirthRecipe(version: unknown): Readonly<{
  userVersion: number; schemaDigest: string; emptyDatabaseContentDigest: string;
}> {
  if (version !== 6 && version !== 7 && version !== 8) throw new KernelStorageError('RECOVERY_REQUIRED', 'unsupported retained kernel schema birth recipe');
  const sql = version === 6 ? pristineSchemaV6 : version === 7 ? pristineSchemaV7 : pristineSchemaV8;
  return Object.freeze({ userVersion: version, schemaDigest: sha256Bytes(Buffer.from(sql, 'utf8')),
    emptyDatabaseContentDigest: canonicalSha256({ applicationId: KERNEL_SQLITE_APPLICATION_ID, userVersion: version, tables: 21 }) });
}

/** One table inventory for pristine bootstrap and its retained birth recipe. */
export const KERNEL_AUTHORITY_TABLES = Object.freeze([
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
  'source_inspection_attempts',
  'mcp_registrations',
  'admin_operations'
] as const);
const REQUIRED_TABLES = KERNEL_AUTHORITY_TABLES;

function pragmaScalar(driver: SqliteConnection, name: string): unknown {
  const row = driver.prepare(`PRAGMA ${name}`).get();
  if (typeof row !== 'object' || row === null) return undefined;
  return Object.values(row)[0];
}

export function applyKernelSchema(driver: SqliteDriver): void {
  const userVersion = requiredSafeInteger(pragmaScalar(driver, 'user_version'), 'user_version');
  const applicationId = requiredSafeInteger(pragmaScalar(driver, 'application_id'), 'application_id');
  if (![0, 1, 2, 3, 4, 5, 6, 7, KERNEL_STATE_SCHEMA_VERSION].includes(userVersion)) {
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
  } else if (userVersion < KERNEL_STATE_SCHEMA_VERSION) {
    driver.transaction((connection) => {
      if (userVersion === 1) connection.exec(KERNEL_SCHEMA_V2_SQL);
      if (userVersion < 3) connection.exec(KERNEL_SCHEMA_V3_SQL);
      if (userVersion < 4) connection.exec(KERNEL_SCHEMA_V4_SQL);
      if (userVersion < 5) connection.exec(KERNEL_SCHEMA_V5_SQL);
      if (userVersion < 6) connection.exec(KERNEL_SCHEMA_V6_SQL);
      if (userVersion < 7) connection.exec(KERNEL_SCHEMA_V7_SQL);
      if (userVersion < 8) {
        validateRetainedChildAllocations(connection);
        connection.exec(KERNEL_SCHEMA_V8_SQL);
      }
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

function validateRetainedChildAllocations(connection: SqliteConnection): void {
  const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const originalText = (value: unknown): string => {
    if (!(value instanceof Uint8Array)) throw new TypeError('unbounded allocation text');
    const text = utf8.decode(value);
    if (!Buffer.from(text, 'utf8').equals(value)) throw new TypeError('allocation text bytes changed');
    return text;
  };
  const rows = connection.prepare(`SELECT
    CASE WHEN length(CAST(parent_run_id AS BLOB)) <= 1048576 THEN CAST(parent_run_id AS BLOB) END AS parent_run_id,
    CASE WHEN length(CAST(child_run_id AS BLOB)) <= 1048576 THEN CAST(child_run_id AS BLOB) END AS child_run_id,
    CASE WHEN length(CAST(state AS BLOB)) <= 1048576 THEN CAST(state AS BLOB) END AS state,
    CASE WHEN length(CAST(row_json AS BLOB)) <= 1048576 THEN CAST(row_json AS BLOB) END AS row_json FROM child_allocations`).iterate();
  for (const row of rows) {
    try {
      const value = decodeChildAllocation(parseJsonStrict(originalText(row.row_json)));
      if (value.parentRunId !== originalText(row.parent_run_id) || value.childRunId !== originalText(row.child_run_id) || value.state !== originalText(row.state))
        throw new TypeError('allocation index mismatch');
    } catch (cause) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'schema migration requires complete original child allocation data', { cause });
    }
  }
}

export function readSchemaUserVersion(connection: SqliteConnection): number {
  const row = connection.prepare('SELECT user_version FROM pragma_user_version').get<{ user_version: unknown }>();
  return requiredSafeInteger(row?.user_version, 'user_version');
}

const SCHEMA_CATALOG_SQL = 'SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name';
let pristineCatalogDigest: string | undefined;

/** Genesis only: version/table presence cannot attest an unowned database.
 * Compile the fixed DDL with this same SQLite engine so its catalog-normalized
 * table/index/trigger definitions, not a hand-maintained allowlist, are exact.
 * Root pages and runtime data are deliberately outside the schema identity. */
export function assertPristineKernelSchema(connection: SqliteConnection): void {
  if (pristineCatalogDigest === undefined) {
    const expected = new DatabaseSync(':memory:');
    let digest: string;
    try {
      expected.exec(KERNEL_SCHEMA_SQL);
      digest = canonicalSha256(expected.prepare(SCHEMA_CATALOG_SQL).all());
    } finally { expected.close(); }
    pristineCatalogDigest = digest;
  }
  if (requiredSafeInteger(pragmaScalar(connection, 'application_id'), 'application_id') !== KERNEL_SQLITE_APPLICATION_ID ||
      requiredSafeInteger(pragmaScalar(connection, 'user_version'), 'user_version') !== KERNEL_STATE_SCHEMA_VERSION ||
      canonicalSha256(connection.prepare(SCHEMA_CATALOG_SQL).all()) !== pristineCatalogDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'fresh genesis requires the exact pristine kernel schema');
  }
}

/** Fixed source for signed schema data. Callers never execute statements taken
 * from a package: package bytes must equal this compiled recipe in full. */
export function kernelSchemaDefinition(version: 7 | 8) {
  const ddl = version === 7 ? pristineSchemaV7 : pristineSchemaV8;
  const database = new DatabaseSync(':memory:');
  try {
    database.exec(ddl);
    const catalog = database.prepare(SCHEMA_CATALOG_SQL).all().map(row => ({ ...row })) as Array<{
      type: string; name: string; tbl_name: string; sql: string | null }>;
    return { ddl, catalog, catalogDigest: canonicalSha256(catalog) };
  } finally { database.close(); }
}

export function kernelSchemaManifest<Version extends 7 | 8>(version: Version) {
  const core = { schemaVersion: 1 as const, format: 'cliq-kernel-schema-manifest-v1' as const,
    applicationId: KERNEL_SQLITE_APPLICATION_ID, userVersion: version,
    schemaDigest: kernelSchemaBirthRecipe(version).schemaDigest };
  return { ...core, manifestDigest: canonicalSha256(core) };
}

export function assertKernelSchemaVersion(connection: SqliteConnection, version: 7 | 8): void {
  if (readSchemaUserVersion(connection) !== version ||
      requiredSafeInteger(connection.prepare('SELECT application_id FROM pragma_application_id').get<{ application_id: unknown }>()?.application_id, 'application_id') !== KERNEL_SQLITE_APPLICATION_ID ||
      canonicalSha256(connection.prepare(SCHEMA_CATALOG_SQL).all()) !== kernelSchemaDefinition(version).catalogDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'database differs from its exact signed schema recipe');
}

/** Only the explicit signed-upgrade transaction calls this. No package SQL is
 * evaluated, and neither the lock nor a new owner is supplied by this helper. */
export function applySignedKernelSchema7To8(connection: SqliteConnection): void {
  assertKernelSchemaVersion(connection, 7);
  validateRetainedChildAllocations(connection);
  connection.exec(KERNEL_SCHEMA_V8_SQL);
  connection.exec('PRAGMA user_version=8');
  assertKernelSchemaVersion(connection, 8);
}
