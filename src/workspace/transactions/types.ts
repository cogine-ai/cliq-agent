export type TxKind = 'edit'; // 'worktree' deferred to v0.9

export type TxState =
  | 'staging'
  | 'finalized'
  | 'validated'
  | 'approved'
  | 'applied'
  | 'aborted'
  | 'applied-partial';

export type Severity = 'blocking' | 'advisory';

export type DiffSummary = {
  filesChanged: number;
  additions: number;
  deletions: number;
  creates: string[];
  modifies: string[];
  deletes: string[];
};

export type OverrideEntry = {
  validatorName: string;
  reason?: string;
  by: string;
  ts: string;
};

export type AuditEntry = {
  ts: string;
  from: TxState | null;
  to: TxState;
  by: string;
  overrides?: string[];
  reason?: string;
};

export type Transaction = {
  id: string;
  kind: TxKind;
  state: TxState;
  workspaceId: string;
  sessionId: string;
  workspaceRealPath: string;
  createdAt: string;
  updatedAt: string;
  diffSummary?: DiffSummary;
  diffArtifactPath?: string;
  validators?: ValidatorResultSummary[];
  blockingFailures?: string[];
  overridesApplied?: OverrideEntry[];
  ghostSnapshotId?: string;
  error?: { stage: string; message: string };
};

export type ValidatorResultSummary = {
  name: string;
  severity: Severity;
  status: 'pass' | 'fail' | 'error';
  durationMs: number;
};

export type ApplyPhase =
  | 'apply-pending'
  | 'apply-writing'
  | 'apply-committed'
  | 'apply-finalized'
  | 'apply-failed-partial';

export type ApplyProgress = {
  phase: ApplyPhase;
  ghostSnapshotId: string;
  startedAt: string;
  filesPlanned: string[];
  filesWritten: string[];
  error?: { stage: string; path?: string; message: string };
};

export type AbortPhase = 'aborting' | 'aborted';

export type AbortReason =
  | 'validator-fail'
  | 'user-abort'
  | 'apply-error'
  | 'apply-conflict'
  | 'staging-error'
  | 'apply-failed-partial-restored'
  | 'apply-failed-partial-kept';

export type AbortProgress = {
  phase: AbortPhase;
  reason: AbortReason;
  startedAt: string;
  ts: string;
};

export type DiffEntry =
  | { path: string; op: 'create'; newContent: string }
  | { path: string; op: 'modify'; oldContent: string; newContent: string }
  | { path: string; op: 'delete'; oldContent: string };

export type BashEffect = {
  command: string;
  exitCode: number;
  ts: string;
  pathsChanged: string[];
  outOfBand: true;
};

export type Diff = {
  files: DiffEntry[];
  outOfBand: BashEffect[];
};

// Used by store.ts when generating new transaction ids.
export const TX_ID_PREFIX = 'tx_';
export const OPEN_RECORD_ID_PREFIX = 'txrec_open_';
export const APPLY_RECORD_ID_PREFIX = 'txrec_apply_';
export const ABORT_RECORD_ID_PREFIX = 'txrec_abort_';

export function openRecordId(txId: string): string {
  return `${OPEN_RECORD_ID_PREFIX}${txId}`;
}

export function applyRecordId(txId: string): string {
  return `${APPLY_RECORD_ID_PREFIX}${txId}`;
}

export function abortRecordId(txId: string): string {
  return `${ABORT_RECORD_ID_PREFIX}${txId}`;
}

// Aggregates validator results into the shape the session record stores.
// Status 'error' is intentionally counted under 'fail' to match the spec's
// session-record schema (Section 15) which only has pass/fail buckets.
// Callers that need to distinguish errored from failed validators should
// walk tx.validators directly.
export function validatorSummaryFromTx(tx: Transaction): {
  blocking: { pass: number; fail: number };
  advisory: { pass: number; fail: number; names: string[] };
} {
  const summary = {
    blocking: { pass: 0, fail: 0 },
    advisory: { pass: 0, fail: 0, names: [] as string[] }
  };
  for (const v of tx.validators ?? []) {
    if (v.severity === 'blocking') {
      if (v.status === 'pass') summary.blocking.pass++;
      else summary.blocking.fail++;
    } else {
      if (v.status === 'pass') {
        summary.advisory.pass++;
      } else {
        summary.advisory.fail++;
        summary.advisory.names.push(v.name);
      }
    }
  }
  return summary;
}
