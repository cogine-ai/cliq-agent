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

// txIds produced by makeTxId() match `tx_<26 Crockford32 chars>` exactly.
// CLI- or test-supplied ids may use slightly less restrictive shapes (e.g.,
// `tx_lock`, `tx_x`) but must still:
//   - start with the `tx_` prefix
//   - contain only [A-Za-z0-9_-] (no path separators, no `.`, no `..`,
//     no NUL, no whitespace)
//   - be 4..128 chars total
// This is the minimum that blocks the path-traversal attack vector
// (`tx_..` or `tx_../../foo`) while keeping test fixtures workable.
// Production code paths still call makeTxId() which produces the full
// strict 26-char Crockford32 shape.
const TX_ID_STRICT_PATTERN = /^tx_[0-9A-HJKMNP-TV-Z]{26}$/;
const TX_ID_LENIENT_PATTERN = /^tx_[A-Za-z0-9_-]{1,124}$/;

export function isValidTxId(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  return TX_ID_LENIENT_PATTERN.test(value);
}

export function isStrictTxId(value: unknown): value is string {
  return typeof value === 'string' && TX_ID_STRICT_PATTERN.test(value);
}

/**
 * Validates a txId against the lenient shape that prevents path traversal.
 * Throws InvalidTxIdError if the value contains `..`, `/`, `\`, or any other
 * character outside `[A-Za-z0-9_-]`, or if the prefix or length is wrong.
 *
 * Call this at every external trust boundary BEFORE the value flows into
 * `path.join(txRoot, txId)` to prevent `tx_../../foo` from escaping the
 * per-tx directory.
 */
export function assertValidTxId(value: unknown): asserts value is string {
  if (!isValidTxId(value)) {
    throw new InvalidTxIdError(value);
  }
}

export class InvalidTxIdError extends Error {
  constructor(value: unknown) {
    const display = typeof value === 'string' ? JSON.stringify(value) : String(value);
    super(
      `invalid tx id: ${display} (expected tx_ prefix + [A-Za-z0-9_-]{1,124}, no path separators)`
    );
    this.name = 'InvalidTxIdError';
  }
}

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
