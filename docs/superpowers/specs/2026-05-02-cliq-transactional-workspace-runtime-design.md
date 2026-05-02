# Cliq Transactional Workspace Runtime Design

**Date:** 2026-05-02
**Status:** Draft
**Target Release:** `v0.7.0` (edit-tx) / `v0.8.0` (worktree-tx, deferred)

## 1. Summary

Cliq today applies tool mutations directly to the working tree. Phase 3 added Git-backed ghost snapshots so users can recover from bad turns after the fact. This release adds the inverse: a pre-mutation gate that lets the agent stage changes, generate a structured diff, run validators, and require approval before any file in the real workspace is touched.

The new layer is called the **transactional workspace runtime**. A transaction (tx) is a persistent, externally consumable artifact that captures the proposed change set, the validator results, and an audit trail of state transitions. Tx coexists with Phase 3 ghost snapshots; it does not replace recovery, it adds prevention.

The release ships two concrete capabilities:

- **edit-tx**: a lightweight overlay that captures `edit`-style declarative file changes; `bash` continues to run against the real working tree, with its side-effects flagged in the diff but not staged.
- **state machine + headless JSON protocol**: a tx is a persistent object under `$CLIQ_HOME/tx/<id>/` with explicit transitions; CLI commands and a `--json` envelope let CI, external tools, and human reviewers consume it without sharing process state.

A heavier `worktree-tx` mode (where `bash` side-effects are also captured by running inside a Git worktree) is described in this document as a forward-compatible extension but is **not** implemented in this release.

## 2. Roadmap Placement

This release sits between Phase 3 (Session As Workflow Asset) and Phase 6 (Automation, Worktrees, Rich UX) on the runtime architecture roadmap. It is not a new layer; it lives inside the existing **Runtime/Tool Layer**.

It builds on:

- Phase 3's `$CLIQ_HOME` global storage and workspace identity model
- Phase 3's ghost snapshot mechanism (used as the apply-pre safety net)
- Phase 3's session record append model

It does not depend on, but is designed to compose cleanly with:

- A separately-tracked auto-compact effort in the session/context layer (see Section 15)
- A future Phase 4 headless RPC/JSONL surface (the JSON envelope defined here is intended to be that surface's first consumer)

It does not implement, defer to later phases:

- worktree-tx (`v0.8` or Phase 6)
- TUI / visual diff browsing
- automated retry loops driven by validator failures
- model-callable validators or model-controlled approval

## 3. Goals

### 3.1 Product Goals

- Let users opt into a "PR-like" review gate where the agent's full multi-step work surfaces as one diff to approve or reject.
- Let CI / headless callers consume agent output as a structured artifact (diff + validator report + approval handle) without depending on stdin prompts.
- Let users group multiple turns into a single transaction so a coherent task gets reviewed as a whole, not one tool call at a time.
- Make rejection cheap: if the diff is wrong, throw it away without touching the real workspace.
- Run project-defined checks (typecheck, tests, lint) against the staged view before apply, not the real workspace.

### 3.2 Architecture Goals

- Keep `edit` and `bash` tool implementations untouched; route writes through a `WorkspaceWriter` abstraction the runner injects.
- Represent transactions as first-class persistent objects under `$CLIQ_HOME`, not transient command outputs.
- Define a single JSON envelope shape used by every `--json` command and by `--headless` mode, so callers write one parser.
- Keep validator severity (blocking vs advisory) explicit and per-validator-overridable, with audit trail.
- Default to off. Existing users see no behavior change until they opt in.

## 4. Non-Goals

This release does not provide:

- worktree-tx mode (full workspace as a Git worktree so `bash` side-effects are captured)
- cross-session transaction merging or rebasing
- partial apply (applying only some files from a tx)
- automatic validator-driven retry loops
- model-registered validators or model-decided override
- a non-Git overlay alternative for ghost snapshots (still requires Git for snapshot coverage)
- TUI or visual diff browsing
- RPC / SDK packaging of the tx protocol (Phase 4 concern)
- cross-workspace shared transactions

## 5. Core Concepts

Cliq must distinguish three layers of state, each with its own lifecycle:

1. **Workspace mutation layer (where this release lives)**: file edits, file creations, file deletions, and shell side-effects. The tx system stages declarative file changes; `bash` side-effects remain out-of-band.
2. **Session/context layer (Phase 3, plus the parallel auto-compact effort)**: append-only records, checkpoints, compactions, handoffs. The tx system writes summary records into this layer, but never raw diffs.
3. **Runtime side effects (out of scope for any layer)**: shell processes, databases, services, network calls. Neither tx nor checkpoint claims to manage these.

The contract between layers is one-way: tx writes summary records into the session; the session/auto-compact never reads tx internals or modifies workspace files. See Section 15 for the precise record schema.

## 6. Storage Model

Tx storage extends Phase 3's `$CLIQ_HOME` layout. No new top-level storage roots are introduced.

```text
$CLIQ_HOME/
  workspaces/<workspaceId>/state.json   # extended: + activeTxId
  tx/<txId>/
    state.json                          # current state, kind, sessionId, workspaceId, timestamps
    diff.json                           # structured diff (per-file old→new, modes, creates, deletes)
    overlay/                            # materialized staged files (durable across cliq restart)
    validators/<validatorName>.json     # per-validator structured result
    audit.json                          # append-only state transition log
  sessions/...                          # Phase 3, unchanged
  checkpoints/...                       # Phase 3, unchanged
```

`workspaceId` and `sessionId` use the same definitions Phase 3 establishes (`workspaceId = sha256(realpath(cwd))`; `sessionId` from the session store).

`txId` format: `tx_<ulid>`. ULIDs sort lexicographically by creation time, which makes `cliq tx list` and directory listings naturally chronological.

The `overlay/` directory is materialized to disk as edits arrive, not held in memory. This is required by the multi-turn lifecycle (Section 8): a tx must survive `cliq` process restart and be resumable from another invocation in the same session.

`overlay/` is cleaned up immediately after a successful `applied` transition. After `aborted`, it is retained for `transactions.abortRetention` (default 7 days) for audit and post-mortem inspection, then garbage-collected by a deferred cleanup pass.

## 7. Transaction Schema

```ts
export type TxKind = 'edit';   // 'worktree' deferred to v0.8

export type TxState =
  | 'staging'      // overlay accepts mutations
  | 'finalized'    // overlay frozen, diff materialized
  | 'validated'    // validators have run (does not imply pass)
  | 'approved'     // no unaddressed blocking failures
  | 'applied'      // overlay written to real workspace
  | 'aborted'      // tx discarded
  | 'applied-partial';  // error path only; see Section 16

export type Severity = 'blocking' | 'advisory';

export type Transaction = {
  id: string;
  kind: TxKind;
  state: TxState;
  workspaceId: string;
  sessionId: string;
  workspaceRealPath: string;
  createdAt: string;
  updatedAt: string;
  diffSummary?: DiffSummary;            // populated at finalize
  diffArtifactPath?: string;            // populated at finalize
  validators?: ValidatorResult[];       // populated at validate
  blockingFailures?: string[];          // derived from validators
  overridesApplied?: OverrideEntry[];   // populated at approve/apply
  ghostSnapshotId?: string;             // populated at apply
  error?: { stage: string; message: string };  // populated on failure paths
};

export type DiffSummary = {
  filesChanged: number;
  additions: number;
  deletions: number;
  creates: string[];     // workspace-relative paths
  modifies: string[];
  deletes: string[];
};

export type OverrideEntry = {
  validatorName: string;
  reason?: string;
  by: string;             // 'cli' | 'auto' | '<callerId>'
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
```

`Transaction.state` is the source of truth; `state.json` on disk is the persistent form.

## 8. State Machine

```text
staging → finalized → validated → approved → applied
                                           ↘ aborted
```

| State | Triggering action | Effect |
|---|---|---|
| `staging` | `tx open` (explicit) or auto-open at turn start (implicit) | overlay accepts mutations from `edit` and equivalent tools |
| `finalized` | `tx finalize` or auto-finalize at turn end | overlay frozen; `diff.json` materialized; further mutations rejected |
| `validated` | `tx validate` after running all configured validators | per-validator results written; state transition records "checked", not "passed" |
| `approved` | `tx approve` (explicit) or auto-approve when no blocking failures and `applyPolicy` permits | every blocking failure has either passed or been explicitly overridden |
| `applied` | `tx apply` | ghost snapshot taken, overlay written to real workspace, session record appended |
| `aborted` | `tx abort` or any transition that errors out terminally | overlay retained per `abortRetention`, no real workspace changes |

Transitions are append-only forward (except `* → aborted`). A `finalized` tx cannot accept new mutations; the user must `abort` and `open` a new tx.

Every transition writes an `AuditEntry` to `audit.json` inside the per-tx directory.

`tx apply` invoked on a tx in `staging`/`finalized`/`validated`/`approved` automatically runs the missing forward transitions, gated by `applyPolicy`. This is the common interactive path; explicit step-by-step transitions exist for headless callers and debugging.

The `applied-partial` state is reachable only from the apply path when filesystem operations partially succeed. It is not a normal transition target. See Section 16 for handling.

## 9. Edit-tx Overlay Model

Edit-tx captures declarative file changes from `edit`-style tools. `bash` is excluded from the overlay (Section 9.4).

### 9.1 Overlay storage

Each accepted mutation writes the full post-mutation file content into `$CLIQ_HOME/tx/<txId>/overlay/<workspace-relative-path>`. The overlay tree mirrors the workspace tree for changed paths only; unchanged files are not copied.

Deletions are recorded by writing a sibling marker file: `<path>.cliq-tx-delete`. This avoids ambiguity between "file not staged" and "file marked for deletion" without requiring a separate manifest.

### 9.2 Diff materialization

At `finalize`, the tx-coordinator walks `overlay/`, compares each staged file against the corresponding real-workspace file, and writes a structured `diff.json`:

```ts
type Diff = {
  files: Array<
    | { path: string; op: 'create'; newContent: string }
    | { path: string; op: 'modify'; oldContent: string; newContent: string }
    | { path: string; op: 'delete'; oldContent: string }
  >;
  outOfBand: BashEffect[];  // see 9.4
};
```

Storing full content (not patches) keeps the format simple and makes apply trivially deterministic. Patches can be derived on demand by `cliq tx diff` for human display.

### 9.3 Staged view materialization (for validators)

Validators need to see the post-apply state without requiring an actual apply. At `validate`, the tx-coordinator materializes `$CLIQ_HOME/tx/<txId>/staged-view/`:

1. Hard-link or copy the real workspace tree into `staged-view/`, respecting `.gitignore` for performance (skip ignored directories like `node_modules`).
2. Apply the overlay on top.
3. Pass `staged-view/` to validators as `ValidatorContext.workspaceView`.
4. After validation, delete `staged-view/` (kept only with `--keep-staged-view` debug flag).

For workspaces with very large ignored directories, copying is still expensive; this release accepts that cost. A faster sparse strategy (only materialize files that the staged view differs in, plus dependencies) is deferred until a real performance complaint surfaces.

### 9.4 `bash` side-effects (out-of-band)

`bash` always runs against the real `cwd`. Its side-effects on the file system are not staged. To preserve diff honesty, every `bash` invocation during a tx writes a `BashEffect` record:

```ts
type BashEffect = {
  command: string;
  exitCode: number;
  ts: string;
  pathsChanged: string[];   // best-effort: files modified by mtime comparison before/after
  outOfBand: true;          // explicit marker so consumers do not treat it as staged
};
```

The tx-coordinator takes a directory mtime snapshot before the `bash` call and compares after. This is best-effort: it catches typical `npm install`, `mkdir`, generated-file scenarios; it cannot detect every form of side-effect.

These records appear in `diff.outOfBand[]` and in the `--json` envelope, so reviewers see "the agent also ran `npm install`, which modified `node_modules/` and `package-lock.json`". They are explicitly **not** in the staged diff and are **not** rolled back if the tx is aborted.

This is the v1 honest tradeoff: edit-tx covers declarative file changes, `bash` is acknowledged but not contained. Users who want full containment use worktree-tx (deferred).

## 10. Validators

### 10.1 Validator contract

Built-in and shell-hook validators implement the same interface:

```ts
type ValidatorContext = {
  tx: Transaction;
  workspaceView: string;     // path to materialized staged view
  realCwd: string;           // real workspace path; informational, do not mutate
  signal: AbortSignal;
};

type ValidatorStatus = 'pass' | 'fail' | 'error';

type ValidatorResult = {
  name: string;
  severity: Severity;
  status: ValidatorStatus;
  durationMs: number;
  message?: string;
  findings?: Finding[];
  artifactPath?: string;     // pointer to per-validator stdout/details
};

type Finding = {
  path?: string;
  line?: number;
  column?: number;
  severity?: Severity;
  message: string;
};

type Validator = {
  name: string;
  defaultSeverity: Severity;
  run(ctx: ValidatorContext): Promise<ValidatorResult>;
};
```

`status: 'error'` distinguishes validator infrastructure failure (e.g., timeout, command not found) from a clean fail. Errors do not satisfy "blocking pass" and do not satisfy "blocking fail with override"; they require explicit `--allow-validator-error <name>`.

### 10.2 Built-in validators

| Name | Default severity | Check |
|---|---|---|
| `builtin:diff-sanity` | `blocking` | every modify target exists; every create target does not exist or is being overwritten with explicit consent; no path escapes the workspace; binary content is not silently treated as text |
| `builtin:index-clean` | `blocking` | apply will not write into the Git index (consistent with Phase 3's worktree-only restore); the Git index has not been modified externally between finalize and apply |
| `builtin:size-limit` | `advisory` | no single file diff exceeds 5000 lines (configurable); guards against runaway generation |

Built-ins can be disabled per workspace via `transactions.validators.disabled`.

### 10.3 Shell-hook validators

Configured in `.cliq/config.json`:

```json
"validators": {
  "shell": [
    { "name": "tsc",   "command": "npm run typecheck", "severity": "blocking", "timeoutMs": 60000 },
    { "name": "tests", "command": "npm test",          "severity": "advisory", "timeoutMs": 120000 }
  ]
}
```

Adapted into `Validator` instances with:

- `cwd` set to `workspaceView` (not the real `cwd` — running tests against the real workspace defeats the gate)
- environment extended with `CLIQ_TX_ID`, `CLIQ_TX_DIFF_PATH`, `CLIQ_WORKSPACE_REAL_PATH`
- exit code 0 → `status: 'pass'`; non-zero → `status: 'fail'`; timeout → `status: 'error'`
- stdout + stderr captured into the per-validator artifact file, truncated to a configurable cap (default 256 KB) before being inlined into `message`

Shell hook validators may only be configured in `.cliq/config.json`. Models cannot register validators or modify the configured set; this is the deliberate exclusion of the model-callable validator anti-pattern from the design exploration.

### 10.4 Execution model

`tx validate` execution:

1. Materialize the staged view (Section 9.3).
2. Run all configured validators **in parallel** by default. `transactions.validators.serial: true` opts into serial execution for resource-constrained environments.
3. Write each `ValidatorResult` to `validators/<name>.json`.
4. Update `state.json` with a derived `validatorSummary` and `blockingFailures`.
5. Transition to `validated`.

`validated` reflects "validation has run", not "validation has passed". The pass/fail decision is made at the next transition (`approve` or `apply`).

### 10.5 Override mechanism

Approving or applying a tx with blocking failures requires explicit per-validator override:

```bash
cliq tx apply --override shell:tsc --reason "flaky in CI, fix in follow-up"
```

Rules:

- Plain `tx approve` / `tx apply` without `--override` fail (exit code 2) if any blocking validator failed.
- `--override <name>` removes that validator from the blocking set for this transition only.
- Multiple `--override` flags accumulate.
- `--override-all` is supported but requires `--reason "..."`; the reason is recorded in audit.
- `--allow-validator-error <name>` is required to proceed past `status: 'error'`; this is separate from `--override` because errors are not informed decisions in the same way.
- Every override writes an `OverrideEntry` to the audit log and to `Transaction.overridesApplied`.

Advisory failures never block any transition; they appear as warnings in interactive output and as records in the `--json` envelope.

## 11. Apply Mechanics and Phase 3 Coexistence

### 11.1 Apply sequence

```
tx apply (called from approved state):
  1. acquire tx-store lock
  2. recheck builtin:index-clean (it may have changed since validate)
  3. create Phase 3 ghost snapshot, store id in tx.ghostSnapshotId
  4. for each diff entry in diff.json:
       - create: write new file (fail if exists, unless overlay marked overwrite)
       - modify: read current real file, verify it matches diff.oldContent, then write newContent
       - delete: verify current file matches diff.oldContent, then unlink
  5. if any step in (4) fails after partial writes:
       - transition to applied-partial
       - emit error including ghostSnapshotId and a manual restore command
       - DO NOT auto-roll-back (filesystem operations are not transactional; pretending otherwise causes worse damage)
  6. otherwise:
       - append session record (kind: 'tx-applied', see Section 15)
       - transition to applied
       - schedule overlay/ cleanup
  7. release tx-store lock
```

The recheck in step 2 is necessary because validation may have run minutes or hours earlier; the user may have done a `git checkout` in between. If oldContent verification fails in step 4, that file's modification is rejected with a clear "external change detected" message before any partial state.

### 11.2 Why pre-apply ghost snapshot

A turn already triggers a Phase 3 ghost snapshot at its start. In tx mode (especially explicit multi-turn or headless deferred-apply), the time gap between that snapshot and the apply moment can be large. The pre-apply snapshot freezes the apply-time state so post-apply restore remains useful.

Two ghost snapshots per applied tx is acceptable overhead: ghost snapshots are cheap Git objects and are eligible for normal Git GC.

### 11.3 Layer responsibilities (do not blur)

| Layer | Trigger | Purpose | Lifetime |
|---|---|---|---|
| Phase 3 ghost snapshot | turn start (existing); apply pre (new) | post-mutation recovery point | Git object lifetime |
| tx overlay | tx in `staging` | pre-mutation review artifact | tx terminal state + retention |
| validator results | tx in `validated` | structured pass/fail evidence | tx terminal state + retention |

Tx does not replace ghost snapshots. Ghost snapshots do not replace tx. They answer different questions.

## 12. CLI Surface

### 12.1 Top-level flags

```bash
cliq --tx edit "task..."              # enable edit-tx for this run
cliq --tx off "task..."               # force tx off (overrides config)
cliq --tx-apply manual-only "..."     # override applyPolicy for this run
cliq --headless ...                   # non-interactive: forced --json, manual-only apply, no prompts, no color
```

### 12.2 `tx` subcommand group

```bash
cliq tx open <name>                                # explicit multi-turn tx
cliq tx status [<txId>]                            # default: active tx in current session
cliq tx diff   [<txId>]                            # render accumulated diff
cliq tx show   [<txId>] [--json]                   # full envelope (default text)
cliq tx list   [--json]                            # all tx in current workspace, including history
cliq tx validate [<txId>]                          # run validators
cliq tx approve  [<txId>] [--override <name> ...] [--reason "..."]
cliq tx apply    [<txId>] [--override <name> ...] [--reason "..."]
cliq tx abort    [<txId>] [--reason "..."]
cliq tx validators                                 # show configured validators and their severities
cliq tx help
```

`<txId>` defaults to the current session's `activeTxId`. If neither is provided nor inferable, the command exits 1 with a clear error directing the user to either pass `<txId>` or run `cliq tx open`.

`tx apply` without prior `tx finalize`/`tx validate`/`tx approve` automatically runs the missing forward transitions, subject to `applyPolicy`. This is the common interactive path. Step-by-step subcommands exist for headless callers and debugging.

`tx finalize` is intentionally not exposed as a subcommand. Finalize is always implied by validate or apply; surfacing it separately would add a vocabulary item with no use case beyond debugging.

## 13. Headless JSON Protocol

### 13.1 Envelope shape

All `--json` output and all `--headless` output follows one envelope:

```json
{
  "schemaVersion": 1,
  "command": "tx.apply",
  "tx": {
    "id": "tx_01HX...",
    "kind": "edit",
    "state": "applied",
    "sessionId": "sess_...",
    "workspaceId": "ws_...",
    "createdAt": "2026-05-02T10:00:00Z",
    "updatedAt": "2026-05-02T10:00:42Z",
    "diffSummary": {
      "filesChanged": 4,
      "additions": 12,
      "deletions": 3,
      "creates": ["src/foo.ts"],
      "modifies": ["src/bar.ts", "src/baz.ts"],
      "deletes": []
    },
    "diffArtifactPath": "$CLIQ_HOME/tx/tx_01HX.../diff.json",
    "validators": [
      { "name": "builtin:diff-sanity", "severity": "blocking", "status": "pass", "durationMs": 12 },
      { "name": "shell:tsc", "severity": "blocking", "status": "fail", "durationMs": 8421,
        "message": "src/foo.ts(42,10): error TS2322: ...",
        "artifactPath": "$CLIQ_HOME/tx/tx_01HX.../validators/shell:tsc.json" }
    ],
    "blockingFailures": ["shell:tsc"],
    "overridesApplied": [
      { "validatorName": "shell:tsc", "reason": "flaky in CI", "by": "cli", "ts": "..." }
    ],
    "ghostSnapshotId": "ws_chk_...",
    "transitions": [
      { "from": null,        "to": "staging",   "ts": "...", "by": "auto:turn-1" },
      { "from": "staging",   "to": "finalized", "ts": "...", "by": "auto:turn-end" },
      { "from": "finalized", "to": "validated", "ts": "...", "by": "cli" },
      { "from": "validated", "to": "applied",   "ts": "...", "by": "cli", "overrides": ["shell:tsc"], "reason": "flaky in CI" }
    ]
  },
  "warnings": [],
  "errors": []
}
```

### 13.2 Envelope rules

- `schemaVersion: 1` is a contract. Breaking changes increment it. Callers may reject unrecognized versions.
- Large content (full diffs, full validator stdout) is not inlined. References use `*ArtifactPath` fields; callers read those files as needed. This bounds envelope size.
- `errors[]` reports command-level failures (invalid arguments, tx not found, IO errors). Validator failures are not `errors`; they are part of `tx.validators`.
- `validators[]`, `blockingFailures[]`, `overridesApplied[]`, and other "current snapshot" fields reflect the moment of output and may change between successive calls. `transitions[]` is append-only audit history.

### 13.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Command succeeded; if apply, tx is now `applied` |
| 1 | Command itself failed (bad arguments, tx not found, IO error) |
| 2 | Tx exists but the requested transition was rejected by business rules (e.g., blocking validator failed, no override) |
| 3 | Tx entered `aborted` |

CI scripts use exit codes to distinguish tooling failures from gate failures.

### 13.4 Output mode resolution

| Condition | Behavior |
|---|---|
| TTY, no `--json` | Human-readable text, color, interactive prompts |
| `--json` | JSON envelope, no prompts; missing approval information exits with code 2 and a clear envelope `errors[]` entry |
| `--headless` | Forces `--json`; forces `applyPolicy: manual-only`; suppresses color and progress; no prompts |

`--json` controls output format. `--headless` is the full non-interactive contract. CI typically passes both: `--headless --json`.

## 14. Configuration

### 14.1 Workspace config (`.cliq/config.json`)

```json
{
  "transactions": {
    "mode": "edit",
    "auto": "per-turn",
    "applyPolicy": "interactive",
    "validators": {
      "shell": [
        { "name": "tsc",   "command": "npm run typecheck", "severity": "blocking", "timeoutMs": 60000 },
        { "name": "tests", "command": "npm test",          "severity": "advisory", "timeoutMs": 120000 }
      ],
      "disabled": [],
      "serial": false
    },
    "abortRetention": "7d"
  }
}
```

| Field | Values | Default | Meaning |
|---|---|---|---|
| `mode` | `off`, `edit` | `off` | `worktree` is reserved; v1 only `off` and `edit` |
| `auto` | `per-turn`, `manual` | `per-turn` | Implicit per-turn auto-open/finalize, or require explicit `tx open` |
| `applyPolicy` | `interactive`, `auto-on-pass`, `manual-only` | `interactive` | Interactive prompts; auto-apply when blocking pass; never auto-apply |
| `validators.shell` | array | `[]` | Shell-hook validators |
| `validators.disabled` | array of validator names | `[]` | Disable specific built-ins or shell hooks |
| `validators.serial` | boolean | `false` | Run validators serially instead of in parallel |
| `abortRetention` | duration string | `"7d"` | How long to retain `aborted` tx overlays |

When `transactions` is absent or `mode: "off"`, the entire feature is dormant; `$CLIQ_HOME/tx/` is not created and no `tx` runtime code path executes for that workspace.

### 14.2 Configuration precedence

```
CLI flag > environment variable (CLIQ_TX_*) > workspace config > built-in default
```

`--tx off` always wins, providing a per-invocation kill switch even when the workspace defaults to `mode: edit`.

### 14.3 Environment variables

- `CLIQ_TX_MODE`: same values as `transactions.mode`
- `CLIQ_TX_APPLY_POLICY`: same values as `transactions.applyPolicy`
- `CLIQ_TX_HEADLESS`: `"1"` is equivalent to `--headless`

## 15. Session Record Contract (Boundary with Auto-Compact)

The session/auto-compact effort proceeds in parallel. The contract between the two is a small, additive set of session record kinds. Tx writes records into the session; nothing in the session/auto-compact layer reads tx internals or modifies `$CLIQ_HOME/tx/`.

### 15.1 New record kinds

```ts
// success path
type TxAppliedRecord = {
  id: string;
  ts: string;
  kind: 'tx-applied';
  role: 'user';
  content: string;     // human-readable summary, e.g. "Transaction tx_01HX... applied: 4 files changed (+12 −3)"
  meta: {
    txId: string;
    txKind: TxKind;
    diffSummary: DiffSummary;
    files: { creates: string[]; modifies: string[]; deletes: string[] };
    validators: {
      blocking: { pass: number; fail: number };
      advisory: { pass: number; fail: number; names: string[] };
    };
    overrides: OverrideEntry[];
    artifactRef: string;        // e.g. "tx/tx_01HX.../"
    ghostSnapshotId?: string;
  };
};

// failure / cancellation path
type TxAbortedRecord = {
  id: string;
  ts: string;
  kind: 'tx-aborted';
  role: 'user';
  content: string;     // e.g. "Transaction tx_01HX... aborted: blocking validator shell:tsc failed"
  meta: {
    txId: string;
    txKind: TxKind;
    reason: 'validator-fail' | 'user-abort' | 'apply-error' | 'staging-error';
    failedValidators?: string[];
    files: { wouldHaveCreated: string[]; wouldHaveModified: string[]; wouldHaveDeleted: string[] };
    artifactRef: string;
  };
};
```

### 15.2 Contract invariants

Tx layer guarantees:

- Exactly one `tx-applied` record is appended on a successful apply, atomically with the file writes (under the same store lock).
- Exactly one `tx-aborted` record is appended on terminal abort, with a structured `reason`.
- Full diff content is **never** inlined into a session record. Only the `meta.artifactRef` pointer.
- `meta.diffSummary` and `meta.files` are stable, structured fields suitable for direct programmatic consumption (preferred by summarizers over `content`).
- `content` is a human-readable sentence intended for model replay; it never contains base64 blobs, full validator output, or content larger than ~512 bytes.

Session/auto-compact layer should:

- Add `'tx-applied'` and `'tx-aborted'` to its record kind enum and treat them as opaque in display flows by default.
- When summarizing, prefer `meta.diffSummary` and `meta.files` over `content` for these record kinds.
- Treat the open and apply/abort moments of an explicit multi-turn tx as **non-splittable boundaries** in compact range selection (analogous to the existing turn-boundary rule). Implicit per-turn tx requires no special handling; it is contained within a single turn.

### 15.3 Coordination

A standalone PR introducing only the new `SessionRecord` kind enum and the `TxAppliedRecord`/`TxAbortedRecord` types should land before either side of the work merges. This unblocks both efforts on independent code paths.

## 16. Concurrency, Locks, and Errors

### 16.1 Lock hierarchy

Tx introduces one new lock (tx-store) and extends one existing lock (workspace state). Acquisition order is fixed to prevent deadlock:

```
workspace state lock > session lock > tx-store lock
```

| Lock | Holder | Scope |
|---|---|---|
| workspace state lock (existing, extended) | When mutating `activeTxId` | `workspaces/<workspaceId>/state.json` |
| session lock (existing) | runner during a turn | `sessions/.../<sessionId>.json` |
| tx-store lock (new) | tx state transitions | `tx/<txId>/state.json` |

### 16.2 Concurrent invocation scenarios

| Scenario | Behavior |
|---|---|
| Two `cliq` processes in the same session | Second process attempting to open a tx fails with "session already has active tx tx_..."; user sees the conflict explicitly |
| Two processes in different sessions, same workspace | Independent `activeTxId` per session; no conflict |
| One process applies, another aborts the same tx | Tx-store lock serializes; second sees "tx already in <state>", exits 1 |
| External `git checkout` during tx | `builtin:index-clean` recheck at apply detects index change; `oldContent` recheck during apply detects file content change; tx fails before partial writes |

### 16.3 Error paths

| Failure point | Handling |
|---|---|
| Overlay write fails (disk full, permission) | Tool returns error; tx remains in `staging`; user can `abort` or resolve and retry |
| Validator infrastructure fails (`status: 'error'`) | Counts neither as pass nor fail; transition rejected unless `--allow-validator-error <name>` is provided |
| Apply fails mid-write (some files written, some not) | No automatic rollback. Tx transitions to `applied-partial`. Error output includes `ghostSnapshotId` and the exact restore command. Filesystem operations are not transactional; pretending otherwise causes worse data loss than honest failure reporting. |
| Session record write fails after files written | The apply path holds both file writes and record append under the session+tx-store locks. Either both succeed or the operation raises. If the process is killed between the two (SIGKILL, power loss), startup detects orphan: a tx in `applied` state with no corresponding session record produces a warning at next `cliq` invocation. The orphan is not auto-reconciled; the user is shown the inconsistency and the tools to resolve it. |
| Cliq process killed mid-tx | Tx state on disk is durable. Next invocation detects `activeTxId` pointing at a tx in non-terminal state, surfaces it via `cliq tx status`, and lets the user resume or abort. |

The `applied-partial` state is intentionally not on the main state diagram. It is reached only from `apply` errors and exits only via explicit user intervention (manual restore from `ghostSnapshotId`, then `tx abort`).

## 17. Module Boundaries

```text
src/
  workspace/
    transactions/
      types.ts           # Transaction, TxState, DiffSummary, AuditEntry, OverrideEntry
      store.ts           # persistence, locking, list/get
      overlay.ts         # edit-tx overlay materialization
      diff.ts            # diff computation, JSON serialization
      apply.ts           # overlay → real workspace atomic apply
      coordinator.ts     # state transitions, session record writes, ghost snapshot integration
    snapshots.ts         # Phase 3, unchanged
  validators/
    types.ts             # Validator, ValidatorContext, ValidatorResult
    registry.ts          # built-in registration + shell adapter integration
    runner.ts            # parallel/serial execution, staged-view materialization
    builtin/
      diff-sanity.ts
      index-clean.ts
      size-limit.ts
    shell.ts             # config-driven shell-hook adapter
  runtime/
    runner.ts            # extended: WorkspaceWriter injection
    workspace-writer.ts  # abstraction with passthrough and overlay implementations
  tools/
    edit.ts              # unchanged: receives WorkspaceWriter
    bash.ts              # unchanged: still real cwd; coordinator records BashEffect around it
  cli.ts                 # extended with tx subcommand group
```

Responsibilities:

- `workspace/transactions/coordinator`: the only module that drives state transitions and writes session records. All `tx` CLI commands route through it.
- `workspace/transactions/store`: persistence and lock primitives; no transition logic.
- `validators/runner`: orchestrates a single `validate` invocation. Does not know tx semantics.
- `runtime/workspace-writer`: small abstraction injected into tools so they remain unaware of tx existence.
- `cli.ts`: parses arguments, formats output (text or envelope), shells into coordinator.

## 18. Test Matrix

Required tests grouped by concern:

**Storage and lifecycle**
- Tx persists across cliq process restart
- Aborted tx overlay retained for `abortRetention`, then cleaned up
- `workspaces/<id>/state.json activeTxId` consistency

**State machine**
- All legal transitions covered
- All illegal transitions rejected (e.g., `staging → applied` skipping validate)
- Concurrent transitions serialized by tx-store lock
- `audit.json` appends never lost

**Edit-tx behavior**
- `edit` writes go to overlay only, not real cwd
- `bash` runs against real cwd; `BashEffect` records appear in diff.outOfBand
- Mutations after finalize rejected
- Multi-turn diff accumulation produces correct final diff

**Validators**
- `builtin:diff-sanity` rejects path escapes and binary-as-text mistakes
- `builtin:index-clean` detects external Git index changes between validate and apply
- Shell-hook validators run in `staged-view`, not real cwd (regression)
- Parallel and serial execution both honored
- Timeout produces `status: 'error'`, not `'fail'`
- `--override` requires the exact validator name; misspellings are rejected
- `--override-all` requires `--reason`

**Apply and Phase 3 coexistence**
- Pre-apply ghost snapshot taken and recorded in `tx.ghostSnapshotId`
- Apply failure includes ghost snapshot id in error output
- Successful apply writes `tx-applied` session record with all `meta` fields
- Aborted apply writes `tx-aborted` session record
- Session records never contain inlined full diffs
- External `git checkout` during validate→apply window detected and rejected before partial writes

**CLI and headless**
- `--tx off` overrides config
- `--headless` forces `applyPolicy: manual-only`
- `--json` envelope contains `schemaVersion: 1`
- Exit codes 0/1/2/3 map to documented scenarios
- Missing `<txId>` and missing `activeTxId` produces clear error message

**Coexistence with existing cliq behavior**
- `transactions.mode: off` produces no behavior change vs. current cliq (regression suite)
- `--policy read-only` plus tx mode: read-only still rejects `edit`; tx does not bypass policy
- `confirm-write` and tx mode: tx mode supersedes per-tool confirm prompts (no double-prompt)

## 19. External Design References

This release synthesizes practices from peer agents:

- **Plandex**: cumulative diff sandbox separated from project Git; review across files before apply; closest precedent for the tx-as-staging model.
- **Codex CLI**: workspace-write sandbox plus approval policy; informs the multi-mode (`mode: off | edit | worktree`) design and per-validator override granularity.
- **Aider**: direct-write plus auto-commit; informs the deliberate decision **not** to auto-commit on apply (cliq's apply writes files but leaves Git workflow untouched).
- **Claude Code**: per-tool diff preview and approval; informs the interactive review UX while explicitly choosing a coarser granularity (per-tx, not per-tool) for the B+D use cases.
- **OpenCode**: post-hoc multi-agent review; informs the validator severity model but is otherwise structurally different from a pre-mutation gate.

The Phase 3 spec's practice of citing source observations alongside design choices is followed here.

## 20. Migration and Backward Compatibility

This release is purely additive at the user-visible level:

- Existing users on `v0.6` who upgrade see no behavior change. `transactions` config is absent; `mode` defaults to `off`; no tx code paths execute.
- No session schema bump is required for the consumers of session records that ignore unknown `kind` values. If the auto-compact effort lands at the same time and bumps `SESSION_VERSION`, that bump should include the new tx record kinds in its migration; otherwise the additive nature of `kind` enums means no version bump is required for tx alone.
- No changes to `.cliq/session.json` migration logic (Phase 3 already handled the workspace-local → global migration).
- `$CLIQ_HOME/tx/` is created lazily on first tx open; does not exist for users who never enable tx.

## 21. Deferred Decisions

- **worktree-tx**: full workspace as a Git worktree so `bash` side-effects are also captured. Defer until edit-tx has real-world usage data on which workflows hit the `bash`-out-of-band limitation.
- **Sparse staged-view materialization**: only copy files differing in the staged view plus their dependency closure. Defer until a concrete performance complaint with measurements is filed.
- **Cross-session tx merging**: for workflows where multiple sessions converge on a single review unit. Defer until a concrete user workflow is documented.
- **Partial apply**: apply only some files from a tx. Defer; current discipline is "tx is reviewed and applied as a unit".
- **Automatic validator-driven retry loops**: tx fails validation, model is asked to fix and tries again automatically. Defer; risks runaway loops and is better explored after tx is in real use.
- **Tx protocol RPC / SDK packaging**: Phase 4 concern. The JSON envelope here is the substrate; explicit RPC framing (JSONL stream, request/response) is its concern.
- **TUI / visual diff browsing**: defer to richer UX phases.
- **Non-Git overlay alternative**: tx overlay does not require Git, but Phase 3 ghost snapshots do. A non-Git workspace using tx still loses recovery if `applied-partial` happens. Defer alternative snapshot mechanisms (e.g., copy-on-write directory snapshots) until needed.
