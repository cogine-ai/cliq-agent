# Cliq Transactional Workspace Runtime Design

**Date:** 2026-05-02 (revised 2026-05-06 to reflect shipped Phase 4 and auto-compact)
**Status:** Draft
**Target Release:** `v0.8.0` (edit-tx) / `v0.9.0` (worktree-tx, deferred)

## 1. Summary

Cliq today applies tool mutations directly to the working tree. Phase 3 added Git-backed ghost snapshots so users can recover from bad turns after the fact. This release adds the inverse: a pre-mutation gate that lets the agent stage **declarative file edits**, generate a structured diff, run validators, and require approval before those edits land in the real workspace.

The new layer is called the **transactional workspace runtime**. A transaction (tx) is a persistent, externally consumable artifact that captures the proposed change set, the validator results, and an audit trail of state transitions. Tx coexists with Phase 3 ghost snapshots; it does not replace recovery, it adds prevention.

**Scope of this release's prevention** (deliberately narrow):

- The gate covers `edit`-driven text replacements in existing files. These are staged into an overlay and never written to the real workspace until apply.
- The gate **does not** cover shell side-effects. `bash` runs against the real working tree by default. Operations like `npm install`, `mkdir build/`, generated files, package locks, and so on land in the real workspace as the agent executes them, regardless of tx state. They are recorded out-of-band in the diff for reviewer awareness but **are not rolled back** if the tx is aborted.
- Workspaces requiring containment of shell side-effects must use worktree-tx (deferred to `v0.9.0`) or restrict `bash` via `transactions.bashPolicy` (Section 9.4) and a stricter `--policy` mode.

The release ships two concrete capabilities:

- **edit-tx**: a lightweight overlay that captures `edit`-style declarative file changes; `bash` continues to run against the real working tree, with its side-effects flagged in the diff but not staged.
- **state machine + headless JSON protocol**: a tx is a persistent object under `$CLIQ_HOME/tx/<id>/` with explicit transitions; CLI commands and a `--json` envelope let CI, external tools, and human reviewers consume it without sharing process state.

A heavier `worktree-tx` mode (where `bash` side-effects are also captured by running inside a Git worktree) is described in this document as a forward-compatible extension but is **not** implemented in this release.

## 2. Roadmap Placement

This release sits between Phase 4 (Headless Runtime Interfaces, shipped in `v0.7.0`) and Phase 6 (Automation, Worktrees, Rich UX) on the runtime architecture roadmap. It is not a new layer; it lives inside the existing **Runtime/Tool Layer**.

It builds on shipped foundations:

- Phase 3 (`v0.6.0`): `$CLIQ_HOME` global storage, workspace identity, ghost snapshot mechanism (used as apply-pre safety net), session record append model
- Phase 4 (`v0.7.0`): the `src/headless/` contract, `RuntimeEventEnvelope` event shape, `HeadlessRunOutput.artifacts`, `HeadlessErrorCode` taxonomy, `cliq run --jsonl` adapter
- Auto-compact (shipped alongside Phase 4): `compact-start/end/skip/error` events, `AutoCompactConfig`, `compaction` artifact id surface

This spec **extends** those contracts rather than parallel-defining new ones. Specifically:

- New runtime events (`tx-staging-start`, `tx-finalized`, `tx-validated`, `tx-applied`, `tx-aborted`) plug into the existing `HeadlessRuntimeEventType` union and reuse `RuntimeEventEnvelope`'s envelope fields (`schemaVersion`, `eventId`, `runId`, `sessionId`, `turn`, `timestamp`).
- A new `transactions: string[]` field is added to `HeadlessArtifacts` so headless callers learn which tx ids a run produced.
- New `HeadlessErrorCode` values (`tx-validator-blocking`, `tx-apply-conflict`, `tx-apply-partial`, `tx-overlay-error`) extend the existing taxonomy.
- New session record kinds (`'tx-applied'`, `'tx-aborted'`) extend the existing `SessionRecord` enum and slot into auto-compact's range-selection rules (Section 15).

It does not implement, defer to later phases:

- worktree-tx (`v0.9` or Phase 6)
- TUI / visual diff browsing
- automated retry loops driven by validator failures
- model-callable validators or model-controlled approval

## 3. Goals

### 3.1 Product Goals

- Let users opt into a "PR-like" review gate where the agent's staged file edits surface as one diff to approve or reject.
- Let CI / headless callers consume agent output as a structured artifact (diff + validator report + approval handle) without depending on stdin prompts.
- Let users group multiple turns into a single transaction so a coherent task gets reviewed as a whole, not one tool call at a time.
- Make rejection of staged edits cheap: if the overlay is wrong, throw it away. (Caveat: `bash` side-effects executed during the tx are not in the overlay and are not rolled back; see Sections 1 and 9.4.)
- Run project-defined checks (typecheck, tests, lint) against the staged view before apply, not the real workspace.

### 3.2 Architecture Goals

- Route `edit` writes through a `WorkspaceWriter` abstraction (passthrough or overlay), with minimal change to existing tool implementations. `bash` continues to run against the real `cwd`; the coordinator wraps it for side-effect bookkeeping.
- Represent transactions as first-class persistent objects under `$CLIQ_HOME`, not transient command outputs.
- Reuse Phase 4's `HEADLESS_SCHEMA_VERSION` across both surfaces tx exposes: `cliq run --jsonl` emits new tx event types inside the existing `RuntimeEventEnvelope`, and `cliq tx show/status/list --json` emit `Transaction` snapshot objects under the same schema version. Implementers do not introduce a second envelope shape; they extend the existing one with new event payloads and pair it with a related snapshot shape (Section 13).
- Keep validator severity (blocking vs advisory) explicit and per-validator-overridable, with audit trail.
- Treat apply as a phased, recoverable operation with explicit on-disk state; do not claim filesystem-level atomicity.
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

1. **Workspace mutation layer (where this release lives)**: file edits, file creations, file deletions, and shell side-effects. **This release's edit-tx stages only `edit`-driven text replacements in existing files.** File creates, file deletes, and shell side-effects fall outside the staging boundary in this release: they happen via `bash` against the real working tree (gated by `transactions.bashPolicy`, Section 9.4) or are deferred to worktree-tx.
2. **Session/context layer (Phase 3 plus shipped auto-compact)**: append-only records, checkpoints, compactions, handoffs. The tx system writes summary records into this layer, but never raw diffs.
3. **Runtime side effects (out of scope for any layer)**: shell processes, databases, services, network calls. Neither tx nor checkpoint claims to manage these.

The contract between layers is one-way: tx writes summary records into the session; the session/auto-compact never reads tx internals or modifies workspace files. See Section 15 for the precise record schema.

## 6. Storage Model

Tx storage extends Phase 3's `$CLIQ_HOME` layout. No new top-level storage roots are introduced.

```text
$CLIQ_HOME/
  workspaces/<workspaceId>/state.json   # Phase 3, unchanged
  sessions/.../<sessionId>.json         # Phase 3, extended: + activeTxId
  tx/<txId>/
    state.json                          # current state, kind, sessionId, workspaceId, timestamps
    diff.json                           # structured diff (per-file old→new); v0.8 contains only modify entries
    overlay/                            # materialized staged files (durable across cliq restart)
    validators/<validatorName>.json     # per-validator structured result
    apply-progress.json                 # phased apply protocol state (Section 11.1); present only during/after an apply attempt
    abort-progress.json                 # abort termination protocol state (Section 11.3); present only during/after an abort
    audit.json                          # append-only state transition log
  checkpoints/...                       # Phase 3, unchanged
```

`workspaceId` and `sessionId` use the same definitions Phase 3 establishes (`workspaceId = sha256(realpath(cwd))`; `sessionId` from the session store).

`txId` format: `tx_<ulid>`. ULIDs sort lexicographically by creation time, which makes `cliq tx list` and directory listings naturally chronological.

### 6.1 `activeTxId` ownership

`activeTxId` is owned by the session, not the workspace. It lives at `Session.activeTxId` in the session JSON. This requires extending the `Session` type in `src/session/types.ts` with an `activeTxId?: string` field; the field is optional (absent when the session has no active tx) and additive (existing sessions deserialize unchanged with the field set to `undefined`).

Implications:

- A session has at most one active tx at a time. This is the invariant the tx-coordinator enforces.
- Multiple sessions in the same workspace can each have their own active tx, with no cross-session interference. The tx-store lock and per-tx `state.json` provide the only contention point, at the granularity of an individual tx.
- The workspace state file (`workspaces/<workspaceId>/state.json`) is unchanged from Phase 3. No `activeTxId` field is added there.
- Cross-session listing (`cliq tx list` for a workspace) is implemented by scanning `$CLIQ_HOME/tx/` for tx whose `state.json` matches the current `workspaceId`. The directory itself is the index. This is acceptable because tx are ULID-named and directory listings stay sorted; if scan cost becomes a problem at very large tx counts, an opt-in cache file under `workspaces/<workspaceId>/` can be added later.

### 6.2 Overlay durability

The `overlay/` directory is materialized to disk as edits arrive, not held in memory. This is required by the multi-turn lifecycle (Section 8): a tx must survive `cliq` process restart and be resumable from another invocation in the same session.

`overlay/` is cleaned up immediately after a successful `applied` transition. After `aborted`, it is retained for `transactions.abortRetention` (default 7 days) for audit and post-mortem inspection, then garbage-collected by a deferred cleanup pass.

## 7. Transaction Schema

```ts
export type TxKind = 'edit';   // 'worktree' deferred to v0.9

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

**v0.8 scope of `DiffSummary`**: `creates[]` and `deletes[]` are present in the schema for forward-compatibility with worktree-tx (`v0.9.0`), but in v0.8 they are always empty arrays. Edit-tx is built on top of the existing `edit` tool, which only replaces text in existing files. File creation, deletion, rename, mode change, and similar operations remain `bash`-driven and out-of-band (Section 9.4) until worktree-tx ships.

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

Edit-tx captures `edit`-driven text replacements in existing files. v0.8 does not stage file creates, deletes, renames, or shell side-effects.

### 9.1 Overlay storage

Each accepted `edit` mutation writes the full post-mutation file content into `$CLIQ_HOME/tx/<txId>/overlay/<workspace-relative-path>`. The overlay tree mirrors the workspace tree for changed paths only; unchanged files are not copied.

The overlay records `modify` operations only. Because the existing `edit` tool can only replace text in existing files, no `create` or `delete` markers are needed in v0.8. The overlay format reserves space for future `create`/`delete` markers (e.g., a sibling `<path>.cliq-tx-delete` file) when worktree-tx introduces them, but v0.8 does not use them.

### 9.2 Diff materialization

At `finalize`, the tx-coordinator walks `overlay/`, compares each staged file against the corresponding real-workspace file, and writes a structured `diff.json`:

```ts
type Diff = {
  files: Array<
    | { path: string; op: 'create'; newContent: string }     // reserved; not produced in v0.8
    | { path: string; op: 'modify'; oldContent: string; newContent: string }
    | { path: string; op: 'delete'; oldContent: string }     // reserved; not produced in v0.8
  >;
  outOfBand: BashEffect[];  // see 9.4
};
```

In v0.8 every entry in `files[]` has `op: 'modify'`. The `create` and `delete` shapes exist for forward compatibility with worktree-tx; v0.8 readers may assert their absence.

Storing full content (not patches) keeps the format simple and makes apply trivially deterministic. Patches can be derived on demand by `cliq tx diff` for human display.

### 9.3 Staged view materialization (for validators)

Validators need to see the post-apply state without requiring an actual apply. At `validate`, the tx-coordinator materializes `$CLIQ_HOME/tx/<txId>/staged-view/`:

1. Walk the real workspace tree. For each entry:
   - If the path is under a configured **bind path** (Section 9.3.2), create a symlink from `staged-view/<path>` to the real workspace path. (Acknowledged write leak; documented below.)
   - Otherwise, materialize the file in `staged-view/` using the configured **copy mode** (Section 9.3.1). The default uses copy-on-write reflinks where the filesystem supports them, falling back to a full byte copy.
2. Walk the overlay tree. For each `modify` entry, write a freshly written file at `staged-view/<path>` containing the staged content. With reflink or copy materialization, this write does not propagate back to the real workspace because the staged-view file is a distinct inode (or a CoW clone whose first write triggers divergence).
3. Pass `staged-view/` to validators as `ValidatorContext.workspaceView`.
4. After validation, delete `staged-view/` (kept only with `--keep-staged-view` debug flag).

This avoids both the earlier `.gitignore`-skip strategy (which produced false validator failures on Node, Python, and similar ecosystems) and the earlier hardlink strategy (which silently leaked validator writes back into the real workspace via shared inodes).

#### 9.3.1 Copy mode

Hard links are explicitly **not** used for staged-view content. A hardlink shares the underlying inode, so any write inside the staged view (e.g., a snapshot test updating fixtures, a formatter run with `--write`, a coverage collector emitting `.coverage`, a build tool touching mtime) silently mutates the real workspace file. This violates the gate.

Cliq materializes non-bound files using:

| `transactions.stagedView.copyMode` | Behavior |
|---|---|
| `auto` (default) | Try copy-on-write reflink first (`clonefile()` on macOS APFS, `FICLONE`/`FICLONERANGE` ioctl on Linux Btrfs/XFS/ext4-with-reflink); on first failure for a tx, fall back to full copy and emit a one-time warning event |
| `reflink` | Require reflink; fail validation if the filesystem does not support it |
| `copy` | Always full byte copy (slowest, most portable, no reflink dependency) |

Reflink is a true copy-on-write clone: the staged-view file shares physical blocks with the real file until either side is written, at which point the writing side gets its own block. Validator writes therefore stay inside `staged-view/` and never reach the real workspace.

Practical support matrix:

- macOS: APFS supports reflinks via `clonefile(2)`; available everywhere on modern macOS
- Linux: Btrfs, XFS (with `reflink=1`), and ext4 (with `reflink` mount option) support `FICLONE`; ext4 default mounts and tmpfs do not
- Windows / cross-filesystem boundary: not supported; falls back to copy in `auto` mode

Performance expectation: reflink is metadata-only and effectively free regardless of file size; copy fallback is O(total workspace size minus bind paths) per validate. For typical TypeScript/Python repos (dependencies bound, sources copied) the copy fallback is on the order of a few MB and completes in tens of milliseconds.

#### 9.3.2 Bind paths

Bind paths are workspace-relative paths that are exposed in the staged view as symlinks to the real workspace, rather than reflinked or copied. Configured via `transactions.stagedView.bindPaths`. Default: `["node_modules"]`.

Bind paths exist because:

- **Performance**: large dependency trees (millions of files in `node_modules/`) are prohibitive to materialize per validation, even via reflink, due to per-file metadata cost.
- **Correctness for runtime resolution**: many language runtimes find dependencies via path resolution rooted at imported files; a symlinked `node_modules` typically resolves correctly because the dependency tree is self-contained.

**Trade-offs explicitly documented**:

- A validator that **writes** into a bind path writes into the real workspace. This is a known leak. Validators that build with output inside `node_modules/` (uncommon but possible: some plugin generators) affect the real workspace. Users who need stricter isolation should use worktree-tx (deferred) or remove the affected path from `bindPaths` (paying the materialization cost in exchange).
- A validator that resolves a bind path through `realpath` (e.g., some bundlers) sees the real workspace location. For read-only validation this is harmless; for codegen that emits absolute paths into output it produces paths pointing into the real workspace. Out-of-scope for v1; users tighten `bindPaths` accordingly or wait for worktree-tx.

Sensible default extensions per ecosystem (configured by users, not built in by default to keep cliq lean):

- Node: `["node_modules"]` (default)
- Python: `["node_modules", ".venv", "venv", "__pycache__"]`
- Go: `["node_modules", "vendor"]`
- Rust: `["node_modules", "target"]`

### 9.4 `bash` side-effects and `bashPolicy`

`bash` always runs against the real `cwd`. Its side-effects on the file system are not staged. The tx-coordinator wraps each `bash` invocation to record a `BashEffect`:

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

#### 9.4.1 `transactions.bashPolicy`

Because `bash` side-effects bypass the gate, users who want a stricter posture can configure `transactions.bashPolicy`:

| Value | Behavior in tx mode |
|---|---|
| `passthrough` (default) | `bash` runs unchanged against real `cwd`. Side-effects flagged in `BashEffect` records. Preserves current cliq behavior. |
| `confirm` | Each `bash` invocation prompts the user (interactive only). Headless mode promotes `confirm` to `deny` and returns a clear error envelope. |
| `deny` | `bash` is rejected during a tx. Tools dependent on `bash` either fail or the user must abort the tx, run `bash` outside tx mode, then re-open. |

`bashPolicy` is independent of the existing `--policy` modes (`auto`, `confirm-bash`, etc.). When both are configured, the stricter wins (e.g., `--policy confirm-bash` plus `bashPolicy: deny` results in `deny` because `deny` is strictly stronger than `confirm-bash`).

This is the v0.8 honest tradeoff: edit-tx covers declarative file changes, `bash` is acknowledged and configurable but not contained. Users who want full containment use worktree-tx (deferred).

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

Configured in `.cliq/config.json` under `transactions.validators.shell`:

```json
{
  "transactions": {
    "validators": {
      "shell": [
        { "name": "tsc",   "command": "npm run typecheck", "severity": "blocking", "timeoutMs": 60000 },
        { "name": "tests", "command": "npm test",          "severity": "advisory", "timeoutMs": 120000 }
      ]
    }
  }
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

### 11.1 Phased apply protocol

Apply is **not** an atomic operation. It is a multi-step protocol with explicit on-disk progress so cliq can recover from interruption (SIGKILL, power loss, OS crash) at any point. The protocol favors honest reporting over magical rollback; filesystem operations are not transactional, and pretending otherwise causes worse data loss than acknowledging the failure mode.

The apply path uses an internal sub-state machine, persisted as `apply-progress.json` in the tx directory:

```ts
type ApplyPhase =
  // in-flight phases — abort rejected while in any of these
  | 'apply-pending'           // intent recorded, ghost snapshot taken, no files written yet
  | 'apply-writing'           // partway through file writes; per-file progress recorded
  | 'apply-committed'         // all files written and fsynced; session record not yet appended
  | 'apply-finalized'         // session record appended; tx state.json transition pending
  // terminal phases — abort permitted from these (and implied by tx state)
  | 'apply-failed-partial';   // recovery moved tx to 'applied-partial'; user must restore and abort manually

type ApplyProgress = {
  phase: ApplyPhase;
  ghostSnapshotId: string;
  startedAt: string;
  filesPlanned: string[];     // workspace-relative paths in apply order
  filesWritten: string[];     // append-only as each file fsyncs
  // No sessionRecordId field: the record id is deterministic
  // (`txrec_apply_<txId>` / `txrec_abort_<txId>`), so Stage C can scan-then-append
  // idempotently without persisting the id separately.
  error?: { stage: string; path?: string; message: string };
};
```

Apply sequence (called from `approved` state) is split into three lock-disjoint stages so the global lock hierarchy `workspace > session > tx` is never violated:

```
STAGE A — preflight (tx-store lock only)
  A1. acquire tx-store lock
  A1a. AUTHORITATIVE state, abort, AND in-flight apply check under tx-store lock:
       - read tx state.json. If state !== 'approved', release lock and
         reject: "tx state is <state>; cannot apply" (covers the case
         where a concurrent abort flipped the tx to 'aborted' between
         the user's `tx apply` invocation and A1).
       - read abort-progress.json. If it exists in any phase, release lock
         and reject: "tx is being aborted; cannot apply" (covers the case
         where a concurrent abort wrote abort-progress before being
         interrupted, or where recovery is mid-stream).
       - read apply-progress.json. If it exists in any phase, release
         lock and reject: "apply already in flight (phase=<phase>); use
         cliq tx status or wait for completion" — also reached if a
         previous apply died and left a non-terminal phase, in which
         case the message points the user at recovery via
         `cliq tx status --recover`. This is the same-direction guard
         that prevents two `tx apply` invocations from each writing
         their own apply-progress and clobbering each other's plan.
         (Terminal phases — apply-finalized and apply-failed-partial —
         imply tx state is 'applied' or 'applied-partial' and would
         already have been caught by the state check above.)
       - This re-check under lock is the symmetric counterpart of the
         abort protocol's AB3a: each side authoritatively verifies the
         other has not started before proceeding, and verifies its own
         direction is not already in flight.
  A2. recheck builtin:index-clean (it may have changed since validate)
  A3. for each entry in diff.json (v0.8: all 'modify' entries):
        a. read current real file at <path>
        b. verify it matches diff.oldContent
        c. record (path, fingerprint, currentSize) in an in-memory plan
      If any verification fails: abort the apply. Tx returns to `approved`.
      No file has been written. The user sees "external change detected at
      <path>" and can decide to investigate, re-validate, or abort the tx.
  A4. create Phase 3 ghost snapshot; record id in tx.ghostSnapshotId
  A5. write apply-progress.json with phase: 'apply-pending', plan recorded,
      filesWritten: []. fsync.
  A6. release tx-store lock

STAGE B — write (tx-store lock only, re-acquired)
  B1. acquire tx-store lock
  B1a. RE-VERIFY state under tx-store lock (defense-in-depth):
       - read tx state.json. If state !== 'approved':
           a. delete apply-progress.json under the lock (we hold tx-store,
              so this is safe and atomic). The current tx state is the
              truth — whatever it is — and the apply-progress file is now
              an orphan from a Stage A that should not have been allowed
              to start. Removing it prevents startup recovery from acting
              on stale plan data.
           b. release lock and exit Stage B with an internal error
              ("tx state changed during apply; aborting Stage B").
           c. do NOT mutate state.json. The terminal state (whatever it
              is) reflects the action that legitimately won.
       - This branch should never execute under the locking scheme:
         A1a rejects a concurrent second apply (which would otherwise
         flip apply-progress underneath us), and AB3a rejects abort
         while apply-progress is in any in-flight phase. B1a exists to
         catch implementation bugs or unforeseen races and fail safely
         rather than write into an unexpected state.
  B2. transition phase: 'apply-pending' → 'apply-writing'
  B3. for each entry in the recorded plan:
        a. re-verify the real file fingerprint matches the planned fingerprint
           (defense in depth against a third party racing between A6 and B1;
            this re-check is per-file and adds negligible cost)
           - on mismatch: stop. Transition to applied-partial. Files written
             so far in this stage stay written. Error includes ghostSnapshotId.
        b. write the new content to <path>.cliq-tx-tmp on the same filesystem
        c. fsync the temp file
        d. rename <path>.cliq-tx-tmp → <path>  (atomic per POSIX rename(2))
        e. append <path> to apply-progress.json.filesWritten[]
        f. fsync apply-progress.json
  B4. transition phase: 'apply-writing' → 'apply-committed'. fsync.
  B5. release tx-store lock
      (At this point all file writes are durable. The only outstanding
       action is appending the session record. If the process is killed
       between B5 and C, the crash recovery protocol idempotently completes
       the record append at next startup. See Section 16.4.)

STAGE C — record + terminal session cleanup (session lock, then tx-store lock)
  C1. acquire session lock
  C2. acquire tx-store lock      (session > tx in the global hierarchy)
  C3. read apply-progress.json. If phase is already 'apply-finalized'
      AND tx state.json is 'applied' AND Session.activeTxId !== txId,
      everything is already done; release both locks and exit no-op.
  C4. session-side terminal write (single fsync at the end):
        a. compute the deterministic record id: recordId = `txrec_apply_<txId>`.
        b. scan session.records for a record with this exact id.
             - If absent: append the session record (kind: 'tx-applied',
               Section 15) with this exact id.
             - If present: skip the append (a previous attempt got this
               far before crashing).
        c. if Session.activeTxId === txId: clear it (set to undefined).
           If Session.activeTxId is already undefined or points elsewhere,
           do not touch it (defensive idempotency).
        d. fsync the session file once for both updates.
  C5. transition phase: 'apply-committed' → 'apply-finalized'. fsync.
  C6. transition tx state.json: 'approved' → 'applied'. fsync.
  C7. release tx-store lock, release session lock
  C8. schedule overlay/ cleanup
```

C4 is a single session-write transaction: the record append and `activeTxId` clear share one fsync, so a crash between them is impossible. A crash between C4 and C5/C6 leaves the session correct and the tx-progress files behind; recovery (Section 16.4) re-enters C from C3, sees the record already present and `activeTxId` already cleared, and converges to `applied`.

Why this split:

- **Lock hierarchy is preserved.** No stage holds the tx-store lock while attempting to acquire the session lock. Stage C acquires session first, then tx-store, in the canonical order.
- **External-change detection happens before any write.** Stage A's preflight verifies *every* file's `oldContent` against the real workspace before stage B writes the *first* byte. A file conflict at the third entry no longer leaves the first two entries written. This is what the test "external `git checkout` during validate→apply window detected and rejected before partial writes" actually means.
- **Stage B's per-file re-verification (B3a)** narrows the race window between A's bulk preflight and B's writes. A truly malicious concurrent writer can still squeeze in between B3a and B3d for a single file, but this is materially harder than the previous "between sequential per-file checks" race, and the result is at most one stale-overwrite (not a cascading partial apply) which the user resolves via ghost snapshot restore.
- **Stage C is exactly-once via deterministic record id.** The record id is computed from the txId (`txrec_apply_<txId>`), not freshly generated each attempt. C4 is idempotent: it scans for the id and skips the append if it already exists. Tx-aborted records use `txrec_abort_<txId>` and follow the same scan-then-append rule. This removes the previous reliance on a `sessionRecordId` bookkeeping field that could itself be lost in a crash window between session-append-fsync and bookkeeping-fsync. Recovery from any crash inside Stage C reruns Stage C from scratch and converges to the same outcome.
- **Crash before A5** leaves no `apply-progress.json` and no real-workspace mutation; the tx stays in `approved` and the user retries.

### 11.2 Apply failure handling

| Failure point | Recovery action |
|---|---|
| Stage A preflight fails (oldContent mismatch on any file) | No file written. Tx returns to `approved`. User sees the conflicting path and decides whether to investigate, re-validate, or abort. |
| Crash before A5 (no `apply-progress.json`) | No-op. Tx is still in `approved`. User retries `tx apply`. |
| `apply-pending` (plan recorded, no writes started) | Next cliq startup branches on the current `state.json.state`: if state is still `approved` (the normal crash case), recovery confirms it as `approved` and discards `apply-progress.json` so the user can retry cleanly. If state is anything else (it shouldn't be, but B1a's defense-in-depth path or an unforeseen race could leave the orphan), recovery discards `apply-progress.json` only and emits a `recovery.json` warning — it does **not** mutate `state.json`. The runtime never resurrects a non-`approved` state into `approved` from a leftover `apply-pending` file. See Section 16.4.1 for the full rule. |
| `apply-writing` (partial files written by stage B) | Next cliq startup moves tx to `applied-partial`, surfaces the list of files written from `apply-progress.filesWritten[]`, and recommends `cliq checkpoint restore <ghostSnapshotId>`. No automatic file restore. |
| Stage B re-verification (B3a) detects mid-write external change | Same as the row above: tx transitions to `applied-partial`. |
| `apply-committed` (all files written, no session record yet) | Next cliq startup runs Stage C from scratch under the proper lock order. The deterministic record id (`txrec_apply_<txId>`) makes C4's append idempotent: if a previous attempt got as far as appending the record before crashing, the rerun finds it and skips. |
| `apply-finalized` but tx state.json not yet flipped | Next cliq startup transitions tx state to `applied`. Idempotent. |
| `applied` | Nothing to do. |

The `applied-partial` state requires explicit user resolution. It is reached only when:

- Stage B per-file re-verification (B3a) catches a concurrent external change after preflight
- Disk error during stage B's write/fsync/rename for a file after earlier files succeeded
- Process kill specifically during the `apply-writing` phase

External-content drift detected before any write (stage A preflight) does **not** produce `applied-partial`; it returns the tx cleanly to `approved`.

Recovery tools the user has access to:

```bash
cliq tx status <txId>        # shows applied-partial, lists files written, ghostSnapshotId
cliq tx show <txId> --json   # full envelope for headless callers
cliq checkpoint restore <ghostSnapshotId>   # restore real workspace to pre-apply state
cliq tx abort <txId>         # mark tx as terminally aborted after manual recovery
```

### 11.3 Abort termination protocol

Abort is the second terminal-state path. Like apply, it must produce a session record (`tx-aborted`), clear `Session.activeTxId`, and transition tx state, all crash-safely. Abort uses a parallel protocol with its own progress file and recovery rules.

Abort accepts a `reason` argument from the caller. Most reasons are caller-supplied (`user-abort`, `validator-fail`, `apply-error`, `staging-error`). Two reasons are reserved and only valid when aborting from `applied-partial`:

- `apply-failed-partial-restored` — the user has restored the workspace via `cliq checkpoint restore <ghostSnapshotId>` and is finalizing the abort.
- `apply-failed-partial-kept` — the user is keeping the partial writes intentionally (e.g., for inspection) and is finalizing the abort with full awareness.

When tx state is `applied-partial`, exactly one of `--restore-confirmed` or `--keep-partial` is required. The flag selects the reason and is recorded in the audit log; without either flag, the abort fails with a clear error directing the user to choose. This makes the integrity claim of the resulting `tx-aborted` record unambiguous to downstream consumers.

```
ABORT (called from any non-terminal state)
  AB0. fast-fail pre-lock check (optimization only): read apply-progress.json
       if present; if phase ∈ {apply-pending, apply-writing, apply-committed,
       apply-finalized} (in-flight phases), reject immediately with
       "apply in progress, run cliq tx status to recover". This is a
       courtesy fast path — it is not authoritative because it is unlocked.
       The authoritative check is AB3a under tx-store lock.
  AB0a. flag enforcement for applied-partial (caller-side, before AB1):
        if state.json.state === 'applied-partial':
          - require exactly one of --restore-confirmed or --keep-partial
          - if --restore-confirmed: caller-supplied reason becomes
            `apply-failed-partial-restored`
          - if --keep-partial: caller-supplied reason becomes
            `apply-failed-partial-kept`
          - if neither: reject with "tx in applied-partial: pass
            --restore-confirmed (after cliq checkpoint restore) or
            --keep-partial (to keep partial writes deliberately)"
          - if both: reject as ambiguous
  AB1. acquire session lock
  AB2. acquire tx-store lock
  AB3a. AUTHORITATIVE apply-progress check under tx-store lock:
        re-read apply-progress.json. If phase ∈ {apply-pending, apply-writing,
        apply-committed, apply-finalized}, release locks and reject with the
        same "apply in progress" error.
        - The terminal phase `apply-failed-partial` does NOT block abort.
          That phase is set by recovery when the tx moves to `applied-partial`,
          signalling the apply has terminated unsuccessfully. The caller's
          --restore-confirmed/--keep-partial choice (validated authoritatively
          in AB3a.5) governs the integrity meaning of the resulting record.
        - This re-check under lock closes the window between AB0 and AB2:
          a concurrent apply that wrote apply-progress between AB0 and AB2
          is detected here.
  AB3a.5 AUTHORITATIVE applied-partial flag re-check under tx-store lock:
         re-read tx state.json (now under lock).
         - If state.json.state === 'applied-partial':
             - exactly one of --restore-confirmed or --keep-partial must
               have been passed by the caller (validated at AB0a if state
               was already applied-partial then; this re-check catches the
               case where state changed from approved/etc. to applied-partial
               between AB0a and AB2 because a concurrent recovery completed).
             - if neither flag was passed: release locks, reject with
               "tx state changed to applied-partial during abort; re-run
               with --restore-confirmed (after cliq checkpoint restore)
               or --keep-partial".
             - if a flag was passed but the reason hadn't been promoted at
               AB0a (because state was different then): override the
               reason now to apply-failed-partial-restored or
               apply-failed-partial-kept according to the flag, and load
               the partial-write metadata (apply-progress.filesWritten,
               ghostSnapshotId) for AB5b's `meta.appliedPartial` field.
         - If state.json.state !== 'applied-partial' but the caller passed
           --restore-confirmed or --keep-partial: release locks, reject
           with "flag <name> only valid when tx is applied-partial".
         This step ensures the integrity claim of the resulting tx-aborted
         record reflects the tx state at the moment locks were acquired,
         not at the moment the user typed the command.
  AB3b. terminal-state idempotency check (all markers, not just state.json):
        - sessionRecordPresent = scan session for record id `txrec_abort_<txId>`
        - activeTxIdCleared = (Session.activeTxId !== txId)
        - txStateAborted = (state.json.state === 'aborted')
        - abortProgressTerminal = (abort-progress.phase === 'aborted')
        - If state.json.state === 'applied': release locks, exit no-op
          (an apply already won; abort should never have been called).
        - If ALL of {sessionRecordPresent, activeTxIdCleared, txStateAborted,
          abortProgressTerminal} are true: release locks, exit no-op
          (a previous run already finished every step).
        - Otherwise: proceed through AB4..AB7, treating each as idempotent
          (each step's write is a no-op if its target is already in the
          desired state).
  AB4. write abort-progress.json:
        { phase: 'aborting', reason, startedAt, ts }
       fsync. (If the file already exists with phase 'aborting' or 'aborted',
       overwrite phase=aborting; reason and timestamps from the most recent
       attempt win; this is purely metadata.)
  AB5. session-side terminal write (single fsync):
        a. recordId = `txrec_abort_<txId>`.
        b. scan session.records for that id; append if absent. The record's
           meta.reason carries the value chosen above (including the
           applied-partial-derived values when applicable). For applied-partial
           aborts, meta also carries:
             - partialFiles: string[]       (from apply-progress.filesWritten)
             - ghostSnapshotId: string      (for restore reference)
             - restoreConfirmed: boolean    (true iff --restore-confirmed)
        c. if Session.activeTxId === txId: clear it. Else leave alone.
        d. fsync session file once.
  AB6. if state.json.state !== 'aborted': transition to 'aborted'. fsync.
  AB7. if abort-progress.phase !== 'aborted': transition to 'aborted'. fsync.
       (The abort-progress.json is retained alongside the tx directory for
       audit, deleted with the rest of the tx artifacts at retention end.)
  AB8. release tx-store lock, release session lock
  AB9. retain overlay/ per `transactions.abortRetention` (NOT cleaned eagerly,
       unlike applied tx where overlay is purged immediately).
```

The split between AB3a and AB3b matters: AB3a rejects (returns an error to the caller), while AB3b skips work but still succeeds. A tx whose apply is in flight cannot be aborted, but a tx whose abort already finished returns success on retry.

Headless callers using `cliq tx abort <id> --json` from `applied-partial` must pass the appropriate flag; missing the flag exits 1 with a structured error, not a prompt.

Crash recovery for abort is symmetric to apply (Section 16.4 lists the rules). Recovery resuming a partial abort uses whatever `reason` was originally written in `abort-progress.json`; it does not need (and cannot infer) the user's `--restore-confirmed` / `--keep-partial` choice afresh because that choice is durably encoded in the in-flight reason.

#### 11.3.1 Why abort doesn't pre-acquire a ghost snapshot

Abort makes no real-workspace mutation. The pre-apply ghost snapshot exists to bound a post-apply restore; abort needs no such bound because the workspace is unchanged from before the tx began. (The Phase 3 turn-start ghost snapshot still applies for any in-turn cliq state the user might want to revert.)

### 11.4 Why pre-apply ghost snapshot

A turn already triggers a Phase 3 ghost snapshot at its start. In tx mode (especially explicit multi-turn or headless deferred-apply), the time gap between that snapshot and the apply moment can be large. The pre-apply snapshot freezes the apply-time state so post-apply restore remains useful.

Two ghost snapshots per applied tx is acceptable overhead: ghost snapshots are cheap Git objects and are eligible for normal Git GC.

### 11.5 Layer responsibilities (do not blur)

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
cliq tx abort    [<txId>] [--reason "..."] [--restore-confirmed | --keep-partial]
                                                   # the two flags are required ONLY when tx state is applied-partial;
                                                   # exactly one must be passed in that state. See Section 11.3 AB0a.
cliq tx validators                                 # show configured validators and their severities
cliq tx help
```

`<txId>` defaults to `Session.activeTxId` for the current session. If neither a `<txId>` argument nor an active tx is set, the command exits 1 with a clear error directing the user to either pass `<txId>` or run `cliq tx open`.

`tx apply` without prior `tx finalize`/`tx validate`/`tx approve` automatically runs the missing forward transitions, subject to `applyPolicy`. This is the common interactive path. Step-by-step subcommands exist for headless callers and debugging.

`tx finalize` is intentionally not exposed as a subcommand. Finalize is always implied by validate or apply; surfacing it separately would add a vocabulary item with no use case beyond debugging.

## 13. Headless Integration

This spec **extends** the shipped Phase 4 headless contract (`src/headless/contract.ts`). It does not introduce a parallel envelope or schema. Headless callers using `cliq run --jsonl` automatically observe tx behavior through new event types and artifact fields once `transactions.mode: edit` is configured.

The user-facing `cliq tx` subcommands (Section 12) accept `--json` to emit per-command snapshots; those snapshots reuse the same `Transaction` shape that flows through the headless event payloads (Section 13.2). There is one shape, two delivery channels.

### 13.1 New runtime event types

Added to `HeadlessRuntimeEventType` and `HeadlessEventPayloadByType` in `src/headless/contract.ts`:

```ts
// added to HeadlessRuntimeEventType
| 'tx-staging-start'
| 'tx-finalized'
| 'tx-validated'
| 'tx-applied'
| 'tx-aborted'

// added to HeadlessEventPayloadByType
'tx-staging-start':  TxStagingStartPayload;
'tx-finalized':      TxFinalizedPayload;
'tx-validated':      TxValidatedPayload;
'tx-applied':        TxAppliedPayload;
'tx-aborted':        TxAbortedPayload;

export type TxStagingStartPayload = {
  txId: string;
  txKind: TxKind;
  trigger: 'auto-turn' | 'explicit-open';
};

export type TxFinalizedPayload = {
  txId: string;
  diffSummary: DiffSummary;          // see Section 7
  diffArtifactPath: string;
  outOfBandCount: number;            // count of BashEffect entries
};

export type TxValidatedPayload = {
  txId: string;
  validators: ValidatorResultSummary[];   // name, severity, status, durationMs only
  blockingFailures: string[];
};

export type TxAppliedPayload = {
  txId: string;
  ghostSnapshotId: string;
  filesWritten: string[];
  overrides: OverrideEntry[];
};

export type TxAbortedPayload = {
  txId: string;
  reason:
    | 'validator-fail'
    | 'user-abort'
    | 'apply-error'
    | 'apply-conflict'
    | 'staging-error'
    | 'apply-failed-partial-restored'
    | 'apply-failed-partial-kept';
  failedValidators?: string[];
  // Present iff reason ∈ {apply-failed-partial-restored, apply-failed-partial-kept}.
  // Mirrors TxAbortedRecord.meta.appliedPartial so headless consumers see the
  // same integrity distinction as session-record consumers.
  appliedPartial?: {
    partialFiles: string[];
    ghostSnapshotId: string;
    restoreConfirmed: boolean;
  };
};
```

Payload sizing follows Phase 4's existing convention: file paths are inlined, blob content is not. Validator `findings[]`, full validator stdout, and the structured diff body remain accessible via `*ArtifactPath` fields, not inlined into events.

### 13.2 `HeadlessArtifacts` extension

```ts
// extends HeadlessArtifacts in src/headless/contract.ts
export type HeadlessArtifacts = {
  checkpoints: string[];
  workspaceCheckpoints: string[];
  compactions: string[];
  handoffs: string[];
  transactions: string[];   // NEW: tx ids produced by this run
};
```

`emptyHeadlessArtifacts()` is updated to initialize `transactions: []`. The merge helper in `src/headless/events.ts` extends to merge tx ids by id.

### 13.3 New error codes

Added to `HeadlessErrorCode`:

| Code | Stage | Triggered by |
|---|---|---|
| `tx-validator-blocking` | `tool` | apply / approve attempted while blocking validator failures exist and no override flag was given |
| `tx-apply-conflict` | `tool` | Stage A preflight detected external workspace change; tx returned to `approved` |
| `tx-apply-partial` | `tool` | Stage B failed mid-write; tx in `applied-partial`; `ghostSnapshotId` available for restore |
| `tx-overlay-error` | `tool` | overlay write failure during `staging` (disk full, permission, path escape) |

`HeadlessErrorStage` adds no new entries; tx errors slot under the existing `tool` stage because they originate from tool-driven mutations.

`HeadlessRunError.recoverable` is `true` for `tx-validator-blocking` and `tx-apply-conflict` (caller can re-validate, override, or re-apply); `false` for `tx-apply-partial` (requires manual ghost-snapshot restore) and `tx-overlay-error` (requires resolving the underlying IO problem).

### 13.4 `cliq run --jsonl` behavior with tx mode on

When the run starts under `transactions.mode: edit`, the existing `cliq run --jsonl` adapter emits the new tx events interleaved with the existing event stream. A typical successful run looks like:

```
run-start
checkpoint-created          ← Phase 3 ghost snapshot, Section 11
tx-staging-start            ← NEW
model-start ... model-end
tool-start (edit) ... tool-end
tx-finalized                ← NEW (auto-finalize at turn end if applyPolicy: per-turn)
tx-validated                ← NEW
checkpoint-created          ← apply-pre ghost snapshot (Section 11.3)
tx-applied                  ← NEW
final
run-end
```

A failure example (validator blocking, no override):

```
run-start ... tx-validated
error                       ← code: tx-validator-blocking, stage: tool, recoverable: true
tx-aborted                  ← NEW; reason: validator-fail
run-end                     ← exitCode reflects the run-level cancellation, not 0
```

The existing Phase 4 cancellation contract applies unchanged: `AbortSignal` triggers a `cancel`-stage `error` event followed by `tx-aborted` (reason: `user-abort`), then `run-end` with `cancelled` status.

### 13.5 Snapshot output for `cliq tx <subcommand> --json`

User-facing `cliq tx show`/`tx status`/`tx list` with `--json` emit a snapshot of the same `Transaction` shape (Section 7) — not the Phase 4 envelope, because these are query commands, not run streams.

```json
{
  "schemaVersion": 1,
  "tx": {
    "id": "tx_01HX...", "kind": "edit", "state": "applied",
    "sessionId": "sess_...", "workspaceId": "ws_...",
    "createdAt": "2026-05-06T10:00:00Z", "updatedAt": "2026-05-06T10:00:42Z",
    "diffSummary": { "filesChanged": 4, "additions": 12, "deletions": 3,
                     "creates": [], "modifies": ["src/bar.ts", "src/baz.ts"], "deletes": [] },
    "diffArtifactPath": "$CLIQ_HOME/tx/tx_01HX.../diff.json",
    "validators": [ { "name": "builtin:diff-sanity", "severity": "blocking", "status": "pass", "durationMs": 12 } ],
    "blockingFailures": [],
    "overridesApplied": [],
    "ghostSnapshotId": "ws_chk_...",
    "transitions": [ { "from": null, "to": "staging", "ts": "...", "by": "auto:turn-1" } ]
  }
}
```

This output is intentionally narrower than Phase 4's `RuntimeEventEnvelope` because it answers "what is the state of this tx right now", not "what happened during a run". The `schemaVersion` shares Phase 4's `HEADLESS_SCHEMA_VERSION` so callers can use one parser.

### 13.6 Exit codes (CLI surface)

| Code | Meaning |
|---|---|
| 0 | Command succeeded |
| 1 | Command-level error (bad arguments, tx not found, IO) |
| 2 | Business-rule rejection (blocking validator failed without override; tx not in expected state) |
| 3 | Tx entered `aborted` (or already aborted at command time) |

These are the `cliq tx` subcommand exit codes. Exit codes for `cliq run --jsonl` are governed by Phase 4 (`HEADLESS_EXIT_*`) and are unchanged: the tx contract communicates failure through the typed `error` events plus a non-zero `run-end` payload, not through new exit codes on `cliq run`.

### 13.7 Output mode resolution

| Condition | Behavior |
|---|---|
| `cliq tx ...` on TTY without `--json` | Human-readable text, color, interactive prompts |
| `cliq tx ... --json` | Snapshot JSON, no prompts; missing approval info exits 2 with a structured error |
| `cliq run --jsonl` (Phase 4 adapter) | Phase 4 envelope stream; tx events appear interleaved as in Section 13.4 |
| `cliq tx ... --headless` (alias) | Equivalent to `--json --tx-apply manual-only`; provided for symmetry with the run-time `--headless` posture |

## 14. Configuration

### 14.1 Workspace config (`.cliq/config.json`)

```json
{
  "transactions": {
    "mode": "edit",
    "auto": "per-turn",
    "applyPolicy": "interactive",
    "bashPolicy": "passthrough",
    "stagedView": {
      "copyMode": "auto",
      "bindPaths": ["node_modules"]
    },
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
| `bashPolicy` | `passthrough`, `confirm`, `deny` | `passthrough` | Per-Section 9.4: passthrough preserves current cliq behavior; confirm prompts each `bash` (interactive only); deny rejects `bash` during a tx |
| `stagedView.copyMode` | `auto`, `reflink`, `copy` | `auto` | How non-bound files are materialized into the staged view (Section 9.3.1). `auto` tries reflink (`clonefile`/`FICLONE`) and falls back to byte copy with a one-time warning; `reflink` requires CoW filesystem support; `copy` always byte-copies. Hardlinks are never used because they share inodes with the real workspace and would silently leak validator writes. |
| `stagedView.bindPaths` | array of workspace-relative paths | `["node_modules"]` | Paths symlinked from real workspace into staged-view (Section 9.3.2). Writes inside bind paths leak to real workspace; users tighten the list as needed. |
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
- `CLIQ_TX_BASH_POLICY`: same values as `transactions.bashPolicy`
- `CLIQ_TX_HEADLESS`: `"1"` is equivalent to `--headless`

## 15. Session Record Contract (Boundary with Auto-Compact)

Auto-compact shipped in `v0.7.0` (`src/session/auto-compaction.ts`, `src/session/auto-compact-config.ts`) with its own structured runtime events (`compact-start`, `compact-end`, `compact-skip`, `compact-error`) and durable compaction artifacts. The tx layer integrates with the existing auto-compact surface rather than co-designing it; nothing in this spec changes auto-compact's contract.

The boundary between tx and auto-compact remains: tx writes records into the session; nothing in auto-compact reads tx internals or modifies `$CLIQ_HOME/tx/`.

### 15.1 New record kinds

```ts
// success path
type TxAppliedRecord = {
  id: string;          // deterministic: `txrec_apply_<txId>` (Section 11.1 Stage C4)
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
  id: string;          // deterministic: `txrec_abort_<txId>`
  ts: string;
  kind: 'tx-aborted';
  role: 'user';
  content: string;     // e.g. "Transaction tx_01HX... aborted: blocking validator shell:tsc failed"
  meta: {
    txId: string;
    txKind: TxKind;
    reason:
      | 'validator-fail'
      | 'user-abort'
      | 'apply-error'
      | 'apply-conflict'
      | 'staging-error'
      // applied-partial-derived; exactly one is selected by the user's flag
      | 'apply-failed-partial-restored'   // user ran cliq checkpoint restore
      | 'apply-failed-partial-kept';      // user kept partial writes deliberately
    failedValidators?: string[];
    files: { wouldHaveCreated: string[]; wouldHaveModified: string[]; wouldHaveDeleted: string[] };
    artifactRef: string;
    // Present iff reason ∈ {apply-failed-partial-restored, apply-failed-partial-kept}
    appliedPartial?: {
      partialFiles: string[];     // workspace-relative paths written before the apply failed
      ghostSnapshotId: string;
      restoreConfirmed: boolean;  // mirrors the reason for downstream readers
    };
  };
};
```

The deterministic record ids are essential to Stage C's exactly-once guarantee (Section 11.1). Recovery passes use the same id formula and detect duplicates by scanning, not by writing extra bookkeeping.

### 15.2 Contract invariants

Tx layer guarantees:

- Exactly one `tx-applied` record is appended on a successful apply, ordered after the file writes by the phased apply protocol (Section 11.1). The record id is deterministic (`txrec_apply_<txId>`); if the cliq process is interrupted between file writes and record append, recovery (Section 16.4) reruns Stage C, scans for the deterministic id, and either skips the append (if a previous attempt already wrote it) or appends it with that id.
- Exactly one `tx-aborted` record is appended on terminal abort, with a structured `reason` and id `txrec_abort_<txId>`.
- Full diff content is **never** inlined into a session record. Only the `meta.artifactRef` pointer.
- `meta.diffSummary` and `meta.files` are stable, structured fields suitable for direct programmatic consumption (preferred by summarizers over `content`).
- `content` is a human-readable sentence intended for model replay; it never contains base64 blobs, full validator output, or content larger than ~512 bytes.
- Adding the tx record kinds to the `SessionRecord` union is an additive type extension. **It is not transparent to existing readers**: every consumer that does an exhaustive switch or validates record shapes by enumerating known kinds must be updated in this spec's PR (see Section 15.3). Without those updates, existing code rejects any session that contains a tx record.

### 15.3 Required consumer updates

The new record kinds extend the `SessionRecord` discriminated union in `src/session/types.ts`. The following modules in `origin/main` have exhaustive logic over record kinds and must be updated in the same PR:

- **`src/session/types.ts`** — add `TxAppliedRecord` and `TxAbortedRecord` to the `SessionRecord` union; add `activeTxId?: string` to the `Session` type (Section 6.1).
- **`src/session/store.ts`** — extend `isSessionRecord` (currently lines 86–113 on `cea4530`) so that records with `kind: 'tx-applied' | 'tx-aborted'` validate. Without this update, `isSession` returns `false` for any session containing a tx record, and `loadSession` rejects the file.
- **`src/headless/contract.ts`** — extend the `SessionRecordView` union (currently around line 214) with view shapes for the two new kinds. Without this update, headless artifact-query commands fail for sessions with tx records.
- **`src/runtime/context.ts`** `recordToMessage` — verify it routes tx records correctly. The current implementation routes any non-`tool` kind by `record.role`; tx records use `role: 'user'` so this works unmodified, but the assumption should be asserted by a regression test rather than left implicit.
- **`src/handoff/export.ts`** and any history/inspection rendering code that switches on `record.kind` — extend to handle the new kinds (or mark them explicitly opaque/skipped).
- **`src/session/auto-compaction.ts`** range selector — extend the existing turn-boundary rule so that the open-and-apply/abort moments of an explicit multi-turn tx form a non-splittable boundary, derived from the presence of `tx-applied`/`tx-aborted` records (and the explicit-tx-open marker, which is a property of the tx layer, not a session record). Implicit per-turn tx is contained inside a single turn and needs no special handling.
- **Default summarizer** (whatever module hosts it in `cea4530` — `src/session/auto-compaction.ts` calls into it) — when summarizing windows that contain `tx-applied`/`tx-aborted` records, prefer `meta.diffSummary` and `meta.files` over `content` for the structured fields surfaced in the compact summary.

### 15.4 SESSION_VERSION decision

`SESSION_VERSION` does **not** need to be bumped, but only because:

1. All readers that switch over record kinds are updated in this PR (Section 15.3). New sessions are loadable by the new binary.
2. Old binaries do not need to read sessions written by the new binary (we accept "upgrade in place; downgrade requires session reset").
3. Old sessions (which contain no tx records) remain readable by the new binary because the new code paths are additive.

If a hard requirement to keep old binaries forward-compatible with new sessions emerges, a `SESSION_VERSION` bump and a migration that strips unknown kinds during downgrade would be required. This release does not commit to that promise.

## 16. Concurrency, Locks, and Errors

### 16.1 Lock hierarchy

Tx introduces one new lock (tx-store). Acquisition order is fixed to prevent deadlock:

```
workspace state lock > session lock > tx-store lock
```

| Lock | Holder | Scope |
|---|---|---|
| workspace state lock (existing) | Phase 3 callers; tx does not acquire this | `workspaces/<workspaceId>/state.json` |
| session lock (existing) | runner during a turn; tx-coordinator during apply Stage C (session record append) | `sessions/.../<sessionId>.json` |
| tx-store lock (new) | tx state transitions; apply Stages A and B; held briefly inside Stage C after the session lock; abort Stages AB2..AB8 | `tx/<txId>/state.json`, `tx/<txId>/apply-progress.json`, `tx/<txId>/abort-progress.json` |

The tx-store lock is per-tx (keyed on `txId`), not global. Different tx never contend with each other.

The apply protocol releases the tx-store lock between Stage B and Stage C so it can re-acquire it after the session lock in the canonical hierarchy order. See Section 11.1 for the full sequence and the rationale for why the in-between window is safe.

### 16.2 Concurrent invocation scenarios

| Scenario | Behavior |
|---|---|
| Two `cliq` processes in the same session | The second process attempting to open a tx reads the session's `activeTxId` and fails with "session already has active tx tx_..."; user sees the conflict explicitly |
| Two processes in different sessions, same workspace | Each session owns its own `Session.activeTxId`; both sessions can have an active tx simultaneously, with no cross-interference |
| Two processes targeting the same `txId` (e.g., one runs `tx apply`, another runs `tx abort`) | Per-tx tx-store lock serializes within a single stage. Cross-stage races are blocked at the protocol level by symmetric authoritative under-lock checks: abort step AB3a rejects when `apply-progress.json` is in any in-flight phase; apply step A1a rejects when state is not `approved` or any `abort-progress.json` exists. AB0 is only an unlocked fast-fail optimization. Recovery passes use the same protocol entry points and idempotency checks as foreground operations. |
| External `git checkout` during tx | `builtin:index-clean` recheck in Stage A2 detects index change; bulk `oldContent` preflight in Stage A3 detects file-content change; both reject the apply before any write. Stage B's per-file re-verification (B3a) catches a third-party that races between Stage A and Stage B |

### 16.3 Error paths

| Failure point | Handling |
|---|---|
| Overlay write fails (disk full, permission) during `staging` | Tool returns error; tx remains in `staging`; user can `abort` or resolve and retry |
| Validator infrastructure fails (`status: 'error'`) | Counts neither as pass nor fail; transition rejected unless `--allow-validator-error <name>` is provided |
| Stage A preflight fails (index changed or any oldContent mismatch) | Apply rejected before any file write. Tx returns to `approved` with a clear "external change detected at <path>" error. User can investigate and re-apply, re-validate, or abort. |
| Stage B disk error mid-write (some files written, some not) | Tx transitions to `applied-partial`. `apply-progress.json` records exactly which files were written. Error output includes `ghostSnapshotId` and the restore command. Recovery is user-driven (Section 11.2). No automatic rollback. |
| Stage B per-file re-verification (B3a) detects mid-write external change | Same as the row above. |
| Process killed between Stage B and Stage C (`apply-committed` durable, no record) | Next cliq startup runs Stage C from scratch under the proper lock order (Section 16.4.1). Files are already on disk; the session record, `activeTxId` clear, and state transition all converge through Stage C's idempotent-by-deterministic-id design. |
| Concurrent `tx abort` racing into the Stage-B-to-Stage-C window | Abort step AB3a (under tx-store lock) rejects when `apply-progress.json` is in any in-flight phase including `apply-committed`. AB0 is only a pre-lock fast-fail; AB3a is authoritative. |
| Concurrent `tx apply` racing after a `tx abort` already won | Apply step A1a (under tx-store lock) rejects when tx state is no longer `approved` or any `abort-progress.json` exists. Symmetric counterpart of AB3a; protects against the inverse window where abort completes between the user's `tx apply` invocation and Stage A's lock acquisition. |
| Process killed mid-abort | Next cliq startup runs the recovery rule from Section 16.4.2 based on `abort-progress.phase`. Same scan-or-append, same conditional `activeTxId` clear, same conditional state transition. |
| Cliq process killed mid-tx (SIGKILL, power loss) | Tx state on disk is durable. Next invocation runs the crash recovery protocol (Section 16.4) for any tx in non-terminal apply or abort phases. |

The `applied-partial` state is intentionally not on the main state diagram. It is reached only from `apply` errors and exits only via explicit user intervention (manual restore from `ghostSnapshotId`, then `tx abort`).

### 16.4 Crash Recovery Protocol

At every cliq startup (and on demand via `cliq tx status --recover`), the tx-coordinator scans `$CLIQ_HOME/tx/` for any tx whose `state.json` is in a non-terminal state (`staging`, `finalized`, `validated`, `approved`, or `applied-partial`), any tx with `apply-progress.json` whose phase is not in the terminal set `{apply-finalized, apply-failed-partial}`, and any tx with `abort-progress.json` whose phase is not `aborted`.

A tx in `applied-partial` with `apply-progress.phase = apply-failed-partial` is **not** auto-recovered. It is awaiting user action (typically `cliq checkpoint restore` followed by `cliq tx abort`). `cliq tx status` surfaces it prominently, but the runtime takes no further action without a user command.

The recovery rule is selected by progress-file presence, in this priority order: `apply-progress.json` first, `abort-progress.json` second, neither third. (Only one progress file should ever exist for a given tx because the under-lock guards reject the conflicting direction: Section 11.3 AB3a rejects abort when `apply-progress.json` is in an in-flight phase, and Section 11.1 A1a rejects apply when `abort-progress.json` exists.)

#### 16.4.1 Apply recovery

| `apply-progress.phase` | Action at startup |
|---|---|
| absent | Tx never entered apply. Surface via `cliq tx status` for the affected session. No real-workspace damage possible. User decides to resume, apply, or abort. |
| `apply-pending` | Intent was logged but no files were written. Recovery branches on the current tx state: (a) if state is `approved`, mark tx state as `approved` (idempotent — clarifies the implicit progression has been reverted), discard `apply-progress.json`, user retries `tx apply` cleanly. (b) if state is anything else (e.g., already `aborted` or `applied` because a legitimate terminal action won and B1a didn't get to clean up), do NOT mutate state.json; discard `apply-progress.json` only if it is safe to confirm it is a stale orphan (the current terminal state is canonical), and surface a `recovery.json` warning prominently for the user. The runtime never resurrects a non-`approved` state into `approved` based solely on a leftover `apply-pending` file. |
| `apply-writing` | Some files were written. Move tx state to `applied-partial` AND transition `apply-progress.phase` to the terminal `apply-failed-partial` phase. Write a warning record (not a session record) to `$CLIQ_HOME/tx/<txId>/recovery.json` describing the state. Surface prominently the next time the user invokes any `cliq` command in the affected workspace, including the `ghostSnapshotId` and the two paths forward: (a) `cliq checkpoint restore <ghostSnapshotId>` then `cliq tx abort <txId> --restore-confirmed`, or (b) keep the partial writes and run `cliq tx abort <txId> --keep-partial` to record the deliberate choice. **Do not automatically restore**; the runtime takes no further action without the user's explicit flag. The `apply-failed-partial` phase is what allows the subsequent abort to proceed past Section 11.3 AB3a. |
| `apply-committed` | All files were written and durable. Recovery **invokes Stage C as defined in Section 11.1** without modification (acquires session lock first, then tx-store lock, runs C3–C8). Stage C's deterministic-id scan and conditional `activeTxId` clear in C4 make it safe to rerun even if a previous attempt got partway through. Recovery does not implement its own session-write logic. The user is informed at the next invocation that recovery completed automatically; they may verify in `cliq tx show <txId>`. |
| `apply-finalized` | Stage C reached C5 but did not finish C6. Recovery re-enters C from C3, sees record present and `activeTxId` already cleared, transitions tx state.json to `applied`. Idempotent. |

#### 16.4.2 Abort recovery

| `abort-progress.phase` | Action at startup |
|---|---|
| `aborting` | Abort started but did not finish. Recovery **invokes the abort protocol from Section 11.3 starting at AB1** (re-acquires locks; AB3a re-checks apply-progress; AB3b's all-terminal-markers check determines whether anything is left to do; AB4..AB7 each run idempotently against their own targets). The protocol converges to `aborted` regardless of where the previous attempt died — including the AB6→AB7 crash window where state.json is already `aborted` but abort-progress.phase is still `aborting`. |
| `aborted` | The abort progress file phase says complete. AB3b verifies the four terminal markers (record present, activeTxId cleared, state.json='aborted', abort-progress.phase='aborted'); if all hold, recovery is a no-op. If any is missing (e.g., manual partial cleanup), recovery completes the missing steps idempotently from AB4 onward. |

The protocol's invariants:

- A tx in `apply-writing` is **never** silently abandoned. The user is always notified.
- A tx in `apply-committed`, `apply-finalized`, or any abort phase is **always** auto-reconciled because the only outstanding actions (record append, `activeTxId` clear, state transition) are provably safe to retry by deterministic-id scan and conditional clear.
- No recovery action ever modifies real workspace files. Only `apply-progress.json`, `abort-progress.json`, `state.json`, and (in the reconciliation cases) the session record file are written by the recovery protocol.
- Recovery is idempotent. Running it twice produces the same result as running it once.
- Abort recovery and apply recovery are mutually exclusive for any single tx because the under-lock guards in Section 11.3 AB3a (rejects abort while apply is in flight) and Section 11.1 A1a (rejects apply while abort-progress exists or another apply-progress is in flight) ensure only one progress file is ever non-terminal at a time.

`cliq tx status` output annotates any tx that went through automatic recovery with a `recoveredAt` timestamp, both in human and JSON forms, so callers can audit.

## 17. Module Boundaries

```text
src/
  workspace/
    transactions/
      types.ts           # Transaction, TxState, DiffSummary, AuditEntry, OverrideEntry, ApplyProgress
      store.ts           # persistence, per-tx locking, list/get
      overlay.ts         # edit-tx overlay materialization
      diff.ts            # diff computation, JSON serialization
      apply.ts           # phased apply protocol (Section 11.1, Stages A/B/C)
      abort.ts           # abort termination protocol (Section 11.3, AB0..AB9)
      recovery.ts        # crash recovery protocol (Section 16.4); shares the
                         # session-write helper used by apply.ts Stage C and
                         # abort.ts AB5 so terminal cleanup logic exists in
                         # exactly one place
      staged-view.ts     # bind-path-aware staged view materialization
      coordinator.ts     # state transitions, session record writes,
                         # activeTxId clearing, ghost snapshot integration
    snapshots.ts         # Phase 3, unchanged
  validators/
    types.ts             # Validator, ValidatorContext, ValidatorResult
    registry.ts          # built-in registration + shell adapter integration
    runner.ts            # parallel/serial execution, staged-view orchestration
    builtin/
      diff-sanity.ts
      index-clean.ts
      size-limit.ts
    shell.ts             # config-driven shell-hook adapter
  runtime/
    runner.ts            # extended: WorkspaceWriter injection; tx event emission via existing onEvent surface
    workspace-writer.ts  # WorkspaceWriter interface + passthrough and overlay implementations
    bash-policy.ts       # bashPolicy enforcement around bash invocation
  headless/
    contract.ts          # extended: new tx event types, payloads, error codes; HeadlessArtifacts.transactions
    events.ts            # extended: runtime → headless event mapping for tx events; mergeArtifacts handles transactions
  session/
    types.ts             # extended: SessionRecord union gains TxAppliedRecord, TxAbortedRecord variants
    auto-compaction.ts   # extended: range-selector treats tx open/apply boundaries as non-splittable
  tools/
    edit.ts              # minimal change: writes via WorkspaceWriter (read + replaceText) instead of fs directly
    bash.ts              # unchanged invocation surface; coordinator records BashEffect around it
  cli.ts                 # extended with tx subcommand group
```

### 17.1 `WorkspaceWriter` interface

The smallest possible abstraction needed to make `edit` overlay-aware:

```ts
type WorkspaceWriter = {
  read(workspaceRelativePath: string): Promise<string>;
  replaceText(workspaceRelativePath: string, oldText: string, newText: string): Promise<void>;
};
```

Two implementations:

- **`PassthroughWriter`**: reads and writes the real workspace via `fs.promises`. Used when tx mode is off, and inside the apply path itself. Matches today's `edit.ts` behavior exactly.
- **`OverlayWriter`**: reads from the overlay if the path is staged, otherwise from the real workspace. Writes to `$CLIQ_HOME/tx/<txId>/overlay/<path>`. Used when tx mode is on and the tx is in `staging`.

The runner injects a `WorkspaceWriter` into the tool execution context. The `edit` tool's existing path-resolution and exact-match-once logic stays put; only the final filesystem call changes from direct `fs.writeFile` to `writer.replaceText`. This is a single-file diff to `src/tools/edit.ts`.

`bash.ts` does not receive a `WorkspaceWriter`. Its execution model is unchanged. The coordinator wraps `bash` invocations with two responsibilities: enforcing `bashPolicy` (Section 9.4.1) before running, and recording `BashEffect` after.

### 17.2 Module responsibilities

- `workspace/transactions/coordinator`: the only module that drives state transitions and writes session records. All `tx` CLI commands route through it.
- `workspace/transactions/store`: persistence and lock primitives; no transition logic.
- `workspace/transactions/apply`: implements the phased apply protocol; updates `apply-progress.json` step by step.
- `workspace/transactions/recovery`: implements the crash recovery protocol; called at startup and on demand.
- `workspace/transactions/staged-view`: materializes the staged view with bind paths.
- `validators/runner`: orchestrates a single `validate` invocation. Does not know tx semantics beyond what `ValidatorContext` exposes.
- `runtime/workspace-writer`: the abstraction layer. Contains both implementations.
- `runtime/bash-policy`: encapsulates the policy decision; called from the runner just before `bash.execute`.
- `cli.ts`: parses arguments, formats output (text or envelope), shells into coordinator.

## 18. Test Matrix

Required tests grouped by concern:

**Storage and lifecycle**
- Tx persists across cliq process restart
- Aborted tx overlay retained for `abortRetention`, then cleaned up
- `Session.activeTxId` consistency: open/abort/apply each correctly mutate the field
- Two sessions in the same workspace can each hold a distinct active tx
- Workspace state.json is unchanged by tx operations (regression)

**State machine**
- All legal transitions covered
- All illegal transitions rejected (e.g., `staging → applied` skipping validate)
- Concurrent transitions on the same `txId` serialized by tx-store lock
- `audit.json` appends never lost

**Edit-tx behavior**
- `edit` via `OverlayWriter` writes to overlay only, not real cwd
- `edit` via `PassthroughWriter` (tx off) preserves current behavior exactly
- `bash` runs against real cwd; `BashEffect` records appear in diff.outOfBand
- Mutations after finalize rejected
- Multi-turn diff accumulation produces correct final diff
- v0.8 diff entries are all `op: 'modify'`; create/delete entries never produced

**Validators**
- `builtin:diff-sanity` rejects path escapes and binary-as-text mistakes
- `builtin:index-clean` detects external Git index changes between validate and apply
- Shell-hook validators run in `staged-view`, not real cwd (regression)
- Staged view exposes `node_modules` via bind path; `npm test` succeeds when project tests pass
- Bind path writes leak to real workspace (documented behavior; assert via test)
- **Non-bound files are reflinked or copied, never hardlinked**: validator writes to a non-bound file inside staged-view do not appear in the real workspace
- `copyMode: auto` succeeds with reflinks on supported filesystems; falls back to copy with one-time warning on others
- `copyMode: reflink` fails fast on filesystems that do not support reflink (no silent slow path)
- Parallel and serial execution both honored
- Timeout produces `status: 'error'`, not `'fail'`
- `--override` requires the exact validator name; misspellings are rejected
- `--override-all` requires `--reason`

**Apply and Phase 3 coexistence**
- Pre-apply ghost snapshot taken and recorded in `tx.ghostSnapshotId`
- Stage A preflight rejects on any oldContent mismatch with no file written; tx returns to `approved`
- Stage A preflight rejects when external change touches a non-first file (the regression motivating the preflight split)
- Stage B disk error mid-write transitions to `applied-partial` with correct `apply-progress.filesWritten[]`
- Stage B per-file re-verification (B3a) catches a mid-stage external change and transitions to `applied-partial` (not silently overwrite)
- Apply failure includes ghost snapshot id in error output
- Successful apply writes `tx-applied` session record with deterministic id `txrec_apply_<txId>` (regression: no duplicates after simulated mid-Stage-C crash and recovery)
- Successful apply clears `Session.activeTxId` (regression: subsequent `cliq tx open` succeeds in the same session)
- Aborted apply writes `tx-aborted` session record
- Session records never contain inlined full diffs
- Apply releases tx-store lock between Stage B and Stage C; concurrent recovery in Stage C is idempotent (verified by spawning a second process during the window)
- Lock acquisition order audit: no code path holds tx-store while attempting to acquire session lock (assertion in tests)
- Concurrent `tx abort` is rejected with `tx-apply-conflict`-shaped error when `apply-progress.json` exists in any non-terminal phase (regression for the Stage-B-to-Stage-C race)
- Apply Stage A1a rejects when tx state is no longer `approved` (e.g., a concurrent abort completed before A1 acquired the lock), without writing apply-progress.json or any file
- Apply Stage A1a rejects when any `abort-progress.json` exists, regardless of phase
- Apply Stage A1a rejects when `apply-progress.json` already exists in any phase (apply-vs-apply same-direction race; second invocation must use `cliq tx status` or wait)
- Apply Stage B1a, when artificially induced to fire (e.g., test-only fault injection that flips tx state mid-stage), deletes `apply-progress.json` under the lock and does NOT mutate `state.json`; the previously-set terminal state is preserved
- `apply-pending` recovery does NOT revert `state.json` to `approved` when current state is `aborted` or `applied`; it only discards the orphan `apply-progress.json` and emits a recovery warning

**Abort termination protocol**
- `tx abort` from `staging`/`finalized`/`validated`/`approved` writes one `tx-aborted` record (deterministic id `txrec_abort_<txId>`) and clears `Session.activeTxId`
- Mid-abort crash with `abort-progress.phase: 'aborting'` is recovered by Section 16.4.2 to the same terminal state
- Crash after AB5 (record appended) but before AB6 (state.json flip): recovery completes the state transition; no duplicate record
- Crash after AB6 but before AB7: recovery enters AB3b, sees `abort-progress.phase` not yet `aborted`, runs through AB4–AB7 idempotently, converges to all four terminal markers set
- AB3a closes the AB0-to-AB2 race: a concurrent apply that creates `apply-progress.json` in an in-flight phase between AB0 and AB2 is rejected at AB3a (test by deterministically interleaving the two protocols using a shared barrier)
- A1a closes the inverse race: a concurrent abort that completes (writes abort-progress and flips state) before apply's Stage A acquires the tx-store lock is rejected at A1a, not via state-blind apply (test with a shared barrier where abort wins the race)
- Abort during `apply-pending` rejected (in-flight phase) with clear error directing to `cliq tx status` recovery flow
- Abort during `apply-writing` rejected (in-flight phase) — workspace already partially mutated; user must restore via ghost snapshot, which moves apply-progress to `apply-failed-partial`, after which abort succeeds
- Abort during `apply-committed` rejected (in-flight phase; apply is bound for `applied`; let recovery finish it)
- Abort during `apply-failed-partial` requires `--restore-confirmed` or `--keep-partial`; missing flag exits 1; passing both rejects as ambiguous
- `--restore-confirmed` produces `tx-aborted` record with reason `apply-failed-partial-restored` and `meta.appliedPartial.restoreConfirmed: true`
- `--keep-partial` produces `tx-aborted` record with reason `apply-failed-partial-kept` and `meta.appliedPartial.restoreConfirmed: false`; `meta.appliedPartial.partialFiles` matches `apply-progress.filesWritten`
- AB3a.5 catches state-changed-mid-abort: if state was `approved` at AB0a but became `applied-partial` between AB0a and AB2 (concurrent recovery completed), abort is rejected with "tx state changed; re-run with --restore-confirmed or --keep-partial" — without writing any session record or progress file
- AB3a.5 rejects `--restore-confirmed`/`--keep-partial` flags when tx state is NOT `applied-partial` at lock time (caller passed an inappropriate flag)
- `tx-aborted` headless event payload (`TxAbortedPayload`) includes the same `reason` and `appliedPartial` fields as the session record (regression: parity between event stream and session record)
- Abort during `apply-finalized` rejected (apply is bound for `applied`; let recovery finish it)
- Abort overlay retained per `abortRetention`; not eagerly cleaned

**Crash recovery (Section 16.4)**
- Crash before `apply-progress.json` exists: tx remains in `approved`, no recovery action needed
- Crash in `apply-pending` with current state still `approved` (normal case): recovery confirms `approved` and discards apply-progress
- Crash in `apply-writing`: recovery moves to `applied-partial` and surfaces warning at next invocation; no automatic file restore
- Crash in `apply-committed`: recovery idempotently appends session record and transitions to `applied`
- Crash in `apply-finalized`: recovery transitions tx state to `applied`
- Recovery is idempotent: running twice yields same state
- Recovery never modifies real workspace files
- `cliq tx status` shows `recoveredAt` timestamp for recovered tx

**Bash policy**
- `bashPolicy: passthrough` runs `bash` unchanged (regression for current users)
- `bashPolicy: confirm` prompts before each `bash` (interactive) and is promoted to `deny` in `--headless`
- `bashPolicy: deny` rejects `bash` during a tx with a clear error
- `--policy confirm-bash` plus `bashPolicy: deny`: stricter wins (deny)

**CLI and headless**
- `--tx off` overrides config
- `cliq tx ... --headless` forces `applyPolicy: manual-only`
- `cliq tx ... --json` snapshot output contains `schemaVersion: 1` (shared with Phase 4 `HEADLESS_SCHEMA_VERSION`)
- Exit codes 0/1/2/3 map to documented scenarios on `cliq tx` subcommands
- Missing `<txId>` and missing `Session.activeTxId` produces clear error message
- `cliq run --jsonl` with tx mode on emits new event types interleaved at correct lifecycle points (start before model-start, finalized at turn end, validated before apply, applied after pre-apply checkpoint)
- `HeadlessArtifacts.transactions[]` is populated for every applied/aborted tx in a run
- New `HeadlessErrorCode` values appear in error events with correct stage and recoverable flag
- Phase 4 `RuntimeEventEnvelope` shape (envelope fields, schemaVersion) is unchanged for existing event types (regression)

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

- Existing users on `v0.7.0` who upgrade to the tx release see no behavior change. `transactions` config is absent; `mode` defaults to `off`; no tx code paths execute.
- No `SESSION_VERSION` bump is required *under the assumption that old binaries do not need to read sessions written by the new binary*. Existing readers do **not** treat unknown record kinds as pass-through (Section 15.3 enumerates the consumer updates required); they are updated in this spec's PR. Section 15.4 documents the trade-off.
- No `HEADLESS_SCHEMA_VERSION` bump is required: the new event types extend `HeadlessRuntimeEventType`, the new artifact field extends `HeadlessArtifacts`, and the new error codes extend `HeadlessErrorCode`. All existing v1 consumers remain compatible because they iterate event types and artifact keys without exhaustive enumeration.
- No changes to `.cliq/session.json` migration logic (Phase 3 already handled the workspace-local → global migration).
- `$CLIQ_HOME/tx/` is created lazily on first tx open; does not exist for users who never enable tx.

If a future revision needs to break either schema, it bumps the corresponding version constant. v1 of both contracts must remain stable for the lifetime of v0.8.x.

## 21. Deferred Decisions

- **worktree-tx**: full workspace as a Git worktree so `bash` side-effects are also captured. Defer until edit-tx has real-world usage data on which workflows hit the `bash`-out-of-band limitation.
- **Staged file creates and deletes**: v0.8 only stages `modify` operations, because the existing `edit` tool only supports text replacement. Adding staged creates and deletes requires either a new declarative tool (`create_file`, `delete_file`) or routing `bash`-driven creates/deletes through the overlay. Both are non-trivial and defer to worktree-tx, which naturally subsumes both via Git worktree semantics.
- **Sparse staged-view materialization**: only copy files differing in the staged view plus their dependency closure. Defer until a concrete performance complaint with measurements is filed.
- **Cross-session tx merging**: for workflows where multiple sessions converge on a single review unit. Defer until a concrete user workflow is documented.
- **Partial apply**: apply only some files from a tx. Defer; current discipline is "tx is reviewed and applied as a unit".
- **Automatic validator-driven retry loops**: tx fails validation, model is asked to fix and tries again automatically. Defer; risks runaway loops and is better explored after tx is in real use.
- **Tx protocol stdio JSON-RPC adapter**: the Phase 4 spec lists a stdio JSON-RPC adapter for the same headless contract as a `v0.7.x` follow-up. When that adapter ships, tx events automatically flow through it because they are part of the same `RuntimeEventEnvelope` stream. No tx-specific RPC work is required by this spec.
- **TUI / visual diff browsing**: defer to richer UX phases.
- **Non-Git overlay alternative**: tx overlay does not require Git, but Phase 3 ghost snapshots do. A non-Git workspace using tx still loses recovery if `applied-partial` happens. Defer alternative snapshot mechanisms (e.g., copy-on-write directory snapshots) until needed.
