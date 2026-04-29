# Phase 3 Session Workflow Assets Design

**Date:** 2026-04-28
**Status:** Draft
**Target Release:** `v0.6.0`

## 1. Summary

Phase 3 upgrades Cliq sessions from a single local conversation log into workflow assets that can be recovered, forked, compacted, and handed off.

This release adds four related capabilities as one coherent session/context layer:

- checkpoint: capture a recoverable session point and, inside Git repositories, a Git-backed workspace snapshot
- fork: create a new session branch from a checkpoint
- compact: produce a structured context summary used for future model replay while preserving raw records
- handoff: export a durable handoff artifact for another model, agent process, UI surface, or human operator

The design intentionally keeps the CLI as a thin surface. Core behavior belongs in session, context, and workspace modules so future headless, RPC, TUI, and automation surfaces can reuse it.

## 2. Roadmap Placement

This release implements Phase 3 from the runtime architecture roadmap: **Session As Workflow Asset**.

It builds on the v0.4 model provider runtime and v0.5 packaging baseline, but does not expand into later roadmap phases:

- Phase 4 headless JSONL/RPC interfaces are deferred.
- Phase 5 token/cost accounting, audit export, and debug/replay are deferred.
- Phase 6 worktree isolation, automation, and richer UI/UX are deferred.

This release may create artifacts that later phases can consume, but it does not implement those later surfaces.

## 3. Goals

### 3.1 Product Goals

- Let users recover from bad agent turns without manually editing session files.
- Let users branch a session from a known point.
- Let long-running sessions continue with compacted context while preserving full history.
- Let users export a clear handoff for another model, agent process, or human reviewer.
- Make recovery behavior explicit enough that users know when files will or will not be changed.

### 3.2 Architecture Goals

- Move model replay construction out of the runner into a context builder.
- Represent checkpoints, compactions, and handoffs as first-class session/context artifacts.
- Add Git-backed workspace snapshots without polluting user branches or staging state.
- Keep file recovery separate from session recovery.
- Preserve current protocol and tool model.

## 4. Non-Goals

This release does not provide:

- full filesystem snapshotting outside Git repositories
- recovery of shell processes, database state, servers, network effects, or external API side effects
- automatic worktree creation for forks
- Claude Code-style Esc realtime interrupt UX
- TUI session tree visualization
- automatic compaction triggered by token budget
- token/cost governance
- cross-provider orchestration as a dedicated workflow
- provider-native tools

## 5. Core Semantics

Cliq must distinguish three layers of state:

1. **Session state:** records, checkpoints, compactions, model identity, lifecycle metadata.
2. **Workspace file state:** files created, modified, deleted, or moved inside the working tree.
3. **Runtime side effects:** shell processes, databases, services, network calls, caches, and external systems.

Phase 3 can manage the first two layers. It must not claim to fully restore the third layer.

## 6. Storage Model

Phase 3 uses a **global-first hybrid** storage model.

Workspace-local `.cliq/` remains the place for project-owned configuration such as `config.json`, local skills, and local extensions. It is not the canonical store for sessions, checkpoints, compactions, or handoffs.

Cliq workflow state is stored under `CLIQ_HOME`.

`CLIQ_HOME` resolution:

1. If `process.env.CLIQ_HOME` is set to a non-empty path, use that path.
2. Otherwise use `path.join(os.homedir(), '.cliq')`.
3. Resolve the final path to an absolute path before use.

The v1 default intentionally uses `~/.cliq` instead of an XDG state path so the implementation and user mental model stay simple. A future migration can add XDG support, but v1 must have one stable default.

```text
$CLIQ_HOME/
  state.json
  workspace-index.json
  workspaces/<workspaceId>/state.json
  sessions/<yyyy>/<mm>/<dd>/<sessionId>.json
  checkpoints/<checkpointId>.json
  handoffs/<handoffId>/handoff.json
  handoffs/<handoffId>/HANDOFF.md
```

Workspace identity:

- `workspaceRealPath = fs.realpath(cwd)`.
- `workspaceId = sha256(workspaceRealPath)`, encoded as lowercase hex.
- `gitRootRealPath` is stored when the workspace is inside a Git repository, but it is not the workspace identity.

Cliq uses the current working directory as the workspace root because existing tools, config loading, and path guards already define the workspace that way. Running Cliq from a repo subdirectory is therefore a distinct workspace from running it at the repo root, even though both may share the same Git object database.

`workspace-index.json` maps `workspaceId` to the last known `workspaceRealPath`, optional `gitRootRealPath`, `activeSessionId`, and `lastSeenAt`. The per-workspace state file stores the same active pointer plus recent session ids so `history` and `reset` do not need to scan the full global store.

CLI behavior under the global store:

- `cliq history` loads the active session for the current `workspaceId` and prints that session.
- `cliq reset` creates a new empty session, sets it as the active session for the current `workspaceId`, and leaves older sessions in the global store.
- Session deletion, global cleanup, and cross-workspace session browsing are deferred.

Global session metadata records the workspace real path, Git repository root when present, active session id, checkpoint ids, and handoff artifact paths.

Git-backed workspace checkpoint content still lives in the repository's Git object database because file snapshots are represented as Git objects. The global Cliq checkpoint metadata records the ghost commit id.

```text
<repo>/.git/objects/...
$CLIQ_HOME/checkpoints/<checkpointId>.json
```

This keeps session metadata out of the project tree while letting Git store the actual file snapshot efficiently.

Phase 3 v1 does **not** create internal refs such as `refs/cliq/checkpoints/*`.

Because ghost commits are not protected by refs, workspace file restore is best-effort and short-term. Git may eventually prune unreachable commits according to the repository's GC configuration. Session restore remains durable because session records live in `CLIQ_HOME`.

Before any file restore, Cliq must verify the ghost commit still exists, for example with `git cat-file -e <commit>^{commit}`. If the commit is missing, Cliq must fail before changing files and report that the workspace snapshot is no longer available. Long-lived protected refs may be revisited later if Cliq needs named checkpoints to survive Git garbage collection, but that is explicitly deferred and not part of this implementation scope.

Rationale:

- Avoid polluting user workspaces with frequently changing session artifacts.
- Avoid accidentally including Cliq session/checkpoint files in Git snapshots.
- Match the storage direction used by larger coding agents such as Codex and Pi, where sessions are indexed from a global home/state directory while Git snapshots use repository Git objects.
- Keep workspace-local `.cliq/` focused on source-controlled or intentionally local project configuration.

Tradeoffs:

- Global state needs cleanup and export/import commands later.
- Moving or renaming a workspace can make existing sessions harder to discover unless the index supports path refresh.

## 7. Session Schema

`SESSION_VERSION` will increase to `5`.

Session records remain append-only. Restore and fork operations create new sessions instead of destructively deleting historical records from an existing session.

```ts
export type Session = {
  version: 5;
  app: 'cliq';
  id: string;
  parentSessionId?: string;
  forkedFromCheckpointId?: string;
  model: SessionModelRef;
  cwd: string;
  createdAt: string;
  updatedAt: string;
  lifecycle: SessionLifecycle;
  records: SessionRecord[];
  checkpoints: SessionCheckpoint[];
  compactions: CompactionArtifact[];
};
```

Checkpoint metadata:

```ts
export type SessionCheckpoint = {
  id: string;
  name?: string;
  kind: 'auto' | 'manual' | 'restore-safety' | 'handoff';
  createdAt: string;
  recordIndex: number;
  turn: number;
  workspaceCheckpointId?: string;
};

export type WorkspaceCheckpoint =
  | {
      id: string;
      kind: 'git-ghost';
      status: 'available' | 'expired';
      createdAt: string;
      workspaceRealPath: string;
      gitRootRealPath: string;
      repoRelativeScope: string;
      commitId: string;
      parentCommitId?: string;
      preexistingUntrackedFiles: string[];
      warnings: string[];
    }
  | {
      id: string;
      kind: 'unavailable';
      status: 'unavailable';
      createdAt: string;
      workspaceRealPath: string;
      reason: 'not-git' | 'snapshot-failed';
      error?: string;
    };
```

`SessionCheckpoint.recordIndex` is a boundary count, not the id of a record. It means "the checkpoint was taken after `records.slice(0, recordIndex)` and before `records[recordIndex]`." Automatic checkpoints created before a user turn therefore point to the state before that user record is appended.

## 8. Checkpoint

Checkpoint combines a session anchor with an optional workspace snapshot.

User commands:

```bash
cliq checkpoint create [name]
cliq checkpoint list
cliq checkpoint restore <checkpoint-id> --scope session|files|both
cliq checkpoint help
```

Runtime behavior:

- Each user turn creates an automatic checkpoint before appending the new user record.
- Users can create named manual checkpoints.
- In Git repositories, checkpoint creation also captures a Git-backed workspace snapshot.
- Outside Git repositories, checkpoint creation still records the session point but marks workspace snapshot status as unavailable.
- Automatic checkpoint creation is a pre-turn gate: the session checkpoint and workspace snapshot attempt must finish before model execution or any write-capable tool execution for that turn begins.
- Phase 3 v1 creates the automatic checkpoint synchronously. A future asynchronous snapshot implementation may overlap read-only preparation, but it must still gate model execution, shell execution, and write tools until the snapshot attempt has completed.

Workspace snapshots use a Codex-style Git ghost snapshot:

- use Git plumbing and a temporary index
- avoid modifying user branch history
- avoid modifying the user staging area
- record paths and warnings
- skip unsupported or risky content such as large ignored directories and nested repositories

Restore scopes:

- `session`: create a new session from the checkpoint record prefix and switch the active session.
- `files`: restore workspace files to the workspace checkpoint and leave the active session unchanged.
- `both`: create a restore-safety checkpoint, restore files, create a new session from the checkpoint prefix, and switch the active session.

File restore rules:

- File restore must ask for confirmation in interactive mode. Non-interactive file restore requires an explicit `--yes`.
- v1 restores the working tree only. It must not restore or rewrite the Git index.
- The restore command must not pass `--staged`.
- If staged changes exist under the restore scope, Cliq must warn that staged entries will be preserved while matching working-tree files may be overwritten. Interactive mode defaults to "no"; non-interactive mode requires `--yes`.
- Git checkpoints record non-ignored untracked files that existed when the snapshot was created. Restore removes non-ignored untracked files created after the checkpoint and preserves preexisting untracked files.
- Before restore mutates files, Cliq verifies that the current `cwd` resolves to the checkpoint's `workspaceRealPath` and that the ghost commit still exists.
- v1 does not support restoring staged/index state back to a checkpoint. A future explicit `--include-staged` mode can be evaluated separately.

This follows the current Codex direction more than older ghost-snapshot variants: snapshot creation uses a temporary index, but restore avoids `--staged` to preserve the user's staged changes. Pi's Git checkpoint example is extension-level and uses `git stash create` / `git stash apply`, also keeping Git checkpointing outside the session core rather than defining staged-index restore as a built-in contract.

## 9. Fork

Fork is a checkpoint consumer.

User commands:

```bash
cliq checkpoint fork <checkpoint-id> [name]
cliq checkpoint fork <checkpoint-id> [name] --restore-files --yes
```

Default fork is session-only:

- create a child session
- copy records through the checkpoint record index
- record `parentSessionId`
- record `forkedFromCheckpointId`
- switch the active session

`--restore-files` performs workspace restore first, then creates the child session. This mode changes the working tree and therefore requires confirmation or `--yes`.

This release does not implement `fork --worktree`. Worktree-based branch isolation is deferred to a later phase.

## 10. Compact

Compact is a context-management artifact, not a destructive history rewrite.

User commands:

```bash
cliq compact create --summary <markdown>
cliq compact create --summary <markdown> --before <checkpoint-id>
cliq compact list
cliq compact help
```

Raw session records remain stored. Compact artifacts affect model replay only.

The compact context model has three parts:

```text
HEAD: regenerated instructions, tools, policy, workspace, skill, extension, and runtime context
SUMMARY: compact summaryMarkdown covering older session records
TAIL: recent raw records starting at firstKeptRecordId
```

Cliq core does not maintain a separate task-anchor or permanent first-user-input record outside compaction. If task intent needs to be preserved, it belongs inside `summaryMarkdown` under stable headings such as `Objective` and `Decisions And Constraints`.

Compact artifacts use a small JSON envelope plus a Markdown summary body. The JSON fields are replay metadata and indexes; the summary itself remains human-readable and model-ready.

```ts
export type CompactionArtifact = {
  id: string;
  status: 'active' | 'superseded';
  createdAt: string;
  coveredRange: {
    startIndexInclusive: number;
    endIndexExclusive: number;
  };
  firstKeptRecordId: string;
  anchorCheckpointId?: string;
  createdBy: { provider: string; model: string };
  summaryMarkdown: string;
  details?: {
    filesRead?: string[];
    filesModified?: string[];
    tests?: string[];
    risks?: string[];
  };
};
```

Range semantics:

- A session has at most one active compaction.
- The context builder must use exactly one active compaction, plus raw records from `firstKeptRecordId` onward.
- Superseded compactions remain stored for audit/debug, but they are ignored by normal replay.
- `coveredRange.startIndexInclusive` is always `0` in v1.
- `coveredRange.endIndexExclusive` is the index of the first raw record kept in the tail.
- `firstKeptRecordId` must equal `session.records[coveredRange.endIndexExclusive].id`.
- A compaction must leave a non-empty tail. If the selected range would cover all records, the command fails with a clear message.

`cliq compact create` range selection:

- If no active compaction exists, summarize raw records from index `0` through the selected cut point.
- If an active compaction exists, summarize the previous active `summaryMarkdown` plus raw records from the previous `firstKeptRecordId` through the new selected cut point.
- Mark the previous active compaction as `superseded` only after the new artifact is written successfully.
- Select the cut point using `keepRecentTokens` and turn-boundary rules.

`cliq compact create --before <checkpoint-id>` range selection:

- The checkpoint's `recordIndex` is a boundary between records.
- Compact records strictly before that boundary.
- Keep records at and after that boundary raw.
- Set `anchorCheckpointId` to the supplied checkpoint id.

`cliq compact create --from <checkpoint-id>` is intentionally deferred. "From" can mean "summarize after this checkpoint", "keep after this checkpoint", or "start a new compaction lineage"; v1 avoids that ambiguity.

Cliq-generated Markdown summaries must use stable headings so they can be inspected by humans and injected into future model context without conversion. The context builder treats `summaryMarkdown` as opaque text; the heading requirement belongs to the default Cliq summarizer and future default hooks.

```md
## Objective
...

## Current State
...

## Decisions And Constraints
...

## Files And Changes
...

## Tests And Validation
...

## Open Questions And Risks
...

## Next Steps
...
```

Rationale:

- This follows the practical direction used by agent compaction systems: keep the compacted context as a readable summary, not a large rigid JSON object.
- The envelope gives Cliq enough metadata to decide replay ranges and supersession.
- The Markdown body can be reused directly by automatic compaction, handoff generation, and model replay.
- Keeping task intent inside the compact summary avoids a separate long-lived task-anchor schema that could pollute later unrelated work in the same session.
- Handoff artifacts may still be more structured than compact artifacts because handoff is an external export format.

### 10.1 Future Automatic Compaction

Phase 3 implements manual compact first, but the artifact shape must support automatic compact later without changing the storage model.

Future automatic compact should only add trigger and range-selection logic:

- `triggerThreshold`: compact when estimated context usage crosses a configured ratio or token count
- `reserveTokens`: preserve enough budget for the next model response and tool loop
- `keepRecentTokens`: keep a recent raw tail after the compacted middle section
- turn-boundary selection: avoid splitting a user/assistant/tool-result sequence unless a single turn is too large

The output remains the same `CompactionArtifact`: older records become `summaryMarkdown`, and recent records remain raw from `firstKeptRecordId`.

### 10.2 Future Extension Hooks

Compact should allow later extension points without hardcoding domain-specific memory or task-anchor rules into Cliq core.

Potential hooks:

```ts
export type CompactHooks = {
  beforeCompact?: (input: CompactInput) => Promise<CompactInputPatch | void>;
  summarizeCompact?: (input: CompactInput) => Promise<CompactSummary | void>;
  afterCompact?: (artifact: CompactionArtifact) => Promise<void>;
  buildContext?: (context: ContextBuildInput) => Promise<ContextPatch | void>;
};
```

Expected uses:

- add domain-specific notes before summarization
- replace the default summarizer
- persist compact summaries to external memory
- inject retrieval or project memory during context building

These hooks are deferred. The Phase 3 core should keep its compact artifact simple enough that hooks can enrich it later without schema churn.

## 11. Context Builder

`src/runtime/runner.ts` currently maps `session.records` directly into chat messages. Phase 3 introduces a context builder:

```ts
buildContextMessages(session, instructions)
```

The context builder owns replay selection.

Without active compaction:

```text
HEAD
+ raw session records
```

With active compaction:

```text
HEAD
+ SUMMARY
+ TAIL
```

Runner remains responsible for the turn loop, model call, protocol parsing, tool execution, and runtime event emission. It should not know how compaction ranges are selected.

## 12. Handoff

Handoff exports current task state for another executor. `cliq handoff create` persists a `kind: "handoff"` checkpoint into session metadata when the user does not supply an existing checkpoint. This gives the artifact a stable session/workspace anchor. It does not modify user workspace files, but it can write global Cliq session metadata and a workspace checkpoint artifact.

User commands:

```bash
cliq handoff create                         # creates and persists a handoff checkpoint first
cliq handoff create --checkpoint <checkpoint-id>  # reuses an existing checkpoint
cliq handoff help
```

If no checkpoint is supplied, Cliq creates and persists a handoff checkpoint before writing the handoff artifact. If `--checkpoint <checkpoint-id>` is supplied, Cliq reuses that checkpoint and does not create another one.

Handoff summary source:

- If the session has an active compaction, handoff uses that `summaryMarkdown` plus the raw tail and current checkpoint metadata as summarizer input.
- If the session has no active compaction, handoff runs a handoff-only summarizer over the current context/raw records.
- A handoff-only summary is persisted only inside the handoff artifact. It does not create a `CompactionArtifact` and does not change the active compaction.
- If summarization fails, `cliq handoff create` fails before writing a partial handoff unless an explicit future `--raw` mode is added.

Output:

```text
handoffs/<handoffId>/handoff.json
handoffs/<handoffId>/HANDOFF.md
```

Content includes:

- session id
- parent session id, when present
- checkpoint id
- active compaction id, when present
- provider/model identity
- workspace checkpoint id, when present
- changed paths and snapshot warnings
- current objective
- constraints and decisions
- files of interest
- tests run or not run
- risks and open questions
- recommended next prompt

Handoff can support cross-provider continuation, but this release only exports the artifact. It does not implement cross-provider orchestration.

## 13. Module Boundaries

Planned modules:

```text
src/session/store.ts
src/session/checkpoints.ts
src/session/fork.ts
src/session/compaction.ts
src/workspace/snapshots.ts
src/runtime/context.ts
src/handoff/export.ts
src/cli.ts
```

Responsibilities:

- `session/store`: active session registry, migration, load/save
- `session/checkpoints`: session checkpoint creation and lookup
- `session/fork`: session prefix copy and restore/fork semantics
- `session/compaction`: compaction artifact lifecycle
- `workspace/snapshots`: Git-backed workspace snapshot and restore
- `runtime/context`: model-visible message construction
- `handoff/export`: JSON and Markdown handoff artifacts
- `cli`: command parsing and thin orchestration

## 14. Migration

Existing `.cliq/session.json` is migrated into the new global session store format.

Migration requirements:

- preserve existing records
- preserve structured model identity
- assign a session id if missing
- set active session id
- record migration source path and timestamp in the global workspace state
- avoid changing workspace files unrelated to Cliq metadata
- keep workspace-local `.cliq/config.json`, skills, and extensions in place
- leave the old `.cliq/session.json` in place after successful import, but stop updating it

After migration, `.cliq/session.json` is no longer canonical.

## 15. Test Matrix

Required tests:

- `CLIQ_HOME` default resolution uses `~/.cliq`
- `CLIQ_HOME` env override changes the global state root
- workspace identity uses `realpath(cwd)` and records optional Git root
- `history` reads the active session for the current workspace id
- `reset` creates a new active session without deleting old global sessions
- old session migration succeeds
- checkpoint creation works inside Git repos
- checkpoint creation works outside Git repos as session-only
- automatic checkpoint completes before model/tool execution starts
- Git snapshot creation does not pollute user staging state
- file restore handles modified files
- file restore handles deleted files
- file restore handles files created after checkpoint
- file restore preserves preexisting untracked files
- file restore does not modify the Git index
- file restore warns or requires `--yes` when staged changes exist
- file restore fails cleanly when the ghost commit has been pruned or is missing
- file restore records warnings for skipped content
- session restore creates a new session prefix
- fork creates a child session from a checkpoint
- fork with file restore requires confirmation or `--yes`
- compact preserves raw records
- compact creates exactly one active compaction
- new compact supersedes the previous active compaction
- compact calculates `firstKeptRecordId` from `coveredRange.endIndexExclusive`
- compact rejects ranges that would leave no raw tail
- context builder uses compact summary plus recent records
- handoff exports JSON and Markdown artifacts
- handoff reuses active compaction when present
- handoff creates a handoff-only summary when no active compaction exists
- CLI commands parse and validate required arguments

## 16. External Design References

Phase 3 uses a mixed reference model:

- Checkpoint follows the Codex-style Git-backed snapshot direction.
- File restore follows current Codex main's safer worktree-only restore direction, where the Git index is preserved.
- Fork follows the Pi-style session branch direction, scoped to checkpoint-based session forking in v1.
- Compact follows the Pi-style structured session artifact direction more than Codex's internal runtime compression.
- Handoff follows the Pi-style handoff artifact direction.
- Claude Code informs restore UX language by separating conversation/session recovery from file recovery.

Source observations:

- Codex ghost snapshot creation uses a temporary Git index and detached `commit-tree` object, keeping snapshots out of user branch history and out of the user index.
- Codex current main restore uses `git restore --source <commit> --worktree -- <scope>` and explicitly avoids `--staged` to preserve the user's staged changes.
- Codex gates mutating tool execution on snapshot readiness through its ghost snapshot task readiness token.
- Pi core stores compaction as a session entry with `summary` and `firstKeptEntryId`; its context builder emits the latest compaction summary plus kept raw messages.
- Pi's Git checkpoint example is an extension that runs `git stash create` at turn start and `git stash apply` before fork restore; it is not a built-in session-store contract.

## 17. Deferred Decisions

- Decide if the default global directory should migrate from `~/.cliq` to an XDG/platform state path.
- Consider protected refs such as `refs/cliq/checkpoints/*` for long-lived workspace snapshots.
- Add an explicit file restore mode that also restores staged/index state only if a real user workflow requires it.
- Introduce `cliq compact create --from <checkpoint-id>` after the lineage model is clearer.
- Evaluate worktree-backed forks after session-only forks prove useful.
- Expose compact/handoff hooks in Phase 4+ headless/RPC surfaces when plugin use cases are concrete.
