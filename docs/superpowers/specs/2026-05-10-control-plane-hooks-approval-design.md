# Control Plane v1: Hooks, Approval, and TX Review — Design Spec

**Status:** draft for review
**Date:** 2026-05-10
**Target Release:** `v0.9.0` as one umbrella release, delivered across multiple focused PRs if needed
**Parent context:** v0.8 transactional workspace runtime is implemented, but TX review polish, reusable hooks, and payload-aware approvals are not yet complete.
**External references:** OpenAI Codex CLI approval/sandbox model and Codex hooks:
- https://developers.openai.com/codex/cli/features
- https://developers.openai.com/codex/agent-approvals-security
- https://developers.openai.com/codex/hooks

## 1. Problem Statement

Cliq currently has three related but incomplete mechanisms:

1. **Policy modes** (`auto`, `confirm-write`, `read-only`, `confirm-bash`, `confirm-all`)
   - Implemented as tool-category authorization over `ToolAccess = read | write | exec`.
   - Useful, but too coarse. The approval prompt knows the tool name and access class, not the specific command, path, diff, network intent, or risk.

2. **Runtime hooks**
   - Implemented as in-process extension callbacks (`beforeTurn`, `beforeTool`, `afterTool`, etc.).
   - Useful internally, but not a product-grade hooks system. Hooks cannot make allow/deny decisions, do not have matcher config, do not have a command protocol, and failures are swallowed with `console.error`.

3. **TX review gate**
   - Implemented at the runtime/coordinator level: staged overlay -> finalize -> validate -> approve -> apply.
   - Architecturally correct, but the user-facing review surface is incomplete. Users can validate/approve/apply, but `tx diff`, `tx show`, `tx validators`, and rich interactive apply review are still missing.

The risk is that future features will keep re-implementing local policy checks, validators, logging, command review, and post-tool inspection as one-off code paths. Codex CLI avoids part of this by separating:

- **sandbox / execution constraints**: what the agent can physically do;
- **approval policy**: when the user or reviewer must approve;
- **hooks**: configurable event interception and automation around prompts, tools, permission requests, and stop conditions.

Cliq should adopt the same separation, but not copy Codex CLI blindly. Cliq's TX runtime is stronger than a post-tool hook for file edits because it can validate and reject a staged diff before touching the real workspace. Hooks should complement TX, not replace it.

## 2. Goals

1. **Make approvals payload-aware.**
   - Approval decisions should know what is being requested: tool name, access kind, command, path, action payload, tx state, and generated reason.
   - The old policy modes remain as compatibility presets.

2. **Introduce a reusable hook protocol.**
   - Workspace-configured hooks can run around important lifecycle events in v1. User-global hooks are deferred.
   - Hooks can provide additional context, block selected events, or decide permission requests where appropriate.
   - Hooks use a stable JSON stdin/stdout protocol so common logic does not need to be compiled into Cliq.

3. **Finish the TX review surface before deeper automation.**
   - TX must become inspectable and usable before adding more policy complexity.
   - The user should see enough evidence before apply: diff summary, validator results, blocking failures, advisory findings, and bash side effects.

4. **Keep enforcement in core.**
   - Hooks are guardrails and automation. Core policy, path safety, TX validators, and future sandbox boundaries remain core runtime responsibilities.

5. **Create a migration path toward Codex-like approval modes.**
   - Avoid forcing a full OS sandbox implementation in this phase.
   - Design the types so a future sandbox layer can plug in without reworking the approval API again.

## 3. Non-goals

This phase does **not** implement:

1. OS-level sandboxing (`seatbelt`, `bwrap`, containers, or equivalent).
2. Full Codex CLI parity.
3. Enterprise managed hooks.
4. Marketplace/package installation for hooks.
5. Arbitrary model-callable hook registration.
6. A new TUI.
7. Replacing TX validators with hooks.
8. Network isolation.
9. Automatic model-based approval reviewer.

These are deliberately excluded because the immediate problem is control-plane architecture and TX usability, not complete environment isolation.

## 4. Current State Evidence

### 4.1 Policy Engine

Current code:

- `src/policy/types.ts`
  - `PolicyMode = 'auto' | 'confirm-write' | 'read-only' | 'confirm-bash' | 'confirm-all'`
  - `ToolAccess = 'read' | 'write' | 'exec'`
- `src/policy/engine.ts`
  - authorizes by `definition.name` and `definition.access`.
  - asks generic prompts such as `Allow edit (write)?`.

This means current approval is **tool-category approval**, not **payload-aware approval**.

### 4.2 Tool Context

Current code:

- `src/tools/types.ts`
  - tool definitions have `name`, `access`, `supports`, `execute`.
  - `ToolContext` can carry `writer` and optional `tx`.

This is a good insertion point: approval requests can be built before `execute`, and TX state can be included when present.

### 4.3 Runtime Hooks

Current code:

- `src/runtime/hooks.ts`
  - supports lifecycle callbacks.
  - hook exceptions are caught and printed.
  - return values are ignored.

This makes hooks safe for logging and soft side effects, but unsuitable for permission decisions or required validation.

### 4.4 TX Runner

Current code:

- `src/runtime/tx-runner.ts`
  - finalizes, validates, optionally prompts `confirmApply`, approves, applies.
- `src/cli.ts`
  - interactive apply prompt is `Apply transaction? [y/N]`.
  - headless event renderer does not render TX events to the human CLI surface.

This means TX is structurally strong but not yet reviewable enough as a human-facing approval gate.

## 5. Design Principles

### 5.1 Separate Approval, Hooks, Validators, and Sandbox

These are different layers:

| Layer | Question | Owner |
|---|---|---|
| Approval | Should this requested action proceed now? | policy engine + user/hook/reviewer |
| Hook | Should external automation add context, block, or review this event? | hook runner |
| Validator | Can this staged TX safely land? | TX core |
| Sandbox | Can this process physically access that resource? | future execution layer |

Do not collapse them.

### 5.2 Hooks Are Not the Trusted Enforcement Boundary

Hooks can block or add context, but core must still enforce:

- read-only mode,
- path normalization,
- workspace path containment,
- TX validator blocking failures,
- apply state transitions,
- future sandbox constraints.

Reason: hooks can be absent, buggy, slow, or misconfigured. Core safety must not depend on a project hook being correct.

### 5.3 TX Remains the File-Change Review Gate

For file edits, the strongest review boundary is not `beforeTool(edit)`. It is:

1. stage edits in overlay,
2. finalize diff,
3. validate staged workspace,
4. present review evidence,
5. approve/apply or abort.

`beforeTool(edit)` can reject obviously forbidden paths or patterns early, but it cannot replace TX review.

### 5.4 Compatibility Presets Stay

Existing users should keep using:

- `--policy auto`
- `--policy read-only`
- `--policy confirm-write`
- `--policy confirm-bash`
- `--policy confirm-all`

Internally, these become presets over the new control-plane model.

## 6. Proposed Scope

### Phase 5a: TX Review Surface

Finish the currently missing TX commands and interactive render path.

In scope:

1. `cliq tx diff [<txId>]`
2. `cliq tx show [<txId>] [--json]`
3. `cliq tx validators [<txId>] [--json]`
4. Human renderer for TX runtime events in one-shot CLI output.
5. Interactive apply prompt displays:
   - tx id,
   - files changed,
   - insertions/deletions if available,
   - validator pass/fail/error summary,
   - blocking failures,
   - advisory failures,
   - bash side-effect summary,
   - artifact directory.

Out of scope:

- full-screen diff UI,
- interactive file-by-file partial apply,
- automatic model reviewer,
- new TUI.

### Phase 5b: Approval Request Model

Replace direct `policy.authorize(definition)` with a richer request object.

```ts
export type ApprovalSubject =
  | {
      kind: 'tool';
      toolName: string;
      access: 'read' | 'write' | 'exec';
      action: ModelAction;
      display: {
        title: string;
        detail?: string;
        path?: string;
        command?: string;
      };
      tx?: {
        enabled: boolean;
        txId?: string;
        mode?: 'edit';
      };
    }
  | {
      kind: 'tx-apply';
      txId: string;
      diffSummary: DiffSummary;
      validators: ValidatorResultSummary[];
      blockingFailures: string[];
      artifactRef: string;
    }
  | {
      kind: 'permission-request';
      source: 'hook' | 'tool' | 'runtime';
      toolName?: string;
      reason: string;
      requestedCapabilities: string[];
    };

export type ApprovalDecision =
  | { behavior: 'allow'; reason?: string; decidedBy: 'policy' | 'user' | 'hook' }
  | { behavior: 'deny'; reason: string; decidedBy: 'policy' | 'user' | 'hook' }
  | { behavior: 'ask'; prompt: string; decidedBy: 'policy' | 'hook' };
```

v1 runtime construction scope:

- The v1 runtime constructs `kind: 'tool'` and `kind: 'tx-apply'` subjects.
- `kind: 'permission-request'` is reserved for future tool-initiated capability escalation, such as a tool asking to escalate network or filesystem capability during execution.
- `PermissionRequest` hooks in v1 receive the original subject that caused `ApprovalEngine.decide(subject)` to return `ask`; they do not require a separate `kind: 'permission-request'` subject in this release.

Policy engine becomes:

```ts
export type ApprovalEngine = {
  mode: PolicyMode;
  decide(subject: ApprovalSubject): Promise<ApprovalDecision>;
};
```

Compatibility mapping:

| Existing mode | New behavior |
|---|---|
| `auto` | allow normal registered tools unless another core rule blocks |
| `read-only` | allow read tools; deny write/exec unless an explicit higher-level command path asks user |
| `confirm-write` | ask for write actions, using payload-aware prompt |
| `confirm-bash` | ask for exec actions, using command-aware prompt |
| `confirm-all` | ask for every tool action |

Important behavior changes:

- Approval prompts include payload details.
- `read-only` should block write and exec before hooks can allow them.
- Hooks may deny allowed actions, but cannot override hard core denies.

### Phase 5c: Hook Protocol v1

Add a command-hook runner with JSON stdin/stdout.

Supported hook events:

```ts
export type HookEventName =
  | 'SessionStart'
  | 'UserPromptSubmit'
  | 'PreToolUse'
  | 'PostToolUse'
  | 'PermissionRequest'
  | 'TxFinalized'
  | 'TxValidated'
  | 'TxApplyReview'
  | 'Stop';
```

Rationale:

- `PreToolUse` handles early guardrails.
- `PostToolUse` handles logging, generated-file reminders, and feedback to the model.
- `PermissionRequest` lets configured hooks auto-allow or auto-deny selected approval prompts.
- TX events let hooks observe or block review/apply flows without pretending to replace validators.
- `SessionStart`, `UserPromptSubmit`, and `Stop` are emitted in v1; a configured hook for these events must not be accepted silently without a runtime emission path.

Hook config shape in `.cliq/config.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "bash|edit",
        "hooks": [
          {
            "type": "command",
            "command": "node .cliq/hooks/pre-tool-use.js",
            "timeoutMs": 30000,
            "statusMessage": "Checking tool request"
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "bash",
        "hooks": [
          {
            "type": "command",
            "command": "node .cliq/hooks/permission-request.js",
            "timeoutMs": 30000,
            "statusMessage": "Reviewing approval request"
          }
        ]
      }
    ]
  }
}
```

Hook input:

```ts
export type HookInput = {
  schemaVersion: 1;
  hookEventName: HookEventName;
  sessionId: string;
  cwd: string;
  turnId?: string;
  model?: string;
  toolName?: string;
  toolUseId?: string;
  matcherAliases?: string[];
  action?: ModelAction;
  toolResult?: ToolResult;
  approvalSubject?: ApprovalSubject;
  tx?: {
    txId: string;
    state?: string;
    diffSummary?: DiffSummary;
    validators?: ValidatorResultSummary[];
    blockingFailures?: string[];
    artifactRef?: string;
  };
};
```

Hook output:

```ts
export type HookOutput = {
  continue?: boolean;
  decision?: 'allow' | 'deny';
  reason?: string;
  systemMessage?: string;
  additionalContext?: string;
  permissionDecision?: {
    behavior: 'allow' | 'deny';
    message?: string;
  };
};
```

Exit code behavior:

| Exit code | Meaning |
|---|---|
| `0` | Parse stdout as optional JSON output; no output means continue |
| `2` | Deny with stderr as reason |
| other non-zero | Hook infrastructure error |

Default failure behavior:

| Event | Hook error default |
|---|---|
| `SessionStart` | fail closed for configured required hooks; otherwise warn |
| `UserPromptSubmit` | warn and continue |
| `PreToolUse` | warn and continue unless hook is marked `required` |
| `PermissionRequest` | no decision; fall back to normal approval flow |
| `PostToolUse` | warn and continue |
| `TxApplyReview` | fail closed if marked `required`; otherwise warn and continue |
| `Stop` | warn and stop normally |

This avoids making every logging hook a reliability risk while still allowing projects to mark selected policy hooks as required.

### Phase 5d: Config and Loading

Extend workspace config:

```ts
export type HookCommandConfig = {
  type: 'command';
  command: string;
  timeoutMs?: number;
  statusMessage?: string;
  required?: boolean;
};

export type HookMatcherConfig = {
  matcher?: string;
  hooks: HookCommandConfig[];
};

export type HooksConfig = Partial<Record<HookEventName, HookMatcherConfig[]>>;

export type WorkspaceConfig = {
  instructionFiles: string[];
  extensions: string[];
  defaultSkills: string[];
  hooks?: HooksConfig;
  transactions?: TxConfig;
};
```

Configuration precedence for v1:

1. workspace `.cliq/config.json`,
2. existing in-process extension hooks,
3. CLI internal hooks.

Deferred:

- user-global hooks,
- managed enterprise hooks,
- hook installation/distribution,
- remote hooks.

Reason: workspace hooks are enough to stop duplicated project logic. User-global and managed hooks add real product surface area and should be designed after v1 proves stable.

### Phase 5e: Bash Policy Fix

Current issue:

- `enforceBashPolicy` accepts `confirm?: () => Promise<boolean>`.
- `bashTool` calls it without passing a confirm function.
- Therefore `bashPolicy=confirm` under TX denies because no prompt callback is available.

Fix:

```ts
export type ToolContextTxFacade = {
  mode: 'edit';
  bashPolicy: TxBashPolicy;
  txId: string;
  headless: boolean;
  confirmBash?: (command: string) => Promise<boolean>;
  recordBashEffect(eff: BashEffect): Promise<void>;
};
```

Runner passes:

- interactive CLI: prompt callback,
- headless: no callback, so confirm still promotes to deny.

This preserves the current headless safety rule but makes interactive TX bash confirmation actually usable.

## 7. Detailed Flow

### 7.1 Tool Execution Flow

Current:

```text
model action
  -> tool registry selects definition
  -> policy.authorize(definition)
  -> beforeTool hooks
  -> definition.execute(...)
  -> afterTool hooks
```

Proposed:

```text
model action
  -> tool registry selects definition
  -> build ApprovalSubject(kind='tool')
  -> run PreToolUse hooks
  -> approvalEngine.decide(subject)
  -> if decision=ask: run PermissionRequest hooks
  -> if still ask: prompt user if available
  -> if allow: definition.execute(...)
  -> run PostToolUse hooks
```

Ordering rule:

- Core deny wins before hooks can allow.
- Hook deny wins over policy allow.
- Hook allow can satisfy an ask, but not override a core deny.

### 7.2 TX Apply Flow

Current:

```text
finalizeTx
validateTx
if interactive: prompt "Apply transaction? [y/N]"
approveTx
applyTx
```

Proposed:

```text
finalizeTx
render diff summary
validateTx
render validator summary
build ApprovalSubject(kind='tx-apply')
run TxApplyReview hooks
approvalEngine.decide(subject)
if ask: prompt user with evidence
approveTx
applyTx
```

TX apply is not a normal tool action. It has its own subject kind because the evidence is different: diff + validators + bash side effects + artifact ref.

### 7.3 Hook Decision Flow for Permission Requests

```text
approvalEngine returns ask
  -> build HookInput(PermissionRequest)
  -> matching hooks run in configured order
  -> any deny wins
  -> first allow can approve
  -> no decision falls back to user prompt
```

This mirrors the useful part of Codex hooks without adopting every Codex-specific field.

## 8. UX Requirements

### 8.1 Tool Approval Prompt

For `confirm-bash`:

```text
Allow bash command?

$ npm test

Policy: confirm-bash
TX: tx_... (records bash side effects)

[y/N]
```

For `confirm-write` outside TX:

```text
Allow edit?

Path: src/foo.ts
Operation: replace exact text span
Policy: confirm-write

[y/N]
```

For `confirm-write` inside TX:

```text
Allow staged edit?

Path: src/foo.ts
Operation: replace exact text span
TX: tx_...
Note: edit will stage in overlay; real workspace changes only after tx apply.

[y/N]
```

### 8.2 TX Apply Prompt

```text
Apply transaction tx_...?

Files changed: 3
Validators:
  PASS  builtin:diff-sanity
  PASS  builtin:index-clean
  WARN  builtin:size-limit: src/big.ts exceeds configured advisory limit
  PASS  tsc

Bash side effects recorded: 1 command, 2 paths changed outside overlay
Artifacts: ~/.cliq/tx/tx_.../

[y/N]
```

If blocking failures exist:

```text
Transaction tx_... has blocking validator failures.

FAIL  tsc: TypeScript errors

Apply is blocked. Use:
  cliq tx approve tx_... --override tsc --reason "..."
```

No interactive prompt should imply that blocking failures can be ignored casually.

Validator naming rule:

- Built-in validators use their registered names, for example `builtin:diff-sanity`.
- Shell validators use the configured `name` exactly as provided, for example `tsc`.
- Override names must match the validator result name exactly; Cliq does not add an automatic `shell:` prefix.

## 9. Security and Trust Model

### 9.1 What This Improves

- Fewer one-off policy implementations.
- Reusable repository-specific guardrails.
- Better evidence before TX apply.
- More explicit approval records.
- Clearer headless behavior.

### 9.2 What This Does Not Solve

- A malicious repo can still write a hook that behaves badly if the user explicitly enables it.
- Without OS sandboxing, allowed bash commands still run with user privileges.
- Post-tool hooks cannot undo side effects.
- Hook-based allow/deny is not a substitute for path safety or TX validators.

### 9.3 Required Safety Rules

1. Hooks must be disabled by default unless explicitly configured.
2. Hook commands must run with timeout.
3. Hook stdin and stdout/stderr must be size-limited.
4. Oversized hook input must be truncated as valid JSON with an explicit `_truncated: true` marker. In v1, only fields present on `HookInput` are truncation targets: `toolResult.content`, `action`, `approvalSubject`, `tx.diffSummary`, and `tx.validators`.
5. Hook command path resolution must stay inside workspace unless explicitly absolute.
6. Hook infrastructure errors must be visible in events.
7. Core deny decisions cannot be overridden by hooks.
8. TX validators cannot be registered by the model at runtime.

## 10. Implementation Slices

This is not the final implementation plan. It is the recommended PR slicing after review.

All slices belong to the same `v0.9.0` release target. Splitting them into several PRs is an integration and review strategy, not a version boundary. A `v0.9.0` release candidate should not be cut until the accepted subset of this control-plane scope is complete.

### Slice 1: TX Review Polish

Files likely touched:

- `src/cli.ts`
- `src/workspace/transactions/store.ts`
- `src/workspace/transactions/types.ts`
- `src/headless/artifacts.ts`
- `src/runtime/tx-runner.ts`
- tests under `src/**/*.test.ts`

Deliverables:

- `cliq tx diff`
- `cliq tx show`
- `cliq tx validators`
- TX event rendering in CLI
- richer interactive apply prompt

Why first:

- TX is already partially shipped in v0.8.
- Without this, users cannot confidently use TX.
- This has the smallest architectural uncertainty.

### Slice 2: ApprovalSubject and Payload-aware Prompts

Files likely touched:

- `src/policy/types.ts`
- `src/policy/engine.ts`
- `src/runtime/runner.ts`
- `src/cli.ts`
- `src/tools/types.ts`
- tests for policy and runner

Deliverables:

- new `ApprovalSubject` / `ApprovalDecision`,
- compatibility mapping for existing policy modes,
- command/path-aware prompts,
- no hook protocol yet.

Why second:

- It creates the decision abstraction that hooks will plug into.
- It avoids designing hooks around the old coarse API.

### Slice 3: Command Hook Runner

Files likely touched:

- create `src/hooks/types.ts`
- create `src/hooks/runner.ts`
- create `src/hooks/config.ts`
- modify `src/workspace/config.ts`
- modify `src/runtime/assembly.ts`
- tests for config parsing, matcher behavior, command execution, timeout, output parsing

Deliverables:

- hook config schema,
- command execution with JSON stdin/stdout,
- matcher support,
- timeout and size caps,
- event integration for `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`.

Why third:

- The hook runner can be tested independently before it participates in approval.

### Slice 4: PermissionRequest Hook Integration

Files likely touched:

- `src/policy/engine.ts`
- `src/runtime/runner.ts`
- `src/hooks/runner.ts`
- `src/cli.ts`
- tests for allow/deny/no-decision behavior

Deliverables:

- hooks can satisfy approval prompts,
- any deny wins,
- no hook decision falls back to normal user prompt,
- core denies cannot be overridden.

### Slice 5: TX Hook Events and Bash Confirm Fix

Files likely touched:

- `src/runtime/tx-runner.ts`
- `src/tools/bash.ts`
- `src/tools/types.ts`
- `src/runtime/bash-policy.ts`
- tests for `bashPolicy=confirm`
- tests for `TxFinalized`, `TxValidated`, `TxApplyReview`

Deliverables:

- `bashPolicy=confirm` works interactively,
- TX hook events are emitted to hook runner,
- required TX review hooks can fail closed.

## 11. Review Questions

These are the questions we should answer before implementation:

1. Should hooks live under top-level `hooks` in `.cliq/config.json`, or under `extensions`?
   - Recommendation: top-level `hooks`, because command hooks are config, not JS extension modules.

2. Should hook errors fail open or fail closed?
   - Recommendation: default fail open with warning, except `required: true` hooks and TX apply review hooks marked required.

3. Should `PermissionRequest` hooks be able to auto-allow?
   - Recommendation: yes, but only for approval prompts generated by non-hard-deny policy. They cannot override `read-only` hard denial.

4. Should TX validators become hooks?
   - Recommendation: no. Validators remain core TX components. Shell validators already provide project-defined checks at the correct staged-workspace boundary.

5. Should we build sandbox now?
   - Recommendation: no. Design for it, but do not implement it in this phase.

6. Should `confirm-write` inside TX ask before each edit?
   - Recommendation: yes for compatibility, but the better user experience is `--tx edit --policy auto` plus TX apply review at the end. We should document that distinction.

7. Should hook config support user-global hooks in v1?
   - Recommendation: no. Start with workspace hooks. User-global hooks are valuable but widen trust and precedence questions.

## 12. Acceptance Criteria

After this control-plane sequence is implemented, the following should be true:

1. A user can inspect a TX with `tx diff`, `tx show`, and `tx validators` before applying.
2. Interactive TX apply shows useful review evidence, not just `Apply transaction?`.
3. Existing policy modes still work.
4. Tool approval prompts include action-specific details.
5. `bashPolicy=confirm` works in interactive TX mode and denies in headless TX mode.
6. Workspace command hooks can run before/after tools.
7. `PermissionRequest` hooks can allow or deny approval prompts.
8. Hook errors are surfaced as runtime events or warnings.
9. Hooks cannot override core hard-deny policy decisions.
10. TX validators remain independent of hooks and still block apply.

## 13. Recommended Next Step

Review this document first. If accepted, write a `v0.9.0` implementation plan with the slices above, starting with **Slice 1: TX Review Polish**.

Do not start with the full hooks system before TX review polish. TX is already exposed and partially implemented; leaving it hard to inspect makes the current v0.8 surface feel unfinished. The whole control-plane effort can still ship under one `v0.9.0` milestone; the sequencing is about reducing review risk, not splitting product versions.
