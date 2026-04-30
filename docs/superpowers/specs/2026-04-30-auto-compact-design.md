# Auto Compact Design

Date: 2026-04-30

## Summary

Auto Compact extends the Phase 3 compact artifact model with automatic trigger, range selection, summarization, and failure handling.

Cliq uses Pi as the main design reference: keep raw session history durable, append a persistent compaction artifact, and replay `HEAD + active summary + raw tail`. It borrows Codex CLI's trigger placement and Claude Code/OpenCode's anti-thrashing behavior.

The central rule is unchanged from Phase 3:

```text
HEAD: regenerated instructions, tools, policy, workspace config, skills, extensions, runtime context
SUMMARY: active compaction summaryMarkdown
TAIL: raw records from firstKeptRecordId onward
```

Auto Compact must not turn Cliq into a coding-only agent. The default summary prompt can include files and validation sections, but those sections must be generic and optional.

## References

- Pi: persistent `CompactionEntry`, `firstKeptEntryId`, `reserveTokens`, `keepRecentTokens`, previous summary update, split-turn fallback.
- Codex CLI: pre-turn, mid-turn, model-downshift, and overflow-oriented auto-compaction trigger placement.
- Claude Code: automatic context management near the context limit, `/compact`, compact hooks, and anti-thrashing guidance.
- OpenCode: compaction config, reserved output budget, recent tail turns/tokens, compaction task, overflow recovery, and optional pruning.

The design follows Pi/OpenCode/Claude-style persisted compaction artifacts rather than Codex's live replacement-history model, because Cliq Phase 3 already treats compactions as session workflow assets.

## Goals

- Automatically compact long sessions before model requests exceed the usable context window.
- Preserve full raw session records for audit, restore, fork, handoff, and future replay.
- Keep model replay deterministic: at most one active compaction plus raw tail.
- Avoid compact loops that repeatedly summarize without freeing enough context.
- Let future hooks replace or enrich summarization without changing the core artifact contract.
- Keep the feature useful for any local agent, not only coding agents.

## Non-Goals

- Do not delete raw records in v1.
- Do not create a separate permanent task-intent anchor outside compact summaries.
- Do not implement Codex's remote compact endpoint.
- Do not implement OpenCode-style tool-output pruning in v1. It remains a later optimization.
- Do not require provider-native tokenizers in v1.
- Do not threshold-trigger auto compaction when Cliq cannot determine a context window and the user has not configured one.

## Configuration

Auto Compact config lives in workspace config first:

```json
{
  "autoCompact": {
    "enabled": "auto",
    "contextWindowTokens": 128000,
    "thresholdRatio": 0.8,
    "reserveTokens": 16000,
    "keepRecentTokens": 20000,
    "minNewTokens": 4000,
    "maxThresholdCompactionsPerTurn": 1,
    "maxOverflowRetriesPerModelCall": 1
  }
}
```

Schema:

```ts
export type AutoCompactEnabled = 'auto' | 'on' | 'off';

export type AutoCompactConfig = {
  enabled?: AutoCompactEnabled;
  contextWindowTokens?: number;
  thresholdRatio?: number;
  reserveTokens?: number;
  keepRecentTokens?: number;
  minNewTokens?: number;
  maxThresholdCompactionsPerTurn?: number;
  maxOverflowRetriesPerModelCall?: number;
};
```

Defaults:

- `enabled`: `"auto"`
- `thresholdRatio`: `0.8`
- `reserveTokens`: `16000`
- `keepRecentTokens`: `20000`
- `minNewTokens`: `4000`
- `maxThresholdCompactionsPerTurn`: `1`
- `maxOverflowRetriesPerModelCall`: `1`

Resolution rules:

- `"off"` disables both threshold auto-compact and overflow recovery auto-compact. Manual `cliq compact create` still works.
- `"on"` enables threshold checks, but requires a context window from config or model metadata. If no context window is available, Cliq errors during runtime assembly with a clear message.
- `"auto"` enables threshold checks only when a context window is known. If no context window is known, Cliq silently skips threshold auto-compact. Overflow recovery also requires an effective context window from config, model metadata, or provider error metadata; otherwise Cliq reports the overflow without attempting compaction.
- `contextWindowTokens` from workspace config is the v1 source of truth when present.
- Future provider model metadata can supply `contextWindowTokens`, but v1 must not depend on a live model catalog.

Validation rules:

- `contextWindowTokens`, when provided, must be a positive integer.
- `thresholdRatio` must be greater than `0` and less than `1`.
- `reserveTokens`, `keepRecentTokens`, and `minNewTokens` must be non-negative integers.
- `maxThresholdCompactionsPerTurn` and `maxOverflowRetriesPerModelCall` must be positive integers.
- When `contextWindowTokens` is known, `reserveTokens` must be less than `contextWindowTokens`.
- The computed `usableLimit` must be positive.
- `keepRecentTokens` must be less than `usableLimit`; otherwise Cliq rejects the config instead of silently keeping an uncompactable tail.
- If `minNewTokens` is larger than the currently compactable span, Cliq skips threshold compaction for that check. This is a runtime decision, not a config error.

Effective threshold:

```text
usableLimit = min(
  contextWindowTokens * thresholdRatio,
  contextWindowTokens - reserveTokens
)
```

Cliq compacts when estimated replay tokens are greater than or equal to `usableLimit`.

## Artifact Shape

The Phase 3 `CompactionArtifact` remains the durable artifact. v1 adds optional metadata so old artifacts remain readable:

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
  auto?: {
    trigger: 'threshold' | 'overflow';
    phase: 'pre-model' | 'mid-loop';
    estimatedTokensBefore: number;
    estimatedTokensAfter?: number;
    usableLimitTokens?: number;
    contextWindowTokens?: number;
    keepRecentTokens: number;
    summaryInputBudgetTokens?: number;
    overflowRetryAttempt?: number;
    previousCompactionId?: string;
  };
};
```

Manual compact artifacts omit `auto`. Missing `auto` means manual or legacy artifact.

## Runtime Placement

Auto Compact belongs between context assembly and model calls. Runner does not know how ranges are selected or summaries are produced; it calls an auto-compaction service.

Proposed runtime flow:

```text
runTurn
  set lifecycle running
  create automatic checkpoint
  append user record
  beforeTurn hooks
  loop:
    maybeAutoCompact(phase=pre-model|mid-loop, trigger=threshold)
    build instructions
    build context
    model.complete(context)
      if context overflow:
        maybeAutoCompact(phase=pre-model|mid-loop, trigger=overflow)
        retry model.complete once
    append assistant record
    if final: afterTurn and return
    execute tool
    append tool record
    afterTool hook
```

This mirrors Codex's useful trigger placement without adopting Codex's replacement-history storage. A tool result can make the next model request too large, so the check must run before every model call in the loop, not only once before the turn.

`phase: "pre-model"` means the first model request after appending the user record. `phase: "mid-loop"` means any later model request in the same turn after assistant and/or tool records have been appended.

## Token Estimation

v1 uses a deterministic approximation:

- Count instruction messages and replay messages after active compaction.
- Estimate text tokens as `ceil(chars / 4)`.
- Add a small per-message overhead constant.
- For tool records, estimate from the stored tool result content after existing truncation.

When providers later expose usage or model tokenizers, Cliq can swap the estimator behind the same interface. The estimator must be deterministic in tests.

```ts
export type TokenEstimate = {
  tokens: number;
  messages: number;
  source: 'approx';
};
```

## Range Selection

Range selection follows the Phase 3 model and Pi's persistent boundary approach.

Inputs:

- current session records
- active compaction, if present
- `keepRecentTokens`
- token estimator

Rules:

- Keep a raw tail whose estimated size is at least `keepRecentTokens`, unless the session is too small.
- Prefer cut points at user-turn boundaries.
- Never split a tool result away from the assistant action that requested it.
- A compaction must leave at least one raw record.
- A new compaction must advance beyond the active compaction's `coveredRange.endIndexExclusive`.
- If fewer than `minNewTokens` of compactable content has accumulated since the previous active compaction, skip threshold auto-compact to avoid churn.

First compaction:

```text
summary input = records[0:endIndexExclusive]
tail = records[endIndexExclusive:]
coveredRange = [0, endIndexExclusive)
firstKeptRecordId = records[endIndexExclusive].id
```

Subsequent compaction:

```text
summary input =
  previous active summaryMarkdown
  + records[previousActive.coveredRange.endIndexExclusive:endIndexExclusive]

tail = records[endIndexExclusive:]
coveredRange = [0, endIndexExclusive)
firstKeptRecordId = records[endIndexExclusive].id
```

Split-turn fallback:

- v1 first tries boundary-only selection.
- If boundary-only selection cannot get under the usable limit because one recent turn is too large, v1 splits inside the oversized turn only at a safe record boundary.
- A safe split point sets `firstKeptRecordId = records[index].id` and must satisfy one of these shapes:
  - `records[index].kind === "user"`.
  - `records[index].kind === "assistant"` and the previous record is not an assistant tool action waiting for its tool result.
  - `records[index - 1].kind === "tool"`, `records[index].kind` is `"user"` or `"assistant"`, and the assistant action that produced that tool result is inside the summarized prefix.
- The first kept record must never be a `tool` record.
- A split point is invalid when `records[index - 1]` is a non-message assistant action whose tool result would fall outside both sides of the split.
- Because v1 records do not have call ids, assistant/tool matching is positional: a non-message assistant action is paired with the immediately following `tool` record before the next `user` or `assistant` record. If records violate this invariant, split-turn fallback fails safely.
- When v1 splits a turn, the summary must include a `Turn Prefix Context` section that captures the original user request and earlier work from the split turn.
- If no safe split exists, auto-compact fails gracefully and reports that the current turn is too large to compact automatically.

## Summary Generation

Auto Compact uses the configured model client in v1. A future `compactModel` can use a cheaper or larger-context model, but separate model routing is not part of v1.

The summarizer input is not the normal replay context. It is a purpose-built prompt:

- Include the previous active summary when updating an existing compaction.
- Include the selected raw records to summarize.
- Do not include regenerated Head messages as content to summarize.
- Include current date/workspace only as metadata if useful for continuity.

Summarizer input budget:

- Summarization has its own budget and must never assume the selected raw range fits into one model call.
- `summaryInputBudgetTokens = contextWindowTokens - reserveTokens - promptOverheadTokens`.
- `promptOverheadTokens` includes the fixed compact prompt, headings, metadata, and output-format instructions as estimated by the same deterministic estimator.
- If `summaryInputBudgetTokens <= 0`, compaction fails before mutating the session.
- If the previous summary plus selected raw records fit, v1 makes one summarizer call.
- If they do not fit, v1 runs iterative chunked summarization from oldest to newest. Each chunk prompt contains the rolling summary plus the next raw-record chunk, and each response replaces the rolling summary using the same headings.
- Only tool record payloads may be truncated for the summarizer input. The serialized input must keep the tool name, status, exit code or error, and an explicit truncation marker. Raw records on disk are never modified.
- User records, assistant messages, assistant actions, and previous summaries are not silently truncated.
- If a single required non-tool record cannot fit, or a tool record cannot fit after tool-payload truncation, compaction fails clearly and leaves the active compaction unchanged.
- Cliq writes the new compaction artifact only after the final summarizer chunk succeeds.

Default summary headings:

```md
## Objective

## Current State

## Decisions And Constraints

## Relevant Artifacts

## Validation

## Open Questions And Risks

## Next Steps
```

Prompt requirements:

- Preserve user goals, explicit constraints, requirements, and preferences.
- Preserve exact paths, commands, identifiers, and error messages when present.
- Mark absent sections as `(none)` rather than inventing detail.
- Do not mention that context was compacted.
- Do not summarize system prompt, tool registry, policy, workspace config, skills, or extension registry.
- Use the same language as the session when obvious.

## Failure Semantics

Threshold compaction:

- If summarization fails before a model call, emit a warning and continue with the original context once.
- If the original context then overflows, escalate to overflow handling.
- A failed threshold compaction suppresses additional threshold auto-compaction attempts for the rest of the current turn.

Overflow compaction:

- If provider error is recognized as context overflow, run one overflow compaction and retry the model call once.
- If overflow compaction fails, stop the turn with a clear error.
- If retry still overflows, stop and suggest starting a new session, lowering input size, or using a larger-context model.

Anti-thrashing:

- `maxThresholdCompactionsPerTurn` defaults to `1` and limits only threshold-triggered auto compactions in the current user turn.
- `maxOverflowRetriesPerModelCall` defaults to `1` and limits only overflow recovery attempts for the current `model.complete` call.
- Overflow recovery does not consume the threshold compaction budget. A successful overflow compaction suppresses any additional threshold compaction for the same model call because the context has already been rebuilt.
- Skip threshold compaction when compactable new content is below `minNewTokens`.
- After any auto compaction, re-estimate context. If still above limit and no safe range can advance, do not loop.
- Never compact twice for the same overflow error.
- Do not trigger from stale usage or stale estimates that predate the active compaction.

Cancellation:

- v1 CLI does not need an interactive cancel path.
- The auto-compaction service accepts an optional abort signal internally so future TUI/RPC callers can cancel without redesigning the service boundary.

## Events

Runtime events are observable but minimal:

```ts
type AutoCompactRuntimeEvent =
  | { type: 'compact-start'; trigger: 'threshold' | 'overflow'; phase: 'pre-model' | 'mid-loop' }
  | { type: 'compact-end'; artifactId: string; estimatedTokensBefore: number; estimatedTokensAfter: number }
  | { type: 'compact-skip'; reason: 'disabled' | 'unknown-context-window' | 'too-small' | 'min-new-tokens' | 'max-threshold-per-turn' | 'max-overflow-retries' }
  | { type: 'compact-error'; trigger: 'threshold' | 'overflow'; message: string };
```

The CLI can initially render only warnings/errors. Full event rendering can wait for TUI/RPC.

## Extension Hooks

Phase 3 deferred hooks. Auto Compact keeps the same deferral, but its internal service exposes clear boundaries:

```ts
export type AutoCompactService = {
  maybeCompact(input: AutoCompactInput): Promise<AutoCompactResult>;
};
```

Future hook points:

- `beforeAutoCompact`: inspect selected range or cancel.
- `summarizeCompact`: replace the default summarizer.
- `afterAutoCompact`: persist external memory or emit custom events.

The v1 implementation does not expose public hook APIs.

## Module Plan

Expected code boundaries:

- `src/workspace/config.ts`: parse and validate `autoCompact`.
- `src/session/auto-compaction.ts`: policy resolution, token estimation, range selection, summary prompt construction, and `maybeAutoCompact`.
- `src/session/compaction.ts`: accept optional auto metadata while preserving existing manual behavior.
- `src/runtime/runner.ts`: invoke `maybeAutoCompact` before model calls and once for overflow recovery.
- `src/runtime/context.ts`: continue consuming exactly one active compaction.
- `src/model/errors.ts`: classify provider errors as context overflow using provider-specific status/messages where available and conservative message matching otherwise.

Runner must remain orchestration-only. Range selection and summarization logic belongs in `session/auto-compaction.ts`.

## Testing

Unit tests:

- Config parsing accepts `enabled: "auto" | "on" | "off"` and rejects invalid numeric values.
- Config parsing rejects invalid numeric relationships such as `reserveTokens >= contextWindowTokens`, `thresholdRatio <= 0`, `thresholdRatio >= 1`, and `keepRecentTokens >= usableLimit`.
- `"auto"` skips threshold checks when context window is unknown.
- `"on"` errors clearly when context window is unknown.
- Token estimator is deterministic.
- Range selection keeps a raw tail, advances over previous active compaction, and avoids splitting tool results from their action context.
- Split-turn fallback only cuts at formal safe record boundaries, rejects malformed assistant/tool sequences, and adds turn-prefix context when one recent turn is too large for boundary-only compaction.
- Summary generation uses one call when the selected input fits the summarizer budget.
- Summary generation chunks oldest-to-newest when selected input exceeds the summarizer budget.
- Summary generation marks truncated oversized tool records and fails without mutating the active compaction when no summarizer chunk can fit.
- `minNewTokens` prevents immediate repeated compaction.
- Existing active compaction is superseded only after new artifact creation succeeds.

Runner tests:

- Auto compact runs before model call when threshold is exceeded.
- Tool result can trigger compaction before the next loop model call.
- Threshold compaction failure warns and continues once.
- Overflow error triggers one compact-and-retry.
- Overflow retry failure stops cleanly.
- `maxThresholdCompactionsPerTurn` prevents repeated threshold compaction loops.
- `maxOverflowRetriesPerModelCall` prevents repeated overflow retries for the same model call.

Regression tests:

- Manual compact commands still work.
- Handoff reuses active auto compaction like any other active compaction.
- Session restore/fork behavior remains based on raw records and checkpoints, not compacted replay.

## Migration

Existing sessions without `auto` metadata remain valid.

Existing workspace config without `autoCompact` resolves to:

```json
{
  "enabled": "auto"
}
```

Because `"auto"` requires a known context window for threshold checks, existing users are not surprised by threshold-triggered automatic LLM calls unless they configure `contextWindowTokens` or the selected model has known metadata. Overflow recovery can still run only when Cliq can derive an effective context window from config, model metadata, or provider error metadata.

## Deferred Decisions

- Add provider/model catalog metadata for context windows.
- Add a separate `compactModel` configuration.
- Add OpenCode-style tool-output pruning before summarization.
- Expose compact hooks publicly through extensions/RPC.
- Add interactive cancellation in TUI/RPC.
- Add UI controls for compaction history and summary inspection.
- Add provider-native tokenizers for more accurate estimates.

## Acceptance Criteria

- Auto Compact is enabled by default in `"auto"` mode.
- Sessions with unknown context windows do not auto-compact by threshold unless explicitly configured.
- Sessions with configured context windows compact before model calls once replay estimate crosses the usable limit.
- Auto compact artifacts are normal `CompactionArtifact`s and participate in context replay, handoff, and audit.
- Raw records remain durable.
- The runner does not contain range-selection or summary-prompt logic.
- A failed threshold compaction does not silently corrupt session state.
- Overflow recovery attempts at most one compact-and-retry per model call.
- Threshold auto compact obeys `maxThresholdCompactionsPerTurn`; overflow recovery obeys `maxOverflowRetriesPerModelCall` and is not blocked by threshold count.
