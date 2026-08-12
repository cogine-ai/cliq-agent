# Typed Runtime And Provider Capabilities

## Backlog Ready Spec

### Verdict

READY WITH RISKS

The runtime protocol decision is closed: provider-native tool calls first, schema/grammar-constrained Agent IR only where the provider guarantees shape, otherwise text-only. The work is implementable now. The remaining risks are inaccurate provider/model capability metadata and provider-specific streaming edge cases; both fail closed and have explicit conformance tests below.

### Source

Brief / issue / roadmap item:

- Work package 2 of the [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md).
- Product promise: **Delegate. Detach. Return to verified work.**

Related issues:

- No existing issue replaces the free-text action protocol and first-tool-call-only runner behavior across all current providers.
- Permission work in [#62](https://github.com/cogine-ai/cliq-agent/issues/62) remains a separate authorization layer. This spec changes the typed invocation supplied to that layer; it does not weaken or replace permission decisions.
- The repository-level relationship is normative in [issue-supersession-map.md](./issue-supersession-map.md).

Related code:

- [`src/model/types.ts`](../../../src/model/types.ts) already defines typed model requests and native `ModelToolCall`, but also retains `ModelStructuredOutput`, `TextActionFallback`, and `ModelRequestMode='text-action'`.
- [`src/model/prompt.ts`](../../../src/model/prompt.ts) currently constructs structured and free-text fallback instructions and hard-codes provider capability choices.
- [`src/model/providers/prompt-mapping.ts`](../../../src/model/providers/prompt-mapping.ts) maps native/structured/free-text modes and parses structured JSON content.
- [`src/runtime/runner.ts`](../../../src/runtime/runner.ts) consumes only `completion.toolCalls?.[0]`, converts it back to `ModelAction`, and falls back to `parseModelAction(rawContent)`.
- [`src/protocol/model/actions.ts`](../../../src/protocol/model/actions.ts) and [`src/protocol/model/json-repair.ts`](../../../src/protocol/model/json-repair.ts) are the free-text JSON action boundary that the RFC removes.
- [`src/tools/types.ts`](../../../src/tools/types.ts) and [`src/tools/registry.ts`](../../../src/tools/registry.ts) already expose model-visible JSON Schemas, but tool definitions are coupled to the central `ModelAction` union.
- [`src/policy/subjects.ts`](../../../src/policy/subjects.ts) and [`src/tui/format.ts`](../../../src/tui/format.ts) consume `ModelAction` and must receive a typed `ToolInvocation`/validated input instead. [`src/hooks/types.ts`](../../../src/hooks/types.ts) and [`src/runtime/hooks.ts`](../../../src/runtime/hooks.ts) implement repository command hooks; they are removed at Kernel Cut by work package 06, not ported to the typed runtime.
- Provider implementations and tests live under [`src/model/providers/`](../../../src/model/providers/).
- [`src/model/registry.ts`](../../../src/model/registry.ts) defines the current six provider names: `openai`, `anthropic`, `openrouter`, `openai-compatible`, `zhipu`, and `ollama`.
- [`src/model/catalog/`](../../../src/model/catalog/) already provides model metadata/provenance and is the correct home for model capability facts.
- [`src/protocol/runtime/events.ts`](../../../src/protocol/runtime/events.ts) is the existing typed event seam to preserve and extend rather than replacing it with provider-specific branches.

### User Outcome

Cliq no longer depends on a model emitting repairable JSON text to decide whether to execute a tool. A model either uses a negotiated native/constrained protocol or it is text-only. Every tool call returned in one response is visible, validated, authorized, executed in deterministic order, and returned to the model with its original call identity.

Users can switch among the current six providers without provider-specific control semantics leaking into the core runner. Capability mistakes produce a clear capability/protocol error and never silently fall back to interpreting assistant text as executable instructions.

### Problem

The current code has a partially typed transport but an untyped execution core:

- provider capability selection is split between provider names, catalog booleans, and request mapping;
- Zhipu and weak/unknown models enter a free-text `TEXT ACTION FALLBACK MODE`;
- arbitrary assistant text is parsed and repaired as a `ModelAction`;
- the tool registry converts typed arguments back into the same central action envelope;
- the runner stores and executes only the first native call in a response;
- policy, TUI formatting, and Session records are coupled to provider-originated action shapes, while the legacy repository command-hook path is an executable extension boundary that the Kernel Cut removes;
- malformed later calls can be silently ignored because they are never inspected;
- provider request errors can invite semantic fallback instead of producing an explicit capability mismatch.

This is unreliable for long-horizon detached work and makes parser behavior part of the security boundary.

### Scope

In:

- Define provider-neutral streaming and completed-turn Agent IR.
- Define deterministic provider/model capability negotiation and freeze the result into assembly input.
- Freeze the canonical endpoint/pricing union: only exact `LocalZeroCostProvenanceV1` from the signed Kernel-managed Ollama `local_inference` service is credential-free; every standard, custom, or bundled-default billable endpoint is an immutable `EndpointRegistrationV1` target with exact model credential bindings. Price-table authority is `ModelPriceTableV1` plus the fixed `cliq-price-ceil-v1` integer algorithm, never a caller price or executable pricing extension.
- Support all six current provider adapters under one conformance contract.
- Prefer native tool calls; permit constrained Agent IR only when shape enforcement is positively known; otherwise use text-only mode.
- Remove free-text JSON action parsing, repair, extraction, and retry from every autonomous execution path.
- Refactor tool definitions to accept direct validated input instead of a central `ModelAction` union.
- Require every executable tool definition to declare the RFC `ReplayClass`.
- Validate every tool call in a returned batch before executing any call.
- Execute all validated calls sequentially in provider order and return all corresponding results in the same order.
- Refactor policy subjects, prompt context, records/items, loop detection, TUI previews, and internal `RuntimeEvent` observers around typed invocations and call ids.
- Preserve streaming text/reasoning/tool-call deltas and provider usage/retry/failure in typed form.
- Implement the canonical durable Run-context compaction frontier. `assemblyRef` freezes context limit/tokenizer/reserved output/thresholds; compaction is a tools-disabled Journaled model call returning only bounded complete Markdown content, works with text-only providers, and commits its plan/item/new context manifest/ready Checkpoint atomically without deleting raw Run items.
- Add provider conformance, capability negotiation, multi-call, malformed-call, streaming, and no-fallback tests.
- Add a focused provider/runtime validation command to `package.json`.

Out:

- Running tool calls concurrently inside one model response. Parallelism is implemented only by bounded child Runs in work package 5.
- Durable Run scheduling, leases, Checkpoints, Journal commits, broker dispatch, or crash reconciliation. This work package defines the events/contracts those packages consume.
- Sandbox implementation, workspace generations, credential handling, or network enforcement.
- Adding providers beyond the current six.
- Treating provider-name support as a claim that every model supports autonomous tools.
- Heuristic JSON extraction from Markdown/code fences, JSON repair, prompt retries asking for corrected action JSON, or parsing normal assistant text as a tool request.
- A general provider plugin ABI or provider-specific branching in the core runner.
- Changing public CLI/TUI/JSONL/RPC schema in this package; work package 6 adapts those clients to the versioned control protocol.
- MCP transport implementation. Work package 6 supplies dynamic MCP tool definitions through the tool contract defined here.
- Porting `src/hooks/*`, repository command hooks, or a replacement executable hook/plugin ABI. Work package 06 diagnoses/removes those entries; trusted internal observers consume typed `RuntimeEvent` values without executing repository commands.

### Proposed Implementation Direction

Likely files/modules:

- Create `src/protocol/agent-ir.ts` for provider-neutral deltas, completed model turns, `AgentToolCall`, `ToolInvocation`, and typed protocol errors.
- Create `src/model/capabilities.ts` for capability evidence, negotiation, fail-closed selection, and assembly serialization.
- Create `src/model/pricing.ts` and `src/model/pricing.test.ts` for registered/local endpoint cross-field validation, `ModelPriceTableV1` signature/digest/validity checks, and checked `cliq-price-ceil-v1` reservation/settlement arithmetic. Kernel Cut has no provider-cap admission side effect.
- Refactor [`src/model/types.ts`](../../../src/model/types.ts) so `ModelClient` returns Agent IR and no longer exposes `ModelStructuredOutput`, `TextActionFallback`, or `ModelRequestMode='text-action'`.
- Refactor [`src/model/prompt.ts`](../../../src/model/prompt.ts) and [`src/model/providers/prompt-mapping.ts`](../../../src/model/providers/prompt-mapping.ts) to accept one negotiated mode: `native-tools`, `constrained-ir`, or `text-only`.
- Refactor all modules under [`src/model/providers/`](../../../src/model/providers/) to emit identical Agent IR and capability evidence.
- Extend [`src/model/catalog/schema.ts`](../../../src/model/catalog/schema.ts), snapshot generation, Ollama discovery, and relevant tests so absence of capability evidence remains explicit rather than inferred as support.
- Refactor [`src/tools/types.ts`](../../../src/tools/types.ts), [`src/tools/registry.ts`](../../../src/tools/registry.ts), and each built-in tool under `src/tools/` to use direct input parsers and typed invocations.
- Refactor [`src/runtime/runner.ts`](../../../src/runtime/runner.ts) to prevalidate a batch, append/publish the whole assistant turn, process every call sequentially, and send the ordered results together on the next model request.
- Refactor [`src/runtime/context.ts`](../../../src/runtime/context.ts), [`src/policy/subjects.ts`](../../../src/policy/subjects.ts), and [`src/tui/format.ts`](../../../src/tui/format.ts) to consume `ToolInvocation` and validated input rather than `ModelAction`; route trusted internal observation through the typed `RuntimeEvent` seam. Do not modify `src/hooks/*` into a new runtime API—work package 06 deletes the repository command-hook path.
- Update [`src/prompt/system.ts`](../../../src/prompt/system.ts) and [`src/instructions/modes.ts`](../../../src/instructions/modes.ts) to describe available typed tools without any text-action fallback instruction.
- Delete [`src/protocol/model/actions.ts`](../../../src/protocol/model/actions.ts), [`src/protocol/model/actions.test.ts`](../../../src/protocol/model/actions.test.ts), [`src/protocol/model/json-repair.ts`](../../../src/protocol/model/json-repair.ts), and [`src/protocol/model/json-repair.test.ts`](../../../src/protocol/model/json-repair.test.ts) after work package 1's importer reads historical action payloads as opaque legacy data.
- Add `src/protocol/agent-ir.test.ts`, `src/model/capabilities.test.ts`, provider conformance fixtures, and focused batch tests in [`src/runtime/runner.test.ts`](../../../src/runtime/runner.test.ts).
- Add `test:agent-runtime` to [`package.json`](../../../package.json).

Implementation notes:

#### 1. Internal Agent IR

Use one provider-neutral completed-turn shape:

```ts
type ModelTextV1 = {
  schemaVersion: 1
  format: 'cliq-model-text-v1'
  utf8: string
  byteCount: number
  textDigest: string
}

type ObservedToolCallInputV1 = {
  schemaVersion: 1
  format: 'cliq-observed-tool-call-input-v1'
  byteCount: number
  observedInputDigest: string
} & (
  | { encoding: 'jcs_json'; value: unknown; utf8?: never }
  | { encoding: 'utf8_json_fragment'; utf8: string; value?: never }
)

type ToolCallInputBaseV1 = {
  schemaVersion: 1
  format: 'cliq-tool-call-input-v1'
  callId: string
  index: number
  toolName: string
  observedInputRef: ArtifactRef
  observedInputDigest: string
  inputDigest: string
}

type ToolCallInputV1 = ToolCallInputBaseV1 & (
  | {
      disposition: 'resolved'
      inputSchemaRef: ArtifactRef
      inputSchemaDigest: string
      value: Record<string, unknown>
      diagnosticRef?: never
      diagnosticDigest?: never
    }
  | {
      disposition: 'rejected_unknown_tool'
      inputSchemaRef?: never
      inputSchemaDigest?: never
      value?: never
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
    }
  | {
      disposition: 'rejected_invalid_input'
      inputSchemaRef: ArtifactRef
      inputSchemaDigest: string
      value?: never
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
    }
)

type AgentToolCall = {
  callId: string
  toolName: string
  inputRef: ArtifactRef
  inputDigest: string
  index: number
}

type AgentUsage = {
  inputTokens: number
  outputTokens: number
  cacheReadTokens: number
  cacheWriteTokens: number
  costMicros: number
}

type AgentModelTurnBase = {
  schemaVersion: 1
  format: 'cliq-agent-model-turn-v1'
  provider: ProviderName
  model: string
  responseId?: string
  usage?: AgentUsage
  usageTrusted: false
  negotiatedMode: 'native-tools' | 'constrained-ir' | 'text-only'
  promptProjectionRef: ArtifactRef
  promptProjectionDigest: string
  requestDigest: string
  responseDigest: string
}

type AgentModelTurn = AgentModelTurnBase & (
  | {
      stopReason: 'end'
      textRef: ArtifactRef // decoded ModelTextV1 UTF-8 byte length >= 1
      toolCalls: []
      abortStopIntentRef?: never
    }
  | {
      stopReason: 'tool_calls'
      textRef: ArtifactRef
      toolCalls: [AgentToolCall, ...AgentToolCall[]]
      abortStopIntentRef?: never
    }
  | {
      stopReason: 'cancelled'
      textRef: ArtifactRef
      toolCalls: []
      abortStopIntentRef: ArtifactRef
    }
)

type ModelUnusableResponseV1 = {
  schemaVersion: 1
  format: 'cliq-model-unusable-response-v1'
  runId: string
  opId: string
  attempt: number
  request:
    | { kind: 'normal'; requestRef: ArtifactRef; requestDigest: string }
    | { kind: 'context_compaction'; requestRef: ArtifactRef; requestDigest: string }
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu' | 'ollama'
  model: string
  negotiatedMode: 'native-tools' | 'constrained-ir' | 'text-only'
  failureCode:
    | 'malformed_transport_payload'
    | 'response_too_large'
    | 'invalid_stop_call_shape'
    | 'stop_reason_length'
    | 'stop_reason_content_filter'
    | 'stop_reason_unknown'
    | 'missing_or_duplicate_call_id'
    | 'tool_calls_forbidden_by_mode'
    | 'context_compaction_requires_end_markdown'
    | 'capability_shape_mismatch'
    | 'provider_rejected_response'
  observedResponse:
    | {
        kind: 'complete'
        mediaType: 'application/json' | 'text/event-stream' | 'application/x-ndjson' | 'unknown'
        bytesRef: ArtifactRef
        bytesDigest: string
        byteCount: number
      }
    | {
        kind: 'prefix_over_limit'
        mediaType: 'application/json' | 'text/event-stream' | 'application/x-ndjson' | 'unknown'
        bytesRef: ArtifactRef
        bytesDigest: string
        byteCount: number
        responseLimitBytes: number
      }
  observedAt: string
  unusableDigest: string
}

type ToolInvocation<TInput extends Record<string, unknown> = Record<string, unknown>> = {
  callId: string
  index: number
  toolName: string
  input: TInput
  replayClass: ReplayClass
}

type ModelTurnItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'model_turn'
  modelOpId: string
  modelAttempt: number
  modelTurnRef: ArtifactRef
  stopReason: 'end' | 'tool_calls' | 'cancelled'
  textRef: ArtifactRef
  abortStopIntentRef?: ArtifactRef
  createdAt: string
}

type ToolCallRecord = {
  callId: string
  index: number
  toolName: string
  inputRef: ArtifactRef
  inputDigest: string
}

type ToolBatchItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'assistant_tool_batch'
  modelOpId: string
  modelAttempt: number
  modelTurnRef: ArtifactRef
  textRef: ArtifactRef
  calls: ToolCallRecord[]
  createdAt: string
}

type ToolResultItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'tool_result'
  batchItemId: string
  callId: string
  index: number
  opId?: string
  outcome: 'executed' | 'denied' | 'error' | 'batch_not_executed' | 'cancelled'
  resultRef: ArtifactRef
  createdAt: string
}

type ToolResultPayloadBaseV1 = {
  schemaVersion: 1
  format: 'cliq-tool-result-payload-v1'
  runId: string
  batchItemId: string
  callId: string
  index: number
  toolName: string
  modelContentRef: ArtifactRef
  modelContentDigest: string
  payloadDigest: string
}

type ToolResultModelContentV1 = {
  schemaVersion: 1
  format: 'cliq-tool-result-model-content-v1'
  callId: string
  index: number
  toolName: string
  outcome: 'executed' | 'denied' | 'error' | 'batch_not_executed' | 'cancelled'
  content: unknown
  contentDigest: string
}

type ToolResultPayloadV1 = ToolResultPayloadBaseV1 & (
  | {
      outcome: 'executed'
      opId: string
      attempt: number
      journalResultRef: ArtifactRef
      journalResultDigest: string
      outputSchemaRef?: ArtifactRef
      outputSchemaDigest?: string
    }
  | {
      outcome: 'denied'
      denial:
        | { source: 'policy'; policyRef: ArtifactRef; decisionDigest: string }
        | { source: 'user'; approvalDecisionRef: ArtifactRef; approvalDecisionDigest: string }
      code: 'TOOL_CALL_DENIED'
    }
  | {
      outcome: 'error'
      code:
        | 'TOOL_NOT_FOUND'
        | 'TOOL_INPUT_INVALID'
        | 'TOOL_AUTHORITY_UNAVAILABLE'
        | 'TOOL_EXECUTION_FAILED'
        | 'TOOL_PROTOCOL_ERROR'
        | 'TOOL_RESOURCE_EXHAUSTED'
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
      opId?: string
      attempt?: number
      journalErrorRef?: ArtifactRef
      journalErrorDigest?: string
    }
  | {
      outcome: 'batch_not_executed'
      code: 'BATCH_REJECTED_BEFORE_DISPATCH'
      invalidCallIds: string[]
    }
  | {
      outcome: 'cancelled'
      cancellationKind: 'undispatched_stop' | 'await_children_stop'
      stopIntentRef: ArtifactRef
      noticeRef: ArtifactRef
      noticeDigest: string
    }
)

type WorkspaceDiffOperationV1 =
  | { path: string; kind: 'add'; after: WorkspaceEntry }
  | { path: string; kind: 'delete'; before: WorkspaceEntry }
  | { path: string; kind: 'modify'; before: WorkspaceEntry; after: WorkspaceEntry }

type WorkspaceDiffV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-diff-v1'
  baseSourceRef: ArtifactRef
  resultSourceRef: ArtifactRef
  operations: WorkspaceDiffOperationV1[]
  diffDigest: string
}

type FinalCandidateItemBase = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'final_candidate'
  producingItemId: string
  baseSourceRef: ArtifactRef
  resultSourceRef: ArtifactRef
  diffRef: ArtifactRef
  summaryRef: ArtifactRef
  sourceDigest: string
  diffDigest: string
  createdAt: string
}

type FinalCandidateItem = FinalCandidateItemBase & (
  | { operation: 'agent'; producingOpId: string }
  | { operation: 'delivery'; producingOpId?: never }
)
```

`AgentUsage` is optional as a whole but never partial: when present, all five members are nonnegative safe integers, input plus output fits the request's reserved model-token ceiling, cache counters are explicit zero when unavailable, and `costMicros` is the frozen price algorithm over those telemetry counters (or zero for local zero cost). It is never settlement authority: `usageTrusted` is literal `false`; exact same-owner `PostClaimNoReleaseEvidenceV1` consumes zero, while every released/possibly-released model terminal/unknown consumes the full request-bound reservation. Let `N` be the exact pinned-tokenizer count of the serialized prompt and `O=maximumOutputTokens`; `NormalModelRequestV1` stores `inputTokenCount=N` plus the sole conservative component vector `(N,O,N,N)`, `modelTokens=N+O`, and exact frozen-table cost (zero locally). Its `requestDigest` binds the vector and the prepared Journal delta repeats its model-token/cost totals with zero tool/repair counters. Provider cache assertions, SDK usage, capability booleans, and omitted counters can affect telemetry only.

The immutable assembly uses the one canonical Kernel-Cut model retry policy: exactly three dispatched attempts, zero same-attempt transport retries, and delays `[500ms,2000ms]`. Provider headers including `Retry-After` cannot alter it: a positively received rejection is completed/non-retried, and only failed/unknown transport attempts use the fixed delays. Any redispatch is a new Journal attempt/reservation; SDK auto-retry is disabled. Tool policies are equally literal: `retry` is three attempts with `[500ms,2000ms]`, `workspace-rollback-retry` is two with `[500ms]`, and `reconcile|manual` have one productive dispatch and no redispatch delay. No request, config, adapter, or tool raises or lowers these values. Exhaustion stops under the canonical op-kind reducer rather than spinning.

Managed-local service availability is outside that provider retry counter but is not unbounded. Before preparing a new Ollama model attempt, absence/death of the exact frozen service causes WP04 to settle any prior attempt, quiesce the worker, leave the Run queued on the same agent frontier, and join the WP01-owned `LocalInferenceActivationCycleV1`. Initial submissions and existing Run frontiers share its append-only max-128 participants and two-launch/120-second/one-second-positive-retirement bound. Cycle success makes the unchanged frontier eligible; cycle failure proposes the exact `runtimeSubtype='local_inference_unavailable'` StopIntent/detail carrying cycle/service/frontier/failure refs. The provider adapter cannot spin, consume model retry attempts while no live service exists, choose indefinite queuing, or fall back to an ambient endpoint.

The streaming seam emits typed events for model start, text/reasoning deltas, tool-call start, argument delta, tool-call completion, usage, retry, error, and end. Provider adapters own wire-format parsing and incremental argument assembly. The runner sees only complete `AgentToolCall` values and never provider JSON/SSE chunks.

Native provider call ids must be non-empty and unique within a response. Missing or duplicate native ids are a protocol error. A constrained-IR call id is generated deterministically from the model invocation `opId` plus call index before the turn is persisted; random ids must not make recovery produce a different context.

Every completed visible model attempt publishes exact `ModelTextV1`, one exact `ObservedToolCallInputV1` plus `ToolCallInputV1` per call, and the durable `AgentModelTurn` before appending `ModelTurnItem` in the same transaction as its op-kind frontier reducer. All self-digests omit themselves; UTF-8/JCS byte counts are exact and bounded to 1,048,576 bytes. Valid JSON observations retain the exact JSON-domain value/JCS bytes; malformed arguments retain the exact assembled UTF-8 fragment, so the assistant call can be reconstructed losslessly. Only `resolved` contains the selected schema-normalized object and may enter policy/grant/Journal/dispatch. Unknown-tool and invalid-input branches retain their observation plus deterministic diagnostic and remain in the batch only for synthetic results. Agent turn call ids/names/indexes/input pairs are byte-identical to the ordered `ToolBatchItem.calls`, and both model/batch `textRef` equal the turn's text artifact. A call batch must match that model item/op/attempt; an agent final candidate must name a same-Run model item with stop `end`. The batch/result immutable Run-item kinds plus canonical `RunFrontier` are the complete continuation contract. The store permits at most one open batch, one result for each `(batchItemId,callId,index)`, and no cross-batch result. A tool frontier's `orderedCallIds` and `nextCallIndex` must agree with those items; an open Journal invocation is reconciled first. Policy, approval, OperationGrant, Journal request, preview, and execution decode the same resolved input artifact and never reparse provider JSON. Committing the final result atomically installs an agent frontier. No array cursor hidden in worker memory, prompt, or free-text reconstruction is authoritative.

For a usable turn, `responseDigest` is not a digest of discarded provider wire bytes. It is exactly SHA-256 of RFC 8785/JCS `{format:'cliq-agent-normalized-response-v1',provider,model,responseId?,usage?,usageTrusted:false,negotiatedMode,requestDigest,stopReason,textRef,toolCalls,abortStopIntentRef?}`, with absent optional members omitted and `toolCalls` in retained index order. Every listed value is copied byte-for-byte from that `AgentModelTurn`; storage recomputes the projection before accepting the Journal result or model item. Raw malformed/oversize/nonterminal-stop bytes instead belong only to `ModelUnusableResponseV1.observedResponse`, so a provider-body hash, adapter-selected JSON, or digest of the entire turn is invalid.

The discriminated turn is an exact XOR, not advisory prose. `end` requires UTF-8 byte length >=1 and zero calls; `tool_calls` requires one or more complete call identities with exact resolved/rejected input artifacts and may carry text; `length|content_filter|unknown` are structurally forbidden from `AgentModelTurn` and `ModelTurnItem`; any provider-supplied text or partial/complete calls for those stops remain only in exact private observed-response bytes. Those three stops map respectively to `stop_reason_length|stop_reason_content_filter|stop_reason_unknown`; a positively received provider rejection maps to `provider_rejected_response`; and they plus every executed invalid pair (`end+calls`, non-tool stop+calls, empty `end`) publish one identity-matched `ModelUnusableResponseV1`, use that ref as Journal result and runtime evidence/error, create neither candidate nor batch, and consume the completed attempt's full reservation. `cancelled` is schema-legal only with an exact pre-existing current StopIntent ref that caused Cliq's authenticated abort of this attempt; it creates no candidate/batch and quiesces under that existing intent rather than inventing cancellation authority. A provider-originated cancel without that binding is completed-unusable runtime failure when positively received, or Journal `unknown`/frozen retry when dispatch outcome is uncertain. After a valid `end`, quiescing/projecting the private workspace makes base/result/diff/summary refs, producing item/op, and exact source/diff digests the canonical `FinalCandidateItem`; the same transaction installs its verify/finalize `RunFrontier`. Text accompanying valid tool calls is retained as assistant content but cannot itself trigger execution. Delivery creates the same item kind only from CAS-first deterministic merged artifacts, never assistant text.

`WorkspaceDiffV1.diffDigest` omits itself under JCS. Its byte-sorted unique operations are exactly the union-path comparison of decoded base/result `WorkspaceEntryManifest`s: add carries the exact result-only entry, delete the exact base-only entry, modify both unequal entries, and equal entries emit nothing. A candidate's `sourceDigest` equals its result `SourceManifest.manifestDigest`; `diffRef/diffDigest` decode that exact base-to-result diff. Agent candidates name the end `ModelTurnItem`, copy its model op id, and use its nonempty text ref as summary. Delivery candidates forbid a producing op id and copy the exact `DeliveryMergeItem` source/result/diff/summary fields. `RunResult` repeats candidate base/result/diff/summary byte-for-byte.

Every terminal commit requires every persisted tool call to have exactly one identity-matched closure and no open typed continuation. The normal closure is `ToolResultItem`; its outcome and call identity equal decoded `ToolResultPayloadV1`, whose `payloadDigest` omits itself. Executed payloads bind the exact completed Journal result and output schema; policy/user denial binds the exact policy or `ApprovalDecisionV1`; error payloads use only the closed codes and require a diagnostic plus matching Journal error whenever an op/attempt exists; an invalid batch lists exactly all invalid call ids; ordinary cancellation binds the winning StopIntent and deterministic notice. Each ordinary payload rehashes one matching `ToolResultModelContentV1`, but the model sees only that bounded ref-free artifact: executed output is schema-normalized; denial is its fixed code; error is its closed code; batch rejection is code plus invalid ids; cancellation is code plus cancellation kind. No authority/audit ref enters model content. The only payload exception is a fully settled/fenced `retry` unknown: its cancelled item points directly to exact `RetryUnknownCancelledResult` and never continues the batch. The sole non-result closure is terminal-only `ToolAbandonedItem` for the exact `ReplayClass='manual'` invocation named in TerminalDetail. `commitRunResult` additionally requires the latest operation-appropriate `FinalCandidateItem` and exact equality between its result/summary refs and RunResult. Cancellation, deadline, or failure closes an undispatched suffix atomically by appending cancelled payloads/results in index order; a dispatched/ambiguous current call must first satisfy ReplayClass-specific terminal quiescence. Unresolved reconcile/manual effects block terminalization rather than being mislabeled cancelled.

```ts
type PromptSerializationProfileV1 = {
  schemaVersion: 1
  format: 'cliq-prompt-serialization-profile-v1'
  provider: RunAssemblyV1['provider']['name']
  model: string
  algorithm: 'cliq-jcs-framed-chat-v1'
  normalPrefixUtf8: string
  normalSuffixUtf8: string
  compactionPrefixUtf8: string
  compactionSuffixUtf8: string
  goldenVectors: Array<{ payloadJcsUtf8: string; renderedBytesBase64url: string }>
  profileDigest: string
}

type ProviderNativeRequestProfileV1 = {
  schemaVersion: 1
  format: 'cliq-provider-native-request-profile-v1'
  provider: RunAssemblyV1['provider']['name']
  model: string
  algorithm:
    | 'cliq-openai-chat-completions-json-v1'
    | 'cliq-anthropic-messages-json-v1'
    | 'cliq-openrouter-chat-completions-json-v1'
    | 'cliq-openai-compatible-chat-completions-json-v1'
    | 'cliq-zhipu-chat-completions-json-v1'
    | 'cliq-ollama-chat-json-v1'
  requestPath: string
  mediaType: 'application/json'
  goldenVectors: Array<{
    requestKind: 'normal' | 'compaction'
    sourceJcsUtf8: string
    bodyBytesBase64url: string
    inputTokenCount: number
  }>
  profileDigest: string
}

type ProviderNativeRequestBodyV1 = {
  schemaVersion: 1
  format: 'cliq-provider-native-request-body-v1'
  provider: RunAssemblyV1['provider']['name']
  model: string
  negotiatedMode: 'native-tools' | 'constrained-ir' | 'text-only'
  profileRef: ArtifactRef
  profileDigest: string
  source:
    | { kind: 'normal'; promptProjectionRef: ArtifactRef; promptProjectionDigest: string }
    | {
        kind: 'compaction'
        compactionPlanRef: ArtifactRef
        promptEnvelopeRef: ArtifactRef
        promptEnvelopeDigest: string
        renderedPromptRef: ArtifactRef
        renderedPromptDigest: string
      }
  requestPath: string
  mediaType: 'application/json'
  bodyBytesRef: ArtifactRef
  bodyBytesDigest: string
  bodyByteCount: number
  inputTokenCount: number
  nativeRequestDigest: string
}

type TokenizerVocabularyV1 = {
  schemaVersion: 1
  format: 'cliq-byte-bpe-vocabulary-v1'
  tokens: Array<{ tokenId: number; bytesBase64url: string }>
  vocabularyDigest: string
}

type TokenizerMergeRanksV1 = {
  schemaVersion: 1
  format: 'cliq-byte-bpe-merge-ranks-v1'
  merges: Array<{
    rank: number
    leftTokenId: number
    rightTokenId: number
    resultTokenId: number
  }>
  mergeRanksDigest: string
}

type TokenizerProfileV1 = {
  schemaVersion: 1
  format: 'cliq-tokenizer-profile-v1'
  provider: RunAssemblyV1['provider']['name']
  model: string
  algorithm: 'cliq-byte-bpe-v1'
  vocabularyRef: ArtifactRef
  vocabularyDigest: string
  mergeRanksRef: ArtifactRef
  mergeRanksDigest: string
  specialTokenPolicy: 'disabled_profile_framing_only'
  goldenVectors: Array<{ renderedBytesBase64url: string; tokenIds: number[] }>
  profileDigest: string
}

type PromptSerializationManifestV1 = {
  schemaVersion: 1
  format: 'cliq-prompt-serialization-v1'
  provider: RunAssemblyV1['provider']['name']
  model: string
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  entryId: string
  entryVersion: string
  entryDigest: string
  profileRef: ArtifactRef
  profileDigest: string
  protocol: 'cliq-render-chat-messages-v1'
  messageAstVersion: 'cliq-chat-messages-v1'
  manifestDigest: string
}

type TokenizerManifestV1 = {
  schemaVersion: 1
  format: 'cliq-tokenizer-v1'
  provider: RunAssemblyV1['provider']['name']
  model: string
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  entryId: string
  entryVersion: string
  entryDigest: string
  profileRef: ArtifactRef
  profileDigest: string
  protocol: 'cliq-count-rendered-prompt-tokens-v1'
  promptSerializationRef: ArtifactRef
  promptSerializationDigest: string
  manifestDigest: string
}

type NormalPromptToolCallV1 = {
  callId: string
  index: number
  toolName: string
  inputRef: ArtifactRef
  inputDigest: string
  argumentsUtf8: string
}

type NormalPromptMessageV1 =
  | {
      index: number
      role: 'system' | 'user'
      sourceKind:
        | 'assembly_instructions'
        | 'session_terminal'
        | 'session_summary'
        | 'parent_context'
        | 'additional_context'
        | 'run_objective'
        | 'run_summary'
        | 'user_input'
        | 'verifier_repair'
        | 'child_result'
      sourceId: string
      contentUtf8: string
    }
  | {
      index: number
      role: 'assistant'
      sourceItemId: string
      contentUtf8: string
      toolCalls: NormalPromptToolCallV1[]
    }
  | {
      index: number
      role: 'tool'
      sourceItemId: string
      toolCallId: string
      contentUtf8: string
    }

type NormalPromptProjectionV1 = {
  schemaVersion: 1
  format: 'cliq-normal-prompt-projection-v1'
  runId: string
  basedOnRunRevision: number
  frontierDigest: string
  runSpecRef: ArtifactRef
  assemblyRef: ArtifactRef
  assemblyDigest: string
  contextManifestRef: ArtifactRef
  contextManifestDigest: string
  messages: NormalPromptMessageV1[]
  tools: Array<{
    index: number
    name: string
    description: string
    inputSchemaRef: ArtifactRef
    inputSchemaDigest: string
    inputSchema: unknown
  }>
  projectionDigest: string
}

type NormalModelRequestV1 = {
  schemaVersion: 1
  format: 'cliq-normal-model-request-v1'
  runId: string
  opId: string
  attempt: number
  provider: RunAssemblyV1['provider']['name']
  model: string
  negotiatedMode: 'native-tools' | 'constrained-ir' | 'text-only'
  promptProjectionRef: ArtifactRef
  promptProjectionDigest: string
  promptSerializationRef: ArtifactRef
  promptSerializationDigest: string
  nativeRequestRef: ArtifactRef
  nativeRequestDigest: string
  tokenizerRef: ArtifactRef
  tokenizerDigest: string
  maximumOutputTokens: number
  inputTokenCount: number
  reservation: {
    inputTokens: number
    outputTokens: number
    cacheReadTokens: number
    cacheWriteTokens: number
    modelTokens: number
    costMicros: number
  }
  requestDigest: string
}

type CompactionModelRequestV1 = {
  schemaVersion: 1
  format: 'cliq-compaction-model-request-v1'
  runId: string
  opId: string
  attempt: number
  compactionPlanRef: ArtifactRef
  promptEnvelopeRef: ArtifactRef
  promptEnvelopeDigest: string
  renderedPromptRef: ArtifactRef
  renderedPromptDigest: string
  nativeRequestRef: ArtifactRef
  nativeRequestDigest: string
  tokenizerRef: ArtifactRef
  tokenizerDigest: string
  inputTokenCount: number
  maximumOutputTokens: number
  reservation: {
    inputTokens: number
    outputTokens: number
    cacheReadTokens: number
    cacheWriteTokens: number
    modelTokens: number
    costMicros: number
  }
  requestDigest: string
}

type CompactionPromptEnvelopeV1 = {
  schemaVersion: 1
  format: 'cliq-compaction-prompt-envelope-v1'
  systemInstructionRef: ArtifactRef
  systemInstructionDigest: string
  userPrefixRef: ArtifactRef
  userPrefixDigest: string
  sourcePlaceholder: '{{CLIQ_SOURCE_CONTEXT_UTF8}}'
  userSuffixRef: ArtifactRef
  userSuffixDigest: string
  resultContract: {
    toolsAllowed: false
    requiredStopReason: 'end'
    mediaType: 'text/markdown; charset=utf-8'
    summaryFormat: 'cliq-context-summary-markdown-v1'
  }
  envelopeDigest: string
}
```

Normal model input is the canonical RFC `NormalPromptProjectionV1`, never an adapter-built message list. `projectionDigest` omits itself under JCS; Run/spec/assembly/context refs, based-on revision, and `frontierDigest=SHA-256(JCS(current RunFrontier))` equal authoritative storage. Messages and tools have contiguous indices. The reducer emits, in order: one system message formed from the signed RuntimeBundle-selected exact nonempty `ModelTextV1` system prompt, the one exact all-scopes workspace-instruction JCS block (all frozen entries in manifest order, with path/scope labels), and one source-labeled JCS block per selected skill in explicit request order, with nonempty pieces joined by two LF bytes; admitted Session raw terminal/summary messages, then parent/additional `ModelTextV1` context in stored order; the exact `RunObjectiveV1`; and current ContextManifest segments. There is no runtime target-path applicability choice and ContextManifest carries no second instruction/skill array: those artifacts are reached only through the immutable assembly. Session legacy/control and Run `excluded_control` segments emit nothing. Run raw projection is closed to assistant ModelTurn text/calls, ToolResult model content, UserInput model content, verifier-repair model content, and child-result model content; every other item is control-only. Human text is NFC/no-NUL. Tool/UserInput/child JSON uses exact UTF-8 JCS; observed valid call arguments use JCS and malformed fragments use their exact retained UTF-8. No grant, principal, StopIntent, receipt, raw verifier output, containment evidence, or other audit payload enters a message.

For native/constrained mode the projection's tool array is exactly the assembly exposed-name sequence and decodes the same manifest descriptions/input schemas; text-only has none. The serializer manifest resolves a signed non-executable exact `PromptSerializationProfileV1`, the assembly provider resolves exactly one signed `ProviderNativeRequestProfileV1`, and the tokenizer manifest resolves exact `TokenizerProfileV1` plus signed `TokenizerVocabularyV1`/`TokenizerMergeRanksV1` members. The fixed `cliq-jcs-framed-chat-v1` renderer emits profile prefix + JCS model-visible `{format,messages,tools,responseContract}` + suffix after stripping every provenance/ref/audit field; compaction uses the separately fixed two-message payload and compaction framing. The fixed `cliq-byte-bpe-v1` algorithm starts from its required 256 one-byte tokens and repeatedly applies the globally lowest-ranked adjacent merge, leftmost on ties, with special-token recognition disabled. Profile/vocabulary/merge omission digests, provider/model, RuntimeBundle entry refs, bounds, and 8..64 signed golden vectors validate before admission; an unavailable exact profile makes the model ineligible.

The native-request profile uses exactly one provider-specific algorithm/path and 8..64 signed source-JCS/body-byte/input-token golden vectors. Before the Journal request publishes, fixed Supervisor code serializes the exact normal projection or compaction plan/envelope/rendered prompt into one secret-free `ProviderNativeRequestBodyV1`; its self digest omits itself, body ref equals the SHA-256 of the exact at-most-1-MiB `application/json` bytes, byte count/path/profile/source all match, and input-token count equals the pinned tokenizer result. Journal `requestRef` decodes `NormalModelRequestV1`, whose digest omits itself and whose Run/op/attempt/provider/model/mode/projection/serializer/native-body/tokenizer fields equal the prepared attempt and assembly; `maximumOutputTokens` is exactly `reservedOutputTokens`, `inputTokenCount` is the independently recomputed prompt/native-body count, and the `(N,O,N,N)` reservation plus aggregate model-token/cost totals match the prepared Journal delta. A compaction attempt instead uses exact `CompactionModelRequestV1`: current plan/envelope/tokenizer, immutable exact rendered UTF-8 prompt, exact compaction native-body source, recomputed input count, summary-token maximum, same reservation vector, and self-omitting request digest. The broker transmits the retained body bytes verbatim and injects only endpoint-authorized transport/authentication headers; an SDK may not rebuild an object, add a message/tool/schema/default, change the path, or follow a redirect after hashing. `AgentModelTurn.promptProjectionRef/promptProjectionDigest` and `requestDigest` repeat the applicable request. Storage and recovery re-render, reserialize, rehash, and recount before accepting the turn.

Durable compaction is not the legacy Session compactor and never runs as an invisible tokenizer heuristic. Import the RFC's total integer algorithm verbatim: admission requires `C>=32768`, `1<=O<=floor(C/4)`, `C-O-8192>=16384`, and source cap `P>=4096`; freeze `H/T/R/S/K/P`, exact serializer/tokenizer, and dual summary caps. `RunAssembly.context.promptTemplateRef` and `tokenizerRef` decode the exact manifests/profiles above, match provider/model/runtime bundle, and resolve signed `prompt_serializer`/`tokenizer` entries plus all transitive profile members whose fixed protocols storage can rerun; the tokenizer repeats the serializer ref/digest. `cliq-chat-messages-v1` is an ordered role/content AST. `RunAssembly.context.compactionPromptEnvelopeRef/digest` resolves the unique provider/model signed RuntimeBundle `compaction_prompt` structured root and decodes only the exact artifact above; each of its three text refs is a signed member, bounded NFC UTF-8 and rehashes, its one logical source slot cannot occur in fixed text, and its digest omits itself. `K` is the pinned-tokenizer count after the pinned serializer renders exactly two messages: system content, then user content equal to prefix + empty source + suffix, with no implicit message or delimiter. Every plan copies envelope ref/digest and all context scalars; `promptOverheadTokens=K`, while source range/digest/tokens come only from the selected ContextManifest projection. Above `T`, protect fixed admitted/instruction/tool context, live references, and newest whole segments totaling `R`; enumerate only contiguous sequence-one prefixes ending at earlier segment boundaries, require source tokens `<=P` and `>=S+512`, and choose the greatest `throughItemSeq`. Publish canonical `RunContextCompactionPlan`, set `RunFrontier.agent.phase='context_compaction'`, and dispatch a normal tools-disabled model attempt under frozen retry/budget rules. Accept only positive `end` Markdown within token and 256-KiB caps. One success transaction appends `RunContextCompactionItem`, replaces exactly the covered projection with its source-digest-bound summary, restores `agent:model_turn`, and publishes a ready Checkpoint reusing unchanged workspace state. It reduces projection by at least 512 tokens; if still above threshold the same deterministic algorithm selects the next larger prefix. No legal prefix proposes the exact `runtimeSubtype='context_window_exhausted'` StopIntent carrying manifest and all required token counts, with no model call. A tool-bearing/malformed/non-end/oversize executed response is Journal `completed` unusable and immediately proposes the exact `runtimeSubtype='context_compaction_failed'` intent carrying plan/model-op/attempt evidence; completed-unusable is never retried. Only pre-dispatch/transport failed-or-unknown attempts use model retry. Raw items remain durable.

#### 2. Capability negotiation

`RunSpec.assemblyRef` imports the canonical RFC `RunAssemblyV1` verbatim; no provider-local assembly shape is legal. This package owns construction/validation of its provider, selected MCP registry revisions, canonical tool-contract manifest, retry, post-Trust instruction/skill manifests, runtime/guest, and context portions: immutable registered-or-local endpoint identity and principal/target-bound credential refs; provider/model adapter id/version/code digest; capability evidence/digest and exact negotiated mode; trusted usage flag; context/output limits; closed `ModelPricingBound`; byte-ordered tool schema/ref/digest/replay/adapter entries; retained runtime/guest identities; exact model/tool retry policies; prompt template/tokenizer/compaction envelope; and the frozen `C/O/H/T/R/S/K/P` equations. `assemblyDigest` is RFC 8785/JCS with itself omitted, unknown fields fail closed, and every referenced digest is revalidated. Native/constrained/text-only mode, selected MCP tools, exposed-tool equality, pricing eligibility, instruction/skill projection, credential union, compaction plans, model requests, Checkpoints, recovery, and CAS retention must all use that same assembly ref and immutable transitive graph.

Replace provider-name switching in prompt construction with two inputs:

1. transport evidence declared by the provider adapter;
2. model evidence from a high-confidence catalog entry or provider discovery.

Use positive evidence only. Unknown equals unsupported. Freeze the selected mode, evidence/provenance, provider adapter version, model identity, streaming decision, and exact tool-schema digest into the Run assembly artifact.

Selection is deterministic:

```text
adapter.nativeTools && model.nativeTools
  -> native-tools
else adapter.constrainedOutput && model.constrainedOutput
  -> constrained-ir
else
  -> text-only
```

The initial adapter matrix is fixed:

| Provider | Native transport | Constrained transport | Model evidence |
|---|---:|---:|---|
| `openai` | yes | yes | built-in catalog; absent facts are false |
| `anthropic` | yes | no | built-in catalog; absent facts are false |
| `openrouter` | yes | yes | per-model catalog/compat metadata; unknown aggregation capability is false |
| `openai-compatible` | yes | yes | discovered or explicitly trusted model metadata only; custom unknown models are text-only |
| `zhipu` | OpenAI-compatible transport exists, but initial autonomous capability is false unless positive model metadata is added | false initially | current `glm-5.2` metadata remains text-only until proven otherwise |
| `ollama` | yes when the signed managed service's retained capability evidence reports tool capability | yes when that evidence reports schema `format` | Kernel `local_inference` boundary only; raw/user-managed loopback and unavailable/unknown evidence are false |

`yes` in the transport columns means the adapter can encode/decode that protocol. It does not elevate a model whose evidence is absent. Existing broad assumptions such as “all OpenAI-compatible models support structured output” must be removed.

No runtime downgrade occurs after the Run assembly is frozen. A malformed/shape-violating provider response—including a required missing/duplicate native call id after the exact Ollama normalization above—or a positively received provider rejection means the model invocation `completed` with exact `ModelUnusableResponseV1` and full request-reservation settlement; it is not Journal `failed` and never decodes as `AgentModelTurn`. The artifact repeats Run/op/attempt, exact normal-or-compaction request, provider/model/mode, a closed failure code (`provider_rejected_response` for the target rejection), and either exact complete response bytes up to 1 MiB or exactly the first 1 MiB+1 bytes for the oversize branch; every bytes ref/digest/size and its self-omitting digest rehash. That one ref is the Journal result plus runtime StopIntent evidence/error and creates no model item, batch, candidate, or compaction summary. Only a local rejection before a claim or exact post-claim no-release closure may be `failed`; neither claims a provider response. The Run then terminates through `commitTerminalStop` as `failed(runtime_failed)` with `MODEL_CAPABILITY_MISMATCH` or `MODEL_PROTOCOL_ERROR` detail (or exact context-compaction failure). There is no semantic retry/downgrade policy for this class. Generic pre-response transport failures still follow the Journal model-call ReplayClass and budget rules, but never retry the same assistant text through `text-action` parsing.

Endpoint identity is closed before pricing. `endpoint.kind='local_zero_cost'` is legal only for the RFC `LocalZeroCostProvenanceV1` produced by WP06's signed managed Ollama service, requires `provider.credentialGrantRefs=[]`, requires `pricing.kind='zero_cost'`, and uses the same provenance ref in both endpoint and pricing. Every billable standard or custom endpoint—including the bundled OpenAI, Anthropic, and OpenRouter defaults—is `endpoint.kind='registered'`. `registrationKind='bundled_default'` records who enrolled the immutable `EndpointRegistrationV1`; it is not free, credentialless, or weaker authority. A registered endpoint has literal `redirectPolicy='reject_all'` and nonempty `EndpointCredentialGrantBinding(purpose='model_endpoint')` refs whose endpoint registration, owner, purpose, identity, TLS, authority/service revisions, secret generation, and external-subject digest match exactly. The adapter disables SDK redirects; every `300..399` is a positively received typed rejection and neither body nor credentials are resent to `Location`. Rotation or external account/scope drift invalidates the frozen binding before I/O; an admitted Run never inherits a later secret generation.

Pricing imports these canonical types verbatim:

```ts
type NormalizedModelCapabilityClaimsV1 = {
  nativeToolCalling: boolean
  constrainedOutput: boolean
  streaming: boolean
  trustedUsageEvidence: boolean
  contextLimitTokens: number
  maxOutputTokens: number
}

type LocalModelManifestV1 = {
  schemaVersion: 1
  format: 'cliq-local-model-manifest-v1'
  signerKeyId: string
  signatureAlgorithm: 'ed25519'
  signatureRef: ArtifactRef
  provider: 'ollama'
  model: string
  architecture: string
  tokenizerRef: ArtifactRef
  tokenizerDigest: string
  files: Array<{
    canonicalRelativePath: string
    contentRef: ArtifactRef
    contentDigest: string
    sizeBytes: number
  }>
  claims: NormalizedModelCapabilityClaimsV1
  modelManifestDigest: string
}

type LocalModelObjectClosureV1 = {
  schemaVersion: 1
  format: 'cliq-local-model-object-closure-v1'
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  objectStoreRootRelativePath: 'local-models/objects'
  modelManifestRef: ArtifactRef
  modelManifestDigest: string
  objects: Array<
    | {
        kind: 'model_manifest'
        logicalPath: 'model-manifest.json'
        artifactRef: ArtifactRef
        artifactDigest: string
        sizeBytes: number
      }
    | {
        kind: 'tokenizer'
        logicalPath: 'tokenizer'
        artifactRef: ArtifactRef
        artifactDigest: string
        sizeBytes: number
      }
    | {
        kind: 'model_file'
        logicalPath: string
        artifactRef: ArtifactRef
        artifactDigest: string
        sizeBytes: number
      }
  >
  objectCount: number
  totalBytes: number
  closureDigest: string
}

type SignedModelCatalogEntryV1 = {
  schemaVersion: 1
  format: 'cliq-signed-model-catalog-entry-v1'
  signerKeyId: string
  signatureAlgorithm: 'ed25519'
  signatureRef: ArtifactRef
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
  model: string
  endpointIdentityDigest: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  claims: NormalizedModelCapabilityClaimsV1
  validFrom: string
  validThrough: string
  catalogEntryDigest: string
}

type EndpointModelNegotiationRequestV1 = {
  schemaVersion: 1
  format: 'cliq-endpoint-model-negotiation-request-v1'
  ownerPrincipalId: string
  endpointRegistrationRef: ArtifactRef
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  credentialGrantRefs: ArtifactRef[]
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
  model: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  protocol: 'cliq-model-capability-query-v1'
  requestedClaims: [
    'nativeToolCalling',
    'constrainedOutput',
    'streaming',
    'trustedUsageEvidence',
    'contextLimitTokens',
    'maxOutputTokens'
  ]
  requestDigest: string
}

type EndpointModelNegotiationResponseV1 = {
  schemaVersion: 1
  format: 'cliq-endpoint-model-negotiation-response-v1'
  requestRef: ArtifactRef
  requestDigest: string
  protocol: 'cliq-model-capability-query-v1'
  claims: NormalizedModelCapabilityClaimsV1
  observedAt: string
  validThrough: string
  responseDigest: string
}

type EndpointModelNegotiationReceiptV1 = {
  schemaVersion: 1
  format: 'cliq-endpoint-model-negotiation-v1'
  ownerPrincipalId: string
  endpointRegistrationRef: ArtifactRef
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  credentialGrantRefs: ArtifactRef[]
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
  model: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  normalizedRequestRef: ArtifactRef
  normalizedRequestDigest: string
  redactedResponseRef: ArtifactRef
  redactedResponseDigest: string
  claims: NormalizedModelCapabilityClaimsV1
  observedAt: string
  validThrough: string
  receiptDigest: string
}

type ModelCapabilityEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-model-capability-evidence-v1'
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu' | 'ollama'
  model: string
  endpointIdentityDigest: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  source:
    | {
        kind: 'signed_catalog'
        runtimeBundleRef: ArtifactRef
        catalogEntryRef: ArtifactRef
        catalogEntryDigest: string
      }
    | {
        kind: 'registered_endpoint_negotiation'
        endpointRegistrationRef: ArtifactRef
        negotiationReceiptRef: ArtifactRef
        negotiationReceiptDigest: string
      }
    | {
        kind: 'managed_local'
        localInferenceServiceSpecRef: ArtifactRef
        localInferenceServiceSpecDigest: string
        localModelManifestRef: ArtifactRef
        localModelManifestDigest: string
      }
  nativeToolCalling: boolean
  constrainedOutput: boolean
  streaming: boolean
  trustedUsageEvidence: boolean
  contextLimitTokens: number
  maxOutputTokens: number
  observedAt: string
  validThrough: string
  evidenceDigest: string
}

type LocalInferenceBoundaryEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-local-inference-boundary-v1'
  ownerPrincipalId: string
  serviceId: string
  serviceSpecRef: ArtifactRef
  serviceSpecDigest: string
  serviceLaunchId: string
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  executableId: string
  executableDigest: string
  modelManifestRef: ArtifactRef
  modelManifestDigest: string
  processContainmentRef: ArtifactRef
  containmentPlanRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  backend: 'macos_vm' | 'linux_namespace'
  externalNetworkEgress: 'denied'
  loopbackOnly: true
  stableServiceIdentityDigest: string
  inspectorSupervisorInstanceId: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  validThrough: string
  evidenceDigest: string
}

type LocalZeroCostProvenanceV1 = {
  schemaVersion: 1
  format: 'cliq-local-zero-cost-v1'
  ownerPrincipalId: string
  provider: 'ollama'
  model: string
  serviceSpecRef: ArtifactRef
  serviceSpecDigest: string
  stableServiceIdentityDigest: string
  endpoint: { scheme: 'http'; host: '127.0.0.1' | '[::1]'; port: number }
  endpointIdentityDigest: string
  boundaryEvidenceRef: ArtifactRef
  boundaryEvidenceDigest: string
  capabilityEvidenceRef: ArtifactRef
  capabilityDigest: string
  createdAt: string
  validThrough: string
  provenanceDigest: string
}

type ModelPriceTableV1 = {
  schemaVersion: 1
  format: 'cliq-model-price-table-v1'
  signerKeyId: string
  signatureAlgorithm: 'ed25519'
  signatureRef: ArtifactRef
  provider: RunAssemblyV1['provider']['name']
  model: string
  endpointIdentityDigest: string
  currency: 'USD'
  unit: 'micros_per_million_tokens'
  prices: {
    input: number
    output: number
    cacheRead: number
    cacheWrite: number
  }
  validFrom: string
  validThrough: string
  tableDigest: string
}

type ModelPricingBound =
  | {
      kind: 'zero_cost'
      maxRunCostMicros: 0
      provenanceRef: ArtifactRef
    }
  | {
      kind: 'trusted_price_table'
      priceTableRef: ArtifactRef
      priceTableDigest: string
      calculationAlgorithm: 'cliq-price-ceil-v1'
      maxRunCostMicros: number
      validThrough: string
      provenanceRef: ArtifactRef
    }
```

Capability claims are source-derived, not adapter assertions. `ModelCapabilityEvidenceV1` repeats the exact six `NormalizedModelCapabilityClaimsV1` fields from either a signature-valid `SignedModelCatalogEntryV1`, a secret-free `EndpointModelNegotiationReceiptV1` bound to the immutable registration/identity/TLS target, or the exact signed `LocalModelManifestV1.claims`. Catalog, receipt, model-manifest, and evidence digests/signatures use the canonical RFC projections; provider/model/endpoint/adapter/validity and every claim match byte-for-byte. A managed-service health probe may confirm but never widen its signed model claims. The managed-local branch additionally requires the exact WP06 `LocalModelObjectClosureV1`: its current StateRoot/store identity and all-and-only signed manifest/tokenizer/model-file objects rehash, and admission copies that complete closure to the expected WP01 CAS refs before provider selection or launch. For endpoint negotiation, fixed Supervisor code publishes the exact normalized request before I/O. The receipt's request decodes exact `EndpointModelNegotiationRequestV1`: same owner/endpoint/TLS/provider/model/adapter, fixed `cliq-model-capability-query-v1`, byte-identical byte-sorted unique credential-binding sequence, and the literal ordered six-claim tuple. Each binding revalidates its frozen authority/service revision, secret generation, external subject, target, purpose, owner, expiry, and revocation before broker redemption. This query is a bounded read-only, nonbilling, nonmutating lookup that cannot submit model input or provider work and rejects every redirect; after a crash before complete response/receipt publication, repeating the identical safe read is the only legal recovery. It is not a Run Journal attempt and creates no reservation; partial/orphan artifacts never authorize a claim and remain GC-eligible. Its redacted response decodes exact `EndpointModelNegotiationResponseV1`, repeats that request pair/protocol, contains the complete six claims plus validity and nothing else, fits 1 MiB JCS, and supplies the receipt claims byte-for-byte. Self digests omit themselves. Credentials/cookies/headers/diagnostics/unparsed extensions/default-filled claims never enter the response or elevate a claim. Unknown, expired, unsigned, omitted, or mismatched source evidence yields text-only capability, never an inferred autonomous mode.

For local zero cost, the port is an integer in `1..65535`, `endpointIdentityDigest = SHA-256(JCS(endpoint))`, and evidence/provenance digests omit only themselves. The canonical `stableServiceIdentityDigest` covers owner/service/spec, RuntimeBundle entry, model manifest, backend, no-egress, and loopback-only fields; provenance and every dynamic boundary observation repeat it. Every boundary observation's inspector ref/digest decodes the exact canonical `SupervisorInspectorIdentityV1`, matches its instance id and current active `StateOwnerRecordV1`, and is within the five-second freshness bound; a bare Supervisor id is invalid. The provenance retains its admission-time boundary evidence for audit, while every dispatch accepts a current active launch only when fresh boundary evidence has the same stable digest and service spec. A death-proven replacement may change launch/containment/plan/SandboxLaunch/inspector/observation fields but never the stable projection. Both validity intervals cover `Run.deadlineAt`, and assembly endpoint/pricing refs are identical. A raw or third-party Ollama URL, loopback alone, or a daemon that could proxy billable traffic is neither local-zero-cost provenance nor an admissible registered HTTPS endpoint.

Pricing eligibility is orthogonal to `native-tools | constrained-ir | text-only`. Apart from the exact local-zero-cost case, every billable model call requires `trusted_price_table`. A `ModelPriceTableV1` has nonnegative safe-integer prices; `tableDigest = SHA-256(JCS(table with tableDigest and signatureRef omitted))`, and `signatureRef` is a valid Ed25519 signature of that digest by a bundled Cliq trust-root key. Provider, model, endpoint identity, currency, and all four component units match exactly; its interval covers admission through `Run.deadlineAt` without wildcard or mutable alias. The pricing bound repeats its ref/digest/validity and fixes `calculationAlgorithm='cliq-price-ceil-v1'`. There is no executable pricing artifact, callback, plugin, caller-selected pricing implementation, or provider-hard-cap branch.

Provider/runtime adapter identity is likewise durable. The `RunAssemblyV1` provider adapter id/version/code digest resolves byte-for-byte to a signed `RuntimeBundleManifest` entry with role `provider_adapter`; every selected built-in tool adapter resolves to a `tool_adapter` entry. Recovery loads only those pinned entries, never a mutable package that happens to share a semantic version.

`cliq-price-ceil-v1` computes each component as `ceil(tokens * microsPerMillion / 1_000_000)` with checked safe-integer arithmetic for input, output, cache-read, and cache-write tokens, then checked-adds the four components. For exact prompt count `N` and maximum output `O`, every request stores/reserves `(N,O,N,N)`, model tokens `N+O`, and that exact cost; every released/possibly-released model outcome consumes the full reservation, while exact no-release evidence consumes zero. Usage/cache telemetry never lowers it.

Kernel Cut accepts no caller-supplied price table, repository price configuration, mutable pricing implementation, hidden adapter override, provider-cap creation, or remote endpoint labeled zero-cost. Unknown, incomplete, unsigned, arithmetically unsafe, expired, or deadline-short price evidence fails before Run creation with `MODEL_COST_UNKNOWN`; it never falls back to an unaccounted text-only call.

#### 3. Constrained Agent IR

Constrained mode is allowed only when the provider API enforces a JSON Schema or grammar. The schema represents the same completed-turn semantics, including a final message or an ordered non-empty tool-call array whose names and inputs are restricted to the current registry schemas.

Parsing API-constrained output is transport decoding, not free-text action parsing. The provider adapter must reject responses when enforcement was not actually requested/acknowledged. Markdown fences, leading prose, best-effort extraction, string repair, or schema-less `JSON.parse` of assistant content are forbidden.

#### 4. Tool contract

Replace the central action union with a direct-input definition:

```ts
type ToolDefinition<TInput extends Record<string, unknown>> = {
  name: string
  access: ToolAccess
  replayClass: ReplayClass
  description: string
  inputSchema: JsonSchema
  parseInput(value: unknown): TInput
  execute(input: TInput, context: ToolContext): Promise<ToolResult>
  approvalSubject(input: TInput): ApprovalSubjectInput
  preview(input: TInput): string
}
```

`parseInput` is the runtime validator and must reject arrays, missing/extra fields, invalid enums/ranges, and unsafe shapes consistently with `inputSchema`. The registry resolves by exact tool name and returns a validated `ToolInvocation`. Policy, events, loop detection, and TUI previews use that invocation; they must not re-parse raw provider data. Repository command hooks receive nothing because they do not exist in the new runtime.

Initial replay classes are explicit:

- read/search/skill resource tools: `retry`;
- private-workspace `edit` and sandboxed `bash`: `workspace-rollback-retry`;
- plan/progress tools: `retry` only after their writes use the invocation `opId`/`callId` idempotently;
- MCP tools: work package 6's explicit user registry supplies frozen tool-schema and `retry`/`reconcile`/`manual` metadata; live repository annotations are ignored and missing metadata defaults to `manual`, never `retry`.

Replay class does not grant permission. Existing Workspace Trust and policy composition still decide whether a validated invocation may execute.

#### 5. Complete batch semantics

For every completed model turn:

1. preserve provider order and assert indexes are contiguous from zero;
2. normalize native call identity, then verify every id is present and unique: OpenAI, Anthropic, OpenRouter, OpenAI-compatible, and Zhipu require provider-native ids, while managed Ollama ignores an optional wire id and sets `callId = base64url(SHA-256(JCS({protocol:'cliq-ollama-native-call-v1',runId,opId,attempt,index})))` from the claimed attempt and contiguous response index; a missing/duplicate required native id or any post-normalization collision is a response-level `MODEL_PROTOCOL_ERROR`, executes no tool, persists no assistant tool-call turn, and returns no fabricated tool-result batch;
3. resolve and validate every tool call before executing any call;
4. if every call has a valid identity but any tool name or input is invalid, execute none; atomically persist the complete typed assistant call batch plus an error result for each invalid call and `batch_not_executed` results for the remaining ids, keep `nextStep='agent'`, then return that durable ordered batch to the model;
5. otherwise persist/emit the whole typed assistant turn once and atomically set `nextStep='tool'`;
6. process calls sequentially, running permission/execution/result handling independently for each call; each committed result makes the first result-less typed call the durable next index, and a successful workspace-mutating result uses work package 01's atomic post-effect Checkpoint commit rather than a standalone result append;
7. preserve an error/denial result and continue to later calls unless Run cancellation or an explicit durable wait stops the worker;
8. append one result per call id in order;
9. after the final result, atomically set `nextStep='agent'` and make one subsequent model request containing the assistant call batch followed by all ordered results.

Do not use `Promise.all` for tool execution. If a future provider marks calls as parallel, preserve their returned order and still execute sequentially. Real parallelism is a child-Run operation.

Cancellation before a call means that call and all later calls are not executed. Once the current invocation is terminal-quiescent, the state service atomically appends `cancelled` results for every undispatched remaining call and closes the batch before terminal stop. Work packages 1, 4, and 5 persist the exact frontier/waiting state; this package must expose the current batch index and call id rather than hiding them in a closure.

Model dispatch uses `ReplayClass='retry'` only with a worst-case token/cost reservation committed with its `prepared` fact. If a response and provider usage cannot be recovered, recovery charges the complete reservation before creating a new model attempt. A provider-specific idempotency/status lookup may reconcile first, but no adapter may replay an unknown model request while refunding its possible cost. Provider retry events are not hidden HTTP loops: every redispatch is a newly committed contiguous Journal attempt with a fresh reservation, including an SDK-local claim that zero request bytes left the process. Kernel Cut fixes exactly three dispatched attempts, delays `[500ms,2000ms]`, and zero same-attempt transport retries; only the separately typed, integrity-bound dependency GET subrequest may use its exact bounded internal retry rule.

#### 6. Provider adapters and streaming

Each of the six adapters must pass one shared conformance suite for:

- non-streaming final text;
- streaming text/reasoning deltas;
- one and multiple native tool calls;
- interleaved streaming argument fragments;
- stable call ordering and ids;
- usage and stop-reason normalization;
- abort propagation;
- malformed arguments and malformed/missing ids;
- negotiated text-only behavior;
- capability mismatch with no semantic fallback.

The core runner imports only the provider-neutral `ModelClient`/Agent IR interface. Provider-specific response types, endpoint details, SSE event names, and compatibility flags stay below the adapter boundary.

Reuse existing code:

- Reuse current provider HTTP, timeout, SSE, authentication, model selection, and catalog infrastructure.
- Reuse current JSON Schema tool descriptions and the model-visible registry.
- Reuse policy decision tables, approval modes, tool result normalization, doom-loop detection, and the typed `RuntimeEvent` seam after converting their input from `ModelAction` to `ToolInvocation`. Do **not** reuse legacy Session compaction as Run compaction; implement the RFC-exact `RunContextCompactionPlan`/`RunContextCompactionItem` reducer and ContextManifest/Checkpoint transaction. Do not reuse repository command-hook execution.
- Reuse existing provider streaming fixtures, expanding them to multiple calls and malformed later calls.

Preserve / do not touch:

- Workspace Trust before repo-controlled configuration.
- Tool Permission as an independent layer from model capability.
- Sandbox/broker ownership of actual effects; this work package does not make current Bash safe.
- JSON for configuration, RPC/JSONL, SQLite payloads, tool arguments, constrained transport, and artifacts.
- Existing user-visible provider ids, auth configuration, model picker, and text-only chat ability.
- Current headless/TUI wire schemas until work package 6 performs the explicit versioned cutover.

### Acceptance Criteria

- [ ] `src/protocol/agent-ir.ts` defines provider-neutral deltas, completed turns, tool calls, validated invocations, usage, stop reasons, and typed errors without provider wire types.
- [ ] Capability negotiation uses positive adapter + model evidence, freezes provenance/mode into assembly input, and maps unknown capability to `text-only`.
- [ ] Every autonomous capability bit/limit is the byte-equal projection of one signature-valid `SignedModelCatalogEntryV1`, endpoint/TLS-bound secret-free `EndpointModelNegotiationReceiptV1`, or signed `LocalModelManifestV1.claims`; an endpoint receipt decodes exact fixed-query request and closed six-claim response artifacts whose request/target/adapter/times/claims all match. The request repeats the exact frozen credential bindings, is published before I/O, and maps only to a bounded read-only/nonbilling/nonmutating/no-redirect query; crash recovery may repeat only those identical bytes and no partial/orphan artifact has authority. Raw responses, cache entries, health probes, provider names, omitted claims, and adapter defaults cannot widen it. Digest/signature/claim/validity/endpoint/adapter mismatches fail closed and recovery revalidates the same retained source.
- [ ] All six current providers pass the same conformance suite and no provider name is switched on inside the core runner; Ollama conformance uses only the signed managed `local_inference` service, while raw/user-managed loopback endpoints are rejected.
- [ ] Managed Ollama conformance rehashes the complete `LocalModelObjectClosureV1`, rejects any package/store/manifest/tokenizer/model-file count, path, size, ref, or digest drift, and launches from the exact read-only `/models` mount/argv projection; no adapter-local model path, mutable cache, caller-selected service field, or ambient Ollama default participates.
- [ ] `openai-compatible`, OpenRouter routes, unavailable Ollama discovery, and Zhipu do not receive autonomous tool capability from transport/name alone.
- [ ] Provider request rejection or response-shape violation produces a typed capability/protocol failure and never falls back to assistant-text action parsing.
- [ ] `RunSpec.assemblyRef` resolves only to canonical `RunAssemblyV1`; `assemblyDigest` equals SHA-256 over RFC 8785/JCS with itself omitted, unknown fields fail closed, arrays satisfy their exact uniqueness/order rules, and every referenced byte/digest is revalidated before admission and recovery.
- [ ] Every eligible provider/model has exactly one signed `provider_request_profile` structured root. Fixed Supervisor code reproduces all 8..64 source-JCS/body-byte/token-count golden vectors, publishes exact secret-free `ProviderNativeRequestBodyV1` before the Journal request, and requires normal/compaction request native-body pairs, profile/path/source/input-token fields, complete body bytes/digest/count, and omission digests to match. The broker transmits only those retained bytes plus authorized headers; adapter/SDK reserialization, hidden defaults/messages/tools/schemas, redirect rewriting, and post-hash mutation fail before provider I/O or recovery acceptance.
- [ ] `mcpServers` is byte-sorted by registration id and contains exactly one entry for every uniquely requested MCP server and no other entry. Each `registryRevisionRef`, numeric revision, and manifest digest resolves to the same immutable retained registry revision; refresh/rebinding cannot change an admitted assembly.
- [ ] `assembly.tools.manifestRef` resolves to `ToolContractManifestV1` and `assembly.tools.manifestDigest` equals that artifact's recomputed digest. Its entries are byte-sorted by globally unique exposed name; every built-in entry matches its retained adapter identity and has only `manual|retry` replay (never `reconcile`), while every MCP entry matches exactly one selected registry revision's server tool name, schema, recovery contract, digest, and byte-identical `manual|retry|reconcile` recovery kind. Collisions are rejected rather than renamed/shadowed; provider `exposedToolNames` is exactly this ordered name sequence for native/constrained mode and empty for text-only, while retry entries have the same ordered names and replay classes.
- [ ] `instructions.systemPromptRef/systemPromptDigest` and `workspaceInstructionsRef/workspaceInstructionsDigest` resolve and match exactly. `WorkspaceInstructionManifestV1` exists even when empty and points to exact `WorkspaceInstructionSourceManifestV1`: after Workspace Trust a held-root no-follow scan captures the all-and-only accepted `AGENTS.md` descriptor/content observations into a context-only closure that never enters SourceManifest/generation/result/publication authority. Entry/source/content omission digests, byte-identical `ModelTextV1`, root-to-deep contiguous order, workspace identity, literal all-scopes-labeled renderer, and 64-entry/1-MiB bounds all revalidate. Selected `SkillManifestV1` artifacts preserve explicit request order, unique `(sourceScope,skillId)`, reject duplicate unqualified ids, and require exact `SkillSourceIdentityV1` plus byte-sorted all-and-only `SKILL.md`/resource closure. Workspace/user sources bind authenticated identities plus held owner-only root capture; bundled sources bind an acyclic signed non-executable `skill_bundle` RuntimeBundle entry and exact `BundledSkillClosureV1`; every omission digest/ref/content equality is recomputed. Recovery never rereads mutable `AGENTS.md`, `SKILL.md`, user/bundle install directories, or resource paths.
- [ ] Provider/context equality is exact: `provider.negotiation.contextLimitTokens === context.contextLimitTokens`, `1 <= context.reservedOutputTokens <= provider.negotiation.maxOutputTokens`, every normal model request uses exactly that reserved output cap, and mode/tool exposure agrees with the negotiation booleans. Only exact `LocalZeroCostProvenanceV1` for a signed `local_inference` entry/no-egress boundary has zero model credential refs and `pricing.kind='zero_cost'`; endpoint/pricing refs are identical and dispatch revalidates the live instance/model. Every billable endpoint is `registered`; a `bundled_default` is billable enrollment provenance and has nonempty exact endpoint/identity/TLS/authority/service-revision/secret-generation/external-subject-matched model credential bindings. A rotation or subject/scope change blocks the old binding before I/O.
- [ ] `RunSpec.credentialGrantRefs` is the byte-sorted unique union of the provider assembly's model-endpoint bindings, `DependencyPolicy.credentialGrantRefs`, and every selected streamable-HTTP MCP revision's credential bindings, with no missing or extra ref. Admission and recovery recompute the union; it is a GC/audit index and never independent dispatch authority.
- [ ] RunSpec, every ContextManifest/Checkpoint, normal/compaction model request, worker launch, and recovery closure resolve the identical assembly ref. CAS retention roots its complete immutable graph—including pricing/local-inference provenance, endpoint/credential bindings, selected MCP revisions, tool schemas/adapters, system/workspace instructions, skills/resources, prompt/tokenizer/compaction inputs, runtime bundle, worker executable, and required guest toolchain—until no authoritative Run/audit/result reference remains; recovery never substitutes a mutable current registry, file, package, or executable. The generated public control schema remains governed by the literal protocol/schema versions and compatibility ranges rather than an unproduced Run-scoped digest. Provider and built-in adapter id/version/digest resolve byte-for-byte to signed `provider_adapter|tool_adapter` RuntimeBundle entries.
- [ ] `ModelPricingBound` is closed: `zero_cost` requires exact `LocalZeroCostProvenanceV1`, `endpointIdentityDigest=SHA-256(JCS(endpoint))`, matching signed service/model/boundary evidence, validity through the deadline, and `maxRunCostMicros=0`; `trusted_price_table` requires a digest-valid bundled Cliq-signed `ModelPriceTableV1`, exact provider/model/endpoint/four-component coverage, `calculationAlgorithm='cliq-price-ceil-v1'`, `maxRunCostMicros === RunSpec.budgets.costMicros`, and `validThrough >= Run.deadlineAt`. No raw-loopback assertion, provider-hard-cap branch, executable pricing ref/plugin, caller-supplied/repository/hidden-config/adapter price authority, missing unit, wildcard, expired evidence, or unsafe arithmetic is accepted; failures return `MODEL_COST_UNKNOWN`.
- [ ] A missing/dead managed Ollama service before a model claim never enters provider SDK retry or an implementation-chosen queue. The exact Run frontier joins the one durable activation cycle after worker quiescence; success re-enables that unchanged frontier, while bounded cycle failure produces `local_inference_unavailable` with exact cycle/service/frontier/failure evidence. No ambient endpoint, third launch, or hidden retry is reachable.
- [ ] `cliq-price-ceil-v1` performs checked safe-integer `ceil(tokens * microsPerMillion / 1_000_000)` independently for input/output/cache-read/cache-write and checked-adds the results. Every model request binds exact `(N,O,N,N)` component maxima, `N+O` model tokens, and cost under its digest; released/possibly-released outcomes consume that full reservation, exact no-release proof consumes zero, and telemetry never reduces it or becomes zero by omission.
- [ ] No autonomous code path imports or calls `parseModelAction`, `repairJsonStrings`, `buildTextActionFallbackInstructions`, or a `text-action` request mode.
- [ ] Assistant text such as `{"bash":"rm -rf ..."}` from a text-only provider remains text and cannot execute a tool.
- [ ] Tool definitions accept direct validated input, declare one `ReplayClass`, and no longer depend on a central `ModelAction` union.
- [ ] Tool schema and `parseInput` conformance tests reject missing, extra, incorrectly typed, out-of-range, and unsafe arguments for every built-in tool.
- [ ] Policy subjects, loop signatures, records/items, UI previews, and trusted `RuntimeEvent` observers use the same validated `ToolInvocation`; none reparses provider payloads, and no repository command-hook callback remains in the runtime.
- [ ] A model response containing N valid calls processes all N in index order; each authorized claimed call dispatches at most once, denial/cancel prevents its execution, and every call receives exactly one identity-matched result before the next model request.
- [ ] A committed assistant call batch sets `nextStep='tool'`; each durable result advances the first result-less typed call, and only the complete batch returns to `nextStep='agent'`.
- [ ] Every durable turn publishes exact `ModelTextV1` and schema-normalized `ToolCallInputV1` artifacts before its `AgentModelTurn`; model/batch text refs and every ordered call ref/digest are byte-identical, and policy/grant/Journal/dispatch all decode the same input artifact. Every ordinary ToolResult decodes exact outcome-matched `ToolResultPayloadV1`; only fenced retry-unknown uses its dedicated direct artifact.
- [ ] No terminal commit has an unclosed ToolBatch call or open typed continuation. Normal calls close with ToolResult, the sole terminal manual-abandon call closes with ToolAbandoned, and a fenced retry-unknown closes with its typed cancelled result; cancellation/deadline/failure atomically close only undispatched remaining calls after the current invocation is terminal-quiescent.
- [ ] Verified/unverified completion requires the latest operation-appropriate `FinalCandidateItem`, and its exact `resultSourceRef` equals the committed RunResult; truncated/filtered/cancelled/unknown model stops cannot create it.
- [ ] `ModelTurnItem.abortStopIntentRef` is required and equals the decoded `AgentModelTurn.abortStopIntentRef` member only for `stopReason='cancelled'`; it is forbidden for `end|tool_calls|length|content_filter|unknown`, so a provider cancellation cannot fabricate Cliq stop authority.
- [ ] Every successful workspace-mutating result is inseparable from its post-effect ready Checkpoint; fault injection never reconstructs completed ToolResult context over a pre-effect workspace.
- [ ] Terminal batch validation accepts exactly one ToolResult per call except the single terminal manual-abandon `ToolAbandonedItem` case; a fenced retry-unknown uses the typed cancelled-result closure and cannot continue or succeed.
- [ ] Context compaction enforces the exact admission inequalities and integer `H/T/R/S/K/P` equations, tokenizes one canonical projection, protects fixed/live/recent context, selects the greatest legal segment boundary, and reduces projected context by at least 512 tokens per success. No legal range yields typed `context_window_exhausted` without dispatch; it never splits/truncates an item or loops. Bounded complete Markdown in text-only mode commits plan/item/context manifest/ready Checkpoint atomically; raw items remain durable and executed protocol-invalid compaction fails without semantic retry.
- [ ] The state store enforces one open `ToolBatchItem`, identity-matched `ToolResultItem` rows, and exact Journal/`waitingOnRef` agreement; recovery after every call boundary selects the same next index without a worker-memory cursor.
- [ ] No in-response tool batch executes via `Promise.all` or concurrent workspace mutation.
- [ ] Every call in a batch is validated before the first tool executes.
- [ ] If call N has a valid unique id but its tool name or input is malformed/unknown, zero calls in that batch execute and the model receives one ordered result for every call id.
- [ ] Every positively received malformed, oversized, mode-incompatible, provider-rejected, or compaction-invalid model response closes Journal `completed` with exact `ModelUnusableResponseV1` (`provider_rejected_response` for a target rejection), full request-reservation settlement, matching request/claim/raw-byte evidence, and the same runtime StopIntent evidence/error ref; it produces no `AgentModelTurn`, Run item, batch, candidate, or summary and is never semantically retried. Journal `failed` never claims a provider response.
- [ ] An identifiable invalid batch persists its assistant call item and every synthetic error/`batch_not_executed` result atomically before the next model request; no result can exist without its assistant call batch.
- [ ] A denied/error call retains its error result and later valid calls continue unless cancellation or a durable wait explicitly stops execution.
- [ ] Native missing/duplicate call ids produce a response-level `MODEL_PROTOCOL_ERROR` before assistant-turn persistence or execution; no synthetic tool results are invented. The sole missing-wire-id exception is managed Ollama: it ignores any optional wire id and derives the exact SHA-256/JCS call id from Run/op/attempt/index, so recovery of the same attempt is stable and a new attempt cannot alias it. Constrained call ids are deterministic from invocation identity and index.
- [ ] Streaming adapters reconstruct multiple interleaved calls without reordering or losing argument fragments.
- [ ] Text/reasoning deltas, usage, retry, stop reason, provider error, and cancellation are normalized into typed events.
- [ ] Every provider retry event names a newly committed Journal attempt/reservation; adapters contain no hidden same-attempt redispatch. Tests enforce the assembly-literal three dispatched attempts, zero same-attempt transport retries, fixed `[500ms,2000ms]` delays, rejection of any `Retry-After` schedule override, deadline truncation, and runtime failure on exhaustion; only the exact dependency integrity GET exception has its separately tested internal retry bound.
- [ ] The model prompt contains no instruction inviting free-text JSON action output.
- [ ] `src/protocol/model/actions.ts` and `json-repair.ts` are absent from production after the legacy importer can preserve their historical payloads opaquely.
- [ ] Existing `npm run build` and `npm test` remain green.

### Validation

Automated:

- Add and run `npm run test:agent-runtime`, covering `src/protocol/agent-ir.test.ts`, capability tests, all provider tests, tool registry/schema tests, policy/event integration, context reconstruction, and runtime batch tests.
- Run `npm run build`.
- Run `npm test`.
- Add a static import test requiring zero production imports of `src/protocol/model/actions.ts` and `src/protocol/model/json-repair.ts` after cutover preparation.
- Add a source assertion that `completion.toolCalls?.[0]`, `parseModelAction`, `repairJsonStrings`, `TEXT ACTION FALLBACK MODE`, and `ModelRequestMode='text-action'` do not exist in production runtime/model code.
- Add table-driven capability tests for every provider/model evidence combination: native, constrained, unknown, misreported, and provider rejection.
- Add canonical `RunAssemblyV1` graph tests covering selected MCP revision equality, global tool-name/schema/recovery matching, provider exposed-tool/retry equality, required empty/nonempty workspace-instruction manifests, ordered skill/resource closure, provider/context limit equality, exact credential union, and full CAS reachability/GC roots. Each one-field mismatch, collision, extra/missing credential, mutable rebind, unknown field, or missing transitive artifact fails admission and recovery.
- Add deterministic pricing fixtures for locally verified `zero_cost` and bundled Cliq-signed `ModelPriceTableV1` plus `cliq-price-ceil-v1`. Reject caller-supplied/repository/adapter price authority, any executable pricing ref/plugin, provider-cap branch, wrong signature/provider/model/endpoint/unit/cache table, `validThrough < Run.deadlineAt`, unsafe multiply/add arithmetic, and a remote model claiming unverifiable zero cost with `MODEL_COST_UNKNOWN` before dispatch.
- Add endpoint fixtures proving `bundled_default` resolves to a billable `registered` endpoint with exact nonempty model credential bindings, while only `local_zero_cost` admits an empty binding set. Reject credentialless bundled defaults and credential-bearing local-zero-cost assemblies.
- Add a shared provider fixture that returns three calls with interleaved streaming deltas and assert stable ids, indexes, inputs, results, and one follow-up request.
- Add a batch fixture with a malformed second call and spies proving no tool in the batch executed.
- Add a text-only fixture whose assistant text is valid legacy action JSON and assert it is emitted/stored only as text.

Manual:

- Run one known-capable model for each configured provider and inspect the frozen negotiation mode/evidence plus a two-tool response.
- Run an unknown custom OpenAI-compatible model and verify Cliq reports `text-only`, advertises no tools, and never interprets returned JSON-looking text as executable.
- Disable or falsify a provider capability in a test config and confirm the Run fails closed with a capability/protocol error rather than switching modes.
- Admit a Run whose deadline is just inside signed-table validity, then move it one second past validity and verify the latter fails `MODEL_COST_UNKNOWN`. Confirm a local zero-cost model passes only with independently verified local provenance and confirm a bundled-default remote endpoint still requires its registered credential binding.
- Exercise a provider stream that emits text plus multiple tool calls and verify the UI order matches the provider order while execution remains sequential.

### Risks And Dependencies

- Provider aggregators and OpenAI-compatible servers frequently overstate compatibility. Positive per-model evidence, frozen provenance, no runtime downgrade, and text-only fallback contain this risk.
- Provider streaming formats differ in argument-fragment ordering and completion markers. The shared conformance suite must test each adapter's real wire fixtures, not only normalized mocks.
- Removing free-text fallback intentionally removes autonomous tools for Zhipu and unknown/custom models until positive capability evidence exists. Text-only operation remains supported; silently restoring the parser is not an acceptable compatibility fix.
- Signed pricing evidence is long-horizon authority, not mutable configuration. A provider/model price table that does not cover the full Run deadline blocks admission; release tooling must ship timely Cliq-signed `ModelPriceTableV1` updates without mutating admitted assemblies, while the fixed `cliq-price-ceil-v1` ships as retained kernel code rather than referenced executable pricing code. Kernel Cut has no provider-hard-cap pricing path.
- Existing UI/policy tests that assert legacy `action` objects must migrate to `ToolInvocation` without exposing raw unvalidated input. Repository command-hook tests are deleted or replaced by work package 06 diagnostics proving hooks cannot execute; they are not converted into typed hook behavior.
- Work package 1 owns the shared `ReplayClass`, durable RunJournal/frontier transaction APIs, and opaque legacy action import. Work package 3 consumes replay classes and executes tools in a sandbox/broker. Work package 4 owns recovery scheduling/reconciliation. Work package 5 consumes this typed boundary for verifier, child, result, and delivery behavior; it does not add a second Journal or recovery reducer.

Required sequence:

1. Work package 1 lands `src/kernel/types.ts` and an importer that treats historical `action` fields as opaque legacy payloads.
2. This work package may implement capability adapters, Agent IR, and batch execution in parallel, but merges deletion of legacy action/parser files after step 1.
3. Work package 1 binds validated invocations to RunJournal facts and durable batch frontiers; work package 3 binds them to sandbox/broker execution; work package 4 resumes/reconciles them; work package 5 consumes the same contracts for verifier/child/delivery flows.
4. Work package 6 adapts public client protocols and removes any temporary old-runner compatibility path at the single Kernel Cut.

Rollback (hard-to-reverse changes):

- Before Kernel Cut, this is a code-only change: revert the typed runtime/provider commits as one unit if provider conformance fails. Do not re-enable only the free-text parser behind the new runner.
- Capability metadata changes are versioned in the frozen assembly. Correcting metadata creates a new assembly/Run; it never mutates an admitted Run's negotiated mode.
- After Kernel Cut, use the state rollback path from work package 1 before installing an old binary. Do not feed new typed Run items into the old `ModelAction` parser.

### Open Questions

None. A provider or model gains autonomous execution only by adding positive capability evidence and passing the existing conformance suite; that is a compatible metadata/adapter addition, not a product decision.

### GitHub Issue Body

```markdown
## Typed Runtime And Provider Capabilities

Implement work package 2 of the Durable Verified Run Kernel RFC.

### Outcome

Cliq executes tools only through negotiated native or schema/grammar-constrained Agent IR, handles every returned tool call deterministically, and treats providers without positive capability evidence as text-only.

### Required contract

- Add provider-neutral Agent IR and deterministic capability negotiation for OpenAI, Anthropic, OpenRouter, OpenAI-compatible, Zhipu, and Ollama.
- Remove free-text JSON `ModelAction` parsing/repair and all semantic fallback to it.
- Refactor tools, policy, context, events, and previews around validated `ToolInvocation` inputs and explicit `ReplayClass`; do not port repository command hooks.
- Validate an entire returned tool batch before execution, then execute every call sequentially in provider order and return all ordered results together.
- Fail closed on missing/misreported capability; never infer autonomous support from provider name alone.
- Freeze and validate the complete canonical `RunAssemblyV1` graph: selected MCP revisions, one canonical tool manifest, post-Trust instruction/skill manifests, provider/context equality, exact credential union, and transitive CAS/GC retention.
- Admit billable durable Runs only with a bundled Cliq-signed `ModelPriceTableV1` evaluated by `cliq-price-ceil-v1` through `Run.deadlineAt`. Bundled-default remotes remain registered, credentialed, and billable; only independently verified local zero cost is credential-free. Caller/config/executable/provider-cap pricing is never authority.
- Preserve JSON for schemas/config/RPC/storage; remove only arbitrary assistant text as the control protocol.

### Validation

- `npm run build`
- `npm test`
- `npm run test:agent-runtime`

Use `docs/backlog/durable-verified-run-kernel/02-typed-runtime-and-provider-capabilities.md` as the complete implementation and acceptance contract.
```
