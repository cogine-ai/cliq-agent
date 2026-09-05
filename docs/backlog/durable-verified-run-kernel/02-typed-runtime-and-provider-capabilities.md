# Typed Runtime And Provider Capabilities

## Backlog Ready Spec

### Verdict

READY WITH RISKS

WP02 is one program with two review gates: trusted model attempt (A), then
typed runtime continuation (B). There are no smaller product slices.
Autonomous execution uses native tools only. Text-only models remain usable
for conversation and compaction; schema/grammar-constrained action envelopes
and free-text action parsing are not part of the Kernel Cut.

Remote billing ceilings and live provider compatibility require release
qualification. Offline tests and signed rate metadata alone do not establish
those facts. A model without a credible signed request ceiling is ineligible
for a hard-budget durable Run, even if its native tools work.

### Source and canonical ownership

- Work package 02 of the [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md).
- Product promise: **Delegate. Detach. Return to verified work.**
- Module architecture and current delivery boundaries:
  [WP02 implementation design](../../kernel/wp02-typed-runtime.md).
- [Issue supersession map](./issue-supersession-map.md) prevents duplicate work.
- [Permission issue #62](https://github.com/cogine-ai/cliq-agent/issues/62)
  remains independent; typed invocations do not grant permission.

The RFC is the single normative definition of shared durable schemas:
`RunAssemblyV1`, `NormalPromptProjectionV1`, `ModelRequestV1`,
`AgentModelTurn`, `ModelUnusableResponseV1`, `ToolCallInputV1`,
`ToolBatchItem`, `ToolResultPayloadV1`, `RunContextCompactionPlan`,
`ModelCapabilityEvidenceV1`, endpoint/local-service evidence,
`ModelPriceTableV1`, and `ModelPricingBound`.
This spec imports those schemas rather than maintaining a second copy.
WP01 owns state transitions and reachability; WP02 may not narrow their
evidence, final-candidate, quiescence, recovery or settlement requirements.

### User outcome

Cliq executes tools from negotiated provider-native calls, never from
repairable assistant JSON text. Every identifiable call is retained, validated
and closed in order; a malformed later call cannot disappear or let an earlier
call execute prematurely. Provider differences stay at the model boundary,
while the runtime, policy, context and UI share typed inputs.

Long-running work still has one authoritative Run, journaled external effects,
bounded budgets, reproducible recovery and independently verified completion.
Removing speculative protocol machinery must not weaken those guarantees.

### Problem

The isolated legacy path currently converts native calls back to
`ModelAction`, consumes only `completion.toolCalls?.[0]`, and falls back to
text extraction/repair. Its tool registry, policy subjects and UI share that
central action envelope. The first Gate A implementation also introduced
custom framed prompts, byte-BPE profiles, per-request golden validation and
multiple request wrappers, without establishing that their counts match a
remote provider's billable tokenizer.

The new path must remove both sources of complexity: interpretation of
assistant text as control, and redundant authority/serialization layers.

### Scope

In:

- Immutable assembly loading and one request-bound model session.
- Native request generation and actual incremental observation for OpenAI,
  Anthropic, OpenRouter, OpenAI-compatible, Zhipu and managed Ollama.
- Provider-neutral typed deltas, complete turns, opaque reasoning continuation,
  and closed unusable responses.
- Evidence-based capability selection, endpoint/credential binding, checked
  pricing and honest separation of context estimates from hard reservations.
- Direct tool schemas/parsers, whole-batch validation, sequential execution
  proposals and ordered result continuation.
- Typed policy subjects, loop signatures, context, durable items and trusted
  internal events/UI projections.
- Durable compaction planning and result validation under the existing
  frontier/Checkpoint protocol.
- Focused source guards and conformance/regression tests.

Out:

- Concurrent execution of calls within a response; WP05 child Runs own bounded
  parallelism.
- Durable state ownership, claims, sandbox/broker execution, scheduling or
  crash reconciliation (WP01/03/04). Gate B includes only the necessary WP01
  typed-request and model/tool/compaction commit reducers as companion work;
  those writes remain inside StateStore, never in the WP02 planners.
- New providers, a provider/plugin ABI, executable pricing, provider-cap
  provisioning, repository command hooks, or a replacement hook system.
- Public CLI/TUI/JSONL/RPC schema changes and the composition switch (WP06).
- Exact remote token counting through a home-grown tokenizer.
- Constrained-action or free-text fallback and post-response semantic retries.
- Live billable calls or a claim of release qualification from mocked fixtures.

### Delivery and implementation

Gate A uses `src/protocol/agent-ir.ts` and `src/model/{run-assembly,
model-session,request,provider-observation,attempt,capabilities,pricing}.ts`.
It returns artifact plans and typed results only.

Gate B integrates direct tool input parsers/registry, runtime batch/context
planning, policy subjects, loop detection, and trusted internal event/UI
projections. It consumes Gate A's prepared request and complete turn without
reparsing wire payloads or converting to `ModelAction`.

The old runner stays isolated and unchanged while this work is incomplete.
WP01 imports historical action data opaquely. WP06 deletes the legacy parser,
runner and repository command-hook path at the single Kernel Cut. Neither
gate introduces a typed-to-legacy bridge. Internal commits may aid review,
but do not create extra public milestones.

#### A. Loaded authority and request lifecycle

`validateRunAssembly` snapshots all data before validating its closed schema,
artifact identity, self digest and transitive material. Successful loading
returns a `ModelSession`, not mutable config or caller-selected counting,
rendering or pricing functions.

Evidence must bind the same provider/model/endpoint/adapter/validity.
A catalog source belongs to the retained runtime bundle; managed-local
capability and provenance name the same signed service/model.
The tool resolver loads the exact signed manifest and schema closure, not
independent entries supplied beside a valid manifest hash. Descriptions,
schemas, refs, ordered names and replay policies are frozen together.

The normal public workflow is:
`prepare -> publish/claim -> broker I/O -> start/push/finish -> commit proposal`.
Only WP01/03 perform the steps between preparation and response observation.
The prepared handle is bound to the loaded session, request kind, Run/op/attempt,
assembly, projection, exact body bytes, output cap and reservation. Replacing
or copying it cannot alter response compilation. Recovery reloads retained
authority and re-prepares the retained projection to reproduce the same bytes.

Static verification runs on load/recovery, not per request. Preparation handles
only changing projection/invocation validation, direct typed serialization,
context estimation, hashing and arithmetic. There are no runtime prompt
profiles, BPE vocabulary/ranks, framed fake prompts, native-body wrappers or
golden-vector execution.

`ModelRequestV1` is the sole normal/compaction request artifact. It binds the
exact at-most-1-MiB body, path, mode, projection, maximum output, assembly and
reservation. Compaction additionally binds its plan. The broker sends the
retained bytes verbatim and adds only endpoint-authorized transport/auth
headers. It must not rebuild objects, insert defaults, follow redirects or
retry inside an attempt.

#### B. Capability and pricing

Native support requires both adapter transport support and positive verified
model evidence. Valid false/absent native capability selects text-only;
malformed, unsigned, stale or mismatched evidence fails admission. Streaming
is the intersection of requested, adapter and verified model support.
There is no runtime mode downgrade.

All six adapters support native transport, subject to per-model evidence.
OpenAI uses Responses; Anthropic uses Messages; OpenRouter, OpenAI-compatible
and Zhipu use their explicit Chat Completions mappings; Ollama uses Chat.
OpenAI reasoning items and Anthropic thinking/signature/redacted blocks survive
observation, durable turns and the next request, bound to provider/model.

The canonical endpoint and credential rules remain unchanged. Only exact
Kernel-managed Ollama service/model/no-egress provenance permits credential-free
zero cost. A raw local URL is insufficient. Every billable endpoint, including
a bundled default, is registered and uses exact owner/target/authority/service
revision/secret generation/external-subject credential bindings. The RunSpec
credential list is the sorted unique union required by provider, dependency
policy and selected streamable-HTTP MCP revisions, never independent authority.

A billable request requires a matching signed `ModelPriceTableV1` valid through
the Run deadline. It includes rates and a four-component
`requestTokenCeiling` covering all requests the retained adapter can release,
including rejected/ambiguous outcomes. Its input/output limits cover admitted
context and both normal/compaction output limits; cache maxima are explicit.
Qualification must substantiate that bound. Rate-only metadata, empirical
estimates, unverifiable zero-cost claims and guessed tokenizer counts fail
`MODEL_COST_UNKNOWN`.

Every attempt reserves the full signed vector, independent of prompt estimates.
`cliq-price-ceil-v1` uses checked integers and rounds each component upward
before checked addition. Released/possibly-released outcomes consume the full
reservation; only exact no-release proof consumes zero. Usage is telemetry,
not a refund, authority or missing-as-zero settlement rule. Observed component
and requested-output violations fail closed but cannot undo spend already
incurred. No provider-cap admission effect or executable pricing extension is
introduced.

#### C. Wire observations and central compilation

The same bounded observer serves buffered and incremental callers. UTF-8
fragments, SSE CR/LF framing, interleaved tool arguments and NDJSON records are
handled across chunks. Text/reasoning/tool deltas are delivered before EOF;
they never authorize effects. Final usage/end events are not lost or duplicated.

The compiler preserves every native call in provider order, including missing
names and malformed argument fragments. Mandatory native ids must be present,
bounded and unique before any input resolution. Managed Ollama alone derives
ids from the RFC Run/op/attempt/index projection; it ignores optional wire ids.

`end` requires nonempty text and no calls. `tool_calls` requires calls.
A trusted cancellation requires the exact pre-existing StopIntent and cannot
execute partial calls or overwrite a complete response. Other nonterminal
stops, incompatible modes/shapes, missing/duplicate ids, oversized/malformed
wire responses and provider rejections produce one `ModelUnusableResponseV1`
with exact raw bytes (or exactly limit+1 prefix). They produce no candidate,
summary or call batch and are not semantically retried.

The central compiler creates typed inputs and outcomes. Unknown tools and
invalid inputs remain identifiable rejected calls for Gate B. A missing name
remains empty in durable truth; native replay may use the reserved unexposed
`__cliq_missing_tool_name` placeholder to close the synthetic result.
Object-only provider histories wrap retained malformed/non-object arguments
without repairing them. Tool resolution must use the frozen schema ref/digest.
Already decoded argument values stay typed across continuation; native request
preparation never parses them back from an internal JSON string.

JSON is retained for provider wire, native schemas and canonical persistence.
In-process control uses typed values. JSON-looking assistant text remains inert.

#### D. Typed batches and continuation (Gate B)

Tool definitions expose direct JSON Schema plus `parseInput(unknown)`, typed
execution input and one RFC `ReplayClass`. Schemas and parsers agree on missing,
extra, invalidly typed, unsafe and out-of-range inputs. No central action union
or repository executable hook participates.

Validate every call before dispatching any call. An identifiable invalid batch
commits its assistant item and exactly one ordered synthetic result per call:
invalid calls receive typed errors, the others `batch_not_executed`.
Missing/duplicate mandatory ids reject the response, not a fabricated batch.

A valid batch executes sequentially in provider order. Each claimed operation
dispatches at most once; denied/error calls retain results and later valid calls
continue unless stop or durable wait prevents them. Policy, grant, Journal,
dispatch, loop signature, context and UI all consume the same normalized input.
Workspace Trust still precedes config/assembly; Tool Permission and the OS
boundary remain independent.

The durable frontier, not worker memory, selects the first result-less call.
The next model request includes the complete assistant turn, continuation and
all matching results in order. Terminal state cannot contain an open batch:
ordinary calls close by ToolResult, the single manual-abandon case by
ToolAbandoned, and fenced retry-unknown by its dedicated cancelled result.
Stop drain closes only undispatched calls after current work is quiescent.
A mutating result is committed with its post-effect ready Checkpoint; it can
never be reconstructed over the pre-effect workspace. Completion still
requires the operation-appropriate latest FinalCandidate and matching result
source under WP01/WP05.

#### E. Context and compaction (Gate B)

Retain the RFC integer admission and `C/O/H/T/R/S/K/P` selection policy, but
counts used for context planning are deterministic byte estimates, not exact
remote tokens. Text estimate is `ceil(UTF8 bytes/3)`; normal prompt estimates
include per-message overhead, tools, arguments and continuation. `K` estimates
the actual retained two-message compaction envelope. `O` and `S` independently
fit the provider output maximum; a small normal cap does not invalidate a
larger legal compaction cap.

Protect fixed/live/recent context and choose the greatest legal whole-prefix
boundary. The source estimate is at most `P` and at least `S+512`. Only a
nonempty tools-disabled complete `end` summary of at most
`min(262144,3*S)` UTF-8 bytes is accepted, so each replacement reduces estimated
source content by at least 512 units without custom tokenizer code. Also verify
that the complete prompt estimate decreases including message overhead. Provider output
is requested with cap `S`; reported over-cap output is invalid.

Compaction is a journaled model operation, never an invisible heuristic edit.
Plan/item/manifest/ready Checkpoint publish atomically with unchanged workspace;
raw items remain durable. No legal prefix produces exact
`context_window_exhausted` evidence without dispatch. Executed invalid
compaction produces `context_compaction_failed` and full settlement without
semantic retry. Estimation can undercount a real context; fail explicitly on
provider rejection, never silently truncate, guess successful completion or
restore text-action parsing.

### Acceptance criteria

Gate A:

- [ ] Load/reload validates and freezes the exact closed assembly, evidence,
  endpoint/credential union, tool/schema closure, retry/context equations and
  runtime/guest identities. Every substitution or missing reference fails.
- [ ] Mutating original config or returned request/bytes cannot change prepared
  authority. Forged/cross-session handles are rejected; reload reproduces bytes.
- [ ] No static verification/profile/tokenizer/golden work occurs per attempt.
  Normal preparation emits only body plus common request; compaction adds only
  the required typed projection.
- [ ] All six providers have independently specified native/text-only request
  fixtures and buffered/streamed response conformance. No action fallback exists.
- [ ] Incremental events precede final bytes; complete-call/usage/end events are
  returned once; chunked UTF-8, CRLF, partial streams and terminal contradictions
  are covered.
- [ ] Every call survives normalization. Native ids, missing names, malformed
  input, schema substitution and all stop/call/mode combinations are tested.
- [ ] OpenAI opaque reasoning and Anthropic signatures/redaction survive a
  response-to-next-request regression, without changing provider/model identity.
- [ ] Cancellation requires StopIntent; partial calls cannot resolve/dispatch,
  and a complete response is not rewritten as cancelled.
- [ ] Missing/invalid signed ceilings and unsafe arithmetic fail before release;
  estimates never lower a reservation. Usage is not trusted settlement.
- [ ] Small normal output limits allow independently valid compaction limits.
  Summary byte/output bounds and closed failures are enforced.
- [ ] Artifact refs/digests rehash independently, and source guards prohibit
  legacy imports, JSON repair and direct unbounded wire decoding.
- [ ] Build, focused tests and the existing full suite pass.

Gate B and integration:

- [ ] Every built-in schema/parser conforms; policy, registry, loop detection,
  context, durable items and previews share typed normalized inputs.
- [ ] An N-call response prevalidates all N, executes sequentially and closes
  each identity exactly once before continuation. An invalid later call causes
  zero dispatches and ordered synthetic results for the whole batch.
- [ ] Recovery at every call boundary selects the same result-less index from
  durable state, without replaying completed effects or losing continuation.
- [ ] Stop, wait, denial, manual abandon and retry-unknown preserve the exact
  WP01 batch/quiescence/terminal closure rules.
- [ ] Normal/compaction requests, RunSpec, ContextManifest, Checkpoint and worker
  recovery use the same retained assembly and complete CAS closure.
- [ ] Model attempts use the frozen three-dispatch policy, zero same-attempt
  transport retries and fixed delays; no SDK/Retry-After semantic override.
- [ ] Compaction selection, estimated reduction, explicit exhaustion/failure,
  raw-item retention and atomic checkpoint publication pass fault injection.
- [ ] Typed-runtime source guards expand with integration. Legacy parsing and
  repository command hooks are removed only at WP06's single Kernel Cut.
- [ ] Public adapters and configured live models are qualified in WP06; none of
  the above offline tests substitutes for those release checks.

### Validation

Run `npm run test:agent-runtime`, `npm run build`, and `npm test`.
Gate A's focused command exercises the real loaded-session seam plus strict
wire, compiler, evidence and pricing edge cases. Extend it in Gate B with
tool/schema, policy/event, batch, context and state-boundary integration.

Use fixed wire fixtures with expected bytes independent of the serializer,
not golden vectors generated from the implementation under test. Include
multi-call follow-up requests, malformed later calls, streaming/cancellation,
authority mutation, reload, capability drift, signed ceiling limits and exact
no-release versus possibly-released settlement at integration boundaries.

Live manual qualification belongs to release integration: use each configured
provider/model, check native continuation and UI order, confirm text-only
unknown models never execute JSON text, and substantiate signed capability,
pricing and billing-ceiling validity. This task does not authorize paid calls.

### Risks, dependencies and rollback

Conservative full-vector reservations can reduce useful work for a small
budget; that is preferable to claiming a hard bound from a heuristic. A
provider lacking authoritative request billing bounds is not hard-budget
eligible. This is an explicit release constraint, not solved by signing a guess.

Aggregators/custom servers can misreport capabilities and streaming behavior.
Exact provenance and fail-closed observations contain runtime authority risk;
conformance fixtures do not prove every deployed endpoint implementation.

WP01 owns durable state/import and consumes artifact plans. WP03 executes
authorized effects; WP04 schedules/reconciles; WP05 verifies/handles children;
WP06 supplies signed qualified material and removes the isolated old path.
Selected instructions/skills load only after Workspace Trust and remain
immutable complete retained closures, never reread from mutable files on resume.

Before Kernel Cut, revert the new-path commits as a unit if required; do not
re-enable only text parsing behind the new loop. Metadata corrections create
a new assembly/Run, never mutate an admitted one. After Kernel Cut, use WP01's
state rollback protocol before installing an old binary.

### Open questions

No product decision blocks implementation. Actual provider/model qualification
and credible billing ceilings remain required evidence, not assumed answers.

### GitHub issue body

Implement WP02 as one typed-runtime program with the two review gates above.
Native calls alone authorize autonomous tool intent; preserve every call,
durable effect/verification guarantees and temporary isolated old-runner
coexistence until WP06. Use this spec and the canonical RFC; do not create
additional protocol slices, repeat the shared schemas, or restore text-action
fallback. Verification requires build, focused and full regression suites;
live provider and budget qualification is a separate release obligation.
