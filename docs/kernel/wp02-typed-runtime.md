# WP02 Typed Runtime Implementation Design

This design implements [WP02](../backlog/durable-verified-run-kernel/02-typed-runtime-and-provider-capabilities.md)
under the [Durable Verified Run Kernel RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md).
The RFC owns shared durable schemas; this document owns implementation seams.

## One program, two review gates

1. **Gate A — trusted model attempt:** immutable loaded authority, exact native
   request bytes, incremental response observation, and one compiled result.
2. **Gate B — typed continuation:** direct tool inputs, whole-batch validation,
   ordered results, policy/context/UI integration, and durable compaction.

These are integration gates, not new product slices or independently evolving
protocols. Gate A does not switch production composition or claim that Gate B,
broker integration, or provider qualification is complete.

Gate A landed in PR #489 (`a153d47`); the model/context continuation landed in
PR #490 (`c29179f`). Gate B also includes the minimum WP01
companion work needed to exercise the real SQLite/CAS continuation. The user
approved that scope on 2026-09-05. This does not transfer storage ownership to
WP02 or include the rest of WP01 migration, WP03 brokers, WP04 scheduling,
WP05 verification, or WP06 production cutover.

The existing M2 Journal reserves and settles budgets but has no model-turn,
tool-batch/result, or compaction commit reducers. Its generic request/result
metadata is not validation of the retained typed model contract. Gate B must
bind the exact model request and full reservation before claim, commit a
completed observation together with its typed continuation, and recover that
continuation from the retained state. A mock state adapter cannot establish
these properties.

The implementation tests cross `ModelSession` and `StateStore`: whole-batch
prevalidation, one ordered result per call, denied/error continuation, stale
revision and duplicate completion rejection, and atomic context/Checkpoint
updates. Store methods derive changes from the current frontier and retained
artifacts; no public generic item append, frontier patch, or caller-selected
budget settlement is added. SQLite transactions and the existing CAS remain
the only durable implementation. Private transaction helpers may be shared
only after the typed reducers have validated their complete input closure.

### Gate B implementation status

The model-attempt/context lifecycle and direct tool-input projection now connect
to StateStore. These are integration checkpoints inside Gate B, not new work
packages or a declaration that Gate B has passed:

- `StateStore.loadAgentRun` loads the retained assembly against the actual Run
  admission/deadline/budget, then derives normal prompts from retained context.
  Its handle retains static authority only, never a second mutable Run state.
  Input schemas compile once from the verified manifest using a pinned standard
  JSON Schema validator (Ajv, draft-07); validation consumes typed values without
  coercion, defaults, stripping, JSON repair, external schema loading, async
  schemas, or a caller-supplied resolver. Unknown dialects/keywords fail closed.
- `loadToolContracts` binds compiled builtin input semantics to the frozen
  name/version/schema/access/replay contract. `read`, `edit`, `bash`, `ls`,
  `find`, `grep`, `plan`, and `todo` accept direct typed inputs. The same
  normalized value determines policy intent, display and the loop signature.
  MCP uses its final exec-class contract and exact frozen registration/server
  tool identity, even if its exposed name matches a builtin. There is no tool
  executor or ambient skill activation behind this interface.
- `readToolInvocation` reads a SQLite recovery cut, revalidates **every** call
  in the retained batch, and checks that the frontier follows exactly its
  ordered result prefix. Its immutable result contains the current invocation,
  action-free policy subject and display, not an OperationGrant or dispatch
  permission. Restart reproduces the same normalized input and loop signature.
- `prepareModel` derives the operation, zero-based Journal attempt, exact native
  body and full signed reservation. Generic invocation admission cannot bypass
  that path for typed Runs; generic completion/refunds cannot replace its checks.
  The shared permanent claim additionally binds the exact agent frontier,
  native request body/projection and ready context (or compaction source), then
  rechecks the cut inside the existing live-lease/highest-attempt transaction.
- `completeModel` independently reads/revalidates the retained result closure and
  commits settlement, model item, batch, synthetic results, context, frontier and
  Checkpoint in one transaction. Invalid batches dispatch nothing. Unusable
  observations retain their raw bytes and full charge, with no semantic retry.
- Recovery requires transitive model/input/result artifacts. Loading the agent
  reconstructs projections from their original immutable sources, reproduces
  retained native requests, and revalidates normalized inputs and continuation
  items. `readModelAttempt` returns the exact retained attempt and its Journal
  phase; it does not grant permission to resend a claimed or settled request.
- `prepareModel` selects the greatest safe whole prefix under the frozen
  compaction equations, protecting the recent suffix and complete tool batches.
  Source text is JCS of the existing model-visible message array, with no audit
  refs or extra instruction framing. The compaction plan/frontier, request and
  full reservation commit together. Its result commits the summary item,
  replacement context and ready Checkpoint with an unchanged workspace state.
  Original items remain durable; control digests bind the normative ordered
  `{itemSeq,kind,payloadRef}` tuples. The complete next prompt must shrink.
- An impossible compaction publishes exact estimate evidence and makes no
  invocation. Invalid or ineffective executed compaction is fully charged,
  leaves the old context intact, and returns `context_compaction_failed` evidence
  without semantic retry. A valid but ineffective summary remains a usable
  observation in the Journal, not an accepted context summary.

Gate B still requires trusted builtin execution and canonical policy/approval
evidence, ordinary ordered tool-result commits (including denied/error and
post-effect checkpoint validation), and user-input/repair/child projections.
Those require the canonical grant, policy/approval, Journal and post-effect
Checkpoint closure; accepting a caller's result or boolean would not establish
it. The user authorized advancing to a reasonable new PR on 2026-09-05, so this
model-state integration is reviewed before that separate authority-bearing
execution work, without creating additional public milestones.

`candidate_required` and `stop_required` describe the retained
observation's handoff to WP05/WP04; they are not permission to mark the Run
successful or bypass stop arbitration/drain. Completed handoffs survive restart
through `readModelAttempt`; `prepareModel` reports `AGENT_HANDOFF_PENDING` with
the disposition and retained evidence reference instead of a cursor TypeError
or a misleading retry attempt. Context exhaustion is reproducible from the unchanged
context and frozen policy. Neither is an implemented StopIntent/candidate reducer.
Broker/sandbox effects, scheduling, dispatch backoff, and production composition
remain outside this implementation. Restart does not revive an old worker lease.

The old Session/`ModelAction` runner remains isolated until WP06's single
Kernel Cut. There is no typed-to-legacy bridge. WP06 removes the old runner,
parser and repository command hooks; historical payloads remain opaque import
data. No permanent compatibility promise is introduced.

### Direct tool intent, not execution authority

Builtin input schemas and semantic checks live together in `builtin-inputs`;
no old action envelope, tool registry, host filesystem or session-plan store is
imported. Paths are lexical workspace-relative identities: redundant `.` and
separators normalize, omitted directory roots become `.`, and absolute paths,
drive paths, parent components, backslashes and NUL reject before batch admission.
Line ranges must be positive safe integers in ascending order. Plan operations
have distinct closed shapes; missing fields are not repaired or inferred.
Actual symlink/descriptor containment and effect handling still belong to WP03.

`PolicySubject` is action-free. The existing decision table, shell-head parser
and mode engine consume it directly; the retiring runner alone retains its old
action field for hooks. Modes and rule composition are unchanged: builtin
denies enter through `composePermissionTable`, not a new implicit policy.
These pure decisions do not manufacture the RFC's `PolicyChannelEvidenceV1`,
approval records, target/request binding, or `OperationGrantV1`.

The loop signature hashes the full frozen manifest entry and normalized input,
excluding call ID/index. It is an observation key, not deduplication authority:
a repeated call must never be skipped or have a result reused on that basis.
`manifestEntryDigest` identifies that entry; it is not the nested MCP registry's
separate `execution.toolContractDigest`.

`skill`/`skillResource` are not exposed as builtin execution contracts yet.
Selected skill instructions continue to load from frozen CAS manifests; future
resource access must use that retained closure, not the old ambient activation
or live-file fallback. Unknown builtin identities fail loading explicitly.

Public loaded-state validation failures carry `KernelStorageError` codes and
their original cause. Invalid completion arguments are `INVALID_REQUEST`;
unreproducible retained state/authority is `RECOVERY_REQUIRED`. Existing lease,
revision, artifact and infrastructure errors retain their classification.

The non-blocking #490 review was checked against the implementation. Highest
attempt and permanent duplicate-claim checks already existed; the necessary
addition is current-frontier/context binding, not banning all model claims.
Candidate/stop reducers remain WP05/WP04 work, with explicit handoff errors here.
Broad per-handle CAS memoization is deferred: it could hide a lost or corrupted
retained artifact. History replay/compaction performance needs measurement;
no claim of linear-time recovery is made by this change.

## One loaded model module

`validateRunAssembly` loads and verifies the exact retained assembly closure.
Its successful result exposes only a `ModelSession`, not mutable configuration,
price tables, tool definitions, tokenizer functions or adapter callbacks.

```text
validateRunAssembly(retained material) -> ModelSession
ModelSession.prepare(typed projection, invocation) -> PreparedModelAttempt
  [WP01 publishes artifacts and claims the exact request; WP03 performs I/O]
ModelSession.start(prepared, response head) -> response
response.push(bytes) -> non-authoritative stream events
response.finish(time, tool-input resolver) -> events + usable/unusable result
```

The prepared object is an identity-bound handle owned by that loaded session.
A copied, forged, cross-session or deserialized handle is rejected. Recovery
reloads the retained assembly and prepares the retained projection again;
identical inputs must reproduce the exact request ref and body bytes. Public
byte getters return copies; nested authority and request fields are immutable.

Static evidence, signature roots, tool/schema closure, envelope members and
context equations are checked on load/recovery, not on every request.
Per-attempt work checks only changing invocation/projection data, serializes
the native body, estimates context size, and computes the fixed reservation.
The input resolver must return the exact frozen tool/schema identity; its
schema-normalized values are consumed by Gate B, never dispatched here.

A normal attempt publishes only the native body and one `ModelRequestV1`.
Compaction additionally publishes its typed two-message projection. There is
no framed-prompt, native-body wrapper, prompt profile, custom BPE vocabulary,
runtime golden-vector execution, or intermediate JSON encode/decode pipeline.
Adapter code is retained through the signed RuntimeBundle, as other executable
authority already is. Golden fixtures are independent build-time tests.

Tool arguments remain typed JSON values or explicitly retained malformed
fragments in memory and history. Only string-native provider fields encode
them; object-native providers receive the existing values without decoding
them again.

## Native provider boundary

Autonomous execution requires positive, matching native-tool evidence.
Valid negative/absent native capability means `text-only`; malformed, expired,
unsigned or identity-mismatched evidence fails admission. There is no
`constrained-ir` branch and no runtime downgrade or text-action repair.

- OpenAI uses Responses, `store:false`, explicit output bounds,
  `truncation:'disabled'`, and encrypted reasoning continuation.
- Anthropic uses Messages and preserves thinking signatures/redacted blocks.
- OpenRouter, OpenAI-compatible and Zhipu retain Chat Completions adapters.
- Managed Ollama retains Chat/NDJSON and deterministic invocation-bound call ids.

These are distinct protocol conformance cases, not six runner implementations.
The stream framer decodes UTF-8 across chunks, incrementally parses SSE/NDJSON,
and bounds retained bytes to 1 MiB plus one byte for an oversized observation.
It does not wait for EOF to deliver text/reasoning/tool deltas. End events and
usage are returned exactly once. Buffered tests use the same observer.

Only the central compiler may create a usable turn. Partial, contradictory,
filtered, truncated, rejected, oversized or mode-incompatible responses cannot
dispatch tools. Every identifiable call survives normalization, including a
missing name or malformed argument fragment. Missing/duplicate mandatory ids
invalidate the whole response before tool resolution. A missing tool name is
retained as empty in durable truth; native history uses the reserved,
unexposed `__cliq_missing_tool_name` placeholder only to close its result.

Provider-owned reasoning continuation is opaque, bounded, provider/model-bound
data. It is carried through the stored turn and next projection, never
interpreted as tools, permissions or instructions by the runtime. Streamed
signatures must not be lost. Gate B reconstructs this field from the retained
turn, not from a mutable provider cache.

`abort(time, stopIntentRef, resolver)` is only for a broker-confirmed abort
caused by an already persisted StopIntent. It cannot execute partial calls or
overwrite a complete response. WP01 independently validates the StopIntent
and decides whether a completed result may be published during stop drain.
Unknown network outcomes are Journal/recovery facts, not fabricated cancels.

## Estimates are not hard billing authority

Context planning uses a fixed, cheap byte estimate: text is
`ceil(UTF8 bytes / 3)`; normal messages add four estimate units each, and
native tool definitions/arguments/continuation also contribute. It is a
deterministic heuristic, not an exact remote tokenizer, a billable-token
measurement, or proof that a provider will accept the context. Provider usage
is observational telemetry, never settlement authority.

A billable request reserves the complete four-component
`ModelPriceTableV1.requestTokenCeiling` and its checked signed-table cost,
independently of that estimate and the smaller requested output limit.
The signed ceiling must cover **every request this retained adapter can release**,
including rejected and ambiguous outcomes, for its exact endpoint/model and
validity interval. A signature alone does not establish a true ceiling:
WP06 qualification must establish that fact from authoritative billing bounds.
A rate-only table, guessed tokenizer, empirical average, or unspecified bound
is ineligible for a hard-budget Run (`MODEL_COST_UNKNOWN`).

Input/output ceilings must cover admitted context and both output caps.
Cache ceilings are explicit components, not inferred from prompt estimates.
Observed component/output-cap violations are rejected, but detecting one
after release cannot retroactively guarantee spend; eligibility must be sound
before release. The conservative full reservation is consumed for released or
possibly released attempts; only proven no-release settles zero. This retains
WP01's settlement rule and may reduce the useful work admitted by small budgets.
No provider-hard-cap mutation or new pricing plugin is added.

Managed-local zero cost still requires the independent signed service/model,
no-egress boundary and live-instance checks. Its token reservation uses
admitted context plus the requested output cap, not a remote billing claim.

## Compaction remains a durable operation

Keep the RFC's fixed integer `C/O/H/T/R/S/K/P` policy, whole-prefix selection,
protected context, raw-item retention, and atomic plan/summary/context/checkpoint
commit. Context counters are estimate units; they are not hard token proofs.
`K` estimates the actual retained two-message envelope. Normal output `O`
and summary output `S` independently fit the model's maximum; `S <= O` is
not required.

Compaction disables tools and accepts only a nonempty, complete `end` summary.
The summary is at most `min(262144, 3*S)` UTF-8 bytes, so its text estimate is
at most `S` without a private tokenizer. Combined with source estimate
`>= S+512`, each successful replacement reduces estimated source content by
at least 512 units; Gate B also verifies that the complete prompt estimate
decreases after accounting for message overhead. Actual model output is
requested with cap `S`; reported
output beyond it is invalid. A provider can still reject an underestimated
context: stop explicitly, never silently truncate or repair/retry output.

## Ownership and verification

WP02 plans artifacts and typed outcomes; it owns no SQLite/CAS writes, Journal
claim, effect, retry or recovery scheduler. WP01 rehashes and atomically commits,
WP03 dispatches through permission/broker/sandbox, WP04 resumes/reconciles,
WP05 verifies, and WP06 qualifies releases and switches composition. Workspace
Trust still precedes configuration/runtime assembly; Tool Permission and the
OS boundary remain independent gates.

Regression tests cross the loaded-session seam: independently specified native
bytes; configuration mutation; forged handles; full schema substitution;
reload determinism; all calls and their next request; opaque continuation;
real chunked deltas; cancellation; output/usage ceilings; and compaction with
a small normal output limit. Focused codec/arithmetic tests cover edge cases
that cannot be reached economically through every integration fixture.

Gate A requires `npm run test:agent-runtime`, `npm run build`, and `npm test`.
Offline conformance does not certify a live model, true billing ceiling,
durable broker integration or the final Kernel Cut.

JSON remains at provider wire, native tool-schema and canonical persistence
boundaries. In-process execution passes typed values; assistant JSON-looking
text is inert. Minimal core means removing unnecessary interpretation and
authority layers, not eliminating a serialization format used by providers
and durable storage.
