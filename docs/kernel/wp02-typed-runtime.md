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

The old Session/`ModelAction` runner remains isolated until WP06's single
Kernel Cut. There is no typed-to-legacy bridge. WP06 removes the old runner,
parser and repository command hooks; historical payloads remain opaque import
data. No permanent compatibility promise is introduced.

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
