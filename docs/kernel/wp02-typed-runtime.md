# WP02 Typed Runtime Implementation Design

This document records the implementation architecture for work package 02 of
the [Durable Verified Run Kernel RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md).
The backlog-ready specification remains the normative behaviour contract; this
document fixes module seams, dependency direction, and merge gates so the
implementation does not optimize one local slice at the expense of the final
Kernel.

## Delivery shape

WP02 is designed as one program and delivered through two merge gates. These
are review gates, not independent protocols or compatibility layers.

1. **Trusted model attempt**: frozen model authority, deterministic request
   preparation, six provider wire adapters, lossless response observation, and
   central compilation into durable Agent IR or one closed unusable response.
2. **Typed runtime continuation**: direct tool input contracts, batch-wide
   validation, ordered continuation, policy/context/event/UI projections, and
   durable compaction contracts.

There are no smaller public milestones inside either gate. Internal commits
may make development and review easier, but they must not introduce temporary
production semantics.

## Coexistence and removal

The current Session/`ModelAction` runner remains isolated and unchanged while
the Kernel path is incomplete. The new path never emits `ModelAction`, invokes
the legacy parser, or converts typed calls into legacy records. Historical
legacy data may be decoded for read, display, or migration only.

At the single Kernel Cut, the composition root switches to the typed runtime
and WP06 removes the old runner and parser. Until then the typed runtime is not
the default path. This is temporary code coexistence, not a compatibility
promise between the two protocols.

## Ownership

WP02 is a pure protocol and planning layer. It does not write SQLite or CAS,
commit Journal entries, dispatch tools, or own recovery.

- WP02 produces canonical artifact bytes and refs, normalized outcomes, and
  deterministic transition/dispatch proposals.
- WP01 rehashes those artifacts and atomically commits authoritative state.
- WP03 executes an authorized effect through the broker and sandbox.
- WP04 schedules, resumes, reconciles, and applies retry policy.
- WP05 consumes the same candidate/result contracts.
- WP06 supplies signed runtime/provider material, public protocol adaptation,
  and the final composition switch.

No downstream package may trust a caller-provided digest merely because it was
produced by WP02; the owning state transition revalidates the exact bytes.

## Trusted model attempt module

The external seam has two lifecycle operations because a durable Journal claim
and external I/O necessarily occur between them:

```text
prepareModelAttempt(authority, projection, invocation)
  -> canonical request artifacts + exact outbound request

provider adapter observes exact response bytes
  -> ObservedModelResponse

compileModelObservation(prepared request, observation, tool resolver)
  -> artifact publication plan
   + AgentModelTurn | ModelUnusableResponseV1
```

Preparation hides prompt rendering, provider-native serialization, tokenizer
counting, price arithmetic, request digests, and reservation construction.
Compilation hides stop/call validation, call identity normalization, observed
input retention, tool-input resolution, usage validation, response digests,
and unusable-response classification.

The module returns results and has no side effects. Tests and callers cross the
same seam.

## Provider adapter seam

A provider adapter is a wire adapter, not a durable authority producer. It may:

- serialize the exact provider-native request from the closed signed profile;
- preserve complete response bytes or the exact over-limit prefix;
- reconstruct streaming text, reasoning, call identity, argument fragments,
  usage, provider response id, and stop information without filtering entries;
- normalize provider wire vocabulary into an untrusted observation.

It may not:

- decide whether a turn is usable;
- discard a malformed or incomplete call;
- infer model capability from provider name or transport compatibility;
- parse ordinary assistant text as executable input;
- mint durable digests or publish artifacts;
- retry a request or follow a redirect.

OpenAI, OpenRouter, OpenAI-compatible, and Zhipu may share one internal
OpenAI-chat implementation, but they remain separate conformance cases with
separate provider identities and request algorithms. Anthropic and managed
Ollama use their own wire implementations.

## JSON boundary

JSON is not the runtime control protocol. The autonomous path never asks a
model to print an action object into ordinary assistant text and never repairs,
extracts, or retries such text. Native provider tool calls are decoded once at
the untrusted wire boundary and immediately become typed observations; the
central compiler then produces typed Agent IR. JSON-looking text in
`text-only` mode remains inert model text.

`constrained-ir` is a narrow compatibility path, not the default harness
protocol. It is available only with positive signed capability evidence and a
provider mechanism that enforces the supplied schema or grammar. The response
uses the versioned `cliq-constrained-model-turn-v1` wire envelope, is decoded
by the same strict bounded decoder, and still passes the central stop/call and
tool-input validation. The generated OpenAI-family schema is a root object
(never a root `anyOf`); provider schema enforcement does not replace Cliq's
cross-field validation.

JSON remains intentionally at three non-executable boundaries:

- provider HTTP, SSE, or NDJSON wire formats that require it;
- model-visible JSON Schema definitions for native or constrained calls;
- RFC 8785/JCS bytes for content-addressed, signed, replayable artifacts.

Those uses provide interoperability or deterministic identity. They do not
make arbitrary model text executable. A source guard rejects legacy action
parsers, JSON repair, and direct `JSON.parse` in the typed model-attempt
modules; the isolated old runner is removed at the WP06 Kernel Cut.

## Complete observation

`ObservedModelResponse` retains every wire fact needed by the central compiler:

- exact provider/model and response media type (the negotiated mode comes from
  the immutable request authority, never from the response);
- exact complete bytes, or exactly the first response-limit-plus-one bytes;
- response id and normalized stop information when decodable;
- untrimmed assembled text;
- every call in provider order, including missing ids/names and malformed JSON
  fragments;
- complete usage fields when supplied;
- the StopIntent binding when Cliq caused an authenticated abort;
- whether constrained output was actually requested and acknowledged.

A positively received provider rejection is also an observation. A local
failure before request release and an uncertain transport outcome are not model
responses and remain WP01/WP04 Journal outcomes.

## Central compiler invariants

The central compiler is the only module allowed to produce
`AgentModelTurn` or `ModelUnusableResponseV1`.

- `end` requires nonempty UTF-8 text and zero calls.
- `tool_calls` requires at least one retained call and permits accompanying
  text only as non-executable assistant content.
- `cancelled` requires the exact pre-existing StopIntent that caused the abort.
- `length`, `content_filter`, unknown stops, incompatible stop/call pairs,
  forbidden-mode calls, duplicate/missing required call ids, malformed wire
  payloads, oversize responses, and provider rejections become one closed
  unusable response.
- Native ids are required for all providers except managed Ollama. Ollama and
  constrained-IR ids are deterministically derived from invocation identity
  and call index.
- Every call is retained. Unknown tools and invalid inputs remain in the batch
  as rejected inputs for synthetic results; one invalid call must never make a
  neighbouring call disappear.
- Only schema-normalized resolved input may reach policy or dispatch.
- A context-compaction result is accepted only as a text-only `end` turn whose
  nonempty Markdown summary satisfies both the byte bound and the pinned
  tokenizer/output-token cap.
- `responseDigest` covers the RFC normalized projection, not provider wire
  bytes. Unusable responses retain the exact observed bytes instead.
- All text, call input, and response artifacts are bounded to 1 MiB unless the
  RFC defines a smaller limit.

## Capability and pricing authority

Capability negotiation consumes one signature-validated source projection and
one fixed adapter transport declaration. Unknown, absent, expired, mismatched,
or unverifiable evidence yields `text-only`; it never enables an autonomous
mode.

```text
adapter.nativeTools && evidence.nativeToolCalling
  -> native-tools
else adapter.constrainedOutput && evidence.constrainedOutput
  -> constrained-ir
else
  -> text-only
```

The selected mode and the exact evidence, adapter, endpoint, context limits,
output limit, retry policy, and exposed tool sequence are frozen in
`RunAssemblyV1`. There is no runtime downgrade after admission.

Billable endpoints require a matching signed price table through the Run
deadline. Only exact managed-local Ollama provenance is zero-cost. Reservation
arithmetic uses checked safe integers and independently rounds each of the four
token-price components upward before checked addition.

## Dependency direction

```text
kernel canonical/identity types
            ^
            |
protocol Agent IR <- trusted model attempt <- provider wire adapters
            ^                 ^
            |                 |
      WP01 state         capability/pricing authority
            ^                 ^
            +------ WP06 signed assembly material

typed runtime continuation -> WP01 transition proposals
                           -> WP03 dispatch proposals
                           -> WP04 recovery inputs
```

The typed modules must not import Session records, `ModelAction`, JSON repair,
legacy prompt fallback, the old runner, or repository command hooks. A source
guard test enforces this direction.

## Gate A completion

The trusted-model-attempt gate is complete only when:

- canonical Agent IR and closed validation errors are implemented;
- capability negotiation and pricing arithmetic fail closed;
- deterministic prompt/native-request artifacts can be prepared from retained
  profiles without SDK reserialization;
- all six providers preserve complete non-streaming and streaming observations
  and pass the same conformance suite;
- the central compiler covers every stop/call/mode matrix branch and never
  silently drops a call;
- artifact plans are deterministic and rehash independently;
- source guards prove the new module has no legacy imports;
- `npm run test:agent-runtime`, `npm run build`, and `npm test` pass.

No production composition switch, direct tool dispatch, durable state write,
or legacy deletion is part of this gate.
