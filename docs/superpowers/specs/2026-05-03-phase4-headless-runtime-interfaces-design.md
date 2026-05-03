# Phase 4 Headless Runtime Interfaces Design

**Date:** 2026-05-03
**Status:** Draft
**Target Release:** `v0.7.0`

## 1. Summary

Phase 4 turns Cliq from a CLI-driven local agent into a runtime that can be called by other processes.

The release adds a stable headless contract above the existing runner:

- headless run input and output shapes
- versioned runtime event envelopes
- `cliq run --jsonl` as the first machine-readable adapter
- cooperative cancellation boundaries
- a stable artifact query surface for sessions, checkpoints, compactions, and handoffs
- a minimal stdio JSON-RPC protocol after the JSONL contract is proven

The goal is not to add another human CLI command. The goal is to let a GUI, gateway, automation process, or another agent start runs, subscribe to events, cancel work, and read artifacts without scraping terminal text or knowing the internal `CLIQ_HOME` layout.

## 2. Roadmap Placement

Phase 4 implements the runtime architecture roadmap item: **Headless Runtime Interfaces**.

It builds on three completed foundations:

- `v0.4.0`: model/provider runtime and normalized runtime events
- `v0.6.0` Phase 3: checkpoint, fork, compact, and handoff as durable workflow assets
- Auto Compact: automatic compaction events and future cancellation hook boundaries

This phase does not replace Phase 5 or Phase 6:

- Phase 5 observability, cost/token tracking, audit export, and debug/replay stay deferred.
- Phase 6 rich TUI, automation, worktrees, and multi-surface UX stay deferred.

Phase 4 must provide the contract those later phases consume.

## 3. External Design References

Cliq should be Codex-like in runtime boundaries and Pi-like in durable session semantics.

Reference model:

- Codex CLI informs the separation between runtime core and host surfaces, the high-level model/tool lifecycle events, checkpoint readiness before mutating execution, and headless-friendly runtime direction.
- Pi informs durable session assets: raw history stays authoritative, compaction is a persisted workflow artifact, and replay uses latest summary plus raw tail.
- Claude Code and OpenCode inform automatic compaction UX, cancellation expectations, and anti-thrashing behavior.

Important limitation:

- Cliq must not assume any private Codex GUI protocol. The GUI is not an open contract. Phase 4 should expose the capabilities any GUI or gateway needs rather than copying an unknown implementation.

## 4. Goals

### 4.1 Product Goals

- Let external hosts run Cliq non-interactively.
- Make progress observable through structured events.
- Let hosts distinguish final assistant output from process completion.
- Let hosts cancel active work and receive a clear terminal event.
- Let hosts read session and workflow artifacts through stable APIs.
- Preserve the existing human CLI behavior unless `--jsonl` or RPC mode is selected.

### 4.2 Architecture Goals

- Keep `src/runtime/runner.ts` focused on the turn loop, model calls, tool execution, compaction, hooks, and runtime events.
- Add a headless layer that owns run contracts, event envelopes, output contracts, and adapter-independent lifecycle.
- Keep CLI rendering as an adapter over the headless layer.
- Avoid exposing raw session file paths or `CLIQ_HOME` structure as public API.
- Version public event and request/response shapes from the first release.

## 5. Non-Goals

Phase 4 v1 does not provide:

- rich TUI
- desktop GUI
- long-running daemon
- multi-user server
- HTTP API
- authentication or remote access controls
- cost/token accounting
- audit export and debug/replay UI
- public compact or handoff extension hooks
- provider-native tool-call streaming
- full rollback of runtime side effects after cancellation
- stable SDK packages for other languages

These are either later roadmap phases or require the Phase 4 contract to stabilize first.

## 6. Core Principles

### 6.1 CLI Is An Adapter

The human CLI and JSONL CLI should call the same headless run API. They should differ only in rendering.

```text
human CLI  ----\
JSONL CLI  -----+--> headless run API --> runtime runner --> session store
RPC stdio  ----/
```

This prevents each surface from recreating model configuration, policy setup, session assembly, auto compact wiring, and error handling.

### 6.2 Events Are Observable Facts

Events describe facts that happened in the runtime. They are not commands, and they are not a replay protocol.

Examples:

- `model-start`: a model request started
- `tool-end`: a tool finished with status
- `checkpoint-created`: a checkpoint was persisted
- `final`: the assistant produced a final message
- `run-end`: the run process reached a terminal state

Hosts may render events, log them, or update UI state from them. They must not need to infer state by parsing human text.

### 6.3 Public Contracts Are Versioned

Every event emitted by a headless adapter uses a versioned envelope. Payloads may evolve, but breaking changes require a schema version bump.

### 6.4 Artifacts Are Queried Through APIs

External hosts should not read `~/.cliq` or workspace `.cliq` internals. They should request artifacts by stable ids:

- session id
- checkpoint id
- workspace checkpoint id
- compaction id
- handoff id

### 6.5 Cancellation Is Cooperative

Cancellation stops future runtime work and attempts to abort in-flight work where the underlying provider or tool supports it.

Cliq must not promise that already executed shell commands, network calls, database writes, or external side effects are undone.

## 7. Current Runtime Baseline

The existing implementation already has useful Phase 4 foundations:

- `RuntimeEvent` exists in `src/runtime/events.ts`.
- `createRunner` accepts an `onEvent` sink.
- Runtime events are distinct from raw model stream deltas.
- CLI rendering is already a separate sink.
- Phase 3 artifacts are persisted under `CLIQ_HOME`.
- Auto Compact emits compact lifecycle events.

Current gaps:

- Events are not wrapped in a stable public envelope.
- Events do not include `runId`, `sessionId`, `turn`, `eventId`, or `timestamp`.
- Checkpoint creation during `runTurn` is not emitted as a runtime event.
- The CLI `run` command is an alias for human chat output.
- The CLI event sink writes human text to stdout/stderr.
- There is no headless run input/output contract.
- There is no public artifact query surface.
- There is no cancellation contract.

## 8. Headless Run Contract

### 8.1 Input

The headless run API accepts a single normalized request.

```ts
export type HeadlessRunInput = {
  prompt: string;
  cwd: string;
  policy?: PolicyMode;
  model?: PartialModelConfig;
  skills?: string[];
  autoCompact?: AutoCompactConfig;
  session?: {
    mode?: 'active' | 'new';
    id?: string;
  };
  metadata?: Record<string, string | number | boolean | null>;
  signal?: AbortSignal;
};
```

Rules:

- `prompt` is required and must be non-empty after trimming.
- `cwd` is required and must resolve to an existing directory.
- `policy` defaults to the same policy resolution used by CLI.
- `model` follows existing workspace, CLI, and environment resolution order.
- `skills` are additive over workspace-discovered skills.
- `autoCompact` overrides workspace auto compact config only for this run.
- `session.mode: "active"` uses the active session for the workspace.
- `session.mode: "new"` creates a new active session before the run.
- `session.id` targets an existing session if supported by the session store; v1 may reject cross-workspace session ids until the lookup semantics are explicit.

### 8.2 Output

The headless run resolves with a terminal output object.

```ts
export type HeadlessRunOutput = {
  runId: string;
  sessionId: string;
  turn: number;
  status: 'completed' | 'failed' | 'cancelled';
  exitCode: number;
  finalMessage?: string;
  checkpointId?: string;
  artifacts: {
    checkpoints: string[];
    workspaceCheckpoints: string[];
    compactions: string[];
    handoffs: string[];
  };
  error?: HeadlessRunError;
};
```

Rules:

- `completed` uses exit code `0`.
- `failed` uses a non-zero exit code.
- `cancelled` uses a non-zero exit code distinct from generic failure.
- `finalMessage` is present only when the model returned a final message.
- `checkpointId` is the automatic checkpoint created before the turn when available.
- `artifacts` lists artifacts created or activated during this run.

## 9. Event Envelope

Headless adapters emit one JSON object per event.

```ts
export type RuntimeEventEnvelope<TPayload = unknown> = {
  schemaVersion: 1;
  eventId: string;
  runId: string;
  sessionId: string;
  turn: number;
  timestamp: string;
  type: HeadlessRuntimeEventType;
  payload: TPayload;
};
```

Required properties:

- `schemaVersion`: public event schema version
- `eventId`: unique id for this event
- `runId`: unique id for the headless run
- `sessionId`: session that owns the turn
- `turn`: session turn number associated with the event
- `timestamp`: ISO timestamp
- `type`: event type
- `payload`: event-specific data

Event ids must be monotonically emitted in process order, but consumers should rely on event order in the stream rather than lexicographic id sorting.

## 10. Event Types

Phase 4 v1 emits these public event types:

```ts
export type HeadlessRuntimeEventType =
  | 'run-start'
  | 'checkpoint-created'
  | 'model-start'
  | 'model-progress'
  | 'model-end'
  | 'tool-start'
  | 'tool-end'
  | 'compact-start'
  | 'compact-end'
  | 'compact-skip'
  | 'compact-error'
  | 'final'
  | 'error'
  | 'run-end';
```

### 10.1 Run Events

`run-start` payload:

```ts
{
  cwd: string;
  policy: PolicyMode;
  model: SessionModelRef;
}
```

`run-end` payload:

```ts
{
  status: 'completed' | 'failed' | 'cancelled';
  exitCode: number;
  output: HeadlessRunOutput;
}
```

`run-end` is always the final event for a headless run unless the process is force-killed outside Cliq.

### 10.2 Checkpoint Event

`checkpoint-created` payload:

```ts
{
  checkpointId: string;
  kind: 'auto' | 'manual' | 'restore-safety' | 'handoff';
  workspaceCheckpointId?: string;
  workspaceSnapshotStatus: 'available' | 'unavailable' | 'expired';
  warning?: string;
}
```

The runner should emit this for the automatic checkpoint created before appending the user record. Manual checkpoint CLI commands may later use the same event shape, but v1 only requires run-turn checkpoints.

### 10.3 Model Events

Model lifecycle payloads mirror the existing runtime events, but remain protocol-safe.

`model-start`:

```ts
{
  provider: ProviderName;
  model: string;
  streaming: boolean;
}
```

`model-progress`:

```ts
{
  chunks: number;
  chars: number;
}
```

`model-end`:

```ts
{
  provider: ProviderName;
  model: string;
}
```

The default headless event stream must not expose raw model delta text because Cliq's current action protocol may contain incomplete internal JSON during streaming.

### 10.4 Tool Events

`tool-start`:

```ts
{
  tool: string;
  preview?: string;
}
```

`tool-end`:

```ts
{
  tool: string;
  status: 'ok' | 'error';
}
```

Tool events do not include full tool output in v1. Full output stays in session records and can be queried through session APIs subject to existing storage caps. A future redaction policy can narrow what artifact views expose without changing the event stream.

### 10.5 Compact Events

Compact events wrap the existing auto compact runtime events.

`compact-start`:

```ts
{
  trigger: 'threshold' | 'overflow';
  phase: 'pre-model' | 'mid-loop';
}
```

`compact-end`:

```ts
{
  artifactId: string;
  estimatedTokensBefore: number;
  estimatedTokensAfter: number;
}
```

`compact-skip`:

```ts
{
  reason: AutoCompactSkipReason;
}
```

`compact-error`:

```ts
{
  trigger: 'threshold' | 'overflow';
  message: string;
}
```

### 10.6 Final And Error Events

`final`:

```ts
{
  message: string;
}
```

`error`:

```ts
{
  code: HeadlessErrorCode;
  stage: 'input' | 'assembly' | 'checkpoint' | 'model' | 'protocol' | 'policy' | 'tool' | 'compact' | 'session' | 'cancel';
  message: string;
  recoverable: boolean;
}
```

`final` means the assistant produced a final message. It does not mean the process has closed. Consumers should wait for `run-end` before treating the run as fully complete.

## 11. Error Taxonomy

Phase 4 introduces stable headless error codes.

```ts
export type HeadlessErrorCode =
  | 'invalid-input'
  | 'config-error'
  | 'model-auth-error'
  | 'model-error'
  | 'context-overflow'
  | 'protocol-error'
  | 'policy-denied'
  | 'tool-error'
  | 'compact-error'
  | 'session-store-error'
  | 'artifact-not-found'
  | 'cancelled'
  | 'internal-error';
```

Guidance:

- `invalid-input`, `config-error`, `model-auth-error`, `protocol-error`, `session-store-error`, and `internal-error` are fatal for the current run.
- `policy-denied` and `tool-error` may be represented as normal tool results when the runner can continue.
- `compact-error` may be recoverable for threshold compaction and fatal for overflow recovery when no successful retry is possible.
- `cancelled` is terminal but intentional.

Every failed headless run should emit an `error` event before `run-end`.

## 12. JSONL CLI Adapter

`cliq run --jsonl "task"` is the first public adapter over the headless contract.

Rules:

- stdout contains only newline-delimited JSON event envelopes.
- Each line is a complete JSON object.
- stdout must not contain human progress text, final message banners, prompts, or shell echo formatting.
- stderr is reserved for process-level diagnostics that cannot be represented as JSON because the adapter failed before event emission.
- Normal runtime errors should be emitted as JSON events and reflected in `run-end`.
- Process exit code matches `run-end.payload.exitCode`.

Example:

```bash
cliq run --jsonl "inspect this repo"
```

Output shape:

```jsonl
{"schemaVersion":1,"eventId":"evt_001","runId":"run_abc","sessionId":"ses_123","turn":4,"timestamp":"2026-05-03T00:00:00.000Z","type":"run-start","payload":{"cwd":"/repo","policy":"auto","model":{"provider":"openai","model":"example-model"}}}
{"schemaVersion":1,"eventId":"evt_002","runId":"run_abc","sessionId":"ses_123","turn":4,"timestamp":"2026-05-03T00:00:01.000Z","type":"checkpoint-created","payload":{"checkpointId":"chk_123","kind":"auto","workspaceCheckpointId":"wcp_123","workspaceSnapshotStatus":"available"}}
{"schemaVersion":1,"eventId":"evt_003","runId":"run_abc","sessionId":"ses_123","turn":4,"timestamp":"2026-05-03T00:00:02.000Z","type":"model-start","payload":{"provider":"openai","model":"example-model","streaming":true}}
{"schemaVersion":1,"eventId":"evt_004","runId":"run_abc","sessionId":"ses_123","turn":4,"timestamp":"2026-05-03T00:00:03.000Z","type":"final","payload":{"message":"Done."}}
{"schemaVersion":1,"eventId":"evt_005","runId":"run_abc","sessionId":"ses_123","turn":4,"timestamp":"2026-05-03T00:00:03.100Z","type":"run-end","payload":{"status":"completed","exitCode":0,"output":{"runId":"run_abc","sessionId":"ses_123","turn":4,"status":"completed","exitCode":0,"finalMessage":"Done.","checkpointId":"chk_123","artifacts":{"checkpoints":["chk_123"],"workspaceCheckpoints":["wcp_123"],"compactions":[],"handoffs":[]}}}}
```

The exact ids and timestamps are examples. The required contract is the envelope and payload schema.

## 13. Minimal RPC Mode

RPC should be implemented after the JSONL adapter because it depends on the same event and run contracts.

The first RPC transport should be stdio JSON-RPC, not a daemon or HTTP server.

Initial methods:

```text
run.start(params: HeadlessRunInput without signal) -> { runId }
run.cancel(params: { runId: string }) -> { status: 'cancelled' | 'not-found' | 'already-finished' }
session.get(params: { sessionId: string }) -> SessionView
artifact.get(params: { artifactId: string }) -> ArtifactView
```

Runtime events are emitted as server notifications:

```json
{"jsonrpc":"2.0","method":"run.event","params":{"schemaVersion":1,"eventId":"evt_001","runId":"run_abc","sessionId":"ses_123","turn":4,"timestamp":"2026-05-03T00:00:00.000Z","type":"run-start","payload":{}}}
```

Concurrency rule for v1:

- A single stdio RPC process may run one active run at a time.
- `run.start` rejects a second run while one is active.
- Multi-run scheduling is deferred.

This keeps lifecycle, cancellation, output ordering, and session mutation simple.

## 14. Cancellation Contract

Cancellation enters through a run controller.

```text
RPC cancel or process signal
  -> RunController.abort()
  -> HeadlessRunInput.signal aborts
  -> runner observes signal at runtime boundaries
  -> model/tool/compact receives signal where supported
  -> error(cancelled)
  -> run-end(cancelled)
```

Required cancellation checkpoints:

- before creating the automatic checkpoint
- after checkpoint creation and before appending user input
- before each model request
- before each tool authorization
- before each tool execution
- before each auto compact attempt
- before each loop iteration

Provider support:

- Providers that support abortable fetch should receive the signal.
- Providers that do not support abort should allow the runner to stop after the current request returns.

Tool support:

- Tools may receive a signal in their execution context.
- Tools that cannot interrupt in-flight work must still let the runner stop after they return.

Session semantics:

- A cancelled run must leave the session valid and saved.
- If cancellation occurs after the user record is appended, that record remains in raw history.
- If cancellation occurs after a tool has executed, its stored result remains in raw history if it was produced.
- Cliq must not silently delete partial history to make cancellation look clean.

## 15. Artifact Query Surface

External hosts need stable read APIs.

Suggested module:

```text
src/headless/artifacts.ts
```

Views:

```ts
export type SessionView = {
  id: string;
  cwd: string;
  model: SessionModelRef;
  lifecycle: Session['lifecycle'];
  parentSessionId?: string;
  forkedFromCheckpointId?: string;
  records: SessionRecord[];
  checkpoints: SessionCheckpoint[];
  compactions: CompactionArtifact[];
};

export type ArtifactView =
  | { kind: 'checkpoint'; checkpoint: SessionCheckpoint; workspaceCheckpoint?: WorkspaceCheckpoint }
  | { kind: 'workspace-checkpoint'; workspaceCheckpoint: WorkspaceCheckpoint }
  | { kind: 'compaction'; compaction: CompactionArtifact }
  | { kind: 'handoff'; id: string; json: unknown; markdown: string };
```

Rules:

- Views are stable API shapes, not direct file dumps.
- Paths may be included as metadata only when they are useful and safe; path layout is not the contract.
- Missing artifacts return `artifact-not-found`.
- Handoff markdown can be returned as content, but callers should not need to know where it lives on disk.

## 16. Module Plan

Expected code boundaries:

```text
src/headless/contract.ts
  public run input/output, event envelope, error code, and view types

src/headless/events.ts
  wraps RuntimeEvent into RuntimeEventEnvelope and tracks created artifacts

src/headless/run.ts
  resolves workspace/session/model/policy/skills and executes one run through createRunner

src/headless/jsonl.ts
  serializes envelopes as newline-delimited JSON

src/headless/artifacts.ts
  provides stable session and artifact query views

src/headless/cancellation.ts
  owns RunController and AbortSignal helpers

src/rpc/stdio.ts
  later adapter for minimal JSON-RPC over stdio

src/cli.ts
  parses --jsonl and delegates run execution to the headless layer

src/runtime/runner.ts
  accepts cancellation signal and emits checkpoint-created through runtime events
```

Runner should not import JSONL, RPC, or headless adapter code.

## 17. Data Flow

```text
CLI / RPC / GUI host
        |
        v
HeadlessRunInput
        |
        v
headless/run.ts
        |
        +--> runtime assembly
        +--> session store
        +--> model config
        +--> policy engine
        |
        v
runtime/runner.ts
        |
        +--> RuntimeEvent
        |
        v
headless/events.ts
        |
        v
RuntimeEventEnvelope
        |
        +--> JSONL stdout
        +--> RPC notification
        +--> future GUI/TUI adapter
```

## 18. Backward Compatibility

Existing behavior remains unchanged unless a headless adapter is selected.

- `cliq run "task"` keeps human output.
- `cliq "task"` keeps human output.
- `cliq chat` keeps interactive behavior.
- `cliq history`, `checkpoint`, `compact`, and `handoff` keep their current output unless future `--json` flags are added.

`--jsonl` is opt-in.

Existing sessions remain valid. Phase 4 adds public views over existing data; it does not require a session schema migration unless cancellation metadata is later persisted.

## 19. Testing

### 19.1 Contract Tests

- Headless input rejects empty prompt.
- Headless input rejects missing or invalid `cwd`.
- Headless run output includes `runId`, `sessionId`, `turn`, `status`, `exitCode`, and artifact arrays.
- Failed runs include a structured `HeadlessRunError`.

### 19.2 Event Tests

- Every emitted event has `schemaVersion`, `eventId`, `runId`, `sessionId`, `turn`, `timestamp`, `type`, and `payload`.
- Event order for a final-message run is `run-start`, `checkpoint-created`, model lifecycle, `final`, `run-end`.
- `final` is not the last required event; `run-end` is.
- Runtime error emits `error` before `run-end`.
- Raw model delta text is not emitted in public headless events.

### 19.3 JSONL Tests

- `cliq run --jsonl "task"` writes only parseable JSON objects to stdout.
- Human progress text never appears in stdout for JSONL mode.
- JSONL mode process exit code matches `run-end.payload.exitCode`.
- Stderr stays empty for normal runtime failures that can be represented as JSON events.

### 19.4 Cancellation Tests

- Cancelling before model call emits `error(cancelled)` and `run-end(cancelled)`.
- Cancelling during a tool prevents the next model call after the tool returns.
- Cancelling during auto compact leaves session valid.
- Cancelled runs save lifecycle status back to idle.

### 19.5 Artifact Query Tests

- `session.get` returns a stable view without requiring callers to read `CLIQ_HOME`.
- `artifact.get` resolves checkpoint, workspace checkpoint, compaction, and handoff ids.
- Unknown artifact id returns `artifact-not-found`.
- Handoff artifact query returns JSON and markdown content without exposing path layout as the primary contract.

### 19.6 Regression Tests

- Human CLI output remains unchanged for normal `cliq run`.
- Interactive chat still works.
- Manual checkpoint, compact, fork, restore, and handoff commands still work.
- Auto Compact still triggers before model calls and on overflow.

## 20. Rollout Plan

Recommended implementation order:

1. Add `src/headless/contract.ts` and event envelope helpers.
2. Add `headless/run.ts` and route one-shot CLI execution through it without changing human output.
3. Emit `checkpoint-created` from automatic checkpoint creation.
4. Add `cliq run --jsonl`.
5. Add artifact query views.
6. Add cooperative cancellation through `AbortSignal`.
7. Add minimal stdio JSON-RPC adapter.

Each step should be independently tested and shippable.

## 21. Deferred Decisions

- Whether future JSONL should support reading `HeadlessRunInput` from stdin or `--input request.json`.
- Whether direct session targeting by `session.id` can cross workspace boundaries in v1.
- Whether event payloads should include redacted tool output snippets in a later schema version.
- Whether cancellation should create an explicit checkpoint after cancellation for recovery UX.
- Whether RPC should eventually support multiple concurrent runs.
- Whether a future daemon should use stdio JSON-RPC, local sockets, or HTTP.
- Whether an SDK should be generated from the TypeScript contract after the protocol stabilizes.
