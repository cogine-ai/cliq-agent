# Protocol Seam Refactor — 2026-05-12

This refactor extracted an explicit "protocol" seam between the runtime (event producer) and its consumers (headless, TUI, future RPC/GUI). It is a pure rename + move; no behavior changed and all 569 tests pass unchanged.

## Why

`src/runtime/events.ts` was importing `HeadlessErrorCode` from `src/headless/contract.ts` — a layering inversion (the kernel reaching into one of its consumers). With a TUI consumer landing alongside headless, the seam needed to be named explicitly so producer and consumer cannot drift, and so a third consumer (RPC, GUI) has an obvious place to plug in.

## Renames

| Old | New |
| --- | --- |
| `src/protocol/actions.ts` | `src/protocol/model/actions.ts` |
| `src/protocol/actions.test.ts` | `src/protocol/model/actions.test.ts` |
| `src/protocol/json-repair.ts` | `src/protocol/model/json-repair.ts` |
| `src/protocol/json-repair.test.ts` | `src/protocol/model/json-repair.test.ts` |
| `src/runtime/events.ts` | `src/protocol/runtime/events.ts` |
| `HeadlessErrorCode` (type, was in `src/headless/contract.ts`) | `RuntimeErrorCode` (type, in `src/protocol/runtime/errors.ts`) |

## What stayed

- `HeadlessErrorStage` remains in `src/headless/contract.ts`. Its extra stages (`input`, `assembly`, `checkpoint`, `compact`, `session`) describe failure points outside the runtime event stream, so they belong to the headless layer rather than the runtime protocol.
- `HEADLESS_SCHEMA_VERSION`, `HeadlessRunRequest`, `HeadlessRunOutput`, `RuntimeEventEnvelope`, and other headless-shaped types stayed in `src/headless/contract.ts`. The seam is `src/protocol/runtime/`; the headless adapter on top of it is `src/headless/`.

## Resulting layout

```
src/protocol/
  model/                 # protocol between assistant output and runtime (parsing)
    actions.ts
    json-repair.ts
  runtime/               # protocol between runtime and UI consumers (events)
    events.ts
    errors.ts
```

## Producer / consumer contract

- **Producer**: `src/runtime/` may import from `src/protocol/runtime/`.
- **Consumers**: `src/headless/`, future `src/tui/`, future RPC/GUI may import from `src/protocol/runtime/`.
- **Direction rule**: `src/protocol/runtime/` must not import from any consumer. The previous `HeadlessErrorCode` inversion is now gone; do not reintroduce it.

The existing `assertNever(event)` in `src/headless/events.ts:54` (in `runtimeEventToHeadless`) functions as a compile-time exhaustiveness check: adding a new `RuntimeEvent` variant without updating the headless mapper fails `tsc`. The TUI consumer will inherit the same pattern.

## Historical docs

Phase plans and design specs under `docs/superpowers/plans/` and `docs/superpowers/specs/` describe paths and type names as they were at the time of writing. The v0.8 docs (`specs/2026-05-02-cliq-transactional-workspace-runtime-design.md`, `plans/2026-05-06-v0.8-transactional-workspace-runtime.md`, `plans/2026-05-07-v0.8-runner-integration.md`, `specs/2026-05-07-v0.8-runner-integration-design.md`) carry a dated note pointing here and have had body references rewritten. Older phase artifacts (v0.4, phase1, phase2, phase4, auto-compact) were left unchanged — they document what was actually built and committed on those dates; rewriting them would falsify their `git add` templates and "Create: X" prescriptions.

When reading any pre-2026-05-12 doc, translate references using the table above.
