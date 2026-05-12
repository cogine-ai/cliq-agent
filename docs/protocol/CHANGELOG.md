# Protocol Changelog

This file tracks breaking and notable changes to Cliq's consumer-facing protocol surface — the types and contracts that runtime exposes to its consumers (`src/headless/`, `src/tui/`, future RPC/GUI clients).

Treat the surface listed below as semver-versioned even though it ships in the same package as the runtime. Breaking changes here trigger consumer rewrites; additive changes do not.

## Surface in scope

- `src/protocol/runtime/events.ts` — `RuntimeEvent` discriminated union, `RuntimeEventSink`.
- `src/protocol/runtime/errors.ts` — `RuntimeErrorCode`.
- `src/protocol/model/actions.ts` — `ModelAction` (consumer-visible because it appears inside `ApprovalSubject.action`).
- `src/policy/types.ts` — `ApprovalSubject`, `ApprovalDecision`, `ApprovalDecider`, `PolicyMode`. These are stable cross-cutting contracts that consumers (TUI, headless) rely on. Architecturally sit in `policy/` rather than `protocol/`; track changes here regardless.

## Conventions

- **Breaking change**: rename, remove, or alter the meaning of an exported member; remove or narrow a discriminant variant.
- **Additive change**: add a new variant to a discriminated union, add a new optional field, add a new exported type. Consumers must use `assertNever` on union types so additive changes still surface as compile errors.
- **Note**: changes to the producer side that are visible to consumers but do not change types (e.g. new event ordering, new emission timing).

For each entry, include date, author, what changed, and migration guidance if breaking.

---

## [0.9.0] — 2026-05-12 — Baseline

Establishes the protocol surface for the v0.9 release line.

### Additive
- `src/protocol/runtime/events.ts` extracted from `src/runtime/events.ts` (PR #40, 2026-05-12). Producer/consumer direction rule established; see `docs/migrations/2026-05-12-protocol-seam.md`.
- `src/policy/types.ts` adds `ApprovalSubject` (`tool` / `tx-apply` / `permission-request` kinds), `ApprovalDecision` (`allow` / `deny` / `ask`), and `ApprovalDecider` for payload-aware approvals (PR #41).
- `src/protocol/runtime/events.ts` adds tx-* event variants (`tx-staging-start`, `tx-finalized`, `tx-validated`, `tx-applied`, `tx-aborted`).

### Notes
- `assertNever(event)` lives in `src/headless/events.ts` and serves as the compile-time exhaustiveness check for `RuntimeEvent`. Future consumers (e.g. `src/tui/`) should adopt the same pattern.
