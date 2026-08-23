# Hidden M2 WP01 State Core

This slice completes the storage core needed by the other Kernel work packages.
It remains hidden and is not a Kernel Cut or a claim that work package 01 is
fully complete.

## Included

- Schema version 2 adds append-only and lifecycle guards for Checkpoints,
  items, Journal facts, worker launches, workspace generations, StateOwner
  history, and the canonical-time fence.
- StateOwner bootstrap, graceful release, contiguous clean reacquisition, exact
  identity/evidence decoding, root/runtime/lock revalidation on every write,
  and explicit clock-regression recovery.
- Exact local-principal and control-channel closure checks bound to the current
  StateRoot.
- Typed workspace-generation and worker-launch reducers covering
  materialization registration, read-only preactivation, atomic Run/lease/write
  activation, narrow heartbeat CAS, revocation, checkpointing, sealing, and
  worker retirement.
- Append-only invocation preparation, permanent singleflight dispatch claims,
  budget reservation/settlement, conservative unknown outcomes, and manual
  abandonment.
- One stable SQLite recovery cut containing the Run, latest Checkpoint, items,
  Journal, unretired launches and generations, and parent/child allocations,
  followed by immutable CAS closure validation.
- Focused state and fault-injection suites, including transaction rollback,
  direct lifecycle-skip rejection, stale-owner fencing, lock replacement,
  expired-lease revival, closed-schema rejection, and artifact registration.

## Deliberately still open

- The descriptor-held cross-process OS lock, positive prior-process death proof,
  and atomic death takeover require the signed native Supervisor/platform
  helper. The TypeScript path fails closed instead of simulating that authority.
- Legacy import, generation cutover, rollback-to-legacy, and native-Windows
  export-only handling remain the migration/rollback tail of WP01 and depend on
  the WP06 authority surfaces.
- Sandbox, containment, operation-grant, typed runtime, Supervisor protocol,
  verifier, child, authorization, MCP/admin, local-inference, list-cut, and
  public-client semantics remain owned by WP02-WP06. This slice stores only the
  state-core portions needed for those integrations and does not make their
  placeholder artifacts executable authority.

Because those gates remain, the default CLI/TUI continues to use the legacy
runtime and the RFC's six-work-package completion count does not advance yet.
