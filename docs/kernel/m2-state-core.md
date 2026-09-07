# Hidden M2 WP01 State Core

This slice completes the storage core needed by the other Kernel work packages.
It remains hidden and is not a Kernel Cut or a claim that work package 01 is
fully complete.

## Included

- Schema version 2 adds append-only and lifecycle guards for Checkpoints,
  items, Journal facts, worker launches, workspace generations, StateOwner
  history, and the canonical-time fence.
- StateOwner bootstrap, graceful release, contiguous clean reacquisition, exact
  identity/evidence decoding, descriptor-held cross-process OS locking,
  root/runtime/lock revalidation on every write, exact platform process-start
  observation, positive prior-process death inspection with atomic owner
  takeover, and explicit clock-regression recovery.
- Exact local-principal and in-process control-channel closure checks bound to
  the current StateRoot; UDS peers fail closed until native credential capture
  and the closed peer-observation decoder are available.
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
  Native regressions use real competing processes, simultaneous fresh startup,
  graceful close/reopen, failed release/close, and abrupt `SIGKILL`.

## Native StateOwner lifecycle

The helper observes this process's native start token and acquires the fixed
StateRoot/runtime/lock closure. Its opaque held handle supplies descriptor
identities, validation, bounded prior-process death inspection and idempotent
close. It exposes no fd, caller-selected lock path, unlock/relock, signal-sending
or general filesystem API. TypeScript still owns all SQLite state transitions.

- Acquisition opens every root component without following symlinks, holds
  same-user `0700` root/runtime descriptors and a `0600`, single-link regular
  lock descriptor, then takes nonblocking exclusive `flock` **before SQLite is
  opened or CAS is initialized**. Existing databases cannot recreate missing
  runtime/lock layout. Lock/root artifacts use `fstat` identities, with unsigned
  decimal device/inode ids, not separately reopened path observations.
- The handle remains in the StateOwner process. Every existing owner write gate
  validates the held descriptors against their exact locators and permissions;
  validation never reacquires a lock. Successful graceful terminalization and
  SQLite close precede descriptor close. Release/close failure retains the lock
  for an explicit retry. Open failure closes every acquired descriptor.
- macOS reads `proc_pidinfo(PROC_PIDTBSDINFO)` start seconds/microseconds; Linux
  reads `/proc/self/stat` field 22. Neither uses wall-clock-minus-uptime estimates.
- Process exit releases the OS lock, but a free lock is **not** death evidence.
  Startup additionally requires positive absence or start-token mismatch of the
  exact retained predecessor, as described below. It never adopts old workers
  or authorizes effect replay.
- Signed-owner bootstrap additionally requires the exact executable
  `platform_helper` entry `state_owner_native`, version `1`, at
  `native/<platform>-<arch>/state-owner.node`. Its digest/size must match the held
  helper file before loading. Signature verification happens first. The local
  schema-only bootstrap cannot supply signed execution/inspector authority.

### StateOwner crash takeover

`openStateStore` handles graceful reacquisition and crash takeover through the
same private successor implementation; there is no public takeover flag,
caller-provided death evidence or second owner-state protocol.

- Before publishing a successor, startup rehashes the retained runtime,
  process/acquisition and root/lock closure, including the predecessor's
  transition and exact successor bindings. Signed owners still require the
  same explicitly trusted bundle; death cannot authorize a runtime upgrade or
  downgrade to schema-only authority.
- The held native handle compares the retained PID/start token to a bounded
  platform observation. A matching process, unavailable/denied inspection,
  invalid token or changed descriptor rejects startup. Linux reads kernel
  procfs and requires a separate no-signal kernel PID-absence check when the
  process entry is missing: [hidden procfs entries are not absence proof](https://www.kernel.org/doc/html/latest/filesystems/proc.html#mount-options).
  macOS uses `proc_pidinfo(PROC_PIDTBSDINFO)` and distinguishes `ESRCH` from
  other failures. No wall-clock estimate, timeout or free-lock inference is used.
- The successor process/nonce and exact death transition/acquisition artifacts
  are staged in CAS. One SQLite transaction rechecks the held descriptors,
  predecessor, process death and the five-second observation window, then
  terminalizes epoch `n`, appends active `n+1`, roots their artifact metadata and
  transfers the canonical time fence. Clock regression preserves its high-water
  and remains fenced. Publication or commit failure leaves the old owner and
  business rows unchanged; unrooted CAS bytes do not grant authority.
- The transaction does not mutate Runs, workers, generations, Journal claims,
  budgets, Sessions or control responses. An old worker cannot renew or dispatch
  under the new owner. Containment retirement, worker-loss reconciliation and
  safe Run resumption still belong to the Supervisor recovery integration.

Real-process regressions cover live/free-lock refusal, `SIGKILL`, simultaneous
successors, consecutive crashes, substituted historical evidence, signed-runtime
closure, missing artifacts, lock replacement, CAS/transaction failure, and the
exact 5000/5001 ms freshness edge. Old prepared and claimed effects remain intact.

### Native StateOwner build

`npm run build` and `npm test` compile `native/state-owner/state-owner.c` using
`cc` and the current Node installation's `include/node` headers. The output is
an owner-only `0500` file under `dist/native/<platform>-<arch>/`; compilation
atomically replaces it, without truncating an already loaded image. The loader
opens the fixed file without following its final symlink, bounds it to 16 MiB,
verifies its held bytes and loads through the descriptor. A different helper
digest cannot replace the loaded implementation within the same process.
There is no runtime compiler, downloaded addon, or approximate fallback.

For a nonstandard Node installation, supply its matching headers explicitly:

```bash
node scripts/kernel/build-state-owner-native.mjs /absolute/path/to/include/node
npx tsc -p tsconfig.json
node --test --test-concurrency=1 --import tsx src/state/native-owner.test.ts src/state/runtime-owner.test.ts
```

Build before running other targeted suites. The existing CI matrix compiles and
tests this helper on macOS/Linux with Node 22.13 and 24. Node-API version 8 keeps
the binding independent of V8's addon ABI. This is source-checkout/CI integration:
the host-built binary is intentionally excluded from the universal npm tarball.
Signed multi-platform helper installation and release qualification remain WP06
work; no default CLI, sandbox, broker or Supervisor service is enabled here.

## Deliberately still open

- UDS peer-credential capture, whole-containment retirement and worker-loss
  reconciliation still require their native Supervisor integration. SQLite/CAS
  descriptor-relative I/O and signed installation qualification also remain
  open; owner death/takeover alone does not qualify those boundaries.
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
