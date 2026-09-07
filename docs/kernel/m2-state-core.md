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
- Atomic worker-loss fencing of the Run, activated launch and writable
  generation into one exact `worker_death` wait, with restart validation and
  retained invocation identities. Cancellation/deadline can still request a
  stop without clearing that wait or asserting containment death.
- Native descriptor-relative generation quarantine relocation on Linux and
  macOS, with a deterministic no-replace target, parent fsync, identity checks
  and exact-pair crash retry. This is a filesystem primitive, not yet the
  containment-death/evidence/SQLite recovery integration.
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
identities, validation, bounded prior-process death inspection, fixed generation
quarantine relocation and idempotent close. It exposes no fd, caller-selected
lock/quarantine path, unlock/relock, signal-sending or general filesystem API.
TypeScript still owns all SQLite state transitions.

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

### Worker-loss fence after ownership acquisition

`beginWorkerRecovery({runId, expectedRunRevision})` is a separate StateStore
transaction, not part of owner acquisition. It derives the wait from one
validated recovery cut; callers cannot supply a wait, generation or death
claim. A trusted Supervisor may revoke even an unexpired worker, and the
operation remains available after cancellation or deadline. It is revocation,
not evidence that a process or containment has died.

- The sole activated launch and its `active|revoking|checkpointing` generation
  atomically become `reconciling` and `fenced_reconciling`. The generation keeps
  its source snapshot, last verified tree, old launch/epoch and any quiesce id.
  The Run loses its active pointer, increments revision, and installs the exact
  initial `worker_death` wait. Its monotonic lease epoch is not reset.
- `openInvocationRefs` retain canonical copies of the existing **prepared
  Journal rows** for all unresolved attempts, in Journal order. These identify
  the original op/attempt/epoch/request/reservation, including older unresolved
  attempts; the Journal remains the sole authority for their current phases.
  The fenced generation retains `fencedJournalSeq` from the same transaction;
  recovery requires exactly the open set in that prefix, even when pre/post-fence
  timestamps are equal. Extra pre-fence settled witnesses and post-fence
  preparations/claims are rejected. Repeated requests do not collapse two
  attempts into one. Late trusted Journal-only settlements do not rewrite the
  wait or erase its original
  identities. Normalized model/tool completion cannot advance its frontier or
  Checkpoint underneath the wait; that requires the future recovery reducer.
- Wait/witness metadata, both lifecycle rows, the Run and its state event
  commit together. Changed Run, heartbeat, generation or Journal cuts reject
  before mutation. Publication/transaction failures cannot partially fence a
  worker or root authority. Restart rehashes the exact wait and witnesses and
  checks the Run/launch/generation bindings and every still-open attempt.
- Cancellation and deadline reuse the existing StopIntent reducers while
  retaining the wait and budget. They cannot terminalize an unretired worker.
  No dispatch, renewal, checkpoint sealing or replacement activation can use
  the fenced rows; the fence itself changes no Journal, Checkpoint, Session,
  workspace bytes or budget counters.

This implements only the mandatory durable fence and its recovery validation.
The initial probe state is `automatic_pending(0,0,nextProbeAt=createdAt)`;
bounded probe dispatch, native whole-containment termination, broker revocation,
quarantine evidence/row integration, preactivation-intent retirement and safe
replacement/restoration remain their owning integrations' work. No probe is
executed and no physical write capability is revoked by this storage operation.
Tests use real SQLite/CAS, signed offline Run fixtures and real owner `SIGKILL`
and restart, not a qualified worker-containment backend. Startup scheduling
must call this reducer; merely opening the store still changes no Run.

### Native generation quarantine relocation

The held native-owner interface exposes only
`quarantineGeneration(generationIdentity, sourceRowVersion)`. It decodes and
rehashes the closed identity, matches its StateRoot to the held root, verifies
the generation-id derivation and host-specific fixed locator, and derives the
sole target as `quarantine/workspace-generations/H(generationId, String(version))`.
No caller supplies a destination, filesystem handle, fallback or success flags.

- Linux relocates the exact `0700` directory at
  `runs/<runId>/generations/<generationId>`; macOS relocates the exact `0600`,
  single-link backing file at the same path with `.img` appended. Parent
  descriptors are same-user `0700`, no-follow and on the held StateRoot device.
  Directory link counts are not file-hardlink counts: the Linux identity no
  longer includes the old impossible fixed `linkCount: 1` constraint. This is
  a pre-cut schema correction, not legacy identity compatibility.
- All filesystem operations use held directory descriptors. The move uses
  Linux `renameat2(RENAME_NOREPLACE)` or macOS `renameatx_np(RENAME_EXCL)`;
  unsupported filesystems fail without a path-based rename or copy/delete
  fallback. All parent links are synced, including newly created quarantine
  ancestors; both rename parents are synced before success is reported.
- Original present/target absent moves the exact inode. Original absent/exact
  target present reobserves and repeats fsync. Both present, both absent,
  identity drift, unsafe permissions, symlinks and substituted parents reject.
  Failure after rename never rolls back or scans for a different target; the
  same durable source version is required on retry.
- The returned immutable observation contains only the exact target inode,
  original absence, no-replace and parent-fsync facts. It neither reads dirty
  contents nor claims a complete tree, guest-volume inspection, process death,
  revoked open descriptors/mounts, or committed generation state. Moving a file
  does **not** stop a writer holding it open.

The future trusted recovery coordinator must first validate the exact fenced
row/current owner, revoke broker and containment write authority, obtain the
required current-inspector death/failure evidence, and then combine this move
with the closed quarantine evidence and versioned SQLite commit. No public
StateStore/control method or startup path calls the primitive yet. Normal
worker replacement and checkpoint restoration remain unavailable.

Tests exercise real host filesystem moves, retained dirty contents, real owner
`SIGKILL`/successor retry, the complete locator conflict matrix, no-follow and
permission guards, and all eight parent-fsync failure points. A separately
compiled **test-only** build of the same C source provides deterministic rename
race/failure barriers; the production helper contains no fault controls.

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
