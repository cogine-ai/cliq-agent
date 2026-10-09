# I1 preactivation retirement and successor retry

Status: **Option A approved; implementation and real qualification in progress.
The before-create retirement/retry tracer has real Linux GREEN; the remaining
creation and successor boundaries are not yet qualified.**
Baseline: `854b9a95e6a99a8380772243853e5b7adc597272` (`main`, PR #514).

This is one complete capability inside I1, not a new work package or a
type-only delivery. The public StateStore/execution test seams remain those
already approved in [the lifecycle plan](i1-trusted-worker-lifecycle.md).

## Outcome

A queued Run whose worker fails before activation can retire the exact old
launch and quarantine its exact generation, then retry from the same ready
Checkpoint using a distinct generation/launch/nonce. Supervisor loss at those
boundaries must follow the same proof requirements. No old handshake is adopted;
no tool claim, budget charge or workspace effect is invented during retirement.

## Verified implementation gap

`run-execution.ts` commits `reserved`, then creates the native worker, observes
its executable/process, publishes containment and WorkerIdentity, and finally
records `preactivated`. The generation remains read-only throughout this gap.

The retained plan binds a cgroup path, logical namespace reservation and old
controller start token. Actual cgroup/namespace inodes and init/monitor/worker
PID/start-token identities exist only in the controller's memory until READY
and the later artifact/state commit. The current controller cleans up on
Supervisor channel loss and exits without a durable identity witness.

`terminateRetained` requires those actual identities. A successor cannot obtain
them from a now-empty cgroup or a missing PID. Existing no-spawn evidence allows
`never_created` or `dead_reaped`, but the latter still requires the exact original
namespace-init token; neither branch may be inferred from an empty path alone.
The same issue exists inside partially failed native creation, where the current
`stop_scope` expects complete process identities that are not yet available.

## Contract decision

### A — descriptor-bound durable backend witness (approved)

Give the exact reserved Linux launch a bounded physical reservation/identity
witness, held through native descriptors and bound to its plan/spec, spawn
nonce, generation and original spawner. Native creation/retirement must preserve
the kernel-observed identities needed after Supervisor loss. Define the ordering
and fsync/atomic-publication requirements before implementing it, including
fork/namespace creation before READY and witness-publication interruption.

This is backend resource evidence, not another Run/WorkerLaunch lifecycle or a
second Journal. It cannot grant activation, choose retry, clear a wait or prove
death merely by existing. A current authorized inspector must revalidate the
exact physical identities and obtain fresh native closure before StateStore
commits retirement. Missing, corrupt, replaced or incomplete evidence remains
fail-closed. Native controller loss before sufficient identity retention is a
negative qualification case, not permission to fabricate no-spawn evidence.

The physical witness's exact shape and creation ordering must be qualified by
the real Linux campaign; this proposal does not assume that an ordinary file
write makes every creation boundary recoverable.

The implementation retains only bounded native birth facts, never a cached
death proof or timestamp. Its ordering is:

1. The held StateOwner creates an exclusive private reservation file beneath
   its descriptor-held runtime directory and fsyncs the file and parent. The
   plan freezes its device/inode/owner identity before freezing the launch spec.
2. The original controller binds the exact plan/spec, nonce, generation and
   spawner to that descriptor and durably acknowledges the binding **before**
   the existing `reserved` transaction. An empty or incompletely bound file
   never qualifies as no-spawn evidence.
3. Native creation retains a durable creation intent before creating resources,
   the monitor's actual PID/start token before releasing its fork barrier, and
   the complete observed namespace/worker identities before reporting READY.
   Any interrupted or invalid record remains fail-closed; parsing an earlier
   complete prefix must not hide a trailing incomplete creation fact.
4. A successor joins the exact original spawner and reads the exact retained
   descriptor. A new trusted controller freshly inspects/terminates its physical
   scope. Historical birth facts choose the exact identities to inspect, but
   cannot themselves prove death or authorize activation.

The same physical witness is used for an ordinary launch failure and successor
recovery. It is never exposed to workspace-controlled input, tool permission
decisions, or the old worker's activation channel.

### B — old controller retained for recovery-only observation

Retain an authenticated, authority-reducing observation/termination channel to
the original controller after Supervisor loss. Never adopt the worker or allow
the successor to activate the old handshake. This avoids some persistent
witness writes, but adds controller lifetime/IPC authentication and handoff
contracts, and still needs a defined fail-closed outcome if that controller dies
before the actual identity is retained. It is a wider interface and ownership
change than A.

Both choices require real physical producers. A decoder, stage code or empty
cgroup check cannot fill the identity gap. Implementing only same-process
cleanup would leave the promised successor path incomplete and is not this
delivery's completion criterion.

## Reuse the existing durable state

- SQL already permits `reserved|preactivated -> retired`. The canonical
  WorkerLaunch type already includes `preactivated_readonly`, but the retired
  decoder admits only `sealed|fenced_reconciling`. Clarify that a retired launch
  retains its last write-authority phase, with exact reason-matched quarantine
  evidence. Never label an unactivated generation sealed or fenced.
- A created-but-unrecorded worker retains an actual observed containment when
  available. Retain WorkerIdentity only if it was genuinely observed; do not
  invent an activation, lease or preactivated transition to make cleanup fit.
- Reuse `launch_aborted` with exact plan-quiescent evidence, or
  `launch_died_before_activation` with exact actual containment/death evidence.
  Extend historical recovery-closure validation to these existing reason edges.
- Queued recovery does not need worker-recovery's fixed-intent supplement.
  Observe/move without incrementing the preactivated generation row: its version
  stays `v` across a post-move/pre-commit crash, so the successor reopens only
  the existing deterministic target for `v`. No directory scan, guessed version
  or new probe field chooses authority.
- Failure cleanup and startup share one exact retirement implementation. After
  fresh native closure and descriptor-relative quarantine, one transaction
  quarantines the generation, retires the old launch, and emits the existing
  Run revision/event. Checkpoint, frontier, Journal, budget and lease epoch stay
  unchanged. Normal retry materializes a new generation and reserves a new
  launch; unsupported/unknown physical closure leaves the old reservation
  blocking release. Existing metadata-only fixtures have no installed execution
  capability: they may close without claiming native retirement, but their
  unretired rows still block retry. A missing/corrupt retained plan cannot make
  that distinction and must retain the actual owner.

## Real verification, one tracer at a time

First reproduce through `executeCurrentTool`: fail after real reservation but
before native spawn, close/reopen the Store, then retry the same Run. Reuse the
existing held-image `fs.readSync` seam rather than mocking the launcher/reducer.
The baseline has now produced an **executed RED** at this public execution seam:
the same Run's retry after close/reopen throws `Run already has an unretired
worker launch`. The one actual held-image read fault and unchanged ready cut
passed before that expected failure. Source revision:
`fab60e484ddeaccc6763b61e4867b8650ec90a40`; free standard Ubuntu 22.04,
Node 22.13.0; [Linux job 113850776335](https://github.com/cogine-ai/cliq-agent/actions/runs/37939743525/job/113850776335).
Baseline local build and all 1805 tests passed before this diagnostic push.
The implementation's focused portable regressions subsequently passed 60/60;
its local full suite passed 1805/1805. Source revision
`43028a3741a0e9fc69319895e33a9d6d88dae96a` then passed the complete new
before-create tracer and all ten existing execution/recovery scenarios on
free standard Ubuntu 22.04, Node 22.13.0:
[Linux job 113861683215](https://github.com/cogine-ai/cliq-agent/actions/runs/37942930149/job/113861683215).
It proves exact old no-spawn retirement, close/reopen, distinct retry and one
real edit/claim/charge, not yet the later creation or successor crash windows.

Two subsequent portable public Store regressions separately produced actual
OS-lock RED, then GREEN after minimal resource-owner corrections. Startup
discovery of a missing reserved plan now enters the retirement-failure boundary
before any decode/read, retaining its actual lock across caller GC. An uncertain
public close is likewise strongly owned until its exact retry succeeds or the
process dies; neither a dropped Store nor a native finalizer can substitute for
resource join. These are real ownership negatives, not Linux death producers.

Then qualify the same complete scenario at these boundaries:

| Boundary | Required physical/fault evidence |
| --- | --- |
| Reserved, before native create | Exact retained row and actual held signed-image read fault |
| Native fork/namespace creation, before READY | Real partial scope and retained descriptor-bound birth witness |
| READY, before identity/state commit | Actual process/image identity and exact still-reserved row |
| Preactivated, before activation | Real committed preactivation and rolled-back activation; no imaginary CAS-read gap |
| Supervisor SIGKILL at each boundary | Parent verifies the exact cut/process first; real child death, successor Store.open and no adoption |
| Generation moved, before retirement commit | Same inode/target/version restored without scanning or changing the target |
| Identity/witness drift or controller/cleanup failure | No positive proof, retirement or retry release; uncertainty remains visible |

Every positive case preserves the old ready Checkpoint and original workspace,
has no preparation/claim/charge/effect before activation, retains old history,
uses distinct new physical identities, and completes exactly one real edit on
retry. Shutdown uncertainty must retain the real owner lock as in #514.

Mac tests can verify canonical closure, error classification and real StateOwner
ownership; they cannot prove Linux namespace/cgroup success. Use the existing
free standard Linux CI environment for the positive native/campaign evidence.
No paid runner, Docker installation, fake native observation or weakened
freshness gate is part of this plan.
