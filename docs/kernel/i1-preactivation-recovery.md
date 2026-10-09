# I1 preactivation retirement and successor retry

Status: **Option A approved; implementation and real qualification in progress.
The before-create, READY-before-identity and invalid private-entry
retirement/retry tracers and reserved-before-create Supervisor crash have real
Linux GREEN. The READY-before-identity Supervisor crash also has real Linux
GREEN, as does committed preactivation before lease activation; the remaining
successor crash boundaries are still being qualified.**
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

The READY-before-identity tracer subsequently passed with the before-create
tracer and all ten existing native scenarios. It independently observes the
actual signed worker executable, namespace/cgroup inodes and PID/start tokens
while SQL still retains `reserved` with no WorkerIdentity or containment. The
injected image-read error then produces real created-worker death, exact
quarantine and one distinct successful retry; no identity commit or activation
is invented. Source revision `6f1d4716f8b04ece7daf63df3495170ebba54993`,
free standard Ubuntu 22.04, Node 22.13.0:
[Linux job 113869762017](https://github.com/cogine-ai/cliq-agent/actions/runs/37945258629/job/113869762017).
All six workflow jobs passed, and the local full suite passed 1807/1807.

A separate actual private-tree tracer then created an escaping symlink beneath
the exact descriptor-held generation after observing READY and before injecting
the same image-read error. Its real Linux RED reached retirement and failed at
`workspace symlink escapes the generation`, not at setup or the fault selector.
Source revision `6021c1c32f455079392f29261eeda8dcfb1dd7bf`:
[Linux job 113876670985](https://github.com/cogine-ai/cliq-agent/actions/runs/37947267308/job/113876670985).
The minimal correction permits `unreadable_partial/path_or_entry_invalid` only
for pure validation failures of actually observed physical entries, after their
cursor/file resources retire and the generation/owner identities are rechecked.
It makes no complete-tree digest or fsync-success claim. Source/CAS integrity,
generic native IO, private Git parsing, cancellation, identity and descriptor
retirement errors remain blocking uncertainty, not partial observations. This
does not claim producer coverage for every partial-observation failure class.
The unchanged real tracer then passed, together with all twelve other native
scenarios, at source revision `ab0bc4b8e80ead581a719f5337e6de717072511b`:
[Linux job 113882359927](https://github.com/cogine-ai/cliq-agent/actions/runs/37948929659/job/113882359927).
The exact old directory inode was quarantined with partial-entry evidence and
the distinct retry produced one real edit/claim/charge. Local build and all
1807 tests passed before pushing this correction.

The next tracer stops a real Supervisor after consuming its exact signed held
image while the sole launch is still reserved. Its parent independently checks
the committed ready cut, the actual binding-only witness and SHA-256 footer,
owner/controller PID tokens, absent cgroup and unchanged generation inode/bytes
before SIGKILL. Only public successor opening may perform fresh native
retirement, followed by one distinct edit retry; the old controller is not
signalled to manufacture closure. This genuine successor case still requires
real Linux qualification before it is counted as complete.
Its first execution at `303c2a46063698b79755e12cde24ceef0e600686` reached
successful successor opening, unchanged ready cut, one retirement revision and
actual original-controller absence. It then failed a test oracle: the public
recovery cut intentionally excludes retired launches, so it cannot supply the
old retired history row. The correction independently reads that exact SQL
history, as the ordinary failure tracer already does, without widening the
production recovery API. This is not an implementation RED or a completed
crash qualification:
[Linux job 113888908835](https://github.com/cogine-ai/cliq-agent/actions/runs/37950845506/job/113888908835).
The portable GC tests also distinguish `open` from `close` failure explicitly;
a later shutdown refusal cannot qualify an unreadable-plan startup rejection.
The next execution at `969dd2162dde99b866bdace872baa0cbaa640462` also verified
the old retired row and exact quarantine before exposing a second oracle error:
canonical no-spawn observations are closed objects, not string discriminants.
The corrected expected backend is now checked against the canonical TypeScript
type and deep-compared in full, including its cgroup path and namespace
reservation. Production retirement is unchanged; a full crash/retry GREEN is
still required:
[Linux job 113894905863](https://github.com/cogine-ai/cliq-agent/actions/runs/37952589604/job/113894905863).
The complete genuine reserved-before-create Supervisor crash and distinct retry
then passed at `63cdf508e25ce5a2c6d2df35dc3196fdaca92e21`, together with all
thirteen other native scenarios:
[Linux job 113901454296](https://github.com/cogine-ai/cliq-agent/actions/runs/37954501234/job/113901454296).
The parent independently observed Supervisor PID 2872 and original controller
PID 2891, killed only the Supervisor, and verified natural controller absence,
fresh successor no-spawn evidence, the same quarantined inode and one real
replacement edit/claim/charge. Local build and all 1807 tests passed before this
push; all six Linux/macOS qualification and Node 22/24 matrix jobs passed.
READY-before-identity is the next genuine crash qualification; ordinary
failure handling at that cut does not substitute for successor opening.
That next tracer reuses the same child/parent operation. Before SIGKILL, its
parent independently verifies all five native witness frame footers with Node
SHA-256, exact zero-padded binding/READY bodies, the real PID-2 signed executable,
same-namespace PID-1 init and exact monitor PID/token/member relationship. The
successor must publish actual whole-containment death with those exact birth
identities while retaining the absence of WorkerIdentity, then satisfy the same
one-edit distinct retry and old-inode/bytes isolation checks. This addition has
now passed at `82a3c081191c6fb62221f01757c80b6ab0917fce`, together with all
fourteen other native scenarios:
[Linux job 113909278670](https://github.com/cogine-ai/cliq-agent/actions/runs/37956807435/job/113909278670).
Its independent pre-crash observation captured Supervisor 2924, controller 2936,
worker 2939, init 2938 and monitor 2937 with actual start tokens. Only the
Supervisor was killed; the successor proved those exact birth identities dead
without inventing WorkerIdentity and completed one distinct edit/claim/charge.
Local build, strict campaign TypeScript checks and all 1807 tests passed before
pushing this tracer; all six qualification and Node 22/24 Linux/macOS jobs passed.

The next tracer targets committed preactivation. It uses a real `Date.now`
sample after `BEGIN IMMEDIATE` but before the activation time fence or any
activation write. The parent must read the independently committed
`preactivated` row and its actual WorkerIdentity/containment while all lease,
ready-cut and budget facts remain powerless. SIGKILL interrupts that real
activation transaction; this cut makes no claim about rolling back already
written activation pages. Successor retirement must preserve the genuinely
recorded identity and containment rather than adopting them for activation.
This tracer passed at `1a463acaef2772b6bd8b76e852aadfdb3aba4ea1`, together with all
fifteen other native scenarios:
[Linux job 113917641321](https://github.com/cogine-ai/cliq-agent/actions/runs/37959269294/job/113917641321).
Actual Supervisor 3028 was killed inside that unwritten activation transaction;
controller 3040, worker 3043, init 3042 and monitor 3041 were independently
observed before the crash. Successor retirement and distinct retry retained the
original committed identity/containment and exact old history. Build, strict
campaign TypeScript checks and all 1807 tests passed locally before pushing;
all six qualification and Node 22/24 Linux/macOS jobs passed.

Queued post-move retirement is next. After one actual pre-create image-read EIO,
the real FileHandle write must finish the temporary quarantine receipt before
the child stops. Publication and the retirement SQL commit have not happened.
The parent treats the child's temporary filename/ref only as untrusted locator
hints: it independently verifies actual canonical bytes, file identity and the
one derived quarantine inode/path for the still-retained generation version.
Successor opening must reuse that exact target, create fresh owner-bound proof,
and commit exactly one retirement without scanning or incrementing the version
before the move. This scenario is not yet qualified.

For the later native-fork/pre-READY window, the user approved a test-only Linux
operating-system tracer. It may observe and suspend the real fork on the free
runner, but must not change the production protocol or fabricate native birth
facts. Its implementation and actual qualification remain pending.
The selected minimal design lets the existing campaign process trace its real
controller descendant, preserving the Supervisor IPC and process topology. A
test-only Node-API module may only arm `PTRACE_O_TRACEFORK`, poll the exact fork
event, and detach/join its attachment; it is not an installed runtime entry.
The precise target is the host monitor fork before MONITOR birth identity is
persisted: the real 2336-byte CGROUP prefix plus an actual newborn process,
not a namespace PID-2 worker or READY claim. Failure to attach/capture/retire is
a campaign failure, never a reason to weaken runner permissions or retry until
capture happens. See the [ptrace contract](https://man7.org/linux/man-pages/man2/ptrace.2.html)
and [Yama ancestry rules](https://docs.kernel.org/admin-guide/LSM/Yama.html).

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
