# I1 trusted worker and recoverable private generation

Status: **Paused at the user's request on 2026-10-09. The fixed worker-recovery
intent supplement is approved; integrated execution and platform qualification
are not complete.**
Source baseline: `30b93356fbc483239d320b7a31ca421b90464e63` (`main`, PR #513).

This is the next integrated capability after native authenticated control and
bounded read cuts. Its approved recovery-intent supplement is recorded in the
[canonical RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md); it creates no
seventh work package. WP01 owns durable facts; WP03 owns actual
execution and filesystem observations; WP04 coordinates the existing closed
operations; WP06 owns installation and qualification. The
[I1–I4 integration order](2026-09-26-design-review.md#5-internal-integration-checkpoints)
remains authoritative.

## One delivery, not a sequence of type-only PRs

The next delivery must exercise one real Linux path:

1. For fresh admission, capture and retain a valid workspace/checkpoint closure
   without modifying the user's workspace or Git index. Continuation/replay and
   recovery consume their frozen closure, never recapture live workspace bytes.
2. Materialize a distinct private generation from that checkpoint, including
   independent Git metadata when the workspace is Git-backed.
3. Reserve the exact worker launch before process creation, then create actual
   strong containment with a blocked, powerless worker.
4. Record native-observed identity and containment; activate the existing
   generation, launch and Run atomically before releasing worker capability.
5. Execute one typed builtin workspace write through an exact permanent claim
   and its immediate pre-I/O release check, inside the correct execution domain.
6. Quiesce/retire writers, observe the complete private tree, and commit its
   immutable result and ready Checkpoint through the existing typed operations.
7. Exercise worker and Supervisor loss. Preserve the exact installed wait,
   positively prove old whole-containment death, quarantine its exact generation,
   and restore into a distinct generation and monotonically newer lease.
8. Use the existing authenticated control/read-cut seam for disconnect,
   reconnect and replay. A reconnect cannot repeat the external write.

Use both Git and non-Git fixtures. The operation may be a declared local fixture
in the integrated test; that does not qualify a model, billing policy, installed
product or complete agent harness. No runtime fallback or fake death/snapshot
artifact may establish the real-execution result.

Do not submit separate PRs solely for copied types, a forwarding launcher,
another scheduler, or isolated reducers. Necessary contracts and checks belong
with their physical producer and this same scenario. Implementation may proceed
in vertical test-first increments without turning every increment into a PR.

## Existing facts to reuse, gaps to close

| Existing module | Reuse | Gap in the integrated path |
| --- | --- | --- |
| StateStore | Generation registration/preactivation, worker reservation/activation, typed tool commits, worker-loss fence | Validate canonical launch/containment/retirement closure, admit the exact replacement branch while its recovery wait remains installed, and commit verified reconciliation |
| Native StateOwner | Held root/lock, owner takeover, authenticated local connection, exact no-replace quarantine | Actual generation creation/materialization/snapshot and execution lifecycle observations |
| Linux execution probe | Demonstrated namespace/cgroup/subreaper and descendant-death mechanics | Production frozen-plan launcher, blocked handshake, exact generation/worker identities and restart inspection |
| Typed runtime/tool planning | Closed requests, permanent dispatch claim, model/tool continuation | Actual broker/execution integration and immediate pre-I/O release/evidence authority |
| RuntimeBundle | Release signature and entry-role validation | Real installed execution bundle and stable bootstrap qualification |

In particular, the current worker reducers merely reading launch/containment or
retirement bytes is not a production proof. A canonical decoder is necessary
but cannot turn caller-supplied booleans into native observation. The present
M0 Linux helper remains a fixed probe, not a production launcher. The separate
worker/controller/edit implementation must qualify its own actual images;
renaming or wrapping the probe cannot establish that qualification.

## Invariants that the implementation must hide or enforce

- StateStore remains the only owner of Run status, revisions, lease epochs,
  launch/generation rows, Journal, budgets, checkpoints and response replay.
  Native handles own resources, not an alternate durable lifecycle.
- All process creation consumes the RFC's exact `SandboxLaunchSpecV1` and
  referenced closure. There is no alternate simplified launch schema, arbitrary
  argv/cwd/env/stdio bag, generic transaction callback or caller-selected mount.
- Retained runtime/executable/profile/resource/owner identities are validated
  before creation. Unimplemented purposes refuse before any process or I/O;
  they must not silently select the worker or probe path.
- Preactivation has no writable generation capability, broker credentials,
  provider/MCP/network capability or child-launch authority. A handshake message
  alone cannot make an unactivated row productive.
- An activated worker can request only an exact typed operation. An operation
  grant, current permanent claim and second release gate all remain necessary.
  Trusting the workspace is not granting tool permission or OS isolation.
- Workspace-controlled configuration, instructions and executable state never
  load before the existing Workspace Trust decision. The execution module does
  not add a second trust or permission policy.
- No worker or descendant receives a mount or credential that reaches the
  original workspace, Cliq state, shared Git metadata, another Run or host HOME.
  Published runtime/CAS bytes are never writable.
- Revocation/fencing precedes termination. A worker exit, disconnected pipe,
  timeout, free owner lock or quarantine rename is not whole-containment death.
- Recovery validates one current immutable cut and fresh native observations.
  It neither adopts old productive workers nor relabels a dirty generation as
  a checkpoint. Failure to prove death leaves the typed wait in place.
- The ready checkpoint refers to the observed post-effect tree. Unknown or
  unresolved effects retain their original Journal identity and conservative
  accounting; lack of a reply is never evidence of no effect.
- No cache replaces current owner/lease/stop/grant/time/release-fence or native
  resource checks. Rebuildable notification/queue maps cannot grant authority.

## Concrete interface choice

Three shapes were compared:

| Shape | Useful property | Reason not to expose the whole shape |
| --- | --- | --- |
| Run-bound factory plus two operations | Keeps resource sequencing local and returns existing committed Run truth | An unrestricted `executeToCheckpoint` would imply unsupported model/verifier/child behavior in this first path |
| Explicit blocked/active/closed native handles | Makes resource ownership, consumed capability and failure cleanup explicit | Exposing each step makes callers responsible for activation/close order and too many failure combinations |
| Current-tool execution plus lost-worker reconciliation | Matches the first integrated caller without another outcome state machine | Keep it Run/revision-bound; a bare Run-id call must not silently select a later tool after a race |

Use the Run-bound shape with the two closed operations needed by this scenario.
Keep blocked/active/retirement handles inside its implementation. The following
is an implementation-interface proposal, not a new wire or artifact schema:

```ts
type RunExecution = Readonly<{
  executeCurrentTool(input: { expectedRunRevision: number }): Promise<Run>;
  recoverWorker(input: { expectedRunRevision: number }): Promise<Run>;
}>;
```

The factory binds this interface to one immutable Run closure and the trusted
Supervisor's existing StateStore, release authority and verified installation.
Opening it validates, but does not spawn, activate, acquire a new lease or start
a recovery operation. Do not accept dependencies, keys, qualification objects,
locators or native handles from a user, model, repository or control frame.
The existing M0 probe result is not automatically proof that a different
production launcher/worker bundle is qualified; exact installed identities and
the real execution campaign must match.

`executeCurrentTool` requires the exact current tool frontier. It reuses the
loaded Run and existing preparation/policy/claim/settlement operations, drives
the necessary real generation/worker/invocation resources, and returns the
committed Run after a ready Checkpoint or existing typed wait/stop disposition.
It does not select another frontier after revision loss or run an unsupported
model/verifier/child path. Unsupported execution rejects before productive I/O;
it does not fall back to the host or probe helper.

`recoverWorker` handles only the selected Run's retained predecessor. It can
materialize the canonical replacement while the exact recovery wait remains
installed, but cannot activate productive replacement work or replay a tool.
The caller rereads the committed Run and schedules eligibility through the
existing Supervisor rules. FIFO, global concurrency, timers, OS service,
provider policy and client rendering are not moved into this module.

Neither operation accepts an arbitrary operation callback, raw bytes to write,
handwritten evidence, settlement amount or target override. Return existing
StateStore truth rather than a second `ExecutionState`/status enum. If storage
cannot commit the required closure, raise the existing error and stop release;
do not return an invented durable wait or checkpoint.

Each call owns its resource scope through normal retirement or fail-closed
reconciliation. No exported `close()` sequence is required from the caller.
The private native handle uses opaque receiver/ownership checks and prevents
reuse; its small consumed/closed flags protect actual resources, not durable
Run semantics. GC can limit leaks but cannot mint death evidence. A new owner
reconstructs inspection from retained exact plans/rows, never adopts a previous
process handle. Client attachment loss is not passed as business cancellation;
Supervisor shutdown and explicit StopIntent retain their existing meanings.

### Worker stays read-only

Keep the worker's generation mount read-only for its entire lifetime. RFC
section 9.1 fixes the worker launch to `preactivated_readonly` and permits the
post-commit activation capability to open a broker channel instead of granting
a writable generation handle. No activation-time remount is necessary.

The typed write uses a distinct `run_invocation` execution domain whose exact
grant/claim/parent/Run/epoch/generation closure is current at both dispatch
gates. It is not a top-level unrelated sibling: the real Linux containment
hierarchy must make the parent worker's death proof cover this write domain.
The macOS adapter must independently prove the equivalent guest/VM ownership;
putting a parent ref in JSON does not establish that relationship.

Revoking the generation blocks new writers and terminates/observes every
existing writer. Checkpoint sealing requires death evidence for the complete
parent worker activation, not merely the last tool. This matches the existing
`prepareToolCheckpoint` contract. Do not optimize away worker retirement or
invent a cheaper writer proof in this capability; measure its cost on the real
scenario before considering a semantic change.

## Verification and completion evidence

The confirmed regression seams are the existing real StateStore interface and
the native execution module's lifecycle interface. Verify observable results,
not private helpers or mocked internal collaborators.

The integrated Linux campaign must prove:

- Original workspace/index remain byte-identical; exactly the intended private
  file changes, and a fresh read recovers the actual ready Checkpoint bytes.
- Preactivation and stale/forged capability attempts perform no productive I/O.
- Worker descendants cannot reach prohibited files, secrets or direct network.
- Losing the client before admission/reply and after operation/reply does not
  create another Run, charge or write on equal replay.
- Lost workers with surviving/reparented descendants are not considered retired
  until the exact cgroup/namespace/descendant death condition is observed.
- Supervisor loss before spawn, after preactivation, after activation and after
  effect/checkpoint publication produces the canonical no-spawn, death,
  reconciliation or unknown-effect outcome for that boundary.
- Replacement generation/launch identities differ; lease epoch increases; old
  heartbeat/dispatch is rejected; no additional effect is blindly replayed.
- Failed death/identity proof or failed replacement materialization/snapshot
  keeps authority fenced and forbids replacement activation. After positive
  death, an unreadable old dirty tree follows the canonical `unreadable_partial`
  quarantine branch and may still recover from a valid ready Checkpoint; those
  unreadable bytes never become a Checkpoint. Publication/transaction failure
  never partially clears the wait.

Reuse the real Linux qualification environment in
`.github/workflows/kernel-foundation.yml`: its disposable delegated cgroup and
unprivileged namespace execution are distinct from the ordinary TypeScript
matrix. The real integration command must fail, not skip, if its required
backend or child campaign is absent. Ordinary local tests must not claim to
have run that command when the environment is unavailable.

The current development machine is macOS. The user confirmed on 2026-10-09
that Docker Desktop is not installed; a discovered CLI/context is not an
available Linux runtime. Do not start/install Docker, change host cgroup policy, weaken a
namespace gate, or modify system services as an implicit test preparation step.
Mac source/native-file tests do not qualify Virtualization.framework. Real Mac
execution additionally needs the pinned guest/toolchain, controlled host and
authorized signed/notarized installation described in the platform plan.

Before pushing a delivery PR, run the repository build, full tests and
design-contract guard. Before recommending merge, also run the real Linux
lifecycle/fault campaign on its supported environment, including the existing
CI environment when it is the available real runner.
Record source revision, actual bundle/helper digests, platform, starting Run
cut, fault boundary, post-restart closure and external effect count. A fixture
release key is development evidence only, never production release authority.

## Gates that remain outside this capability's completion claim

This path does not by itself complete I1. Descriptor-relative SQLite (including
WAL/SHM/journal) and all CAS I/O remain WP01 gates; an fd-shaped pathname is not
a native VFS. Original socket-to-process identity/PID-ABA qualification remains
a prerequisite to public UDS exposure and is not waived by the accepted
StateRoot host-tampering boundary. Full public schema routing, signed stable
installation, supported macOS strong execution and the remaining I1 evidence
also remain open. I2–I4 and all six package acceptance criteria are unchanged.

## Approved fixed recovery intent

The implementation exposed a crash boundary in RFC section 9.1: the generation
may already have moved into its exact quarantine target when the Supervisor
dies before the row CAS. The target is derived from the current `rowVersion`.
Persisting a successor inspection changes the generation's wait ref and
increments that version, so its newly derived target differs from the retained
directory's actual target. The existing rule permits reconstructing the same
target, but does not specify how a successor may reconcile this changed target.

Keep the Run fenced and its wait installed. Do not guess an earlier version,
scan directories to select authority, fabricate death evidence, or activate a
replacement while this boundary remains unresolved.

**Deviation gate: approved by the user.** The worker-only RFC supplement
retains the exact first pre-probe
`WorkspaceGenerationStateV1` row as the immutable inspection target. Reserve
one quarantine source version/target with that first probe, and reuse that
target through later inspection attempts. Subsequent wait-metadata CASes still
increment the real row version, and the final commit must compare the current
row; they must not change the previously reserved physical destination.

This supersedes the initial proposal to relocate an already archived directory
to each newer probe's target. A stable intent avoids those additional filesystem
mutations and needs no new row type, table or second lifecycle. The successor
must still fence-close the predecessor task and obtain its own fresh probe
nonce, deadline and inspector; retaining an inspection target never authorizes
adopting a dead owner's task or evidence. Native reobservation must open only
the original locator or this exact retained target, verify the same descriptor
identity and reject conflicting/both-present/both-absent states. Original-locator
absence and parent fsyncs remain required. The canonical RFC now records this
contract. Its StateStore and native implementation is being verified against
the actual crash boundaries below.

## Earlier portable verification and remaining gaps

The counts in this section precede the approved source-inspection supplement;
they are historical checks, not a final build/test sweep of the current diff.

- Project build and TypeScript checking pass. Generation-focused tests pass 9/9 on
  Darwin, including a real 2,000-directory chain, independent unborn Git
  metadata, symlink-boundary checks, and a real file larger than 512 MiB.
- Focused worker-seal, Run-execution refusal and StateStore-core tests pass
  18/18. These do not establish a positive Linux execution result.
- Native-quarantine, persisted StateStore-probe and worker-recovery suites pass
  66/66. Real `SIGKILL` successors close the old probe through retained owner
  death, honor the full eight-attempt backoff and hard limit, and acquire fresh
  nonces without retargeting. Rehashed foreign anchors, frozen Journal cutoffs
  and reservation versions reject. The physical native staging-directory test
  additionally checks exact archived reopening, descriptor/parent drift,
  both-present/both-absent states and inability to borrow or write. Darwin
  staging directories/backing files are not a VM or qualified Linux worker.
- An isolated worker-thread termination regression with live native trees,
  streams/cursors/borrows and unfinished writers passes on Darwin. Deferred
  native parent ownership no longer depends on JavaScript finalizer order.
  This normal native run is not an AddressSanitizer memory-safety proof.
- Execution loading is exclusive per Run, including its asynchronous opening;
  Store shutdown joins that opening and the complete execution cleanup.
  Resource-free failed validation releases its reservation; a resolved scope
  with failed close or a failed opening with unjoined resources remains owned
  across shutdown retries. The real Store refusal/reservation/shutdown tests
  pass 3/3; unsupported opening leaves the durable closure unchanged and a
  concurrent shutdown permits a genuine successor.
- Same-owner task registration now occurs synchronously after the existing
  dispatch transaction, before inspection I/O. Cancellation aborts real native
  polling and filesystem stream checkpoints; its opaque receipt requires the
  exact wait/dispatch/nonce/task/owner plus actual work and resource joins.
  Missing tasks are not positive receipts. Shutdown gates new dispatch,
  retains the owner through the stored deadline, and commits the existing
  `cancelled_and_joined` timeout XOR before release. A genuine child regression
  confirms that bare metadata-only probes cannot gracefully release the lock;
  a real contender is blocked and only actual `SIGKILL` permits takeover.
- Generation/private-Git tests pass 10/10, including real mid-stream and
  directory-entry cancellation, CAS temporary cleanup and inability to bypass
  an aborted factory. CAS tests pass 32/32: four OS-boundary cleanup-failure
  cases were observed RED before GREEN. Descriptor/temp retirement failures
  retain an internal `RECOVERY_REQUIRED` classification; normal inspection
  errors do not. A failed cleanup cannot mint a receipt or disappear when a
  later independent join succeeds. These portable tests do not qualify native
  Linux cancellation.
- The full test run after cancellation/shutdown and cleanup-failure changes
  passed 1,724/1,724, with no failures or skips (485,312 ms); project build,
  the design-contract guard and its 9 tests also pass. The
  obsolete fixed checkout count and reuse of a predecessor inspector fixture
  after restart were corrected without weakening credential or inspector
  checks. A final private receipt guard refuses a regressed join timestamp
  and permits a fresh real sample after clock repair, reusing the original
  work/resource promises without reexecution or invented future time. After
  this guard, build and the real Store/probe tests pass 7/7. Live Linux
  cancellation and clock-fault behavior remain unqualified.
- The real Linux campaign is implemented but has not run. Its nine explicit
  scenarios cover actual edit/ready Checkpoint/reconnect, claimed parent loss
  before release, no-open-invocation worker recovery, opening versus Store
  close, stopped-controller asynchronous resource join, and actual same-owner
  inspection cancellation/deadline closure followed by successor recovery,
  and Supervisor loss after physical quarantine move but before receipt/CAS
  publication, plus CAS-close uncertainty before probe registration and during
  timeout closure. Those two cases require repeated Store shutdown refusal
  and actual flock contention until real Supervisor death. The cancellation
  case pins one new controller to its actual signed image/start token,
  observes actual `SIGSTOP`, and uses public Store shutdown; it accepts no
  handwritten receipt or early timeout. Offline model and
  initial worker facts are labeled fixtures, not provider or native evidence.
  Its OS-boundary I/O fault injection is distinct from actual process death.
  Portable C text-edit tests and macOS unsupported stubs do not compile or
  qualify the Linux controller/native body. Real Linux compilation, pidfd
  signaling and native asynchronous completion remain required checks.
- Nonempty Git materialization, authenticated fresh workspace capture,
  same-owner inspector cancellation/join platform qualification, ambiguous
  claimed-effect/manual disposition and full stop/shutdown settlement remain
  incomplete. Recovery
  completion checks deadline before physical move and at the final CAS; its
  genuine Linux deadline and newly implemented Supervisor-crash-after-move/before-CAS campaign
  still need physical verification. The fixed intent makes a retained archive
  retryable, but portable tests alone do not establish that integrated result.
- Graceful release validates every retained worker wait and rechecks the
  complete waiting-Run cut inside the final owner transaction, so a new wait
  cannot enter the asynchronous validation gap. Same-owner timeout history
  also requires the exact owning inspector lifetime. Both the previously
  unsafe graceful release and a rehashed foreign-owner lifetime substitution
  were reproduced RED, then rejected after the fix. The positive native
  deadline/cancellation campaign above is still required before qualification.
- Recovery error wrapping now preserves actual resource-retirement failure.
  Parallel CAS operations in the owned inspection/execution path all settle
  before returning, with retirement uncertainty taking precedence over normal
  read/validation errors. Three real Store/CAS regressions were observed RED
  before GREEN: concurrent missing/held recovery reads, concurrent schema reads
  during agent opening, and an actual close failure inside typed model recovery.
  Ordinary missing inputs remain ordinary recovery failures. The first full
  sweep passed 1,726/1,726 with no failures/skips (523,049 ms); the third regression
  and final call-path additions were made during that sweep and have separate
  post-change validation below, not a claim of a final 1,727-test sweep.
  After the final additions, all 64 focused agent/tool/approval/input/control/
  execution-closure/seal/retirement tests pass (102,887 ms), including all three
  retirement regressions. Project build, strict campaign/child typechecking,
  design-contract guard and its 9 tests pass. These portable tests do not
  establish a joined Linux inspector or qualify the crash scenario.
- The new crash campaign uses a separate actual Supervisor. It suspends one
  real CAS write before the quarantine receipt's first byte, after native move;
  its parent independently reobserves the frozen row/owner/dispatch, original
  locator absence, exact archive identity and uncommitted receipt before
  `SIGKILL`. A genuine successor must retain the ready checkpoint, close the
  predecessor task through owner death, acquire a fresh nonce and inspector,
  reuse the first anchor's fixed `rowVersion + 1` destination, and produce only
  one replacement edit. Strict standalone script typechecking passes; on
  Darwin the campaign fails explicitly rather than skipping. The nine actual
  Linux scenarios remain unrun and unqualified.

The next source/Git closure is not satisfied by accepting caller-authored CAS
refs. Fresh admission still verifies root identity and retained manifests.
The descriptor-relative ordinary non-Git source producer is now connected to
one owning authenticated submission task, after persisted Workspace Trust and
the exact Session/physical identity checks. Initial private Git state and final
Run admission are not yet installed by that path. Replay retains the original
capture rather than rereading live bytes. The existing
Git artifact contracts suffice, but nonempty restore additionally needs a
retained signed Git image/dependency closure and fixed read-only inspection
recipe. Ambient `PATH` Git, copying pack bytes without object/delta/reachability
verification, and buffering complete large packs do not meet that contract.
Keep the current generation interface; this work needs no new durable status,
seventh work package, or generic process-execution interface.

### Approved supplement: pre-admission source inspection

The next implementation uncovered a contract gap, not merely a missing Git
adapter. RFC section 9.1 closes `ProcessContainmentOwner` to worker activation,
Run invocation, MCP administration and local inference. Its all-spawn rule
requires an exact owner/recipe/filesystem binding. Fresh source Git inspection
must finish before the Run and its initial Checkpoint commit, so none of those
four owners can legitimately own it. A signed `platform_helper` entry alone
does not establish containment or lifecycle authority.

**Deviation gate: approved by the user (方案 A, 2026-10-08).** RFC section 9.1
now defines one internal pre-admission source-inspection owner, one owning
`source_inspection_attempts` table and the fixed read-only recipe. The single
attempt freezes authenticated principal/Session/intent, exact source-read
authority, input and actual staging/backend reservations; it cannot silently
retry, recapture live bytes, extend its deadline or release an old attempt.
Cancellation and successor cleanup require actual joined resources, descendant
death where applicable, exact staging removal and parent fsync. Network,
credentials, original-workspace writes and arbitrary execution remain
unavailable. This adds no public method, scheduler or seventh work package.

Do not manufacture a provisional Run/worker, relabel this as an MCP probe, or
run host Git outside the canonical launch contract. The alternative is to
finish only the non-Git path while explicitly rejecting Git; it cannot satisfy
this integrated capability's acceptance criteria. Implementation of the
approved supplement is in progress. Actual native producers, not schema-valid
artifacts or booleans, must establish its proofs.

The same source closure must also separate inline request/intent digests from
resolved capture refs and directly retain the original admission response.
Admission-key replay now retains the original request/response association
and binds a new transport request id through current authenticated dispatch,
owner and time fences. Real state-progress/source-movement, corrupted-link and
v3/v4 reopening regressions pass (26 focused tests); migration does not invent
original links for old rows. Native source identity retains no-follow ancestor
descriptors, and bounded metadata-first capture opens only an explicit resolved
selection. Five source-identity, eleven source-capture, two held-Trust and
eighteen real-Git index normalization regressions pass locally. The index codec
checks complete framing/checksum/path semantics and canonical tree identity;
it does not prove object existence/type/reachability or a qualified Git runtime.

The non-Git producer now freezes an ordinary-source projection through actual
metadata-held selection and bounded native capture. Known managed home/state
roots, external devices, special entries and exact exclusions cannot enter its
source graph; links are checked through their declared lookup chains. Whole
source/per-file ceilings are independent of later changed-result limits.
Its seven local regressions pass, including genuine cancellation and drift.
Explicit include authorization and the Git producer are still unsupported,
not silently authorized.

Six exact source-staging regressions pass on APFS, including partial trees,
pending-cleanup shutdown, stale receipts and actual root/ancestor rename races
in an isolated syscall-fault helper. Linux requires the retained original
directory FD's post-unlink link count to be zero. APFS retains its cached link
count, so Darwin instead binds the held parent OS path plus fixed name before
unlink and checks that exact original FD path, current parent and namespace
absence afterward. A rename or failed descriptor/parent observation is sticky
retirement uncertainty. These are physical staging observations, not task or
process joins, VM qualification or a verified Linux branch.

The internal Store entry owns opening/validation/capture promises before their
first asynchronous action. It rejects an unconfigured installation and cancels
and joins outstanding tasks on shutdown. A real isolated Supervisor regression
reproduced an authentication read returning while its sibling CAS close was
unjoined; using the existing all-settled join now preserves that retirement
failure and retains the owner until actual process death. Equal in-flight
submissions share one physical capture while checking each request id and
binding each real authenticated replay to the original failure bytes. A failed
resource join retains its exact task/key reservation; it never becomes a fresh
capture on retry.

Captured and failed replay now require the retained original request, signed
runtime/profile, exact target and retirement/inspector closure. Missing actual
receipt or inspector CAS bytes reject replay. Retained internal errors bind
their exact inspection-derived error id, and historical owner-death transitions
bind the actual successor acquisition timestamp. A real foreign-error CAS/row
substitution regression was observed RED before rejection. Real shutdown during a 64 KiB
source write joins native readers and temporary-file cleanup before owner
release. Shutdown during an ordinary error write commits a matching
`CANCEL_REQUESTED` response/outcome, not a cancelled row with the previous error.

Startup retires the dead predecessor's exact `capturing` reservation before
publishing its successor Store. It uses positive retained owner-death evidence
and the original staging nonce/inode, not the live source, a timeout or a new
capture. A retained absent staging root is reobserved through its held native
parent and fsynced; a replacement is never deleted. The existing fixed prefix
can clean a rejected Git target too: no process may spawn before its `prepared`
transaction commits. Prepared/active process retirement remains unsupported
until its genuine containment closer exists. Internal recovery fixes one
original error in the retired owning row; an actual authenticated reconnect
alone associates those same bytes with its transport request/channel.

Four real isolated-process takeover regressions pass on macOS: a source-write
crash with staging present; staging removed before retired SQL commit; a Git
target rejected before any inspector plan; and uncertain startup CAS close.
The last case first reproduced an incorrectly released native flock. A private
strong resource owner now retains the failed opening across forced GC until
actual process death; ordinary fully joined opening errors still clean up.
All successor scenarios move the source and managed Home away before recovery,
then replay and reopen the retained result without recapture. These tests do
not qualify Linux, a Git inspector, a local model or final Run admission.

The first current full sweep exposed one genuine V2 upgrade fixture failure:
it retained V4 columns/table while relabeling its version. Recreating the actual
V2 layout fixed that regression without relaxing migration. The final unified
sweep after successor recovery, failed-opening retention and exact binding
fixes passed **1,803/1,803**, with zero failures, cancellations or skips
(512,330 ms). Project build, standalone strict campaign/child typechecking,
design-contract guard and its 9 tests also pass. This is local evidence on
Darwin 25.6.0 arm64 / Node v26.0.0, not the supported Node/OS CI matrix or Linux
execution qualification. The actual tested StateOwner image SHA-256 is
`6ef7dba72d8ca26f5103d4486d17777ea4a1ad39ddf15aa5b8fb2bc93ee27002`;
it is a development build, not a signed production installation.

The next physical gate is real Linux compilation and namespace/cgroup/crash
qualification, followed by the signed fixed Git inspector and its frozen
descriptor-held input. An accepted Run additionally requires actual strong
backend/worker probes and registered model/capability/pricing authority; a
model-name string or fixture assembly cannot provide it. Reuse the existing
single admission transaction once those producers exist. Its identity must
come from the original inline request, with resolved refs in the separate
admitted closure digest. First admission still revalidates the Session's exact
root/repository descriptors but consumes retained source content without
recapture; accepted-result replay precedes all live source/Session resolution.
Initial Git WorkspaceState must consume the retained private Git ref, while
non-Git forbids it. No new submit facade, lifecycle or recapture switch is needed.

The user subsequently authorized review and shipping of this integrated pause
point, not completion of I1 or resumption of new feature work. No Docker
installation or local Linux environment preparation was performed. Physical
Linux verification may be deferred to the user's own runner; the repository
campaign is also authorized, but only on free standard GitHub-hosted runners
for this public repository, never larger/paid runners.

Final self-review found two paths that could lose a CAS resource-retirement
failure before worker-task registration or during probe closure. Both now
retain `ResourceRetirementError` in the existing execution resource owner;
ordinary revision, clock and inspection errors remain retryable. The actual
Linux CAS-close fault regressions require the same physical campaign and do
not count as locally executed evidence on macOS. The installation loader also
rejects a native addon owned by another unprivileged UID before hashing and
loading it; a digest alone cannot exclude that file owner's later rewrite.
Its negative Linux check uses readable, same-digest actual installed bytes
under a different owner, not a fake addon or a simulated platform.

The shipping sweep after the retirement fixes passed **1,803/1,803** with
zero failures, cancellations or skips (528,473 ms), followed by a fresh
successful `npm run build`. The 48-test focused closure/source/owner sweep,
9 design-guard tests, design-contract check, portable C edit contract and
standalone strict typechecking of all three Linux campaign/installation
scripts also pass. The nine real Linux lifecycle scenarios and the actual
foreign-owner installation check have not run on this macOS host; their
pending CI result must not be substituted with those portable successes.

The first free `ubuntu-22.04` execution job reached the real GCC/musl build
and rejected a potential `snprintf` overlap inside the controller's retained
scope object (`-Werror=restrict`). Formatting into an independent bounded
local buffer before copying preserves the exact token/length contract and
strict compiler flags. The real namespace/cgroup probe job passed, but that
separate probe does not qualify this worker recipe; its complete compilation
and lifecycle campaign still need their own successful evidence. At the
first shipped commit `e5f0d8a`, the free `ubuntu-24.04` Node 22.13.0 and 24.x
build/full-test jobs also passed, followed by both corresponding `macos-15`
jobs. This is broader platform evidence, not a successful execution campaign
or evidence for later commits. The local full sweep after the compile fix
again passed **1,803/1,803**, with no failures/cancellations/skips (526,626 ms);
design guards, the portable edit contract and all three strict script checks
also pass. The actual Linux compile remains a separate CI gate.

At `08fff28`, the free Linux job compiled the worker/controller/edit/addon
and passed the actual foreign-owner installation regression. The campaign
then correctly rejected the producer's base64url cgroup reservation as not
being a lowercase SHA-256 digest. Both worker and edit producers now use
`canonicalSha256` for that digest; opaque namespace identifiers retain `H`.
The real edited-checkpoint scenario additionally checks both retained plans
against their exact tag/identity inputs. The strict decoder is unchanged.
Successful compilation/loading is still not complete worker qualification.
The subsequent local digest-fix sweep passed **1,803/1,803**, zero
failures/cancellations/skips (496,809 ms). Project/strict-script typechecking,
the design contract guard and portable edit contract also pass; these cannot
substitute for the next actual Linux lifecycle result.

At `932d9c0`, the next real Linux campaign rejected the worker recipe's
cgroup basename: both the launcher and native controller require
`cliq-<64 lowercase hex characters>`, but the producer embedded an opaque
base64url launch/invocation identity. Worker and edit names now derive from
their existing canonical reservation digests. Both exact retained-path
assertions run in the actual completed-edit scenario; the native/launcher
gates and opaque namespace identities are unchanged. All four supported
Node 22/24 build/full-test matrix jobs and the separate Linux namespace/cgroup
probe passed on that commit, but the lifecycle failure remains unqualified
until the corrected recipe passes the actual campaign.
The local basename-fix sweep passed **1,803/1,803**, with zero failures,
cancellations or skips (571,329 ms); project build, strict checking of the
three campaign scripts, the design contract and its 9 tests, and the portable
edit contract also pass. This fix has not yet supplied actual Linux GREEN.

The subsequent seven inline and one documentation review comments were checked
against current code. Bounded shipping fixes add fail-closed seccomp ABI/x32
checks to the fixed signed worker, classify only retained recovery-row changes
as `REVISION_CONFLICT`, and correct WP03's remaining four-owner prose to include
source inspection. The concurrency regression first reproduced the original
`TypeError`, then passed through public Store registration and authenticated
cancel after a real CAS-read barrier. Reads, corruption and resource-retirement
failures are not broadly converted to revision conflicts. The seccomp checks
require the actual Linux kernel, not macOS or an interpreted BPF substitute;
current fixed worker code has no identified alternate-ABI execution path.
The final combined local sweep passed **1,804/1,804**, with zero failures,
cancellations or skips (485,557 ms). Project build, standalone strict campaign
typechecking, the 9 design-guard tests and portable edit contract pass. The
new seccomp syscall regression remains an actual Linux CI gate, not locally
executed evidence. The tested native StateOwner image digest is unchanged.

Review also confirmed unfinished preactivation recovery: a failed
`reserved|preactivated` launch can retain an unretired row and block later
reservation. This requires the RFC's actual planned-containment/no-spawn or
all-descendant death observation, exact durable retirement and successor reaping;
the activated-worker recovery path cannot be reused without those facts.
There is no automatic queued-launch fault recovery at this pause point. New
native observation/recovery capabilities remain paused, and I1 is not complete.

A real SIGKILL during streaming CAS publication may also retain an unlinked
`.tmp-stream-*` file. Ordinary joined abort cleans its exact temporary, but
crash-orphan GC is not implemented. The review's immediate startup deletion
is not adopted in place of bounded, identity-checked cleanup and the RFC's
reachability/retention policy. These disk-availability risks remain explicit.
The two campaign cleanup paths can mask a primary assertion with a cleanup
error, but still fail the job; their diagnostic improvement is not a false-GREEN
fix. Legacy-artifact compatibility is not added to the approved breaking
reconstruction; unsupported historical identities remain fail-closed.

There is also an unqualified availability risk: the current worker death
observation precedes the complete generation walk and checkpoint validation.
Slow trees or storage can exceed the five-second retirement freshness window
and enter recovery instead of completing the edit. The freshness gate remains
unchanged; delayed physical Linux I/O must establish the bounded reobservation
design before claiming production qualification.

When the user resumes, continue the same integrated capability with an
explicitly selected Linux environment; do not turn the contract supplement
into a type-only delivery or claim that I1 is complete.
Update this record when subsequent verification and the real Linux campaign
finish; prior test counts do not qualify subsequent changes.

### Resumed actual Linux diagnosis

The user subsequently authorized necessary fixes using the existing free
standard GitHub-hosted Linux runner. This lifts the diagnosis pause, not the
pause on unrelated capabilities or the missing I1 production qualifications.

The first execution rejection had been hidden by an independent retirement
failure. Run execution now preserves both failures through repeated public
Store shutdown; the crash child also retains its assertion/cleanup chain.
Four raw SQL COUNT selectors use the driver's real `bigint` contract (`0n`),
so their zero-attempt fault predicates actually execute.
At `f082019`, actual controller SIGKILL, exact primary CAS EIO, independent
native cleanup failure, repeated shutdown refusal, and live flock retention
until Supervisor SIGKILL pass. No PID/death/ownership fact is simulated.

The completed edit then exposed a reused sealed helper image at EOF before
bootstrap. Bubblewrap's data bind consumes its input with ordinary reads.
At `39fb367`, each bootstrap opens an independent reader of the same verified
sealed inode; it neither rewinds a shared cursor nor copies the whole image.
The temporary EOF probe is removed. The actual completed edit now passes:
one permanent claim, one native effect, ready checkpoint publication, unchanged
original workspace, and responsive control reads. The preceding controller-loss
regression passes again in the same job:
https://github.com/cogine-ai/cliq-agent/actions/runs/37851170943/job/113564146572.
The local sealed-reader sweep passed **1,804/1,804**, with no failures,
cancellations or skips (644,197 ms); build and strict campaign checks pass.

That job next fails in the parent-loss test's selector, not at the intended
native identity gate: the permanent claim already exists during the initial
sealed adapter-image hash, before native invocation/cgroup creation. The
selector now skips only ENOENT for that exact planned `cgroup.procs` path.
It still requires a real matching executable inode, retained parent identity,
actual SIGKILL before release, rejection, conservative claim reservation and
zero effects. Missing injection remains a failed campaign, never a skip.
The local selector-fix sweep passed **1,804/1,804**, with no failures,
cancellations or skips (613,345 ms); project build, strict campaign checks,
all 9 design-guard tests and the portable edit contract pass.
Actual Linux verification of this selector and the remaining scenarios is
pending; the PR is not yet green and I1 remains incomplete.

At `1865ce6`, both actual Linux jobs inject the parent SIGKILL and pass the
native pre-release identity rejection and worker-death wait checks. The next
assertion incorrectly compares against the earlier fixture checkpoint:
`prepareTool` has already committed the authorization decision checkpoint,
reusing its unchanged ready workspace state. The parent-loss regression now
requires that exact grant-derived checkpoint, its corresponding prepared
Journal sequence before the permanent claim, and the original workspace ref
and bytes. It cannot accept a completed-effect checkpoint or dirty generation
promotion. The regression additionally reads the exact fenced private generation
through a held directory descriptor, verifies its device/inode and no-follow
file type/size, and requires the original bytes there as well: checkpoint and
source preservation alone cannot prove that a blocked edit did not run.
Production checkpoint/lifecycle logic is unchanged.
The local pre-effect/effect-oracle sweep passed **1,804/1,804**, with no
failures, cancellations or skips (526,727 ms); build and strict campaign
typechecking pass.
The complete scene and subsequent scenarios still require actual Linux GREEN;
latest results are recorded on PR #514 and its linked CI checks.

At `9a63bdd`, both actual Linux jobs pass the complete parent-loss scene,
including the descriptor-held private-file zero-effect oracle. The next
no-open-invocation recovery performs actual native death observation, workspace
inspection and quarantine, then fails its final SQLite transaction because
`requireCurrentCut` reads the outer driver inside a scoped transaction.
The helper now explicitly accepts the current connection: the pre-move check
uses the driver, and the final transaction check uses its scoped connection.
All owner, Run/launch/generation/replacement/Journal, abort and deadline gates
remain intact; the SQLite transaction guard is not weakened.
The existing real Linux recovery scene is the regression: it must preserve the
ready checkpoint, archive the exact old generation, install one read-only
replacement and then perform one actual edit. macOS cannot supply its genuine
Linux death observation, so no fabricated proof or new test API is added.
Local SQLite/probe/execution checks pass **43/43**. The completion-fix full
sweep passes **1,804/1,804**, with no failures, cancellations or skips
(712,746 ms); project build, strict campaign typechecking, all 9 design-guard
tests and the portable edit contract pass. Actual Linux verification of this
completion fix is pending; latest results remain on PR #514 and its CI checks.
