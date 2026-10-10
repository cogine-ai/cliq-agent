# I1: prepare once, reobserve, seal

Baseline: merged PR #517, `5b730cfeb6eb475abb0a0a4ef794a537e7a6194d`.

## Capability and limits

One real contained tool effect can complete after slow workspace observation,
CAS verification, settlement and continuation publication. The public loaded
Run still uses `executeCurrentTool({ expectedRunRevision })`. Preparation and
finalization do not execute another invocation, create another claim, or charge
another tool call. Five-second current-observation authority is not relaxed.

This is one integrated native/StateStore capability, not a new general executor
or a public prepare/refresh/SQL callback interface. It does not complete I1,
enable the default CLI, implement the macOS VM, or change provider billing.

The final small evidence publication can itself fail or remain slow. Final
authority acquisition is bounded; exhausted freshness, a changed owner/cut,
uncertain resource retirement or unresponsive storage cannot count as success.
No guarantee is made that arbitrary disk blocking completes within five
seconds. Freshness is checked at the actual synchronous authority-seal sample,
not at a future, unknowable end of SQLite COMMIT fsync.

## Two truthful observations

The initial canonical death evidence D0 proves the complete worker containment
is empty before a sealed snapshot S is observed. The sealed snapshot explicitly
roots that evidence through `quiescenceEvidenceRef`; a materialization snapshot
forbids that field. The referenced evidence is rehashed, strictly decoded and
bound to the same owner, plan, launch nonce, actual containment and generation.
Its CAS reference already hashes the complete bytes; its embedded evidence
digest is independently checked, not duplicated as a second snapshot field.

After all bulk preparation, the still-owned native scope performs a real new
inspection D1. WorkerLaunch.retirementEvidenceRef roots the complete canonical
D1 artifact. A SQL timestamp alone is not replayable containment/inspector
evidence and cannot replace it. D0 and D1 may have identical bytes if they were
genuinely observed in the same millisecond; their roles remain distinct.

The final transaction C requires `D0 <= S <= D1 <= C`, with `C - D1 <= 5,000 ms`.
The exact current StateOwner and Run/WorkerLaunch/generation/quiesce/Journal cut
are mandatory. Checkpoint.createdAt and WorkerLaunch.retiredAt use the actual
transaction time. Already-published observation, settlement, item and Journal
timestamps stay unchanged and precede that commit. Historical replay checks
their identity/sequence/revision correspondence and the two observations;
time equality is not used as a substitute for atomic publication.

## Native interface

Reuse the existing installed-image-pinned STOP_SCOPE command. Every explicit
stop requests a new native observation, including an already-stopped scope.
The controller revalidates the retained cgroup descriptor's identity and empty
state and absence of the original process identities before sampling its own
wall clock. Repeated polling without a new request returns the original native
timestamp. JavaScript receipt time never turns a cached observation fresh.

The controller, its pinned installation and original containment identity stay
owned through finalization. Already-retired generation/invocation descriptors
cannot be borrowed again or used to reactivate the worker. Closure and owner
loss are fail-closed, not invitations to adopt a retained worker.

## StateStore implementation boundary

Keep large tree/blob/manifest reads and result/settlement/continuation/terminal
publication before the final native observation. The final path publishes only
the small canonical current-death evidence and performs synchronous exact-cut
validation plus one SQLite transaction. It never skips artifact verification
or accepts an unbranded native observation.

If final publication expires the observation, only current-authority inspection
and its small publication may be retried, within a finite attempt bound. The
prepared immutable completion graph and effect are not rebuilt or replayed.
The transaction independently rechecks time, owner and exact mutable fences.
An expired observation at that boundary still refuses the entire mutation.
The bound belongs to one prepared seal, not to each outer retry. An exact Run,
Journal, budget or Session cut change refuses that prepared mutation rather
than rebuilding it. Unrelated Runs advancing the global time fence do not
invalidate immutable preparation: the final transaction samples and accepts C.

Completion, approval (including undispatched-grant refunds), input, terminal
stop and direct generation seal share this proof/commit discipline. Worker-free
operations need no fabricated observation. A cold public StateStore command
without the live native capability must supply valid canonical current evidence
or refuse; old historical bytes cannot mint a refresh capability.

Terminal stop retains one strictly decoded preparation time T in its canonical
terminal detail. Its refunds and cancelled results stay bound to that same T,
with `StopIntent.createdAt <= T <= C`; the owning Run, Checkpoint, launch and
Session SQL projection use C. Public recovery validates both death observations
for every typed sealed/retired activated worker, not only terminal stops, while
preserving the separate no-spawn and quarantined recovery contracts.

## Required evidence

- Public StateStore regressions prove the D0/S/D1/C ordering, exact five-second
  boundary, refusal without a genuine fresh authority path, exact-cut changes
  and historical reopen. Offline proof fixtures are not native qualification.
- A real Linux tool edits its private file exactly once. Real bulk/settlement
  writes are delayed beyond five seconds, and the original controller is
  actually paused. No D1 may be published while it is paused; final evidence
  must carry an inspection time after the controller is released. One completed
  claim, one charge, exact ready bytes, unchanged host bytes/inode, joined
  processes and public reopen must all hold.
- Sustained late final-evidence publication remains bounded and fail-closed:
  no new Checkpoint/completion/charge, permanent claim and conservative budget
  retained, and no second edit. A wrong primary error, missing injected fault,
  manufactured evidence or uncertain cleanup cannot pass.
- Build, full tests, strict campaign checking, design-contract guard and the
  real free-runner Linux campaign must qualify the submitted exact head.
  Native baseline RED and subsequent GREEN are recorded with the PR. Prior
  #517 results are the starting defect evidence, not qualification of this work.
