# I1 coherent terminal retirement — implementation contract

Status: implementation direction approved on 2026-10-16. The original nine-fix
candidate `2630f23` passed both exact-source Linux campaigns, including 29 native
cases per event; that does not complete I1. The owner additionally approved
repairing two shutdown-order defects and a further credential-finalizer shutdown
gap in the same PR on 2026-10-17. Admission shutdown now passes both exact-source
Linux events at `db6f658`; preparation shutdown has genuine forced-stop RED.
Execution producer and credential-finalizer shutdown repairs still require
qualification. At `d9770e2`, both preparation probes lost their final writer
observation before the target stop; their later cleanup exit 1 remains an
unresolved production-retirement signal, not a passing cut. The native
inspection cancellation component reached genuine RED; ABI2 implementation and
the independent installed/effect controls are under qualification. This document itself
qualifies nothing. The owner accepted one WorkerLaunch preparation
spine plus genuine preparation-retirement/private rollback evidence, including
fail-closed incomplete birth. Model unknown retains the existing strictly newer
StateOwner rule. Normative RFC/WP amendments and implementation must ship
together; none of this document itself grants authority.

## Goal and limits

Complete installed Run cancellation/deadline handling across an in-flight
private edit, worker-death recovery and a generation that never reached worker
launch. Keep one lifecycle rather than adding a stop engine, operation-status
protocol, second ledger, Run status or generic recovery bypass.

Reuse StopIntent precedence, WorkerLaunch, WorkspaceGeneration, Journal,
BudgetSettlement, Checkpoint, Session publication and the sole terminal reducer.
The default CLI, Workspace Trust, per-tool permission and OS sandbox remain
independent. No new productive dispatch or permission is allowed after stop.

## Confirmed gaps addressed by the implementation candidate

- Installed cancel previously closed model transports, not the tool operation
  owner. Native invocation result polling has no cancellation input.
- The driver previously submitted a tool result with its pre-cancel Run revision, although
  the existing tool reducer can accept genuine evidence at the current stopped
  cut. Cancellation must not make a real result disappear.
- Worker recovery previously rejected stop/expiry because its terminal
  quiescence branch is absent. Removing that check would incorrectly requeue.
- Activation previously created a generation and controller before WorkerLaunch reservation.
  Closing their descriptors is not positive durable retirement of either tree.
- Recovery previously eagerly created a replacement before retiring the predecessor,
  leaving an unused generation when cancellation wins.
- Claimed private edits need typed rollback closure when no genuine result is
  available; ordinary no-dispatch cancellation cannot close that claim.

## One execution owner, two distinct operations

Add one narrow internal operation to the existing execution module:
`requestStop()` means request productive revocation and retain the original
producer's join. It neither means terminal nor returns death evidence.
It is distinct from final `close()`, which permanently closes the execution
module and launcher. The native resources needed for drain must remain owned.

The control response still acknowledges the persisted StopIntent, not completion
of whole-tree cleanup. After that transaction, revocation enters the real native
owner immediately. The owning join is retained by scheduling; duplicate stop
requests do not create another producer or drop an existing failed join.
Cleanup uses its own bounded recovery continuation, not the aborted productive
signal. A stop during a physical inspection must not cancel that inspection
merely because its authority-reducing work is still needed.

```text
StopIntent commit → revoke productive release → join original producer
                 → preserve actual result / unknown and original charge
                 → prove original physical retirement
                 → typed closure + terminal Checkpoint + Session item
```

## Supervisor shutdown — revoke before joining, fence after settlement

Supervisor shutdown is not `run.cancel`: it creates no StopIntent and must not
erase an accepted admission or replace a genuinely received result with unknown.
Use two phases in the same resource owners, not concurrent full service/Store
closure, a second lifecycle or a transferable shutdown receipt.

The first phase synchronously closes productive gates and starts revocation
before waiting for control handlers or installed scheduling tasks. A submission
owns its complete asynchronous handler, including source capture, independent
instruction capture, assembly, admission and the accepted Run's agent load.
Its existing AbortSignal remains bound to its original private admission token;
the existing transaction-scoped workspace recheck checks abortion before the
first admission write. No post-acceptance abortion check discards the original
committed response. Historical replay does not borrow that transient token.

Start original model transport closure in this phase too: a control handler may
be queued behind its installed credential/runtime borrow. Keep the original
transport, memoized join and dispatch fence through typed settlement. Closing
the transport is neither a refund nor a replacement no-release/death proof.

An in-flight credential finalizer must similarly retain its exact original
native inspection job. The approved signed credential-platform ABI revision
adds cancel-and-join only to that inspection owner; ABI1 is not a fallback.
Shutdown starts cancellation before draining the public finalizer handler,
while its credential scope remains held through the actual worker, watchdog,
bus/runtime descriptor and main-loop timer joins. A JS timeout, detached native
Promise or early lock release is not cancellation. The transaction's existing
closing gate must continue to reject new authority; a previously committed
operation keeps its exact replay result. A failed native retirement remains
sticky and prevents StateOwner or installation release.

An execution's first phase must abort preparation and revoke its original
pending native controller before joining that task; aborting only a file walker
cannot interrupt a native BIND/launch wait. Already claimed/received tool work
must retain its original join and genuinely received result. An idle worker
supporting an in-flight model operation is not fenced in this phase. Any narrow
received-tool drain after the closed gate must retain the exact original worker
and physical owner; it does not reopen dispatch, lease or grant authority.

Final close joins complete handlers and producers while StateOwner and the
installation remain held, settles original model outcomes, then performs the
existing worker fencing/death/retirement and descriptor joins. Only successful
retirement permits the existing graceful owner transition and SQL/lock release.
Initiation and join failures remain retained, and one failure must not prevent
independent owners from starting revocation. No best-effort close is a positive
retirement receipt.

Keep the installed service's two-second stop policy unchanged. Its regression
requires actual zero exit, the original owner's committed `graceful_release`
and a validated successor acquisition, not merely a missing process. The
existing worker inspection's original persisted deadline is also unchanged;
these controls do not assert universal two-second completion for an in-flight
thirty-second inspection or qualify an unobserved precise cut.

The harness-only `3dd1536` kept production identical to `2630f23`. Its PR event
`38990393818` positively observed the original pending admission and AGENTS.md
descriptor, then recorded `Result=timeout`, `ExecMainCode=2`, `ExecMainStatus=9`
under the ordinary two-second policy. The push event `38990389971` legitimately
finished gracefully. Both original reports and the unchanged-runner cleanup
evidence are retained; the positive event does not erase the genuine RED.
Neither observation proves the exact private precommit-abort cut.

At `db6f658`, push `38993016349` and PR `38993020888` both pass admission shutdown
with positive original process/instruction-descriptor/pending-handler checks,
zero service exit, committed graceful owner release and exact successor history.
The PR preparation job `117279313425` positively brackets the queued, unclaimed
Run cut with original Supervisor generation-write observations, then records
the ordinary service's two-second `timeout`, code 2, status 9. That is the
execution shutdown RED. The push preparation failure occurred at the final
pre-stop observation; its later cleanup timeout is not evidence for that cut.
Both failures remain preserved, rather than being conflated or rerun away.

At `d9770e2`, push `38994258934` / PR `38994262929` preserve two further
pre-stop observation failures and cleanup `exit-code`, status 1. No target
preparation stop or graceful release is inferred. Sampling may retry a whole
three-observation attempt within the same thirty-second deadline; it must still
positively observe the original writer, strict public queued cut, same-generation
writer and final same-generation writer immediately before ordinary SIGTERM.
Missing observations are never successful stops. Fixed source-enum diagnostics
may help distinguish genuine preparation registration, activation and native
retirement failures, but cannot release resources or stand in for evidence.

The native component RED on completed push job `117283158935` positively records
an actual pending inspection, then `cancelJoinedWithin1500ms: false`, with the
original inspection connection retired and both children joined. Its specific
cancel-and-join assertion fails; the other three component cases and subsequent
92-test Supervisor suite pass. This is not a compilation/setup failure and does
not qualify the installed finalizer. The new ABI2 owner must pass that same real
component test and the independent signed installed finalizer stop scenario.

## Tool result and settlement rules

| Actual cut | Required behavior |
| --- | --- |
| Prepared, never claimed | Existing positive no-dispatch settlement; undispatched call/suffix cancellation only. |
| Genuine result, same unfenced claim/frontier/native owner | Revalidate current cut and reuse completeTool with current revision; retain executed/error and actual post-effect Checkpoint. No next dispatch. |
| Claimed private edit, result not positively known | Preserve unknown and pessimistically settle once; real whole-containment death plus original generation quarantine/rollback must precede typed failed closure. |
| Unknown external effect | Preserve the existing ReplayClass-specific reconciliation/manual wait; physical zero alone is not effect resolution. |

Private rollback evidence must be a closed union branch binding the original
op/attempt/dispatch, request/grant/target, WorkerLaunch, generation, last ready
Checkpoint, actual death/quarantine/retirement and current inspector. Its normal
tool result reports a proven abandoned private effect, never "not executed".
An unknown-to-failed transition reuses the existing settlement: no second charge,
refund or dispatch permission. Cross-fence late results remain audit-only when
their frontier/subject is no longer current. Every call closes exactly once.

## Stop-aware worker recovery

Reuse the exact persisted worker-death subject, probe nonce and immutable
quarantine anchor. StopIntent may change Run revision; the owner may reread that
same subject and verify a newer stopping cut, not accept an arbitrary frontier.

The final stopped-recovery commit must not expose a queued Run or an invalid
intermediate wait. In particular, a worker-death wait cannot remain installed
after its required reconciling launch/fenced generation are silently replaced
with retired rows. Prepare immutable artifacts and fresh native observations,
then use the existing owning reducers' private commit plans to atomically close
the wait, launch/generation, required invocation settlement and terminal facts.
If an external ambiguity remains, retain its valid typed wait instead of
pretending terminal quiescence. There is no generic clear-wait operation.
Physical closure must not prematurely change the reconciling launch and
fenced_reconciling generation required by that worker-death wait. Keep that
valid tuple, with only existing probe CAS transitions, until full terminal
closure can commit atomically. Switching to another wait would require its
complete owning-validator contract; this proposal does not assume one exists.

This bounded, authority-reducing recovery may proceed after the Run deadline;
it never extends productive eligibility. Keep the original probe deadline,
backoff, five-second evidence freshness, StateOwner and canonical-time gates.
An expired probe, clock regression, CAS drift or failed join retains recovery.
The quarantine target derives from the original anchor even after a physical
move before SQL commit; a new probe/version must not select another target.

Create replacements lazily: retire the original domain first, then prepare the
next generation only if the current Run is still allowed to continue. Stopped,
candidate and unknown branches never create a replacement just to clean it up.

## Approved preparation contract

Keep the existing unique unretired WorkerLaunch per Run. Add a discriminated
`preparing` branch to that same spine, committed before resource creation:

```text
preparing → reserved → preactivated → activated → reconciling / retired
    └────────────────── genuine preparation retirement ─────────→ retired
```

Preparing records only known logical identity: original Run/revision/owner,
source Checkpoint, launch/nonces, fixed deadline and derived resource locators.
It has no worker creation, activation, lease, operation grant, broker release or
private-write authority. Never fill missing generationRef, inode, controller
PID/start, plan/spec or death facts with placeholder values.

A genuine native preparation owner creates resources and records their actual
birth identities. Include the controller leaf/process and reservation, not only
the generation. Record the actual generation identity before copying payload;
partial materialization cannot become ready. Only the real readonly snapshot,
complete plan/spec and durable original BIND acknowledgement allow a CAS from
preparing to the existing reserved branch. Do not reset the original preparation
deadline when promoting. Existing blocked birth/activation ordering then stays.

Early no-worker retirement consumes genuine preparation closure plus original
tree/descriptor/controller/broker joins. It is not preactivation_failed,
launch_aborted, sealed, or ProcessContainmentNoSpawnEvidence with missing fields.
Native records hold real birth facts, not another durable Run phase ledger.
The existing anchor remains a root pin, not an implicit StateOwner/Run authority.

Durable intent is a blocker, not proof: missing, truncated or substituted birth
records remain explicit RECOVERY_REQUIRED after owner loss. Automatic recovery
of every mkdir/clone-before-registration cut is not established by this proposal.
That broader guarantee would require additional native registration design and
real evidence. Old unpaired generations are not backfilled with fictional
launch history or accepted through a permissive legacy path.

## Model unknown — preserved strict rule

The existing `broker_release_fenced` terminal-abandonment contract and its
literal lock action remain unchanged. Installed broker quiescence or
transport.close by the claiming owner cannot be relabeled as that evidence.

The owner additionally approved a distinct `broker_process_domain_dead` branch
on 2026-10-16. It binds the original permanent claim/token and historical
process identity to a genuine fresh PID/start-lifetime death observation under
a strictly newer StateOwner. The initial implementation is limited to the same
verified signed installed runtime and fixed native broker recipe; this recipe
has nontransferable creator-process release authority, including across its
fixed fork/exec paths. Graceful release, a new Supervisor id, a missing socket,
or a caller PID/digest are not death evidence. An old process that is still
alive remains waiting. No token-revoked or active-release-zero observation is
invented for a mutex that disappeared with its process.

Immutable `8c56faf` reached the genuine installed public-cancel terminal RED
after the original fifteen-second deadline in both Linux runs, with unchanged
unknown/full charge and completed joins/scans/cleanup. The next implementation
adds the worker-free owning producer and terminal/history consumer; their new
Linux qualification remains pending. Pure closed-data decoders establish no
native authority. The owning plan holds the real branded signed installation
through its terminal transaction, binds the actual current process and private
native lock, reads the original Journal/Owner/process/recipe closure itself,
and fresh-rechecks native death, lineage and the five-second canonical-time cut
at terminal commit. Active-worker unknowns continue refusing before any seal
preparation; this branch does not substitute for the whole retirement package.
The original unknown and full charge remain unchanged;
there is no retry, fabricated failed result or duplicate settlement. Same-owner
automatic terminal abandonment remains outside this package, and process-domain
death does not resolve provider effect or billing.

The shared retained-owner reader walks genesis through the recorded inspector,
including one exact successor witness if that inspector later died in a
takeover. It does not demand today's active owner or installation and does not
turn a graceful transition into death evidence. Its birth validation supports
the two implemented `fresh_empty|fresh_installed` recipes at the exact current
schema/hash; arbitrary older schemas and migrated origins remain unsupported,
not silently accepted. A historical birth snapshot is never mistaken for a
requirement that the now-grown business database or CAS be empty again.

The owner approved closing the original companion source contract: installed
genesis now records `modelAuthoritySource` as explicit `none` or
`present(closureRef,closureDigest)` from the genuinely held verified installation
in the same first StateOwner transaction. The companion is signed after the
bundle; current installation lookup and CAS search cannot reconstruct its
original provenance. Retained validation requires every original bundle data/
structured edge and that exact companion's typed inventory, and refuses missing,
extra or substituted members even when surrounding snapshot hashes are redone.
The data-only companion validator returns no verified authority; live import
still authenticates every signature. No legacy fallback or new ledger exists.
Local data/history regressions and genuine Linux-only installation regressions
are separate: the latter and the installed terminal/restart consumer must pass
on the next immutable Linux candidate before this package is qualified.

## Validation contract

Use the real signed installed entry/v1 UDS and existing genuine native worker
campaigns. Pure decisions/SQL diagnostics prove only their existing data seam.
Keep free standard Linux runners, every original timeout, secret scan, native
identity check, cleanup and baseline assertion. Do not reconstruct blocked pause
workflows or call timing, an elapsed sleep, or a claim row a precise fork proof.

| Scenario | Required direct evidence |
| --- | --- |
| Queued cancel/expiry | No new productive request or generation; terminal Checkpoint and Session publication once. |
| Preparing cancel | Original preparation joined/retired; no worker activation, invented no-spawn or released slot before proof. |
| Reserved/preactivated stop | Exact original no-spawn or created/dead branch and complete quarantine/retirement. |
| In-flight edit stop/result race | Actual original invocation/release cut observed; producer joined; real result or typed rollback, one claim and no next model/tool dispatch. |
| Stop/expiry during recovery | Original wait/nonce/anchor retained; no replacement/lease; valid final atomic closure, no transient queued state. |
| Restart after quarantine | Same deterministic locator and original claim; no redispatch or duplicate settlement/Session item. |
| Corrupt birth, ABA, failed join, clock regression | Explicit recovery, no terminal/proof/slot release; original authority remains fenced. |
| Normal installed loop | Existing model→edit→model, ready Checkpoint, lease renewal, reconnect/restart, credentials/endpoint and native/P1/P2 campaigns all remain green. |

Exact cuts not genuinely exercised remain unverified, including preparation
pre-registration crashes, native result-versus-revocation, controller-leaf crash
reclamation and move-before-commit interruptions. Designing an assertion or
adding a diagnostic does not qualify a cut. Full I1 and merge readiness remain
false until their required implementation and exact-source evidence are present.
