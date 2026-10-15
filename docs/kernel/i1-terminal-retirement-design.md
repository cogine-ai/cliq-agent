# I1 coherent terminal retirement — implementation contract

Status: implementation direction approved on 2026-10-16; not implemented or
qualified by this document. Closed data types/schema, the physical materialization
owner and controller-only birth/retirement receipts have implementation; the owning preparation/retirement producers and
their real Linux qualification remain incomplete. The owner accepted one WorkerLaunch preparation
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

## Confirmed gaps

- Installed cancel currently closes model transports, not the tool operation
  owner. Native invocation result polling has no cancellation input.
- The driver submits a tool result with its pre-cancel Run revision, although
  the existing tool reducer can accept genuine evidence at the current stopped
  cut. Cancellation must not make a real result disappear.
- Worker recovery deliberately rejects stop/expiry because its terminal
  quiescence branch is absent. Removing that check would incorrectly requeue.
- Activation creates a generation and controller before WorkerLaunch reservation.
  Closing their descriptors is not positive durable retirement of either tree.
- Recovery eagerly creates a replacement before retiring the predecessor,
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

The existing broker_release_fenced terminal-abandonment contract requires a
strictly newer StateOwner. Installed broker quiescence or transport.close by
the claiming owner cannot be relabeled as that evidence. The conservative path
keeps waiting until a genuine successor produces the existing fence proof.
Same-process automatic terminal abandonment is outside this package. No new
token-fence/release-mutex/native-join evidence branch is authorized by the
approval, and physical death does not resolve provider effect or billing.

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
