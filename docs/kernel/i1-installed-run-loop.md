# I1 — Linux installed Run vertical loop

This change composes the existing state, broker, worker and control contracts
through the signed installed entry. It is one integration deliverable, not
completion of I1, I2, the six work packages or default CLI cutover.

Normative sources are the [RFC](../rfcs/2026-08-11-durable-verified-run-kernel.md)
and its [WP06 contract](../backlog/durable-verified-run-kernel/06-ecosystem-surfaces-and-kernel-cutover.md).
The existing [credential acceptance gaps](i1-credential-authority.md) remain.

## Production composition

- A post-bundle, independently signed companion imports the complete catalog,
  price and detached-signature closure before the existing single active
  selection is published. It breaks the Bundle/endpoint hash cycle without a
  second authority ledger. Admission selects current discovery data; recovery
  verifies the Run's frozen members against its exact signed Bundle.
- The actual authenticated v1 control channel creates a Session, captures a
  trusted source and admits a Run. Frozen instructions, tool contracts,
  capability, full-vector price ceiling, endpoint and credential bindings are
  checked together. Workspace trust does not grant tool permission or replace
  the sandbox. Request replay retains the exact public request core in CAS,
  rooted by the existing request digest, not by a second lifecycle table.
- One Supervisor-owned serial lane drives the retained Run. Client disconnect
  neither owns nor cancels execution. Model and tool operations use the same
  actual worker lease and strongly contained private generation. A nonretired
  launch keeps the single worker slot even after productive driving yields.
  Joined maintenance enforces queued deadlines and renews only a genuinely
  held live lease; initial lease expiry is capped inside its activation
  transaction. Deadline control is loaded before productive scheduling, not
  behind an active broker. Each maintenance cut checks the existing time fence;
  regression fences the lane and revokes/joins producers without healing time.
- The fixed native broker redeems the actual Secret Service item locally,
  claims before network work, then repeats current authority and native worker
  checks before releasing the request body. Raw keys stay outside Supervisor
  JavaScript. The initial recipe is nonstreaming JSON, exact TLS/SPKI, no
  redirects and one bounded native operation deadline, including retirement.
- A real private edit produces a ready automatic Checkpoint. Host source is
  not edited. Reconnect and Supervisor restart read the same durable Run,
  Journal and Checkpoint; they do not resend a completed or ambiguous call.
- Quarantine is not retirement or sealing. Generation retirement requires
  original containment death, joined native tree/mount owners and genuine
  broker quiescence, followed by the existing fenced SQL cut. A successor can
  resume this physical retirement for an already queued quarantine. Terminal
  stop accepts only fully validated sealed or proof-backed retired rows.
  Fully charged installed-model unknowns can retain their exact ambiguity and
  frozen witnesses during physical quarantine only with genuine current broker
  quiescence rechecked before the move and at SQL commit. This branch permits
  no replacement, retry, effect resolution, new Checkpoint or terminal closure.

An ordinary provider refusal is local to its Run. Uncertain physical resource
retirement remains a process-wide failure that retains ownership; it cannot be
turned into successful cleanup or permission to continue.
The public `maxSingleFileBytes` default is 256 MiB, matching the unchanged
Linux worker recipe limit. Installed admission rejects an explicitly larger
value before source capture or admission; it never silently clamps that intent.
The generic 1 MiB..16 GiB input range remains available to other recipes.
The installed broker also supports only its existing ASCII base-path subset
(at most 4096 bytes, with no encoded characters or empty interior segments).
Admission checks the actual registered endpoint before source capture and
refuses unsupported paths; general endpoint registration remains wider. No
registered path is decoded, rewritten or silently normalized to make it fit.
The same preflight rejects more than 64 SPKI pins, matching the native broker's
array capacity without truncating the registered TLS policy. Generic endpoint
registration retains its wider nonempty, unique, sorted pin-array contract.
The fixed bearer recipe requires exactly one model credential grant before
source capture; generic request normalization retains its 1..32 grant range.
The fixed installed recipe also refuses new `default`-policy admissions until
its interactive approval control path is implemented. Generic policy semantics
remain unchanged: `default` asks before writes, `plan` denies them, and no
request is silently upgraded to `accept-edits`. Already committed admission and
source-refusal replays retain their original early replay behavior. This
preflight does not make historical approval waits actionable.
Cancellation preserves exact committed replay before evaluating a new cut.
Reusing that request ID with changed intent remains `REQUEST_ID_CONFLICT`;
a fresh stale revision remains `REVISION_CONFLICT`. Only a fresh request at
the validated current terminal revision returns nonretryable `RUN_TERMINAL`,
without changing Run, Journal, Session or events. Other invalid transitions
are not reclassified by this narrow terminal error.
New installed Session creation holds the actual platform user's persisted
Workspace Trust before reading workspace Git configuration, then reasserts
that same held Trust after capture and before the final write transaction.
Exact committed replays still precede all home/workspace opening; generic
non-installed Session creation is unchanged.
The installed scheduler retains at most 1000 nonterminal Runs across Sessions.
An installed-only, read-only preflight refuses a full queue before the physical
source capture factory. It follows the existing source request/key conflicts
and original in-flight capture join. Passing reserves no capacity or authority.
New installed admission checks that same bound in its original write transaction,
after replay/conflict and all authority/time guards, before inserting any Run.
Queued, running and waiting Runs occupy capacity; terminal history does not.
Capacity refusal neither disables the scheduler nor changes generic admission,
and the existing strict inventory readers still reject an inconsistent overflow.
Only this fixed capacity classification returns the RFC's
`RESOURCE_EXHAUSTED(resourceKind='run_queue', retryable=true, retryAfterMs=1000)`;
ordinary malformed requests remain `INVALID_REQUEST`. The delay is a retry hint,
not a promise of capacity or permission to retry any effect.
After a validated terminal Run, its joined driver task closes the original
launcher/sealed-image owners before evicting memory caches. This reclaims no
durable history and does not treat a candidate, unknown or wait as terminal.

## Preparation-retirement implementation boundary

The [approved coherent retirement contract](i1-terminal-retirement-design.md)
keeps one WorkerLaunch lifecycle and the strictly newer-StateOwner rule for
model unknown. Its closed data union distinguishes non-executing `preparing`,
bound launches and retired preparation without fictional generation, worker,
lease or write fields. Schema V5 extends the existing phase triggers; it does
not add a ledger, backfill birth history or remove the unique unretired index.
The promotion reducer retains complete actual birth bindings; the decoder alone
cannot enforce transition history. The preparation producer now registers that
same spine before allocating resources, binds actual births before copying,
and promotes only after genuine BIND without resetting its original deadline.
Its owning history validator rewalks both promotion and preparation retirement;
missing, incomplete or substituted births still require recovery. An unverified
preparation quarantine is accepted only inside the complete historical retirement
closure, never as a standalone current quarantined row. No prepared shape can
release a slot or grant execution. These implementations require new exact-head
Linux qualification; earlier data/schema evidence does not qualify them.
The new native controller-only retirement receipt requires the original
authenticated ordinary controller, original join and actual leaf removal;
each read rechecks the held root/parent, original process lifetime and absent
leaf. It does not prove worker no-spawn, workspace or broker retirement, and
becomes invalid when its launcher closes. Immutable `5bc17c1` passed this new
receipt, all original 25 native scenarios and installed Trust ordering in both
Linux events; those jobs are not qualification of the remaining lifecycle.
Missing/partial/substituted birth and every unexecuted physical cut remain
explicitly recovery-required or unverified.

The physical materialization owner now separates actual directory birth from
copying and complete rewalk. Its synchronous factory starts no allocation;
the installed composition can retain the owner before starting work. Close
joins copying and every minted snapshot/CAS operation before a separate fresh
native retirement read. Starting close synchronously refuses new execution
borrows without closing the tree ahead of its required CAS join. The installed
owner now binds that lifetime into StateStore; the materialization receipt alone
still does not prove directory quarantine, containment death or terminality. Genuine
controller birth now records the authenticated HELLO time in native code and
freshly checks the original root/parent/leaf and PID/start lifetime; its opaque
token and retirement receipt share the original identity digest. Immutable
`e46c752` reached the exact missing-reader RED in both real native campaigns.
Immutable `bebbb45` then passed the complete controller-birth assertions and all
25 original native scenarios in both real Linux event runs. The owning
StateStore preparation graph was not exercised by those historical runs.

Instruction capture uses a fixed native instruction cursor: Git metadata is
never entered, only exact `AGENTS.md` file contents may be read, and symlink
contents are unavailable. The ordinary source cursor still rejects selected
nested repositories. Source exclusion does not discard ordinary instruction
scopes; Trust, source permission and tool permission remain separate. Real
descriptor/CAS regressions pass. Both `e46c752` installed failure campaigns
passed captured bytes and source exclusion, then the owned HTTPS fixture
failed before qualifying the prompt or reaching Busy. Its raw-newline substring
assertion is now replaced by an exact canonical instruction-block/scope check,
with a real capture/CAS/production-renderer regression. Actual installed prompt
qualification is now GREEN at immutable `bebbb45` in both actual installed
failure campaigns, including exact structured guidance received by the owned
HTTPS fixture. Production rendering is unchanged.

Both `5bc17c1` installed failure campaigns reached the exact Busy UDS regression:
actual `INVALID_REQUEST` instead of required `RATE_LIMITED`. The dedicated,
immutable projection now applies only to `run.submit` scope contention; the
non-reentrant scope guard is unchanged. The `e46c752` prompt-fixture failure
prevented this assertion from executing; immutable `bebbb45` subsequently
passed actual `RATE_LIMITED` and exact-payload assertions in both real installed
failure campaigns. The fixed retry hint does not authorize retry of an
invocation or effect. Both event workflows completed all nine jobs successfully,
including original HTTP429/full-charge/terminal-once/replay assertions, retained
secret scans, native joins and resource cleanup; no archive hash is inferred
from this status statement.

The approved independent `broker_process_domain_dead` contract now has pure
closed-data decoders and a new real installed-journey target after all original
short-Run assertions. The target reuses the already-closed reflection broker's
unknown and actual Supervisor restart, then requests public cancellation and
requires exact original claim/process/token, strictly newer same-signed-runtime
inspector, immutable unknown/full charge, one terminal Checkpoint/Session item,
cancel replay and contiguous attach. Immutable `8c56faf` reached the precise
consumer RED in both real Linux runs: public cancel accepted, unchanged queued
unknown with StopIntent, four provider requests and no provider failure, then
the original 15-second terminal deadline. This was not a client/setup timeout;
joins, scans and cleanup completed, but the later terminal assertions and full
final corpus did not execute. The independent native prior-lifetime/time and
close-fault/FD-reuse/GC-lock-retention regressions passed on actual Linux.

The next implementation adds the genuine held-installation owning plan and
complete retained StateOwner-prefix reader, with fresh native death and exact
owner/Journal/settlement CAS in the terminal transaction. It is worker-free:
unknowns with an active worker still refuse before any seal preparation.
Generic Run loaders cannot mint this evidence; the original fixed signed
SEA/Linux/main-thread/backend gate is shared with real broker dispatch. The
new installed target additionally requires an actual restart after terminal
commit, unchanged history, original cancellation replay and no extra effect.
This implementation and the post-terminal restart still require new exact-head
Linux qualification. It is not a live POST producer crash: that separate
physical cut remains explicitly false.
The owner approved retaining the original optional companion source in the same
first StateOwner transaction. The implementation now records explicit `none` or
`present(closureRef,closureDigest)` and rewalks the original all-and-only signed
seed; genuine Linux installation regressions remain unqualified. Today's
selection, CAS search and the narrower original Run-used model closure cannot
stand in for the original whole-inventory provenance.
Full I1 and unexecuted crash cuts remain incomplete. The owning preparation,
private rollback and atomic stopped-recovery implementations below must pass
their independent current-source Linux campaigns before being qualified.

## Validation boundary

The Linux journey uses a disposable real user manager, signed installation,
Secret Service, native broker and an owned scripted HTTPS endpoint on a free
standard Ubuntu 22.04 runner. It calls the installed entry and existing v1 UDS,
not private Store, native-owner or authority factories.
For final exit-history observation only, a test observer retains the two actual
unit objects on one continuous user-bus connection before ordinary stop/show,
then releases both references, closes and joins. It does not change the production
profiles or substitute for normal-exit, process-absence or secret-scan assertions.
Its disposable HOME requires a real bounded ext4 filesystem: the native
generation and controller gates check total filesystem capacity, not free
space. Providing this physical limit for the experiment does not qualify an
ordinary host filesystem, an automatic quota installer or per-generation
storage isolation. The installed executable still has to run from that volume;
the worker's separate filesystem, permission and network gates are unchanged.

Its required positive chain is model → private edit → model, with nine exact
prepared/claimed/completed Journal rows, byte-verified ready Checkpoint,
unchanged source, disconnect/reconnect, exact and fresh-nonce replay,
Supervisor restart without a repeated effect, and proof-backed cancellation.
The model's final response is an I2 candidate handoff, **not** verified success.
The same experiment observes that candidate's original worker for at least
65 seconds, then verifies a capacity-blocked Run reaches its own three-second
deadline with zero effects. A separate 45-second Run verifies real activation
and cancellation. Fixture wall time covers these added experiments; existing
phase limits, runner timeout, scan bounds and safety assertions are unchanged.
Public status and launch identity across 65 seconds alone do not prove a lease
was renewed. The agreed diagnostic additionally takes two independent, short
read-only SQLite cuts before and after that interval, tied to the public Run and
its exact activated WorkerLaunch. Both the version and expiry must advance,
the second observation must cross the first expiry while retaining a live lease,
and the complete non-lease launch projection, database identity and Supervisor
process must remain unchanged. The diagnostic creates no StateOwner, writes no
database and provides no clock, dispatch or physical recovery authority. Its
regressions do not qualify actual renewal; only an executed exact-SHA installed
journey with these assertions establishes that narrow claim.

The negative endpoint response exercises native secret-reflection refusal.
Only a real released request with joined resources can produce the existing
exact broker ambiguity branch. Its unknown Journal charges the full reservation
to consumed budget, clears the reservation and uses the actual settlement timestamp. The fixed
`broker_response_refused` log correlates that refusal to the actual claim; it
contains no secret or dynamic provider diagnostic and grants no authority.

An independent fresh-UID campaign requires a positively received owned HTTP429
response to retain its exact completed model observation and full charge, then
stop as `runtime_failed` before the Run deadline. It checks the failure wrapper,
StopIntent, terminal detail, native terminal drain, one Session publication and
reconnect/replay without another provider request. It shares the real installed
setup and unchanged cleanup/scan bounds, not the full journey's secret or state.
Only a passing complete report qualifies this case; neither a timeout nor the
separate full journey's success does so.
After that terminal drain, the same independent campaign obtains a genuine
retired source refusal from duplicate exclude selectors, revokes the original
credential through the installed entry and deletes its actual Secret Service
item. Original- and fresh-nonce replay must preserve the exact refusal, while
request-ID and admission-key conflicts remain conflicts without a new Run,
Session change or provider request. This remains inside the existing scan cap;
it does not add a source experiment to the full journey's near-cap corpus.
It then creates a second real Session using an NFD name: normalized-equivalent
intent may replay under a fresh nonce, but different original public bytes under
the same nonce must conflict. Normalization must not replace wire identity.
The same campaign submits its Run objective in NFD, retains that original JCS
request identity, and requires the objective artifact and actual owned HTTPS
request to contain NFC. After credential revocation, exact and fresh normalized
nonce replay preserve the original admission/refusal responses; changed original
values under either bound nonce conflict, and a normalized digest substituted
into the NFD request is rejected. This is canonical JSON identity, not retention
of transport whitespace, key order or escape spelling. Only a complete passing
current-source campaign qualifies that installed chain.

A second independent campaign temporarily changes only the test user's default
Secret Service alias through the existing standard-API fixture. It requires a
real unclaimed preparation failure and complete refund, restores the exact
original collection on the same daemon and item lifetime, then requires the
same Run/worker to dispatch once, retain its candidate and genuinely drain on
explicit cancellation. This tests recovery from temporary configuration drift,
not locked-store recovery, daemon restart or permission to resend a claimed or
unknown invocation. The pure scheduling decision regressions grant no authority
and cannot replace this installed observation or its final scans and cleanup.
After genuine cancellation, this campaign closes and joins its owned HTTPS
listener before another Run attempts the same endpoint. A real post-claim
connection refusal must retain a fully charged `unknown`, never an unsettled
claim, refund or resend. This does not qualify the pre-connect claim gap,
unknown cancellation/terminal outcome, or a post-claim no-release producer.

The approved read-only SQL capacity seam uses real SQLite data to verify the
999/1000 boundary, all three nonterminal states and terminal capacity release.
It creates no StateOwner, installed identity or native proof. It does not
qualify an actual installed 1000-Run load or replace the original admission
transaction's replay/conflict, authority, time and atomicity requirements.
It also verifies the exact canonical fixed public refusal projection reused by
the server; it does not dynamically exercise a full-capacity installed UDS call.

Preactivation quarantine retirement is covered by the existing real worker
campaign, not inferred from a later successful worker. A joined reservation
inspector supplies a distinct native capability, rechecking the original birth
witness and kernel lifetimes synchronously at the retirement transaction. The
no-spawn branch invents no containment or WorkerIdentity; the created branch
requires its exact empty original cgroup and vanished process lifetimes. Both
retain the workspace/broker owners, five resource-zero predicates and existing
time/terminal gates. The campaign requires the original generation's separate
quarantine-to-retired proof, unchanged Journal/charges/private bytes, and one
terminal Session publication. This does not implement discard of a healthy
generation with no WorkerLaunch reservation.

The native broker returns its actual closeable owner synchronously instead of
waiting for preparation I/O;
both installed registries record it synchronously before awaiting `ready`.
Shutdown cancels these owners before joining producers, without waiting for
their credential lock. Failed/cancelled preparation cannot reject `ready`
before its original worker, connection, timer and cleanup-hook owners join.
The approved isolated native lifecycle test delays a real external D-Bus reply;
within one 1500 ms window it requires ready rejection, native close and the
external bus's actual connection disappearance, before releasing that reply.
Even a failing test must then join the original connection and fixture children
and preserve the host runtime namespace. This is a native lifecycle seam, not
an installed Supervisor stop cut, queue-starvation bound or full I1 proof.

The ordinary credential scope remains strictly non-reentrant. Only its fixed
busy refusal before the model callback enters, with no native transport and
exactly the original unclaimed prepared row, may use the existing pre-dispatch
failure settlement. The original owner/time/revision/claim checks still decide
the final transaction; no callback-entry error or permanent/unknown claim gains
retry authority. Automatic wake still requires the same original error identity,
exact prepared/failed history, actual settlement and existing ready retry policy.
Copied request bytes are scrubbed even on digest or scope-entry refusal.
The real signed-selection guard test proves that classification and reservation
release without activating ambient credential authority. It does not qualify an
actual installed concurrent finalizer-versus-prepared dispatch cut.

This document describes the implemented composition and its validation boundary;
it does not certify a source revision. Qualification requires the exact-SHA
evidence set described below. The journey's bounded reports cover only assertions
that actually execute. Pure-data codec, corruption and local resource tests do
not establish physical Linux authority.

Still unverified by this scope: real-provider capability and billing,
streaming, macOS strong execution, cross-reboot recovery, live updates,
unexecuted credential finalizer/producer/ABA and exact crash cuts, and I2
verification/result publication. No blocked pause workflow is retried. The
legacy default path is not cut over or used as a fallback for this entry.
The queued deadline experiment does not qualify a live worker's exact deadline
or a clock-regression-during-release cut; those remain unverified.

New replacements are now created lazily only after genuine predecessor
retirement and a fresh productive cut. A current preparing generation has its
own original materialization/controller/reservation join and typed retirement;
old unpaired generations are not retroactively granted fictional birth history.
Installed cancellation now revokes the original tool controller and retains its
join. An authentic already-received result is retained; otherwise the original
unknown/full charge precedes genuine private rollback, with no refund or retry.
The `ac7d167` push and PR native campaigns both reached an actual edit, original
worker death and checkpointing before injecting one joined CAS write ENOSPC.
Both then failed the unchanged original-owner assertion (`waiting` instead of
`running`): this is genuine post-result durability RED, not installation setup
failure or full-disk qualification. The current repair candidate retains the
original result and physical owner across positively joined CAS write failure
or an actual native SQL mutation failure followed by successful rollback,
including already committed revocation/checkpointing stages. Retrying
the effect, converting its known result to unknown, rebuilding a prepared
completion to reset its three final-death observations, or treating failed CAS
temporary cleanup as recoverable publication are not acceptable substitutes.
The same private completion keeps its selected cut, immutable settlement and
continuation graph, partial publications and cumulative three-observation death
budget. Only an exactly validated monotonic StopIntent change can rebind its
revision; the first conflicting public call still refuses. Failed temporary,
descriptor or rollback cleanup cannot grant a retry classification. Maintenance
and close may resume only this original persistence owner, never prepare or
release another effect. The existing exhausted-freshness recovery assertions
remain unchanged. Current-source Linux GREEN is still required; neither these
implementation changes nor the normal received-tool SIGTERM campaign qualifies
the post-result failure-recovery cut.
The original-release timeout's retained negative reports include temporary
fixed-stage observations. Their last observed boundary never proves phase
duration, a sole cause or retirement. The tagged logs, single-byte stderr
observations and temporary refusal statuses were removed only after both
matching Linux received-tool campaigns passed with the unchanged five-second
poll, 64 MiB target and two-second stop. All historical negative evidence stays
retained; the diagnostic-free source still requires fresh matching validation.
The decoder now counts and copies binary-safe ASCII spans in bulk while keeping
the original replacement decoding, UTF-16 counts and exact output bound for
mixed or invalid UTF-8. The portable text contract includes word boundaries,
embedded NUL and the unchanged 64 MiB received-tool size. This optimization is
not physical authority or a real-time guarantee under arbitrary OS scheduling;
the matching complete installed report remains the acceptance boundary.
Stopped worker recovery retains the exact wait/nonce/anchor until its unique
atomic terminal transaction; it never exposes a transient queued replacement.
The real worker campaign exercises these branches separately from
the installed journey. They are implementation candidates, not qualified merely
by adding tests; accepted StopIntent is not physical retirement evidence.
The queued launcher-image allocation guard is implemented. The approved read-only
descriptor-inventory diagnostic pins the original Supervisor's PID/start/image,
bounds its inventory and compares actual sealed-image identities across two
ordinary queued cuts. Stop/cleanup is deliberately not gated. It requires an
executed complete current-source report; the existing queued-deadline assertions
alone do not qualify absence of retained images.

Credential redemption refusal now retains exact original credential/endpoint
records and stops an unclaimed Run as runtime_failed before its deadline, rather
than keeping the only lane until expiry. A new independent signed installed
campaign revokes a real credential after queued admission, requires zero provider
release and complete terminal/restart history. The original installed Busy
campaign additionally checks credential.finalize and an explicit continuation
replay after drain; its RATE_LIMITED hint grants no effect-retry permission.
The verified installed credential facade refuses scope contention before
enqueueing installation work, so it cannot wait behind the very native callback
whose Busy condition it must report. Original held-identity checks remain.
Neither campaign is qualified until a complete current-source report passes.

After claim but before CONNECT, only the original native token/release mutex,
actual I/O join and a held opaque no-release guard can produce the existing
same-owner zero-consumption settlement. A closed transport report alone cannot.
The native lifecycle regression exercises that retained mutex and environment
teardown, not the exact installed SQL claim-to-CONNECT cut, which remains
unverified. A genuinely received model response is retained by its original
settlement owner across stop-only revision races and durability retry; it is
never re-requested. The portable concurrent public-operations regression accepts
either genuine CAS winner and verifies the single original completion and charge;
a stale cancellation must conflict before a fresh-revision cancellation. It does
not force a publication interleaving or physically qualify every post-response
publication failure cut.

An independent approved storage-failure campaign retains one original ordinary
authenticated v1 connection before an actual POST. On its disposable bounded
ext4 volume only, it holds the original CAS inode and temporarily sets its
immutable flag: mode, identity and reads remain unchanged, while an actual
unprivileged create fails with EPERM. After closing the original owned endpoint
connection it requires the exact unsettled claim and degraded public status
while writes remain refused; after unconditional exact flag restoration it
requires one same-owner, fully charged unknown settlement and no additional
accepted TCP connection, TLS connection or POST. Only then may actual successor
restart and public cancellation close the historical ambiguity. This tests the
common retained failed-producer owner, not storage failure while a never-CONNECT
mutex guard is held; that distinct cut remains unverified. Neither the fixture
nor this document is qualification without its complete exact-source report.
The fixed model recipe now admits a normal request only when both its frozen
token threshold and its actual provider-native serialized body fit. Compaction
keeps complete, protected-prefix selection and additionally checks the complete
escaped compaction envelope against the same 1 MiB bound. No safe candidate
means a reproducible resource StopIntent and the original proof-backed terminal
drain, never truncation, a larger cap, another claim or reduced signed billing.
The separate installed request-resource campaign uses one actual signed package,
three public Runs and six owned HTTPS POSTs to check whole-prefix compaction,
byte-only exhaustion below the token threshold, queued successor dispatch,
terminal history, reconnect and Supervisor restart without redispatch. It uses
its own disposable UID so the original full campaign and its 4096-stream/512 MiB
scan limits remain unchanged. It is not qualified before its complete matching
Linux report passes. Clearing the public worker pointer is not independent
retirement evidence. The approved read-only diagnostic additionally fixes the
actual original WorkerLaunch, generation and CAS worker identity before sending
the fifth genuine owned HTTPS response, then observes that same worker's
retirement and PID/start lifetime after terminalization, reconnect and restart.
It reads closed, bounded SQLite/CAS data without creating StateOwner or native
authority, and preserves the original active-lease reader's stricter contract.
The normal stop branch retains a sealed generation; this is not a claim that
the generation directory was deleted. Independent qualification is limited to
the original worker process lifetime, not every descendant, cgroup or mount,
and remains unqualified until its complete matching Linux report passes.
Its restart observation retains both original unit histories, while stopping
only Supervisor. The original two-unit runtime assertion remains in force.
The read-only property query explicitly includes `TimeoutStopUSec`; an omitted
property cannot stand in for checking the actual unchanged two-second policy.
The 30-second native deadline bounds operation eligibility and cancellation,
not hard real-time disappearance under arbitrary OS scheduling. Completion
and retirement receipts still require the actual worker and callback joins.

The finalizer fixture starts its one original external Secret Service after
manager/owner/endpoint metadata setup, before real enrollment. The same service
identity must survive enrollment, ordinary stop, successor cleanup, retry and
revoke; it is never replaced to finish the campaign. Its 90-second deadline,
60-second enrollment budget and two-second unit stop are unchanged. Bounded
parent-spawn age and a fixed deadline-expired marker distinguish observations
from a guessed service lifetime; yielding pending pipe callbacks does not retry
the failed operation. Only the full matching Linux report can qualify this
changed fixture lifetime, not the diagnostic or prior successful heads.

## Evidence

Qualification evidence is indexed in the associated complete PR's Evidence
section and preserved in its retained evidence archive. The manifest identifies
the exact tested source SHA, workflow run and attempt, bounded journey report,
cleanup report and artifact SHA-256 hashes. Generated run identifiers and hashes
are not committed back into source.

A passing claim requires the matching immutable-SHA workflow and complete reports
to satisfy the existing acceptance criteria, including successful writer/resource
joins, retained-secret scanning and outer cleanup. Missing, failed or incomplete
evidence establishes no qualification. The manifest must retain every explicitly
unverified boundary: a passing installed-loop run does not imply complete I1,
real-provider capability/billing, macOS or I2 qualification. Lease renewal requires
the explicit read-only observations above, not public retention alone.
