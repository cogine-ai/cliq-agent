# Delivery publication: controlled-arena design boundary

This is a design/validation record, not a completion or platform qualification
claim. The RFC is authoritative. The owner has approved the unified private
arena, same-filesystem supported set, and captured-object/quiescent-workspace
contract recorded below. The first four races below are historical RED evidence;
the corresponding real workspace-actor regressions now pass against the arena implementation.
Full proof/SQL integration and installed Linux qualification remain incomplete.
Successful production publication must close its last Journal/result/settlement,
fresh projection and the existing sole RunResult/Session writer in one SQL
transaction. The approved nonterminal received handoff may root its actual M
seal earlier without settling or advancing the publication frontier.
A separately committed forward-finalize-ready state creates a
later-Stop window requiring another abort projection; an extra Stop-adoption
Checkpoint does not satisfy that contract. The original owned completion must
retain its exact effect and snapshot across CAS/rolled-back SQL failures.
Its intended publication Checkpoint id is stable in Run/Plan, not dependent on
the later fresh projection digest. Development producers now connect these
paths, but complete claimed Stop drain and installed Linux qualification still
require independent evidence; source connectivity is not qualification.
The fifth test is retained as historical RED evidence against the stronger
current-path/no-outside-effect assertion. The owner has now approved a different
accepted set: captured-object publication requires a quiescent workspace and
does not provide that atomic ancestry guarantee. New-contract validation is
pending for the installed Linux path; the old assertion is not retroactively counted as passed, and this
decision does not declare the publisher complete.

## Reproduced boundary

The test-only translation unit compiles the actual StateOwner implementation.
Its fixed syscall callbacks execute real filesystem changes immediately after
birth or immediately before the actual rename/unlink syscall. They do not pause
processes, manufacture authority, or replace the production syscall's result.
These cases ran on macOS; they are not Linux or installed-Run qualification.

| Exact cut | Concurrent action | Historical sibling-prototype result | Invariant or contract status |
| --- | --- | --- | --- |
| `mkdirat` succeeds, before first descriptor open | Move born `.stage` to `.born`, insert a different directory at `.stage` | `stage()` succeeds and chmods the foreign directory from `0700` to `0755` | Never adopt, normalize or clean a directory without its original birth identity |
| `symlinkat` succeeds, before first descriptor open | Move born `.stage` to `.born`, insert a different symlink with the same target | `stage/finishStage/commit` succeed and publish the foreign inode | Equal target bytes do not establish original birth ownership |
| Finished regular staging is checked, before rename | Move held `.stage` to `.born`, put an `evil` file at `.stage` | `commit()` detects mismatch only after publishing the foreign inode at the real destination | A failed postcheck cannot undo unauthorized publication of a foreign staging inode |
| Exact quarantined preimage is checked, before unlink | Move original `.old` to `.saved`, put a foreign file at `.old` | `finishCleanup()` deletes the foreign file, then detects that the original FD's link count did not drop | Never unlink a foreign inode; detecting loss afterwards is insufficient |
| Captured nested parent passes the final ancestry check, before rename | Move `workspace/dir` outside the workspace, install another directory at its old path | Rename through the original parent FD publishes the desired file outside the root, then the postcheck refuses | Historical stronger assertion RED; owner-approved captured-object accepted set now requires refusal/retention, not atomic current-path ancestry; new validation pending |

The tests are in `src/state/publication-native-fault.test.ts`; the fixed
instrumentation is in `src/state/testing/publication-fault-native.c` and the
existing quarantine fixture. The actual observations for the last three cases
are respectively:

```text
symlink: {refused:false, publishedForeign:true, foreignPreserved:false}
rename:  {refused:true,  publishedForeign:true, foreignPreserved:false}
unlink:  {refused:true,  originalPreserved:true, foreignPreserved:false}
parent:  {refused:true,  outsidePublished:true, replacementPreserved:true}
```

Adding another stat, checking emptiness, comparing contents, retrying the same
check, or guessing a timestamp cannot close these cuts. `mkdirat/symlinkat`
return no original FD. Ordinary pathname rename/unlink does not condition its
effect on the source inode previously checked through another FD.

## Approved private-inode boundary

The arena below addresses the first four cuts, **not** the fifth current-root
ancestry cut. The latest real tests keep the same first-open, before-rename and
before-unlink cuts and create actual foreign same-name inodes in the workspace.
Those foreign inodes remain unchanged while the original private desired inode
is published or the exact private preimage is cleaned. Safe publication need
not refuse an unrelated workspace sibling; the invariant is that it is never
adopted, chmodded, published or removed. The tests do not attack StateRoot and
claim that mode `0700` protects against a malicious same-UID StateRoot actor.
Do not report the arena as solving all five races or as full qualification.

Use one controlled private publication arena under the already held StateRoot:

```text
StateRoot/runtime/publications/<arenaId>/
  desired       # freshly built desired inode, if this branch needs one
  preimage      # actual inode displaced by the original operation, if any
```

The fixed parent and per-envelope arena have mode `0700`, actual held directory
FDs, owner/device/no-follow checks and the existing StateOwner child-resource
registry. The fixed deterministic identity is
`H('cliq-publication-arena-v1', runId, operationId, opId, attempt, dispatchId)`.
Every input comes from the original approved Plan and permanent Journal claim;
the successor must derive the same identity from that original claim, not from
its new StateOwner epoch or a directory scan. `publicationArenaId` encodes the
attempt as canonical base-10 text. The canonical Plan uses fixed `desired` and
`preimage` components inside that distinct arena; `mkdir` uses its fixed
internal `desired` component too. No workspace-sibling collision allocator is
needed. The native mechanism can validate bounded component input without
confusing it with canonical Plan or publication authority.

This is a physical role of the existing publication envelope, not a new SQL
table, permission ledger, worker lifecycle or independent retry owner. Do not
reuse a retired source-inspection attempt, and do not move or mutate the private
generation holding `M` to obtain an inode for publication. Build the desired
inode from the fully checked immutable CAS bytes instead.

The security assumption is the repository's existing protected StateRoot
boundary: ordinary workspace mutation cannot change these private names.
Mode `0700` is not a defence against arbitrary malicious code already running
as the Supervisor's OS user. That stronger actor can tamper with the existing
database, CAS and StateOwner resources too; an arena must not claim otherwise.
The native implementation still revalidates every actual held descriptor/name
and treats any detected StateRoot drift as recovery-required, not authority to
adopt a replacement.

### Required same-filesystem preflight

Before **any publication write to the workspace**, readonly global preflight
must prove that the controlled StateRoot arena and every touched workspace
parent are on the same actual `st_dev`, with the captured root/parent identities
still held. Also preflight every touched old regular file's single-link
requirement before the first write; recheck it again for the actual operation.
Capture itself may read multiply linked regular files.

This is broader than a new-directory limitation. File/symlink creates and
replacements need controlled staging sources, while deletes and replacements
need controlled preimage cleanup. Cross-filesystem publication is therefore an
explicit owner-approved unsupported gap, not a fallback to the unsafe sibling
implementation. Full cross-filesystem delivery would require a separately
designed and qualified mechanism. `EXDEV`, mount changes and
failed preflight never fall back to copy/delete, overwrite rename, host paths,
shell tools or a weakened acceptance rule.

### Fixed operations

All namespace operations remain descriptor-relative. The native API exposes
only the four immutable publication actions, not arbitrary rename/unlink.

- `create`: build and fsync the exact inode in private `desired`; publish with
  no-replace rename from the held arena FD to the held workspace parent FD.
- `mkdir`: birth/open/normalize/fsync an empty directory in private `desired`,
  then the same no-replace release. Logical `mkdir` need not use a racy live
  workspace `mkdirat` as its physical release primitive.
- `replace`: exchange private `desired` with the destination. The actual
  displaced inode is now in the controlled arena, not a user-mutable staging
  sibling. Bind it to the actual FD, preserve its bytes/type in CAS, and retain
  it until the original envelope's durable PathProgress barrier permits exact
  cleanup. A fixed internal no-replace slot move may name it `preimage`.
- `delete`: no-replace move the destination into private `preimage`. Preserve
  the actual displaced inode and use the same PathProgress/cleanup lifecycle.

The arena source slot cannot be replaced by ordinary workspace mutation between
the final check and rename. The cleanup slot likewise cannot be replaced
between its exact-inode check and unlink. This is why **all** staging and
quarantine must move behind the boundary; merely protecting the initial
directory/symlink birth is insufficient.

Destination concurrency remains a distinct contract. These syscalls do not
offer an atomic compare-inode exchange/delete against an uncooperative actor.
A destination can change after its precheck. The primitive must retain the
actual displaced inode in the controlled arena, detect disagreement with the
approved preimage, and wait with typed ambiguity; it must never discard it,
pretend the expected inode was displaced, invent a completion receipt, or
blindly exchange it back over another concurrent edit. A real fixed
before-exchange/before-delete regression must demonstrate this retained state.
If acceptance instead requires *no namespace effect at all* when the
destination changes in that final cut, this design alone does not provide it;
that stronger contract needs an explicit supported-filesystem/coordination
mechanism and must not be silently claimed.

A separate fixed before-exchange component regression already demonstrates the
weaker, honest ambiguity boundary: the concurrent destination's real inode and
`user concurrent edit` bytes remain in the displaced slot, the original captured
inode remains where the concurrent actor moved it, `commit` and cleanup both
refuse, and the destination contains the desired bytes. This does not prove
there was no namespace effect. That prototype could retain but at that point could not yet
stream that *unexpected* displaced inode through its expected-original reader;
the controlled design needs a separately held actual-preimage FD for bounded
CAS preservation, without promoting the mismatch to completion authority.

The development native implementation now holds that separate actual FD only
after an acknowledged real release. Its bounded reader checks the captured
inode, raw metadata and controlled slot before and after every chunk, hashes
the complete bytes, and never changes expected-preimage verification or cleanup
permission. The reader also covers same-inode, same-length byte drift: the
expected digest still refuses the changed bytes, while the original actual FD
can preserve them. A successfully acknowledged internal slot move may update
only that FD's locator and the corresponding post-rename read snapshot; restart
never refreshes identity. Lost acknowledgement cannot discover or adopt a slot.
Raw symlink bytes are not decoded as text. Oversized or multiply linked files,
nonempty directories and unsupported objects remain ambiguous, not complete
preserved artifacts. The durable CAS wrapper and strict original
unknown-Journal/birth/slot/full-byte reader now have twenty-six passing local
data regressions. They create no physical or cleanup authority. The development
publication consumer now uses that preserved closure; its installed Linux
qualification remains pending.

### Owner-approved captured-object / quiescent-workspace contract

The fifth historical RED diagnostic captures `workspace/dir`, opens its real
parent FD, and successfully checks its original root-relative linkage. At the existing fixed
`before_rename` syscall cut, it moves that directory to `moved-parent` beside the
workspace (still inside the test-owned disposable fixture), then installs a new
directory with a foreign marker at `workspace/dir`. The actual rename through
the held old FD creates `moved-parent/file`. The original workspace's replacement
and marker are preserved, but `commit` refuses only **after** the outside write.
No credentials, external user directory or unowned filesystem target is used.

The owner has explicitly approved captured-object authority with a quiescent
human workspace, not an atomic current-path/no-outside-write guarantee. The
captured parent is still the same inode object; its namespace ancestry has
changed. Reopening with no-follow or Linux `openat2` resolution restrictions establishes the
resolution-time path, not a future rename/unlink-time ancestry lock. A final
extra fstat/linkage walk has the same check-to-syscall gap. An advisory lock or a
UI quiescence promise does not fence an uncooperative writer.

The accepted contract retains every source/projection/grant, no-follow, root,
parent, device and entry check. Drift detected at preflight or a precheck must
refuse the operation before its write; no replacement at the old path is
adopted. A move in the final check-to-syscall gap may affect the original
captured object, including outside the current workspace path. Once detected,
the producer must refuse successful completion, stop further semantic release,
and retain its original descriptors and actual displaced inode/data for typed
reconciliation of the same claim. It must not blind-rollback over another edit,
mint a success receipt, or discard an unexplained preimage. No namespace-atomic
current-path fence, new permission ledger or coordination mechanism is implied.

This is an owner-approved accepted-set revision, not a fix of the stronger
historical assertion. Keep its original RED observation above and verify the
new contract independently at precheck and final syscall cuts, through native
proof/SQL/recovery and actual Linux installation. Private-arena tests alone
prove neither current-path atomicity nor that this full new contract is already
qualified. A future stronger guarantee would need separately designed and
verified OS/filesystem coordination; it is not part of this approval.

Directory-to-leaf operations first remove only exact planned descendants, then
require the original directory's captured identity/raw mode and a fresh empty
observation. Unexpected children remain untouched and block progress. Created
directory parent edges bind the original creator's durable receipt, not a
directory discovered by matching path or contents. Abort cleanup removes only
delivery-created empty directories; it is not a rollback of successful desired
descendants or of workspace state to `A`.

The owner-approved `not_created` contract means **the planned directory was
not created**, not necessarily that the path is absent. Before a file/symlink
to directory conversion, the original captured `A` leaf may still be present.
The same held-root read-only observer hashes every original file byte and raw
mode, or reads the symlink's exact target without following it; the producer
and retained reader bind that state to the immutable Plan's captured expected
entry. They do not infer a captured leaf inode identity that does not exist.
No unresolved creator may remain, and a later terminal failure cannot justify
an earlier observation. Original leaves are not deleted or normalized and no
maintenance claim is issued for this branch. A blocking unchanged original
leaf can prove only no-follow projection absence of a planned descendant.
The real observer regression passes locally; the full installed Linux
conversion/cancellation lifecycle is still unqualified.

## Necessary retained-data changes

The old observation's single workspace-relative `path` cannot honestly describe
a private StateRoot slot. Do not disguise an arena path as a workspace path or
reuse a workspace-root identity for it. The smallest proposed typed distinction
is an observation locator:

```text
{kind:'workspace', path:<approved relative destination>}
{kind:'publication_arena', arenaId:<original-claim-derived id>,
 slot:'desired'|'preimage'}
```

An arena observation also binds actual arena/parent device+inode and the actual
slot inode/type/raw mode/hash. The owning reader recomputes the original claim
derivation and verifies its current StateRoot/inspector provenance. A locator,
hash, decoder result or metadata label is never permission or native proof.
Directory identity remains content-independent; physical raw mode remains
separate from logical normalized SourceManifest mode.

The normative revision replaces workspace-sibling staging/quarantine rules
and their uniqueness/absence projection with private components scoped by the
original claim. It must update only the corresponding operation/transient proof
shapes, terminal absence projection and full-graph reader. Workspace topology
capture and the `B/S/A -> M` merge algorithm do not acquire write authority or
change their logical content identities.

The same Journal attempt covers private staging, semantic release, actual
preimage CAS preservation, PathProgress commit, cleanup, parent fsync and final
receipt. Both affected directories must be fsynced when moving between arena
and workspace. No new claim or `toolCalls` reservation is created for cleanup.
Only a genuine producer-minted opaque progress object backed by the held native
operation may reach the SQL barrier; structural refs or caller booleans cannot
authorize deletion. After the barrier, cleanup requires its corresponding
opaque, freshly checked retained-progress brand.

## Stop, failures and crash limits

The implementation now has an unarmed native birth state. Private preparation
can obtain `readHeldPublicationBirth` only from the genuine original handle and
StateOwner lock; a structural stand-in is rejected before its properties run.
The canonical birth artifact is bound to the original prepared operation's
single proposed dispatch id. The original claim transaction must retain that
actual birth before the sole producer calls `arm`; `arm` itself is merely the
physical release gate, not permission or a SQL claim.

Revoke semantic release before joining operations. Stop/deadline may continue
only original-claim observation, preservation, exact controlled-slot cleanup
and fsync; it may not publish another desired inode. Resource cancellation and
CAS/SQL errors remain real errors, not clean merge conflicts or successful
retirement. Uncertain descriptor close keeps the original StateOwner lock held
until actual process death. The two-second stop and existing recovery budgets
are unchanged and still require actual Linux validation.

The still-live producer retains its original FDs, prepared bytes and progress
object across joined CAS or rolled-back SQL failures. It may re-observe and
retry the same envelope, never create another semantic dispatch. After process
death a derived name alone is insufficient: only durable original-claim birth,
PathProgress or receipt evidence can rebind an inode. A crash after physical
birth/release but before sufficient durable identity evidence therefore remains
explicitly waiting/reconciliation. Missing, replaced, partial or multiply
present slots never authorize path/hash-based adoption or automatic deletion.
This design does not promise to close those crash cuts merely by adding an
arena.

The arena itself is retired in the same lifecycle, not retained as a GC witness.
After exact slot cleanup, `finishArenaRetirement` requires the actual private
directory to be empty, rmdirs the original held inode, proves its named absence,
and fsyncs the actual private and workspace parents. It then requires actual
`close` to join every original descriptor before `readRetiredPublicationArena`
can return a physical retirement observation. That friend rechecks the fixed
private parent's original identity and current arena absence and joins its
temporary read descriptor; it never recreates an arena or adopts one by name.
An unpublished, positively discarded original stage follows the same resource
retirement path without authorizing any workspace effect. A delete whose
rename acknowledgement was lost cannot use that no-effect branch.

The two platform witnesses are deliberately different. Linux requires the held
old directory FD's actual `st_nlink == 0`. On this macOS/APFS host, a real probe
observed `beforeLinks=2`, `afterLinks=2`, and the same held inode after rmdir; the
code does not invent zero. It reuses the existing source-staging mechanism's
original-FD `F_GETPATH` and original-parent path observations unchanged across
the actual rmdir, plus the same-inode/type/private-mode checks and named absence.
The closed retained union records `linux_unlinked(linkCount:0)` or
`darwin_unlinked(heldPathUnchanged:true,parentPathUnchanged:true,observedLinkCount)`.
The owning reader binds it to actual/retained platform and original birth.
This macOS component observation is not macOS sandbox qualification.

Physical removal is not durable completion. A real fixed fsync-failure
regression showed that a removed arena could otherwise be mislabeled retired
by a no-op retry. The lifecycle now retains removed-but-unsynced state and
really retries parent fsync; only successful completion sets `retired`. The
`arena_retirement` proof and the aggregate's canonical `arenaRetirementRefs`
therefore cannot be substituted with a directory-name absence guess. Slot
absence observations precede arena retirement; the final actual root projection
follows it, without pretending all observations share one timestamp.

## Validation required before a completion claim

1. Preserve the first four real workspace-actor regressions, now GREEN against
   the controlled implementation. They still perform actual concurrent mutation
   at the original syscall cuts, not merely assert that a private path string
   was selected. Keep their historical RED evidence above. Preserve the fifth
   diagnostic's original assertion and observations as historical evidence;
   do not count that stronger assertion as GREEN under the newly approved
   captured-object accepted set.
2. Validate file, symlink, directory birth, both type conversions, directory
   deletion, dependency order, global hardlink refusal, complete preimage CAS,
   genuine progress barrier, original-claim retry and stop/cleanup end to end.
3. Exercise destination replacement at the final syscall cut and prove actual
   unexpected preimage retention with no foreign cleanup or fabricated receipt.
4. Exercise cross-device and changed-mount preflight before the first workspace
   write; never qualify cross-filesystem delivery by skipping those cases.
5. Exercise before/after rename, unlink and both-parent fsync failures, missing
   durable birth, crash before/after PathProgress, retained reopening, and real
   cancellation/close joins using the existing native and installed mechanisms.
6. Run the unchanged Linux installation/Run/UDS validation and retain exact
   evidence. Pure planner tests and macOS component tests do not substitute for
   installed Linux, provider, macOS sandbox or release qualification.
7. Independently validate the approved captured-object contract: precheck drift
   causes no write, while final-gap drift may affect only the original captured
   object and must refuse completion, fence further semantic release and retain
   actual data for reconciliation. Cover native and actual installed Linux
   paths; private staging/quarantine tests do not qualify this contract. No
   atomic current-path/no-outside-write guarantee follows from held FD provenance.

Until that evidence exists, source merge/planning, approval and read-only result
inspection can continue independently. Publication must remain explicitly
unqualified, not reported as an existing-parent safe subset.

The original stronger fifth diagnostic remains historical RED, not a passed
capability. A new regression for the owner-approved captured-object boundary
verifies the exact captured inode/effect, post-effect refusal, preservation of
the foreign replacement and refusal of further semantic release. The latest
isolated actual native fault batch passes all twenty-six tests, including real
empty-directory CAS preservation and the original-root-FD link-count getter.
The directory path no longer calls the native file/symlink byte reader: it
requires real empty-directory observations on the same original FD before and
after publication. Nonempty directories, changed contents and substituted slots
cannot produce that wrapper or gain cleanup authority. The same-inode/same-length regression first
failed, then passed for both real replace and delete. The earlier
lost-delete-acknowledgement regression also first exposed and fixed an unsafe
no-effect classification. These results are not a full repository, installed
Linux or release qualification. The real original publication owner now has a
physical progress/cleanup path and a branded settlement adapter. Development
execution now connects the last-path atomic transaction and fresh partial-root
abort finalization to the existing sole terminal writers. Preparation closure
also binds the original returned native birth/retirement, or genuine no-birth,
to its once-only zero settlement. None of these component/refusal results is
an installed positive publication, cancellation or recovery qualification.

Bounded shutdown remains a separate unqualified contract. Pre-cleanup PathProgress
cannot locate a known last receipt after the arena has retired; cancelling
read-only projection must not lose that receipt or turn it into UNKNOWN. A
fixed nonterminal handoff in the same invocation/Continuation is now approved
and connected in the producer, read-only execution task, settlement and retained
readers. Real installed qualification remains incomplete. It preserves the original claim,
actual receipt and complete retirement graph without advancing the forward
frontier, granting release, settling twice or weakening the last terminal
transaction. Missing/partial handoff and unsupported retained-open windows
must still wait for recovery, not infer physical success from absence.

### Approved result-handoff contract (installed qualification pending)

The owner approved this contract; the connected implementation and its local
refusal/data/descriptor regressions are not installed recovery qualification.
It reuses the existing excluded-control continuation and
auto-Checkpoint mechanism. Keep the immutable cleanup-pending progress item;
a distinct closed received-handoff variant needs a different deterministic
item/Checkpoint identity. It must not overwrite progress or add a second
Journal, permission table, charge or retry owner.

Only the genuine original last-forward publication producer can persist the handoff, after
its actual known completion, complete slot-absence/arena-retirement graph and
descriptor joins. Bind it to the original Run/Plan/sequence/operation, attempt
zero and permanent claim; retain the exact evidence/receipt digest and complete
retirement refs. The same transaction appends this immutable excluded-control
item and an auto-Checkpoint retaining the current accounted M and frontier,
commits its original M seal once and clears the active worker pointer.
It neither advances publication nor releases its reservation or Run capacity.
An unresolved UNKNOWN, unreturned birth or uncertain join cannot enter this
branch. The approved recovery extension below can enter it only after a real
same-claim probe has positively established the actual outcome and resources.

The closed `received_handoff` variant binds `sequence='forward'`, attempt zero,
the original dispatch/claim Journal sequence, exact receipt ref/semantic
digest and slot/arena retirement refs. Its closed `generationResources` XOR is
either `sealed` with the original M launch/generation/snapshot refs, or
`genuinely_retired_from_verified_checkpoint` with the original launch/generation,
verified source Checkpoint and actual quarantine/retirement evidence refs.
The latter also requires its complete reconciliation-evidence pair; it never
asserts a seal or reconstructs the retired M. Cleanup-pending
destination/preimage fields are forbidden in this variant.
Its item id uses `cliq-publication-received-handoff-item-v1`; the original
`cliq-delivery-publication-checkpoint-v1` id remains the actual M resource
Checkpoint. Only a completely validated handoff selects the later
`cliq-delivery-publication-terminal-checkpoint-v1` id. Without one, the early
Stop and no-op branches retain the old terminal id. There is no existence-based
fallback and no immutable Checkpoint is overwritten.

Only after that transaction actually commits may shutdown cancel and join the
separate read-only full-root projection without losing the known result. CAS
or SQL failure keeps the same original owner and fixed bytes. A timeout is not
proof of a join. Actual physical retirement and handoff I/O must still satisfy
the original stop gate; this contract cannot guarantee two-second graceful
completion on arbitrarily stalled storage.

A successor must validate the entire original graph and the real predecessor
process/worker retirement under the existing fence, then create only a fixed
non-release recovery task. It cannot construct an old native owner from refs,
arm a token, reopen a retired arena, dispatch again or reuse an old fresh-root
observation. It must capture the actual root again and verify the genuine M
retirement/seal already rooted by the actual original resource Checkpoint,
without resetting its cumulative budget or committing it again. Stop selects the abort
path without changing the original received fact. The sole last transaction
still writes the terminal Journal/BudgetSettlement, last path result, pubCP,
RunResult/Session outcome together; the handoff is not any of those terminal
facts.

The following table records the earlier handoff-only boundary. The approved
same-claim and registered-namespace extensions below are not retroactive passes
for these historical gaps.

| Actual cut | Earlier handoff-only evidence and supported boundary |
| --- | --- |
| Unclaimed preparation | Original no-birth or returned-birth retirement closure only; no new dispatch attempt follows from it |
| Permanent claim, no durable PathProgress | No sufficiently bound destination/cleanup barrier; do not re-execute or infer no effect |
| Durable PathProgress, original arena and recorded inodes still present | Current retained native mechanism can validate the exact old envelope and perform only fenced cleanup; installed successor integration is still absent |
| Preimage already absent, original arena still present | Current retained native opener refuses; a new truthful current-absence branch needs separate design and real validation |
| Original arena retired, handoff durably committed | Connected producer/read-only successor consumes the known result without release or resealing; real installed shutdown/restart and once-settlement qualification pending |
| Arena retired, no durable handoff | Do not scan CAS or infer original retirement from a missing name; recovery remains required |

### Approved same-claim UNKNOWN recovery (implementation/qualification pending)

For a productive forward claim, retire and prove the original worker/generation
before publication inspection; do not discard continuously held original
publication descriptors during that separate worker retirement. A stopped
abort-maintenance claim may instead bind the same genuinely sealed M and its
already retired original launch, with the complete original seal graph; it
must not turn that sealed generation into a fictitious retirement. Both paths
preserve the original claim lease, exact Stop/grant/creator and resource graph.
Retention irrevocably revokes semantic release.
A successor may open only a cleanup-only envelope whose durable original
claim/birth/progress, exact inodes and complete resource graph validate. A
name, derived arena id, identical bytes or unrelated CAS object is insufficient.
Missing or unreturned births remain waiting, not adopted or retried. The
approved registered-namespace branch below covers an absent original arena
only with the complete original birth/progress/resource graph; a missing name
alone remains insufficient.

If the original claim never wrote UNKNOWN, its first conservative settlement
has two explicit sources. A genuine original worker-death task may record
ambiguity and the full original reservation charge before that same worker's
quarantine, retaining its original wait, anchor and fenced Journal cursor. A
worker-free abort instead requires its actual readonly maintenance task,
already-closed original M, genuine original-claim owner death and zero charge;
it creates no worker-death observation. Both use the same initial-ambiguity
item/Checkpoint transaction, preserve W_M, and then re-read the complete actual
cut. Neither source opens an arena or proves any successful path effect.

The first fixed `PublicationInspectionTargetV1` comes only from the complete
original Journal/prefix and freezes the prepared/claim/UNKNOWN sequences,
original full settlement and optional durable progress/Checkpoint. Each
automatic or authenticated user probe first persists the existing bounded
dispatch/nonce/deadline. Read-only probing never performs reconciliation's
possible rename or cleanup; any later exact-private cleanup has its separate
original-claim gate and joined producer. Public `probe_now` enqueues, not
synchronously reports an effect or grants a retry. Each dispatch roots its
actual `previousWaitingSubjectRef`, so the complete prior wait/count/backoff
chain is validated rather than reconstructed from future progress. A genuine
shutdown cancellation joins its original task and durably closes only that
nonce with the disjoint `probe_cancelled` record; it is neither an early timeout
nor proof of a path outcome. A genuinely received result takes precedence over
this cancellation, including a concurrent monotonic Stop revision.

Cleanup-pending progress roots `beforeObservationRef`, the original complete
pre-release observation and captured parent/link count. A successor cannot
derive that historical observation from the displaced inode and today's
parent, even if the bytes match. Missing original before evidence remains
waiting, without new cleanup, adoption or replay authority.

After this same producer commits progress, a private opaque token synchronously
hands its exact actual item/Checkpoint/Run delta to the existing probe closure
cache, before any cancellation or full retained read. The source binds the
original planned context ref and actual SQL time; the consumer permits only
that one item, unchanged W_M/Journal/budget/nonce and a previously validated
monotonic Stop. This is not a future RecoveryClosure or permission to resume
cleanup. A cancellation can therefore close its actual joined task without
discarding a committed progress cut or accepting arbitrary Checkpoint drift.
Data/CAS/SQLite and forged-token regressions pass; the physical progress-to-
cancellation cut and two-second installed shutdown remain unqualified.

A new inspector must prove actual original StateOwner process death and strict
new ownership in the same StateRoot, not merely a larger epoch. Its separate
`PublicationRecoveryOriginV1` retains the existing exact takeover-acquisition
pair, or exclusively carries closed `gracefulOwnerDeath` data: the original
terminal row digest, process identity ref/digest, graceful transition ref/digest,
fixed `kind='observed_after_graceful_release'` and fixed absent/start-token-
mismatch observation. The latter is produced only by the current genuine
lock's actual `observePriorProcessDeath` for the retained original PID/token;
its native time becomes `origin.observedAt`, no earlier than release and current
acquisition. Full original claim/birth/owner/process/runtime/lock/root history
is read before I/O and compared unchanged by the original SQL friend. The
graceful owner row and all acquisition history remain untouched. No broker or
worker-death authority, old FD, new claim, nonce or budget is derived from this
publication-only provenance. An alive or unobservable original process still
refuses. The real installed SIGTERM→exit→restart/namespace recovery branch
remains unqualified until executed; data and actual native-alive refusal do
not qualify it. Claim-bound observations/receipt/retirement can name this
origin; fresh whole-workspace observations cannot. The original same-owner
branch retains its existing exact inspector checks. The acyclic graph is
result/handoff → probe evidence → actual receipt/proof → recovery origin;
the target points only to the older UNKNOWN/progress, never back to a result.

The original UNKNOWN and its full BudgetSettlement remain immutable. Positive
resolution appends the exact original claim's completed/failed fact with zero
additional budget and reuses that settlement; it cannot refund, re-charge,
create another attempt or dispatch. A last known outcome first roots the
truthful sealed-or-retired resource handoff, then performs a fresh complete
workspace projection. Only the sole terminal transaction closes the final
Journal/result/Checkpoint/Session graph. Stop selects the existing abort
contract and does not erase the real outcome. Installed positive recovery,
interrupted probes, once-only settlement and two-second shutdown still require
their independent real Linux evidence.

Same-process resolution keeps the original invocation owner and immutable
UNKNOWN. After the exact shared native owner actually joins, its physical
closed/retired flags advance even if later CAS publication fails. Only a
timely probe with durably published fixed facts can archive that original
owner's retirement data. Abort independently rewalks the complete retained
prefix and requires the exact resolved result, original UNKNOWN/claim/birth,
probe wrapper, evidence and retirement references. This archive retains no
inspection task or cleanup capability. An unresolved claim or late audit alone
cannot use it. Data association and real lost-ACK/retirement/CAS regressions
pass; the genuine installed resolution-to-abort positive cut remains unverified.

The owner approved two further evidence branches in the same lifecycle. They
are under implementation, not installed Linux qualification:

- A fixed `publication_late_observation` excluded-control item retains the
  original claim, expired dispatch digest/wait, raw evidence and actual joined
  retirement for a known result. `completedAt` is sampled once by the actual
  producer after its result is complete; it is distinct from the raw path
  observation's unmodified time. Completion after the original deadline is
  audit-only, even if that earlier path read was in time. UNKNOWN forbids a
  retirement assertion. The audit transaction appends only one item and W_M
  Checkpoint plus Run revision/time: wait/nonce, Journal, settlement, frontier
  and budgets remain unchanged. Its exact committed delta updates both
  original task caches synchronously before any cancellable read. CAS/SQL
  retry retains the same fact/item and only reselects a validated monotonic
  Stop; it cannot retime evidence or manufacture a current probe result.
- `arena_namespace_absence` proves the current absence of the complete
  registered original envelope. It requires actual original claim-holder
  death, strict successor acquisition, full birth and durable progress,
  unchanged original desired inode and full bytes, current exact parent
  identities, actual parent fsync and joined observer handles. The native
  readonly role cannot arm, publish, discard staging or unlink a preimage.
  Its separate fixed maintenance friend may remove only the exact held empty
  original arena and sync the actual parents. A unique registered preimage
  routes, after observer close/join, to the unchanged original retained
  cleanup/full-hash checks; foreign/extra/missing-identity refusals never fall
  back. An absent arena cannot supply a fictitious old FD, slot-parent read or
  `linux_unlinked`/`darwin_unlinked` observation.

A late audit is never positive authority for a later nonce. Progress requires
a new actual bounded probe, independently qualified original-holder death and
current namespace evidence, then the unchanged sole result/terminal writer.
For that validated original-UNKNOWN resolution only, the result item is
prepared before its new zero-delta Journal row: receipt/probe observation ≤
item creation ≤ Journal time = the exact atomic result Checkpoint time.
Initial settlement retains its original settled-time-before-item ordering;
neither branch retimes the original receipt, UNKNOWN or BudgetSettlement.
The new receipt/retirement/aggregate branches are disjoint from original
descriptor retirement and cover every claimed envelope without inventing
empty old-slot arrays. A still-live original claim holder remains waiting;
same-process transport closure is not proof of its death. Missing complete
original provenance remains recovery. All corresponding installed Linux
late-return, cleanup-before-ack, new-probe, Stop/storage-failure, once-only
settlement and two-second shutdown cuts remain unverified until actually run.

Real Linux validation must independently cover original claim/charge counts,
unchanged receipt bytes, Stop winning before terminal commit, actual producer
and descriptor joins, storage failure and retry on the same owner, successor
restart and exact replay. Missing/partial/corrupt handoffs must refuse. Neither
this table nor native component reopening tests qualify an unexecuted cut.

The full terminal projection uses a fresh complete frozen SourceProjection,
not prior receipts as new observations. When a touched path's strict ancestor
is actually absent, a file or a symlink, `ancestor_projection_absence` binds the
target to that exact no-follow ancestor observation. It means the descendant
is absent from this projection, not that a symlink target does not exist. Both
proofs retain the same original owner and observation time; chains, directory
anchors and arena anchors are refused. Twenty-two kernel/retained-data cases
and the original structural-root refusal pass, but these data cases cannot
mint a native observation or substitute for an installed delivery Run.

## Single fresh validation DAG — candidate validation pending

WP01's within-validation reference deduplication applies to one complete
relational cut and its entire CAS closure, not to the lifetime of a received
result. The current helper graph repeatedly expands admission, original source
recovery, verification and authorization inside that same traversal. Its
static expansion count is not a required security check count or a measured
timeout cause.

The candidate assembles those dependencies once per fresh traversal
using internal immutable data flow. Every semantic role still performs its own
closed decoding, identity, digest and graph-association checks. Every required
object is completely read and byte-verified in that traversal; old metadata,
path existence, a prior successful traversal or caller-supplied material is
never fresh integrity evidence. No execution permission, native proof, global
cache, additional persistent record or callback-selected bypass is introduced.

Received-result reading, genuine received-result construction, settlement
construction and each actual settlement retain their independent fresh
traversals. The separate pre-handoff generation-seal check and each handoff
CAS/SQL attempt also retain their own fresh traversals; the four received-result
stages are not an exhaustive count of acceptance boundaries. Retries, rollback,
reentry and successor ownership cannot inherit another traversal's validated
nodes. Keep the original source/Session and
full SQL-cut comparisons at their logical acceptance points; source Delivery
chains retain each Run's actual cut and reject ancestor cycles before reuse.
Independent historical and prefix entry points remain fresh. In particular,
prefix validation must not recursively start a new full recovery walk from a
Stop/recovery edge.

Current frame/StateOwner checks, all installed-image revalidations, permanent
claim and UNKNOWN accounting, real task/root identity, Stop/time fencing,
fresh complete workspace projection and its five-second gate remain outside
this data-flow optimization at their existing boundaries. Final storage
revalidation and the sole Journal/Checkpoint/RunResult/Session transaction are
not replaced by a previous graph. Failure and cancellation still join every
issued read; original resource-retirement uncertainty takes precedence.
Data regressions cannot qualify physical publication, restart or the unchanged
two-, five-, thirty- and ninety-second installed acceptance gates.

### Installed cancellation evidence consumers

The campaign distinguishes a received child Stop (the original child receipt,
three recorded child lifetimes and independent `/proc` observations) from an
original settled UNKNOWN closed by `verifier_parent_domain_dead`. The latter
rewalks the original claim and generation source, exact full charge, atomic Stop
Checkpoint, owner history and complete recovered-parent retirement graph. Its
independent process observations cover the recorded parent lifetimes and actual
worker, not an unrecorded child PID or a fabricated child Stop receipt. The
closed cancellation summary records that distinction; a parent-domain success
cannot claim the precise in-flight child cut. Reconnect/restart repeat both the
retained graph and actual process checks. Data regressions do not qualify Linux;
the original run471 cancellation report remains failed pending a new real run.


### Run-bound publication timing observation V2

`CLIQ_PUBLICATION_WORK_V2` is a separate diagnostic window. V1 first-arrival
phase markers and the process-wide Stop phase keep their original meanings;
neither can be reinterpreted as a Run-bound span or completion. Each V2 span
names the actual owning Run, a fixed work label, and integer milliseconds from
that Run's first subscribed observation on the process monotonic clock. Its
end is recorded only after the original awaited promise fulfills or rejects.
Cancellation remains pending until that promise's existing resource join has
settled. A fulfilled promise is not physical publication, native retirement,
Stop, or qualification proof.

The fixed labels cover fresh publication recovery, completion recovery,
settlement preparation/settlement and the readonly received-result preparation
and settlement. The two original result-recovery label producers (result
preparation and terminal retirement) are also named by their actual Run, so a
process-wide Stop phase cannot silently be attributed to a different Run.
No full read, per-use identity/currentness check, SQL gate,
original producer or resource join is removed or reused. No timer or keepalive
is added. Ordinary images without the trusted diagnostic subscriber sample no
clock and allocate no Run tracker. The producer tracks at most 64 observed Run
origins; observations after that diagnostic-only bound may be unavailable.

The existing trusted sink retains only two Run windows and six issued spans
per Run. It evicts completed spans explicitly, reports their discarded count,
and never turns a pending span into a completion on phase change. Its Stop and
exit snapshots each encode at most 16 closed logical rows (255 bytes each)
in one JSON marker line of at most 4096 bytes. The whole new window is at most
two physical lines/8192 bytes, inside the unchanged journal
80-line/256-KiB cap and five-second read. Both snapshots use synchronous bounded
writes under the original Stop deadline. An abnormal exit may omit the exit
snapshot. Missing or malformed V2 data cannot discard V1 diagnostics.

The report's new `publicationWorkDiagnostics(profile=publication_work_v2)`
retains the complete snapshots after original PID absence and image/start/uid/
invocation checks and the existing secret scan. A Delivery terminal-deadline
Run id is copied only from that actual public cut and is attached to an
observed window only if the same Run is present. Otherwise the field records
`terminal_deadline_run_not_observed`. These observations do not upgrade any
old report, alter its original bytes or satisfy Linux acceptance. The original
90/5/2/30-second gates and all sixteen full runtime reads remain unchanged.
