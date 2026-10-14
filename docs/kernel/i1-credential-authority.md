# I1 — installed Linux credential authority

## Backlog Ready Spec

### Verdict

Implementation and qualification in progress, not qualified or complete. The owner approved option A
on 2026-10-12: enroll/rotate may automatically start or connect the installed
Supervisor; only its existing canonical-time authority may finalize expansion.
Read, historical replay, revoke and cleanup remain independent. This is one
credential capability, not a sequence of schema/adapter-only PRs. On 2026-10-14
the owner approved a clearly labelled progress PR for review, with qualification
still incomplete. That approval does not complete I1 or authorize kernel cutover.
On 2026-10-15 the owner authorized and PR #521 merged as that progress checkpoint
at `b7107476e33b6d0d9438352718e3ff7b6307d903`. Its tree is identical to the
reviewed `e839ebd7d34920539ef9305fe532afc4a4e6747e` implementation. This merge
does not install a release, migrate legacy data or enable default CLI cutover.

### Source

- Base: `main` at `c91787c7f947c748a32902926237350b36b38786` (PR #520).
- Contract: RFC section 5 credential authority, section 3 canonical time and
  section 14 local authentication; WP06 owns the external store and commands.
- De-duplication: successful GitHub searches across open/closed issues for
  `credential`, `auth` and `durable kernel`. An initial GraphQL 502 was retried;
  it is not evidence of an empty backlog. Closed #52 concerns existing provider
  management; open #100/#103 concern the cliq-models contract/integration, not
  this installed authority. No matching implementation issue was found within
  these query scopes. No new GitHub issue is published.
- Reuse `src/kernel/credential-authority.ts`, the installed runtime's private
  credential scope/endpoint history, genuine control frames, canonical-time
  repository and signed SEA/keeper installation. The Secret Service probe is
  prerequisite evidence, not a production adapter.

### User Outcome

One local auth action stores a secret in the same-user Linux default Secret
Service collection, returns an opaque credential id and can rotate it safely.
Exact committed replay never asks for or reads a replacement secret. Revocation
remains effective even when the platform store or Supervisor is unavailable.
Neither an old binding nor a later channel silently acquires the new generation.

### Problem

PR #520 provides the signed installation, authenticated endpoint registry,
separate same-engine credential database and physical lock/VFS ownership. It
does not implement credential business phases, a production Secret Service
adapter, credential finalization, or production user-unit autostart.

### Scope

In: Linux enroll/rotate, latest metadata and exact historical replay, terminal
revoke, orphan/superseded-item cleanup, original-producer finalization, automatic
start/observe of correctly installed user units, real installed/Secret Service
journeys and process-crash cuts. Initially use `opaque_generation`; caller JSON
cannot manufacture `provider_verified` evidence.

Out: default CLI/cutover, plaintext/env/custom-command fallback, live provider
calls/charges, broker redemption and Run admission, macOS credential
qualification, runtime upgrade/reboot recovery and power-loss qualification.
Retained controller-leaf reclamation and the exact READY-survivor cut remain
requirements before worker execution/restart cutover, not credential evidence.

### Proposed Implementation Direction

#### One deep module, existing physical owners

Local auth presents complete business actions. SQL, descriptors, native scope,
time sources, phase writers and platform selectors stay private. Reuse genuine
`HeldCredentialAuthorityLock`; no structural owner/native/store/time factory.
Local auth never writes Run SQLite/CAS. Supervisor never receives secret bytes
or calls `GetSecret` in finalization.

Prepare only after the installed Supervisor is available and its startup
recovery has finished. Start/observe fixed installation-bound user units;
missing/incompatible installation or user manager yields explicit remediation.
No sudo, qualifier invocation, temporary delegated cgroup, or unmanaged
background-fork fallback. Do not start a manager for read/revoke/cleanup.

#### Installed command seam

Integration invokes the same fixed signed `runtime/bootstrap
--bootstrap-credential <metadata>` entry as local auth. Metadata is at most
65536 bytes of strict canonical UTF-8 JSON, encoded as canonical unpadded
base64url; raw secret bytes use fd 0 only and are never part of that envelope.
Identity, channel, subject, core hashes and platform selectors are producer-owned.

- `{schemaVersion:1,kind:'read',credentialGrantId}` returns
  `{schemaVersion:1,record}` with latest committed metadata or null.
- `{schemaVersion:1,kind:'install_services'}` is explicit installation setup,
  returning `{schemaVersion:1,keeperUnit,supervisorUnit}`. It creates only the
  fixed installation-bound same-user profiles and reloads their manager. It
  does not start services or replace incompatible/user-edited profiles.
  Both fixed roles explicitly use working directory `/`; effective-property
  checks do not mistake the user manager's implicit passwd-home default for
  an empty setting or accept arbitrary working-directory drift.
  Reject control characters, DEL and quotes in the StateRoot before creating
  profiles: systemd rejects these bytes in a decoded executable path even when
  unit text quotes or C-escapes them. Generic filesystem identity remains unchanged.
  After both profiles load, the effective keeper `Before` may contain only
  shutdown ordering and this installation's exact Supervisor (the mirror of
  its fixed `After=keeper`); this does not authorize any extra startup dependency.
- `{schemaVersion:1,kind:'enroll',requestId,credentialGrantId,purpose,
  endpointRegistrationId,secretSubmissionId,expiresAt?}` contains stable user
  intent, not an externally generated subject or command core. Success returns
  `{schemaVersion:1,operation}` for the committed original operation. The first
  pre-input history check and the post-input lock-held race check are distinct.
- `{schemaVersion:1,kind:'rotate',requestId,credentialGrantId,
  expectedAuthorityRevision,secretSubmissionId,expiresAt?}` derives owner,
  purpose and the immutable endpoint/handle from validated active history.
  It returns the same committed-operation envelope. Omitted expiry inherits
  the expected active revision's expiry; it never silently removes a deadline.
  Retry and historical replay interpret omission against that retained revision,
  not a later latest record. Expected revision is compared before secret input
  and against `intendedAuthorityRevision - 1` on replay; changed intent conflicts.
  A new rotation cannot reuse any committed generation's submission id within
  that grant. Exact replay and uncommitted frozen-core retries retain their id.
  Expansion reserves the final safe authority revision for terminal revocation;
  exhausted rotation capacity must never produce an unrevocable active grant.
- `{schemaVersion:1,kind:'revoke',requestId,credentialGrantId,
  expectedAuthorityRevision}` derives its target digest privately. It returns
  `{schemaVersion:1,operation}` for the original revoke receipt, whose cleanup
  fields may advance after metadata commits. Pending-only enrollment has no
  committed revision to revoke; an active grant with a live rotation may still
  be revoked without aborting or deleting that producer's pending item.
- `{schemaVersion:1,kind:'cleanup',requestId}` names an existing enroll, rotate
  or revoke request, never a new cleanup identity. It returns that operation
  envelope after the owning cleanup phase. Live/unknown pending producers refuse;
  current latest active items remain protected. Aborted and superseded items
  use their exact creating-operation selectors, and absence/deletion reflects
  only the fresh observed cut, not a promise that a late remote create can
  never arrive. No cleanup ledger hides these known items from later sweeps.
  Ordinary completed revoke replay returns its exact retained receipt without
  platform access. Explicit cleanup still sweeps the known item; success returns
  that unchanged completed receipt, while a failed fresh sweep returns a closed
  error rather than rewriting historical completion.

Ordinary auth does not install/reload/repair units. Missing profiles or drift
produce remediation; a successful manager job/socket existence alone is not
readiness. Bind the actual connected server process to its current manager
invocation and selected image, then use the existing current-owner hello and
finalizer feature. No new client-side epoch/time authority is required.

The native platform operation's selected 30-second monotonic budget starts at
submission, including waiting in Node's shared worker queue. While the main
loop is responsive, expiry cancels queued work without waiting for an available
worker. Completion joins every worker/watchdog/timer owner before publishing a
result or releasing copied input; this is an operation budget, not canonical
authority time or a guarantee about a stalled main loop.

#### Local preparation and private platform identity

1. Authenticate the fixed signed auth producer and read existing request
   history before prompting or reading secret input. Committed replay and
   permanent digest conflict do not touch the platform store. Retire this
   initial scope before bounded fd-0/hidden-terminal input; never hold credential
   exclusive while waiting for the user to enter a secret.
2. Reacquire global shared then credential exclusive. Recheck replay/conflict,
   live pending producer and latest intent, then validate the latest active
   endpoint's owner/purpose/ref/identity/TLS and current credential history.
   The pre-input read is not the final race gate.
3. Generate the opaque 256-bit subject candidate **before** core hashing, then
   freeze the complete secret-free core. Its bytes/subject observedAt and
   intended revision/generation remain unchanged across contiguous attempts
   1..3; only one committed generation can acquire it. Each attempt freezes its
   own first authenticated channel and producer lifetime: a fresh attempt never
   adopts the dead earlier producer's channel or rewrites its retained facts.
   Resubmitted uncommitted secrets are latest-secret-wins, not compared to
   abandoned bytes. If a competing rotation changes the intended revision or
   generation, refuse the old request rather than repurposing its candidate;
   the caller must create a new request/core. A later committed generation gets
   a new subject.
4. Persist `prepared` with a fresh logical platform item id, then create a fresh
   item without replacement, read back/compare in memory, discard input and
   persist `secret_stored`. Raw input is never hashed or persisted. Do not
   invent a secret-stored timestamp absent from the canonical operation.
5. Fully retire the credential SQLite/native scope before sending finalization.
   Never wait for a Supervisor RPC while holding credential exclusive.

Linux `platformItem.itemId` is the logical id fixed in `prepared`, not a guessed
or returned D-Bus object path. Fixed secret-free attributes bind schema,
namespace, logical id, principal/root and operation/generation. Lookup checks
the complete attribute set, unique match, default-collection membership,
unlocked state and the same-user unique service owner. Paths are only locators.
The operation attribute is always the creating enroll/rotate operation id;
revoke/cleanup reconstruct its attributes from that retained creating operation,
never substitute the revoke operation id.
CreateItem success followed by a lost reply remains recoverable by that id.
The `secret_stored` fact retains one bounded, self-hashed, secret-free native
platform observation in that same fact row: complete fixed attribute selector and
creating operation/logical id, actual bus GUID/socket/runtime/lifetime, service
unique owner/uid/lifetime and default collection/item locators. A unique bus
name alone can be reused after bus restart. Finalization freshly compares that
observation; cleanup uses the current same-user store and complete original
attributes, not a permanently required old daemon. This is provenance, not a
new ledger, secret hash, authority grant or time ticket.
Locked, prompted, ambiguous, replaced-owner/alias or unavailable-store results
never create active authority. Errors and trace artifacts exclude remote
payloads/secrets; no promise is made to erase every V8/GIO copy.

[Lookup attributes](https://specifications.freedesktop.org/secret-service/latest/lookup-attributes.html)
are not secret storage. The
[Collection interface](https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Collection.html)
returns an item path after creation and supports replacement; neither is an
authority identity or an acceptable overwrite policy here.

#### Narrow authenticated finalizer

`credential.finalize` carries only `protocolVersion:1`, `method`, the original
`requestId`, `operationId`, `attempt` and `commandDigest`. It is a continuation
of the credential operation, not a new `MutationBase` or `control_requests`
identity. It carries no raw secret,
principal/channel/PID, timestamp, platform path, subject or verified boolean.
The original operation remains the sole request/replay identity; no second
time-ticket, finalizer journal or authority-request ledger is created.

Before the synchronous section, the finalizer performs actual metadata-only
platform revalidation: exact item attributes, default alias/membership, current
same-user service owner and unlocked state. It never calls `GetSecret` or treats
historical `secret_stored` as proof of current platform availability. After all
asynchronous traversal, it reads its own locked authority database and validates
exact `secret_stored` history, core/item, endpoint and intended revision/generation.
Its genuine native UDS frame must match the
prepared original producer's platform/uid/PID/start-token/selected signed image,
StateRoot and principal. Do not compare whole process artifact digests: their
observation times differ. Same uid/image without the original lifetime is not
continuation. Preserve the first local auth channel in the committed result.

In one non-reentrant synchronous section, with the existing StateOwner and
global/credential locks continuously held:

1. Freshly assert native frame, physical scopes and current StateOwner/epoch.
2. Sample canonical C and durably commit the existing Run time fence first.
   Regression persists only regression, with no credential authority expansion.
   C cannot precede endpoint, prepared, subject or original/current channel
   causal times; reject rather than manufacture C from their maximum.
3. Without await, externally supplied/reentrant JavaScript callback, D-Bus
   access or CAS publication, atomically commit
   `active record + committed operation` in credential SQLite using C, then
   read back the complete result under that lock. Fixed private transaction
   closures and native SQLite VFS callbacks remain part of this owned section.

These are ordered commits, **not cross-database atomicity**. Prefix-only crash
conservatively advances the sole high-water but grants no credential. Failed
second commit cannot be completed by a local client or historical time ticket.
Active commit followed by lost response is exact historical replay. The final
fresh assertion/C sample is the explicit request's authorization cut; it does
not pin another process alive until physical COMMIT. Death after that cut may
leave an accepted in-flight commit, never an automatic orphan promotion.

Local prepared/abort/revoke/cleanup times are non-expanding causal audit, not
proof that the canonical fence is healthy. No copied credential time fence.
Supervisor reuses its already-held StateOwner rather than reacquiring it inside
credential exclusive; new global/credential acquisitions are nonblocking and
ordinary/exclusive cutover modes keep the documented lock/token discipline.
Migration already holding global exclusive/credential tokens cannot call this
ordinary remote finalizer. Its future integration requires an explicit owning
held-token path, not temporarily released cutover locks or recursive RPC. This
increment does not qualify migration finalization.

#### Concurrent reads, recovery and revocation

Read returns only validated committed metadata and never recovers or aborts a
live pending attempt. New enroll/rotate/retry and orphan-cleanup operations
encountering a live/unknown original producer report busy/unknown; they do not
spend its three attempts. This does not block terminal revoke. Orphan
recovery needs positive original-process death/lifetime replacement from the
private native observer, then cleans the exact planned item and appends aborted.
No caller PID/path or StateOwner acquisition is needed for ordinary recovery.
Startup never finalizes a pending row, including `secret_stored`.

Rotation preserves service/handle/target and appends the next revision and
generation with a new item/subject. Old-item deletion follows committed active
publication. A current endpoint/credential revocation can win the lock and
make finalization refuse; no stale continuation resurrects authority. Revoke
does not abort or delete a live producer's pending item. Superseded-item sweeps
test whether the current latest active record names an item; immutable historical
active revisions do not prevent cleanup or confer usable secret authority.

Revoke atomically appends terminal metadata plus `metadata_committed`, then
cleans the item. Positive absence/deletion completes cleanup; closed errors
retain secret-free observations and leave authority revoked. Retry retains
the original revoke identity, not a new enrollment attempt. Historical revoke
receipt identity is immutable; cleanup status may advance, not freeze failed
cleanup bytes as the final replay result.

The same cleanup-observation column retains either the existing actual native
observation or a closed failure projection: `{schemaVersion:1,
kind:'cleanup_failure',selector,stage,errorCode}`. Stage is only
`platform_load|delete_known|result_validation`; code is the RFC's three cleanup
codes. Hash the complete canonical stored observation for the receipt. A failed
load does not invent a bus/service/item observation, and resource-retirement
uncertainty propagates instead of becoming an ordinary failed-cleanup receipt.

#### Schema and files

Credential schema extension is one transactional v1-to-v2 change preserving
existing endpoint rows/provenance byte-for-byte, with endpoint reopen accepting
the supported new version. Test it by creating v1 through the actual existing
endpoint entry, then upgrading through actual auth; no SQL-seeded fake authority
or unqualified old bundle is necessary. Unknown formats remain refusals.

Likely files: installed entry/runtime/control, native-owner/control-frame bridge,
canonical-time/StateStore finalizer, fixed native Secret Service implementation,
credential business module and signed user-unit startup module. Reuse existing
package/real-user-manager qualification under `scripts/kernel/testing/`.

### Acceptance Criteria

- [x] Real installed enroll/read/replay/rotate/revoke/cleanup journey with one
  genuine default Secret Service and no provider I/O.
- [x] Same-request committed replay returns original result/provenance without
  reading new secret; bounded 1..3 orphan retries, permanent digest conflict.
- [ ] Live producer/read/concurrent mutation do not cause orphan promotion or
  gratuitously consume attempts; new/ABA process cannot finalize old pending.
- [ ] Real v1-to-v2 old/new schema cuts preserve existing endpoint replay.
- [ ] Genuine SIGKILL after prepared, CreateItem-before-reply, readback,
  secret_stored, fence-prefix, active commit, revoke and delete-before-receipt.
- [ ] Prefix crash has no active authority; current clock regression, expiry,
  epoch/peer drift and concurrent revoke reject expansion before commit.
- [ ] Store unavailable/locked/ambiguous/changed owner or alias refuses; read and
  revoke metadata remain independent, failed cleanup never reactivates.
- [ ] Actual SQLite/CAS/output/trace checks contain no generated test secret.
- [ ] Uncertain descriptor retirement preserves sticky refusal and owner joins.

### Validation

`npm run build`, `npm test`, design-contract tests/checker, focused real installed
and Secret Service cases on the existing free standard Linux runner. Call the
same signed auth and authenticated UDS interfaces as production; no fake native
proof, time/store injection or public phase-writer test factory. Retain bounded
secret-free raw commit/platform/process evidence. Local macOS portable success
does not qualify Linux, broker, power loss or complete I1.
The first metadata-only tracer checks exact CAS bytes and absence of Run-owner
side effects. It does not yet prove zero platform calls or the complete journey.

#### Retained genuine Linux progress

Commit `cf29744d4d2c4e62c4fae13e19c0328ac13a4ae1` passed all seven checks in
[run 38299252622](https://github.com/cogine-ai/cliq-agent/actions/runs/38299252622)
on the existing free standard runners. Its credential journey uses the real
signed installed entry, actual user manager and actual GNOME Secret Service:

- Enroll/read/rotate preserve exact historical replay; replay accepts an
  unwritten, unended input pipe with Supervisor/keeper and Secret Service down.
- Terminal revoke commits independently of those services; failed cleanup can
  retry against a genuinely restarted persistent store without rewriting the
  original receipt identity. Explicit superseded/revoked cleanup preserves
  original operations, while the current active item remains protected.
- A real prepared writer is SIGKILLed and fully joined, then the same request
  commits attempt two with its complete frozen core and a fresh producer/item.
  Three separately observed prepared writers can be killed and joined; the
  fourth and repeated request produce the exact exhaustion refusal before
  secret input. The copied actual history has no fourth attempt and preserves
  all earlier facts.

This is positive evidence for those specific cuts, not full qualification of
every acceptance criterion. Live-producer scope retirement, finalizer/clock and
other crash cuts and actual locked/ambiguous/owner/alias drift remain separate
proof obligations.
Generic refusal, portable tests or a successful schema/adapter probe cannot
substitute for them. No complete capability PR is published on partial proof.

Commit `6088093a420bfd0cc08c1da6d5062d9fd2215ebf` also passed the focused
credential journey in
[run 38302749082](https://github.com/cogine-ai/cliq-agent/actions/runs/38302749082).
Its final stable cut scans both original SQLite databases and copied logical
TEXT/BLOB values, every fixed flat CAS object/name, command output, the report
and all four joined trace corpora. The retained report records 204 files,
66 logical rows and 936 closed scan streams, with no forbidden generated-secret
bytes or selected encodings found and no copied scan needles/tails retained.
This is not secure erasure of all VM/native copies or coverage of unexercised
transient/crash paths. No Secret Service keyring files are treated as CAS or
included in this SQLite/CAS corpus; the platform store is the intended secret
owner.

Run [38305329871](https://github.com/cogine-ai/cliq-agent/actions/runs/38305329871)
additionally observed permanent same-request intent conflict before input,
real locked-store refusal, metadata read/revoke with both installed roles down,
and receipt-preserving cleanup after a genuine unlock/restart. Its complete
journey was **not qualified**: an attempted missing-alias fixture lost its
precondition. [GNOME 40.0](https://github.com/GNOME/gnome-keyring/blob/40.0/daemon/dbus/gkd-secret-service.c)
reloads the default alias for each new client and falls back to `login` when
the stored identifier is empty. Same-connection absence therefore cannot
prove a fresh auth client has no default. The corrected fixture tests an
actually observed non-durable session default instead, not missing-alias
qualification, and restores only the original or the exact fixture-owned
session alias. Production checks are not relaxed to match the fixture.

Commit `b2dade2d8594bf9be881740e11f9f63bb1330823` passed that corrected
focused journey in
[run 38308638275](https://github.com/cogine-ai/cliq-agent/actions/runs/38308638275).
Fresh independent clients observed the actual session collection as default;
signed auth refused without new authority or changing the terminal record,
and restoration selected the original `login` collection. The same report
retains locked-store and permanent-intent refusals, 231 scanned files and
1209 joined/closed scan streams without detected generated-secret bytes.
The six other checks passed; the later broad component step was interrupted
by the next schema-regression submission, so this is not an all-seven-check
claim for that commit or proof of missing-alias/owner drift.

The signed schema regression at `73ca35d8682a452948bf34f4453eaa8dca87e481`
in [run 38310358784](https://github.com/cogine-ai/cliq-agent/actions/runs/38310358784)
observed a genuine RED after successful initial v1 read: an extra legal
`sqlitex` table was accepted, and version zero containing that table incorrectly
ran schema genesis. `LIKE 'sqlite_%'` used a wildcard underscore rather than an
exact internal-table prefix. The one-line `GLOB 'sqlite_*'` correction is paired
with v0/v1 signed-entry negatives and a genuine v2 journey negative; portable
success cannot qualify those three Linux checks. The RED run was stopped only after its
schema test finished and the failure was retained; it is not a full campaign.

CI schedules the credential journey and independent component baseline in
parallel on the same free standard Ubuntu 22.04 runner label, retaining their
own reports. No production-operation deadline or qualification assertion is
relaxed to fit a serialized job budget.

The bounded diagnostic at `d8dc886b84273db3297005949fcee5376b20cdb9` in
[run 38354473748](https://github.com/cogine-ai/cliq-agent/actions/runs/38354473748)
confirmed the v2 extra-table read returned the exact expected refusal, with all
four fields and no extra path. The journey still failed: its strict comparison
used an ordinary expected object while the strict JSON parser intentionally
returns null-prototype objects. Matching the expected prototype preserves the
complete exact comparison; the existing signed v0/v1 negatives now use that
same strict representation and bound. This run passed the seven other checks,
but did not reach the final SQLite/CAS corpus scan and is not a green campaign.

Commit `3d069e6622bbcac93c23dbccc13987cbb63cb3e9` passed all eight checks in
[run 38356121735](https://github.com/cogine-ai/cliq-agent/actions/runs/38356121735).
The actual expired enrollment returned the exact preparation-time refusal;
read returned no authority and explicit cleanup proved no retained operation.
The original record/item bytes, actual services and readiness stayed unchanged.
The v0/v1/v2 unsupported-format refusals passed, followed by the final stable
corpus scan: 237 files, both SQLite databases, 96 logical rows and all four
joined trace corpora; 1253 scan streams all closed, with no detected generated
secret bytes or retained needles/tails. Preparation-time expiry does not
qualify finalizer expiry, clock regression or any precise pause/crash cut.

Commit `3937c44269bcbd0026812e6c9ffc87244e53af3e` passed all eight checks in
[run 38357917600](https://github.com/cogine-ai/cliq-agent/actions/runs/38357917600).
The platform-negative fixture added one fixed non-secret attribute to a
genuinely enrolled item while preserving all nine actual selector pairs. The
real search still matched that item; the exact attribute-set check refused
cleanup without blocking terminal revocation. The item and its secret bytes
remained unchanged; restoring only the extra attribute allowed the same
original receipt to finish cleanup, with terminal metadata unchanged and both
installed roles inactive. This is not ambiguity, owner/alias replacement or
finalizer-drift evidence. The fixture never reads the secret or creates/deletes
items and stays restricted to the actual disposable account, GNOME image and
observed bus/service lifetime. The final corpus covered 246 files, both SQLite
databases, 110 logical rows and four joined trace corpora; all 1362 scan streams
closed without detected generated-secret bytes or retained needles/tails.

Commit `d3d9443a1e7f56a2f8e8eb45e654b8da5a727acd` passed all eight checks in
[run 38404301875](https://github.com/cogine-ai/cliq-agent/actions/runs/38404301875).
The static admission negative revoked the actual endpoint through the signed
endpoint command, then attempted a new enroll with an unwritten, unended
secret-input pipe. The exact endpoint refusal preceded input, no new authority
or operation was retained, historical credential replay/read stayed unchanged,
and the actual store inventory remained empty with installed roles inactive.
This does not qualify concurrent endpoint revocation at the finalizer cut.
No additional active grant or production interface was introduced. The final
corpus covered 246 files, both SQLite databases, 114 logical rows and four
joined trace corpora; all 1394 scan streams closed without detected generated
secret bytes or retained needles/tails.

That qualified journey completes the historical-replay/bounded-retry criterion:
original and rotated operation/provenance bytes replay with an unwritten,
unended input pipe and platform/services absent; the original prepared request
retries with its frozen core, and actual attempts one through three preserve
prior facts. Repeated fourth attempts and permanent intent conflicts return
their exact pre-input refusals. This does not close the separate live-producer,
ABA, finalizer or remaining crash criteria.

The completed-schema preservation check saves the original signed endpoint
registration/read responses before the first credential enrollment. After the
actual v1-to-v2 extension, it requires exact original operation/record equality
and identical canonical response bytes from the same signed public entry.
Those exact comparisons passed in the test-first run below and in the complete
extended journey at `92e3c8e` below. This does not qualify old/new migration
crash cuts.

The next genuine ambiguity check enrolls one item through the signed entry,
then the bounded disposable-account fixture must create a second actual item
with identical complete selector attributes and a different already-scanned
generated secret. A fresh public nonce belongs only to its fixture Label, not
the selector. Revoke and explicit cleanup must commit/retain terminal metadata
but refuse to delete either ambiguous item. Only the positively identified
fixture-created path/Label may be removed; original-receipt cleanup must then
complete against the unique original item. That static cleanup case is qualified
at `92e3c8e` below and proves no finalizer ambiguity or precise crash cut.

The test-first commit `28fdaf58bebbcfec367aa89dc1e890ee351fce2e` completed
[run 38414424280](https://github.com/cogine-ai/cliq-agent/actions/runs/38414424280)
with seven successful checks and the expected credential-journey failure at
`ambiguous_store_create`: that immutable commit intentionally lacked the
fixture's duplicate-create command. This is a missing test-fixture capability,
not a demonstrated production defect. The retained report confirms the actual
completed v1-to-v2 endpoint operation/record and response-byte preservation
checks passed before that failure. Its bounded output scan closed all 511
streams without detecting generated secrets or retaining needles/tails, and
joined the daemon; it did not reach the final SQLite/CAS corpus scan. Neither
this RED nor portable tests qualify the pending real ambiguity case.

Commit `1f8bab928dcb890e7b0c0502e3acd758a613b5da` completed
[run 38418796368](https://github.com/cogine-ai/cliq-agent/actions/runs/38418796368)
with the seven independent checks successful, but the credential journey failed
at its final `secret_corpus` phase. Actual duplicate creation/removal, the full
ambiguity-cleanup assertions and completed-schema preservation all passed
before that failure. The daemon joined and all 1169 output scan streams closed
without a secret hit or scan-limit exhaustion. The copied logical SQLite scan
then wrapped an unknown native/API error; its deleted diagnostic copies and
closed report cannot retrospectively establish the underlying error category.
This is not a fully qualified campaign or evidence of secret absence across the
complete SQLite/CAS corpus. A minimal source-owned database/stage/error-class
diagnostic preserves the same sequence, assertions and limits for the next run.
The independently reproduced full-width SQLite INTEGER limitation is not yet
evidence of this Linux failure's cause. Later independent store regressions
remain held outside this diagnostic iteration.

Commit `92e3c8e7d147022012bda7bcab7bc5bbee8d67ec` passed all eight checks in
[run 38423130293](https://github.com/cogine-ai/cliq-agent/actions/runs/38423130293).
The complete journey report qualifies completed-schema endpoint preservation
and actual full-selector ambiguity cleanup: neither matching item was deleted
under ambiguity, terminal metadata and original receipt identity survived, and
only the positively identified fixture item was retired before unique-original
cleanup completed. Its final corpus covered 255 files, both SQLite databases,
128 logical rows, 472 logical values and four joined trace corpora; all 1537
scan streams closed without detected generated secrets or retained needles/tails.
This remains a scoped journey, not complete I1 or finalizer ambiguity evidence.

Independent diagnosis on checksum-verified stock Node 22.13.0 reproduced its
[upstream iterator ownership defect](https://github.com/nodejs/node/issues/57493).
The original temporary `prepare(...).iterate()` expression fails a real copied
database/scanner regression under GC; keeping the actual statement live through
iteration passes all 100 rows and detects a secret only in the final row, while
preserving original database bytes. A post-iteration statement read makes that
ownership explicit. The same temporary iterator also existed in production
credential history, so both readers now use one data-only owned-statement
primitive in the existing SQLite module. It delegates native IteratorClose,
keeps number revisions unchanged, and owns no database or authority. Parameter
binding, early break and consumer-error regressions cover that exact primitive;
the GC copy-reader test covers full rows and final-row secret detection. A
separate bounded default-engine GC child uses the production-shaped temporary
statement call and requires all 100 rows plus the exact last row. On stock
Node 22.13, removing helper ownership makes that test fail; restoring ownership
makes it pass, without relying on the copy reader's own final statement access. No
client/runner version, query bounds or scanner limits
are changed. This establishes a supported-version reader defect, not the unique
historical cause of run `38418796368`, whose closed original error is unavailable.
The same private row reader also now preserves both ends of SQLite's signed
64-bit INTEGER domain; the regression proves those fields cannot stop a later
TEXT secret scan and leaves original bytes unchanged. This is not a business
schema change or evidence identifying that historical Linux error.

The real post-`secret_stored`, retired-scope producer pause remains blocked:
both the proposed native helper and the narrower standard-tool metadata-only
owned pause implementation were stopped by the platform safety check. Their
incomplete/unintegrated work is recoverably kept outside this patch. No test
hook, fabricated NativeProof, process-memory inspection or alternate authority
is introduced to get around that constraint. Live-producer/finalizer/clock and
remaining crash qualification must stay explicitly incomplete until genuine,
permitted evidence is available; the blocked workflow is not evidence or a
reason to claim a completed capability. The later approved progress PR does
not change this qualification boundary.

Two further no-pause regressions reuse existing genuine journey state, not new
grants or production interfaces. The locked-store receipt's known original
item now remains until the default alias is changed to the actual session
collection: replay/explicit cleanup must refuse deletion, preserve the original
receipt identity and terminal record, and leave both collections' inventories
unchanged. Only restoring the original alias permits cleanup; an independent
byte comparison first proves the original secret survived. Separately, a
completed revoke receipt is replayed byte-for-byte with Secret Service fully
joined/offline. A fresh explicit sweep must return its exact closed refusal
without rewriting that completed receipt or terminal record; after restarting
the actual store it must return the same completed bytes. Both cases passed
genuine Linux qualification in run `38533888757`; they qualify neither
finalizer drift nor resource-retirement uncertainty.

Commit `b61ca1e15ec2250939474433a1fdd641282dade6` passed the four complete
OS/Node build-test matrix jobs and three other Linux jobs in
[run 38530434655](https://github.com/cogine-ai/cliq-agent/actions/runs/38530434655),
but its credential job was cancelled at the unchanged 20-minute limit. Only
the initial runner baseline was retained, not the journey's final report.
This is not qualification of either new store case or the final corpus. The
preceding green credential job already took 19 minutes 45 seconds. Its three
independent component checks took about 62 seconds (64 in the cancelled run);
they now run unchanged in the existing same-baseline Linux preflight job.
The stateful journey remains intact, no authority moves between jobs, and
the 20/15-minute budgets and free standard runners are unchanged. Bounded
fixed-phase/monotonic-elapsed test logs diagnose remaining latency only;
they neither identify this timeout's unique cause nor replace final evidence.

Commit `7a8f0bef5d7a2924895d22bca7f1378a2dd68bb4` passed all eight checks in
[run 38533888757](https://github.com/cogine-ai/cliq-agent/actions/runs/38533888757).
The real credential job took 18 minutes 58 seconds and the preflight job
8 minutes 22 seconds within the unchanged budgets. Linux Node 22.13's complete
suite passed 1926/1926, including the direct temporary-statement GC, IteratorClose
and consumer-error regressions; the complete local suite passed 1898/1898.
The retained journey report is `qualified=true`, `phase=complete`, with both
new static store cases' assertions satisfied and `daemonJoined=true`. The final
corpus covered 255 files, both databases, 128 logical rows, 472 logical values,
CAS and four joined trace directories. All 1629 scan streams closed, with 108
needles, no secret match or limit breach, and zero retained needles/tails.
Its downloaded report's SHA-256 is
`e8ad60bd73de3787416d887766e6c4fbbfbfe7184b578996b76b2f6a4a04f345`.
The migration-crash, finalizer-drift/expiry/ambiguity, concurrent-revoke, clock,
live-producer, ABA and complete-I1 evidence boundaries remain unchanged; this
green scoped campaign does not establish complete I1. The subsequently approved
progress PR must explicitly retain that distinction.

A further no-pause qualification now tests the unlocked input interval. A
fresh signed auth caller has not written or ended fd 0 when its genuine initial
UDS channel becomes visible. The test reads only the actual bounded CAS and
validates the full channel/peer/process/principal/StateRoot closure against the
original live PID/start/UID/selected image, not a guessed delay or caller-made
native proof. Source order establishes that initial intent classification has
already retired before this hello dispatch; it does not prove receipt of the
hello ACK or the exact `readSecret` entry. Another normal signed endpoint command
must then commit revocation before the original caller supplies its complete
secret input. The original caller must naturally join with the exact endpoint
refusal, no credential record or retained operation/attempt, and unchanged
actual empty platform inventory/owner/collection. The prior static refusal and
all historical replay, corpus and retirement assertions remain. Both the
production 10-second input bound and CI budgets remain unchanged. This case
is pending genuine Linux qualification and qualifies neither live pending
producer/ABA nor finalizer revocation competition or any precise crash cut.

The first real run of this case at
`f491e95516e3bfd0d8de799be639844ae9f3abb6`,
[run 38553599311](https://github.com/cogine-ai/cliq-agent/actions/runs/38553599311),
passed seven independent checks but failed the credential journey at
`initial_gate_endpoint_revocation`. The closed report locates the unchanged
30-second fixture deadline, not an observation error or a CI timeout. It does
not prove that the observer was called, that the original auth reached its
selected image, or that an initial hello was published. The daemon joined and
all 727 output scan streams closed without a generated-secret match or limit
breach; the final SQLite/CAS corpus was not reached. The downloaded report's
SHA-256 is `bbbe0470a136716b282495876da0c22ef6f876ab4ee738a369d68719804af9b3`.
This is not qualification or evidence identifying a production defect.
The next iteration records only fixed original-auth/pending classifications,
bounded CAS counts and complete-input-write join status. It preserves every
identity/closure/retirement predicate and all original time/scan budgets;
pending diagnostics never satisfy readiness or manufacture authority.

The bounded diagnostic iteration at
`36a2a35fe7b500cf1b039c892c68a05439c43d2b`,
[run 38557844718](https://github.com/cogine-ai/cliq-agent/actions/runs/38557844718),
again passed seven independent checks and failed at that fixture deadline.
It positively observed the owned launcher/direct auth, the complete genuine
hello closure and the complete input-write join; the endpoint revoke command
and its ACK checks necessarily preceded that input. It therefore excludes
missing auth/hello observation as this run's failure, but does not establish
the unique cause of the remaining natural-join timeout. The daemon joined and
all 727 output scan streams closed without a secret match or limit breach;
the final corpus was again not reached. Its report's SHA-256 is
`9a6d3c6be766a3eadfab4d20665d37bfc603aefbd5ad8ab88a6cf6f29da558d7`.
The independent PR run of the same immutable commit,
[run 38558452327](https://github.com/cogine-ai/cliq-agent/actions/runs/38558452327),
retained the same phase/deadline and positive auth/hello/input-join flags,
with 825 ready checks instead of 836. Its report's SHA-256 is
`1086aa9e5452811f3ad878b4f2bc329315ac4d02f4ef7c116d58308454e759b0`.
Both are RED, not complete qualification or unique-root-cause evidence.

The next fixture arrangement reuses the genuine Supervisor already started
by the preceding nondurable-alias auth case, before the existing stopRoles.
It requires both fixed services active/running and verifies unchanged actual
PID/invocation/cgroup after the input race. The original cold-autostart case
remains intact; this new cut qualifies connection to an existing Supervisor,
not cold startup. No role is artificially started, no readiness is inferred
from a manager job, and no new pause, delay or budget is introduced. The single
existing stop then precedes all original unknown-schema/inactive, static
endpoint-refusal, historical-replay, offline-receipt and final-corpus checks.
Earlier real endpoint revocation does not change terminal credential reads,
which validate the original registration closure rather than active authority.
Every original assertion remains; this arrangement still awaits genuine Linux
qualification and is not a demonstrated production fix.

Commit `1bc4156070a006c0dae5dc12af99f44c9da4f5ec` passed all eight checks in
both [PR run 38562311225](https://github.com/cogine-ai/cliq-agent/actions/runs/38562311225)
and [branch run 38562304187](https://github.com/cogine-ai/cliq-agent/actions/runs/38562304187).
Their credential jobs took 16 minutes 9 seconds and 19 minutes 46 seconds,
respectively, within the unchanged 20-minute limit; the latter's narrow margin
is not evidence of ample budget for further qualification. Local build and
1898/1898 tests, strict journey/observer TypeScript and design contracts passed.
The source change only rearranged the fixture and added strict existing-service
checks; it did not change production or weaken any predicate or budget. These
successful runs do not retroactively identify the unique prior timeout cause.

Both genuine reports are `qualified=true`, `phase=complete`, with the new
initial-gate/input endpoint-revocation assertions satisfied: the original auth
and initial hello were observed before the real revoke ACK, complete input then
joined, the auth naturally exited with the exact refusal, and no new credential
or retained operation/attempt appeared. Empty platform inventory/owner/collection
and both actual service PID/invocation/cgroup bindings remained unchanged.
Cold autostart, exact readSecret entry, live-pending/ABA and finalizer competition
are explicitly not qualified by this new cut. Every original schema/static/
historical/offline/store assertion and the final corpus completed; daemon join,
runner-baseline restoration and zero cleanup errors were independently checked.
Each corpus covered 261 files, both databases, 128 logical rows, 472 values,
CAS and four trace directories. All 1659 streams closed, with 108 needles,
no secret match or limit breach, and zero retained needles/tails.
The downloaded report SHA-256 hashes are
`7753a5fca7fb3f2fbb7e93cf17aa3edfd19b019f720cd8a7fe6b5b8cfe48c228` (PR)
and `bd66ccf105b64a741de2e1b344810b87489e0c50f509edb44182e556e6e06423` (branch).
The approved [progress PR #521](https://github.com/cogine-ai/cliq-agent/pull/521)
does not complete I1: the acceptance checklist above is still incomplete,
regardless of its GitHub Draft/ready presentation.

The documentation-only commit `b474783691adffe8b7674a7599bf34688b810fd7`
also passed all eight checks independently in
[PR run 38565646184](https://github.com/cogine-ai/cliq-agent/actions/runs/38565646184)
and [branch run 38565637401](https://github.com/cogine-ai/cliq-agent/actions/runs/38565637401).
Credential jobs took 19 minutes 28 seconds and 18 minutes 53 seconds under the
unchanged 20-minute limit; this still does not establish spare capacity. Both
reports retained the genuine initial-gate/input endpoint refusal, unchanged
negative qualification boundaries, complete 261-file/two-database/128-row/
472-value corpus, daemon join, restored runner baseline and zero cleanup errors.
The PR report closed all 1661 streams and the branch report all 1659, with 108
needles, no match or limit breach and zero retained needles/tails. Their SHA-256
hashes are `d05ee4acb97b971c94ce58c2bcbdc5ed5301d67d2c24331a08483ed6724f0ce7`
(PR) and `5dfa43734a092c653039ca3d98e7a03b5ae27fdc31db12876ccaea08b557fb14`
(branch). These runs precede the review repairs and cannot qualify their code.

#### PR #521 review triage

The current-code review identified three necessary repairs: reject systemd's
unsupported decoded executable characters before profile writes, accept the
server's closed `REQUEST_ID_CONFLICT` refusal without changing retry semantics,
and retire a timed-out platform operation's local D-Bus connection without
reusing its cancelled operation token. Genuine close failure must still retain
its owners and poison subsequent operations; successful local retirement does
not turn an expired operation into success. The owner approved direct testing
of the existing pure wire decoder; it creates no peer or credential authority.

Other suggestions do not justify changes in this repair: fixed local refusal
diagnostics intentionally import no remote payload or new retry policy; the
native self-image predicate also enforces regular-file/size admissibility; the
SQLite post-iteration statement reference deliberately retains its owner.
Extracting authority storage, enlarging CI budgets, making qualification optional
or splitting the stateful journey would exceed this focused repair without
demonstrated necessary correctness benefit. Missing live-pending/ABA/finalizer
and crash-cut evidence remains missing, not waived by this review or green CI.

For these repairs, local build and 1916/1916 tests passed with zero failures or
skips; stock Node 22.13 passed the focused profile/wire/SQLite suite (60 tests).
The profile and request-conflict regressions were observed RED before their
minimal fixes and GREEN after them. Strict journey/observer/component TypeScript
and design-contract checks passed. The new public native component fixture uses
a private mount namespace and a real same-UID D-Bus daemon, with only its external
service withholding the first reply. It must observe actual first-connection
departure, admit a healthy subsequent call and join all owned children without
altering the host runtime. It creates no StateOwner, credential phase, installed
identity or canonical clock. Production still requires positive local close/join
and preserves actual retirement failures; a post-failure closed flag alone does
not waive them. Linux compile/runtime and an actual old-code RED for this native
case have not yet been observed locally; source review is not runtime evidence.

Repair commit `d5cafbf6e27d1e431889b760c7abf982a046cb08` is not all-green:
[PR run 38576057378](https://github.com/cogine-ai/cliq-agent/actions/runs/38576057378)
passed seven checks, but the new executing-timeout component failed. Its native
module and fixture compiled; the unchanged queue case passed. The new caller
was refused with `process_identity_unavailable` after about 3.7 seconds, before
the intended 30-second timeout. The branch run reproduced this refusal after
about 3.3 seconds. Neither qualifies the new executing-timeout regression.
The root-to-user fixture coordinator had not performed an ordinary user exec;
Linux's nondumpable `/proc` ownership is consistent with the native identity
gate correctly refusing it. A fixture-only ordinary non-root re-exec is being
verified, not a dumpability/sysctl change or weakened `/proc`/UID assertion.

The independent genuine installed credential job in that PR run completed in
12 minutes 13 seconds with its original scoped assertions, daemon join and full
261-file/two-database/128-row/472-value/four-trace corpus. All 1659 scanner streams
closed, with 108 needles, no match/limit breach and zero retained needles/tails;
runner baselines matched and cleanup errors were zero. Its report SHA-256 is
`1fb608d7a8bc4c71f35af4a3a96896809d66f597c05b96fca1e8ba539666738a`.
Linux Node 22.13 passed 1944/1944 tests with zero failures/skips. These successes
do not erase the failed component gate or complete the remaining I1 campaign.
The same-commit [branch run 38576047311](https://github.com/cogine-ai/cliq-agent/actions/runs/38576047311)
reached the credential job's unchanged 20-minute limit and was cancelled; its
installed journey is not qualified. The successful PR run does not erase this
independent timeout or establish ample runner capacity.

The fixture correction re-execs the same test ELF normally after full UID/GID
drop, in the same private mount namespace. Before exporting its external service,
it checks actual same-UID `/proc` ownership and all real/effective/saved IDs,
retains the parent-death hook, verifies and consumes both namespace handles,
and binds its private `/run` marker/flags to the actual held mount ID. Covered
older `/run` rows in mountinfo are not the current descriptor's mount. The healthy
native response must name the actual caller's parent as its manager. All original
timeout, rejection, connection-departure, host-runtime and child-join assertions
remain; the pre-exec ownership boolean is an observation, not authority evidence.
Local build and a second full 1916/1916 suite passed with zero failures/skips;
strict TypeScript, JS syntax and independent source audits passed.

At fixture correction `7626f9f05e7024987ceff6512e6967cebe29bf02`, both real
Linux preflight jobs passed the executing-timeout component and unchanged queue
component (2/2, zero failures/cancellations/skips). Each closed component report
observed the ordinary user exec, actual first-connection departure, healthy
subsequent operation and all child joins; `installedI1Qualified` remained false.
The executing native call met its unchanged 25..35-second assertion around the
production 30-second deadline. This is a genuine current-code GREEN, not an
observed old-code RED or installed/finalizer qualification.

The [branch run 38580252866](https://github.com/cogine-ai/cliq-agent/actions/runs/38580252866)
passed all eight checks; its credential job completed in 18 minutes 46 seconds.
The exact report is `qualified=true / phase=complete / daemonJoined=true`, with
261 files, two databases, 128 logical rows, 472 logical values and four evidence
directories. All 1659 scanner streams closed, with 108 needles, no match/limit
breach and zero retained needles/tails. Runner baselines matched, cleanup errors
and campaign exit status were zero. Report SHA-256:
`7d7995e331fab3dd694fa55cf03549985eb583ea355074059a3c5062619e7965`.
The same-commit [PR run 38580259687](https://github.com/cogine-ai/cliq-agent/actions/runs/38580259687)
passed seven checks but its credential job was cancelled at the unchanged
20-minute limit. It retained only the initial baseline, not a final qualified
journey/corpus report. The branch success does not erase that PR gate.

The existing fixed phase logs are sufficient to diagnose capacity without
additional instrumentation. The four prepared crash blocks took 374.397 seconds
in the successful branch run and 380.873 seconds in the cancelled PR run; ordinary
commands were broadly 10..15 percent slower in the cancelled run. The successful
final corpus scan took about 0.223 seconds. These observations do not establish
a unique cause or justify reducing crash/scanner assertions or raising budgets.

Implementation `e839ebd7d34920539ef9305fe532afc4a4e6747e` increases only
installed-runtime's internal
streaming IO batch from 64 KiB to a bounded 1 MiB. It retains every fresh complete
byte hash, signed count, EOF, before/after physical identity, revalidation boundary
and descriptor retirement. No cached integrity result, authority, probe change,
pause delay change or omitted journey case is introduced. The existing public
installer-only seam now checks a signed opaque entry spanning multiple MiB with
a partial tail and refuses same-size corruption in its last byte before creating
StateRoot. These opaque bytes are never executed and cannot qualify an installed
image. At the implementation commit the Linux results were still pending;
the subsequently completed exact-head evidence is retained below. A local proxy
measurement alone cannot establish actual Linux performance or qualification.
Local build and another complete 1916/1916 suite passed with zero failures,
cancellations or skips; the unchanged design guard passed all nine regressions.
macOS exercised only the unsupported-platform installer contract, not the new
Linux large-entry/tail-corruption cases.

Both exact-head [PR run 38588125656](https://github.com/cogine-ai/cliq-agent/actions/runs/38588125656)
and [branch run 38588111674](https://github.com/cogine-ai/cliq-agent/actions/runs/38588111674)
passed all eight checks. Their credential jobs took 12 minutes 27 seconds and
11 minutes 3 seconds respectively within the original 20-minute budget. Both
Linux preflight jobs passed the large-entry/tail-corruption cases and the real
timeout/healthy-retry component; the latter still declares
`installedI1Qualified=false`. Linux Node 22.13 passed 1945/1945 tests, with zero
failures, cancellations or skips.

Both actual journey reports are `qualified=true / phase=complete`, with the
daemon joined. Each scanned 261 files, both databases, 128 logical rows, 472
logical values and four trace directories. All 1659 scanner streams closed,
with 108 needles, no match/limit breach and zero retained needles/tails. Actual
before/after runner baselines matched, cleanup errors and campaign exit status
were zero. The nine positive input-revocation flags remain true and all four
excluded input qualification flags remain false; the other unqualified
finalizer/crash/live-producer cases remain excluded as well.
Report SHA-256:

- PR: `2fe4d4cf0566abe98e40779af985ee7590caea0e257c270c8ee2aefe0d9bf69e`.
- Branch: `89c78a18508efbb9555cad2623b47903747d648499faff40314dd819a036c174`.

The faster completed runs support retaining the bounded fresh-byte read change.
They do not establish a unique causal diagnosis or guarantee future runner
capacity. Earlier cancellations remain recorded; no budget, identity check,
pause delay, scanner limit, stateful journey case or acceptance requirement was
relaxed. Progress-merge approval is not release, rollback/downgrade or complete-I1
approval; reverting source cannot undo experimental credential databases/items.

### Risks And Dependencies

Order: synchronize RFC/WP contracts; one real public tracer bullet; implement
only its owning path; repeat within this one capability; independent review;
full portable and real Linux qualification before claiming I1 complete. The
merged progress checkpoint retains its missing evidence explicitly. Qualification
uses generated disposable secrets/keys/users, not the owner's real credentials.
The default CLI/state remain untouched. No downgrade or legacy fallback is
introduced; schema-crash recovery accepts complete supported old/new states.

### Open Questions

No additional product choice is needed for this approved A path. Concrete
transport/input/unit details must satisfy the above contracts before their
tests/implementation; failure to prove them is not permission to weaken them.

## Backlog Ready Spec — fixed finalizer-time diagnostics

### Verdict

On 2026-10-15 the owner confirmed implementation of this two-reason contract.
The minimal production change and pure wire-data regressions are implemented;
complete local verification passed, while exact-head Linux is pending at this
checkpoint.
The reasons are diagnostic only, not evidence that a finalizer-negative cut has
executed. The existing full-I1 criteria and excluded pause workflows remain.

### Source

Base: merged PR #521 at `b7107476e33b6d0d9438352718e3ff7b6307d903`.
Successful GitHub issue searches for `finalize_refused`, `finalizer diagnostic`
and `credential refusal` found no matches within those open/closed query scopes
(limit 20 each). No issue is created. Current code has one generic
`credential.finalize_refused` projection in `src/state/installed-control.ts`
and a fixed local refusal in `src/state/installed-credential-client.ts`.
`src/state/store.ts` separately checks preparation and finalizer time/expiry.

### User Outcome

A genuine time refusal received from the installed Supervisor can produce a
fixed local diagnosis distinguishing noncausal finalization timestamps from
expiry at finalization. Diagnosis supplies no retry permission, completion
status, active authority, time ticket or proof of any unexecuted acceptance case.

### Problem

An ordinary short-expiry request can fail at preparation before finalization.
Even retained `secret_stored` history cannot prove the Supervisor received the
continuation. Current generic rejection, a null credential read, or a diagnostic
alone is therefore insufficient evidence of the finalizer's expiry cut.

### Scope

In: two fixed finalizer-time `messageCode` values and a compiled local mapping
through the existing `credential.finalize` response and pure decoder seam.
Out: `operation_status`, new wire fields/error-code variants/methods, phase readers/writers,
time/identity inputs, negative-receipt tables, protocol-version changes, recovery
advice, automatic retries and a new logger or adapter factory. This increment
does not reconstruct or retry the excluded producer-pause workflows.

### Proposed Implementation Direction

Only an internally classified refusal thrown by the actual finalizer time
guard may select these values. Use a narrow typed error, not exception-message
matching, caller properties or an arbitrary cause chain. Keep its existing
`STATE_TRANSITION_INVALID` classification; on the wire keep
`code='AUTHORIZATION_REQUIRED'`, `retryable=false`, and the exact v1 envelope.
Other state/endpoint/phase refusals keep `credential.finalize_refused`.

| Finalizer guard | Fixed wire `messageCode` | Fixed local diagnostic |
| --- | --- | --- |
| Any existing causal timestamp exceeds sampled C | `credential.finalize.noncausal_time` | `installed Supervisor refused credential finalization because its timestamps are not causal` |
| No causal violation; `expiresAt <= C` | `credential.finalize.expired` | `installed Supervisor refused expired credential finalization` |
| Other valid refusal / unknown messageCode | Existing value / no new mapping | Existing generic fixed refusal |

When both causal violation and expiry hold, keep the existing causal-check
precedence. Do not
move or resample C, move a guard before the Run fence, add an await/callback/log
between ordered commits, change any condition, or write credential facts on a
refusal. Canonical-fence regression and retirement failure are not time-diagnostic
successes: preserve their current error/poisoning behavior and precedence.

The client selects fixed text only for the exact verified triple
`(credential.finalize, AUTHORIZATION_REQUIRED, known messageCode)`. Within an
otherwise valid expected-method refusal, a known text paired with another
code/hello method, or an unknown messageCode, uses the existing fixed generic
refusal. A wrong envelope/method or unknown wire code still fails strict decoding.
Never print remote payload, errorId, timestamps, paths,
raw exception text or an unrecognized messageCode. Keep outer
`RECOVERY_REQUIRED`, `retryable=false`, exact decoding and resource joins.

Likely files: `src/state/store.ts`, `src/state/errors.ts`,
`src/state/installed-control.ts`, `src/state/installed-credential-client.ts`,
adjacent approved decoder regressions and
the mirrored RFC/WP contracts. Do not expose an internal classifier or add a
fake Store/frame/clock seam solely to exercise it.

### Acceptance Criteria

- [x] Owner confirmed this two-reason design before production changes.
- [x] Source inspection: only the actual finalizer time guards select the two new
  diagnostics; preparation, hello, epoch/peer/endpoint drift and clock regression
  do not. This is not runtime evidence of either negative cut.
- [ ] Every existing state/time/identity predicate, lock order, fence/credential
  commit order, immutable replay and terminal-revoke behavior remains unchanged.
- [x] Approved pure seam: client known-pair mapping, cross-code/method misuse, unknown-messageCode
  fallback, unchanged strict malformed-frame rejection and absence of
  remote-content import are tested at the approved pure seam.
- [ ] Genuine retirement failure still wins over ordinary refusal; no diagnostic
  changes cleanup, sticky refusal, descriptor joins or retry policy.
- [ ] Existing installed journey/expiry-preparation assertions and full secret
  corpus pass within unchanged free-runner budgets, without omitted cases.
- [ ] Unexecuted finalizer negatives and all other open I1 cuts remain explicitly
  unverified; pure-data/source review cannot mark them qualified.

### Validation

Use `npm run build`, `npm test`, design-contract guards and the approved pure
wire decoder tests. Reuse the genuine signed installed entry/v1 UDS journey on
the free standard Linux runner with all existing assertions and scan limits.
Review the exact throwing branches and error projection; this source check is
not runtime evidence of a negative cut. No new test seam is approved here.

At the implementation checkpoint, both positive fixed-text regressions were
observed RED against the previous decoder and GREEN after their corresponding
minimal mapping changes. The complete approved pure decoder suite passed 64/64
with zero failures, cancellations or skips. It includes each reason crossed with
all seven other accepted refusal codes, expected hello, unknown canonical codes,
malformed envelopes and bounded/Unicode message-code rejection. Generic outcomes
also assert no imported `cause`, `messageCode` or `errorId`. Independent source
review found exactly two typed-error construction sites at the original finalizer
guards, with unchanged causal precedence, sampled C, fence/credential ordering,
identity/lock predicates and retirement handling. Design-contract checks found no
drift and their nine regressions passed.
Local build and the full 1963/1963 suite passed with zero failures,
cancellations or skips; stock Node 22.13 also passed the 64-test decoder suite.

These are pure-data and source observations, not executed finalizer time-refusal
branches/server projection, a simultaneous causal-and-expiry cut or a genuine
retirement-over-time-refusal cut. Those runtime cases remain unverified. The
genuine installed journey, preparation-expiry assertions, native components,
secret scanners and all CI budgets are unchanged and require exact-head Linux
verification; previous-head green runs cannot qualify this change.

### Risks And Dependencies

Diagnostic data remains untrusted and non-authoritative even on an authenticated
connection. A real acceptance claim still needs the genuine original process,
request/operation correlation, actual reached guard, retained state/platform
closure, absence of expansion and all owning-resource/secret-scan joins.
More granular messages do not make those missing facts exist. This proposal
adds no database/schema migration; reverting it restores fixed generic text,
not rollback of experimental credential state.

### Open Questions

A deterministic, permitted full finalizer-negative qualification path remains a
separate missing requirement; approving or implementing diagnostics neither
supplies it nor relaxes its standard.
