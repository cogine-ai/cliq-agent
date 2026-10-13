# I1 — installed Linux credential authority

## Backlog Ready Spec

### Verdict

Implementation and qualification in progress, not qualified or complete. The owner approved option A
on 2026-10-12: enroll/rotate may automatically start or connect the installed
Supervisor; only its existing canonical-time authority may finalize expansion.
Read, historical replay, revoke and cleanup remain independent. This is one
credential capability, not a sequence of schema/adapter-only PRs.

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

- [ ] Real installed enroll/read/replay/rotate/revoke/cleanup journey with one
  genuine default Secret Service and no provider I/O.
- [ ] Same-request committed replay returns original result/provenance without
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

The next no-pause case uses an actually expired enrollment through the signed
entry and checks no retained operation, no new authority and unchanged original
record/item, actual services and readiness. It remains pending genuine Linux
qualification. Preparation-time expiry does not qualify finalizer expiry,
clock regression or any precise pause/crash cut.

The real post-`secret_stored`, retired-scope producer pause remains blocked:
both the proposed native helper and the narrower standard-tool metadata-only
owned pause implementation were stopped by the platform safety check. Their
incomplete/unintegrated work is recoverably kept outside this patch. No test
hook, fabricated NativeProof, process-memory inspection or alternate authority
is introduced to get around that constraint. Live-producer/finalizer/clock and
remaining crash qualification must stay explicitly incomplete until genuine,
permitted evidence is available; this is not another product choice or a
reason to publish a partial capability PR.

### Risks And Dependencies

Order: synchronize RFC/WP contracts; one real public tracer bullet; implement
only its owning path; repeat within this one capability; independent review;
full portable and real Linux qualification before a coherent PR. Qualification
uses generated disposable secrets/keys/users, not the owner's real credentials.
The default CLI/state remain untouched. No downgrade or legacy fallback is
introduced; schema-crash recovery accepts complete supported old/new states.

### Open Questions

No additional product choice is needed for this approved A path. Concrete
transport/input/unit details must satisfy the above contracts before their
tests/implementation; failure to prove them is not permission to weaken them.
