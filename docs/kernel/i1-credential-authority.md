# I1 — installed Linux credential authority

## Backlog Ready Spec

### Verdict

READY for implementation, not qualified or complete. The owner approved option A
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
- `{schemaVersion:1,kind:'enroll',requestId,credentialGrantId,purpose,
  endpointRegistrationId,secretSubmissionId,expiresAt?}` contains stable user
  intent, not an externally generated subject or command core. Success returns
  `{schemaVersion:1,operation}` for the committed original operation. The first
  pre-input history check and the post-input lock-held race check are distinct.

Ordinary auth does not install/reload/repair units. Missing profiles or drift
produce remediation; a successful manager job/socket existence alone is not
readiness. Bind the actual connected server process to its current manager
invocation and selected image, then use the existing current-owner hello and
finalizer feature. No new client-side epoch/time authority is required.

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
   freeze the complete secret-free core and first authenticated channel.
   Its bytes/observedAt remain unchanged for the same uncommitted core and
   contiguous attempts 1..3; only one committed generation can acquire it.
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
Locked, prompted, ambiguous, replaced-owner/alias or unavailable-store results
never create active authority. Errors and trace artifacts exclude remote
payloads/secrets; no promise is made to erase every V8/GIO copy.

[Lookup attributes](https://specifications.freedesktop.org/secret-service/latest/lookup-attributes.html)
are not secret storage. The
[Collection interface](https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Collection.html)
returns an item path after creation and supports replacement; neither is an
authority identity or an acceptable overwrite policy here.

#### Narrow authenticated finalizer

`credential.finalize` carries only protocol/request correlation plus the
original `operationId`, `attempt` and `commandDigest`. It carries no raw secret,
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
