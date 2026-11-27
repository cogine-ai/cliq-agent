# Public locked-package GET native owner

This is the private Linux `dependency_registry_broker@1` mechanism for the
locked Node dependency operation. It does not add a Run, Journal, credential
selector, provider request, approval, execution lease, or public control method.
Workspace trust, tool permission and the sandbox remain separate gates. The
Supervisor must validate the original signed plan, current registry/TLS source,
Run, owner, grant and claim before each release. Loading this native image is
not that authorization.

The image is built separately from `credential-platform.c`, with
`CLIQ_DEPENDENCY_REGISTRY_BROKER_MODULE`. The original SecretService/platform
and model broker branches retain their original exports and model body limit.
The new export is `prepareDependencyTransport(configurationBytes,
trustStoreBytes)`. Both arguments are real Buffers; no object properties,
getter, URL, secret, body, pathname, FD number, or JavaScript callback selects a
network operation.

The fixed canonical configuration has exactly these fields:

- `schemaVersion: 1`, `transport: public_integrity_get_v1`;
- `planDigest`, `sandboxLaunchSpecRef`, `packageCount`,
  `packageDescriptorBytes`, `descriptorSequenceDigest`;
- `maxPackageBytes`, `maxTransferBytes`, `runRemainingMs`;
- `targets`, `trustStoreDigest`.

Each target has exactly `endpointRegistrationRef`, `hostAscii`, `port`,
`basePath`, `serverNameAscii`, `spkiSha256Pins`, `tlsPolicyDigest`. There are at most
128 unique targets. The original TLS policy digest is kept distinct from the CA bytes digest.
The Supervisor binds each policy to the same current signed default
trust-store entry: one complete CA Buffer is retained, bounded by the existing
16 MiB trust-store limit. TLS is exactly TLS 1.3, with real certificate/hostname
verification and one of the frozen SPKI SHA256 pins. Proxying, redirects,
credentials, URL query/fragment/userinfo and response decompression are absent.
The request path is the frozen base path plus the selected original package
path. The canonical path uses the same fixed ASCII registry path vocabulary.

## Original descriptor sequence

`registerPackagePage(Buffer)` accepts only the fixed canonical page
`{schemaVersion:1, firstIndex, descriptors}`. A page contains 1–32 complete
six-field descriptors and is at most 64 KiB. Every record retains the original
`packageName`, `packageVersion`, `endpointRegistrationRef`,
`canonicalPackagePath`, `integrityAlgorithm`, `integrityDigest` bytes. The
original TypeScript lock resolver still validates npm names, semver, graph,
platform and endpoint provenance; the native parser checks the complete closed
canonical transport representation rather than implementing another resolver.

The package tuple is strictly increasing in the original field order above.
The native owner copies each page before parsing it, rejects gaps, duplicate or
reordered records, extra/malformed pages and another endpoint, and checks the
exact total count and original package-descriptor byte total. Its sequence SHA
is incrementally computed over ASCII
`cliq-dependency-package-descriptors-v1\0`, followed by each original canonical
six-field descriptor's u32 little-endian length and all its bytes. There is no
whole-graph JSON array, truncation, extra CAS ledger or new writer.

`sealPackagePlan()` resolves `ready` only after that full comparison. All pages
must be registered and all queued data operations joined before the original
claim. The package hard ceiling remains 200,000, without claiming that such a
plan also fits the existing lockfile 1 MiB/10,000-node limit or other resource
limits.

The single owner data bound is 64 MiB. Before any GET it reserves:

1. `fixedOwnerStorageBytes`, exported by the actual compiled image;
2. for every page, its complete canonical byte length plus exported
   `descriptorPageStorageBytes`;
3. for every package, four bytes plus the canonical FD4 record length using
   the original descriptor, `blobBytes=maxPackageBytes`, and a 64-character
   SHA256 placeholder.

Their sum must not exceed exported `maximumOwnerDataBytes=67108864`. The same
native check applies while pages arrive. The metadata stream and page/native
structures do not each receive another 64 MiB allowance. The existing single
file/output/profile limits still apply independently; each downloaded archive
is at most the smaller authorized limit and 64 MiB.

## One claim, actual GET and data children

The original 14-field invocation binding is supplied as canonical Buffer bytes
and frozen by `bindInvocation` after `retainDispatchFence`. The native token is
randomly born by this owner. Every subsequent release must equal the exact
original Run, operation, attempt, dispatch, Journal sequence, request, target,
grant, Supervisor, StateOwner epoch, lease epoch and token digest. This does not
replace their original durable authorization checks.

`connect(binding,index,attempt)` and `releaseGet(binding,index,attempt)` select
only the next frozen descriptor. Package HTTP attempt is exactly 1, 2 or 3;
Journal attempt remains its original independent zero-based field. There is no
fourth GET. A successful package must have all original data cursors joined and
its data owner closed before the next index. Only a completed HTTP error,
integrity mismatch or joined original `transport_interrupted` failure can
advance to the next HTTP attempt of that same descriptor. Cancellation,
expiry, binding, limit, storage, TLS authorization and retirement failures do
not become transport retries.

The owner captures its outer monotonic remaining-duration cut once at native
entry. Each connection/request uses one absolute deadline bounded by the
smaller of that original remaining duration and 30 seconds. Connect, headers,
body and EOF do not refresh it. The Supervisor also retains the original Run
deadline, lease, fresh release gates and Stop. This is no new canonical clock.

The actual GIO/TLS worker owns and closes its original connection. Request
release and active-release accounting use the original native mutex; a
settlement fence cannot overlap an active request. HTTP framing retains the
bounded strict header/chunk grammar, rejects redirects, ambiguous framing,
trailing bytes and incomplete EOF, and streams raw body bytes in chunks of at
most 64 KiB. An unframed response that reaches the exact byte ceiling without EOF is
refused without requesting another payload byte; its EOF is still unknown.
Length/chunk-framed exact-bound responses retain their real framing/EOF checks.
All actually received payload bytes, including failed attempts,
count against the original aggregate download budget (default 5 GiB, hard
ceiling 20 GiB). Error bodies are discarded; only bounded status/count data
survives. No package body is decoded as UTF-8, model JSON, an exception or log.

Only complete 200/EOF data with matching original SHA256 or SHA512 SRI creates a
package owner. Its memfd is mode 0400, fully sealed, reopened read-only, checked
against the same inode and actually closed on the writable side before return.
`openReader/readChunk/assertComplete/close` uses independent real FD cursors,
full raw SHA256/EOF and before/after identity/seal checks. Metadata is not EOF.
CAS failure leaves the original package and fence available for a fresh data
cursor and persistence retry; it does not issue another GET. Closing an active
reader's owner is refused. Whole-owner cancellation revokes and actually joins
all its original readers and FDs.

The async fixed native Error has a distinct purpose tag.
`observeFailure(error)` accepts only that same owner's actual error, retains
its creation-time index/attempt/count/EOF and joined-I/O facts, and returns
closed data. A foreign or substituted Error, proxy, getter or message is no
source of a retry. The wrapper must still match its exact original task and
must not interpret business refusals as native transport throws.

## FD4 and the original offline scope

Successful package close appends only native-owned facts to an internal memfd:
u32 little-endian record length, then strict canonical JSON with exactly
`blobBytes`, `blobSha256`, `canonicalPackagePath`, `endpointRegistrationRef`,
`integrityAlgorithm`, `integrityDigest`, `packageName`, `packageVersion`.
JavaScript cannot supply blob metadata. `sealPackageInputs(binding)` performs
the complete stream reread, EOF, original incremental SHA and stable identity
checks on a joined native worker, then seals/reopens it read-only and closes the
writable FD. Zero packages produce a real empty sealed stream. This preparation
finishes before scope acquisition/CREATE and does not consume the READY window.

The same-process purpose tag/ABI/creator and fixed C function pointers follow
the existing native input-bridge pattern. The original scope registers with
`acquire_worker` before CREATE can send or partially fail, then borrows the
metadata FD exactly once through `borrow_package_inputs`. No JS FD is exposed.
The actual original controller/scope owns that duplicate until its full join.
FD3 remains a bounded small root; FD4 is parsed incrementally, with original
count/sequence/full hash/EOF/close checks. Packages then enter the original
blocked scope through its fixed bounded data channel. The worker must finish
all package input hashes, EOF and closes before `release_execution` can run npm.
Only `owner.releaseProcess` may invoke that fixed C release callback; the
ordinary scope release API refuses this purpose. No extra runner, claim,
callback, fake lease or recycled scope is introduced.

## Settlement, retained result custody and shutdown

`acquireSettlementFence(binding)` is a new purpose-specific native brand. It
permanently revokes further release, holds the original mutex and requires no
active release, joined network I/O, all package cursors/owners closed, and the
original process's real complete domain retirement when a scope was acquired.
Network/request-start observations remain honest. This fence is not the old
model no-release brand, and it does not claim that original retained result
memfds have been consumed or closed.

The original raw result, captured bytes and quartet must persist and actually
join, and the unique complete-tool SQL transaction must succeed, before
`beginAcknowledgeProcessResult` can send the original exact result ACK.
`pollProcessResultAcknowledged` must observe its actual native completion;
CAS/SQL failure retains the same result and does not repeat execution or
settlement. `releaseDispatchFence` requires result custody retired and the
original peer borrow released. Actual I/O close can finish while that dispatch
fence or a settlement guard is retained; its closed data reports both states.
It does not wait for the caller to drop the fence that the caller needs that
very close result to settle. The native allocation/mutex remains protected until
explicit guard/fence release, independently of the joined I/O receipt. Scope numbers, next scope, limits, death guards,
UNKNOWN accounting and recovery fences are unchanged.

Whole cancellation requests actual close of that original controller, not just
a structural closed bit or a unit observation. Only actual cleanup, reap and
resource join may local-drop result custody. `acknowledged` and
`controller_joined` remain distinct origins; a local drop does not claim SQL
success or a post-commit ACK. Close never starts ACK for uncommitted data. The
original two-second shutdown boundary remains; uncertainty retains the native
owner/fence/result and returns retirement failure. Native borrow counts protect
broker, package, reader, Error, fence and peer allocations independently of
N-API environment finalizer order. Data/GC release is not a claim that physical
RSS has returned to the OS.

## Verification boundary

Portable compiled C/data tests cover exact descriptor and FD4 canonical bytes,
sequence hashes, missing/unknown/reordered/duplicate input, framing errors and
more than 3 MiB of arbitrary binary body data. A Linux-only test builds the
actual addon and exercises real TLS, three original fetch attempts, SRI/sealed
memfd cursors and cancellation/close join. On a non-Linux host it is explicitly
skipped. Host syntax checks with Linux-only declarations are syntax evidence,
not Linux compilation or supported installed qualification. The full same-owner
Journal/worker/SQL/ACK integration and actual installed Linux campaign remain
separate required gates; no component result raises them to passed.
