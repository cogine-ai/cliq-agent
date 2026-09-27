# Durable Kernel implementation progress

**Target:** Complete all six accepted work packages and the single Kernel Cut.
**Baseline:** `main@8029659` after PR #509.
**Execution branch:** `cliq/kernel-implementation`.
**Current checkpoint:** I1; not passed.

The [design review](2026-09-26-design-review.md) and the six work-package
acceptance criteria remain the implementation plan. No package is complete from
source presence, a test fixture, or an unsigned/uninstalled build alone.

## 2026-09-26: accepted control authority and first live path

- Created a clean isolated worktree and installed the lockfile dependencies.
- Checked the existing StateOwner, StateStore/control reducers, native owner
  helper, platform qualification, and the planned I1 integration order.
- Added a real macOS/Linux native socket characterization program and one
  regression test. On Darwin 25.5.0, the filesystem socket node and live socket
  descriptor have different identities/permissions; `fchmod` and `O_EVTONLY`
  cannot turn the latter into the former.
- Identified a separate source-level gap: repeating cached peer credentials
  does not prove the connection's original PID has not been reused.
- The project owner accepted [option A](../rfcs/2026-09-26-local-control-identity.md):
  authorize the local UID and continuously held connection; PID/start/image are
  diagnostic only. The August RFC and WP01/WP03/WP04/WP06 now carry that contract.
- Added a separate V2 closed peer-observation schema/decoder, historical closure,
  and a one-use runtime request authority. Session and Run admission authenticate
  before replay lookup, preserving the original committed channel provenance.
- Added a native same-user UDS listener with independent endpoint/listener/accepted
  descriptor checks, safe own-node unlink, bounded framing, OS peer credentials,
  and connection-lifetime revocation. The signed RuntimeBundle binds its native
  helper bytes before the hidden StateStore service starts.
- Wired a limited hidden `control.hello`/`session.create` path through real
  StateStore. Mac tests cover same-user credentials, unexpected/replaced endpoint,
  forged caller identity, history-only artifact rejection, reconnect replay,
  and disconnect after commit before reply consumption.
- A persisted Workspace Trust decision is required before the server reads
  repository configuration. After that asynchronous read, the native helper
  rechecks the held connection and named endpoint before a one-use dispatch cut.
  The trust record is selected by the canonical request path without reopening
  the directory, so an already committed request can replay after that path
  disappears; a new admission still performs no-follow capture and refuses it.
- Validation: native probe, focused control/state tests, design-copy guard,
  `npm run build`, and the 1,623-test full suite passed on macOS after the
  replay-path refinement. Linux runtime,
  installed I1, complete public methods and six-package qualification remain open.
- The first branch CI run qualified the existing Linux namespace/cgroup probe.
  Its four Node/macOS/Linux matrix jobs found an asynchronous `EPIPE` when the
  native listener exited after endpoint drift, and Linux also produced an
  expected client `ECONNRESET`. The listener now handles the pipe error on its
  fail-closed path, and the drift tests accept the connection reset. Branch CI
  for `115cd8a` passed the Linux strong probe and all four Node/macOS/Linux
  matrix jobs.
- Recovery closure reads now use a fixed eight-worker mapper, and each
  `ArtifactCatalog` limits actual CAS reads across concurrent callers to eight.
  Focused tests cover pending-work bounds, result order, failure drain and
  release of a failed read slot. A second `npm run build` and the 1,626-test full
  suite pass on macOS with these changes. Scale and latency qualification are
  still open.
- The hidden control service now rejects noncanonical `session.create` name and
  workspace spellings before digest/replay comparison. A same-ID non-NFC then
  NFC request test proves the rejected spelling did not consume the ID.
- Added owner-gated `session.get` with one SQLite snapshot, exclusive item
  cursor, captured high-water, a 1 MiB metadata cap, and a current UDS peer
  recheck. Focused tests cover empty pages, pagination across a later append,
  foreign principal, future cursors, unknown/forged wire fields, and a missing
  item before high-water. The 1,627-test full suite and build pass on macOS;
  four-platform CI for that commit is in progress.
- Added an owner-gated hidden `run.attach` read cut with retained event bounds,
  strict typed event parsing, and a snapshot-bearing expired-cursor result.
  Focused tests cover a later appended progress event, a caught-up empty page,
  principal isolation, malformed retained event and expiry reset. A same-UID
  UDS test reads a real queued StateStore Run admitted with the explicitly
  labeled M2 placeholder source/assembly fixture; that is query integration,
  not strong execution or real Run-admission qualification. The 1,628-test
  full suite and build pass on macOS. Public
  protocol/error generation and the remaining Run methods are still open.
- `npm pack --dry-run` lists 243 files and no `dist/native` helper; installed
  native delivery remains a WP06 gate. A local macOS Developer ID Application
  identity for the expected team signed the pinned probe successfully after a
  transient timestamp-service failure. The unnotarized local build was rejected
  by `spctl` and `test:sandbox-probe:macos` with
  `UNSUPPORTED_EXECUTION_IDENTITY`, as required. A second, timestamped build was
  accepted by Apple notarization, stapled, and accepted by `spctl`. On macOS
  26.5.2/arm64, the actual VM probe returned `authorityReady=true`, including
  source/state/home denial, direct-network denial, authenticated guest boot,
  descendant enumeration, empty forced termination, and no writable host share.
  The probe manifest digest was
  `fa04dd9e4ab39481794797d21ac3d9e62be6ad13de8a9b8b33353a6873efa9a3`;
  the signed helper digest was
  `4246949b17a335e8be3d3b4736ac060db71bb2505d96d74d5554481b83f69957`.
  This qualifies that local probe asset, not an installed worker/private
  generation or the I1 restart scenario. The probe build's fixed-offset
  extraction now uses byte-offset `tail` rather than `dd bs=1`; the extracted
  kernel rehashed to the pinned SHA-256 before and after the change.
- RuntimeBundle signature verification now also checks the closed, byte-sorted
  structured-root index, required role mapping, guest-root refs, and the exact
  unique signed `bundle_object` entry/path for each distinct member ref. Tests
  re-sign malformed bundles so failures prove structural validation rather
  than a rejected signature. Complete structured-root decoding, secure
  installed-file import, version selection, and rollback remain WP06 work.
- Added a fail-closed structured-payload verifier over supplied, rehashed signed
  entry bytes. It decodes the fixed policy profile, system prompt, compaction
  envelope and its three ModelText members, and bundled skill closure/files;
  it independently checks complete-byte refs, semantic digests, exact member
  sets and canonical JSON. Unsupported guest-toolchain, MCP-recovery, and
  portable-schema roots reject until their decoders exist. This is an internal
  decoder, not a descriptor-safe package installer or activation proof.
- Added owner-gated hidden `run.get`: it captures Run, item/Journal sequence
  high-waters and the latest Checkpoint in one SQLite read cut, validates exact
  retained Checkpoint cursors, and pages three independent streams under the
  combined 1 MiB canonical metadata limit in item/Journal/Checkpoint order.
  The UDS handler rechecks the held connection and rejects caller authority
  fields. Focused tests cover cursor round trips, later item append, principal
  isolation, and byte-cap truncation; they still use the explicitly labelled
  M2 placeholder assembly for Run admission, not an I1 production Run.
- Added a byte-exact signed RuntimeBundle manifest decoder and combined
  manifest/structured-payload gate. It rejects noncanonical JSON/UTF-8,
  untrusted or changed signatures, and missing/wrong structured root bytes;
  it returns the complete signed-manifest ArtifactRef separately from the
  self-omitting manifest digest. The verified graph is frozen in memory.
  Complete remaining kind decoders, installed CAS graph rooting, immutable
  install directory and active-selection protocol remain open.
- The [I1 release-trust decision](release-trust-decision.md) records the
  missing production Ed25519 root/key custody. npm can remain the sole required
  public distribution channel; the installed path still needs platform payloads,
  protected signing and clean-install qualification. The existing npm publish
  token, test signatures and notarized probe do not fill that gap.
- Signed RuntimeBundle entry paths now reject non-NFC spellings, NUL,
  traversal/empty components, and paths or components too long for the native
  descriptor-relative reader. Re-signed malformed-manifest tests enforce the
  check independently of signature failure; runtime activation remains open.
- Added a native, descriptor-held source-package reader on Linux and macOS.
  Its helper requires a bootstrap-supplied complete-byte digest, and the fixed
  `runtime-bundle.json` entry is read with a native size bound before any signed
  path is selected. Each entry is opened no-follow beneath the held package
  root, streamed in bounded chunks, rehashed and checked for stable metadata
  and locator identity. A preflight now checks the signed manifest, supported
  structured payloads and every declared entry. It does not publish bytes to
  CAS or make them executable; a real installer must independently copy and
  verify staged bytes before activation. The test suite injects a fixture
  helper digest and fixture release key, neither of which is a production
  bootstrap authority.
- Added a descriptor-held CAS writer for signed package entries. It stages
  bounded chunks in an owner-only 0700 CAS root, seals and fsyncs a 0400 file,
  rehashes the staged bytes, publishes by same-directory hard link and fsync,
  and reopens the final object to verify its complete digest. A matching
  existing object is independently verified; corrupt objects and replaced
  roots/staging names fail closed. The package importer copies the fixed
  manifest and every signed entry, then rechecks supported structured roots
  from the imported CAS bytes. Tests cover multi-chunk import, idempotent
  reimport, partial failure cleanup and path substitution. These CAS objects
  are unselected: no immutable bundle directory, active selection, installed
  bootstrap, service registration or production release key exists yet.
- Bound complete package import to the actual signed StateStore owner. Its
  package-reader helper must match the owner's signed entry digest and byte
  count, and the held package manifest must equal the owner's complete signed
  bundle ref before any CAS write. The owner waits for an in-flight import
  before releasing its OS lock. A real-store test imports a signed fixture,
  reopens the owner and reads the imported object, rejects concurrent imports,
  and proves a second valid signed manifest cannot be imported under the first
  owner's authority. The imported objects remain unselected; no installed
  bootstrap or activation is implied by this test.
- Proved the proposed Supervisor image shape with a Node 24 SEA fixture on
  macOS: a bundled entry runs from the executable image, embeds its disposable
  release public key, and ignores injected `NODE_OPTIONS`. The final ad-hoc
  signed image and native helpers enter a test-key-signed RuntimeBundle. The
  actual SEA process verifies that manifest, takes StateOwner, imports all
  signed package bytes to CAS, exits, and a second SEA process reopens the
  owner and reads the retained policy object. Each process starts the signed
  native UDS listener and completes an authenticated `control.hello` on its
  owner epoch. The complete executable digest and advancing owner epoch are
  checked; a manifest signed by an unrelated key is rejected before
  StateRoot mutation. The same fixture has a Linux/macOS Node 24 CI gate.
  Source-mode helpers resolve under `dist`; SEA helpers resolve beside the
  image. This is an ephemeral packaging/integration fixture, not a production
  signature or I1 completion.
- A macOS SEA UDS smoke test exposed the `sockaddr_un.sun_path` bound when the
  temporary StateRoot was too deep. The native listener now rejects an
  oversized literal path before spawning its child, and the fixture uses a
  short real temporary root. Signed StateStore opening now runs the same
  preflight before native acquisition or first StateRoot genesis. The stable
  bootstrap must invoke this check before staging a candidate as well.
- Added read-only installed-selection inspection to WP06. A pinned native
  reader opens `runtime/active.json` as a same-owner 0400 regular file under a
  held 0700 runtime descriptor, parses its exact canonical schema, opens the
  digest-named installed bundle through no-follow descriptors, inventories
  every file and directory, verifies the release signature, structured graph
  and all declared bytes, then rereads the selection. Tests reject unsigned
  files/empty directories, writable contents/root, untrusted signatures,
  noncanonical selection and a symlinked active file. The tests construct the
  installed directory fixture directly; no native installer, atomic selection
  writer, service handoff or production release key exists yet.
- Extended the Node 24 SEA gate: after owner-scoped CAS import, the fixture
  constructs a read-only, digest-named installed tree and test selection,
  launches the copied signed SEA from that tree, verifies its exact selection,
  reopens StateOwner and completes another authenticated UDS hello. This
  exercises the selected-image read path on macOS locally; Linux CI remains
  to be checked for this revision. The fixture's setup does not implement
  descriptor-safe staging, fsynced publication, update compatibility or a
  production installer.
- The first Linux Node 24 CI run of the selected-tree fixture exposed a native
  addon loader collision: after package-reader verification, `dlopen` could
  reuse the same `/proc/self/fd/N` spelling for StateOwner and return the first
  addon's exports. Both pinned addon loaders now retain their verified file
  descriptors for the process lifetime, keeping those loader identities
  distinct. A same-process dual-addon test and the macOS SEA gate pass. Exact
  `ab6516e` CI passed the Linux strong probe and all four Node/macOS/Linux
  matrix jobs, including the prior failing Linux Node 24 installed SEA test.
- Added a pinned-native candidate stage primitive. It accepts a fresh empty
  same-owner 0700 directory; the SEA fixture places it outside StateRoot. It
  copies the manifest and signed entries from held source descriptors through
  descriptor-relative destination operations, refuses symlinks/path
  substitution/duplicate files, seals files
  to 0400/0500, fsyncs them and their directories, and independently verifies
  the final 0500 tree against the signed inventory and structured graph.
  The Node 24 SEA fixture now starts its initial StateOwner import from this
  staged candidate before its test-only publication and selection. macOS
  requires the root directory to be temporarily writable for the fixture's
  cross-directory rename; the fixture reseals it. A native no-replace
  publication protocol, active-selection writer, candidate health,
  compatibility inspection, service handoff and production release key remain
  open. This staging primitive alone is not an installed release qualification.
- The next exact-head Linux Node 24 CI run rejected the test fixture's direct
  cross-parent rename of a sealed 0500 candidate, matching macOS. Publication
  now uses a pinned-native no-replace rename: it verifies the sealed candidate
  again, briefly makes its root writable within one native call, checks held
  source/destination descriptors and same-device identity, moves to the
  digest-named unselected bundle location, re-seals and fsyncs the tree and
  parents, then independently rehashes and inventories the published tree.
  A conflicting destination leaves the candidate and selected runtime
  untouched. The SEA fixture exercises this path after StateOwner import and
  release; it still writes `active.json` directly for test setup. The actual
  selection writer, candidate health/compatibility, service transition and
  release qualification remain open.
- An activation-path audit found a separate StateOwner transition gap:
  `acquireOrBootstrapStateOwner` presently requires the next signed Supervisor
  to have the prior owner's exact RuntimeBundle and executable identity, and
  `acquireSuccessorStateOwner` copies those prior fields into its new row. A
  correctly published candidate therefore still cannot become authoritative.
  WP01/WP06 must add a durable, owner-authored handoff intent with exact old/new
  bundle and selection identities, candidate self-test and compatibility
  evidence, admission fence, and rollback eligibility. Only a graceful prior
  release may authorize an image change; death takeover keeps the prior bundle.
  Selection, successor acquisition/health and rollback must be ordered under
  the stable bootstrap's single service-transition authority. Until that path
  exists, this branch does not write `active.json` outside the SEA fixture.
- The first-install selection filesystem cut now has a pinned-native,
  no-replace writer. It independently verifies the complete signed published
  tree, writes exact canonical selection bytes into an owner-only temporary
  regular file, seals and fsyncs it, atomically publishes `active.json` only
  when absent, fsyncs the directory, and reopens the selected signed tree.
  Read-only inspection handles do not expose this write capability.
  The SEA fixture uses this writer after its initial owner import and release.
  Duplicate selections and symlink targets fail closed. This is a filesystem
  primitive: the production installer must still prove that the released
  StateOwner imported this exact bundle and hold the stable service-transition
  lock. It cannot update a selected bundle or replace the missing handoff.
- WP01 filesystem identity preserves device and file ids as canonical
  unsigned-decimal strings. The shared BigInt formatter rejects unsafe number
  inputs, and the current native reader emits decimal ids directly from
  `stat`, without routing them through JS numbers. This addresses precision;
  source-tree capture and a descriptor-relative workspace walk are still
  required before public `run.submit` can use this identity as execution
  authority.
- Session identity capture and Run admission recapture now call the held
  StateOwner native helper for a component-wise no-follow root open and
  literal descriptor-relative `.git/config` read. It observes same-user
  root/Git inode identities without converting 64-bit ids through JS numbers,
  rejects linked, symlinked, oversized, changed or invalid-UTF-8 Git config,
  checks the actual `.git`/`config` entry spelling on case-insensitive volumes,
  and binds `extensions.objectformat` to the RepositoryIdentity. Replaced roots
  and Git directories fail before Run admission; Session and Run also recheck
  this identity inside their final SQLite transaction after asynchronous CAS
  publication, with swap fault tests proving no authority row commits. This is
  a read-only identity observation. Complete source-tree traversal, the safe
  Git-config profile, Git object closure and private generation remain open.
- WP01 Run admission now decodes the persisted live WorkspaceIdentity and its
  referenced RepositoryIdentity as closed, self-rehashed shapes. It checks
  canonical paths and unsigned 64-bit filesystem ids, requires paired Git
  reference/digest fields, and binds repository platform, owner and digest to
  the Session before recapturing the live root. Focused tests include a Git
  Session-to-queued-Run admission with an explicitly synthesized empty Git
  source fixture and rehashed malformed identity cases. This does not supply
  the descriptor-held source/index capture or full GitIndexSnapshot decoder
  required for production `run.submit`.
- The shared WorkspaceEntryManifest decoder now follows the RFC's exact tree
  projection: the digest covers schema, format and entries; entry and byte
  counts are independently checked, including symlink UTF-8 bytes. It also
  rejects noncanonical root-relative paths, `.git` entries, escaped symlinks,
  invalid file/directory/symlink modes and mismatched symlink target digests. Existing
  M1/M2 fixtures were regenerated with the corrected tree digest. Admission
  and recovery now also read every distinct complete CAS file blob through a
  bounded mapper and reject a declared size mismatch; a real-store test proves
  a failed size check commits no Run and a corrected source can then admit and
  recover. Full descriptor-held source capture and Git object closure remain
  separate work.
- Git SourceManifest readback now rejects rehashed extension fields and malformed
  HEAD forms. Admission and recovery rehash the retained RepositoryIdentity and
  `GitIndexSnapshotV1`, bind its repository identity and SHA-1/SHA-256 object
  format, reconstruct the fixed zero-stat/no-extension Git index v2 bytes, and
  recompute its tree object id. Tests compare canonical bytes and tree ids with
  independently produced Git indexes in both object formats, reject a bad
  tree before Run admission, and read a valid Git Run recovery closure. The
  descriptor-held source-index acquisition, referenced Git object existence
  and pack closure, and private Git generation are still required for
  production Git execution.
- A pure source-index parser now checks the full-file v2/v3/v4 checksum,
  stage/mode/extended flags, canonical paths, v4 prefix compression and
  extension framing before emitting the exact zero-stat v2
  index and `GitIndexSnapshotV1`. Tests compare real Git v4 bytes and known
  SHA-1/SHA-256 images. A held StateOwner reader now streams only the literal
  `.git/index` under the recorded workspace and Git directory descriptors. It
  rejects hardlinked or symlinked indexes and changes to the root, Git directory
  or file during reading; a real Git index is read and parsed in a focused test.
  A high-level read now checks the repository digest, root/Git/config stability,
  complete bytes, and a 64 MiB raw and expanded index ceiling before returning
  the normalized snapshot. A newly initialized repository with a twice-checked,
  descriptor-proven absent literal index yields the canonical empty v2 index;
  an alias or a newly appearing index is rejected. CAS publication, referenced
  object existence, pack closure and atomic Run integration remain open.
- FrozenIgnoreRules and SourceProjection now reject rehashed extension fields,
  malformed root-relative selectors, duplicate selectors, widened result
  ceilings, non-Git ignore sources, unordered Git ignore sources/rules, and
  source content refs whose digest differs from the retained CAS ref. Run
  admission and recovery bind the ignore graph to the exact live/retained
  repository identity and read every distinct ignore file as valid UTF-8
  without NUL. This is
  schema and raw-byte closure only. The fixed Git wildmatch matcher, selector
  authorization/classification evidence, and descriptor-held source capture
  remain prerequisites for public `run.submit` and I1.
- WP01 source entry decoding now requires every nested entry to have a preceding
  directory parent. Run admission checks that the rehashed base SourceManifest
  names the exact decoded entry tree before committing its first Checkpoint;
  mismatched trees and missing or non-directory parents are rejected even when
  each artifact has an internally valid digest. This closes an admission-time
  cross-artifact gap; trusted descriptor-held source capture remains open.
- The held StateOwner native helper now opens ordinary regular source files
  through literal, no-follow workspace components anchored to the recorded
  root device/inode/owner. It exposes bounded chunk reads and a complete-read
  stability check over held root, parent and file descriptors; closing or
  replacing the owner/root/file invalidates the handle. Git metadata aliases,
  symlinks and special files are rejected, while source hardlinks remain valid.
  Complete directory traversal, symlink-entry capture, frozen ignore
  classification, CAS streaming publication and a full second tree walk remain
  required before this primitive can produce a SourceManifest.
- The same held helper now enumerates one literal source directory at a time
  under the recorded root. It rejects non-UTF-8 names, symlinked directory
  components, foreign-owner or cross-device entries, special files and
  directory changes during the scan; the TypeScript boundary requires NFC
  names. The caller still has to build the complete bounded tree, apply the
  frozen projection and publish every accepted byte into CAS.
- The held helper now reads one source symlink's raw UTF-8 target from its
  literal parent without following it, checking the link, parent, root and
  owner lock before returning. The TypeScript boundary rejects absolute,
  noncanonical, lexically escaping and Git-metadata targets. Entry-manifest
  decoding also rejects represented link chains that escape or cycle. The
  shared source-selector and Git-index path decoders reject case variants of
  `.git` as well as raw components hidden by path normalization. These checks
  do not yet validate links through every excluded or changing source entry;
  complete tree capture, projection and a second descriptor walk remain open.
- The strict `SanitizedGitConfigV1` parser/decoder accepts only the RFC's
  non-executable core fields and object-format extension from held UTF-8 bytes
  of at most 1 MiB. It rejects includes, hooks, helpers, remote/config paths,
  duplicate keys and ambiguous Git syntax, and rehashes a closed artifact. A
  held-workspace reader binds those bytes to the Session's root and Git
  descriptor identities and object format. It is not yet connected to Run
  source publication, private Git materialization or the recovery closure.
- Admission and recovery now reparse each retained `.git/info/exclude` and
  `.gitignore` source into the exact ordered `FrozenIgnoreRuleV1` array before
  trusting it. The pinned Git 2.45 line parser handles BOM, CRLF, comments,
  unescaped trailing spaces, negation, directory and slash anchoring, and
  unterminated final lines; a rehashed but forged rule array fails. Descriptor-
  held ignore-source capture and complete source projection remain open.
- A pure UTF-8 byte NFA now evaluates the fixed case-sensitive Git 2.45
  wildmatch profile, including component globstars, classes, escaped bytes,
  ancestor-base rule order and the ignored-parent negation limit. It does not
  invoke ambient Git or use regex backtracking. During development it matched
  a compiled Git v2.45.0 helper on 366 [upstream wildmatch test](https://github.com/git/git/blob/v2.45.0/t/t3070-wildmatch.sh) comparisons, 35,918
  generated pattern/path comparisons and 234 Unicode comparisons; a separate
  960-case comparison with Git v2.45.0 `check-ignore` agreed on parent and
  nested-source decisions. Repository tests retain focused regression cases.
  Descriptor-held ignore-source capture, hard-exclusion and tracked-entry
  classification, projection publication and public `run.submit` remain open.

## 2026-09-27: held source metadata and include admission

- The trusted source readers now publish the canonical Git index snapshot and
  frozen `.git/info/exclude`/`.gitignore` rule graph from held no-follow
  descriptors, then recheck their live sources. Native file, directory and
  symlink observations expose link counts from the same descriptor/stat cut;
  an inserted hardlink between `.gitignore` scans is rejected. Branch CI for
  `5781efb` passed the Linux namespace/cgroup job and all four macOS/Linux
  Node 22/24 jobs.
- Added closed `SourceIncludeClassificationEvidenceV1` and
  `SourceIncludeAuthorizationV1` decoders. Builtin include admission now checks
  the selector, principal/Run/Session/workspace/intent bindings, exact captured
  entry digests, frozen ignore classification, and canonical Git-index tracking.
  It opens each included path again under held no-follow descriptors, rehashes
  file bytes or verifies symlink targets, and repeats the live check inside the
  final SQLite transaction. A mutation after CAS publication leaves no Run.
- The internal admission intent now binds requested include/exclude selectors
  instead of the Supervisor-generated source projection and manifest refs;
  this removes the include-authorization digest cycle and lets identical
  requests replay the original Run after the live source changes. The
  recovered root Run revalidates the retained builtin include graph. An
  ignored include's consumed read grant remains deliberately unsupported
  until grant consumption and the Run transaction are one atomic operation.
  Tests use an explicitly synthesized source graph; there is still no
  production complete-tree capture or public `run.submit` path.
- Local `npm run build`, all 1,711 tests, and the design-copy contract check
  passed for this source-include slice. The full test run followed recovery
  closure integration; a subsequent test-only fixture cleanup passed its
  focused build and four tests.
- Complete CAS blob verification now hashes fixed 1 MiB chunks, and
  WorkspaceEntryManifest file validation uses that bounded verifier rather
  than allocating an entire retained file. Read, stat, verify and publication
  also recheck the named CAS root after the held operation; a root-swap test
  proves verification fails closed. Source-file publication into CAS is still
  not wired to a complete source-tree capture.
- The native StateOwner source-file handle now permits rewind only after a
  complete stable read. One held descriptor can hash a source file, rewind,
  and stream the same file into the pinned native CAS writer in 1 MiB chunks.
  The writer rehashes the sealed stage and final artifact, and checks source
  stability again before and after publication. A staged-publication race test
  proves that changed source bytes leave no CAS temporary object. The source
  tree walk, Git object closure, and admission integration remain open. The
  local build, 17 focused native/source tests, and full 1715-test suite pass.
- A higher-level source-file capture now binds that CAS blob to the exact
  literal directory entry observed before opening and after publication. It
  checks descriptor identity, mode, size and link count at both cuts, returns
  normalized WorkspaceEntry metadata plus the retained source observation,
  and refuses a replacement before opening or after CAS publication. This is
  one file's capture primitive; source selection, complete tree traversal and
  the final admission-transaction live recheck remain open. The local build,
  focused source-file suite, and 1716-test full suite pass on macOS.

## Next integration order

1. Qualify the native control endpoint/connection lifetime and approved live
   authentication contract on Linux and macOS CI; extend the closed public
   methods only as their actual admission/recovery paths become ready.
2. Complete WP02 Supervisor-generated assembly and WP01 source capture, then
   WP03 containment/private-generation evidence and WP06 installed bootstrap
   for the I1 restart scenario. Use actual StateStore throughout.
3. Implement WP05 candidate, verifier receipt, result and delivery transitions
   against the same real store, then complete I2 with a qualified provider.
4. Finish the I3 behavior and fault matrix across all six owners.
5. Execute I4 installed-platform, migration/rollback, scale, repair-usefulness
   and release campaigns. Cut over only after every mandatory gate passes.

The early `cliq/durable-kernel-foundation` branch in the main repository remains
untouched. No signing/notarization submission, paid model call, production
migration, public release or remote merge has been performed by this work.
