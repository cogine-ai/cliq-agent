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
