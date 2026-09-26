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
  fail-closed path, and the drift tests accept the connection reset. Cross-
  platform verification of that fix is pending the next branch CI run.
- Recovery closure reads now use a fixed eight-worker mapper, and each
  `ArtifactCatalog` limits actual CAS reads across concurrent callers to eight.
  Focused tests cover pending-work bounds, result order, failure drain and
  release of a failed read slot. A second `npm run build` and the 1,626-test full
  suite pass on macOS with these changes. Scale and latency qualification are
  still open.

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
