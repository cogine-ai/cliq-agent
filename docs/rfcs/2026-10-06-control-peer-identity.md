# I1 control peer identity — accepted clarification

Status: **Accepted on 2026-10-06. Native listener/peer capture and internal
authenticated StateStore dispatch are implemented and tested on development
macOS. Public control routing, installed integration and Linux qualification
remain open; acceptance does not enable a public UDS control server.**

This clarification closes two platform ambiguities in the Durable Verified Run
Kernel RFC and records the StateRoot host-tampering boundary explicitly approved
on 2026-10-06. It adds no public method, changes no artifact shape, and leaves
Workspace Trust, Tool Permission and worker Sandbox guarantees unchanged.

## Why the clarification is necessary

An AF_UNIX listening transport descriptor and its bound filesystem entry are
different OS objects. On the development macOS machine, the descriptor's `fstat`
reported a synthetic device/inode and mode `0666`; the path's no-follow `lstat`
reported the actual filesystem device/inode and mode `0600`. Opening that socket
path with SDK `O_EVTONLY | O_NOFOLLOW` failed with `EOPNOTSUPP` (errno 102).
Linux also gives sockets a separate socketfs identity; see the kernel's
[`sock_alloc` implementation](https://github.com/torvalds/linux/blob/master/net/socket.c).
The two identities must not be asserted equal or substituted for one another.

Separately, a control peer usually runs a client executable rather than the
Supervisor executable. The general process-identity shape can describe both;
the consumer must enforce the applicable executable expectation.

## Accepted exact interpretation

- `LocalSocketPeerObservationV1.listener` records the bound filesystem entry at
  the literal `runtime/control-v1.sock`, observed by `fstatat` with
  `AT_SYMLINK_NOFOLLOW` relative to the still-held private runtime directory.
  Its socket type, owner, `0600` mode and device/inode must match the exact entry
  established by the native listener. No alternate path is accepted.
- The native module separately retains the actual listening transport descriptor
  and its initial `fstat` identity. It verifies AF_UNIX, SOCK_STREAM, listening
  state and the exact bound name. Root, runtime, bound entry and transport
  identity are rechecked before and after peer observation. Replacement or
  permission/type drift refuses the connection. Cleanup immediately rechecks
  the held private parent and exact no-follow socket type/mode/uid/device/file
  identity, retaining any replacement or drift already present at that check;
  the approved host-tampering boundary below applies.
- `acceptedSocket` remains the accepted transport descriptor's own `fstat`
  identity. That descriptor is held through frame authentication,
  independently of the filesystem-entry identity.
- Linux uses only `SO_PEERCRED`; macOS uses `getpeereid` plus `LOCAL_PEERPID`.
  Both native credential samples, process start/image observations, platform,
  principal uid and StateRoot must agree. No caller pid, descriptor, path, digest
  or JSON attestation can mint a live channel.
- `PlatformProcessIdentityV1` records the executable image of its native observed
  pid. A StateOwner/inspector consumer still requires the exact selected signed
  Supervisor entry. A UDS peer consumer binds the independently observed client
  image and must not mislabel it as the Supervisor image.
- Retained artifacts establish provenance only. Fresh UDS requests additionally
  require an opaque native live connection held under the current StateOwner.
  Historical reads do not require the old peer to remain alive. A fresh genuine
  channel may replay an old committed request without rewriting its provenance.
- Transport authentication and injected identity precede calling any state
  operation, including admission replay. Existing admission replay ordering
  inside StateStore remains unchanged.

The existing deterministic principal formula remains normative:
`H('cliq-local-principal-v1', stateRootIdentityDigest, platform, effectiveUid)`.
The caller cannot choose a principal or channel identity.

## Acceptance and integration

On real macOS and Linux, exercise cross-process connections, repeated native
credential capture, exact descriptor/path checks, peer death/image drift,
replacement/symlink/mode changes, closure substitution and connection close.
A self-consistent CAS fixture must still fail fresh authorization. Reconnection
replay returns the first committed response and retains its original channel.
No test fixture establishes platform qualification or installed I1 completion.

The canonical RFC's caller-identity and process-identity paragraphs and WP04's
native listener description now incorporate this interpretation. Artifact
shapes, public methods, billing and sandbox semantics are unchanged. The native
listener now owns the fixed socket and accepted descriptors. Internal dispatch
binds each asynchronous request scope to its exact owner, native connection and
injected identity; a retained or copied identity cannot borrow another active
scope. Actual child-process connections exercise SQLite/CAS Session admission,
reconnection replay and owner reopen without a wire-protocol simulation.

The native process start token is anchored at accept before handing the peer to
JavaScript; the first capture must match it rather than assigning a new token.
This closes delayed first-capture substitution after accept. The tests do not
force actual PID-number reuse or prove socket-to-process identity against reuse
before accept; that stronger native-platform qualification remains open. Repeated
numeric credential samples alone must not be presented as such proof.

Public generated-schema routing, signed installed composition, Linux native
qualification and the remaining I1 execution path are still required. These
development tests do not establish installed I1 completion.

### Approved StateRoot host-tampering boundary

On 2026-10-06, option A was explicitly approved: the StateRoot isolation boundary
excludes a malicious or uncooperative unsandboxed host process running as the
StateRoot owner uid that directly tampers with StateRoot entries outside the
Supervisor ownership/lock protocol. This is not blanket trust for same-uid
control callers. The exclusion does not apply to workers or their descendants,
different-uid actors, or socket-to-process identity/PID-ABA checks; Workspace
Trust, Tool Permission and worker Sandbox enforcement remain unchanged.

Automatic cleanup and stale-socket recovery remain enabled while holding the
StateOwner lock. Immediately before `unlinkat`, the implementation rechecks the
held private parent and exact no-follow socket type, mode, uid and device/file
identity, preserving any replacement or drift already present at that check.
Stale recovery additionally proves no live compatible Supervisor owns the entry.
All descriptor, credential, process start/image and authentication checks remain
mandatory; this decision neither accepts a drifted observation nor makes retained
JSON into fresh authority.

POSIX does not provide inode-conditional atomic pathname unlink. An excluded
same-uid host could still replace the entry between the final check and removal;
neither the implementation nor its regression tests claim atomic exclusion of
that race. The approved boundary resolves the former absolute cleanup wording,
not platform qualification: public routing, signed installed integration, Linux
qualification and the remaining I1 execution path stay open.
