# Local control identity: filesystem endpoints and connection authority

**Status:** Accepted — option A, local UID and continuously held connection authority.
**Date:** 2026-09-26
**Baseline:** `8029659f5f4b18709cc932b881dcf90c509fd44b`
**Affected owners:** WP01, WP03, WP04, WP06.
**Supersedes:** The UDS peer-observation and authentication paragraphs of the
2026-08-11 Kernel RFC and corresponding WP01/WP03/WP04/WP06 criteria.

## 1. Why this decision is required now

The first installed/restart integration checkpoint requires authenticated UDS
control. The August RFC's `LocalSocketPeerObservationV1` and WP04's corresponding
acceptance criterion conflate two different OS objects: the filesystem socket
entry and the live listening socket descriptor. They also claim that two peer
credential samples surrounding a process lookup reject PID reuse.

Native macOS experiments contradict the first requirement. Kernel source and
documented credential semantics do not establish the second guarantee. These
are control-authority contracts, so replacing a failed check with a successful
constant or silently weakening it in the implementation is unacceptable.

The current branch has a hidden, signed-bundle-gated StateStore UDS path for
`control.hello` and `session.create`. It does not qualify an installed Kernel or
enable the public control surface.

## 2. Reproducible evidence

Run from this checkout on macOS or Linux with a C compiler:

```sh
node scripts/kernel/probe-control-socket-identity.mjs
node --test --import tsx src/control/socket-identity-probe.test.ts
```

The probe compiles a disposable C program, creates a private temporary parent,
binds only a local Unix stream socket, observes real descriptors and OS peer
credentials, replaces its own endpoint, and removes its temporary files. It
does not open the user's StateRoot, use credentials, send network traffic, or
provide production authority.

Observed on macOS arm64, Darwin 25.5.0:

| Observation | Filesystem endpoint | Listening descriptor |
| --- | --- | --- |
| Permission bits | `0600` | `0666` |
| Device identity | Real filesystem device | `NODEV`, represented as unsigned `4294967295` |
| Inode/file identity | Filesystem entry inode | Different kernel socket identity |
| Descriptor permission change | Not applicable | `fchmod(fd, 0600)` fails with `EINVAL` |
| Open endpoint through held parent | `openat(..., O_EVTONLY \| O_NOFOLLOW)` fails with `EOPNOTSUPP` | Already held socket |

Replacing the endpoint changes the filesystem identity while the original
listening descriptor retains its identity. Therefore checking one identity
cannot replace checking the other. Raw numeric inode values are deliberately
not fixed expectations; they vary between executions.

This is a macOS runtime observation. The probe also builds for Linux, but a
Linux run has not yet been performed in this task. Linux results must be
recorded independently; compilation or source inspection is insufficient.

Apple's [fchmod documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fchmod.2.html)
documents the socket-descriptor error. Linux's
[Unix socket documentation](https://man7.org/linux/man-pages/man7/unix.7.html)
separately describes pathname ownership/permissions and connection peer
credentials. Its `SO_PEERCRED` tuple is captured at connection/listen time;
repeating that call does not refresh the peer's process identity.

### PID reuse is a separate proof gap

A cached peer PID plus a current process lookup does not establish that the
current occupant of that PID created the connection. Reading the same cached
credentials again cannot close that gap. This is a source-derived counterexample,
not a claim that a PID-reuse exploit was reproduced on this machine.

Apple's [XNU peer-option implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_usrreq.c)
also makes `LOCAL_PEERTOKEN` unsuitable as an assumed repair: that branch looks
up the stored numeric PID before obtaining an audit token. A token obtained
that way must not be represented as a connect-time frozen process reference.
Linux's [SO_PEERPIDFD implementation](https://github.com/torvalds/linux/blob/v6.6/net/core/sock.c#L1673)
uses the socket's original kernel process reference. This is different from
calling `pidfd_open` with the cached numeric PID. Its availability and the
minimum supported kernel need explicit qualification.

The August RFC additionally describes every `PlatformProcessIdentityV1` image
digest as matching the selected signed Supervisor entry, although its UDS branch
uses the same type for a client process. The generic observation and the
Supervisor-specific signed-image check must have separate, explicit meanings.

## 3. Decision

### A. Authorize the local user and the live connection — accepted

Keep the existing per-user UDS architecture. Authenticate the connection's
native peer UID against the held StateRoot owner. Bind each request to an opaque,
live accepted-connection capability and a fresh Supervisor channel nonce.
The capability is scoped to the current StateOwner and revoked at connection
close, owner loss or endpoint drift. Neither caller JSON nor retained artifact
bytes can manufacture it.

PID, process start and executable observations are optional diagnostics. They
cannot authorize a request, establish signed-client identity, claim protection
against PID reuse, or serve as containment/StateOwner death evidence. Supervisor
ownership and sandbox evidence keep their existing stronger process contracts.

This explicitly trusts the authorized local user, not a particular client
executable. Another application under the same UID is not distinguished by
this control layer. An intentionally transferred connected descriptor is a
delegated capability; this option does not promise per-frame sender identity.
Productive sandbox processes still receive no control descriptor, StateRoot
mount or ability to connect to the host control endpoint.

This matches the current single-user scope and avoids creating an unsupported
client-binary attestation guarantee. The project owner accepted this contract
on 2026-09-26 for the six-package implementation.

### B. Require exact OS-authenticated sending-process identity — declined for this cut

Keep the stronger process-origin guarantee and select transports/primitives
that can actually establish it. Investigate Linux peer pidfds and a macOS
Mach/XPC message audit-token path rather than deriving a token from a numeric
PID lookup. This may change the supported Linux kernel floor and the macOS
transport, client packaging and tests.

Apple documents [message-based XPC client validation](https://developer.apple.com/forums/thread/681053).
A one-time Mach handshake followed by arbitrary UDS messages would still not
prove each message's writer: a connected descriptor can subsequently be
transferred. This option must distinguish original-peer lifetime from per-message
sender identity before selecting a primitive on either platform.

This is an alternative requiring its own qualification, not an implemented or
verified solution. It broadens WP03/WP04/WP06 and delays I1. Choose it if
distinguishing client processes under one UID is a real product requirement.

### Rejected shortcuts

- Treating socket `fstat` identity as the filesystem endpoint identity.
- Reporting `0600` from a constant after observing a different descriptor mode.
- Reopening a socket pathname and claiming a retained descriptor on macOS.
- Treating repeated credentials or `LOCAL_PEERTOKEN` as PID-reuse proof.
- Granting authority from a stored channel artifact without a live capability.
- Adding TCP, an embedded runtime fallback, or a weaker execution sandbox.

## 4. Normative contract for option A

Introduce a separately versioned peer observation, rather than silently changing
the meaning of previously serialized v1 fields. `LocalSocketPeerObservationV1`
is never produced by the live transport; retained V1 bytes, if encountered,
are historical evidence only and cannot authorize a request. The closed V2
schema contains:

| Part | Source and required checks |
| --- | --- |
| StateRoot pair | Existing held root identity and current StateOwner authority |
| Endpoint identity | Literal `runtime/control-v1.sock`, held-parent no-follow `fstatat`, Unix socket entry, real device/inode, owner UID, mode `0600` |
| Listener socket identity | `fstat` of the continuously held listener plus native `AF_UNIX`/`SOCK_STREAM` checks; no filesystem-mode claim |
| Accepted socket identity | `fstat` and native type checks on the continuously held accepted socket |
| Peer credentials | Platform-discriminated native API, observed UID/GID, matching StateRoot owner; no PID field or caller identity fields |
| Observation closure | Canonical time and omission digest; fresh channel nonce remains in the channel identity |

The accepted socket's continuously held native handle, owner epoch, and channel
nonce comprise a runtime-only capability. Its handle is not serialized,
reconstructed from an inode, or accepted as a caller argument. The authority
checks immediately before dispatch require that handle to remain live, the
listener and named endpoint to retain their own checked identities, and the
StateOwner epoch to remain current. A channel artifact alone is never a grant.

Descriptor device/inode fields are observations, not serializable capabilities.
Their validity ends with the owned native handle; an equal tuple obtained later
cannot recreate authentication. Namespace observations likewise cannot promise
atomic exclusion of arbitrary renames by another unisolated process of the same
trusted user.

The native module owns descriptors, bind/accept, no-follow parent observations,
type/credential checks, and cleanup. Startup refuses an existing endpoint unless
the normal StateOwner recovery path proves that it is safe to retire. It never
unlinks an unfamiliar or replaced node. Binding and cleanup races require real
fault tests; the table alone is not evidence that they are solved.

The application uses a small owner-scoped interface, conceptually:

```ts
await store.serveLocalControl({ dispatch: application.execute })
```

This is an interface sketch, not a new public API or generic mutation hook.
Application methods remain the RFC's closed typed methods. The implementation
owns connection handles; callers cannot pass raw file descriptors, arbitrary
listener paths, principal IDs, peer observations or authority context.

Live authentication happens before every dispatch, including replay lookup.
Existing reducers may return an old `control_requests` response before walking
that request's historical channel closure. That ordering is valid only after
the new request has passed live authentication. Equal replay retains the first
mutation's original provenance; it does not rewrite its historical channel to
the new connection.

Workspace Trust is evaluated before any repository config or context capture.
For a detached Supervisor, a persisted per-workspace trust decision is the
minimum noninteractive evidence; a caller field or inherited
`CLIQ_TRUST_WORKSPACE=trust` is not an automatic server-side grant. Async trust
reads precede a fresh native check of the still-held accepted descriptor and
named endpoint at the authentication cut. A disconnect or endpoint change while
the trust read is pending prevents dispatch.

There is one explicit request-authenticated cut after complete framing, hello
compatibility and live identity checks, before application/replay dispatch.
Before that cut, disconnect prevents execution. After that cut, the exact
authenticated request may complete its durable operation even if its response
cannot be delivered. It cannot authorize another request. Owner loss still
fences every authoritative write through the existing StateOwner checks.

Disconnect cannot roll back a committed mutation. Cancellation still requires
its own explicit control command. Request identity allows a later authenticated
connection to retrieve a committed response after reply loss. StateStore close
automatically stops accept/authentication, drains already authenticated calls,
closes transport resources, then gracefully releases ownership and the lock.

## 5. Acceptance before enabling UDS

1. Update the normative RFC and affected work packages together; update
   schema/bundle compatibility explicitly.
2. Closed decoders and CAS/recovery closure distinguish old artifacts, new peer
   observations and runtime-only live capabilities. No serialized capability.
3. Run native macOS and Linux tests for endpoint replacement, parent drift,
   unexpected existing paths, symlinks, mode/owner drift and descriptor closure.
4. Exercise real separate processes and rejected native peer identities; caller
   principal/PID/path fields never influence authentication.
   Confirm that an untrusted workspace never reaches `.git/config` or assembly
   capture, and that trust I/O races a fresh native connection recheck.
5. Prove owner loss and disconnect revoke future dispatch; no descriptor leaks,
   inherited control descriptors, or uncertain-node unlink on shutdown.
6. With real StateStore, prove authentication precedes replay, disconnect after
   commit replays exactly once, and cross-connection replay preserves provenance.
7. Explicitly test the selected policy for descriptor delegation and process
   identity. Do not label cached credentials as stronger evidence than they are.
8. Pass the installed I1 path on each supported platform before claiming the
   control transport or any work package complete.

## 6. Current implementation evidence

The native characterization and its regression test pass on the current Mac.
A signed-bundle-gated, hidden StateStore service now proves the native
endpoint/descriptor distinction and real same-user `control.hello` plus
`session.create` admission. Focused tests cover endpoint replacement, history
artifact rejection, a second native recheck after asynchronous Workspace Trust
I/O, replay after the admitted workspace path moves, and disconnect after
commit. It is a limited
integration path: public `run.submit`, full control methods, installed
bootstrap, Linux runtime evidence, containment and Kernel Cut remain open.
