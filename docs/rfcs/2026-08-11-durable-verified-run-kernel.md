# RFC: Durable Verified Run Kernel

**Status:** Final
**Date:** 2026-08-11
**Decision Type:** Architecture
**Implementation Status (2026-09-26, main `0f2fa146`):** Hidden M0/M1/M2 foundations, native StateOwner crash takeover, worker-loss fencing/quarantine primitives, and substantial WP02 typed continuation have landed. Supervisor/broker/verification/package integration and migration/rollback remain incomplete; the default CLI/TUI still uses the legacy runtime. See the [six-package design review](../kernel/2026-09-26-design-review.md) for current evidence and remaining boundaries. Kernel Cut has not passed.
**Audience:** Core maintainers, implementers, reviewers, and integration authors

> **Product promise:** **Delegate. Detach. Return to verified work.**
> **中文：**交出任务，离开终端，回来拿到经过验证的结果。

## 1. Decision

Cliq will become a code-first, local-first, provider-neutral delegation runtime built around one small kernel: the **Durable Verified Run Kernel**.

The kernel has four semantic control planes:

1. **Session** preserves human/agent context continuity.
2. **Run** is the sole mutable execution truth.
3. **Checkpoint** identifies an immutable, recoverable consistent cut.
4. **RunJournal** records nondeterministic or effectful facts that must never be guessed after a crash.

The operating-system-managed **Supervisor** hosts the control plane. A **RunWorkspace** is an isolated resource owned by one worker generation. A **Verifier** is a Run completion gate. None of those is an additional control plane.

This RFC rejects the following architectures:

- Session as both transcript and execution state.
- A background process that continues against the user's real workspace.
- A general Task aggregate, workflow graph, or distributed scheduler.
- Full event sourcing as the source of all current state.
- A generic transaction filesystem or universal `EffectPlan` abstraction.
- Free-text JSON action envelopes as the model/runtime control protocol.

The design is delivered as one **Kernel Cut**. The six implementation work packages may proceed in parallel, but the old execution path is not removed and the new path is not made default until every release gate in this RFC passes.

## 2. Meaning Of The Product Promise

### 2.1 Delegate

A submitted Run freezes an immutable `RunSpec` containing:

- the objective;
- the admitted Session context;
- the base workspace manifest;
- provider/model and tool capability assembly;
- policy, sandbox, and credential references;
- required verifier specification;
- time, token, cost, tool, repair, depth, and child-concurrency ceilings.

The caller delegates only after the Run has been durably admitted. A prompt stored in a terminal process is not delegation.

### 2.2 Detach

Client attachment is not Run state. Closing the CLI or TUI cannot cancel, pause, or orphan an accepted Run.

`cliq run --detach` may return success only after all of the following are durable:

1. the immutable `RunSpec`;
2. the admitted context and base workspace manifests;
3. the initial ready Checkpoint;
4. the queued Run row;
5. Supervisor ownership of the admission.

Process death, Supervisor restart, and machine reboot must either resume the same Run from a consistent state or leave it in an explicit waiting/recovery state. Cliq must never silently lose it.

### 2.3 Verified Work

`succeeded` means only:

> The immutable result was verified against the required checks frozen into the RunSpec.

It does not mean the result is universally correct. A Run with no required checks terminates as `completed_unverified`; that status is reserved for the absence of a required gate. A Run whose required checks remain failing after bounded repair terminates as `failed` with reason `verification_failed`. The model cannot set any of these terminal states directly.

Detached admission with no required verifier requires explicit interactive confirmation or `allowUnverified=true`; unattended callers cannot accidentally invoke the verified-work promise without a gate.

### 2.4 Self-Heal

Cliq provides two bounded forms of self-heal:

- **Infrastructure recovery:** reacquire a fenced lease, construct a new workspace generation, reconcile open invocations, and resume from a ready Checkpoint.
- **Agentic repair:** feed assertion diagnostics back to the same Run while its repair, token, cost, tool, and wall-time ceilings remain available.

An ambiguous opaque external effect is not repairable by guessing. It becomes `waiting(reconciliation)`.

## 3. Current-State Boundary

At the time of this decision, Cliq is not yet this system:

- `SessionCheckpoint` is a conversation-prefix bookmark with a Git ghost snapshot reference.
- non-Git workspace checkpoints are unavailable, and ghost objects can expire.
- `cliq resume` loads a Session rather than resuming a durable Run.
- Session state is stored by rewriting JSON documents.
- the runner consumes only the first native tool call and retains a free-text JSON fallback.
- Bash executes in the user's current workspace and inherits the Cliq process environment.
- stdio RPC owns at most one in-process active run and has no daemon lifecycle.
- the README correctly states that current Cliq is not a sandbox.

This RFC is normative for the Kernel Cut. Existing behavior and historical documents remain accurate descriptions of their releases until the cutover occurs.

Global canonical notation is exact. `JCS(x)` means RFC 8785 UTF-8 bytes after the enclosing schema has rejected unknown fields, normalized every protocol string to NFC where its type requires text normalization, and omitted absent optional members (an explicit `null` remains a value only where the schema permits it). Every `SHA-256(...)` digest field is 64 lower-case hexadecimal characters. Every deterministic identity written as `H(v1,...,vn)` means unpadded base64url of `SHA-256(JCS([v1,...,vn]))`; argument order and JSON type are significant, every argument named at the call site must be present, and no optional/implicit `undefined`, delimiter concatenation, platform encoding, or hex output is legal. If absence participates in an identity, the call site must explicitly specify a permitted `null` or a discriminated object. `ArtifactRef` is exactly the raw 64-character lower-case hexadecimal SHA-256 digest of the complete immutable artifact bytes under its declared format. It never carries a `sha256:` prefix, path, URI, algorithm tag, or upper-case character; runtime decoders accept only `^[0-9a-f]{64}$`. Work packages and generated fixtures import these definitions rather than redefining an encoder.

Durable time and local caller identity are equally canonical:

```ts
type ArtifactRef = string

type CanonicalTimeFenceV1 = {
  schemaVersion: 1
  format: 'cliq-canonical-time-fence-v1'
  stateOwnerEpoch: number
  lastAcceptedAt: string
  observedWallClockAt: string
  state: 'healthy' | 'clock_regressed'
  updatedAt: string
  fenceDigest: string
}

type LocalPrincipalIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-local-principal-identity-v1'
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  platform: 'macos' | 'linux'
  effectiveUid: number
  principalId: string
  identityDigest: string
}

type LocalSocketPeerObservationV1 = {
  schemaVersion: 1
  format: 'cliq-local-socket-peer-observation-v1'
  platform: 'macos' | 'linux'
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  listener: {
    canonicalRootRelativePath: 'runtime/control-v1.sock'
    fileType: 'unix_stream_socket'
    deviceId: string
    fileId: string
    ownerUid: number
    mode: 384
  }
  acceptedSocket: {
    socketType: 'SOCK_STREAM'
    deviceId: string
    fileId: string
  }
  credentialApi: 'macos_getpeereid_local_peerpid' | 'linux_so_peercred'
  peerUid: number
  peerGid: number
  peerPid: number
  peerProcessIdentityRef: ArtifactRef
  peerProcessIdentityDigest: string
  observedAt: string
  observationDigest: string
}

type LocalControlChannelIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-local-control-channel-identity-v1'
  principalIdentityRef: ArtifactRef
  principalIdentityDigest: string
  principalId: string
  client: 'cli' | 'tui' | 'jsonl' | 'rpc'
  transport:
    | {
        kind: 'in_process'
        processIdentityRef: ArtifactRef
        processIdentityDigest: string
      }
    | {
        kind: 'uds_peer'
        peerObservationRef: ArtifactRef
        peerObservationDigest: string
      }
  openedAt: string
  channelNonceDigest: string
  channelIdentityDigest: string
}
```

Every durable `*At`, deadline, expiry, and retry timestamp is exactly a valid UTC Gregorian instant encoded `YYYY-MM-DDTHH:mm:ss.sssZ`: four-digit year `1970..9999`, fixed separators and three decimal digits, no offset spelling, leap second, `24:00`, omitted fraction, or alternate normalization. Parsing produces one nonnegative safe-integer Unix millisecond; comparison and duration addition use only that integer with checked safe-integer arithmetic, then re-encode the same fixed form. A malformed/overflowing time is rejected before hashing or state access.

The state database has one `CanonicalTimeFenceV1` singleton under the StateOwner gate. A healthy authoritative transaction samples wall UTC, requires it not precede `lastAcceptedAt`, uses that sample as its sole `now`, and advances the fence in the same transaction; in-process deadlines additionally use a monotonic clock anchored to that accepted sample. Startup and every heartbeat/dispatch compare wall UTC to the retained high-water. If it regresses, one fenced transaction records `clock_regressed`; all new admission, lease renewal, capability/grant redemption, productive dispatch, retry, and authority expiry extension stop, and active external release gates are revoked/quiesced. Recovery may return to `healthy` only after wall UTC reaches/exceeds the retained high-water under a current owner epoch. It never rewrites an old timestamp or treats reboot/rollback as elapsed-time credit. Thus clock rollback can pause work but cannot prolong usable authority.

`LocalPrincipalIdentityV1.identityDigest` omits itself, and `principalId = H('cliq-local-principal-v1',stateRootIdentityDigest,platform,effectiveUid)`. The exact StateRoot owner uid must equal the trusted process effective uid. In-process CLI/TUI/JSONL derives it from the signed process identity. Caller JSON can never supply/override principal or channel fields.

RPC authentication produces one exact `LocalSocketPeerObservationV1` while the accepted socket descriptor is held open. Its `observationDigest` omits itself; the StateRoot pair rehashes exact `StateRootIdentityV1`; the listener is descriptor-opened at the literal root-relative path, is owned by that root uid, is mode `0600`, is a stream Unix socket, and its `deviceId/fileId` equal `fstat` on the still-open listener. The accepted descriptor is `SOCK_STREAM` and its `deviceId/fileId` equal its own `fstat`. Linux obtains the atomic `(pid,uid,gid)` tuple only from `getsockopt(SOL_SOCKET,SO_PEERCRED)`; macOS obtains uid/gid from `getpeereid` and pid from `getsockopt(SOL_LOCAL,LOCAL_PEERPID)`. The Supervisor captures exact `PlatformProcessIdentityV1` for that native pid, then repeats the credential calls before publication; both samples must be identical, process pid/owner uid must equal the peer tuple, process observation must not predate the accepted connection, and any unavailable API, exited/reused pid, uid mismatch, listener replacement, non-socket, or descriptor drift rejects/closes the connection. A caller-supplied pid/path/hash is never consulted.

Each accepted transport then publishes `LocalControlChannelIdentityV1`; its digest omits itself and its principal pair rehashes. The in-process branch rehashes the current signed process identity. The UDS branch rehashes the peer observation, requires its StateRoot/platform/peer uid to equal the principal identity, and remains bound to that exact still-open accepted descriptor until the request frame is authenticated. `openedAt` is canonical and not earlier than the observation; `channelNonceDigest` hashes 32 fresh Supervisor-generated bytes. Every persisted authority-bearing request, grant, consent, approval, abandonment, MCP risk, migration, and rollback carries the injected `channelIdentityRef/channelIdentityDigest` pair plus matching `principalId`; the ref closed-decodes this exact artifact and the semantic digest is recomputed. `control_requests` retains the pair for the channel that first committed the mutation. Same-request replay follows that retained control response even from a later authenticated channel without rewriting provenance; a new authority-bearing decision uses the new channel rather than copying a caller string.

## 4. Semantic Ownership

| Object | Answers | Mutable? | Must not contain |
|---|---|---:|---|
| Session | What continuity should the human and agent retain? | Append/compact/fork | lease, queue, pending invocation, workspace ownership |
| Run | What should the Supervisor do next? | Yes, revisioned | full historical truth or prompt payloads |
| Checkpoint | Which consistent context/workspace cut can be restored? | No | active lease, mutable budget, pending approval, invocation outcome |
| RunJournal | Which nondeterministic/effectful facts are known, failed, or ambiguous? | Append-only | scheduler state, prompt transcript, UI log stream |
| RunEvent | What should attached clients display? | Append-only, retainable | recovery or authorization truth |
| Artifact | Where are immutable large payloads and receipts stored? | No | current scheduling decisions |

### 4.1 Session Contract

```ts
type RepositoryIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-repository-identity-v1'
  platform: 'macos' | 'linux'
  gitDirectoryRelativePath: '.git'
  gitDirectoryIdentity: {
    deviceId: string
    fileId: string
    ownerUid: number
  }
  objectFormat: 'sha1' | 'sha256'
  repositoryIdentityDigest: string
}

type WorkspaceIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-identity-v1'
  ownerPrincipalId: string
  platform: 'macos' | 'linux'
} & (
  | {
      kind: 'live'
      canonicalRootPath: string
      rootIdentity: {
        deviceId: string
        fileId: string
        ownerUid: number
      }
      repositoryIdentityRef?: ArtifactRef
      repositoryIdentityDigest?: string
      identityDigest: string
    }
  | {
      kind: 'legacy_unavailable'
      legacyCanonicalRootPath: string
      unavailableReason: 'missing' | 'moved' | 'unsupported_platform' | 'identity_unverifiable'
      observedAt: string
      identityDigest: string
    }
)

type Session = {
  schemaVersion: 1
  id: string
  workspaceIdentityRef: ArtifactRef
  name?: string
  parentSessionId?: string
  forkedThroughItemSeq?: number
  contextRevision: number
  latestItemSeq: number
  contextProjectionRef: ArtifactRef
  createdAt: string
  updatedAt: string
}

type SessionItem = {
  schemaVersion: 1
  itemId: string
  sessionId: string
  itemSeq: number
  kind:
    | 'compaction'
    | 'run_terminal'
    | 'legacy_record'
    | 'legacy_compaction'
    | 'legacy_plan'
    | 'legacy_handoff'
    | 'legacy_bookmark'
  payloadRef: ArtifactRef
  createdAt: string
}

type SessionContextSegment =
  | {
      kind: 'raw'
      fromItemSeq: number
      throughItemSeq: number
      items: Array<{ sourceSessionId: string; itemSeq: number; itemId: string; kind: SessionItem['kind']; payloadRef: ArtifactRef }>
    }
  | {
      kind: 'summary'
      fromItemSeq: number
      throughItemSeq: number
      compactionItemId: string
      summaryRef: ArtifactRef
      summaryDigest: string
      sourceItemsDigest: string
      retainedItemIds: string[]
    }
  | {
      kind: 'excluded_control'
      fromItemSeq: number
      throughItemSeq: number
      sourceItemsDigest: string
    }

type SessionContextProjection = {
  schemaVersion: 1
  format: 'cliq-session-context-v1'
  sessionId: string
  contextRevision: number
  throughItemSeq: number
  segments: SessionContextSegment[]
  projectionDigest: string
}

type SessionCompactionItem = {
  schemaVersion: 1
  kind: 'compaction'
  fromItemSeq: number
  throughItemSeq: number
  sourceItemsDigest: string
  summaryRef: ArtifactRef
  summaryDigest: string
  retainedItemIds: string[]
  previousProjectionRef: ArtifactRef
  createdAt: string
}

type SessionHandoffEntryV1 = {
  index: number
  sourceKind: 'run_terminal' | 'summary'
  fromItemSeq: number
  throughItemSeq: number
  sourceRef: ArtifactRef
  sourceDigest: string
  contentUtf8: string
}

type SessionHandoffV1 = {
  schemaVersion: 1
  format: 'cliq-session-handoff-v1'
  sessionId: string
  workspaceIdentityRef: ArtifactRef
  workspaceIdentityDigest: string
  contextRevision: number
  throughItemSeq: number
  contextProjectionRef: ArtifactRef
  contextProjectionDigest: string
  entries: SessionHandoffEntryV1[]
  excludedRanges: Array<{ fromItemSeq: number; throughItemSeq: number; sourceItemsDigest: string }>
  handoffDigest: string
}
```

`workspaceIdentityRef` resolves only to `WorkspaceIdentityV1`. `session.create` may create only `kind='live'`: it descriptor-walks the supplied absolute path without following symlinks, requires a same-principal-owned directory, canonicalizes it to NFC absolute platform spelling, and records `fstat` device/file ids as canonical unsigned decimal strings (no sign or leading zero) plus the safe-integer owner uid. A Git workspace additionally requires an in-root real `.git` directory opened from the held root descriptor; linked/outside Git directories, `.git` files, symlinks, and owner/type/link-count mismatches are rejected. Its `RepositoryIdentityV1` repeats the platform, the literal `.git` path, descriptor-held directory identity, and Git-reported `extensions.objectFormat` normalized to `sha1|sha256`; `repositoryIdentityDigest = SHA-256(JCS(repository identity with repositoryIdentityDigest omitted))`. The live workspace carries both repository ref and digest or neither, and a non-Git root carries neither. `identityDigest = SHA-256(JCS(workspace identity with identityDigest omitted))`.

The canonical root path is a locator, not authority: every capture, authorization, Run admission, apply, and publication reopens it by no-follow descriptor traversal and requires the same owner/device/file tuple; a Git root also requires the same repository ref preimage and digest. A moved/replaced root or `.git` returns `ARTIFACT_MISMATCH` and requires a new Session rather than retargeting the ref. `RunSubmitRequest.workspacePath` must resolve byte-for-byte to the live Session identity; `run.apply` has no path parameter and derives/revalidates the source Run's live Session identity. Every `workspaceIdentityDigest` in RunPolicy, authorization/grant, SourceManifest, instruction, verifier/dependency, child, and delivery artifacts equals this exact artifact's digest, and every Git repository digest equals its retained repository artifact. Session fork copies the ref unchanged. No realpath hash, ambient cwd, caller path string, or Git worktree indirection is a substitute.

Legacy import attempts the same descriptor-held construction. If the recorded root is absent, moved, on an unsupported platform, or cannot prove identity, the importer creates only `kind='legacy_unavailable'`; its digest uses the same omission rule and its path is retained solely for display/audit. That Session remains readable, compactable, exportable, and forkable for context, but neither it nor its forks may admit a Run or `run.apply`; the user creates a new live Session to execute. Import never fabricates device, repository, or executable identity and does not fail unrelated Session migration merely because an old root disappeared.

The logical Session stream is immutable and contiguous by sequence; a physical child Session may inherit its prefix rather than copy rows. Only context projection/revision/name/timestamps are mutable; fork lineage and workspace identity never change. `contextProjectionRef` resolves to the exact versioned shape above and must match Session id/revision/latest sequence. Segments are ordered, nonoverlapping, and cover every sequence `1..throughItemSeq`: a raw segment contains exactly one source-Session identity/payload tuple for every sequence in its range; a summary binds the source range digest and immutable `SessionCompactionItem`/summary; an excluded-control segment binds non-model-visible history without projecting it. Retained ids exist in the covered source range and are projected after the summary in stable item-sequence order. Every item id/kind/payload ref is checked against either this Session's row or the exact immutable ancestor lineage reachable through `parentSessionId/forkedThroughItemSeq`; an inherited entry's sequence may not exceed any lineage fork cursor. `sourceItemsDigest` is over ordered logical `{itemSeq,kind,payloadRef}` tuples, deliberately independent of physical owner/item id, so a forked view preserves it. `projectionDigest` is SHA-256 over the RFC 8785/JCS object with that member omitted.

Kernel Cut deliberately rejects ambiguous projection surgery. `session.compact` requires `fromItemSeq` and `throughItemSeq` to equal whole current segment boundaries, requires every selected segment to be `raw`, and requires retained ids to be unique logical source items inside that exact range; any summary, `excluded_control`, straddling, nested, or recompaction range returns `INVALID_REQUEST`. The public `summaryMarkdown` is normalized to NFC, rejects NUL/unpaired surrogates, and publishes exact `ModelTextV1` with UTF-8 bytes in `1..262144`; `summaryRef` names it and `summaryDigest` equals its `textDigest` in both the item and projection segment. It publishes summary/item/new-projection artifacts first and atomically appends one child-owned `SessionCompactionItem` at `latestItemSeq+1`, replaces the projection, increments `contextRevision`, and updates `latestItemSeq`. The new compaction item itself is always represented by an exact one-item `excluded_control` segment whose source digest binds its `{itemSeq,kind,payloadRef}` tuple; it is never model-visible or ambiguously raw. `session.fork throughItemSeq` must be zero or the `throughItemSeq` of a current segment; a cursor inside a summary/raw/control segment is rejected rather than re-expanded. One idempotent transaction creates the child with `parentSessionId`, `forkedThroughItemSeq`, `contextRevision=1`, and `latestItemSeq=throughItemSeq`, plus a new projection whose prefix entries keep exact source Session/item ids; it clones no item rows. The child's first local append uses `throughItemSeq+1`. Subsequent lookup validates the immutable ancestor chain, and a parent later append/compaction cannot enter the frozen child prefix. Legacy item kinds are retained for inspect/export only and must occur exclusively in `excluded_control` segments; they are never decoded as model context. A later RFC may add deterministic re-expansion/recompaction. Session contains no status, lease, wait, budget, worker, Journal, workspace generation, or Run frontier field.

`session.handoff.create` is one exact read projection. An omitted `throughItemSeq` means the captured projection's `throughItemSeq`; an explicit cursor must be zero or the end of a current segment and no greater than that cut. The server reads Session, lineage rows, and projection in one SQLite snapshot and rejects a revision mismatch. It walks the exact prefix: each raw `run_terminal` emits one entry with its payload ref, `sourceDigest=SHA-256(JCS(SessionRunTerminalItem))`, and the section 4.2 model-visible JCS string; each summary emits one entry with the compaction item ref, its `summaryDigest`, and decoded `ModelTextV1.utf8`; every `excluded_control` range is copied to `excludedRanges`; legacy kinds are control-only. Entries and excluded ranges are contiguous in their respective stored encounter order, indices start at zero, refs/digests rehash, and no current mutable path, checkpoint, principal, credential, grant, receipt body, or hidden Run transcript enters the handoff. `contextProjectionDigest` and workspace identity equal the captured Session; `handoffDigest = SHA-256(JCS(handoff with handoffDigest omitted))`.

The JSON artifact is exactly UTF-8 RFC 8785/JCS of `SessionHandoffV1`. The Markdown artifact is rendered from that decoded object only: start with `# Cliq Session Handoff\n\n`, then `Session: <JCS(sessionId)>\nContext revision: <base-10 contextRevision>\nThrough item: <base-10 throughItemSeq>\n`; for each entry append `\n## Entry <base-10 index+1>: <sourceKind>\n\n` followed by every LF-normalized content line prefixed with four ASCII spaces and one final LF; then append `\nExcluded control ranges: <base-10 excludedRanges.length>\n`. Input CRLF/CR in human text is normalized to LF when the originating `ModelTextV1` is published, so the renderer performs no platform newline choice. Markdown bytes are UTF-8, their artifact digest is SHA-256 of those exact bytes, and the result descriptors must rehash the JCS and Markdown artifacts. Identical Session/revision/cursor therefore returns identical refs; there is no creation timestamp, random id, ambient path, or renderer option.

### 4.2 Session And Run Concurrency

Run admission freezes a Session cursor into a context manifest. The Run then owns an ordered Run-local item stream. Root and child Runs never append their live model/tool transcript directly into a shared Session.

Every terminal Run without `parentRunId` atomically appends exactly one idempotent Session item in its terminal state transaction:

```ts
type SessionRunTerminalItem = {
  schemaVersion: 1
  format: 'cliq-session-run-terminal-v1'
  kind: 'run_terminal'
  itemKey: `run-terminal:${string}`
  runId: string
  operation: 'agent' | 'delivery'
  admittedSessionItemSeq: number
  status: Extract<RunStatus, 'succeeded' | 'completed_unverified' | 'failed' | 'cancelled'>
  terminalReason: RunTerminalReason
  resultRef?: ArtifactRef
  terminalDetailRef?: ArtifactRef
  summaryRef?: ArtifactRef
  summaryDigest?: string
}
```

The storage gate enforces the same status/result/detail matrix as the Run and uniqueness by Session plus `runId`; retry after a crash observes the existing item. The item is owned by the exact root Run's Session, `itemKey` is the literal ``run-terminal:${Run.id}``, `runId === Run.id`, `operation === decoded RunSpec.operation`, and `admittedSessionItemSeq === decoded AdmittedContextManifest.throughSessionItemSeq` reached through that RunSpec. Its status and terminal reason equal the terminal Run row; a failed/cancelled `terminalDetailRef` equals the Run's exact terminal-detail ref. `succeeded|completed_unverified` require the Run's exact `resultRef`, forbid `terminalDetailRef`, and require `summaryRef/summaryDigest` to equal the decoded `RunResult.summaryRef` and that exact `ModelTextV1.textDigest`. `failed|cancelled` require the exact detail and forbid result and summary fields. Concurrent roots receive Session sequence numbers in SQLite commit order. Each root-terminal append increments `latestItemSeq` and `contextRevision` once and extends the prior projection with a **new, never-coalesced, one-item `raw` segment** whose sole entry is the exact new `{sourceSessionId=sessionId,itemSeq,itemId,kind='run_terminal',payloadRef}` tuple and whose source digest is computed by the ordinary raw-segment rule. The model-visible rendering of that item is exactly UTF-8 RFC 8785/JCS of `{kind:'run_terminal',runId,operation,status,terminalReason,resultRef?,summaryRef?}` with absent optionals omitted; `admittedSessionItemSeq`, `terminalDetailRef`, and `summaryDigest` remain audit/control metadata and are not projected. This fixed segment and rendering rule makes later compaction/fork boundaries, projection digests, and admitted prompt bytes implementation-independent. A child never publishes directly into Session: its terminal transaction produces the parent-owned `ChildResultItem`/wake contract instead. Thus client `cliq resume` deterministically sees every committed root outcome without copying live Run transcripts or depending on an event spool.

### 4.3 Physical Storage Is Not A Control Plane

The first implementation uses SQLite for small structured state and a content-addressed artifact store for large immutable payloads. Physical tables do not define semantic ownership.

Minimum tables:

- `sessions`
- `items`, with an exclusive Session or Run owner
- `runs`
- `checkpoints`
- `run_journal`
- `run_events`
- `worker_launches`
- `control_requests`
- `child_allocations`
- `authorization_grants`
- `mcp_registrations`
- `admin_operations`
- `local_inference_activation_cycles`
- `local_inference_launches`
- `state_owners`
- `artifacts`

`run_events` is a non-authoritative durable spool for attach cursors. Losing an old retained event may reduce display history; it must never alter recovery, permission, or verification decisions. Every `ArtifactRef` reachable from a retained event row remains a CAS root until that row and its cursor metadata are pruned in the same transaction.

The public v1 event union is intentionally only two shapes:

```ts
type RunEvent =
  | {
      schemaVersion: 1
      kind: 'state_changed'
      runId: string
      eventSeq: number
      runRevision: number
      status: RunStatus
      nextStep: RunNextStep
      waitingReason?: WaitingReason
      waitingOnRef?: ArtifactRef
      frontierRef?: ArtifactRef
      latestRunItemSeq: number
      resultRef?: ArtifactRef
      terminalReason?: RunTerminalReason
      terminalDetailRef?: ArtifactRef
      occurredAt: string
    }
  | {
      schemaVersion: 1
      kind: 'progress'
      runId: string
      eventSeq: number
      observedRunRevision: number
      phase: 'agent' | 'tool' | 'verify' | 'recovery' | 'delivery'
      opId?: string
      messageRef?: ArtifactRef
      completedUnits?: number
      totalUnits?: number
      occurredAt: string
    }
```

Every authoritative **Run workflow** mutation emits `state_changed` in its transaction; narrow heartbeat, launch-row write-gate, recovery-probe scheduling, and other explicitly named row-only CAS operations do not mutate the Run revision and emit no Run event. `run.attach` reads the authoritative Run snapshot, earliest/latest retained bounds, and `highWaterEventSeq` in one SQLite snapshot, then returns only committed events `(afterEventSeq, highWaterEventSeq]` up to the requested limit. `nextEventSeq` is the last returned sequence, or the supplied cursor when the page is empty. The earliest valid cursor is `max(0, earliestRetainedEventSeq - 1)`: initial `afterEventSeq=0` therefore returns event 1, `afterEventSeq=earliestRetainedEventSeq-1` returns the first retained event, and only a smaller cursor returns `EVENT_CURSOR_EXPIRED`. `afterEventSeq > highWaterEventSeq` is `INVALID_REQUEST` rather than an empty page or a future cursor. `afterEventSeq=highWaterEventSeq` returns an empty page with the same cursor. If `nextEventSeq < highWaterEventSeq`, the client **must** request the next page with `afterEventSeq=nextEventSeq`; only when they are equal has it caught up through that captured cut. A later request from that cursor captures a new high-water and returns subsequently committed events. Public v1 defines no implicit server-push subscription or out-of-band event envelope, so a transport may optimize polling internally only if it preserves this exact page/result sequence. Nonterminal Runs retain all events; a terminal Run may prune older display rows after the retention window but retains at least its terminal `state_changed` row as the nonempty cursor anchor. Item/audit detail remains on `run.get`. `progress` is bounded display telemetry only: units are nonnegative safe integers, message artifacts are <=64 KiB/redacted, and coalescing or pruning cannot change state. No provider-specific event kind enters the public contract.

SQLite must use foreign keys, a bounded busy timeout, WAL mode where supported, and crash-durable synchronization. Schema migrations are transactional and versioned. The concrete Node binding is internal behind a narrow storage adapter.

`control_requests` is the crash-safe mutator dedup boundary, not a new lifecycle. It has unique `(principalId, method, requestId)`, the exact first-commit `channelIdentityRef/channelIdentityDigest`, canonical request digest, immutable response artifact ref/revision, and commit timestamp. The channel ref closed-decodes `LocalControlChannelIdentityV1` for that principal/client and is a retained artifact root. A mutator publishes the deterministic response artifact first, then writes the request row in the same SQLite transaction as its state change. A retry with the same digest returns that response even when its expected revision/wait ref or authenticated channel is now different; it never rewrites the original provenance. A different digest returns `REQUEST_ID_CONFLICT` and never reruns the reducer. Read methods and deterministic `session.handoff.create` need no row.

`child_allocations` is similarly narrow: unique parent/child ids, immutable granted additive ceilings/deadline/mode/delegate identity, state `reserved|child_terminal|settled`, terminal result/diagnostic/usage refs, and settlement timestamp. Child terminal may advance only its allocation row unless the parent is lease-free on the exact child subject; parent budget counters change only in a parent revision transaction. Settlement moves inclusive actual usage to consumed and releases unused granted capacity exactly once; it can never refund consumed/settled usage, reverse state, or detach the child.

`authorization_grants` stores principal-owned opaque ids, closed target kind, canonical workspace/toolchain/bundle identity, purpose, target/request digest, use bounds, expiry, and `active|consumed|revoked`; it never stores secret bytes. `mcp_registrations` stores one user registration id plus monotonic registry revision and immutable manifest refs; refresh appends a new referenced revision while admitted Runs retain the old digest. Both mutate only through the exact Supervisor methods and `control_requests`, and both fail closed on ownership/digest/revision mismatch.

`admin_operations` is not a second Run engine. It is a narrow crash fence for executable registry probes: unique principal/method/request id plus contiguous attempt, immutable target/request refs, phase `prepared|active|completed|failed`, Supervisor instance, planned/actual process-containment refs, lease version/expiry, result/evidence refs, and timestamps. It has no prompt, tools, children, Checkpoint, budget, or user-facing resume method. No probe process/network request starts before `prepared`; blocked preactivation then records `active`. Startup never adopts it: it kills/proves the containment empty and records either a bounded retryable recovery failure or a final failure. Only `completed`, `final_rejection`, or `retry_exhausted` commits the immutable `control_requests` response; a retryable recovery failure deliberately commits no public response.

```ts
type AdminOperationBase = {
  schemaVersion: 1
  adminOperationId: string
  principalId: string
  method: 'mcp.register' | 'mcp.refresh'
  requestId: string
  requestDigest: string
  attempt: number
  maxAttempts: 3
  deadlineAt: string
  targetRef: ArtifactRef
  targetDigest: string
  probePayloadCoreRef: ArtifactRef
  probePayloadCoreDigest: string
  supervisorInstanceId: string
  plannedContainmentRef: ArtifactRef
  plannedContainmentDigest: string
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  rowVersion: number
  createdAt: string
}

type AdminProbePayloadCoreV1 = {
  schemaVersion: 1
  format: 'cliq-admin-probe-payload-core-v1'
  probeKind: 'mcp_stdio' | 'mcp_streamable_http'
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  adapterExecutableId: string
  adapterVersion: string
  adapterExecutableDigest: string
  protocolRecipe: 'mcp-initialize-capabilities-tools-list-v1'
  maximumResponseBytes: number
  payloadCoreDigest: string
}

type McpAdminProbeTargetV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-admin-probe-target-v1'
  ownerPrincipalId: string
  registrationId: string
  method: 'mcp.register' | 'mcp.refresh'
  expectedRegistryRevision?: number
  sourceRegistryRevisionRef?: ArtifactRef
  resolvedTransport:
    | {
        kind: 'stdio'
        executionIdentityGrantId: string
        executionIdentityConsumptionReceiptRef: ArtifactRef
        executionIdentityConsumptionReceiptDigest: string
        executable:
          | {
              kind: 'guest_toolchain'
              toolchainManifestRef: ArtifactRef
              toolId: string
              executionPath: string
              executableDigest: string
            }
          | {
              kind: 'runtime_bundle'
              runtimeBundleRef: ArtifactRef
              executableId: string
              executionPath: string
              executableDigest: string
            }
        argv: NonSecretArgumentRequest[]
      }
    | {
        kind: 'streamable_http'
        endpointRegistrationRef: ArtifactRef
        endpointIdentityDigest: string
        tlsPolicyDigest: string
        credentialGrantRefs: ArtifactRef[]
      }
  assertStatelessPerCall: true
  requestedToolRecovery: Array<{ toolName: string; recovery: RequestedMcpRecoveryV1 }>
  lifecycle: {
    launchTimeoutMs: number
    callTimeoutMs: number
    maxLaunchesPerCall: number
  }
  requestCoreDigest: string
  targetDigest: string
  createdAt: string
}

type McpAdminProbeResultV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-admin-probe-result-v1'
  adminOperationId: string
  attempt: number
  dispatchId: string
  probeRequestDigest: string
  targetRef: ArtifactRef
  targetDigest: string
  probePayloadCoreRef: ArtifactRef
  probePayloadCoreDigest: string
  processContainmentRef: ArtifactRef
  initializeResponseRef: ArtifactRef
  initializeResponseDigest: string
  capabilityResponseRef: ArtifactRef
  capabilityResponseDigest: string
  toolsListResponseRef: ArtifactRef
  toolsListResponseDigest: string
  initializeDigest: string
  capabilityDigest: string
  normalizedTools: McpProbedToolInterfaceV1[]
  probedToolsListDigest: string
  completedAt: string
  resultDigest: string
}

type AdminProbeClosureEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-admin-probe-closure-evidence-v1'
  adminOperationId: string
  attempt: number
  targetRef: ArtifactRef
  targetDigest: string
  plannedContainmentRef: ArtifactRef
  plannedContainmentDigest: string
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  evidenceDigest: string
} & (
  | {
      closureKind: 'no_spawn'
      noSpawnEvidenceRef: ArtifactRef
      noSpawnEvidenceDigest: string
      processContainmentRef?: never
      dispatchId?: never
      probeRequestDigest?: never
      deathEvidenceRef?: never
      deathEvidenceDigest?: never
    }
  | {
      closureKind: 'containment_dead'
      processContainmentRef: ArtifactRef
      dispatchId?: string
      probeRequestDigest?: string
      deathEvidenceRef: ArtifactRef
      deathEvidenceDigest: string
      noSpawnEvidenceRef?: never
      noSpawnEvidenceDigest?: never
    }
)

type AdminProbeErrorV1 = {
  schemaVersion: 1
  format: 'cliq-admin-probe-error-v1'
  adminOperationId: string
  attempt: number
  targetRef: ArtifactRef
  targetDigest: string
  closureEvidenceRef: ArtifactRef
  closureEvidenceDigest: string
  diagnosticRef: ArtifactRef
  diagnosticDigest: string
  createdAt: string
  errorDigest: string
} & (
  | {
      code: 'target_rejected' | 'schema_invalid' | 'capability_mismatch'
      deterministicRejection: true
    }
  | {
      code:
        | 'preactivation_no_spawn'
        | 'transport_failed_no_effect'
        | 'timeout_after_containment_death'
      deterministicRejection: false
    }
)

type AdminProbeDispatchState =
  | { state: 'blocked' }
  | {
      state: 'claimed'
      probeRequestDigest: string
      dispatchId: string
      claimedAt: string
    }
  | {
      state: 'released'
      probeRequestDigest: string
      dispatchId: string
      claimedAt: string
      releasedAt: string
    }

type AdminOperation = AdminOperationBase & (
  | {
      phase: 'prepared'
      processContainmentRef?: never
      leaseExpiresAt?: never
      resultRef?: never
      resultDigest?: never
      evidenceRef?: never
      evidenceDigest?: never
      errorRef?: never
      errorDigest?: never
      controlResponseRef?: never
      controlResponseDigest?: never
      failureDisposition?: never
      retryNotBeforeAt?: never
      probeDispatch?: never
      finishedAt?: never
    }
  | {
      phase: 'active'
      processContainmentRef: ArtifactRef
      leaseExpiresAt: string
      probeDispatch: AdminProbeDispatchState
      resultRef?: never
      resultDigest?: never
      evidenceRef?: never
      evidenceDigest?: never
      errorRef?: never
      errorDigest?: never
      controlResponseRef?: never
      controlResponseDigest?: never
      failureDisposition?: never
      retryNotBeforeAt?: never
      finishedAt?: never
    }
  | {
      phase: 'completed'
      processContainmentRef: ArtifactRef
      probeDispatch: Extract<AdminProbeDispatchState, { state: 'released' }>
      resultRef: ArtifactRef
      resultDigest: string
      evidenceRef: ArtifactRef
      evidenceDigest: string
      controlResponseRef: ArtifactRef
      controlResponseDigest: string
      errorRef?: never
      errorDigest?: never
      failureDisposition?: never
      retryNotBeforeAt?: never
      finishedAt: string
      leaseExpiresAt?: never
    }
  | {
      phase: 'failed'
      failureDisposition: 'retryable_recovery'
      processContainmentRef?: ArtifactRef
      probeDispatch?: AdminProbeDispatchState
      resultRef?: never
      resultDigest?: never
      evidenceRef: ArtifactRef
      evidenceDigest: string
      errorRef: ArtifactRef
      errorDigest: string
      controlResponseRef?: never
      controlResponseDigest?: never
      retryNotBeforeAt: string
      finishedAt: string
      leaseExpiresAt?: never
    }
  | {
      phase: 'failed'
      failureDisposition: 'final_rejection' | 'retry_exhausted'
      processContainmentRef?: ArtifactRef
      probeDispatch?: AdminProbeDispatchState
      resultRef?: never
      resultDigest?: never
      evidenceRef: ArtifactRef
      evidenceDigest: string
      errorRef: ArtifactRef
      errorDigest: string
      controlResponseRef: ArtifactRef
      controlResponseDigest: string
      retryNotBeforeAt?: never
      finishedAt: string
      leaseExpiresAt?: never
    }
)

type AdminProbeBrokerRequest = {
  schemaVersion: 1
  kind: 'mcp_registry_probe'
  requestId: string
  adminOperationId: string
  attempt: number
  principalId: string
  method: 'mcp.register' | 'mcp.refresh'
  originalRequestDigest: string
  targetRef: ArtifactRef
  targetDigest: string
  probeRequestDigest: string
  dispatchId: string
  supervisorInstanceId: string
  containmentRef: ArtifactRef
  target:
    | { kind: 'stdio' }
    | {
        kind: 'streamable_http'
        endpointRegistrationRef: ArtifactRef
        endpointIdentityDigest: string
        tlsPolicyDigest: string
        credentialGrantRefs: ArtifactRef[]
      }
  payloadRef: ArtifactRef
  payloadDigest: string
  expiresAt: string
}
```

The primary identity is `(principalId,method,requestId,attempt)` and `adminOperationId = H(principalId,method,requestId,requestDigest,targetDigest)`; `attempt` is exactly `1..3`, contiguous for an identical request digest/target, and at most one nonterminal attempt exists. `deadlineAt = createdAt + target.lifecycle.launchTimeoutMs`, where the normalized lifecycle value is the public default `30000` or an accepted `1000..300000`; the deadline never extends. Refresh copies that immutable lifecycle from the current registry revision, so it has the same producer and no hidden timeout input. Phase transitions are `prepared -> active|failed` and `active -> completed|failed`; inside active, row-version CAS permits only `blocked -> claimed -> released`, terminal rows are immutable, and the permanent dispatch id is never cleared or reused. `active/blocked` is legal only after inspected containment identity is durable and before release of its sole probe capability. `claimAdminProbe` binds the JCS/SHA-256 probe request and unique `dispatchId`; `releaseAdminProbe` rechecks the same active row, request/target/principal/Supervisor, exact admin-owned containment, grant/endpoint bindings, live admin lease/deadline, and absence of another claim immediately before executable/network/payload/credential release. A failed second check reaches no target and cannot mint another claim for that attempt. `completed` requires the retained released state. A failed row retains its last dispatch state, or omits it only for `prepared -> failed` with positive no-spawn evidence.

`AdminProbeBrokerRequest.requestId = H(adminOperationId,attempt,probeRequestDigest)` and cannot alias changed bytes. It carries no Run id, Run revision, lease epoch, worker launch, generation, Run frontier, or Run budget. Its stdio branch carries no second executable ref: the broker decodes the exact `McpAdminProbeTargetV1` at `targetRef`, requires its stdio transport to equal the admin SandboxLaunchSpec/process identity, and releases only that frozen executable probe capability. Its HTTP branch can redeem only the exact principal/purpose/endpoint-bound credential refs repeated from that same target. Both gates read `admin_operations`, not `runs`/`worker_launches`; duplicate frames join the same dispatch. `completed`, or `failed` after active, additionally requires evidence proving the exact complete containment dead and no probe I/O/process remains; a preactivation `prepared -> failed` may instead use positive no-spawn/empty-planned-containment evidence. Timeout, lease expiry, Supervisor loss, or inaccessible containment is not automatically failed. A new Supervisor never adopts/renews an active row and no later attempt begins until death/no-spawn evidence terminalizes the prior one.

`AdminOperation.targetRef` always resolves to `McpAdminProbeTargetV1`, never an opaque request blob. For register, `expectedRegistryRevision`/`sourceRegistryRevisionRef` are absent; for refresh both are required and name the exact current revision whose immutable transport/recovery/lifecycle inputs are copied. `requestCoreDigest = SHA-256(JCS(public method body with protocolVersion/requestId/requestDigest omitted))`; `targetDigest = SHA-256(JCS(target with targetDigest omitted))`. Recovery overrides are unique and byte-sorted by tool name; missing discovered tools normalize to `manual`. Lifecycle defaults/ranges are the MCP registry contract. `probePayloadCoreRef` resolves to `AdminProbePayloadCoreV1`, whose `payloadCoreDigest` omits itself under JCS, whose adapter id/version/digest resolves to a signed RuntimeBundle helper, and whose `maximumResponseBytes` is `65536..1048576` (default `1048576`); the fixed protocol recipe contains no dispatch id, containment, credentials, endpoint payload, or caller argv. It is published before containment planning. The SandboxLaunchSpec repeats only that static core ref; after claim, `AdminProbeBrokerRequest.payloadRef` must equal it and supplies the claim/containment/target envelope separately. The admin row, admin-owned `ProcessContainment`, broker envelope target/core, probe result/receipt, and final registry core must all reference or reproduce these exact artifacts; any method/owner/registration/revision/executable/argv/endpoint/TLS/grant/recovery/lifecycle/payload/digest mismatch fails before I/O or publication.

For initial stdio registration, target construction resolves the public
`executionIdentityGrantId` to the exact active principal-owned
`AuthorizationGrantV1(target.kind='execution_identity_read',
purpose='mcp_stdio')`. Artifact bytes for an
`AuthorizationConsumptionReceiptV1(consumer.kind='mcp_registration',
registrationId,registryRevision=1)` are published first; the transaction that
inserts admin attempt 1 consumes that one-use grant and stores the receipt
ref/digest plus grant id in the target. Executable kind/manifest/id/path/digest
equal the grant target byte-for-byte. A later admin attempt reuses that same
target/receipt and never consumes again. Refresh accepts no execution grant: it
copies the current registry revision's exact grant id, consumption receipt,
executable, and argv into its target and revalidates the retained grant/receipt
closure. The final stdio `McpRegistryRevision` repeats those three identity
fields. A raw grant id/ref, unconsumed grant, receipt for another principal/
registration/revision, or changed executable cannot reach containment or I/O.

Probe terminal artifacts are closed. `McpAdminProbeResultV1.resultDigest`, `AdminProbeClosureEvidenceV1.evidenceDigest`, and `AdminProbeErrorV1.errorDigest` each omit only themselves under JCS; every other ref/digest pair rehashes its named bytes. A result is legal only for the released dispatch and repeats the row's operation/attempt/request/target/payload/containment. Its three bounded secret-free response artifacts are the exact bytes decoded by the fixed recipe; `initializeDigest`/`capabilityDigest` are their normalized protocol projections. `normalizedTools` contains only byte-sorted unique `McpProbedToolInterfaceV1` rows, each `interfaceDigest = SHA-256(JCS(interface with interfaceDigest omitted))`, and `probedToolsListDigest = SHA-256(JCS(normalizedTools))`. It contains no requested recovery intent, profile, template, predicate, final tool contract, or registry digest. The completed row's result ref/digest names that artifact exactly.

Every terminal attempt also names one `AdminProbeClosureEvidenceV1`. `no_spawn` decodes the exact `ProcessContainmentNoSpawnEvidenceV1` for the row's plan/spec/owner/nonce and is legal only before release, with no process/dispatch fields. `containment_dead` decodes the exact `ProcessContainmentDeathEvidenceV1`, repeats the actual containment, and requires dispatch/request iff the row reached claimed/released. Its inspector is current and every row/target/plan/spec/digest matches. An `AdminProbeErrorV1` repeats that closure; deterministic protocol target/schema/capability rejection has `deterministicRejection=true`, while preactivation/transport/timeout recovery failures are false and require the named positive no-spawn/death fact. Diagnostic bytes are bounded/redacted and never decide disposition. `retryable_recovery|retry_exhausted` require false; `final_rejection` requires true. The row's result/evidence/error/control-response ref/digest pairs are exact and forbidden outside their typed phase.

Failure disposition is closed. A deterministic target/schema/capability rejection is `final_rejection` on any attempt. A death-proven Supervisor/transport/preactivation recovery failure on attempt 1 or 2 is `retryable_recovery`, has no `controlResponseRef` or `control_requests` row, and sets `retryNotBeforeAt = finishedAt + 1s` after attempt 1 or `finishedAt + 5s` after attempt 2. Only after that instant may recovery or the same request-id caller insert the next contiguous attempt; concurrent retries join the existing row. The same recovery-class failure on attempt 3 is `retry_exhausted`. `completed` commits its validated result, MCP registry revision/receipt, exact `controlResponseRef`, and matching `control_requests` row together. `final_rejection` and `retry_exhausted` commit their exact error response ref and matching control row with the failed row. Those three final outcomes are the first and only public response; same-digest replay returns it, while a different digest conflicts against either the control row or the still-open admin attempt. The row has no broker authority after terminal phase.

All state is private local data. The state root must be a real, same-user-owned, non-symlink directory with mode `0700`; every state/CAS/temp/socket/backup/archive/runtime-bundle directory is opened by descriptor-relative no-follow traversal and remains `0700`. SQLite database/WAL/SHM, mutable metadata, temp files, migration manifests, and socket endpoints are `0600`; a fully published CAS object, bundle data file, or read-only backup is `0400`; a digest/signature-verified runtime executable/helper is owner-only `0500`. Publication uses same-directory `O_EXCL` temp creation, file+directory fsync, digest/signature verification where applicable, and descriptor-relative rename. The store rejects ownership mismatch, symlink components, unexpected file type, and authoritative regular files with link count other than one; it never follows a caller-selected state path or relies on process umask. Startup revalidates these invariants before opening SQLite, executing a bundle, or serving a client.

The Kernel Cut performs no automatic deletion of Sessions, Runs, RunResults, verification receipts, Journal facts, or migration archives. There is no `run.delete` method. `run_events` may prune display events after 30 days while preserving an explicit earliest cursor; every artifact referenced by a retained event is rooted until row and artifact-edge pruning commit atomically. Quarantined generations may be removed only after containment-death proof and retention checks; unreferenced CAS orphans older than seven days may be garbage-collected only by a reachability walk rooted at all Sessions/items, Runs/specs/results, Checkpoints, Journal entries, retained RunEvent refs, worker/admin/local-inference activation cycles and launches, control-request responses, child allocations, authorization grants, MCP registry revisions, local-service/model/capability evidence, receipts/provenance, grants/waits, runtime bundles, and migration archives. Product-level deletion/retention requires a later RFC, which keeps “return to verified work” from depending on an unspecified default GC policy.

## 5. Immutable RunSpec

```ts
type RunObjectiveV1 = {
  schemaVersion: 1
  format: 'cliq-run-objective-v1'
  utf8: string
  byteCount: number
  objectiveDigest: string
}

type RunSpec = {
  schemaVersion: 1
  operation: 'agent' | 'delivery'
  objectiveRef: ArtifactRef
  admittedContextRef: ArtifactRef
  baseWorkspaceManifestRef: ArtifactRef
  sourceProjectionRef: ArtifactRef
  assemblyRef: ArtifactRef
  policyRef: ArtifactRef
  sandboxProfileRef: ArtifactRef
  verifierSpecRef: ArtifactRef
  dependencyPolicyRef?: ArtifactRef
  unverifiedConsentRef?: ArtifactRef
  credentialGrantRefs: ArtifactRef[]
  budgets: {
    wallTimeMs: number
    modelTokens: number
    costMicros: number
    toolCalls: number
    repairAttempts: number
    childDepth: number
    childConcurrency: number
  }
}

type PolicyDisposition = 'allow' | 'ask' | 'deny'

type PolicyActionClass =
  | 'read'
  | 'plan'
  | 'write'
  | 'exec'
  | 'mcp'
  | 'verifier'
  | 'dependency_install_scripts'
  | 'delivery'
  | 'child_read_only'
  | 'child_mutating'

type PolicyEngineProfileV1 = {
  schemaVersion: 1
  format: 'cliq-policy-engine-profile-v1'
  evaluator: 'cliq-policy-evaluator-v1'
  permissionGrammar: 'cliq-permission-grammar-v0'
  bashParser: 'cliq-bash-head-parser-v1'
  profileDigest: string
}

type RunPolicySnapshotV1 = {
  schemaVersion: 1
  format: 'cliq-run-policy-v1'
  principalId: string
  workspaceIdentityDigest: string
  mode: 'default' | 'accept-edits' | 'plan' | 'yolo'
  engine: {
    id: 'cliq-policy-v1'
    version: string
    runtimeBundleRef: ArtifactRef
    profileEntryId: string
    profileRef: ArtifactRef
    profileDigest: string
  }
  toolManifestRef: ArtifactRef
  toolManifestDigest: string
  decisions: Record<PolicyActionClass, PolicyDisposition>
  decisionRules: Array<{
    ruleId: string
    order: number
    source: 'builtin' | 'cli' | 'user_config' | 'session' | 'repository_request'
    sourceRef?: ArtifactRef
    channel: 'fs-read' | 'fs-write' | 'bash' | 'mcp' | 'plan' | 'plan-progress' | 'named-action'
    pattern: string
    disposition: PolicyDisposition
  }>
  repositoryRequestRefs: ArtifactRef[]
  policyDigest: string
  createdAt: string
}

type PolicyChannelEvidenceBaseV1 = {
  schemaVersion: 1
  format: 'cliq-policy-channel-evidence-v1'
  principalId: string
  runId: string
  policyRef: ArtifactRef
  policyDigest: string
  frontierRef: ArtifactRef
  opId: string
  requestRef: ArtifactRef
  requestDigest: string
  targetRef: ArtifactRef
  targetDigest: string
  actionClass: PolicyActionClass
  decisionSource: 'rule' | 'mode_fallthrough'
  matchedRuleIds: string[]
  effectiveDisposition: PolicyDisposition
  evaluatedAt: string
  evidenceDigest: string
}

type PolicyChannelEvidenceV1 = PolicyChannelEvidenceBaseV1 & (
  | {
      channel: 'fs-read' | 'fs-write'
      canonicalRootRelativePaths: string[]
    }
  | {
      channel: 'bash'
      command:
        | { encoding: 'argv'; argv: string[] }
        | { encoding: 'shell_text'; shellText: string }
      parser: 'cliq-bash-head-parser-v1'
      outerCommandHead?: string
      nestedBuiltinDenyHeads: string[]
      unsafeForAllow: boolean
    }
  | {
      channel: 'mcp'
      registrationId: string
      serverToolName: string
    }
  | {
      channel: 'plan' | 'plan-progress'
      normalizedPlanIdentity: string
    }
  | {
      channel: 'named-action'
      namedAction:
        | { kind: 'verifier'; candidateItemId: string; verifierPlanRef: ArtifactRef; verifierId: string }
        | { kind: 'dependency_install_scripts'; dependencyPlanRef: ArtifactRef; lockfileDigest: string }
        | { kind: 'delivery'; deliveryPlanRef: ArtifactRef; operationSetDigest: string }
        | {
            kind: 'mcp_server_launch'
            registryRevisionRef: ArtifactRef
            registryManifestDigest: string
            lifecycleSeq: number
            originatingBatchItemId: string
            originatingCallId: string
            originatingCallIndex: number
          }
        | {
            kind: 'child'
            batchItemId: string
            callId: string
            callIndex: number
            mode: 'read_only' | 'mutating'
          }
      identityKey: string
    }
)

type OperationGrantV1 = {
  schemaVersion: 1
  format: 'cliq-operation-grant-v1'
  grantId: string
  principalId: string
  runId: string
  policyRef: ArtifactRef
  frontierRef: ArtifactRef
  opId: string
  requestRef: ArtifactRef
  requestDigest: string
  targetRef: ArtifactRef
  targetDigest: string
  subject:
    | {
        kind: 'model_call'
        turnId: string
        phase: 'model_turn' | 'context_compaction'
        assemblyRef: ArtifactRef
      }
    | {
        kind: 'tool_call'
        batchItemId: string
        callId: string
        callIndex: number
        toolName: string
        toolContractDigest: string
        replayClass: ReplayClass
      } & (
        | { policySubjectKind: 'ordinary_tool'; childMode?: never }
        | { policySubjectKind: 'child_delegate'; childMode: 'read_only' | 'mutating' }
      )
    | {
        kind: 'verifier_launch'
        candidateItemId: string
        resultSourceRef: ArtifactRef
        verifierPlanRef: ArtifactRef
        verifierIndex: number
        verifierId: string
        verifierSpecDigest: string
        required: boolean
      }
    | {
        kind: 'mcp_server_launch'
        registryRevisionRef: ArtifactRef
        registryManifestDigest: string
        lifecycleSeq: number
        originatingBatchItemId: string
        originatingCallId: string
        originatingCallIndex: number
      }
    | {
        kind: 'delivery_plan'
        deliveryPlanRef: ArtifactRef
        deliveryPlanDigest: string
        operationSetDigest: string
      }
    | {
        kind: 'publication_path'
        deliveryPlanRef: ArtifactRef
        sequence: 'forward' | 'abort'
        operationIndex: number
        operationId: string
        operationDigest: string
      }
    | {
        kind: 'dependency_acquisition'
        dependencyPlanRef: ArtifactRef
        lockfileDigest: string
        resultSourceRef: ArtifactRef
        installScripts: boolean
      }
  provenance:
    | {
        kind: 'policy_snapshot'
        actionClass: PolicyActionClass
        channelEvidenceRef: ArtifactRef
        channelEvidenceDigest: string
        matchedRuleIds: string[]
        effectiveDisposition: 'allow'
        decisionDigest: string
      }
    | {
        kind: 'user_approval'
        waitingSubjectRef: ArtifactRef
        decisionRef: ArtifactRef
        requestId: string
        channelEvidenceRef: ArtifactRef
        channelEvidenceDigest: string
      }
    | {
        kind: 'verifier_template'
        templateRef: ArtifactRef
        candidateOrdinal: number
        decisionRef: ArtifactRef
      }
    | {
        kind: 'run_assembly'
        assemblyRef: ArtifactRef
        assemblyDigest: string
      }
    | {
        kind: 'dependency_policy'
        dependencyPolicyRef: ArtifactRef
        dependencyPolicyDigest: string
      }
    | {
        kind: 'dependency_install_scripts_template'
        dependencyPolicyRef: ArtifactRef
        templateRef: ArtifactRef
        candidateOrdinal: number
      }
    | {
        kind: 'delivery_plan_derivation'
        planAuthorizationGrantRef: ArtifactRef
        deliveryDecisionItemId: string
      }
  maxDispatchedAttempts: number
  maxLaunches?: number
  issuedAt: string
  expiresAt: string
  grantDigest: string
}

type DirectUnverifiedConsentV1 = {
  schemaVersion: 1
  kind: 'direct_unverified_consent'
  principalId: string
  client: 'cli' | 'tui' | 'jsonl' | 'rpc'
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  admissionIntentDigest: string
  runSpecCoreDigest: string
  allowUnverified: true
  createdAt: string
  consentDigest: string
}

type DerivedChildUnverifiedConsentV1 = {
  schemaVersion: 1
  kind: 'derived_child_unverified_consent'
  parentRunId: string
  childRunId: string
  delegateBatchItemId: string
  delegateCallId: string
  delegateCallIndex: number
  delegateOpId: string
  delegateOperationGrantRef: ArtifactRef
  childCapabilityGrantCoreDigest: string
  childRunSpecCoreDigest: string
  allowUnverifiedHelper: true
  createdAt: string
  consentDigest: string
}

type EndpointRegistrationV1 = {
  schemaVersion: 1
  format: 'cliq-endpoint-registration-v1'
  endpointRegistrationId: string
  registrationKind: 'bundled_default' | 'user'
  ownerPrincipalId: string
  purposes: Array<'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'>
  target: { scheme: 'https'; hostAscii: string; port: number; basePath: string; redirectPolicy: 'reject_all' }
  tls: {
    serverNameAscii: string
    minimumVersion: 'TLSv1.3'
    trustStoreRuntimeBundleRef: ArtifactRef
    trustStoreRuntimeBundleManifestDigest: string
    trustStoreEntryId: 'default_https_trust_store'
    trustStoreRef: ArtifactRef
    trustStoreDigest: string
    spkiSha256Pins: string[]
  }
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  createdAt: string
  registrationDigest: string
}

type CredentialExternalSubjectV1 = {
  schemaVersion: 1
  format: 'cliq-credential-external-subject-v1'
  endpointIdentityDigest: string
  subject:
    | {
        kind: 'provider_verified'
        providerNamespace: string
        accountSubjectDigest: string
        scopes: string[]
        audiences: string[]
      }
    | {
        kind: 'opaque_generation'
        opaqueSubjectId: string
        scopes: ['endpoint_exact_only']
        audiences: []
      }
  observedAt: string
  subjectDigest: string
}

type EndpointCredentialGrantBinding = {
  schemaVersion: 1
  credentialGrantId: string
  authorityRevision: number
  credentialServiceRevision: number
  ownerPrincipalId: string
  credentialHandleIdentityDigest: string
  secretGeneration: number
  externalSubject: CredentialExternalSubjectV1
  externalSubjectDigest: string
  purpose: 'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'
  endpointRegistrationRef: ArtifactRef
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  createdAt: string
  expiresAt?: string
  bindingDigest: string
}

type EndpointAuthorityRecordBaseV1 = {
  schemaVersion: 1
  endpointRegistrationId: string
  authorityRevision: number
  ownerPrincipalId: string
  sourceRequestId: string
  sourceRequestDigest: string
  registration: EndpointRegistrationV1
  expectedRegistrationArtifactRef: ArtifactRef
  createdAt: string
}

type EndpointAuthorityRecordV1 = EndpointAuthorityRecordBaseV1 & (
  | {
      state: 'active'
      revokedAt?: never
      revokedByRequestId?: never
      recordDigest: string
    }
  | {
      state: 'revoked'
      revokedAt: string
      revokedByRequestId: string
      revokedByRequestDigest: string
      recordDigest: string
    }
)

type EndpointAuthorityCommandCoreV1 =
  | {
      schemaVersion: 1
      kind: 'register'
      ownerPrincipalId: string
      registration: EndpointRegistrationV1
      expectedRegistrationArtifactRef: ArtifactRef
      commandDigest: string
    }
  | {
      schemaVersion: 1
      kind: 'revoke'
      ownerPrincipalId: string
      endpointRegistrationId: string
      expectedAuthorityRevision: number
      commandDigest: string
    }

type EndpointAuthorityOperationV1 = {
  schemaVersion: 1
  operationId: string
  requestId: string
  requestDigest: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  commandCore: EndpointAuthorityCommandCoreV1
  ownerPrincipalId: string
  kind: 'register' | 'revoke'
  endpointRegistrationId: string
  disposition: 'registered' | 'already_registered' | 'revoked' | 'already_revoked'
  committedAuthorityRevision: number
  resultRecordDigest: string
  committedAt: string
  operationDigest: string
}

type CredentialAuthorityRecordBaseV1 = {
  schemaVersion: 1
  credentialGrantId: string
  authorityRevision: number
  credentialServiceRevision: number
  ownerPrincipalId: string
  purpose: 'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'
  endpointRegistrationRef: ArtifactRef
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  credentialHandleIdentityDigest: string
  secretGeneration: number
  externalSubject: CredentialExternalSubjectV1
  externalSubjectDigest: string
  platformItem:
    | {
        kind: 'macos_keychain'
        service: 'ai.cogine.cliq.credentials.v1'
        accountId: string
      }
    | {
        kind: 'linux_secret_service'
        schema: 'org.freedesktop.Secret.Generic'
        collection: 'default'
        itemId: string
      }
  createdAt: string
  expiresAt?: string
}

type CredentialAuthorityRecordV1 = CredentialAuthorityRecordBaseV1 & (
  | {
      state: 'active'
      revokedAt?: never
      revokedByRequestId?: never
      recordDigest: string
    }
  | {
      state: 'revoked'
      revokedAt: string
      revokedByRequestId: string
      revokedByRequestDigest: string
      recordDigest: string
  }
)

type CredentialAuthorityCommandCoreV1 = {
  schemaVersion: 1
  ownerPrincipalId: string
  kind: 'enroll' | 'rotate'
  credentialGrantId: string
  purpose: 'model_endpoint' | 'dependency_registry' | 'mcp_streamable_http'
  endpointRegistrationRef: ArtifactRef
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  expiresAt?: string
  secretSubmissionId: string
  externalSubject: CredentialExternalSubjectV1
  externalSubjectDigest: string
  credentialTargetDigest: string
  commandDigest: string
}

type CredentialAuthorityOperationBaseV1 = {
  schemaVersion: 1
  operationId: string
  requestId: string
  requestDigest: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  commandCore: CredentialAuthorityCommandCoreV1
  attempt: 1 | 2 | 3
  ownerPrincipalId: string
  kind: 'enroll' | 'rotate'
  credentialGrantId: string
  credentialTargetDigest: string
  intendedAuthorityRevision: number
  intendedSecretGeneration: number
  intendedExternalSubjectDigest: string
  platformItem: CredentialAuthorityRecordBaseV1['platformItem']
  createdAt: string
  operationDigest: string
}

type CredentialAuthorityOperationV1 = CredentialAuthorityOperationBaseV1 & (
  | {
      phase: 'prepared' | 'secret_stored'
      committedAuthorityRevision?: never
      abortReason?: never
      finishedAt?: never
    }
  | {
      phase: 'committed'
      committedAuthorityRevision: number
      abortReason?: never
      finishedAt: string
    }
  | {
      phase: 'aborted'
      committedAuthorityRevision?: never
      abortReason: 'recovered_orphan' | 'platform_store_failed' | 'request_conflict'
      finishedAt: string
    }
)

type CredentialAuthorityRevokeCommandCoreV1 = {
  schemaVersion: 1
  kind: 'revoke'
  ownerPrincipalId: string
  credentialGrantId: string
  expectedAuthorityRevision: number
  credentialTargetDigest: string
  commandDigest: string
}

type CredentialAuthorityRevokeOperationBaseV1 = {
  schemaVersion: 1
  operationId: string
  requestId: string
  requestDigest: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  commandCore: CredentialAuthorityRevokeCommandCoreV1
  ownerPrincipalId: string
  credentialGrantId: string
  credentialTargetDigest: string
  disposition: 'revoked' | 'already_revoked'
  committedAuthorityRevision: number
  revokedRecordDigest: string
  platformItem: CredentialAuthorityRecordBaseV1['platformItem']
  metadataCommittedAt: string
  operationDigest: string
}

type CredentialAuthorityRevokeOperationV1 = CredentialAuthorityRevokeOperationBaseV1 & (
  | {
      cleanupPhase: 'metadata_committed'
      cleanupEvidenceDigest?: never
      cleanupErrorCode?: never
      cleanupFinishedAt?: never
    }
  | {
      cleanupPhase: 'cleanup_complete'
      cleanupEvidenceDigest: string
      cleanupErrorCode?: never
      cleanupFinishedAt: string
    }
  | {
      cleanupPhase: 'cleanup_failed'
      cleanupEvidenceDigest: string
      cleanupErrorCode: 'platform_store_unavailable' | 'delete_denied' | 'delete_failed'
      cleanupFinishedAt: string
    }
)

type InterpreterIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-interpreter-identity-v1'
  guestToolchainManifestRef: ArtifactRef
  guestToolchainManifestDigest: string
  toolId: string
  executionPath: string
  executableDigest: string
  version: string
  invocationProtocol: 'script_path_as_first_argument-v1'
  identityDigest: string
}

type AuthorizationGrantTargetV1 =
  | {
      kind: 'read_scope'
      purpose: 'source'
      workspaceIdentityDigest: string
      canonicalRootRelativePath: string
      scope: 'entry' | 'subtree'
      expectedDigest?: string
    }
  | {
      kind: 'execution_identity_read'
      purpose: 'verifier'
      identity:
        | {
            kind: 'guest_toolchain'
            guestToolchainManifestRef: ArtifactRef
            manifestDigest: string
            toolId: string
            executionPath: string
            executableDigest: string
          }
        | {
            kind: 'workspace_script'
            workspaceIdentityDigest: string
            canonicalRootRelativePath: string
            scriptDigest: string
            interpreterIdentityRef: ArtifactRef
            interpreterIdentityDigest: string
          }
    }
  | {
      kind: 'execution_identity_read'
      purpose: 'mcp_stdio'
      identity:
        | {
            kind: 'guest_toolchain'
            guestToolchainManifestRef: ArtifactRef
            manifestDigest: string
            toolId: string
            executionPath: string
            executableDigest: string
          }
        | {
            kind: 'runtime_bundle_executable'
            runtimeBundleRef: ArtifactRef
            runtimeBundleManifestDigest: string
            executableId: string
            executionPath: string
            executableDigest: string
          }
    }
  | {
      kind: 'verifier_execution'
      verifierId: string
      verifierRequestCoreDigest: string
      executionIdentityGrantId: string
      executionIdentityTargetDigest: string
      maxCandidateGenerations: number
      maxAttemptsPerCandidate: number
    }
  | {
      kind: 'dependency_install_scripts'
      workspaceIdentityDigest: string
      lockfilePath: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock'
      lockfileDigest: string
    }

type AuthorizationGrantBaseV1 = {
  schemaVersion: 1
  grantId: string
  ownerPrincipalId: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  sourceRequestId: string
  sourceRequestDigest: string
  target: AuthorizationGrantTargetV1
  targetDigest: string
  maxUses: 1
  rowVersion: number
  createdAt: string
  expiresAt: string
  grantCoreDigest: string
}

type AuthorizationGrantV1 = AuthorizationGrantBaseV1 & (
  | {
      state: 'active'
      useCount: 0
      consumptionReceiptRef?: never
      consumedAt?: never
      revokedByRequestId?: never
      revokedAt?: never
      rowDigest: string
    }
  | {
      state: 'consumed'
      useCount: 1
      consumptionReceiptRef: ArtifactRef
      consumedAt: string
      revokedByRequestId?: never
      revokedAt?: never
      rowDigest: string
    }
  | {
      state: 'revoked'
      useCount: 0
      consumptionReceiptRef?: never
      consumedAt?: never
      revokedByRequestId: string
      revokedAt: string
      rowDigest: string
    }
)

type AuthorizationConsumptionReceiptV1 = {
  schemaVersion: 1
  grantId: string
  ownerPrincipalId: string
  targetDigest: string
  consumer:
    | { kind: 'run_admission'; runId: string; admissionIntentDigest: string }
    | { kind: 'mcp_registration'; registrationId: string; registryRevision: number }
    | { kind: 'authorization_derivation'; derivedGrantId: string }
  consumedAt: string
  receiptDigest: string
}

type LocalModelManifestV1 = {
  schemaVersion: 1
  format: 'cliq-local-model-manifest-v1'
  signerKeyId: string
  signatureAlgorithm: 'ed25519'
  signatureRef: ArtifactRef
  provider: 'ollama'
  model: string
  architecture: string
  tokenizerRef: ArtifactRef
  tokenizerDigest: string
  files: Array<{
    canonicalRelativePath: string
    contentRef: ArtifactRef
    contentDigest: string
    sizeBytes: number
  }>
  claims: NormalizedModelCapabilityClaimsV1
  modelManifestDigest: string
}

type LocalModelObjectClosureV1 = {
  schemaVersion: 1
  format: 'cliq-local-model-object-closure-v1'
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  objectStoreRootRelativePath: 'local-models/objects'
  modelManifestRef: ArtifactRef
  modelManifestDigest: string
  objects: Array<
    | {
        kind: 'model_manifest'
        logicalPath: 'model-manifest.json'
        artifactRef: ArtifactRef
        artifactDigest: string
        sizeBytes: number
      }
    | {
        kind: 'tokenizer'
        logicalPath: 'tokenizer'
        artifactRef: ArtifactRef
        artifactDigest: string
        sizeBytes: number
      }
    | {
        kind: 'model_file'
        logicalPath: string
        artifactRef: ArtifactRef
        artifactDigest: string
        sizeBytes: number
      }
  >
  objectCount: number
  totalBytes: number
  closureDigest: string
}

type NormalizedModelCapabilityClaimsV1 = {
  nativeToolCalling: boolean
  streaming: boolean
  trustedUsageEvidence: boolean
  contextLimitTokens: number
  maxOutputTokens: number
}

type SignedModelCatalogEntryV1 = {
  schemaVersion: 1
  format: 'cliq-signed-model-catalog-entry-v1'
  signerKeyId: string
  signatureAlgorithm: 'ed25519'
  signatureRef: ArtifactRef
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
  model: string
  endpointIdentityDigest: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  claims: NormalizedModelCapabilityClaimsV1
  validFrom: string
  validThrough: string
  catalogEntryDigest: string
}

type EndpointModelNegotiationRequestV1 = {
  schemaVersion: 1
  format: 'cliq-endpoint-model-negotiation-request-v1'
  ownerPrincipalId: string
  endpointRegistrationRef: ArtifactRef
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  credentialGrantRefs: ArtifactRef[]
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
  model: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  protocol: 'cliq-model-capability-query-v1'
  requestedClaims: [
    'nativeToolCalling',
    'streaming',
    'trustedUsageEvidence',
    'contextLimitTokens',
    'maxOutputTokens'
  ]
  requestDigest: string
}

type EndpointModelNegotiationResponseV1 = {
  schemaVersion: 1
  format: 'cliq-endpoint-model-negotiation-response-v1'
  requestRef: ArtifactRef
  requestDigest: string
  protocol: 'cliq-model-capability-query-v1'
  claims: NormalizedModelCapabilityClaimsV1
  observedAt: string
  validThrough: string
  responseDigest: string
}

type EndpointModelNegotiationReceiptV1 = {
  schemaVersion: 1
  format: 'cliq-endpoint-model-negotiation-v1'
  ownerPrincipalId: string
  endpointRegistrationRef: ArtifactRef
  endpointIdentityDigest: string
  tlsPolicyDigest: string
  credentialGrantRefs: ArtifactRef[]
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
  model: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  normalizedRequestRef: ArtifactRef
  normalizedRequestDigest: string
  redactedResponseRef: ArtifactRef
  redactedResponseDigest: string
  claims: NormalizedModelCapabilityClaimsV1
  observedAt: string
  validThrough: string
  receiptDigest: string
}

type ModelCapabilityEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-model-capability-evidence-v1'
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu' | 'ollama'
  model: string
  endpointIdentityDigest: string
  adapter: { adapterId: string; version: string; codeDigest: string }
  source:
    | {
        kind: 'signed_catalog'
        runtimeBundleRef: ArtifactRef
        catalogEntryRef: ArtifactRef
        catalogEntryDigest: string
      }
    | {
        kind: 'registered_endpoint_negotiation'
        endpointRegistrationRef: ArtifactRef
        negotiationReceiptRef: ArtifactRef
        negotiationReceiptDigest: string
      }
    | {
        kind: 'managed_local'
        localInferenceServiceSpecRef: ArtifactRef
        localInferenceServiceSpecDigest: string
        localModelManifestRef: ArtifactRef
        localModelManifestDigest: string
      }
  nativeToolCalling: boolean
  streaming: boolean
  trustedUsageEvidence: boolean
  contextLimitTokens: number
  maxOutputTokens: number
  observedAt: string
  validThrough: string
  evidenceDigest: string
}

type LocalInferenceServiceSpecV1 = {
  schemaVersion: 1
  format: 'cliq-local-inference-service-v1'
  serviceId: string
  ownerPrincipalId: string
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  executableId: string
  executableVersion: string
  executableDigest: string
  modelManifestRef: ArtifactRef
  modelManifestDigest: string
  endpoint: { scheme: 'http'; host: '127.0.0.1' | '[::1]'; port: number }
  backend: 'macos_vm' | 'linux_namespace'
  sandboxProfileRef: ArtifactRef
  sandboxProfileDigest: string
  resources: SandboxResourceSpec
  createdAt: string
  serviceSpecCoreDigest: string
  serviceSpecDigest: string
}

type LocalModelRegistrationBaseV1 = {
  schemaVersion: 1
  format: 'cliq-local-model-registration-v1'
  ownerPrincipalId: string
  provider: 'ollama'
  model: string
  registryRevision: number
  serviceId: string
  serviceSpec: LocalInferenceServiceSpecV1
  expectedServiceSpecRef: ArtifactRef
  modelManifest: LocalModelManifestV1
  expectedModelManifestRef: ArtifactRef
  objectClosure: LocalModelObjectClosureV1
  expectedObjectClosureRef: ArtifactRef
  createdAt: string
}

type LocalModelRegistrationV1 = LocalModelRegistrationBaseV1 & (
  | { state: 'active'; retiredAt?: never; registrationDigest: string }
  | { state: 'retired'; retiredAt: string; registrationDigest: string }
)

type LocalModelRegistryHeadBaseV1 = {
  schemaVersion: 1
  format: 'cliq-local-model-registry-head-v1'
  ownerPrincipalId: string
  provider: 'ollama'
  model: string
  headRevision: number
  committedAt: string
  headDigest: string
}

type LocalModelRegistryHeadV1 =
  | (LocalModelRegistryHeadBaseV1 & {
      transition: 'initial'
      state: 'active'
      headRevision: 1
      predecessorHeadRef?: never
      predecessorHeadDigest?: never
      activeRegistrationRef: ArtifactRef
      activeRegistrationDigest: string
      retiredRegistrationRef?: never
      retiredRegistrationDigest?: never
    })
  | (LocalModelRegistryHeadBaseV1 & {
      transition: 'replace'
      state: 'active'
      predecessorHeadRef: ArtifactRef
      predecessorHeadDigest: string
      activeRegistrationRef: ArtifactRef
      activeRegistrationDigest: string
      retiredRegistrationRef: ArtifactRef
      retiredRegistrationDigest: string
    })
  | (LocalModelRegistryHeadBaseV1 & {
      transition: 'retire'
      state: 'retired'
      predecessorHeadRef: ArtifactRef
      predecessorHeadDigest: string
      activeRegistrationRef?: never
      activeRegistrationDigest?: never
      retiredRegistrationRef: ArtifactRef
      retiredRegistrationDigest: string
    })
  | (LocalModelRegistryHeadBaseV1 & {
      transition: 'reenroll'
      state: 'active'
      predecessorHeadRef: ArtifactRef
      predecessorHeadDigest: string
      activeRegistrationRef: ArtifactRef
      activeRegistrationDigest: string
      retiredRegistrationRef?: never
      retiredRegistrationDigest?: never
    })

type LocalInferenceActivationParticipantV1 =
  | {
      kind: 'run_submission'
      requestId: string
      requestDigest: string
      runSubmitRequestRef: ArtifactRef
      admissionKey: string
      admissionIntentDigest: string
      joinedAt: string
    }
  | {
      kind: 'run_model_frontier'
      runId: string
      runRevisionAtJoin: number
      frontierRef: ArtifactRef
      joinedAt: string
    }

type LocalInferenceActivationFailureV1 = {
  schemaVersion: 1
  activationCycleId: string
  ownerPrincipalId: string
  serviceId: string
  serviceSpecRef: ArtifactRef
  serviceSpecDigest: string
  finalAttempt: 1 | 2
  reason:
    | 'activation_timeout'
    | 'sandbox_launch_failed'
    | 'health_mismatch'
    | 'capability_mismatch'
    | 'containment_unprovable'
  launchIds: string[]
  evidenceRefs: ArtifactRef[]
  observedAt: string
  failureDigest: string
}

type LocalInferenceActivationCycleBaseV1 = {
  schemaVersion: 1
  activationCycleId: string
  ownerPrincipalId: string
  serviceId: string
  serviceSpecRef: ArtifactRef
  serviceSpecDigest: string
  cycleOrdinal: number
  participants: LocalInferenceActivationParticipantV1[]
  rowVersion: number
  createdAt: string
}

type LocalInferenceActivationCycleV1 = LocalInferenceActivationCycleBaseV1 & (
  | {
      phase: 'starting_launch'
      activationAttempt: 1 | 2
      launchIds: string[]
      currentLaunchId: string
      retryNotBeforeAt?: never
      boundaryEvidenceRef?: never
      failureDetailRef?: never
      finishedAt?: never
      cycleDigest: string
    }
  | {
      phase: 'retry_wait'
      activationAttempt: 1
      launchIds: [string]
      currentLaunchId?: never
      retryNotBeforeAt: string
      boundaryEvidenceRef?: never
      failureDetailRef?: never
      finishedAt?: never
      cycleDigest: string
    }
  | {
      phase: 'active'
      activationAttempt: 1 | 2
      launchIds: string[]
      currentLaunchId: string
      retryNotBeforeAt?: never
      boundaryEvidenceRef: ArtifactRef
      failureDetailRef?: never
      finishedAt: string
      cycleDigest: string
    }
  | {
      phase: 'failed'
      activationAttempt: 1 | 2
      launchIds: string[]
      currentLaunchId?: never
      retryNotBeforeAt?: never
      boundaryEvidenceRef?: never
      failureDetailRef: ArtifactRef
      finishedAt: string
      cycleDigest: string
    }
)

type LocalInferenceServiceLaunchBaseV1 = {
  schemaVersion: 1
  serviceId: string
  launchId: string
  ownerPrincipalId: string
  serviceSpecRef: ArtifactRef
  serviceSpecDigest: string
  supervisorInstanceId: string
  activationCycleId: string
  activationAttempt: 1 | 2
  activationNonceDigest: string
  containmentPlanRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  rowVersion: number
  leaseVersion: number
  createdAt: string
  activationDeadlineAt: string
}

type LocalInferenceServiceLaunchV1 = LocalInferenceServiceLaunchBaseV1 & (
  | {
      phase: 'reserved'
      processContainmentRef?: never
      boundaryEvidenceRef?: never
      leaseExpiresAt?: never
      quiesceId?: never
      retirementEvidenceRef?: never
      retiredAt?: never
    }
  | {
      phase: 'preactivated'
      processContainmentRef: ArtifactRef
      boundaryEvidenceRef?: never
      leaseExpiresAt?: never
      quiesceId?: never
      retirementEvidenceRef?: never
      retiredAt?: never
    }
  | {
      phase: 'active'
      processContainmentRef: ArtifactRef
      boundaryEvidenceRef: ArtifactRef
      leaseExpiresAt: string
      quiesceId?: never
      retirementEvidenceRef?: never
      retiredAt?: never
    }
  | {
      phase: 'revoking'
      processContainmentRef: ArtifactRef
      boundaryEvidenceRef: ArtifactRef
      leaseExpiresAt?: never
      quiesceId: string
      retirementEvidenceRef?: never
      retiredAt?: never
    }
  | {
      phase: 'retired'
      retirementKind: 'no_spawn'
      processContainmentRef?: never
      boundaryEvidenceRef?: never
      leaseExpiresAt?: never
      quiesceId?: never
      retirementEvidenceRef: ArtifactRef
      retiredAt: string
    }
  | {
      phase: 'retired'
      retirementKind: 'death'
      processContainmentRef: ArtifactRef
      boundaryEvidenceRef?: ArtifactRef
      leaseExpiresAt?: never
      quiesceId: string
      retirementEvidenceRef: ArtifactRef
      retiredAt: string
    }
)

type ModelPriceTableV1 = {
  schemaVersion: 1
  format: 'cliq-model-price-table-v1'
  signerKeyId: string
  signatureAlgorithm: 'ed25519'
  signatureRef: ArtifactRef
  provider: RunAssemblyV1['provider']['name']
  model: string
  endpointIdentityDigest: string
  currency: 'USD'
  unit: 'micros_per_million_tokens'
  prices: {
    input: number
    output: number
    cacheRead: number
    cacheWrite: number
  }
  requestTokenCeiling: {
    inputTokens: number
    outputTokens: number
    cacheReadTokens: number
    cacheWriteTokens: number
  }
  validFrom: string
  validThrough: string
  tableDigest: string
}

type LocalInferenceBoundaryEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-local-inference-boundary-v1'
  ownerPrincipalId: string
  serviceId: string
  serviceSpecRef: ArtifactRef
  serviceSpecDigest: string
  serviceLaunchId: string
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  executableId: string
  executableDigest: string
  modelManifestRef: ArtifactRef
  modelManifestDigest: string
  processContainmentRef: ArtifactRef
  containmentPlanRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  backend: 'macos_vm' | 'linux_namespace'
  externalNetworkEgress: 'denied'
  loopbackOnly: true
  stableServiceIdentityDigest: string
  inspectorSupervisorInstanceId: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  validThrough: string
  evidenceDigest: string
}

type LocalZeroCostProvenanceV1 = {
  schemaVersion: 1
  format: 'cliq-local-zero-cost-v1'
  ownerPrincipalId: string
  provider: 'ollama'
  model: string
  serviceSpecRef: ArtifactRef
  serviceSpecDigest: string
  stableServiceIdentityDigest: string
  endpoint: { scheme: 'http'; host: '127.0.0.1' | '[::1]'; port: number }
  endpointIdentityDigest: string
  boundaryEvidenceRef: ArtifactRef
  boundaryEvidenceDigest: string
  capabilityEvidenceRef: ArtifactRef
  capabilityDigest: string
  createdAt: string
  validThrough: string
  provenanceDigest: string
}

type ModelPricingBound =
  | {
      kind: 'zero_cost'
      maxRunCostMicros: 0
      provenanceRef: ArtifactRef
    }
  | {
      kind: 'trusted_price_table'
      priceTableRef: ArtifactRef
      priceTableDigest: string
      calculationAlgorithm: 'cliq-price-ceil-v1'
      maxRunCostMicros: number
      validThrough: string
      provenanceRef: ArtifactRef
    }

type WorkspaceInstructionSourceManifestV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-instruction-source-v1'
  workspaceIdentityRef: ArtifactRef
  workspaceIdentityDigest: string
  entries: Array<{
    canonicalRootRelativePath: string
    directoryDepth: number
    fileDescriptor: {
      deviceId: string
      fileId: string
      ownerUid: number
      mode: 384 | 420
      linkCount: 1
    }
    rawBytesRef: ArtifactRef
    rawBytesDigest: string
    rawByteCount: number
    sourceEntryDigest: string
  }>
  capturedAt: string
  sourceDigest: string
}

type WorkspaceInstructionManifestV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-instructions-v1'
  workspaceIdentityDigest: string
  instructionSourceRef: ArtifactRef
  instructionSourceDigest: string
  rendering: 'cliq-all-scopes-labeled-instructions-v1'
  entries: Array<{
    order: number
    canonicalRootRelativePath: string
    appliesToSubtree: true
    directoryDepth: number
    instructionSourceEntryDigest: string
    contentRef: ArtifactRef
    contentDigest: string
  }>
  manifestDigest: string
}

type BundledSkillClosureV1 = {
  schemaVersion: 1
  format: 'cliq-bundled-skill-closure-v1'
  skillId: string
  files: Array<{
    canonicalRelativePath: string
    rawBytesRef: ArtifactRef
    rawBytesDigest: string
    rawByteCount: number
  }>
  closureDigest: string
}

type SkillSourceFileBytesV1 = {
  canonicalRelativePath: string
  rawBytesRef: ArtifactRef
  rawBytesDigest: string
  rawByteCount: number
}

type DescriptorCapturedSkillSourceFileV1 = SkillSourceFileBytesV1 & {
  fileDescriptor: {
    deviceId: string
    fileId: string
    ownerUid: number
    mode: 384 | 420 | 448 | 493
    linkCount: 1
  }
  sourceEntryDigest: string
}

type BundledSkillSourceFileV1 = SkillSourceFileBytesV1 & {
  sourceEntryDigest: string
}

type SkillSourceIdentityBaseV1 = {
  schemaVersion: 1
  format: 'cliq-skill-source-identity-v1'
  skillId: string
  sourceIdentityDigest: string
}

type SkillSourceIdentityV1 = SkillSourceIdentityBaseV1 & (
  | {
      sourceScope: 'workspace'
      workspaceIdentityRef: ArtifactRef
      workspaceIdentityDigest: string
      files: DescriptorCapturedSkillSourceFileV1[]
      rootDescriptor: {
        canonicalRootRelativePath: string
        deviceId: string
        fileId: string
        ownerUid: number
        mode: 448 | 493
      }
    }
  | {
      sourceScope: 'user'
      ownerPrincipalId: string
      principalIdentityRef: ArtifactRef
      principalIdentityDigest: string
      files: DescriptorCapturedSkillSourceFileV1[]
      rootDescriptor: {
        canonicalAbsolutePath: string
        deviceId: string
        fileId: string
        ownerUid: number
        mode: 448
      }
    }
  | {
      sourceScope: 'bundled'
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      bundleEntryId: string
      bundleEntryVersion: string
      bundledClosureRef: ArtifactRef
      bundledClosureDigest: string
      files: BundledSkillSourceFileV1[]
    }
)

type SkillManifestV1 = {
  schemaVersion: 1
  format: 'cliq-skill-manifest-v1'
  skillId: string
  sourceScope: 'bundled' | 'user' | 'workspace'
  sourceIdentityRef: ArtifactRef
  sourceIdentityDigest: string
  instructionRef: ArtifactRef
  instructionDigest: string
  resources: Array<{
    canonicalRelativePath: string
    kind: 'text' | 'schema' | 'template' | 'executable-disabled'
    contentRef: ArtifactRef
    contentDigest: string
  }>
  manifestDigest: string
}

type ToolContractManifestV1 = {
  schemaVersion: 1
  format: 'cliq-tool-contracts-v1'
  entries: Array<{
    name: string
    version: string
    description: string
    access: 'read' | 'write' | 'exec' | 'plan' | 'control'
    inputSchemaRef: ArtifactRef
    inputSchemaDigest: string
    outputSchemaRef?: ArtifactRef
    outputSchemaDigest?: string
  } & (
      | {
          replayClass: 'manual' | 'retry'
          execution: {
            kind: 'builtin'
            adapterId: string
            adapterVersion: string
            adapterCodeDigest: string
          }
        }
      | {
          replayClass: ReplayClass
          execution: {
            kind: 'mcp'
            registrationId: string
            registryRevisionRef: ArtifactRef
            registryManifestDigest: string
            serverToolName: string
            toolContractDigest: string
          }
        }
    )>
  manifestDigest: string
}

type ProviderContinuation = {
  provider: RunAssemblyV1['provider']['name']
  model: string
  items: unknown[] // opaque provider reasoning/signature material, never tool authority
}

type ObservedToolArguments =
  | { encoding: 'jcs_json'; value: unknown; utf8?: never }
  | { encoding: 'utf8_json_fragment'; utf8: string; value?: never }

type NormalPromptToolCallV1 = {
  callId: string
  index: number
  toolName: string
  inputRef: ArtifactRef
  inputDigest: string
  arguments: ObservedToolArguments
}

type NormalPromptMessageV1 =
  | {
      index: number
      role: 'system' | 'user'
      sourceKind:
        | 'assembly_instructions'
        | 'session_terminal'
        | 'session_summary'
        | 'parent_context'
        | 'additional_context'
        | 'run_objective'
        | 'run_summary'
        | 'user_input'
        | 'verifier_repair'
        | 'child_result'
      sourceId: string
      contentUtf8: string
    }
  | {
      index: number
      role: 'assistant'
      sourceItemId: string
      contentUtf8: string
      toolCalls: NormalPromptToolCallV1[]
      continuation?: ProviderContinuation
    }
  | {
      index: number
      role: 'tool'
      sourceItemId: string
      toolCallId: string
      contentUtf8: string
    }

type NormalPromptProjectionV1 = {
  schemaVersion: 1
  format: 'cliq-normal-prompt-projection-v1'
  runId: string
  basedOnRunRevision: number
  frontierDigest: string
  runSpecRef: ArtifactRef
  assemblyRef: ArtifactRef
  assemblyDigest: string
  contextManifestRef: ArtifactRef
  contextManifestDigest: string
  messages: NormalPromptMessageV1[]
  tools: Array<{
    index: number
    name: string
    description: string
    inputSchemaRef: ArtifactRef
    inputSchemaDigest: string
    inputSchema: unknown
  }>
  projectionDigest: string
}

type ModelRequestV1 = {
  schemaVersion: 1
  format: 'cliq-model-request-v1'
  kind: 'normal' | 'context_compaction'
  runId: string
  opId: string
  attempt: number
  assemblyRef: ArtifactRef
  assemblyDigest: string
  provider: RunAssemblyV1['provider']['name']
  model: string
  negotiatedMode: 'native-tools' | 'text-only'
  promptProjectionRef: ArtifactRef
  promptProjectionDigest: string
  compactionPlanRef?: ArtifactRef
  requestPath: string
  mediaType: 'application/json'
  bodyBytesRef: ArtifactRef
  bodyByteCount: number
  streaming: boolean
  maximumOutputTokens: number
  estimatedInputTokens: number
  reservation: {
    inputTokens: number
    outputTokens: number
    cacheReadTokens: number
    cacheWriteTokens: number
    modelTokens: number
    costMicros: number
  }
  requestDigest: string
}

type RunAssemblyV1 = {
  schemaVersion: 1
  format: 'cliq-run-assembly-v1'
  provider: {
    name: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu' | 'ollama'
    model: string
    endpoint:
      | {
          kind: 'local_zero_cost'
          identityDigest: string
          localProvenanceRef: ArtifactRef
        }
      | {
          kind: 'registered'
          registrationKind: 'bundled_default' | 'user'
          endpointRegistrationRef: ArtifactRef
          endpointIdentityDigest: string
          tlsPolicyDigest: string
        }
    credentialGrantRefs: ArtifactRef[]
    adapter: { adapterId: string; version: string; codeDigest: string }
    negotiation: {
      mode: 'native-tools' | 'text-only'
      capabilityEvidenceRef: ArtifactRef
      capabilityDigest: string
      nativeToolCalling: boolean
      streaming: boolean
      trustedUsageEvidence: boolean
      contextLimitTokens: number
      maxOutputTokens: number
      exposedToolNames: string[]
    }
    pricing: ModelPricingBound
  }
  mcpServers: Array<{
    registrationId: string
    registryRevisionRef: ArtifactRef
    registryRevision: number
    manifestDigest: string
  }>
  tools: {
    manifestRef: ArtifactRef
    manifestDigest: string
  }
  instructions: {
    systemPromptRef: ArtifactRef
    systemPromptDigest: string
    workspaceInstructionsRef: ArtifactRef
    workspaceInstructionsDigest: string
    skills: Array<{ skillId: string; manifestRef: ArtifactRef; manifestDigest: string }>
  }
  runtime: {
    runtimeBundleRef: ArtifactRef
    runtimeBundleManifestDigest: string
    workerExecutableId: string
    workerExecutableDigest: string
    sandboxBackend: 'macos_vm' | 'linux_namespace'
    guestToolchainManifestRef?: ArtifactRef
    guestToolchainManifestDigest?: string
  }
  retry: {
    model: {
      maxDispatchedAttempts: 3
      maxZeroByteTransportRetriesPerAttempt: 0
      postAttemptDelaysMs: [500, 2000]
    }
    tools: Array<
      | { toolName: string; replayClass: 'retry'; maxDispatchedAttempts: 3; postAttemptDelaysMs: [500, 2000] }
      | { toolName: string; replayClass: 'workspace-rollback-retry'; maxDispatchedAttempts: 2; postAttemptDelaysMs: [500] }
      | { toolName: string; replayClass: 'reconcile' | 'manual'; maxDispatchedAttempts: 1; postAttemptDelaysMs: [] }
    >
  }
  context: {
    compactionPromptEnvelopeRef: ArtifactRef
    compactionPromptEnvelopeDigest: string
    contextLimitTokens: number
    reservedOutputTokens: number
    hardPromptTokens: number
    triggerThresholdTokens: number
    protectedRecentTokens: number
    summaryTokenCap: number
    compactionEnvelopeTokens: number
    sourceInputTokenCap: number
    maxSummaryBytes: 262144
  }
  assemblyDigest: string
  createdAt: string
}
```

`RunSpec.objectiveRef` always decodes exact `RunObjectiveV1`.
`objectiveDigest = SHA-256(JCS(objective with objectiveDigest omitted))`;
`utf8` is the NFC-normalized public objective, contains no NUL or unpaired
surrogate, has exact UTF-8 `byteCount` in `1..262144`, and is published exactly
once during admission. The final admitted request digest and every normal model
prompt bind that ref; no worker rereads the inline request, ambient argv, or a
Session label to reconstruct the objective.

`policyRef` resolves only to `RunPolicySnapshotV1`. The snapshot is compiled after Workspace Trust from the authenticated principal's selected public `policyMode`, the exact admitted workspace identity, and the frozen `ToolContractManifestV1`; public or repository bytes cannot supply the artifact ref. `policyDigest = SHA-256(JCS(snapshot with policyDigest omitted))`, the tool ref/digest equals the Run assembly, `repositoryRequestRefs` is unique/byte-sorted, and repository requests may only change `allow -> ask|deny` or `ask -> deny`. They can never widen a mode. `PolicyEngineProfileV1.profileDigest` omits itself. `engine.runtimeBundleRef` equals `RunAssemblyV1.runtime.runtimeBundleRef`; `profileEntryId` and `engine.version` equal that bundle's sole signed, **non-executable** `policy_engine` data-profile entry, the entry's signed complete-file digest equals `profileRef`, and decoding those exact retained bytes yields `PolicyEngineProfileV1` whose independently recomputed self-omitting `profileDigest` equals `engine.profileDigest`. The complete-byte `profileRef` and semantic `profileDigest` are distinct hash domains and are never required to equal. Fixed signed Supervisor code alone interprets `cliq-policy-evaluator-v1`, `cliq-permission-grammar-v0`, and `cliq-bash-head-parser-v1`. The profile is never spawned or loaded as native/in-process plugin code, so no SandboxLaunchSpec branch is required. Recovery uses the retained profile plus the pinned Supervisor implementation; mutable installed code, an executable policy helper, or semantic-version compatibility alone is not authority. The complete v1 mode table is:

| mode | `allow` | `ask` | `deny` |
|---|---|---|---|
| `default` | `read`, `plan` | `write`, `exec`, `mcp`, `verifier`, `dependency_install_scripts`, `delivery`, `child_read_only`, `child_mutating` | none |
| `accept-edits` | `read`, `plan`, `write`, `child_read_only` | `exec`, `mcp`, `verifier`, `dependency_install_scripts`, `delivery`, `child_mutating` | none |
| `plan` | `read`, `plan`, `child_read_only` | none | `write`, `exec`, `mcp`, `verifier`, `dependency_install_scripts`, `delivery`, `child_mutating` |
| `yolo` | every listed class | none | none |

The closed builtin `request_input` contract has `access='control'` and no
`PolicyActionClass`; section 9.3 owns its authenticated input transition.
It does not enter this permission table or produce an OperationGrant.

The v1 builtin floor is the ordered prefix `builtin:bash:rm` (`bash`, `rm`),
`builtin:fs-write:git-tree` (`fs-write`, `.git/*`), and
`builtin:fs-write:git-root` (`fs-write`, `.git`), all `deny`, with orders 0–2
and no source ref. Frozen non-builtin rules follow that prefix; a snapshot
cannot remove, replace or relabel it.

RuntimeBundle signature encoding is standard padded base64 of a 64-byte
Ed25519 signature. It covers UTF-8 `cliq-runtime-bundle-v1`, one NUL byte, and
the lower-case 64-hex `manifestDigest` (not raw digest bytes or a `sha256:`
prefix). The trusted release key set is Supervisor composition authority, never
loaded from the Run, repository, worker or control request. Checking the selected
signed entries/profile does not replace WP06's full bundle installation and
structured-root walk or WP03's executing-process/broker identity checks.

The action classifier is closed: built-in tools use their manifest `access`, except `delegate` becomes `child_read_only|child_mutating`; any MCP tool is `mcp`; verifier, install-script, delivery-plan, and child admission use their named classes. Kernel Cut exposes no generic network/integration tool or child endpoint capability: model, dependency registry, and streamable-HTTP MCP access remain their own typed broker contracts. `decisionRules` freezes `cliq-permission-grammar-v0`, not an opaque policy program: contiguous unique order/rule ids, at most 256 entries/1 MiB, one listed channel, and a nonempty pattern using only exact `*`, literal, suffix ` *`, or suffix `/*` semantics (`**` has no glob meaning). Channel primary keys are canonical root-relative paths for `fs-*`, the trusted parsed command head for `bash`, `registrationId/serverToolName` for MCP, and normalized plan identity for plan channels. Kernel Cut drops the unimplemented `network` channel.

Every evaluation first publishes exact `PolicyChannelEvidenceV1`; there is no ephemeral parser result or adapter-owned matcher input. `evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`. Its policy ref/digest rehashes the current RunSpec snapshot; principal/Run/frontier/op/request/target equal the exact prospective subject and immutable artifacts; action class is the closed classifier result; and `evaluatedAt` uses canonical time before any approval, grant, denial item, Journal preparation, or target I/O. The fixed Supervisor evaluator plus retained `policy_engine` profile is the sole producer. Storage reruns that exact interpreter/profile over the immutable request/target and compares the full JCS output; a mutable installed parser, caller primary key, worker boolean, executable plugin, or semver-compatible engine is invalid.

Channel extraction is exact. Filesystem evidence contains the nonempty unique byte-sorted all-and-only canonical admitted-root-relative paths touched by the normalized request; matching evaluates every path and uses the strongest result (`deny > ask > allow`). MCP evidence copies the registration id/server tool name from the exact selected tool contract. Plan evidence copies the fixed normalized plan identity from the typed request/target. Bash evidence copies exactly one closed input projection from the schema-normalized built-in shell request: `argv` is its nonempty ordered argv array and `shell_text` is its exact NFC/no-NUL command string; neither form may be synthesized from the other. The deterministic `cliq-bash-head-parser-v1` emits the optional outer executable head, every nested builtin-deny head in lexical occurrence order, and `unsafeForAllow`. Heads are NFC/no-NUL strings of at most 4096 UTF-8 bytes; the nested list is at most 64 and contains no duplicate occurrence tuple. The parser recognizes the fixed bundled shell grammar and wrappers in golden fixtures; unsupported/dynamic/ambiguous syntax yields no trusted outer head and `unsafeForAllow=true`, never an implementation guess. Artifact recovery uses these retained bytes and exact profile output rather than reparsing with a host shell or changed repository configuration.

Every action class without a filesystem/bash/MCP/plan primary key uses the closed `named-action` branch. `verifier` repeats the candidate/plan/verifier fields; `dependency_install_scripts` repeats the plan/lock digest; `delivery` repeats the plan/operation-set digest; `mcp_server_launch` repeats the registry/lifecycle/originating call identity; and `child_read_only|child_mutating` repeats the owning delegate call plus exact requested mode. `identityKey` is respectively `verifier/<verifierId>`, `dependency_install_scripts/<lockfileDigest>`, `delivery/<operationSetDigest>`, `mcp_server_launch/<registryManifestDigest>/<base-10 lifecycleSeq>`, or `child/<read_only|mutating>` using literal ASCII separators and no escaping. Branch kind/fields must equal the prospective ApprovalSubject/OperationGrant/request/target; action class must be the corresponding named class (`mcp` for server launch). The equality is exhaustive: verifier ask/grant fields repeat candidate, result source, plan, index, verifier id/spec/required; dependency repeats plan, lock digest, result source, and literal `installScripts=true`; delivery repeats plan/digest and operation-set digest; MCP-server repeats revision/manifest/lifecycle/originating batch-call-index; and a delegate remains `kind='tool_call'` but requires `policySubjectKind='child_delegate'` plus the exact child mode in both ApprovalSubject and OperationGrant. Every non-delegate tool requires `policySubjectKind='ordinary_tool'` and forbids `childMode`. A named-action rule may match only this key; mode fallthrough is otherwise exact. There is no untyped subject, omitted named identity, or implementation-selected channel.

Rule precedence is deterministic: first matching builtin deny, then other deny, then allow, then ask, then the mode table. Empty/unidentifiable Bash command heads match only deny; `unsafeForAllow=true` converts a matching allow into ask, and every nested builtin-deny head is checked against deny before the outer head. Repository-request rules may only be ask/deny; CLI/authenticated user/session rules may allow; builtin deny cannot be overridden. `hook` is intentionally not a policy source: legacy repository hooks are migration diagnostics only and can neither appear in this union nor mint a grant. Every non-builtin rule stores its immutable source ref, and `repositoryRequestRefs` is exactly the byte-sorted unique set for repository rules. Evidence with `decisionSource='rule'` names exactly the single winning rule; `mode_fallthrough` requires an empty list. Its effective disposition is the recomputed precedence result. `allow` may mint only the exact operation grant below; `ask` embeds the same evidence ref/digest in the `ApprovalSubject`; and `deny` embeds it in `PolicyDecisionItem` while invoking that subject kind's normalized no-I/O denial reducer. `ApprovalDecisionV1.subject` and an approval-derived grant preserve that pair unchanged. `yolo` still cannot bypass builtin deny, Workspace Trust, source/read/executable identity, credential, budget, sandbox, supported-platform, or replay gates. A recovered Run reuses the immutable snapshot/evaluator and frozen channel evidence; it never reparses against a host shell or mutable repo/user configuration.

Every Journal/Broker `grantRef` resolves only to `OperationGrantV1`; policy decisions, approval text, verifier templates, or opaque authorization rows are not substitutes. `grantDigest = SHA-256(JCS(grant with grantDigest omitted))`; `grantId` is unique for `(runId,opId,requestDigest,subject,issuedAt)`. Every principal-owned `AuthorizationGrantV1` additionally retains the authenticated `channelIdentityRef/channelIdentityDigest` that created it; storage rehashes that exact principal/client artifact and the matching `control_requests` row before consumption. The Run/principal/policy/frontier/op/request/target and subject fields must byte-match the current immutable request, tool/model/verifier/MCP/delivery/dependency plan, and originating batch/index. For policy provenance, storage decodes and revalidates the exact channel evidence, requires its precedence result is `allow`, and requires grant action class/rule ids/request/target/policy/frontier/op plus evidence ref/digest to equal it byte-for-byte. `decisionDigest = SHA-256(JCS({policyRef,channelEvidenceRef,channelEvidenceDigest,actionClass,requestDigest,targetDigest,matchedRuleIds,effectiveDisposition:'allow'}))`; checking only a coarse mode or reparsing a command is forbidden. A user grant's `decisionRef` decodes only to the exact committed allow `ApprovalDecisionV1` for the current WaitingSubject/request/frontier, its channel-evidence pair equals the decoded subject and grant provenance, and the grant expiry equals its `grantExpiresAt`; a decision ref cannot cross a wait, parser result, or target. A verifier-template `decisionRef` decodes instead to the exact consumed `AuthorizationConsumptionReceiptV1` that created the template, and a candidate grant requires that template, candidate ordinal, and result source. A model grant derives only from the exact Run assembly/model frontier and authorizes no non-model target. A scriptless dependency grant derives from the exact immutable dependency policy/plan; a script-bearing one uses only `dependency_install_scripts_template` provenance and requires the exact template/policy/plan plus a previously unused candidate ordinal in `0..maxCandidateGenerations-1`. `maxDispatchedAttempts` is `1..5` and no greater than the assembly/tool/verifier/plan bound, except the approval-only `delivery_plan` parent grant is exactly `0` because it performs no I/O. `maxLaunches` is required only for `mcp_server_launch` (`1..3`) and forbidden otherwise.

Delivery approval never supplies a stale frontier grant to a path operation. It mints one `delivery_plan` parent grant bound to the approval frontier and exact complete operation-set digest, with `expiresAt = Run.deadlineAt` regardless of a shorter ordinary approval TTL. As each immutable forward/abort operation becomes current, the state reducer derives a fresh `publication_path` grant whose `frontierRef`, sequence/index/id/request/target and `opId` match that exact path frontier and whose provenance names the parent grant plus allow `DeliveryDecisionItem`; its expiry equals the parent's. The parent authorizes derivation only; it is never accepted by `claimDispatch`. A changed plan/branch/index/decision, expired parent, or child expiry beyond the parent cannot derive a grant. This avoids mid-plan reapproval while keeping authority bounded by the already-approved immutable plan and absolute Run deadline. Usage is derived from immutable Journal attempts or matching MCP lifecycle rows that name the exact grant—there is no resettable counter artifact. Other grants have `expiresAt <= Run.deadlineAt`, no renewal or target substitution is legal, and a replacement grant is a new artifact. Both dispatch gates validate this entire closure, current use count, expiry, stop/deadline, and exact frontier; post-dispatch evidence may describe reality but cannot reuse the grant for I/O.

`EndpointRegistrationV1` is the only registered remote target. `purposes` and SPKI pins are nonempty, unique, and byte-sorted; the HTTPS host is lower-case IDNA ASCII without userinfo/trailing dot, port is explicit `1..65535`, and `basePath` is an absolute normalized path with no query, fragment, backslash, encoded separator, or dot segment. Server name follows the same host normalization. Kernel Cut accepts only the Cliq-signed RuntimeBundle entry `entryId='default_https_trust_store', role='trust_store', executable=false`; the TLS fields repeat that bundle ref/manifest digest, the entry's CAS content ref/digest, and no user/custom/system-ambient CA path is accepted. SPKI pins may only narrow that retained trust root. `tlsPolicyDigest = SHA-256(JCS(tls))`, `endpointIdentityDigest = SHA-256(JCS({target,tlsPolicyDigest}))`, and `registrationDigest = SHA-256(JCS(registration with registrationDigest omitted))`. A ref may serve a purpose only when its owner/purpose/identity/TLS fields match exactly; bundled defaults are immutable registrations created for the same local principal, not ambient URLs.

The external endpoint registry stores exactly `EndpointAuthorityRecordV1` plus `EndpointAuthorityOperationV1` in credential `authority.sqlite`; it does not hide another endpoint schema. Registration/owner/id in the inline `registration` equal the row, `expectedRegistrationArtifactRef` is the content-addressed ref of those exact JCS bytes, and `recordDigest` omits itself. `commandDigest = SHA-256(JCS(command core with commandDigest omitted))`, `requestDigest` equals it, `operationId = H(ownerPrincipalId,requestId,requestDigest)`, and `operationDigest` omits itself. The operation's `channelIdentityRef/channelIdentityDigest` is injected from the authenticated local transport that first commits it, closed-decodes exact `LocalControlChannelIdentityV1` for `ownerPrincipalId`, and is deliberately outside `commandDigest/requestDigest`; same-request replay through a later authenticated channel returns the retained operation without rewriting that pair. One authority transaction appends the operation plus either the new record revision or an exact no-op disposition. `(ownerPrincipalId,requestId)` is request-digest-idempotent; same bytes return the immutable operation, different bytes conflict. Register creates revision 1, or `already_registered` only when the same endpoint id already has byte-identical registration/ref; different target/TLS/purpose conflicts and requires a new id. Revoke requires the expected latest active revision and appends the next `revoked` record with both revocation request id/digest; a later request receives `already_revoked` without another revision. Revocation prevents new bindings but does not rewrite already-admitted artifacts. When a Supervisor first resolves an active id it publishes those exact bytes through WP01 CAS, verifies the resulting ref equals `expectedRegistrationArtifactRef`, and only then publishes an `EndpointCredentialGrantBinding`. The external authority therefore never writes Run CAS while still giving every later consumer one deterministic immutable ref. Every registered target has literal `redirectPolicy='reject_all'`. Provider, endpoint-negotiation, dependency, and Streamable-HTTP MCP clients disable library/SDK redirect following (`maxRedirects=0` or manual equivalent); any HTTP `300..399`, including same-origin/same-path redirects, is a received typed rejection/error and no `Location` target is resolved, authorized, retried, or sent a body, cookie, or credential header. Only a newly registered immutable endpoint may change host, port, base path, or TLS identity.

Every `credentialGrantRef` used by a Run, dependency policy, capability query, or MCP revision resolves to one immutable, secret-free binding; `bindingDigest = SHA-256(JCS(binding with bindingDigest omitted))`. Its `endpointRegistrationRef` must decode to the exact same owner, contain the binding purpose, and reproduce `endpointIdentityDigest` and `tlsPolicyDigest`; lookup ids or matching URLs are insufficient. `CredentialExternalSubjectV1.subjectDigest = SHA-256(JCS(subject artifact with subjectDigest omitted))`, and the binding's inline subject plus `externalSubjectDigest` must reproduce that exact artifact. A provider-verifiable credential records the provider namespace plus account-subject digest and unique byte-sorted scopes/audiences returned by the fixed read-only credential validation protocol. When that protocol cannot expose account/scope, enrollment generates a fresh 256-bit `opaqueSubjectId` for the secret generation and restricts it to literal `scopes=['endpoint_exact_only']` and `audiences=[]`; that opaque id is never reused for a later secret.

The credential service identity `(ownerPrincipalId,credentialGrantId,credentialHandleIdentityDigest)` remains append-only, but an admitted binding freezes `authorityRevision`, `credentialServiceRevision`, `secretGeneration`, and the external-subject digest in addition to owner/purpose/endpoint/TLS. Rotation appends the next authority revision and secret generation even when it preserves the handle and target. Before any dispatch the broker requires the latest active authority row to match **every** frozen binding field and then reads only that row's named platform item. A later generation, changed provider subject/scope/audience, revocation, expiry, or missing item returns authorization-required with no target I/O; it never substitutes current bytes into an older admitted Run. New work must resolve and publish a new binding for the new generation. Public ids are therefore lookup handles, never durable authority by themselves. Admission requires every used binding active and either nonexpiring or `expiresAt >= Run.deadlineAt`; a Run is never accepted with credential authority known to expire first. `RunModelRequest.modelCredentialGrantIds` resolves only `purpose='model_endpoint'`; dependency/MCP ids enter through their own bounded request and immutable registry/policy closure.

The concrete credential authority is closed. On macOS it stores secret bytes only in the login Keychain under service `ai.cogine.cliq.credentials.v1`; on Linux it stores them only in the default freedesktop Secret Service collection under schema `org.freedesktop.Secret.Generic`. Kernel Cut has no plaintext-file, environment-variable, SQLite/CAS, process-environment, or custom command fallback. If the same-user platform store is unavailable, locked, or cannot round-trip a newly entered secret, enrollment fails before any binding becomes active; billable remote providers/dependency endpoints/HTTP MCP remain unavailable until the user repairs that store. Secret-free metadata and `CredentialAuthorityOperationV1` live in a separate descriptor-protected `${stateRoot}/credentials/authority.sqlite` (`0700` directory, `0600` database/WAL/SHM) behind one same-user exclusive lock. The Run database never writes it.

The internal authority API has one lock-aware form, `withCredentialAuthorityLock`, which returns an unforgeable process-local held-lock token. Ordinary `cliq auth` operations acquire it once; migration/rollback acquire it only after the earlier locks in the canonical global order and pass the same token through endpoint/credential operation, record revalidation, platform-item read, marker replacement/rematerialization, and authority publication. Every locked repository method requires that token and **never reacquires or releases** the underlying lock; calling an ordinary auto-locking entry point while a token is held is rejected as a programming error. Token owner/process/lock-generation are checked, callbacks cannot escape the token, and crash releases only the OS lock—not any uncommitted authority state. This prevents both self-deadlock and a rotate/revoke race across cutover.

`CredentialAuthorityRecordV1` revisions are append-only and exactly one latest revision exists per grant id. Its endpoint ref/identity/TLS/owner/purpose must equal one active `EndpointAuthorityRecordV1` and that row's deterministic expected artifact ref before `prepared` may commit. A combined `cliq auth` command registers the secret-free endpoint first, then performs credential enrollment; a crash may leave a harmless replayable endpoint row but never an active credential without it. `credentialHandleIdentityDigest = SHA-256(JCS({ownerPrincipalId,credentialGrantId,credentialServiceRevision,purpose,endpointRegistrationRef,endpointIdentityDigest,tlsPolicyDigest}))`; `recordDigest` omits itself. Target fields and `credentialServiceRevision` are immutable for the id. Rotation increments `authorityRevision` and `secretGeneration`, selects a fresh platform item, and preserves the handle digest/target, while the newly authenticated or opaque external subject is part of that new revision; target change creates a new grant id. Credential revocation uses the separate secret-free `CredentialAuthorityRevokeOperationV1`: its command/request/operation digests use the same omission/idempotency rules, require the expected current target digest/revision, and in one metadata transaction append the terminal `revoked` revision plus `cleanupPhase='metadata_committed'`. Same request bytes replay, different bytes conflict, and a later request receives `already_revoked` without another record revision. Only after that commit may it delete the named platform item, moving to `cleanup_complete` on positive absence/deletion or `cleanup_failed` with the closed error and a SHA-256 digest of the secret-free platform observation stored in `authority.sqlite`; the external authority never needs a Run-CAS write. Startup resumes an indeterminate deletion idempotently. Redemption is denied from metadata commit onward even if cleanup is delayed or permanently fails. Expiry/revocation never moves backward.

Enrollment/rotation is request-idempotent and crash ordered. `CredentialAuthorityCommandCoreV1` is the complete persisted secret-free command: its inline external subject rehashes to `externalSubjectDigest`; `credentialTargetDigest = SHA-256(JCS({credentialGrantId,ownerPrincipalId,purpose,endpointRegistrationRef,endpointIdentityDigest,tlsPolicyDigest,expiresAt,externalSubjectDigest}))`; `commandDigest = SHA-256(JCS(commandCore with commandDigest omitted))`; and `requestDigest = commandDigest`. Operation owner/kind/grant/target/subject fields must repeat the core, and `intendedAuthorityRevision`/`intendedSecretGeneration` are exactly one greater than the latest row for rotation or both one for enrollment. Every enroll/rotate/revoke operation also retains the first-commit authenticated `channelIdentityRef/channelIdentityDigest`, closed-decodes it for the same owner, and keeps it outside the command/request digest so later-channel replay cannot rewrite provenance or create a false request conflict. Raw secret bytes are deliberately excluded and never hashed/persisted. `operationId = H(ownerPrincipalId,requestId,requestDigest,attempt)`, attempts are contiguous `1..3`, and at most one nonterminal attempt exists. Under the lock, append `prepared`; write a fresh generated platform item; read it back through the same-user store and compare in memory; run the fixed read-only provider subject/scopes validator or generate the one-generation opaque subject; require equality with the command; append `secret_stored`; then in one metadata transaction append the active authority revision and `committed` operation. Only after commit may rotation delete the superseded item. `operationDigest` omits itself, request-id+different-digest conflict is permanent, and a committed replay returns the same grant/revision **without reading, comparing, or storing newly submitted secret bytes**. Changing a committed secret requires a new request/secret-submission id and `rotate`.

Startup never promotes an incomplete operation without the original secret bytes: it deletes any planned item it can identify and appends `aborted(recovered_orphan)`. The same request/digest may create only the next contiguous attempt when the caller (or still-raw legacy preflight) supplies a secret again; concurrent retries join it. Because no prior authority committed and no secret commitment is retained, that resubmission is explicitly **latest-secret-wins** for the fresh attempt—there is no unenforceable promise that it equals the abandoned bytes. The input buffer is discarded immediately after platform-store write/compare; a committed replay, digest conflict, or terminal attempt discards it without platform access. After attempt 3 aborts, that request is terminal and a new request id is required. An unreachable superseded item is removed by a lock-held sweep only when no active metadata revision names it. Crash after active commit is therefore recoverable; crash before it grants no authority, repeated crashes are bounded, and deterministic legacy entry ids can resume through their recorded attempt. No log, error, telemetry, shell history, artifact, or response echoes the secret.

Legacy `~/.cliq/auth.json` is a release-gated credential migration, not a normal Session backup. Before general state import, the new binary locks the legacy auth store and records exact `LegacyAuthStoreObservationV1`: either one held same-owner regular-file/link-count-one/no-follow descriptor or descriptor-relative no-follow `ENOENT`. A present file must use the current recognized provider-auth schema; its supported HTTPS targets normalize into `EndpointRegistrationV1`, its non-secret fields enter `LegacyAuthNonSecretProjectionV1`, and its secret-bearing entries perform deterministic credential enrollment as above. An absent store produces an empty projection/ready record set without creating a file. This preflight leaves the original raw file or exact absence unchanged while legacy remains authoritative; general migration/backup excludes auth bytes and records only the observation, non-secret projection, and secret-free credential-ready manifest. It never copies raw legacy keys into CAS, SQLite, archives, logs, or rollback backups.

Only after all noncredential import bytes are staged and verified does final cutover, while continuously holding the canonical lock order—exclusive Kernel global/cutover gate plus current state-owner lock, local-model registry/object-store lock, legacy auth-store lock, every legacy Session/transaction/plan lock in byte order, then credential-authority—publish durable `MigrationControlV1(phase='credential_cutover')`, revalidate the exact source observation and latest credential authority records/platform-item identities, atomically replace a present file or create over verified absence and fsync `auth.json` with the secret-free `cliq-auth-migrated-v1` marker, and then publish the Kernel authority marker **last**. Every ordinary external credential or local-model operation first holds the global gate in shared mode and then its own authority lock; the exclusive cutover/rollback holder therefore fences them before inventory through authority publication. Rotation, revocation, enrollment, or local-model object publication cannot cross that window. A crash before the authority marker reacquires the same order and restores the exact observation: deterministic normalized ProviderAuthStore-v1 semantics from the projection/platform items for `present`, or marker unlink plus parent fsync and verified `ENOENT` for `absent`. It then clears control and leaves legacy authoritative; it never strands legacy behind a marker it cannot parse. A crash after authority publication completes/validates the marker. Unsupported/plain-HTTP/raw-Ollama/ambiguous entries, unavailable platform store, or failed replacement/restoration blocks publication while the original branch remains usable.

Explicit rollback cannot restore a marker and then start an old binary. Before the legacy authority marker is published, the new binary requires `--allow-plaintext-legacy-credentials` (or interactive equivalent), reads each still-active platform item through the same-user authority, writes one `0600` staged ProviderAuthStore-v1 file, fsyncs and validates it, and atomically installs it at the legacy path. Missing/revoked/unreadable credentials block rollback with exact re-enrollment instructions; no old runtime starts first. Credential materialization joins the rollback sentinel/staging protocol and the legacy authority marker remains last. Raw secrets are thereby reintroduced only by explicit rollback consent, never by a retained backup. No claim of secure erasure of prior filesystem blocks is made.

Provider capability evidence is also a closed artifact, not an adapter boolean. `ModelCapabilityEvidenceV1.evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`; provider/model/endpoint and adapter id/version/code digest equal the assembly. Its five claim fields are byte-for-byte equal to the selected source's `NormalizedModelCapabilityClaimsV1`; a ref or digest without this projection equality is not authority.

For a catalog source, `catalogEntryRef` decodes only as `SignedModelCatalogEntryV1`, its digest is `SHA-256(JCS(entry with catalogEntryDigest and signatureRef omitted))`, and the detached Ed25519 signature is by a bundled Cliq catalog key. Runtime bundle/ref, provider/model/endpoint identity, adapter identity, claims, and validity equal the evidence and assembly. For endpoint negotiation, `negotiationReceiptRef` decodes only as `EndpointModelNegotiationReceiptV1`; `receiptDigest` omits itself under JCS, endpoint registration/identity/TLS and owner match the immutable registered endpoint, and adapter/provider/model/claims/validity equal the evidence.

The receipt's normalized request ref/digest decodes exact
`EndpointModelNegotiationRequestV1`. `requestDigest` omits itself; endpoint,
owner, provider/model, adapter, fixed protocol, the byte-sorted unique
`credentialGrantRefs`, and the literal six-element claim tuple equal the
receipt. Every credential binding revalidates the exact endpoint/TLS,
authority/service revision, secret generation, external subject, owner,
purpose, expiry, and revocation before the query reaches the broker. The fixed
query is a bounded read-only capability lookup: it cannot create, mutate,
bill, submit model input, or trigger provider work, redirects are forbidden,
and repeating the identical request is its only legal crash recovery. Fixed
Supervisor code publishes and fsyncs the normalized request before I/O. A
crash before the complete response and receipt are published may leave only
unreachable CAS objects and may repeat that exact safe read; no partial body,
cache row, or orphan is capability authority. This pre-admission lookup is not
a Run Journal attempt and creates no reservation. The trusted adapter may map
the logical query to provider-specific transport only under its exact code
digest and registered endpoint/credential broker. The redacted response
ref/digest decodes exact
`EndpointModelNegotiationResponseV1`; `responseDigest` omits itself, its request
pair rehashes the same request, and its protocol/times/complete five claims equal
the receipt. The response artifact is at most 1 MiB JCS and contains only the
closed fields above—no headers, credentials, cookies, raw body, diagnostics,
unknown extensions, or omitted claim. The adapter's provider-specific parser
must either produce that full normalized response or reject negotiation; it
cannot fill missing booleans/limits from defaults. Receipt claims are exactly
response claims, and capability evidence/assembly claims are exactly receipt
claims. A raw provider body, mutable discovery cache, or adapter assertion
cannot directly set a claim.

Managed local evidence instead binds the exact signed service/model manifests. `LocalModelManifestV1` has unique byte-sorted file paths, safe sizes, digest-valid CAS files/tokenizer, one complete signed `claims: NormalizedModelCapabilityClaimsV1`, and `modelManifestDigest = SHA-256(JCS(manifest with modelManifestDigest and signatureRef omitted))`; its Ed25519 signature is from a bundled Cliq model trust key. Managed-local evidence repeats all six model-manifest claims byte-for-byte; the service health probe may confirm them but never widen them. All catalog/receipt/evidence times are ordered, evidence limits are safe integers, `contextLimitTokens >= 32768`, `1 <= maxOutputTokens <= floor(contextLimitTokens/4)`, and `validThrough >= Run.deadlineAt`. RunAssembly negotiation booleans/limits/digest/ref repeat the evidence exactly; mode is `native-tools` only when native tool calling is true, otherwise `text-only`. Unknown, expired, unsigned, endpoint/adapter/model-mismatched, source-claim-mismatched, or mutable evidence sets every autonomous capability false rather than enabling execution by provider name.

Local model selection has one exact producer. The explicit same-user `cliq models enroll --manifest <absolute-package-path>/model-manifest.json` command is outside the Run control protocol, performs no download/network access, and accepts only this fixed descriptor-relative package layout: the selected basename is literally `model-manifest.json`, its parent contains one same-owner directory named `objects`, and the tokenizer/model bytes are regular files named `objects/<64-lower-case-hex-ArtifactRef>`. The importer opens the package root, manifest, object directory, and every object by held no-follow descriptors; rejects symlinks, hardlinks, special files, owner/mode drift, duplicate refs, extra/missing manifest entries, replacement between reads, or any object whose exact size/SHA-256 differs; and never interprets a caller path from inside the manifest. It imports those verified bytes into descriptor-protected `${stateRoot}/local-models/objects/<ArtifactRef>` and fsyncs each new object plus the directory. Source descriptors are transient input evidence, not durable authority after the content-addressed copy.

The importer first acquires the Kernel global/cutover gate in shared mode, then the exclusive local-model registry/object-store lock, and keeps both through object fsync and registry commit; an exclusive migration/rollback gate therefore blocks it before any publication. It publishes exact `LocalModelObjectClosureV1`: the decoded current `StateRootIdentityV1` pair; literal store-relative path; the signed model-manifest pair; and an all-and-only object sequence containing one manifest entry, one tokenizer entry, then the manifest's byte-sorted model-file entries. The manifest entry names the complete JCS artifact bytes, the tokenizer ref/digest equals its imported object SHA-256, and each model-file ref/digest/path/size equals its manifest member. Every `artifactRef === artifactDigest`; `objectCount === objects.length`; `totalBytes` is their checked sum; all sizes are positive safe integers; model-file logical paths are the manifest paths; and `closureDigest = SHA-256(JCS(closure with closureDigest omitted))`. Every object exists at the exact store path named by its ref and rehashes before commit. The embedded closure and `expectedObjectClosureRef` are byte-identical JCS and content-addressed; `registrationDigest` omits itself. No opaque source-store id, mutable lookup, download cache, or post-enrollment pathname is authority.

Service construction is also fixed. Enrollment uses the currently selected signed RuntimeBundle and requires exactly one executable entry with `entryId='ollama_local_inference'`, role `local_inference`, and matching version/digest; chooses `macos_vm` on macOS or `linux_namespace` on Linux only after the strong backend probe; and publishes a `SandboxProfileV1` with sole owner `local_inference_service`, the fixed reachability policies, and the displayed default `SandboxResourceSpec`. Callers cannot select or raise those fields. The endpoint is exactly `{scheme:'http',host:'127.0.0.1',port}`; while holding the registry lock, `port` is the smallest integer in `49152..65535` not named by any retained registration and is never reused while that registration is retained. Exhaustion rejects enrollment. The trusted producer first canonicalizes every service field except identity/time/digests, then sets `serviceSpecCoreDigest = SHA-256(JCS(serviceSpec with serviceId,createdAt,serviceSpecCoreDigest,serviceSpecDigest omitted))`, `serviceId = H(ownerPrincipalId,'ollama',model,serviceSpecCoreDigest)`, one transaction timestamp, and finally `serviceSpecDigest = SHA-256(JCS(serviceSpec with serviceSpecDigest omitted))`. Same semantic core reuses the exact existing registration; changed endpoint/backend/resources/version/manifest/executable/profile or any other semantic service field changes the core and service id. Exactly one active revision exists for `(ownerPrincipalId,'ollama',model)`; a changed manifest/spec creates a higher revision/new service id and retirement never rewrites an old registration used by a Run. Broader download/catalog/update UX remains outside Kernel Cut.

The registry implements that last invariant with an append-only head, never an in-place artifact rewrite. Its mutable SQLite pointer row is exactly `(ownerPrincipalId,provider,model,currentHeadRef,currentHeadDigest,headRevision)` and names one immutable `LocalModelRegistryHeadV1`; `headDigest` omits itself. `initial` requires no pointer/predecessor, head and registration revision one, and one exact active registration. `replace` CASes the current active head, publishes an immutable retired copy whose base fields are byte-identical to the predecessor active registration except `state/retiredAt/registrationDigest`, publishes the new active registration at old registration revision plus one, then advances the head by one with both refs. `retire` performs the same retired-copy projection and advances to a head with no active registration. `reenroll` is legal only from the current retired head and publishes the next active registration revision. Every noninitial predecessor pair rehashes the current head, every head revision is exactly predecessor plus one, and artifact publication plus pointer CAS is one lock-held registry transaction. Lookup/admission follows only the current active head; an old active artifact remains immutable and rooted for every admitted Run but is no longer selectable after head advance. Thus neither two current actives nor mutation of retained Run authority is possible.

`run.submit` with the Ollama model branch resolves that exact active registration, copies/verifies its objects and inline manifests into WP01 CAS, and requires the resulting refs equal the expected refs before any launch or Run row. Missing/retired/invalid registration returns `UNSUPPORTED_EXECUTION_IDENTITY` with no Run/launch. If a matching fresh active launch exists, admission uses it. Otherwise the Supervisor artifact-first publishes the validated secret-free submit request/admission intent and calls `ensureLocalInferenceActive`; this is a durable service activation cycle, not a private retry loop owned by whichever request arrived first.

`activationCycleId = base64url(SHA-256(JCS({ownerPrincipalId,serviceId,serviceSpecDigest,cycleOrdinal})))`, where `cycleOrdinal` is the next contiguous positive integer for that owner/service. At most one cycle in `starting_launch|retry_wait` exists per owner/service, and at most one unretired launch exists. Before creating or joining a cycle, storage searches every retained participant for the same public request id: the same digest returns that participant's cycle/result and different bytes are `REQUEST_ID_CONFLICT`, so a request that joined another request's cycle can never replay into two fresh attempts. A new request with no prior participant joins the current nonterminal cycle when its exact service spec matches, or creates the next cycle only after the prior cycle is terminal and any blocking launch is positively retired. Participants are append-only in join order, unique by `(kind,requestId)` or `(kind,runId,frontierRef)`, bounded to 128, and `run_submission` names the exact retained request/admission bytes while `run_model_frontier` names the exact queued Run revision/frontier. Exceeding the bound returns `RESOURCE_EXHAUSTED` without joining or starting I/O. `cycleDigest = SHA-256(JCS(cycle with cycleDigest omitted))`; `failureDigest` uses the same rule for `LocalInferenceActivationFailureV1`. Service-spec digests, launch ids, participant order, and every ref are independently validated.

One cycle owns a contiguous prefix of at most two launch rows. Attempt 1 has a fixed 120-second activation deadline. `starting_launch(1)` either reaches `active` or follows one mandatory failure matrix: if exact no-spawn/death retirement is obtained, it **must** become `retry_wait` with `retryNotBeforeAt = retirementTime + 1s`, and attempt 2 is the sole legal successor with another fixed 120-second deadline; if the attempt cannot be positively retired, the cycle fails immediately with `finalAttempt=1`, `failureKind='containment_unresolved'`, and the blocking launch remains fenced/unretired. Attempt 1 may not terminal-fail for timeout, launch, health, or capability mismatch after positive retirement, and may not retry without it. Any attempt-2 launch/timeout/health/capability failure is terminal after recording its positive retirement, or terminal as `containment_unresolved` if retirement cannot be proved. No third attempt, hidden background retry, request-specific counter, or counter reset after disconnect/restart is legal. Every failure publishes exact `LocalInferenceActivationFailureV1` whose final attempt/reason/retirement closure satisfies that matrix. The final cycle transaction is bounded and exhaustive over its participants. On success it requires the exact active launch/boundary, sets `phase='active'`, admits every still-valid `run_submission` (or stores its exact non-activation admission error) with the same-transaction `control_requests` response, and makes each still-matching queued `run_model_frontier` eligible without changing its frontier. On failure it sets `phase='failed'`, stores the same typed `RECOVERY_REQUIRED(recoveryKind='local_inference_service')` response for every joined submission without creating a Run, and for each still-matching existing Run proposes `runtime_failed/local_inference_unavailable` whose exact cycle/service/frontier fields carry that `failureDetailRef`; terminal `primaryEvidenceRef` equals it. A Run already stopped, terminal, or moved from that frontier is only recorded as an obsolete participant. Thus cycle completion and participant fanout cannot be split by a crash.

An existing Run never chooses between waiting and failing. When its frozen local service is absent before the next model claim, the Supervisor first settles any prior model attempt, quiesces/checkpoints and retires its worker, then atomically leaves the Run `queued` at the same agent frontier and joins/creates the one service cycle; no model reservation or claim remains live. Service activation makes that exact queued frontier schedulable. Exhaustion of the cycle's bounded attempts proposes the typed failure above. A service death after admission therefore uses the same durable cycle/retry/fanout reducer as initial admission, without a new user request, ambient-endpoint fallback, or implementation-selected infinite queue.

The managed local service has its own narrow durable activation and launch authority, not an untracked child process. `LocalInferenceServiceSpecV1.serviceSpecDigest` omits itself under JCS and resolves one signed RuntimeBundle `local_inference` entry, signed local model manifest, loopback endpoint, strong backend/profile, and bounded resources. The model must already be explicitly installed and trusted; `run.submit` never downloads weights or follows a workspace request. `local_inference_activation_cycles` stores exactly `LocalInferenceActivationCycleV1`; `local_inference_launches` stores exactly `LocalInferenceServiceLaunchV1`. Every launch names its owning cycle and attempt, the cycle's `launchIds` is the same contiguous ordered set, and the row/service/spec/owner identities match byte-for-byte. The launch table permits one unretired row per `(ownerPrincipalId,serviceId)`. Its productive spine is `reserved -> preactivated -> active -> revoking -> retired(death)`; recovery additionally permits `reserved -> retired(no_spawn)` and `preactivated -> retired(death)`. Reserved state durably names the containment plan and canonical SandboxLaunchSpec before spawn; preactivation is isolated, networkless, credentialless, and blocked from accepting model traffic. Activation requires an exact health/capability probe plus `LocalInferenceBoundaryEvidenceV1`, then a row CAS exposes the loopback endpoint. Heartbeat changes only `leaseVersion/leaseExpiresAt`. A reserved row that positively never spawned retires with `retirementKind='no_spawn'`, no process/boundary/quiesce fields, and exact `ProcessContainmentNoSpawnEvidenceV1`; any row that obtained a containment retires with `retirementKind='death'`, that containment, a quiesce id, and exact `ProcessContainmentDeathEvidenceV1` (boundary evidence is present iff activation reached it). A new Supervisor never adopts an old launch: it revokes, kills, proves the exact containment/spec closure dead, retires it, and advances only the owning cycle's legal next edge. No second launch or model request proceeds until that proof.

Endpoint shape is also closed. `local_zero_cost` is permitted only for `LocalZeroCostProvenanceV1`: a Cliq-managed Ollama local-model service whose signed RuntimeBundle entry has role `local_inference`, whose exact service/model manifests and capability evidence are retained, and whose Supervisor-attested Linux namespace/macOS VM boundary denies external egress. Its port is an integer in `1..65535`, IPv4 and IPv6 loopback spellings are already canonical literals, and `endpointIdentityDigest = SHA-256(JCS(endpoint))`. `stableServiceIdentityDigest = SHA-256(JCS({ownerPrincipalId,serviceId,serviceSpecRef,serviceSpecDigest,runtimeBundleRef,runtimeBundleManifestDigest,executableId,executableDigest,modelManifestRef,modelManifestDigest,backend,externalNetworkEgress:'denied',loopbackOnly:true}))`; every boundary evidence and its provenance repeat it. `evidenceDigest` and `provenanceDigest` each omit only themselves under JCS.

The provenance's `boundaryEvidenceRef` is the admission-time audit observation and its dynamic `serviceLaunchId`, containment, plan, SandboxLaunch, inspector, and observation fields are **not** stable service identity. Provenance binds the stable digest, service spec, provider/model, loopback endpoint, and capability evidence; both provenance and admission evidence validity cover `Run.deadlineAt`. Every boundary evidence's inspector ref/digest decodes the exact current `SupervisorInspectorIdentityV1`, repeats its instance id, and matches the active `StateOwnerRecordV1` under the ordinary five-second evidence freshness rule. A bare Supervisor id is not an attestation. RunAssembly `endpoint.localProvenanceRef` and `pricing.provenanceRef` are the same artifact, its endpoint identity equals the assembly, credential refs are empty, and `maxRunCostMicros=0`. Before every dispatch the broker reads the current active launch and fresh `LocalInferenceBoundaryEvidenceV1`, requires their service spec and stable identity digest equal the provenance, validates the current lease/dynamic containment closure, and rechecks model/capability/no-egress identity. A death-proven replacement may change only launch/containment/plan/SandboxLaunch/inspector/observation fields; it cannot change the stable projection. Mismatch reaches no provider and proposes generic `runtime_failed`. A third-party Ollama/OpenAI-compatible daemon, mere loopback URL, remote proxy, or mutable cloud-routing assertion is not zero-cost authority. Kernel Cut therefore includes only the minimal signed local-inference service/bootstrap needed for the Ollama provider contract; model download, catalog, routing, and the broader `cliq-models` product remain outside this RFC.

Every billable standard or custom endpoint—including bundled OpenAI/Anthropic/OpenRouter defaults—is resolved to an immutable `registered` endpoint; `bundled_default` describes who enrolled the registration, not a weaker identity. Its assembly registration kind/ref/identity/TLS and model credential bindings must reproduce one `EndpointRegistrationV1` exactly. If a frozen binding is revoked or becomes unavailable after admission, no in-place rebind, approval loop, or free predispatch retry is permitted: a model call proposes generic `runtime_failed` with credential evidence; required dependency acquisition proposes generic `runtime_failed`; and an MCP tool call appends one identity-matched `ToolResultItem(outcome='error')` and continues the ordered batch. None reaches the target or changes immutable assembly/policy/registry refs; the user submits a new Run after repairing authority.

The `authorization_grants` table stores exactly `AuthorizationGrantV1`, never a generic target JSON blob. `targetDigest = SHA-256(JCS(target))`, `grantCoreDigest = SHA-256(JCS(base fields with grantCoreDigest/rowVersion omitted))`, and `rowDigest = SHA-256(JCS(full row with rowDigest omitted))`. Paths use the same descriptor-validated canonical workspace identity/path rules as capture; workspace scripts are legal only for verifier identity, never MCP stdio. Guest/runtime entries resolve immutable signed manifests and exact executable digests. A verifier-execution target binds `verifierRequestCoreDigest` (with `executionGrantId` omitted), an active identity grant's exact target digest, candidate bound `1..6`, and attempts `1..4`. Dependency script authority binds one exact workspace/lockfile/digest. Unknown fields or target combinations fail closed.

The only row transitions are `active(rowVersion=1,useCount=0) -> consumed(rowVersion=2,useCount=1)` or `active -> revoked(rowVersion=2,useCount=0)`, under owner/request-id CAS; terminal rows are immutable and a consumed grant cannot later be presented as generally active. Consumption first publishes `AuthorizationConsumptionReceiptV1`, then atomically installs that ref and the Run admission/MCP registration/derived-authorization state it authorized. The receipt digest omits itself and its consumer must match the exact state transaction. A `run_admission` receipt binds the pre-resolution `admissionIntentDigest`, never the final admitted digest: the intent is computed from the public normalized request before any receipt, projection, dependency template, or RunSpec ref exists; after those artifacts are published, storage computes the final admitted digest over the intent plus the complete resolved ref/digest closure and commits the receipt, authorization row, RunSpec, Run, Checkpoint, and control response together. This publication order is acyclic, and replay must reproduce both digests and every resolved ref. Expiry is checked before inspection/use and no later than 24 hours from creation; it cannot be extended. `authorization.list` exposes redacted target summaries/state/revision, while create/revoke are control-request-idempotent. Revoking active returns `ControlResultV1` disposition `revoked`; replaying revoked returns `already_revoked`; revoking consumed is a successful no-op result with disposition `already_consumed` plus the unchanged consumed grant summary, and never rewrites the use receipt or claims to revoke derived authority. These user authorization grants only resolve/capture identity or mint the bounded verifier template/install-script authority; they are not `OperationGrantV1`, carry no secret, and grant no direct target I/O.

Verifier execution derivation is the one closed consumed-identity exception. `authorization.create(verifier_execution)` atomically consumes the named active `execution_identity_read(purpose='verifier')` grant with `consumer.kind='authorization_derivation'` and publishes exactly one derived verifier-execution grant whose id/target digest the receipt names. That identity grant cannot derive again. A later `VerifierRequest` without `executionGrantId` requires and consumes an active `identityReadGrantId`; with `executionGrantId`, it must repeat the consumed identity id and admission accepts it only by following that exact derivation receipt to the active derived grant, then consumes the derived grant into this Run's template. Any other consumed identity, mismatched verifier core/target/maxima, or missing derivation receipt is `AUTHORIZATION_REQUIRED`. Thus the wire may carry both ids without treating a consumed grant as reusable authority.

`assemblyRef` resolves only to `RunAssemblyV1`; `assemblyDigest = SHA-256(JCS(assembly with assemblyDigest omitted))`, every array is unique in declared order, unknown fields fail, and all referenced bytes/digests validate before admission. The Supervisor derives it from the public model request plus trusted endpoint/credential enrollment, live capability negotiation, frozen price/cap evidence, canonical tool registry, post-Trust instructions/skills, and the retained runtime/guest manifests. Public clients cannot supply these refs. Registered model credentials must be `EndpointCredentialGrantBinding(purpose='model_endpoint')` for the exact endpoint; only `local_zero_cost` uses none. Native-tools requires `nativeToolCalling=true`; text-only exposes no tools. `provider.negotiation.contextLimitTokens` equals `context.contextLimitTokens`, `1 <= context.reservedOutputTokens <= provider.negotiation.maxOutputTokens`, and every normal request uses that exact reserved output cap.

Model authority is loaded once from the exact retained assembly and signed RuntimeBundle. Provider adapter code supplies pure native serialization directly from typed messages/tools; it is not selected by a prompt profile, tokenizer profile, source-JCS callback, mutable registry or SDK default. Static signature/reference/tool-schema/envelope checks run on admission and recovery. Per-attempt work checks the changing projection and invocation, then serializes and hashes the exact body. A loaded `ModelSession` owns immutable configuration and identity-bound prepared handles; storage still rehashes and validates every authoritative commit. There is no custom BPE, fictional framed prompt, or per-request execution of golden vectors. Independent expected-wire fixtures qualify the retained code at build/release time.



The selected signed RuntimeBundle obeys work package 06's exact `structuredArtifacts` closure. Each root binds kind/id/provider/model, a complete-byte root ref, an independently recomputed self-omitting semantic digest, and unique byte-sorted all-and-only member refs. Members are signed non-executable `bundle_object` entries whose digests equal their complete-byte ArtifactRefs. Install descriptor-verifies and imports every root/member before activation. Exactly one `system_prompt` and one `compaction_prompt` root match the assembly provider/model: the former is nonempty `ModelTextV1` and binds `instructions.systemPromptRef/systemPromptDigest`; the latter is `CompactionPromptEnvelopeV1`, binds the assembly envelope pair, and has exactly its three `ModelTextV1` members. Complete-byte and semantic digests never collapse. The same general closure retains bundled-skill files, guest image/signature, MCP recovery arguments/predicates and Windows projection schemas. Recovery never assumes preseeded CAS or rereads ambient package paths. The actual tokenizer/model files of managed local inference remain part of its signed model closure; they are not a host-side remote token counter.

Normal prompt construction is a total stored projection, not adapter assembly. `NormalPromptProjectionV1.projectionDigest = SHA-256(JCS(projection with projectionDigest omitted))`; its Run/spec/assembly/context refs equal the current authoritative Run and ready Checkpoint, `contextManifestDigest` equals the decoded `ContextManifest.projectionDigest`, `basedOnRunRevision` is the revision being dispatched, and `frontierDigest = SHA-256(JCS(the exact current RunFrontier))`. Message indices and tool indices are contiguous from zero. The producer walks only the frozen artifacts in this order:

1. Emit one system message from a closed instruction projection. The first, mandatory nonempty piece is the decoded signed-RuntimeBundle `RunAssembly.instructions.systemPromptRef` `ModelTextV1.utf8`. If the decoded workspace manifest has entries, the next piece is UTF-8 JCS of `{format:'cliq-workspace-instruction-prompt-v1',entries:[{order,canonicalRootRelativePath,appliesToSubtree:true,instructionUtf8}]}`, using every manifest entry in order and the exact decoded `ModelTextV1.utf8`; this preserves each nested scope instead of guessing one ambient target path. Each selected skill then contributes UTF-8 JCS of `{format:'cliq-skill-instruction-prompt-v1',skillId,sourceScope,instructionUtf8}` in the assembly's explicit skill order. Omit only the empty workspace block, require every skill instruction to be nonempty, and join the remaining exact pieces with two LF bytes. Every ref/digest, source identity, and text digest rehashes, and `sourceKind='assembly_instructions'`, `sourceId=assemblyRef`.
2. Walk the admitted `SessionContextProjection` segments in order. A raw segment may project only `run_terminal` items and emits one user message per item using the exact JCS rendering in section 4.2. A summary emits one user message containing its decoded `ModelTextV1.utf8`. `excluded_control` emits none; every legacy kind must be there. Then emit one user message for each `AdmittedContextManifest.parentContextRefs` and `additionalArtifactRefs`, in their stored array order, each of which must decode a bounded `ModelTextV1`. Source kind/id identify the exact Session item, compaction item, or context artifact ref.
3. Emit one user message for the exact `RunObjectiveV1.utf8` named by `RunSpec.objectiveRef`, with `sourceKind='run_objective'` and that ref as `sourceId`.
4. Walk the current `ContextManifest.segments` in order. A summary emits its exact `ModelTextV1` as one user message. An `excluded_control` segment emits none. Every raw item must be one of the following model-visible forms; every other item belongs in `excluded_control`: a `ModelTurnItem` emits one assistant message whose text equals its `ModelTextV1` and whose ordered calls equal the decoded `AgentModelTurn`; each call's `arguments` retains `{encoding:'jcs_json',value}` or `{encoding:'utf8_json_fragment',utf8}` directly from its observation, with no internal stringify/parse round trip, and its ref/digest/id/index/name equal `ToolCallInputV1`; a `ToolResultItem` emits one tool message whose content is `UTF8(JCS(decoded ToolResultModelContentV1.content))`; a `UserInputItem` emits one user message containing exact text or `UTF8(JCS(value))` from its ref-free `UserInputModelContentV1`; a `RepairDiagnosticItem` emits one user message per ordered diagnostic using only `VerifierRepairModelContentV1.message`; and a `ChildResultItem` emits one user message containing `UTF8(JCS(ChildResultModelContentV1.content))`. The source item id and source kind match each message. No authority/audit payload, raw verifier output, principal, grant, StopIntent, containment fact, or legacy payload is serialized.

The `tools` array is empty for text-only mode. Otherwise it is the contiguous projection of `provider.negotiation.exposedToolNames` in that order: every name selects exactly one `ToolContractManifestV1` entry, description is byte-identical, and `inputSchemaRef/inputSchemaDigest/inputSchema` rehash and decode the exact finite JSON-domain schema. There are no hidden or adapter-added tools. The entire projection's JCS is bounded to the admitted context/model limit before dispatch; an indivisible oversized message follows the context-window failure rule rather than truncation.

Every normal or context-compaction model Journal `requestRef` decodes the single `ModelRequestV1`; `requestDigest` omits itself under JCS. Run/op/attempt, assembly ref/digest, provider/model/mode, projection pair, body ref/count/path, streaming flag, output cap, estimate and reservation equal the prepared attempt. Normal mode is the frozen assembly mode, output cap is `O`, and `compactionPlanRef` is absent. Compaction mode is `text-only`, cap is `S`, and the plan is the current frontier's exact plan. Its stored projection is the retained envelope's system message plus user prefix/source/suffix, with no tools or fabricated framing. `AgentModelTurn` repeats the applicable projection pair and request digest. Recovery reloads the same immutable closure and re-prepares the retained projection, reproducing the same request and wire bytes before accepting a response.


Preparation publishes the exact secret-free native body (at most 1 MiB) and one common request artifact; compaction additionally publishes its typed projection. OpenAI uses Responses with `store:false`, explicit output cap, disabled truncation and encrypted reasoning continuation; Anthropic uses Messages; OpenRouter/OpenAI-compatible/Zhipu use their explicit Chat Completions mappings; managed Ollama uses Chat. The broker sends those bytes verbatim and injects only endpoint-authorized transport/auth headers. It cannot reserialize, add messages/tools/defaults, change the path, follow redirects or retry inside an attempt. Opaque provider reasoning/signature blocks are bounded, identity-bound data retained in the turn and next projection, never tool or permission authority. All identifiable native calls and their ordered synthetic/executed results remain in history. An empty tool name remains empty in durable truth; native history uses only the reserved, unexposed `__cliq_missing_tool_name` placeholder to close its result, without repairing the call.


`mcpServers` is byte-sorted by registration id, has exactly one entry for each unique public requested server id and no others, and each ref/digest/revision validates an immutable registry revision. `ToolContractManifestV1.entries` is byte-sorted by exposed `name`; names are globally unique across built-ins and every selected MCP registry, and admission rejects rather than renames/shadows any collision. An MCP entry must match exactly one selected server revision and its server tool name/schema/recovery contract digest; its `replayClass` is byte-for-byte the decoded registry tool recovery kind. A built-in entry matches the retained adapter identity and its closed type forbids `reconcile`; Kernel Cut has no hidden built-in reconciliation adapter. Provider `exposedToolNames` is exactly the manifest entry-name sequence for native mode and empty for text-only. Retry entries are the same ordered names/replay classes. The assembly `tools.manifestDigest` equals the referenced manifest's digest; there is no second schema array for adapters to reinterpret. The signed `RuntimeBundleManifest` named by `runtime.runtimeBundleRef` resolves `workerExecutableId` to role `worker`, `provider.adapter.adapterId/version/codeDigest` to one `provider_adapter` entry, every built-in tool's adapter id/version/code digest to one `tool_adapter` entry, every bundled skill's complete-byte closure ref plus independently validated semantic closure digest to a non-executable `skill_bundle` entry, and the sole `default_https_trust_store` id/content to a non-executable `trust_store` entry. Entry ids, roles, and versions match byte-for-byte; each entry's signed digest hashes its complete retained file and is compared only with that file's ArtifactRef, never with a structured artifact's self-omitting semantic digest. Selected MCP and guest executables follow their own retained manifest identities. Recovery never loads a mutable installed adapter, skill closure, trust path, or CA bundle merely because its semantic version/path appears compatible.

`WorkspaceInstructionManifestV1` is required even when empty. Workspace Trust authorizes this separate declarative-context capture; it does **not** add these files to `SourceManifest`, a private generation, result/diff, or publication authority and does not create tool/read permission. The source pair decodes exact `WorkspaceInstructionSourceManifestV1`, whose workspace identity ref/digest equals the Session's held `WorkspaceIdentityV1`; `sourceDigest = SHA-256(JCS(source manifest with sourceDigest omitted))`. Trusted code walks that held root by descriptor-relative no-follow traversal and captures the all-and-only regular files at literal `AGENTS.md` or suffix `/AGENTS.md`. Each must be owned by the workspace owner, have literal mode `0600` (decimal 384) or `0644` (decimal 420), and have link count exactly one; executable, group/other-writable, hardlinked, symlink/special/external, owner-mismatched, or changed files fail admission, as do more than 64 files, 1 MiB total bytes, a scan race, or invalid text. Source entries are unique and byte-sorted by canonical path. Each `sourceEntryDigest = SHA-256(JCS({canonicalRootRelativePath,directoryDepth,fileDescriptor,rawBytesRef,rawBytesDigest,rawByteCount}))`; raw digest/count rehash the complete held-file bytes and `fileDescriptor` is reobserved unchanged before releasing the handle.

The instruction manifest's source ref/digest and workspace digest equal that artifact. Its entries are the all-and-only source entries, ordered root-to-deep by `(directoryDepth,canonicalRootRelativePath)` with contiguous `order` and literal `rendering='cliq-all-scopes-labeled-instructions-v1'`; each `instructionSourceEntryDigest` equals the source entry digest at the same path/depth. Raw bytes must already be NFC/LF-normalized UTF-8 with no NUL. `contentRef/contentDigest` decodes `ModelTextV1` whose UTF-8 bytes are byte-identical to the source bytes and whose `textDigest` equals `contentDigest`. The prompt projects every frozen entry once in the exact JCS block defined above; it never dynamically chooses an “applicable” subset from a later tool target. Deeper guidance has scoped precedence only for descendants of its labeled directory. `manifestDigest = SHA-256(JCS(manifest with manifestDigest omitted))`.

Every selected `SkillManifestV1` has a unique `(sourceScope,skillId)`, a mandatory `sourceIdentityRef/sourceIdentityDigest`, and an exact immutable instruction/resource closure; duplicate unqualified ids across scopes are an admission error rather than implicit shadowing. `SkillSourceIdentityV1.sourceIdentityDigest`, `BundledSkillClosureV1.closureDigest`, and `SkillManifestV1.manifestDigest` each omit only themselves under JCS. Source-identity files are unique byte-sorted canonical paths and are exactly `SKILL.md` plus the manifest resources, with matching ref/digest/byte count; `SKILL.md` must be nonempty NFC/LF-normalized UTF-8 with no NUL and deterministically publishes the manifest's exact `ModelTextV1` instruction, while every resource ref/digest equals its source file's raw bytes. Descriptor-captured workspace/user files are same-owner regular files with literal mode `0600|0644|0700|0755`, link count one, unchanged pre/post `fstat`, and complete rehashed bytes; executable modes remain data-only under `kind='executable-disabled'`. A workspace identity rehashes the Session's held `WorkspaceIdentityV1`, requires the displayed same-owner workspace-relative skill-root descriptor at `0700|0755`, and computes each entry digest as SHA-256 JCS of `{sourceScope:'workspace',workspaceIdentityDigest,rootDescriptor,canonicalRelativePath,fileDescriptor,rawBytesRef,rawBytesDigest,rawByteCount}` after descriptor-relative no-follow capture; like `AGENTS.md`, this declarative context closure is separate from SourceManifest and grants no source/tool authority. A user identity rehashes the authenticated `LocalPrincipalIdentityV1`, requires the held owner-only `0700` root descriptor, and uses the exact projection `{sourceScope:'user',principalIdentityDigest,rootDescriptor,canonicalRelativePath,fileDescriptor,rawBytesRef,rawBytesDigest,rawByteCount}`. A bundled identity resolves its `BundledSkillClosureV1`; projecting each identity file to `{canonicalRelativePath,rawBytesRef,rawBytesDigest,rawByteCount}` must equal the closure's file array byte-for-byte in order, and `sourceEntryDigest = SHA-256(JCS({sourceScope:'bundled',bundledClosureDigest,canonicalRelativePath,rawBytesRef,rawBytesDigest,rawByteCount}))`. The Run's signed RuntimeBundle names the closure artifact as an exact `role='skill_bundle', executable=false` entry whose id/version equal `bundleEntryId/bundleEntryVersion`; the entry's signed complete-file digest equals `bundledClosureRef`, and decoding those exact retained bytes yields `BundledSkillClosureV1` whose independently recomputed self-omitting `closureDigest` equals `bundledClosureDigest`. The complete-byte `bundledClosureRef` and semantic `bundledClosureDigest` are distinct hash domains and are never required to equal. The bundle entry points only to the closure bytes and not back to the source identity, so the hash graph is acyclic. Resources are maximum 128/16 MiB, descriptor-contained below the selected skill root, transitively frozen with no cycle or escape, and never executed merely by inclusion. Skills appear in the explicit request order. All source, manifest, instruction, and resource refs remain CAS roots; recovery never rereads mutable `AGENTS.md`, `SKILL.md`, user directories, bundle-install paths, or resource paths.

Pricing artifacts are closed rather than executable plugins. `ModelPriceTableV1` contains nonnegative safe-integer rates and a required four-component `requestTokenCeiling`. `tableDigest = SHA-256(JCS(table with tableDigest and signatureRef omitted))`; its Ed25519 signature, provider/model/endpoint identity and validity through `Run.deadlineAt` all verify. The signed ceiling must bound every request the retained adapter may release (at most 1 MiB), including rejected or ambiguous attempts, for the exact target and billing semantics. Its input/output maxima cover admitted `C` and both requested output caps; cache-read/write maxima are explicit. A signature is not proof of a genuine billing bound: WP06 qualification must substantiate it from authoritative bounds. Rates without a credible complete ceiling, tokenizer estimates or empirical averages are not hard-budget authority and fail `MODEL_COST_UNKNOWN`.

Every remote normal/compaction attempt stores and reserves the full signed vector, irrespective of prompt estimate or its smaller requested output cap. `modelTokens=inputTokens+outputTokens`; `cliq-price-ceil-v1` computes each `ceil(tokens * microsPerMillion / 1_000_000)` with checked integers, then checked-adds all four costs. Managed-local zero cost reserves `(C,requestedOutput,0,0)` and zero cost. The prepared Journal delta is exactly `{modelTokens,costMicros,toolCalls:0,repairAttempts:0}`. Released or possibly released outcomes consume this full reservation; only proven no-release settles zero. Usage is untrusted telemetry, never a refund. Observed per-component or output-cap violations are rejected, but post-release detection cannot retroactively guarantee spend. Conservative reservation may limit useful work for a small budget; it must not be silently relaxed.

Kernel Cut has no provider-hard-cap pricing branch. Creating or reserving a remote cap before the admission transaction would add a second crash/reconciliation protocol, so billable providers are eligible only through the signed immutable table above. `trusted_price_table.maxRunCostMicros` equals the admitted `RunSpec.budgets.costMicros` exactly; individual call reservations are computed only by `cliq-price-ceil-v1` and must fit the remaining ceiling. A shared account limit, local estimate, opaque cap, expired table, missing unit, mismatched endpoint/model, invalid signature, unsafe arithmetic, or mutable calculator fails admission with `MODEL_COST_UNKNOWN` before provider I/O.

The context block is a deterministic planning policy, not exact remote token authority. Text estimate is `ceil(UTF8 byte length/3)`; normal projection estimates add four units per message and include tool definitions, call names/arguments and opaque continuation. Let the stored fields be `C/O/H/T/R/S/K/P`: `C>=32768`, `1<=O<=floor(C/4)`, `H=C-O`, `H-8192>=16384`, `T=min(floor(7*C/10),H-8192)`, `R=min(32768,floor(C/4))`, `S=min(8192,floor(C/8))`. Both `O` and `S` independently fit the provider maximum; `S<=O` is not required. `K` estimates exactly two retained envelope messages with empty source, including their eight overhead units. `P=min(floor(C/2),C-S-K)` and `P>=4096`. Assembly and plan bind the exact envelope/ref/digest and these scalars. Estimates may undercount provider tokenization; rejection stops explicitly without hidden truncation or semantic repair. macOS retains both runtime and guest identities; Linux may omit guest fields only for its retained namespace runtime. RunSpec, ContextManifest/Checkpoint, requests, worker launch and recovery all resolve the same assembly and complete retained graph.

The assembly freezes one Kernel-Cut `ModelRetryPolicy`: exactly three dispatched attempts, zero hidden same-attempt transport retries, and post-attempt delays `[500ms,2000ms]`. Provider response headers—including `Retry-After`—cannot alter this schedule: every positively received rejection is the completed, non-retried typed response above, while only failed/unknown transport attempts may follow these stored delays. Every redispatch after a claim is therefore a new Journal attempt/reservation; SDK auto-retry and an implementation claim that zero request bytes/no billing occurred cannot hide another wire attempt. Exhaustion terminates the model frontier as `failed(runtime_failed)` rather than spinning or silently changing model/mode.

The model delay is measured from the first durable `failed|unknown` settlement timestamp of the most recent dispatched attempt. The next preparation and claim both require canonical `now >= settledAt + delay`; later audit resolution or an intervening pre-dispatch failure cannot restart or shorten this delay. Pre-dispatch failures do not consume dispatched-attempt capacity. A retry preserves the original operation's exact native body, provider/model/mode, output bound, reservation and compaction plan; only its next contiguous attempt identity and audit projection may differ. These Journal-derived conditions are necessary but do not replace the dispatch-closure, live authority, stop/deadline or available-budget checks in section 8.1.

It also freezes one non-configurable policy per executable tool: `retry` is exactly three dispatched attempts with `[500ms,2000ms]`; `workspace-rollback-retry` is exactly two with `[500ms]`; `reconcile|manual` have one productive dispatch and no redispatch delay because their recovery contracts are inspection/manual closure. No public field, repository config, adapter, or tool may raise or lower these values in Kernel Cut. A user grant's `maxAttempts` equals the applicable literal. Predispatch/no-I/O replacement attempts do not consume this dispatched-attempt bound, while every post-claim attempt does. Exhaustion is closed by op kind **and Journal truth**. If the final allowed attempt is positively `failed`, an ordinary tool or MCP call appends one identity-matched error `ToolResultItem` and continues the batch's normal ordered reducer; a child merge appends its structured merge-error result and returns the parent to an agent diagnostic frontier without applying later children; dependency acquisition proposes `runtime_failed` (or the higher-precedence dependency kernel-integrity StopIntent when source integrity failed); publication proposes typed `delivery_publication_failed` and switches to the abort/reconciliation contract. If the final allowed `retry` attempt remains `unknown`, positive dispatch/containment fencing permits conservative settlement but does not invent failure evidence: the reducer proposes `runtime_failed` and closes only through terminal detail plus `RetryUnknownCancelledResult`, never continues that batch or succeeds. Model and verifier attempts use their dedicated frozen policies. None may spin until wall/tool budget happens to expire or choose between error-return and terminal stop at implementation time.

All ceilings are mandatory `Number.isSafeInteger` values after normalization. Defaults are 24 hours elapsed wall time (including waits/reboots), 2,000,000 model input+output tokens, 10,000,000 cost micros (10 USD), 1,000 tool attempts, 2 repairs, child depth 2, and child concurrency 4. Accepted ranges are: `wallTimeMs` 1,000 through 2,592,000,000 (30 days); `modelTokens` 0 through 100,000,000; `costMicros` 0 through 10,000,000,000; `toolCalls` 0 through 1,000,000; `repairAttempts` 0 through 5; `childDepth` 0 through 8; and `childConcurrency` 0 through 32. Zero token/tool/repair/child values disable that action class; zero wall time is invalid. An `operation='agent'` Run whose assembly can dispatch a billable model cannot set `costMicros=0`; a local zero-price model may. An `operation='delivery'` Run inherits the source assembly only for exact provenance/runtime/verifier identity, fixes model tokens/cost/repair to zero, and is storage-forbidden from preparing a model call, so the inherited provider's billing class is irrelevant to its zero model budget. Pricing eligibility is independent of tool capability: any billable model actually dispatchable by a durable agent Run—including text-only mode—requires a bundled Cliq-signed `ModelPriceTableV1` evaluated only by `cliq-price-ceil-v1`. Kernel Cut exposes no provider-cap admission effect, user-defined pricing profile, executable calculator, or hidden config authority. A trusted table must cover the exact provider/model/input/output/cache units and satisfy `validThrough >= Run.deadlineAt`. Otherwise admission fails `MODEL_COST_UNKNOWN`, so a detached Run never outlives its cost authority or degrades into an unaccounted text-only call.

`RunSpec.credentialGrantRefs` is the byte-sorted unique union of provider assembly bindings, `DependencyPolicy.credentialGrantRefs`, and every selected HTTP MCP revision's bindings, with no extra ref. Storage recomputes that union at admission/recovery; it is a GC/audit index, never an independent permission source.

`unverifiedConsentRef` is absent when at least one **required** verifier exists. When the required set is empty (advisory entries may still exist), admission requires exactly one of the versioned consent artifacts above. `runSpecCoreDigest = SHA-256(JCS(normalized RunSpec with unverifiedConsentRef omitted))`; the child form uses that identical projection after all child assembly/policy/verifier/dependency/credential fields are final and names it as `childRunSpecCoreDigest`. `consentDigest = SHA-256(JCS(consent with consentDigest omitted))`. Publication order is acyclic: publish the normalized spec core inputs, compute the core digest, publish the direct/derived consent, then publish the final RunSpec containing its ref and bind both refs in the admitted-request digest. Direct consent binds the local principal/client/channel, timestamp, `admissionIntentDigest`, `runSpecCoreDigest`, and explicit flag. Derived consent binds the full batch/call/index/delegate identity, exact delegate operation grant, `ChildCapabilityGrantV1.grantCoreDigest`, child id/spec core, and explicit helper flag. With `verifierMode='inherit_parent'`, `derivedUnverifiedConsentRef` is forbidden; with `verifierMode='none'`, it and `allowUnverifiedHelper=true` are required, and the child RunSpec names that same ref. The final capability grant may include the consent ref without a hash cycle because the consent binds only its pre-ref core digest; the final admitted request separately hashes both refs. A derived child result is never directly deliverable and its parent must verify the merged final result. Interactive confirmation and noninteractive API flags both become direct consent; client text alone is not authority. Storage recomputes the exact core projection and rejects a required-empty Run without one matching form, a changed field behind the consent, or any consent when the required set is nonempty.

For recursive Runs, token, cost, tool-attempt, and repair-attempt allocations are reserved from the direct parent's remaining ceilings and settled by inclusive descendant usage. Wall time is not summed or refunded: each child deadline is capped by the parent's remaining absolute deadline, and the parent clock continues while waiting. `childDepth` is checked from ancestry. `childConcurrency` means the maximum number of direct nonterminal child Runs admitted by that parent; a slot is released only at child terminal commit.

A terminal Run never returns to `running`. The Kernel Cut has no separate Run-level retry relation; users submit a new Run explicitly, while invocation retries remain Journal attempts under one Run.

## 6. Authoritative Run State

```ts
type RunStatus =
  | 'queued'
  | 'running'
  | 'waiting'
  | 'succeeded'
  | 'completed_unverified'
  | 'failed'
  | 'cancelled'

type RunNextStep = 'agent' | 'tool' | 'verify' | 'finalize' | 'delivery' | null

type WaitingReason =
  | 'approval'
  | 'input'
  | 'child'
  | 'reconciliation'

type BudgetUsage = {
  modelTokens: number
  costMicros: number
  toolCalls: number
  repairAttempts: number
}

type RunFrontier =
  | {
      schemaVersion: 1
      kind: 'agent'
      phase: 'model_turn' | 'context_compaction'
      turnId: string
      contextItemSeq: number
      cause: 'initial' | 'tool_batch_complete' | 'repair' | 'child_results' | 'input'
      compactionPlanRef?: ArtifactRef
    }
  | {
      schemaVersion: 1
      kind: 'tool'
      batchItemId: string
      orderedCallIds: string[]
      nextCallIndex: number
    }
  | {
      schemaVersion: 1
      kind: 'verify'
      phase: 'dependencies' | 'verifiers'
      candidateItemId: string
      resultSourceRef: ArtifactRef
      verifierPlanRef: ArtifactRef
      dependencyPlanRef?: ArtifactRef
      nextVerifierIndex: number
      afterPass: 'finalize' | 'delivery_approval'
    }
  | {
      schemaVersion: 1
      kind: 'finalize'
      operation: 'agent'
      candidateItemId: string
      resultSourceRef: ArtifactRef
      verificationClosureRef: ArtifactRef
      deliveryTerminalProjectionEvidenceRef?: never
    }
  | {
      schemaVersion: 1
      kind: 'finalize'
      operation: 'delivery'
      candidateItemId: string
      resultSourceRef: ArtifactRef
      verificationClosureRef: ArtifactRef
      deliveryTerminalProjectionEvidenceRef: ArtifactRef
    }
  | {
      schemaVersion: 1
      kind: 'delivery'
      sourceRunResultRef: ArtifactRef
      phase: 'merge'
      capturedWorkspaceRef: ArtifactRef
    }
  | {
      schemaVersion: 1
      kind: 'delivery'
      sourceRunResultRef: ArtifactRef
      phase: 'approval'
      candidateItemId: string
      resultSourceRef: ArtifactRef
      verifierPlanRef: ArtifactRef
      verificationClosureRef: ArtifactRef
      deliveryPlanRef: ArtifactRef
    }
  | {
      schemaVersion: 1
      kind: 'delivery'
      sourceRunResultRef: ArtifactRef
      phase: 'publish' | 'abort_cleanup'
      candidateItemId: string
      resultSourceRef: ArtifactRef
      verifierPlanRef: ArtifactRef
      verificationClosureRef: ArtifactRef
      deliveryPlanRef: ArtifactRef
      nextPathOperationIndex: number
    }

type ApprovalSubject = {
  policyChannelEvidenceRef: ArtifactRef
  policyChannelEvidenceDigest: string
} & (
  | ({
      kind: 'tool_call'
      batchItemId: string
      callId: string
      callIndex: number
      opId: string
      target: string
      toolName: string
      toolContractDigest: string
      replayClass: ReplayClass
    } & (
      | { policySubjectKind: 'ordinary_tool'; childMode?: never }
      | { policySubjectKind: 'child_delegate'; childMode: 'read_only' | 'mutating' }
    ))
  | {
      kind: 'verifier_launch'
      candidateItemId: string
      resultSourceRef: ArtifactRef
      verifierPlanRef: ArtifactRef
      verifierIndex: number
      verifierId: string
      verifierSpecDigest: string
      opId: string
      target: string
      required: boolean
    }
  | {
      kind: 'mcp_server_launch'
      registryRevisionRef: ArtifactRef
      registryManifestDigest: string
      lifecycleSeq: number
      opId: string
      originatingBatchItemId: string
      originatingCallId: string
      originatingCallIndex: number
    }
  | {
      kind: 'delivery_plan'
      deliveryPlanRef: ArtifactRef
      deliveryPlanDigest: string
      operationSetDigest: string
      opId: string
    }
  | {
      kind: 'dependency_install_scripts'
      dependencyPlanRef: ArtifactRef
      lockfileDigest: string
      resultSourceRef: ArtifactRef
      installScripts: true
      opId: string
    }
)

type ApprovalDecisionV1 = {
  schemaVersion: 1
  format: 'cliq-approval-decision-v1'
  decisionId: string
  principalId: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  runId: string
  waitingSubjectRef: ArtifactRef
  waitingSubjectDigest: string
  frontierRef: ArtifactRef
  subject: ApprovalSubject
  subjectDigest: string
  requestId: string
  requestDigest: string
  expectedRunRevision: number
  decision: 'allow' | 'deny'
  requestedTtlMs?: number
  grantExpiresAt?: string
  createdAt: string
  decisionDigest: string
}

type McpRecoveryProbeEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-recovery-probe-evidence-v1'
  runId: string
  waitingSubjectRef: ArtifactRef
  opId: string
  attempt: number
  probeKind: 'automatic' | 'user_requested'
  probeOrdinal: number
  probeNonceDigest: string
  probeDispatchDigest: string
  registryRevisionRef: ArtifactRef
  registryManifestDigest: string
  serverToolName: string
  profileId: string
  profileDigest: string
  statusRequestTemplateRef: ArtifactRef
  statusRequestTemplateDigest: string
  statusRequestDigest: string
  brokerDispatchId: string
  brokerTargetDigest: string
  statusResponseRef: ArtifactRef
  statusResponseDigest: string
  completedPredicateRef: ArtifactRef
  completedPredicateDigest: string
  failedPredicateRef: ArtifactRef
  failedPredicateDigest: string
  disposition: 'completed' | 'failed' | 'unresolved'
  observedAt: string
  evidenceDigest: string
}

type WorkerRecoveryEvidenceBaseV1 = {
  schemaVersion: 1
  format: 'cliq-worker-recovery-evidence-v1'
  runId: string
  waitingSubjectRef: ArtifactRef
  oldWorkerLaunchId: string
  oldLeaseEpoch: number
  oldWorkerIdentityDigest: string
  processContainmentRef: ArtifactRef
  containmentDeathEvidenceRef: ArtifactRef
  containmentDeathEvidenceDigest: string
  workspaceGenerationRef: ArtifactRef
  generationTreeDigest: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  evidenceDigest: string
}

type WorkerRecoveryEvidenceV1 = WorkerRecoveryEvidenceBaseV1 & (
  | {
      generationDisposition: 'quarantined'
      restoredCheckpointId?: never
      restoredWorkspaceStateRef?: never
      replacementWorkspaceGenerationRef?: never
    }
  | {
      generationDisposition: 'restored_from_checkpoint'
      restoredCheckpointId: string
      restoredWorkspaceStateRef: ArtifactRef
      replacementWorkspaceGenerationRef: ArtifactRef
    }
)

type ReconciliationProbeDispatchV1 = {
  schemaVersion: 1
  format: 'cliq-reconciliation-probe-dispatch-v1'
  runId: string
  reconciliationSubjectDigest: string
  probeKind: 'automatic' | 'user_requested'
  probeOrdinal: number
  probeNonceDigest: string
  probeStartedAt: string
  probeDeadlineAt: string
  owningSupervisorInstanceId: string
  dispatchDigest: string
} & (
  | {
      subjectKind: 'mcp_recovery'
      brokerDispatchId: string
      brokerRequestDigest: string
      brokerTargetDigest: string
      brokerFenceTokenDigest: string
    }
  | {
      subjectKind: 'publication'
      inspectorTaskId: string
      inspectionTargetDigest: string
    }
  | {
      subjectKind: 'worker_recovery'
      inspectorTaskId: string
      inspectionTargetDigest: string
    }
)

type ReconciliationInspectorTaskClosureV1 =
  | {
      closureKind: 'cancelled_and_joined'
      inspectorTaskCancelledAndJoined: true
      ownerDeathAcquisitionEvidenceRef?: never
      ownerDeathAcquisitionEvidenceDigest?: never
    }
  | {
      closureKind: 'owner_process_dead'
      ownerDeathAcquisitionEvidenceRef: ArtifactRef
      ownerDeathAcquisitionEvidenceDigest: string
      inspectorTaskCancelledAndJoined?: never
    }

type ReconciliationProbeTimeoutClosureV1 = {
  schemaVersion: 1
  format: 'cliq-reconciliation-probe-timeout-closure-v1'
  runId: string
  waitingSubjectRef: ArtifactRef
  probeKind: 'automatic' | 'user_requested'
  probeOrdinal: number
  probeNonceDigest: string
  probeDispatchDigest: string
  probeDeadlineAt: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  closedAt: string
  closureDigest: string
} & (
  | {
      subjectKind: 'mcp_recovery'
      brokerDispatchId: string
      brokerTargetDigest: string
      brokerFenceTokenDigest: string
      noActiveReleaseForNonce: true
    }
  | {
      subjectKind: 'publication'
      deliveryPlanRef: ArtifactRef
      pathOperationId: string
      attempt: number
      inspectorTaskId: string
      taskClosure: ReconciliationInspectorTaskClosureV1
    }
  | {
      subjectKind: 'worker_recovery'
      oldWorkerLaunchId: string
      processContainmentRef: ArtifactRef
      inspectorTaskId: string
      taskClosure: ReconciliationInspectorTaskClosureV1
    }
)

type ReconciliationProbeEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-reconciliation-probe-evidence-v1'
  runId: string
  waitingSubjectRef: ArtifactRef
  waitingSubjectDigest: string
  probeKind: 'automatic' | 'user_requested'
  probeOrdinal: number
  probeNonceDigest: string
  probeDispatchDigest: string
  probeStartedAt: string
  probeDeadlineAt: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  evidenceDigest: string
} & (
  | {
      outcome: 'subject_observation'
      subjectEvidenceKind: 'mcp_recovery' | 'publication' | 'worker_recovery'
      subjectEvidenceRef: ArtifactRef
      subjectEvidenceDigest: string
      timeoutClosureRef?: never
      timeoutClosureDigest?: never
    }
  | {
      outcome: 'probe_timeout'
      timeoutReason: 'no_authoritative_observation_before_deadline'
      timeoutClosureRef: ArtifactRef
      timeoutClosureDigest: string
      subjectEvidenceKind?: never
      subjectEvidenceRef?: never
      subjectEvidenceDigest?: never
    }
)

type ReconciliationSubject =
  | {
      kind: 'invocation'
      recovery: 'mcp_reconcile'
      opKind: 'mcp'
      opId: string
      attempt: number
      registryRevisionRef: ArtifactRef
      registryManifestDigest: string
      serverToolName: string
      profileId: string
      profileDigest: string
      statusRequestTemplateRef: ArtifactRef
      statusRequestTemplateDigest: string
      completedPredicateRef: ArtifactRef
      completedPredicateDigest: string
      failedPredicateRef: ArtifactRef
      failedPredicateDigest: string
    }
  | {
      kind: 'invocation'
      recovery: 'manual'
      opKind: 'tool' | 'mcp'
      opId: string
      attempt: number
    }
  | {
      kind: 'publication_path'
      deliveryPlanRef: ArtifactRef
      pathOperationId: string
      attempt: number
    }
  | {
      kind: 'worker_death'
      oldWorkerLaunchId: string
      oldLeaseEpoch: number
      oldWorkerIdentity: string
      processContainmentRef: ArtifactRef
      workspaceGenerationRef: ArtifactRef
      openInvocationRefs: ArtifactRef[]
    }

type ReconciliationLastProbeEvidenceV1 =
  | {
      lastProbeEvidenceRef?: never
      lastProbeEvidenceDigest?: never
    }
  | {
      lastProbeEvidenceRef: ArtifactRef
      lastProbeEvidenceDigest: string
    }

type ReconciliationProbeStateV1 =
  | {
      phase: 'manual_only'
      automaticProbeCount: 0
      userProbeCount: 0
    }
  | {
      phase: 'automatic_pending'
      automaticProbeCount: 0
      userProbeCount: 0
      nextProbeAt: string
      lastProbeEvidenceRef?: never
      lastProbeEvidenceDigest?: never
    }
  | {
      phase: 'automatic_pending'
      automaticProbeCount: 1 | 2 | 3 | 4 | 5 | 6 | 7
      userProbeCount: 0
      nextProbeAt: string
      lastProbeEvidenceRef: ArtifactRef
      lastProbeEvidenceDigest: string
    }
  | {
      phase: 'automatic_in_flight'
      automaticProbeCount: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8
      userProbeCount: 0
      dispatch: ReconciliationProbeDispatchV1 & {
        probeKind: 'automatic'
        probeOrdinal: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8
      }
    }
  | {
      phase: 'automatic_exhausted'
      automaticProbeCount: 8
      userProbeCount: number
      lastProbeEvidenceRef: ArtifactRef
      lastProbeEvidenceDigest: string
    }
  | {
      phase: 'user_in_flight'
      automaticProbeCount: 8
      userProbeCount: number
      dispatch: ReconciliationProbeDispatchV1 & {
        probeKind: 'user_requested'
        probeOrdinal: number
        controlRequestId: string
        controlRequestDigest: string
      }
    }

type WaitingSubject =
  | {
      schemaVersion: 1
      kind: 'approval'
      runId: string
      createdFromRevision: number
      createdAt: string
      frontierRef: ArtifactRef
      subject: ApprovalSubject
    }
  | {
      schemaVersion: 1
      kind: 'input'
      runId: string
      createdFromRevision: number
      createdAt: string
      frontierRef: ArtifactRef
      inputRequestItemId: string
      batchItemId: string
      callId: string
    }
  | {
      schemaVersion: 1
      kind: 'child'
      runId: string
      createdFromRevision: number
      createdAt: string
      frontierRef: ArtifactRef
      subject:
        | {
            kind: 'await_tool'
            waitSetRef: ArtifactRef
            awaitBatchItemId: string
            awaitCallId: string
            awaitCallIndex: number
          }
        | { kind: 'finalize_settlement'; waitSetRef: ArtifactRef; modelTurnItemId: string }
        | {
            kind: 'stop_settlement'
            waitSetRef: ArtifactRef
            stopIntentRef: ArtifactRef
            awaitOrigin?: { batchItemId: string; callId: string; callIndex: number }
          }
    }
  | {
      schemaVersion: 1
      kind: 'reconciliation'
      runId: string
      createdFromRevision: number
          createdAt: string
          frontierRef: ArtifactRef
          subject: ReconciliationSubject
          probeState: ReconciliationProbeStateV1
        }

type RunTerminalReason =
  | 'verified'
  | 'no_required_verifier'
  | 'verification_failed'
  | 'verifier_infrastructure_failed'
  | 'verifier_mutated_source'
  | 'budget_exhausted'
  | 'runtime_failed'
  | 'cancelled_by_user'
  | 'parent_cancelled'

type StopIntentBase = {
  schemaVersion: 1
  runId: string
  createdAt: string
}

type KernelIntegrityEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-kernel-integrity-evidence-v1'
  runId: string
  sourceProjectionRef: ArtifactRef
  workspaceGenerationRef: ArtifactRef
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  evidenceDigest: string
} & (
  | {
      subjectKind: 'verifier'
      verifierOpId: string
      verifierAttempt: number
      resultSourceRef: ArtifactRef
      dependencyPlanRef?: never
      dependencyOpId?: never
      dependencyAttempt?: never
    }
  | {
      subjectKind: 'dependency_acquisition'
      dependencyPlanRef: ArtifactRef
      dependencyOpId: string
      dependencyAttempt: number
      verifierOpId?: never
      verifierAttempt?: never
      resultSourceRef?: never
    }
) & (
  | {
      observationKind: 'audited_write_attempt'
      processContainmentRef: ArtifactRef
      sandboxLaunchSpecRef: ArtifactRef
      operationRequestRef: ArtifactRef
      operationRequestDigest: string
      targetCanonicalRootRelativePath: string
      requestedAccess: 'create' | 'write' | 'truncate' | 'rename' | 'delete' | 'metadata_mutation'
      enforcementPoint: 'sandbox_filesystem' | 'trusted_broker'
      disposition: 'blocked_before_write'
      sourceBeforeRef: ArtifactRef
      sourceBeforeDigest: string
      sourceAfterRef: ArtifactRef
      sourceAfterDigest: string
      changedEntryDigests?: never
    }
  | ({
      observationKind: 'source_digest_drift'
      sourceBeforeRef: ArtifactRef
      sourceBeforeDigest: string
      sourceAfterRef: ArtifactRef
      sourceAfterDigest: string
      changedEntryDigests: string[]
      operationRequestRef?: never
      operationRequestDigest?: never
      targetCanonicalRootRelativePath?: never
      requestedAccess?: never
      enforcementPoint?: never
      disposition?: never
    } & (
      | {
          observationSource: 'trusted_out_of_containment_rehash'
          processContainmentRef?: never
          sandboxLaunchSpecRef?: never
        }
      | {
          observationSource: 'claimed_process_rehash'
          processContainmentRef: ArtifactRef
          sandboxLaunchSpecRef: ArtifactRef
        }
    ))
)

type RuntimeFailureEvidenceBaseV1 = {
  schemaVersion: 1
  format: 'cliq-runtime-failure-evidence-v1'
  runId: string
  frontierRef: ArtifactRef
  frontierDigest: string
  failingOpId: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  evidenceDigest: string
}

type RuntimeFailureEvidenceV1 = RuntimeFailureEvidenceBaseV1 & (
  | {
      failureKind: 'model_unusable_response'
      unusableResponseRef: ArtifactRef
      unusableResponseDigest: string
    }
  | {
      failureKind: 'model_attempts_exhausted'
      attempt: number
      terminalJournalSeq: number
      modelRequestRef: ArtifactRef
      modelRequestDigest: string
      failureCode: 'transport_exhausted'
    }
  | {
      failureKind: 'credential_redemption_failed'
      credentialGrantRef: ArtifactRef
      credentialGrantDigest: string
      endpointRegistrationRef: ArtifactRef
      endpointRegistrationDigest: string
      credentialAuthorityRecordDigest: string
      authorityRevision: number
      credentialServiceRevision: number
      failureCode: 'expired' | 'revoked' | 'platform_item_absent' | 'platform_store_unavailable'
    }
  | {
      failureKind: 'retry_unknown_exhausted'
      retryUnknownResultRef: ArtifactRef
      retryUnknownResultDigest: string
    }
  | {
      failureKind: 'dependency_acquisition_failed'
      dependencyPlanRef: ArtifactRef
      dependencyPlanDigest: string
      attempt: number
      terminalJournalSeq: number
      failureCode: 'download_exhausted' | 'integrity_exhausted' | 'install_failed' | 'credential_unavailable'
    }
  | {
      failureKind: 'local_service_identity_mismatch'
      localProvenanceRef: ArtifactRef
      localProvenanceDigest: string
      serviceSpecRef: ArtifactRef
      serviceSpecDigest: string
      boundaryEvidenceRef: ArtifactRef
      boundaryEvidenceDigest: string
      failureCode: 'missing_active_launch' | 'stable_identity_mismatch' | 'boundary_invalid'
    }
)

type StopIntent =
  | (StopIntentBase & {
      origin: 'kernel_integrity'
      targetStatus: 'failed'
      reason: 'verifier_mutated_source'
      verifierOpId: string
      integrityEvidenceRef: ArtifactRef
      integrityEvidenceDigest: string
    })
  | (StopIntentBase & {
      origin: 'kernel_integrity'
      targetStatus: 'failed'
      reason: 'runtime_failed'
      source: 'dependency_acquisition'
      dependencyPlanRef: ArtifactRef
      failingOpId: string
      integrityEvidenceRef: ArtifactRef
      integrityEvidenceDigest: string
    })
  | (StopIntentBase & {
      origin: 'user_cancel'
      targetStatus: 'cancelled'
      reason: 'cancelled_by_user'
      requestId: string
      principalId: string
    })
  | (StopIntentBase & {
      origin: 'parent_cancel'
      targetStatus: 'cancelled'
      reason: 'parent_cancelled'
      sourceRunId: string
      sourceStopIntentRef: ArtifactRef
    })
  | (StopIntentBase & {
      origin: 'deadline'
      targetStatus: 'failed'
      reason: 'budget_exhausted'
      deadlineAt: string
    })
  | (StopIntentBase & {
      origin: 'budget'
      targetStatus: 'failed'
      reason: 'budget_exhausted'
      counter: keyof BudgetUsage
      ceiling: number
      consumed: number
      reserved: number
      required: number
    })
  | (StopIntentBase & {
      origin: 'verification'
      targetStatus: 'failed'
      reason: 'verification_failed' | 'verifier_infrastructure_failed'
      candidateItemId: string
      verifierPlanRef: ArtifactRef
    })
  | (StopIntentBase &
      {
        origin: 'policy_deny'
        targetStatus: 'failed'
        opId: string
        policyChannelEvidenceRef: ArtifactRef
        policyChannelEvidenceDigest: string
      } & (
        | { subjectKind: 'verifier'; reason: 'verification_failed' }
        | { subjectKind: 'delivery' | 'dependency_install_scripts'; reason: 'runtime_failed' }
      ))
  | (StopIntentBase &
      {
        origin: 'runtime'
        targetStatus: 'failed'
        reason: 'runtime_failed'
      } & (
        | {
            runtimeSubtype: 'context_compaction_failed'
            compactionPlanRef: ArtifactRef
            modelOpId: string
            attempt: number
          }
        | {
            runtimeSubtype: 'context_window_exhausted'
            contextManifestRef: ArtifactRef
            nextPromptTokens: number
            triggerThresholdTokens: number
            hardPromptTokens: number
            protectedTokens: number
            sourceInputTokenCap: number
          }
        | {
            runtimeSubtype: 'delivery_merge_conflict'
            deliveryMergeConflictItemRef: ArtifactRef
            conflictRef: ArtifactRef
          }
        | {
            runtimeSubtype: 'delivery_publication_failed'
            deliveryPlanRef: ArtifactRef
            sequence: 'forward' | 'abort'
            operationId: string
          }
        | {
            runtimeSubtype: 'local_inference_unavailable'
            activationCycleId: string
            serviceId: string
            frontierRef: ArtifactRef
            failureDetailRef: ArtifactRef
          }
        | {
            runtimeSubtype: 'runtime'
            failingOpId: string
            runtimeFailureRef: ArtifactRef
            runtimeFailureDigest: string
          }
      ))
  | (StopIntentBase & {
      origin: 'manual_abandon'
      targetStatus: 'cancelled'
      reason: 'cancelled_by_user'
      requestId: string
      principalId: string
      opId: string
      attempt: number
      attestationRef: ArtifactRef
    })

type Run = {
  id: string
  sessionId: string
  parentRunId?: string
  specRef: ArtifactRef
  status: RunStatus
  nextStep: RunNextStep
  frontierRef?: ArtifactRef
  waitingReason?: WaitingReason
  waitingOnRef?: ArtifactRef
  revision: number
  leaseEpoch: number
  activeWorkerLaunchId?: string
  latestCheckpointId: string
  budgetReserved: BudgetUsage
  budgetConsumed: BudgetUsage
  repairCount: number
  resultRef?: ArtifactRef
  terminalReason?: RunTerminalReason
  terminalDetailRef?: ArtifactRef
  stopIntentRef?: ArtifactRef
  cancelRequested: boolean
  createdAt: string
  deadlineAt: string
  updatedAt: string
}
```

Every nonterminal Run carries a non-null `nextStep` and a `frontierRef` whose verified `RunFrontier.kind` exactly matches it; queued and waiting Runs preserve that same immutable frontier until a subject-specific reducer deliberately replaces it. Every terminal Run has `nextStep=null`, no `frontierRef`, an authoritative `terminalReason`, and no active lease/wait fields. `terminalDetailRef` is required if and only if status is `failed|cancelled`; succeeded/unverified results forbid it. Display events are never the source of stop truth.

The status/reason mapping is exact: `succeeded -> verified`; `completed_unverified -> no_required_verifier`; `failed -> verification_failed | verifier_infrastructure_failed | verifier_mutated_source | budget_exhausted | runtime_failed`; and `cancelled -> cancelled_by_user | parent_cancelled`. Nonterminal Runs have no terminal fields. New terminal meanings require a schema/RFC change rather than an untyped error string.

`stopIntentRef` is the authoritative target while quiescence work delays terminal commit. The store validates the artifact and chooses the winning intent by fixed precedence: any `origin='kernel_integrity'` > `cancelled_by_user` > `parent_cancelled` > `budget_exhausted` > `verification_failed` > `verifier_infrastructure_failed` > ordinary `runtime_failed`; equal-precedence intents retain the earliest committed one, with artifact digest as the deterministic tie-break inside one transaction. A later higher-precedence fact may replace the pointer, but a lower/equal one cannot. `origin='budget'` is required for additive token/cost/tool/repair exhaustion and proves `consumed + reserved + required > ceiling`; wall expiry uses only `origin='deadline'`. `cancelRequested` is a monotonic dispatch index set by any user/parent cancellation intent even if later integrity evidence wins; it is not terminal-reason truth. Every productive dispatch requires no stop intent. `commitTerminalStop` validates and retains the current winning artifact after terminal quiescence and derives status/reason/detail from it; recovery never guesses from events or the last error. Failed/cancelled terminal Runs retain that ref, while succeeded/unverified Runs require it absent.

Stop-to-**reason-detail** derivation is total and one-to-one; `StopIntentBase` deliberately has no generic evidence ref. The terminal primary-evidence matrix is exact and acyclic: verifier/dependency integrity use `integrityEvidenceRef`; parent cancellation uses `sourceStopIntentRef`; local-inference failure uses `failureDetailRef`; direct verifier/delivery/dependency policy denial uses `policyChannelEvidenceRef`; generic runtime uses `runtimeFailureRef`; manual abandon uses `attestationRef`; every user cancellation, deadline/budget, verification, context-compaction/window, delivery-merge, or delivery-publication branch uses the winning `stopIntentRef` itself after that immutable artifact has been published. The corresponding `TerminalReasonDetail` copies the exact branch fields; its `stopIntentRef|evidenceRef` where present equals that same selected primary ref. Each `origin='runtime'` variant maps only to the detail with identical `runtimeSubtype`; generic runtime requires its exact `RuntimeFailureEvidenceV1` ref/digest and matching `failingOpId`. Storage rejects a subtype/detail mismatch, missing field, alternate primary ref, or caller-selected reason projection. This post-publication pointer creates no content hash cycle because the StopIntent contains no self ref. The surrounding publication/manual/retry closure fields are a separate deterministic projection of authoritative Journal/items at terminal quiescence; they may close facts learned after the winning intent without changing its reason. Candidate, diagnostic, verifier-receipt, and child-result facts remain in their already ordered typed Run-item/Journal graph and are not copied into implementation-selected TerminalDetail lists.

`RuntimeFailureEvidenceV1.evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`. Its Run/frontier/failing op/current-inspector fields equal the proposed Run and the inspector is fresh under the canonical five-second rule. `model_unusable_response` rehashes the exact `ModelUnusableResponseV1` that is the completed Journal result for that op. `model_attempts_exhausted` names the final contiguous failed model attempt, exact normal/compaction request, Journal sequence, and literal `transport_exhausted`; that failed row must satisfy the ordinary pre-dispatch or exact post-claim-no-release closure and therefore cannot claim a provider response. `credential_redemption_failed` is produced while holding the credential-authority lock before target I/O; its immutable binding/endpoint equal the Run assembly, and its latest authority-record digest/revisions plus canonical time or platform-store observation prove exactly expired, revoked, absent item, or unavailable store. `retry_unknown_exhausted` rehashes exact `RetryUnknownCancelledResult` and its Journal/settlement/dispatch-closure chain. `dependency_acquisition_failed` equals the current candidate plan and final acquisition Journal attempt/sequence with one closed failure code. `local_service_identity_mismatch` rehashes the assembly provenance/service spec plus the current boundary evidence that failed the active-launch/stable-identity gate before provider release. No branch accepts another branch's members, generic diagnostic text, a provider/worker boolean, or an untyped Journal error. The StopIntent and TerminalDetail repeat the same evidence ref/digest/failing op, and storage re-walks the named Journal/request/authority graph before terminal commit.

Kernel-integrity stop evidence is one closed chain. `KernelIntegrityEvidenceV1.evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`; its Run/source projection/generation/current inspector match the exact Journal claim and frozen RunSpec. Canonical target paths are NFC admitted-root-relative paths with no empty/`.`/`..` component. An `audited_write_attempt` is emitted only by the strong sandbox filesystem or trusted broker at the blocked syscall/request boundary, repeats the exact request/containment/SandboxLaunch, has `sourceBeforeRef === sourceAfterRef` and equal digests, and proves no byte changed. A `source_digest_drift` rehashes two exact SourceManifests, requires unequal digests and a nonempty unique byte-sorted list of the changed WorkspaceEntry digests. Its source XOR either forbids both containment/spec refs for a trusted Supervisor rehash outside a child process, or requires both and matches them to the same owning Journal claim and actual containment; ref-only or spec-only drift is invalid. The verifier subject matches one verifier Journal op/attempt/result source, while dependency matches the exact candidate plan and acquisition op/attempt. For both kernel-integrity StopIntent variants, branch `integrityEvidenceRef` and digest name this same artifact; `TerminalReasonDetail` and `primaryEvidenceRef` copy the identical ref/digest. A verifier `source_mutation` receipt requires both violation fields and the verifier form of this artifact; every other outcome forbids both. The audited branch requires equal receipt source digests, the drift branch requires unequal ones. Dependency completion/ready state is forbidden and its integrity StopIntent uses the dependency form. A generic CAS ref, verifier text, caught un-audited read-only error, or adapter assertion cannot win kernel-integrity precedence.

`Run.resultRef` exists if and only if status is `succeeded|completed_unverified`. Failed/cancelled candidate, diagnostic, and audit artifacts are reachable only through `terminalDetailRef` or typed Run items; they are never mislabeled RunResults. Every admitted Run has a non-null `latestCheckpointId` from the admission transaction onward; terminal/history rows retain it. There is no persisted accepted state before that initial ready Checkpoint.

`nextStep` is an indexed discriminator, not a second source of truth. The immutable `RunFrontier` is the complete resumable cursor: exact normal-model or context-compaction phase/context cursor, ordered tool batch and next call, immutable candidate plus ordered verifier plan/index, finalize closure, or delivery phase/plan/path index. An agent frontier requires `compactionPlanRef` if and only if phase is `context_compaction`. Every frontier change, its matching typed Run item, Run revision, and any Journal/budget change commit atomically. Storage rejects a discriminator/artifact mismatch, an out-of-range index, a verifier plan that differs from the frozen RunSpec, or a frontier whose referenced item/result is not owned by this Run. Recovery never derives a frontier from prompt text, display events, receipt enumeration, or directory contents.

A verify frontier begins at `phase='dependencies'` if and only if RunSpec's `dependencyPolicyRef` enabled setup, the candidate-bound VerifierPlan contains its derived `dependencyPlanRef`, and no matching ready Checkpoint for that candidate/plan is current; in that phase `nextVerifierIndex` is zero. Otherwise it begins at `phase='verifiers'` and the frontier-local dependency ref is absent. The completion transaction removes that frontier-local ref after binding readiness through `DependencyReadyItem`/Checkpoint; no verifier or model repair may race setup.

Delivery frontiers are a closed proof-carrying union. Admission already captured the real workspace, so the first delivery frontier is `phase='merge'` with exact `sourceRunResultRef` and `capturedWorkspaceRef`; there is no post-admission capture phase. After merge, verification uses the common verify frontier. When `afterPass='delivery_approval'`, the final verifier/dependency transaction publishes `VerificationClosureV1` but installs `delivery:approval`, not `finalize`, and carries the exact candidate/result/verifier-plan/closure/plan refs. Approval and every publish/abort reducer preserve those bytes unchanged. The last successful forward operation (or a zero-operation no-op path) additionally publishes exact `DeliveryTerminalProjectionEvidence` and installs `finalize(operation='delivery')` carrying both refs. An agent finalize forbids `deliveryTerminalProjectionEvidenceRef`; a delivery finalize requires it. Thus approval/publication cannot discard or reconstruct verification truth.

`waitingOnRef` always names an immutable, schema-validated `WaitingSubject` whose `kind` matches `waitingReason` and whose embedded `frontierRef` equals the Run's current frontier. The subject—not an error string—preserves the exact approval/input/child/reconciliation identity. In particular, a worker-death subject retains the old epoch, process-containment identity, generation, and open invocations after active ownership fields are cleared. No generic “clear wait” mutation exists; only the closed subject-specific reducers in section 9 may replace the frontier and queue or stop the Run.

Wall time is not an additive reservation. Admission persists `deadlineAt = createdAt + normalized RunSpec.budgets.wallTimeMs`; a child uses the earlier of that computed deadline and its parent's `deadlineAt`. Time continues through waits, detach, process death, and reboot. At or after the deadline the Supervisor atomically proposes the typed `budget_exhausted` StopIntent, applies precedence, forbids every new productive/semantic dispatch, and terminal-fails only after quiescence. It does not erase unsafe ambiguity to make that terminal state: unresolved `reconcile|manual` external effects remain `waiting(reconciliation)`, and a parent with outstanding child allocations remains `waiting(child)`, until positive resolution/settlement makes terminalization safe. A fully settled `retry` invocation may be abandoned after the old dispatch is fenced/dead because its result cannot affect Run state; its `unknown` audit fact remains and the terminal detail records abandonment. A `workspace-rollback-retry` invocation becomes quiescent only after old-worker death plus generation quarantine/rollback evidence resolves it as failed. Dispatch propagates the absolute deadline and caps the operation timeout to the remaining interval; expiry is a wall-budget stop intent, not verifier infrastructure failure. `BudgetUsage` contains only additive reservable/settleable counters. Model input and output are retained separately in invocation usage/telemetry, but their sum alone increments `BudgetUsage.modelTokens`; reservations, consumption, and child allocations therefore enforce `reserved.modelTokens + consumed.modelTokens <= RunSpec.budgets.modelTokens` without a per-direction double ceiling. `repairCount` counts repairs executed by this Run itself, while `budgetConsumed.repairAttempts` is inclusive of settled descendant usage; an own repair increments both.

Lease ownership is status-exact without turning heartbeats into workflow mutations. `Run` stores only the monotonic `leaseEpoch` and, while running, `activeWorkerLaunchId`; worker identity, process containment, generation, lease expiry, and heartbeat version live in that activated `worker_launches` row. `queued`, `waiting`, and terminal Runs have no active launch pointer. A queued Run may have at most one bounded `reserved|preactivated` launch intent; a worker-death reconciliation wait may retain one non-active `reconciling` launch row referenced by its WaitingSubject. `running` requires its pointer to name exactly one `activated` row for this Run and epoch. An expired running activation remains pointed to until recovery atomically clears it and moves the launch to `reconciling|retired`; expiry is never silently rewritten as queued. Only the Supervisor's blocked activation transaction may install the pointer and transition `queued -> running`. Returning to queued never ignores an unretired launch.

Heartbeat is a narrow lease CAS on the activated launch row: `(launchId, leaseVersion, runId, leaseEpoch, workerIdentityDigest) -> (leaseVersion+1, leaseExpiresAt)`. It rechecks that the Run is still running and points at that launch, but it does **not** change Run revision/`updatedAt`, append a Run item, or emit `RunEvent`. Activation, recovery ownership change, and retirement are workflow mutations and do increment Run revision exactly once. Every dispatch/evidence decision reads the Run and exact launch row from one SQLite snapshot/transaction, so a heartbeat can neither invalidate a prepared frontier revision nor revive a retired activation.

A terminal Run has every `budgetReserved` counter equal to zero, no frontier/open typed continuation, no unclosed tool call, no unresolved `reconcile|manual` invocation, no unrolled-back workspace invocation, no outstanding child allocation or unsatisfied child wait set, no live MCP-server containment, and no unresolved publication path. A normal call closes with exactly one `ToolResultItem`; the sole non-result closure is one identity-matched `ToolAbandonedItem` for the same manual invocation named by `TerminalDetail.abandonedManualInvocation`. A tool/MCP call whose fully settled `retry` attempt remains unknown closes only at terminal stop with `ToolResultItem(outcome='cancelled')` whose result ref is the exact `RetryUnknownCancelledResult`; this reports that Cliq did not use the ambiguous result, not that the external call was cancelled. Non-call retry unknowns require no call item. Those closures never continue the batch or enter a succeeding result. A terminal Run may retain such a retry unknown only when its old dispatch is proven fenced/dead and it is explicitly listed in terminal detail. Deadline, cancellation, or parent cancellation may stop new work immediately, but none can violate this terminal-quiescence invariant; ambiguous reservations are conservatively consumed before terminal commit.

`verifying` and `recovering` are observable phases, not additional durable statuses. Verification is represented by `status='running', nextStep='verify'`. Recovery is an operation performed by the Supervisor against a revisioned Run.

## 7. Checkpoint Contract

```ts
type Checkpoint = {
  id: string
  schemaVersion: 1
  runId: string
  basedOnRunRevision: number
  runItemSeq: number
  contextManifestRef: ArtifactRef
  journalSeq: number
  workspaceStateRef: ArtifactRef
  createdAt: string
  reason: 'initial' | 'auto' | 'manual' | 'pre-effect' | 'handoff'
}
```

### 7.1 What The References Contain

The formats are versioned recovery contracts, not implementation-private JSON:

```ts
type ContextSegment =
  | {
      kind: 'raw'
      fromItemSeq: number
      throughItemSeq: number
      items: Array<{ itemSeq: number; itemRef: ArtifactRef }>
    }
  | {
      kind: 'summary'
      fromItemSeq: number
      throughItemSeq: number
      compactionItemId: string
      summaryRef: ArtifactRef
      summaryDigest: string
      sourceItemsDigest: string
      preservedItemRefs: ArtifactRef[]
    }
  | {
      kind: 'excluded_control'
      fromItemSeq: number
      throughItemSeq: number
      sourceItemsDigest: string
    }

type AdmittedContextManifest = {
  schemaVersion: 1
  format: 'cliq-admitted-context-v1'
  sessionId: string
  sessionContextRevision: number
  throughSessionItemSeq: number
  sessionProjectionRef: ArtifactRef
  parentContextRefs: ArtifactRef[]
  additionalArtifactRefs: ArtifactRef[]
  contextDigest: string
}

type ContextManifest = {
  schemaVersion: 1
  format: 'cliq-context-manifest-v1'
  runId: string
  throughItemSeq: number
  admittedContextRef: ArtifactRef
  segments: ContextSegment[]
  assemblyRef: ArtifactRef
  projectionDigest: string
}

type WorkspaceEntry =
  | { path: string; kind: 'directory'; mode: number }
  | { path: string; kind: 'file'; mode: number; size: number; blobRef: ArtifactRef }
  | { path: string; kind: 'symlink'; mode: number; target: string; targetDigest: string }

type WorkspaceEntryManifest = {
  schemaVersion: 1
  format: 'cliq-workspace-entries-v1'
  entries: WorkspaceEntry[]
  entryCount: number
  byteCount: number
  treeDigest: string
}

type GitIndexSnapshotV1 = {
  schemaVersion: 1
  format: 'cliq-git-index-snapshot-v1'
  repositoryIdentityDigest: string
  objectFormat: 'sha1' | 'sha256'
  canonicalIndexVersion: 2
  entries: Array<{
    canonicalRootRelativePath: string
    stage: 0
    mode: 33188 | 33261 | 40960
    objectId: string
    assumeValid: boolean
    skipWorktree: false
  }>
  canonicalIndexBytesRef: ArtifactRef
  canonicalIndexBytesDigest: string
  canonicalIndexByteCount: number
  indexTreeObjectId: string
  snapshotDigest: string
}

type GitObjectPackV1 = {
  schemaVersion: 1
  format: 'cliq-git-object-pack-v1'
  objectFormat: 'sha1' | 'sha256'
  packBytesRef: ArtifactRef
  packBytesDigest: string
  packByteCount: number
  packTrailerObjectHash: string
  packIndexBytesRef: ArtifactRef
  packIndexBytesDigest: string
  packIndexByteCount: number
  packIndexVersion: 2
  objectCount: number
  objectIds: string[]
  packDigest: string
}

type GitObjectClosureV1 = {
  schemaVersion: 1
  format: 'cliq-git-object-closure-v1'
  repositoryIdentityDigest: string
  objectFormat: 'sha1' | 'sha256'
  packs: Array<{
    packRef: ArtifactRef
    packDigest: string
    packTrailerObjectHash: string
  }>
  reachableObjectIds: string[]
  closureDigest: string
}

type SourceManifest = {
  schemaVersion: 1
  format: 'cliq-source-manifest-v1'
  role: 'base' | 'result'
  workspaceIdentityDigest: string
  entriesRef: ArtifactRef
  sourceProjectionRef: ArtifactRef
  sourceProjectionDigest: string
  frozenIgnoreRulesRef: ArtifactRef
  frozenIgnoreRulesDigest: string
  git?: {
    repositoryIdentityDigest: string
    head: { kind: 'unborn'; branch: string } | { kind: 'symbolic'; ref: string; objectId: string } | { kind: 'detached'; objectId: string }
    indexRef: ArtifactRef
    indexTreeObjectId: string
  }
  treeDigest: string
  manifestDigest: string
}

type SanitizedGitConfigV1 = {
  schemaVersion: 1
  format: 'cliq-sanitized-git-config-v1'
  core: {
    repositoryFormatVersion: 0 | 1
    fileMode: boolean
    bare: false
    logAllRefUpdates?: boolean
    ignoreCase?: boolean
    precomposeUnicode?: boolean
  }
  extensions?: {
    objectFormat: 'sha1' | 'sha256'
  }
  configDigest: string
}

type PrivateGitStateManifest = {
  schemaVersion: 1
  format: 'cliq-private-git-v1'
  head: { kind: 'unborn'; branch: string } | { kind: 'symbolic'; ref: string } | { kind: 'detached'; objectId: string }
  indexRef: ArtifactRef
  refs: Array<{ name: string; objectId: string }>
  objectClosureRef: ArtifactRef
  objectClosureDigest: string
  sanitizedConfigRef: ArtifactRef
  sanitizedConfigDigest: string
  manifestDigest: string
}

type WorkspaceStateManifest = {
  schemaVersion: 1
  format: 'cliq-workspace-state-v1'
  runId: string
  baseWorkspaceManifestRef: ArtifactRef
  entriesRef: ArtifactRef
  privateGitStateRef?: ArtifactRef
  invalidatedEphemeralPaths: string[]
  sourceProjectionDigest: string
  stateDigest: string
}

type WorkspaceGenerationIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-generation-identity-v1'
  generationId: string
  runId: string
  workspaceIdentityDigest: string
  sourceCheckpointId: string
  sourceWorkspaceStateRef: ArtifactRef
  sourceWorkspaceStateDigest: string
  sourceTreeDigest: string
  creationNonceDigest: string
  locator:
    | {
        kind: 'linux_directory'
        stateRootIdentityRef: ArtifactRef
        stateRootIdentityDigest: string
        canonicalRootRelativePath: string
        deviceId: string
        directoryFileId: string
        ownerUid: number
        mode: 448
      }
    | {
        kind: 'macos_vm_volume'
        stateRootIdentityRef: ArtifactRef
        stateRootIdentityDigest: string
        backingStoreCanonicalRootRelativePath: string
        backingStoreDeviceId: string
        backingStoreFileId: string
        backingStoreOwnerUid: number
        backingStoreMode: 384
        backingStoreLinkCount: 1
        vmVolumeReservationId: string
        guestVolumeId: string
      }
  createdAt: string
  identityDigest: string
}

type WorkspaceGenerationSnapshotEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-generation-snapshot-evidence-v1'
  purpose: 'materialized_from_checkpoint' | 'sealed_to_checkpoint'
  runId: string
  generationRef: ArtifactRef
  generationIdentityDigest: string
  checkpointId: string
  workspaceStateRef: ArtifactRef
  workspaceStateDigest: string
  entriesRef: ArtifactRef
  treeDigest: string
  privateGitStateRef?: ArtifactRef
  descriptorRewalkComplete: true
  fileFsyncComplete: true
  directoryFsyncComplete: true
  observedAt: string
  evidenceDigest: string
}

type WorkspaceGenerationFailureDetailV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-generation-failure-detail-v1'
  runId: string
  generationRef: ArtifactRef
  generationIdentityDigest: string
  sourceCheckpointId: string
  phase: 'materializing' | 'preactivated_readonly'
  failureCode:
    | 'descriptor_io_failed'
    | 'artifact_missing_or_corrupt'
    | 'path_or_entry_invalid'
    | 'tree_or_state_digest_mismatch'
    | 'git_closure_invalid'
    | 'fsync_failed'
    | 'runtime_incompatible'
  failingCanonicalRootRelativePath?: string
  observedAt: string
  detailDigest: string
}

type WorkspaceGenerationQuarantineEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-generation-quarantine-evidence-v1'
  runId: string
  generationRef: ArtifactRef
  generationIdentityDigest: string
  sourceRowVersion: number
  observedState:
    | { kind: 'complete_tree'; treeDigest: string }
    | {
        kind: 'unreadable_partial'
        failureCode: 'descriptor_io_failed' | 'artifact_missing_or_corrupt' | 'path_or_entry_invalid' | 'git_closure_invalid'
      }
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  quarantineCanonicalRootRelativePath: string
  quarantineDeviceId: string
  quarantineFileId: string
  originalLocatorAbsent: true
  renameNoReplace: true
  directoryFsyncComplete: true
  observedAt: string
  evidenceDigest: string
} & (
  | {
      reason: 'materialization_failed'
      fromPhase: 'materializing'
      failureDetailRef: ArtifactRef
      failureDetailDigest: string
      workerRecoveryEvidenceRef?: never
      workerRecoveryEvidenceDigest?: never
      workerLaunchId?: never
      quiesceId?: never
      containmentDeathEvidenceRef?: never
      containmentDeathEvidenceDigest?: never
    }
  | {
      reason: 'preactivation_failed'
      fromPhase: 'preactivated_readonly'
      failureDetailRef: ArtifactRef
      failureDetailDigest: string
      workerRecoveryEvidenceRef?: never
      workerRecoveryEvidenceDigest?: never
      workerLaunchId?: never
      quiesceId?: never
      containmentNoSpawnEvidenceRef?: never
      containmentNoSpawnEvidenceDigest?: never
      containmentDeathEvidenceRef?: never
      containmentDeathEvidenceDigest?: never
    }
  | {
      reason: 'launch_aborted'
      fromPhase: 'preactivated_readonly'
      workerLaunchId: string
      containmentNoSpawnEvidenceRef: ArtifactRef
      containmentNoSpawnEvidenceDigest: string
      failureDetailRef?: never
      failureDetailDigest?: never
      workerRecoveryEvidenceRef?: never
      workerRecoveryEvidenceDigest?: never
      quiesceId?: never
      containmentDeathEvidenceRef?: never
      containmentDeathEvidenceDigest?: never
    }
  | {
      reason: 'launch_died_before_activation'
      fromPhase: 'preactivated_readonly'
      workerLaunchId: string
      containmentDeathEvidenceRef: ArtifactRef
      containmentDeathEvidenceDigest: string
      failureDetailRef?: never
      failureDetailDigest?: never
      workerRecoveryEvidenceRef?: never
      workerRecoveryEvidenceDigest?: never
      quiesceId?: never
      containmentNoSpawnEvidenceRef?: never
      containmentNoSpawnEvidenceDigest?: never
    }
  | {
      reason: 'worker_recovery'
      fromPhase: 'fenced_reconciling'
      workerRecoveryEvidenceRef: ArtifactRef
      workerRecoveryEvidenceDigest: string
      failureDetailRef?: never
      failureDetailDigest?: never
      workerLaunchId?: never
      quiesceId?: never
      containmentNoSpawnEvidenceRef?: never
      containmentNoSpawnEvidenceDigest?: never
      containmentDeathEvidenceRef?: never
      containmentDeathEvidenceDigest?: never
    }
  | {
      reason: 'checkpoint_failed'
      fromPhase: 'revoking' | 'checkpointing'
      workerLaunchId: string
      quiesceId: string
      containmentDeathEvidenceRef: ArtifactRef
      containmentDeathEvidenceDigest: string
      failureDetailRef?: never
      failureDetailDigest?: never
      workerRecoveryEvidenceRef?: never
      workerRecoveryEvidenceDigest?: never
      containmentNoSpawnEvidenceRef?: never
      containmentNoSpawnEvidenceDigest?: never
    }
)

type WorkspaceGenerationRetirementEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-generation-retirement-evidence-v1'
  runId: string
  generationRef: ArtifactRef
  generationIdentityDigest: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  evidenceDigest: string
} & (
  | {
      fromPhase: 'sealed'
      snapshotEvidenceRef: ArtifactRef
      snapshotEvidenceDigest: string
      workerLaunchId: string
      containmentDeathEvidenceRef: ArtifactRef
      containmentDeathEvidenceDigest: string
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
    }
  | {
      fromPhase: 'quarantined'
      quarantineEvidenceRef: ArtifactRef
      quarantineEvidenceDigest: string
      sourceQuarantinedRowVersion: number
      activeRunPointerCount: 0
      nonretiredWorkerLaunchCount: 0
      liveContainmentCount: 0
      activeMountCount: 0
      releasableBrokerClaimCount: 0
      snapshotEvidenceRef?: never
      snapshotEvidenceDigest?: never
      workerLaunchId?: never
      containmentDeathEvidenceRef?: never
      containmentDeathEvidenceDigest?: never
    }
)

type WorkspaceGenerationStateBaseV1 = {
  schemaVersion: 1
  generationId: string
  runId: string
  generationRef: ArtifactRef
  generationIdentityDigest: string
  rowVersion: number
  sourceCheckpointId: string
  sourceWorkspaceStateRef: ArtifactRef
  sourceWorkspaceStateDigest: string
  lastVerifiedTreeDigest: string
  updatedAt: string
}

type WorkspaceGenerationStateV1 = WorkspaceGenerationStateBaseV1 & (
  | {
      phase: 'materializing'
      snapshotEvidenceRef?: never
      snapshotEvidenceDigest?: never
      activeWorkerLaunchId?: never
      leaseEpoch?: never
      quiesceId?: never
      waitingSubjectRef?: never
      waitingSubjectDigest?: never
      fencedFromPhase?: never
      fencedJournalSeq?: never
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
      observedState?: never
      retirementEvidenceRef?: never
      retirementEvidenceDigest?: never
    }
  | {
      phase: 'preactivated_readonly'
      snapshotEvidenceRef: ArtifactRef
      snapshotEvidenceDigest: string
      activeWorkerLaunchId?: never
      leaseEpoch?: never
      quiesceId?: never
      waitingSubjectRef?: never
      waitingSubjectDigest?: never
      fencedFromPhase?: never
      fencedJournalSeq?: never
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
      observedState?: never
      retirementEvidenceRef?: never
      retirementEvidenceDigest?: never
    }
  | {
      phase: 'active'
      snapshotEvidenceRef: ArtifactRef
      snapshotEvidenceDigest: string
      activeWorkerLaunchId: string
      leaseEpoch: number
      quiesceId?: never
      waitingSubjectRef?: never
      waitingSubjectDigest?: never
      fencedFromPhase?: never
      fencedJournalSeq?: never
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
      observedState?: never
      retirementEvidenceRef?: never
      retirementEvidenceDigest?: never
    }
  | {
      phase: 'revoking' | 'checkpointing'
      snapshotEvidenceRef: ArtifactRef
      snapshotEvidenceDigest: string
      activeWorkerLaunchId: string
      leaseEpoch: number
      quiesceId: string
      waitingSubjectRef?: never
      waitingSubjectDigest?: never
      fencedFromPhase?: never
      fencedJournalSeq?: never
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
      observedState?: never
      retirementEvidenceRef?: never
      retirementEvidenceDigest?: never
    }
  | ({
      phase: 'fenced_reconciling'
      snapshotEvidenceRef: ArtifactRef
      snapshotEvidenceDigest: string
      activeWorkerLaunchId: string
      leaseEpoch: number
      waitingSubjectRef: ArtifactRef
      waitingSubjectDigest: string
      fencedJournalSeq: number
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
      observedState?: never
      retirementEvidenceRef?: never
      retirementEvidenceDigest?: never
    } & (
      | { fencedFromPhase: 'active'; quiesceId?: never }
      | { fencedFromPhase: 'revoking' | 'checkpointing'; quiesceId: string }
    ))
  | {
      phase: 'sealed'
      snapshotEvidenceRef: ArtifactRef
      snapshotEvidenceDigest: string
      activeWorkerLaunchId?: never
      leaseEpoch?: never
      quiesceId?: never
      waitingSubjectRef?: never
      waitingSubjectDigest?: never
      fencedFromPhase?: never
      fencedJournalSeq?: never
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
      observedState?: never
      retirementEvidenceRef?: never
      retirementEvidenceDigest?: never
    }
  | {
      phase: 'quarantined'
      snapshotEvidenceRef?: never
      snapshotEvidenceDigest?: never
      activeWorkerLaunchId?: never
      leaseEpoch?: never
      quiesceId?: never
      waitingSubjectRef?: never
      waitingSubjectDigest?: never
      fencedFromPhase?: never
      fencedJournalSeq?: never
      quarantineEvidenceRef: ArtifactRef
      quarantineEvidenceDigest: string
      observedState: WorkspaceGenerationQuarantineEvidenceV1['observedState']
      retirementEvidenceRef?: never
      retirementEvidenceDigest?: never
    }
  | {
      phase: 'retired'
      snapshotEvidenceRef?: never
      snapshotEvidenceDigest?: never
      activeWorkerLaunchId?: never
      leaseEpoch?: never
      quiesceId?: never
      waitingSubjectRef?: never
      waitingSubjectDigest?: never
      fencedFromPhase?: never
      fencedJournalSeq?: never
      quarantineEvidenceRef?: never
      quarantineEvidenceDigest?: never
      observedState?: never
      retirementEvidenceRef: ArtifactRef
      retirementEvidenceDigest: string
    }
)
```

`admittedContextRef` equals RunSpec and validates the frozen Session id/revision/cursor/projection plus any parent/explicit child context. `sessionProjectionRef` resolves to the exact `SessionContextProjection` above at the same revision/cursor and independently recomputes that artifact's `projectionDigest`; `contextDigest = SHA-256(JCS(AdmittedContextManifest with contextDigest omitted))`. Context segments are ordered, nonoverlapping, and cover exactly item sequences `1..throughItemSeq`, which equals Checkpoint `runItemSeq`. A raw segment contains exactly one explicit sequence/ref pair for every item in its range; non-model-visible gaps require an `excluded_control` segment rather than omission. Summary segments match their `RunContextCompactionItem` range/digest; `excluded_control` binds audit/control ranges without projecting their payloads. Preserved refs are explicitly projected after a summary. `ContextManifest.assemblyRef` equals RunSpec; instructions and skills are reached only through that decoded immutable assembly, and the ContextManifest has no redundant instruction/skill arrays that could disagree. `projectionDigest` is SHA-256 of the JCS object with that member omitted. Lease, budget, wait, child, StopIntent, and invocation truth stay in their own planes even though excluded digests bind the cut.

Workspace entries use `cliq-exact-path-v1`, are strictly byte-sorted and unique, include empty directories needed for recovery, and forbid `.git`, special files, outside-root links, credentials, and declared ephemeral contents. A descriptor-validated source file with link count greater than one is accepted, but link identity is intentionally erased: each admitted path is hashed as an independent regular-file entry, and recovery/materialization creates independent files with link count one. Private Run generations, CAS object storage, and publication transients themselves forbid hardlinks, so no later mutation can alias another admitted path or CAS object. File blobs/dimensions and symlink target text are verified; modes are normalized to directory `0755` and regular `0644|0755`. For a decoded `WorkspaceEntryManifest`, `entryCount = entries.length`; `byteCount` is the checked unsigned sum of file `size` plus UTF-8 byte length of every symlink target (directories contribute zero); and `treeDigest = SHA-256(JCS({schemaVersion:1,format:'cliq-workspace-entries-v1',entries}))`. Thus neither count nor tree digest is self-referential, and every referenced file blob/size and symlink target/digest is revalidated before accepting the manifest.

Every Git `indexRef|gitIndexRef|capturedIndexRef|observedIndexRef` in this RFC decodes only exact `GitIndexSnapshotV1`; a raw `.git/index` blob is never directly used as an authority ref. `snapshotDigest = SHA-256(JCS(snapshot with snapshotDigest omitted))`; `canonicalIndexBytesDigest === canonicalIndexBytesRef` is SHA-256 of the exact canonical Git-index bytes and `canonicalIndexByteCount` is their positive safe-integer length. Descriptor-held input accepts Git index version 2, 3, or 4 only after verifying the object-format checksum and complete parse. It rejects unmerged stages, gitlinks, intent-to-add, any skip-worktree bit, split/sparse index, unknown mandatory extensions, path escape/duplicate/non-NFC/NUL, invalid mode/object id, or missing referenced objects. Optional accelerator extensions are discarded. Fixed `cliq-git-index-normalize-v1` writes one version-2 index containing exactly the byte-sorted stage-0 entries shown, with every `skipWorktree` literal false, no extended flags, zeroed stat fields, the v2 NUL-terminated path and 8-byte entry padding rules, the declared object-format checksum, and no extension; reparsing those bytes must reproduce the artifact. Version-4 prefix compression/varint encoding is accepted only by the input parser and is never emitted by the canonical v2 writer. `indexTreeObjectId` is the fixed Git tree-object construction over those entries and nested directories. Thus host Git version, stat cache, fsmonitor/untracked cache, extension order, and source raw bytes cannot change tracked classification or recovery.

SourceManifest and SourceInclude classification index refs rehash the same admitted snapshot, their repository identity and `indexTreeObjectId|gitIndexTreeObjectId` equal its members, and tracked classification is an all-and-only lookup in its entries. `PrivateGitStateManifest.indexRef` names the snapshot whose canonical bytes are written to its independent `.git/index`; its HEAD/refs and object format agree. `PublicationProofV1(kind='git_index_unchanged')` is a closed repository XOR: non-Git forbids all four refs/digests, while Git requires both snapshots, each digest equals the decoded `snapshotDigest`, and success requires identical snapshot refs/digests. A changed semantic entry or tree is not “unchanged” merely because a raw index file happened to retain an inode or timestamp.

Git object storage is equally closed. Every `GitObjectPackV1` raw pack/index ref is declared respectively as complete Git pack and pack-index-v2 bytes; the SHA-256 digest equals its ArtifactRef, byte counts are exact, the pack trailer uses the declared Git object format, and fixed trusted `index-pack` validation recomputes the trailer, object count, unique byte-sorted object-id list, per-object content hash, delta closure, and exact deterministic v2 index bytes. `packDigest` omits itself. `GitObjectClosureV1.closureDigest` omits itself; pack tuples are unique and byte-sorted by trailer hash, rehash every pack artifact, and `reachableObjectIds` is the unique byte-sorted all-and-only graph walk from private HEAD, refs, and index entries through commits/trees/tags/blobs. The disjoint union of every decoded pack's `objectIds` equals `reachableObjectIds` exactly: every reachable object occurs in exactly one retained pack, and no unreachable, deleted, or otherwise extra object is retained. A Git `PrivateGitStateManifest` uses that one closure ref/digest instead of an untyped pack list. `SanitizedGitConfigV1.configDigest` and `PrivateGitStateManifest.manifestDigest` each omit themselves under JCS; the manifest's config and object-closure pairs rehash their exact artifacts. The config is a closed allowlist containing only the displayed non-executable repository/object-format booleans/literals. Every other Git key is absent, including hooks, remotes, credentials, includes, helpers, aliases, pagers, filters, attributes drivers, diff/merge drivers, `core.fsmonitor`, `core.sshCommand`, worktree paths, and environment-driven config. Fixed trusted startup code supplies private-generation paths and disables system/global/environment config; it never copies repository/user config. A non-Git state forbids the private-Git manifest.

Both `RunSpec.baseWorkspaceManifestRef` and every candidate/RunResult `resultSourceRef` name `SourceManifest`, never an adapter-specific tree. `entriesRef` must decode to exactly one valid `WorkspaceEntryManifest`, and `SourceManifest.treeDigest` must equal that entry manifest's `treeDigest`. `manifestDigest = SHA-256(JCS(SourceManifest with manifestDigest omitted))`; its included `treeDigest` is already the non-self-referential entry projection above. Its workspace digest equals the live Session identity. The `git` member is present iff that identity carries a repository artifact, and `git.repositoryIdentityDigest` equals it; absence is required for non-Git. A result inherits the admitted workspace/repository/head/index/ignore/projection identity and changes only its projected entries/tree/role; storage rejects cross-projection or cross-repository equality. `diffRef` is deterministically computed between the two referenced entry manifests. Verification, delivery, and inherited-provenance “same result” means the identical verified SourceManifest artifact ref, not merely equal loose directory bytes. A Checkpoint `workspaceStateRef` instead always names `WorkspaceStateManifest`; a SourceManifest is never installed directly in that field.

Every `diffRef` decodes exact `WorkspaceDiffV1`; `diffDigest = SHA-256(JCS(diff with diffDigest omitted))`. Its base/result refs rehash exact SourceManifests and the operation list is the unique byte-sorted union-path comparison of their decoded entry manifests. A path absent only in base emits `add` with the exact result entry; absent only in result emits `delete` with the exact base entry; unequal canonical entries on both sides emit `modify` with those exact before/after entries; byte-identical entries emit nothing. Every operation path equals its entry path(s), no path appears twice, and no renderer-specific hunk/text/binary heuristic enters this authority artifact. Thus an empty list means exact entry-manifest equality, while any source change has exactly one reproducible operation.

`WorkspaceStateManifest.entriesRef` independently decodes to the complete recoverable `WorkspaceEntryManifest`. `baseWorkspaceManifestRef` decodes to the Run's exact SourceManifest and supplies the required workspace/repository/projection identity; `sourceProjectionDigest` equals that source manifest. `privateGitStateRef` is present iff the base source is Git and absent otherwise. `invalidatedEphemeralPaths` is strictly byte-sorted, unique, root-relative, and disjoint from materialized entries. `stateDigest = SHA-256(JCS(WorkspaceStateManifest with stateDigest omitted))`; the entry manifest and private-Git artifacts are referenced inputs, so no digest points back to the state manifest. Checkpoint validation recomputes this projection and requires the manifest `runId` and base ref equal the owning Run/current source cut.

Every `workspaceGenerationRef|generationRef` in a WorkerLaunch, wait, recovery/integrity evidence, containment plan, Sandbox filesystem/mount, or actual containment decodes only exact `WorkspaceGenerationIdentityV1`; its ArtifactRef rehashes the bytes and `identityDigest = SHA-256(JCS(identity with identityDigest omitted))`. The source Checkpoint belongs to the same Run and its workspace-state ref/digest/tree equal the identity. `generationId = H(runId,sourceCheckpointId,sourceWorkspaceStateRef,creationNonceDigest)`. Linux uses descriptor-relative creation at exactly `runs/<runId>/generations/<generationId>` beneath the decoded StateRoot, requiring the displayed directory identity, owner and `0700` mode. Directory link counts vary by filesystem and child directories and are not a file-hardlink or immutable-identity check; regular generation files still forbid hardlinks. macOS uses exactly `runs/<runId>/generations/<generationId>.img` for its root-relative private `0600`, single-link backing image plus a uniquely reserved guest volume; backing descriptor and guest volume ids must both stay equal. A path, mutable handle, VM id, or directory that is not in this signed/hashed identity cannot be substituted after restart.

`workspace_generations` stores one exact `WorkspaceGenerationStateV1` mutable pointer row per immutable identity. `rowVersion` is a positive safe integer incremented by one on every CAS; all base identity/source fields are immutable. The success spine is exactly `materializing -> preactivated_readonly -> active -> revoking -> checkpointing -> sealed -> retired`; entering `revoking` only closes new worker writes/releases, and the same quiesce id then advances to `checkpointing` before any snapshot can seal. Every non-success edge goes through `quarantined`: `materializing|preactivated_readonly` may transition directly after their closed failure/no-spawn/death evidence; a checkpoint/quiesce failure with already-positive death evidence may transition from `revoking|checkpointing` using `checkpoint_failed`; every worker-loss/takeover path from `active|revoking|checkpointing` first atomically becomes `fenced_reconciling` and installs its exact wait even when death proof is already immediately available; and `fenced_reconciling` may only become `quarantined` through `worker_recovery`. Only `sealed|quarantined` may transition to `retired`. Direct `active -> checkpointing`, `revoking -> sealed`, worker recovery directly from a pointer-bound phase, `fenced_reconciling -> active`, or any other edge, phase skip, or reuse of a retired/quarantined generation is illegal. The branch XOR is storage-enforced. `preactivated_readonly|active|revoking|checkpointing|fenced_reconciling|sealed` snapshot evidence rehashes exact `WorkspaceGenerationSnapshotEvidenceV1`; its identity/checkpoint/state/entries/private-Git/tree fields re-walk the generation and Checkpoint, and all three fsync literals must be true. Materialization evidence uses the source Checkpoint. Sealing evidence is artifact-first and commits with the new ready Checkpoint/state row; it names that intended Checkpoint id without pointing back from an immutable artifact, so no hash cycle exists. An active/revoking/checkpointing row's launch/epoch equals the sole matching WorkerLaunch and Run active pointer. A `fenced_reconciling` row instead requires that Run pointer absent, the Run waiting on its exact `worker_death` WaitingSubject, and its launch/epoch/wait ref/digest/fenced source phase/quiesce id equal that subject and the sole matching `WorkerLaunch(phase='reconciling',generationWriteState='fenced_reconciling')`. It is read-only and cannot dispatch, checkpoint, seal, or be selected by another launch. Only `lastVerifiedTreeDigest` is authoritative while writes were active. No directory rescan becomes a current state without the sealed evidence/Checkpoint transaction.

Every quarantine operation derives its sole target before touching the filesystem: `sourceRowVersion` equals the current row and `quarantineCanonicalRootRelativePath = 'quarantine/workspace-generations/' + H(generationId,base-10 sourceRowVersion)`. It then publishes or reconstructibly stages exact `WorkspaceGenerationQuarantineEvidenceV1`, rehashes its current inspector, moves the held generation descriptor by no-replace rename into that path, fsyncs the parent, proves the original locator absent, and CASes the row while repeating `observedState`. A complete descriptor rewalk records `complete_tree` with its exact tree digest; a partial, corrupt, or unreadable generation records only the corresponding closed `unreadable_partial.failureCode` and must not invent a tree digest. A crash with the original locator present and target absent retries the move; original absent plus that one exact target present may only reobserve/rebuild the same evidence and finish the CAS; both present, both absent, identity drift, or any other target blocks recovery. No directory scan chooses authority. `WorkspaceGenerationFailureDetailV1.detailDigest`, `WorkspaceGenerationQuarantineEvidenceV1.evidenceDigest`, and `WorkspaceGenerationRetirementEvidenceV1.evidenceDigest` each equal SHA-256 of their JCS artifact with only that artifact's own digest member omitted. A quarantined row's ref/digest rehashes that exact quarantine artifact and repeats its complete observed-state union; a retired row does the same for exact retirement evidence. The reason/from-phase matrix is closed: `materialization_failed` is only from `materializing` and its failure detail has `phase='materializing'`; `preactivation_failed` is only from `preactivated_readonly` and its failure detail has that phase; both details repeat the row's Run/generation/source Checkpoint and one closed failure code. `launch_aborted` is only from `preactivated_readonly` and requires exact no-spawn evidence; `launch_died_before_activation` is only from that phase and requires the exact created containment's all-descendant death evidence. `worker_recovery` is only from `fenced_reconciling` and rehashes exact `WorkerRecoveryEvidenceV1` for that installed wait; `checkpoint_failed` is only from `revoking|checkpointing` and requires the same launch/quiesce plus exact containment-death evidence. All refs, run/generation/launch/epoch/last-verified-tree/inspector identities must match the row and owning Run/wait. No future launch may select the quarantined identity. `restored_from_checkpoint` never rewinds or reuses that mutable directory: it requires a distinct `replacementWorkspaceGenerationRef` derived from the named ready Checkpoint and proven `preactivated_readonly` by its own materialization evidence.

Retirement first publishes exact `WorkspaceGenerationRetirementEvidenceV1` and then CASes the row. A sealed retirement rehashes the sealing snapshot and exact death evidence for its last worker launch. A quarantined retirement rehashes the quarantine evidence, sets `sourceQuarantinedRowVersion` to the current row, and in the same state-owner transaction recomputes literal zero for active Run pointers, nonretired WorkerLaunch rows, live containments, active mounts, and releasable broker claims naming this generation. A free boolean or stale count cannot retire it. Evidence/run/generation/inspector/digest fields are byte-equal and neither branch accepts a generic ArtifactRef. WorkerLaunch `generationWriteState` is a denormalized index that must equal the generation row phase (`preactivated_readonly`, `active`, `revoking`, `checkpointing`, `fenced_reconciling`, or `sealed`) in the same transaction. The generation row, not a directory name or worker assertion, is the sole mutable generation authority.

Restore always targets a new empty generation identity through descriptor-relative no-follow creation, inserts its `materializing` row, materializes entries and an independent `.git`, fsyncs, re-walks and recomputes tree/state/index/object-closure digests, publishes snapshot evidence, then CASes to `preactivated_readonly` before a blocked worker launch may select it. Missing/unknown format, duplicate/path escape, broken blob/pack/index/ref, byte/count mismatch, unsupported runtime bundle, or partial generation state fails `RECOVERY_REQUIRED`; it never selects an older cut or existing mutable directory silently. `WorkspaceStateManifest` is the full private recovery image and is intentionally not the deliverable `resultSourceRef`.

### 7.2 Publication Protocol

1. Create context and workspace artifacts in the content-addressed store.
2. Flush file contents and containing directories and verify their digests.
3. In one SQLite transaction:
   - compare-and-swap the Run at `basedOnRunRevision`;
   - insert the immutable Checkpoint;
   - append the corresponding client event;
   - update `runs.latestCheckpointId`, revision, and `nextStep` as needed.
4. Commit the transaction.

A published Checkpoint records the pre-publication Run revision whose item, Journal, context, and workspace cut it captures. The same transaction advances the authoritative Run to `basedOnRunRevision + 1` while installing `latestCheckpointId`. A crash before step 3 leaves only unreferenced artifacts eligible for garbage collection. The database must never reference a missing or unverified artifact.

Admission is the one insert form of that rule. It uses virtual pre-admission revision `0`: CAS/CAS-artifact work happens first, then one SQLite transaction inserts the initial Checkpoint with `basedOnRunRevision=0`, `runItemSeq=0`, `journalSeq=0`, and the frozen admitted context/workspace refs; inserts the Run at `revision=1`, `status='queued'`, its operation-specific initial frontier and non-null `latestCheckpointId`; appends event sequence 1; and records the idempotent admission response. An agent Run starts at its initial agent frontier. `run.apply` first performs the same descriptor-safe immutable real-workspace capture used by publication and publishes source manifest **A**. Trusted code then materializes A into a new empty private delivery generation and publishes recovery image **W_A**, an exact `WorkspaceStateManifest` whose `runId` is the new delivery Run, `baseWorkspaceManifestRef=A`, entries/private-Git state reproduce A, and source-projection/repository/index/tree identities validate against A. The admitted `RunSpec.baseWorkspaceManifestRef` and initial `delivery:merge.capturedWorkspaceRef` both equal A, while the initial Checkpoint `workspaceStateRef` equals W_A and can never equal the differently typed A artifact. The Run starts directly at `delivery:merge {sourceRunResultRef,capturedWorkspaceRef:A}`. There is no admitted delivery Run whose required capture/recovery image is absent and no post-admission `delivery:capture` choice. No revision-0 Run row is externally visible. A failed transaction leaves only unreachable artifacts and no accepted Run.

Checkpoints are published only at quiescent boundaries. An open invocation is represented by the RunJournal, not embedded in a Checkpoint.

### 7.3 Recovery Closure

The complete recovery input is:

```text
immutable RunSpec
+ authoritative Run row
+ latest ready Checkpoint
+ ordered typed Run items after Checkpoint.runItemSeq
+ RunJournal entries after Checkpoint.journalSeq
+ every WorkerLaunchIntent/phase fact for the current or unretired activation
+ every child_allocation row where this Run is parent or child
+ when the assembly selects local_zero_cost, every activation cycle in which the Run is a participant, every current/unretired local-inference launch for its exact service spec, and their participant/request/frontier/failure/boundary/model/capability evidence
+ referenced immutable artifacts
```

The referenced closure includes the current frontier, wait subject/probe state, StopIntent, applicable grant/templates, launch containment identities, and terminal child result/usage refs; no control response or display event is needed to decide execution. Checkpoint alone never guarantees recovery.

## 8. RunJournal And Effect Semantics

RunJournal is not a general event-sourcing framework. It records only facts that cannot safely be reconstructed by replaying deterministic local code.

### 8.1 Invocation Lifecycle

```text
prepared         -> dispatch_claimed | failed
dispatch_claimed -> completed | failed | unknown
unknown          -> completed | failed | abandoned
```

Every state transition is appended as a new journal entry. Existing entries are immutable.

```ts
type ReplayClass =
  | 'retry'
  | 'workspace-rollback-retry'
  | 'reconcile'
  | 'manual'

type InvocationPhase =
  | 'prepared'
  | 'dispatch_claimed'
  | 'completed'
  | 'failed'
  | 'unknown'
  | 'abandoned'

type InvocationJournalEntry = {
  seq: number
  runId: string
  opId: string
  opKind: 'model' | 'tool' | 'mcp-server' | 'mcp' | 'verifier' | 'publish'
  attempt: number
  leaseEpoch: number
  phase: InvocationPhase
  target: string
  requestRef: ArtifactRef
  sandboxLaunchSpecRef?: ArtifactRef
  replayClass: ReplayClass
  idempotencyKey?: string
  grantRef?: ArtifactRef
  dispatchId?: string
  supervisorInstanceId?: string
  stateOwnerEpoch?: number
  brokerFenceTokenDigest?: string
  resultRef?: ArtifactRef
  receiptRef?: ArtifactRef
  errorRef?: ArtifactRef
  evidenceRef?: ArtifactRef
  evidenceDigest?: string
  attestationRef?: ArtifactRef
  budgetDelta: BudgetUsage
  budgetSettlementRef?: ArtifactRef
  timestamp: string
}
```

The store enforces uniqueness for `(runId, opId, attempt, phase)` and monotonic sequence allocation inside the same transaction that commits related Run state, Run items, and budget settlement. `dispatch_claimed` requires an unguessable `dispatchId` plus the current trusted Supervisor instance and exact positive `stateOwnerEpoch`; that pair equals the sole active StateOwner row and is the durable singleflight claim. If and only if release uses the trusted broker without a child containment, that same claim transaction also stores the SHA-256 digest of one unguessable broker fence token; process-contained and non-broker claims forbid it. The token itself exists only in the live broker and is released only after the second dispatch gate rehashes it against the current claim. No external I/O, sandbox process launch, or billable provider call may start from `prepared` alone. Concurrent duplicate frames race to append the single claim; only the winner dispatches and all others join its in-flight/result state. After Supervisor loss, a claimed attempt is conservatively possibly dispatched and is never dispatched again under that attempt number. Every post-claim phase repeats the claim's dispatch/Supervisor/state-owner identity. `prepared` and the pre-dispatch `failed` branch forbid all three.

Phase/op-kind validation is closed at storage, not left to adapters:

- `prepared` requires immutable request, target, ReplayClass, original epoch, applicable grant, and the complete four-counter reservation in `budgetDelta`; it forbids dispatch/result/receipt/error evidence ref/digest and a settlement ref. The sole zero-reservation form is a typed abort-directory recovery-maintenance request admitted by `claimRecoveryMaintenance`'s preconditions.
- `dispatch_claimed` requires the one matching prepared row, `dispatchId`, trusted Supervisor instance plus exact active `stateOwnerEpoch`, the broker-token-digest XOR above, the complete four-counter zero value in `budgetDelta`, and no terminal fields, evidence pair, or budget settlement.
- `completed` requires the matching claim, exact `budgetSettlementRef`, plus an op-kind result: exact usable `AgentModelTurn` or exact `ModelUnusableResponseV1` for `model`, under their closed XOR; result artifact for `tool|mcp`; exact `McpServerInstanceIdentityV1` result plus `McpServerLaunchReceiptV1` for `mcp-server`; a passed/assertion/source-mutation verification receipt for `verifier`; or exact `PublicationProofV1(kind='terminal_receipt')` for `publish`.
- `failed` is a closed XOR. `pre_dispatch` requires the exact prepared row, error, settlement, and zero consumed `budgetDelta`, while forbidding dispatch/Supervisor/owner/token/result/receipt/evidence pair/attestation fields; the absence of any claim under the universal dispatch gate is itself authoritative proof that no target capability or request byte was released. `post_claim` repeats the exact claim and is legal only in two forms: its `evidenceRef/evidenceDigest` decodes exact `PostClaimNoReleaseEvidenceV1`, or an `opKind='verifier'` infrastructure failure carries its cross-field-valid `infra_failed` receipt plus exact containment-death closure and forbids the generic pair. The first form consumes zero and proves the same live owner closed the second gate before any release/spawn; the verifier form consumes its exact attempt usage. Every other claimed failure with no typed result is `unknown`, while a typed negative target response is `completed` with its exact result artifact. A verifier stopped by Run cancel/deadline has a `VerifierStopItem` and no receipt. A malformed response received from an executed/billable provider is `completed` with an unusable-response artifact, not a false no-effect failure.
- `unknown` requires the matching claim, an `evidenceRef/evidenceDigest` pair decoding exact `InvocationAmbiguityEvidenceV1`, and the exact conservative full `budgetSettlementRef`.
- `abandoned` requires an existing `unknown` whose ReplayClass is exactly `manual`, repeats that unknown row's settlement ref with zero additional delta, carries the local-principal attestation described below, forbids its own evidence pair, fabricates no result, and has the terminal-only identity-matched `ToolAbandonedItem` when the invocation originated from a tool/MCP call. It is administrative closure, not completion/failure evidence.

Every Journal evidence ref is accompanied by its digest or both are absent; the phase/op-kind decoder fixes the only legal artifact type. `InvocationAmbiguityEvidenceV1.evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`. Its Run/frontier/op/kind/attempt/dispatch/claim sequence, immutable request and target pairs, claiming Supervisor/StateOwner epoch, current inspector, and observation time equal the exact claimed attempt and the frontier transaction entering `unknown`; no caller/worker payload is accepted. `claim_owner_lost` rehashes exact `StateOwnerAcquisitionEvidenceV1(takeover_after_owner_death)` for the historical claim owner and requires the inspector to be that strictly newer active owner. `broker_channel_lost_after_claim` is limited to a claim that stored the same broker fence-token digest; the same still-live owner records one closed deadline/connection/stream failure after the second release gate and proves the Journal has no durable terminal result. `sandbox_channel_lost_after_claim` rehashes the claim's exact SandboxLaunchSpec and actual containment; its same-owner live branch requires `observedAt >= responseDeadlineAt`, an authenticated channel-close time, and no result, while its death branch rehashes exact all-descendant `ProcessContainmentDeathEvidenceV1` and proves no terminal result was durably received before death. `publication_path_ambiguous` rehashes only the same claim's exact `PublicationProofV1(kind='path_ambiguity')`. Any other kind/mechanism combination, free error string, missing pair, current-owner mismatch, or evidence that instead proves completion/failure is invalid. The `unknown` row repeats this exact pair; a later `ManualAbandonAttestationV1` must repeat the same pair byte-for-byte, not substitute newer display or probe evidence.

`PostClaimNoReleaseEvidenceV1.evidenceDigest` omits itself. Its Run/op/attempt/dispatch/claim sequence, request/target/grant, claiming Supervisor/owner epoch, and current inspector ref/digest equal the prepared/claim rows and current `SupervisorInspectorIdentityV1`; the inspector is the same still-live owner and the observation is within five seconds. The broker branch is legal iff the claim stored that exact fence-token digest: while holding the broker release mutex, the same owner revokes the still-unreleased token, observes zero matching active release, publishes the artifact, and appends post-claim failed plus zero-consumption settlement in one transaction before dropping the mutex. The process branch is legal iff the claim's exact SandboxLaunchSpec has not spawned; its ref and `ProcessContainmentNoSpawnEvidenceV1` rehash the same plan/spec/nonce and positively prove zero matching process. It likewise commits with the failed row before spawn authority can be released. A restart, owner change, absent live token, observed process/release, partial rollback, generic death, adapter assertion, or inline boolean cannot produce this artifact and therefore routes the claim to `unknown` unless the verifier-specific receipt/death form applies. No other op-specific post-claim failed evidence is admitted in v1.

Every `completed|unknown|abandoned` row and every post-claim `failed` row binds exactly one claim and immutable request. Only pre-dispatch `failed` binds the prepared row while proving claim absence and forbidding claim identity. Fields forbidden by the relevant phase/op-kind combination are rejected. These constraints apply equally to importer and test helpers, so no generic insert can fabricate a receipt or completion.

Attempts are contiguous from zero and at most one attempt per `opId` is current. Preparing attempt `n+1` is legal only when attempt `n` is fully settled and no prior dispatch remains live. A pre-dispatch `failed` attempt—local crash recovery, activation loss, or grant expiry after `prepared` but before any claim—always permits a replacement attempt for the same still-current frontier without consuming effect retry capacity. Its terminal transaction verifies that no claim row exists, releases the exact reservation, consumes the complete four-counter zero value, and records the deterministic local error; fresh authority, grant, budget, and deadline checks still apply to replacement. After a claim, a new attempt additionally requires either (a) `n` is `unknown` and its frozen ReplayClass authorizes retry after full pessimistic charge, or (b) `n` is positively `failed` and an explicit frozen same-op retry policy still has capacity. Case (b) includes same-digest verifier infrastructure retries and `workspace-rollback-retry` only after durable rollback/quarantine evidence; it never includes a completed attempt or an assertion repair against a new candidate, which receives a new opId. The new `prepared` row and reservation commit atomically, so recovery cannot schedule it twice. Once attempt `n+1` exists, a late resolution of attempt `n` may update audit/billing evidence but cannot append model/tool results, advance the typed frontier, or become the Run-visible result; only the highest prepared attempt is eligible to do so.

Before any model, tool, MCP, verifier, or semantic publication attempt, the transaction that appends `prepared` checks the frozen ceiling and moves a conservative upper bound from available budget into `Run.budgetReserved`. Immediately before I/O, the trusted DispatchArbiter appends the unique `dispatch_claimed` fact only through `claimDispatch`; only `releaseClaimedDispatch` may then release bytes/capability. The sole exception is the zero-budget abort-directory maintenance attempt governed by both recovery-maintenance checks above. A completed or positively failed attempt settles evidence-backed usage into `budgetConsumed` and releases the reservation. If usage is unknowable after timeout, disconnect, or death, Cliq charges the full reservation before any policy-authorized retry; crash recovery never refunds or resets it. Outstanding child allocations are also reservations on the parent, so concurrent child admission cannot oversubscribe a ceiling.

Budget mapping is exact. A claimed `model` attempt consumes its measured or conservatively reserved `modelTokens` and `costMicros` but no `toolCalls`. Every claimed non-model **productive** attempt—`tool`, `mcp-server`, `mcp`, `verifier`, and each semantic `mkdir|create|replace|delete` publication envelope—consumes exactly one `toolCalls`; verifier retries and MCP relaunches are new attempts and count again. Exact cleanup inside an already-claimed publication envelope and an abort-only removal of a delivery-created empty directory are pre-reserved recovery maintenance, not another productive attempt, and add zero `toolCalls`. Kernel child admission/await/merge actions execute as built-in `tool` operations and therefore count through their claims rather than through a hidden counter. `repairAttempts` increments only at the repair-authorization transaction. Supervisor-only no-new-effect recovery inspection is not a productive invocation and does not consume Run tool budget.

Reconciliation probing has no hidden infinite loop. The wait stores the exact `ReconciliationProbeStateV1` XOR. A manual invocation uses only `manual_only`. Every inspectable subject starts `automatic_pending(automaticProbeCount=0,userProbeCount=0,nextProbeAt=createdAt)` with no evidence pair. At its due time, one revision CAS enters `automatic_in_flight`, increments the automatic count, and persists one complete `ReconciliationProbeDispatchV1` before any query or inspection: `probeOrdinal=automaticProbeCount`, one unique nonce, fixed `probeDeadlineAt=probeStartedAt+30s`, current owning Supervisor, and the subject-specific broker dispatch or inspector-task identity. No prior evidence ref is carried into an in-flight state. An unresolved response at ordinal `n<8` enters `automatic_pending` with `nextProbeAt=observedAt+[1s,5s,30s,2m,10m,30m,1h][n-1]`; ordinal 8 enters `automatic_exhausted`. Every post-probe pending or exhausted state requires the exact last-evidence ref/digest pair; neither branch permits an absent or half-present pair. Counts, dispatch, and evidence survive reboot. Only the owning live Supervisor may resume the exact same dispatch/nonce without incrementing a counter; a successor first fence-closes the predecessor dispatch and follows the unresolved edge.

At `automatic_exhausted`, authenticated `run.reconcile(probe_now)` is an enqueue mutation, not a synchronous inspection result. One CAS increments positive safe-integer `userProbeCount`, enters `user_in_flight`, and persists a complete dispatch whose `probeOrdinal` equals that count, nonce/deadline are fresh, and `controlRequestId/controlRequestDigest` equal the public mutation. In that same transaction it publishes/stores the deterministic `ControlResultV1.resolution={kind:'probe_enqueued',dispatchDigest,userProbeCount}` plus the post-enqueue snapshot and commits `control_requests`; only afterward may the no-new-effect probe perform I/O. Same request bytes replay that response and join the same dispatch without probing twice; different bytes conflict. Completion later stores evidence and advances the wait through the ordinary internal reducer, producing Run events/snapshot changes but no second public response. An unresolved response returns to `automatic_exhausted` with the evidence pair and unchanged automatic count. `probe_now` before automatic exhaustion or for `manual_only` is `INVALID_REQUEST`; manual permits only exact-risk abandonment, whose synchronous result instead uses `resolution={kind:'abandoned',evidenceRef}`.

`ReconciliationProbeDispatchV1.dispatchDigest = SHA-256(JCS(dispatch with dispatchDigest omitted))`, and `reconciliationSubjectDigest = SHA-256(JCS(the frozen ReconciliationSubject))`. The MCP branch persists `brokerDispatchId = H(runId,reconciliationSubjectDigest,probeKind,probeOrdinal,probeNonceDigest)`, the exact no-new-effect request/target digests, and an unguessable broker fence-token digest; the broker release gate accepts only that still-current in-flight row and token. Publication/worker branches persist `inspectorTaskId = H(runId,reconciliationSubjectDigest,probeKind,probeOrdinal,probeNonceDigest)` and the exact descriptor-only target digest. Those fixed in-process tasks have no broker, child-process, mutation, or credential capability. A dispatch id/task id/fence token created only in memory is invalid.

Every automatic/user result first publishes exactly one `ReconciliationProbeEvidenceV1`; its omission digest, Run/wait digest, dispatch digest, kind/ordinal/nonce/start/deadline, current inspector, and observation time equal the persisted in-flight dispatch. `subject_observation` wraps exactly one subject-allowed artifact and rehashes its ref/digest: `McpRecoveryProbeEvidenceV1`, `PublicationProofV1`, or `WorkerRecoveryEvidenceV1`; MCP evidence additionally repeats the same probe-dispatch digest and broker identities. `probe_timeout` is legal only at or after the stored deadline and its ref/digest decodes exact `ReconciliationProbeTimeoutClosureV1`; `closureDigest` omits itself under JCS and all common probe/inspector/dispatch fields equal the wrapper/in-flight state. MCP closure first atomically revokes the exact persisted fence token, waits for the broker's matching active-release count to become zero, and records the same dispatch/target/token plus `noActiveReleaseForNonce=true`. Publication/worker closure repeats the persisted task id and either proves synchronous cancellation-and-join by its owning live Supervisor or names exact `StateOwnerAcquisitionEvidenceV1(takeover_after_owner_death)` proving that task's owning process died before the successor observed closure. Timeout authorizes no claim that the underlying effect completed or failed. It follows the same unresolved edge and schedule as an unresolved response. A late response for a closed nonce is audit-only and cannot clear a newer nonce or advance the Run. Each completed probe installs the wrapper's ref/digest or atomically applies the subject reducer. There is no public evidence payload, counter reset, automatic ninth probe, invalid ref-without-digest combination, or claim that repeated user inspection must eventually resolve. A global Supervisor ceiling bounds all probes.

Dispatch uses two mandatory checks shared by broker, sandbox launcher, model, MCP, verifier, and publish paths. `claimDispatch` reads Run plus `activeWorkerLaunchId` in one SQLite transaction and requires `status='running'`, the exact activated launch/current epoch/identity/generation/containment, unexpired launch lease, no `stopIntentRef`, no cancel flag, `now < deadlineAt`, the highest/current prepared attempt with no prior claim, matching typed frontier/operation, live grant, and matching reservation; it atomically appends the unique claim. Immediately before releasing any target capability or request bytes, `releaseClaimedDispatch` re-reads the same Run plus launch and the live stop/cancel/deadline/grant/frontier/reservation predicates and requires the exact just-created `dispatchId` as current—rather than the now-false “no claim” predicate. Failure closes or reconciles that claim without I/O. Only a successful second check authorizes new I/O.

There is one narrower post-stop gate, `claimRecoveryMaintenance`, and it is not a back door into `claimDispatch`. It runs only inside the trusted publication broker, requires an approved immutable DeliveryPlan and the historical decision/grant binding for that exact plan (the productive grant may now be expired), an active StopIntent, no live semantic publication claim, and an exact `abortOperations` entry whose referenced mkdir receipt proves this delivery created the directory. It prepares/claims a zero-budget `opKind='publish', ReplayClass='reconcile'` maintenance attempt using the Run's current monotonic `leaseEpoch`, current Supervisor instance, and no worker-launch authority, then allows only descriptor-relative `rmdir` of that exact proven-empty directory plus fsync/evidence. `releaseRecoveryMaintenance` rechecks those predicates and rejects any file write, desired-path create/replace/delete, nonempty/unexpected directory, or target drift. Completing cleanup inside an already-claimed leaf uses that leaf's existing claim and a similarly bounded recovery continuation; it never creates a second claim. These two paths are the only mutation exceptions after stop/deadline.

`assertEvidenceAuthority` is deliberately different. A trusted Supervisor may accept signed broker receipts, target status evidence, or positively inspected containment/process evidence for an already claimed attempt after its lease, grant, deadline, or cancellation state changed; expiry cannot erase what happened. It validates the immutable request/claim/original epoch and evidence provenance, but authorizes no new productive I/O. If the attempt is still highest/current and the exact `frontierRef` or `WaitingSubject` still matches, one transaction may append its terminal fact, normalized op-kind item, budget settlement, and subject-specific frontier reducer. If a newer attempt/frontier exists, the evidence is audit/billing-only and cannot change Run-visible state. An unauthenticated late worker assertion is never sufficient evidence.

Deadline/cancellation does not forbid the trusted recovery plane. After productive dispatch is stopped, bounded no-new-semantic-effect operations may still run: kill/death proof, status/idempotency query, generation quarantine/rollback, child cancel/settlement, publication inspection, completion/cleanup of an already-claimed publication envelope, abort-only removal of an exact delivery-created empty directory, and terminal commit. Conditional retry, model/tool/MCP call, or a new semantic publication envelope is never recovery and remains forbidden after deadline/cancel.

Every Journal `budgetDelta` is a complete `BudgetUsage` with exactly the four nonnegative safe-integer counters; optional members and omitted-versus-explicit zero encodings are forbidden. For a `prepared` entry it is the reservation created by that transaction. `dispatch_claimed` and `abandoned` use the exact all-zero value. Every terminal or `unknown` settlement publishes `BudgetSettlementV1`: `settlementDigest = SHA-256(JCS(settlement with settlementDigest omitted))`; its Run/op/attempt/prepared/terminal sequence and phase equal the Journal pair; `released = reserved`; `consumed` equals the terminal row's `budgetDelta`; `budgetConsumedAfter = budgetConsumedBefore + consumed`; and `budgetReservedAfter = budgetReservedBefore - released`, all component-wise with checked arithmetic. Pre-dispatch failure and exact `PostClaimNoReleaseEvidenceV1` consume the all-zero value; every released/possibly-released model terminal or `unknown` consumes its exact request-bound reservation in full. The settlement ref is retained by the terminal/unknown evidence closure and is reused—not recomputed as another charge—when terminal abandonment records it. Kernel Cut never lowers budget settlement from provider usage telemetry, cache assertions, SDK counters, or an adapter trust boolean; such fields may be retained only as non-authoritative telemetry. Negative deltas and decreasing reserved/consumed counters are invalid.

A completed model Journal result is a closed XOR. A usable response's `resultRef` decodes exact work-package-02 `AgentModelTurn` and satisfies the stop/call/text matrix. Any positively received but malformed, oversized, capability-incompatible, operation-invalid, or provider-rejected response instead decodes exact `ModelUnusableResponseV1`; a target rejection uses literal `failureCode='provider_rejected_response'` and never masquerades as a no-release failure. Its Run/op/attempt and normal-or-compaction request pair equal the claim and Journal request, while provider/model/mode equal the frozen assembly. `unusableDigest = SHA-256(JCS(artifact with unusableDigest omitted))`. A complete observed response retains the exact received bytes at `bytesRef`, requires `bytesDigest === bytesRef`, exact `byteCount <= 1,048,576`, and forbids `failureCode='response_too_large'`. An oversized response stores exactly the first `responseLimitBytes+1` bytes, fixes `responseLimitBytes=1,048,576`, requires the prefix branch and `failureCode='response_too_large'`, and releases no later byte to parsing. Media type and every other failure code are closed as typed; unknown provider fields remain only in those retained private response bytes. The Journal `resultRef` is this unusable artifact; for a normal request the Supervisor then publishes exact `RuntimeFailureEvidenceV1(failureKind='model_unusable_response')` naming it and the generic runtime StopIntent/TerminalDetail repeat that wrapper ref/digest. A context-compaction request instead uses its dedicated subtype and retains the immutable StopIntent itself as terminal primary evidence. It appends no `ModelTurnItem`, candidate, tool batch, or summary, consumes the full request reservation, and is never semantically retried. A response not positively known to exist remains `unknown`; only a local rejection proven before any claim or an exact post-claim no-release failure may be Journal `failed`, and neither is represented as a provider response.

Terminal abandonment of a `retry` unknown also requires `InvocationDispatchClosureEvidenceV1`; `evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`, and Run/op/attempt/dispatch/unknown sequence equal the one claimed-then-unknown Journal chain. `containment_death` rehashes its containment/death pairs and decodes exact `ProcessContainmentDeathEvidenceV1` whose owner/spec/dispatch closure matches that invocation. `broker_release_fenced` is legal only for a brokered claim with no child containment and decodes exact `BrokerReleaseFenceEvidenceV1`; its `evidenceDigest` omits itself under JCS. Run/op/attempt/dispatch/claim sequence/request/grant/target equal the Journal claim and decoded `OperationGrantV1`; claiming Supervisor/epoch equal its historical StateOwner row; current inspector ref/digest/epoch equal the sole active StateOwner and that epoch is strictly newer. Under the state-owner and broker locks, the current Supervisor atomically revokes the exact persisted fence-token digest, prevents a new matching release, waits for that dispatch's active-release count to reach zero, and only then records the two times/literal disposition. A token minted only in memory, token/claim/target drift, untrusted worker assertion, elapsed lease, socket loss, or mere new Supervisor id is not closure evidence. `RetryUnknownCancelledResult` and `TerminalDetail` repeat the exact settlement and dispatch-closure refs; storage decodes both before allowing the result to remain unused at terminal stop.

`unknown` pessimistically settles the attempt once by consuming and releasing its full reservation. A later positive-evidence `unknown -> completed|failed` fact carries zero additional budget settlement and never refunds, releases, or charges that attempt again. If it is still the highest attempt and its exact frontier/wait subject matches, the Supervisor applies the normalized op-kind reducer atomically; only a superseded attempt is audit-only.

### 8.2 Meanings

- `prepared`: Cliq durably recorded the exact request before dispatch.
- `completed`: positive evidence proves completion and the result/receipt is durable.
- `failed`: positive evidence proves the effect did not occur, or it was completely rolled back.
- `unknown`: the operation may have occurred, but Cliq cannot prove the outcome.
- `abandoned`: a local principal explicitly accepted unresolved truth and stopped this Run without consuming or fabricating the operation's result.

Timeout, connection reset, process death, and lost response are not automatically `failed`.

### 8.3 Tool Recovery Contract

Every executable tool definition declares one `ReplayClass`. This is separate from capability authorization:

- capability answers whether the Run may perform the action;
- replay class answers what recovery may do if the outcome is ambiguous.

The meanings are closed:

- `retry`: the request is semantically safe to issue as a new attempt. The old attempt remains `unknown`; its full budget reservation is consumed before retry.
- `workspace-rollback-retry`: the effect is confined to the abandoned private generation. Recovery restores the last ready workspace state into a fresh generation before a new attempt.
- `reconcile`: the target exposes idempotency or authoritative status lookup. The trusted Supervisor queries/conditionally retries; if positive evidence is still unavailable, the Run waits.
- `manual`: there is no safe automatic proof or replay contract. The Run immediately waits. Independently verifiable evidence uses the normal `completed|failed` reducer. Choosing `abandon_run` makes the Supervisor publish `ManualAbandonAttestationV1`, for which `attestationDigest = SHA-256(JCS(attestation with attestationDigest omitted))`; every principal/channel/control request, current wait/frontier, exact unknown Journal row/op/attempt/sequence, immutable operation request/target, ambiguity evidence, and digest must match authoritative state. It then appends `abandoned`, uses that identical ref in the Journal, StopIntent/terminal closure, and terminal-only `ToolAbandonedItem` when applicable, and terminates as `cancelled(cancelled_by_user)` without a result. The artifact is created only from authenticated `acknowledgeExactRisk:true`, cannot cross a wait/attempt/target, and never permits blind retry or an invented ToolResult.

A retry is always a new Journal attempt under the same stable `opId`; Journal history is never rewritten. Model calls use `retry` only because their uncommitted output cannot affect Run state and their possible billing is pessimistically charged first. Provider/effect HTTP adapters may not hide redispatch inside an attempt: every model, tool, MCP, verifier, publication, or other productive redispatch requires the prior attempt's settled `failed|unknown` fact plus a newly committed `prepared` row/reservation, even when an SDK claims that zero request bytes left the process. The sole read-only subrequest exception is dependency broker GET by exact frozen URL+cryptographic integrity: at most three GETs per package may occur inside the owning acquisition attempt, partial bytes are discarded, success requires the expected digest, and the terminal cache manifest records attempt counts/status. Such GETs have no remote mutation/idempotency ambiguity and cannot carry provider billing/tool results. Any other transport retry uses a new Journal attempt.

No general `EffectPlan` is introduced.

### 8.4 Workspace Transition Commit Invariant

No transition may make changed generation bytes part of the authoritative Run frontier until the matching post-transition workspace state is recoverable. This applies to every successful `workspace-rollback-retry` tool and every kernel-owned workspace transition whose later agent frontier depends on that mutable generation, including serial application of a mutating child result. Kernel-owned transitions use a stable `opId`, a Journal invocation identity, and `ReplayClass='workspace-rollback-retry'`; they do not bypass the effect contract merely because their code is trusted. The protocol is:

1. publish a ready pre-effect Checkpoint;
2. append `prepared` and reserve budget;
3. execute the single tool or kernel transition against its exclusive generation;
4. quiesce the generation and create a verified post-effect `workspaceStateRef` plus a context manifest that includes the deterministic ToolResult or kernel transition item;
5. in one SQLite transaction append Journal `completed`, insert that result/transition item, settle budget, insert the post-effect Checkpoint, advance `latestCheckpointId`/typed frontier/revision, and emit the client event.

A crash before step 5 leaves at most orphan artifacts and a `prepared` invocation; recovery restores the pre-effect Checkpoint and retries in a fresh generation. A crash after step 5 sees both the completed fact and the matching post-effect workspace/context cut. The store must reject `completed` or a Run-visible “merged/applied” item for any workspace-mutating operation unless that same commit installs its post-effect ready Checkpoint. If snapshot publication fails, the mutated generation is quarantined/discarded and cannot be exposed to the model as success.

A delivery merge is deliberately not such a transition. It is a pure deterministic projection from immutable source Run artifacts plus an immutable captured real-workspace manifest. Its temporary merge directory is disposable; before the delivery frontier advances, CAS must contain the normalized merged `resultSourceRef`, diff, and publication plan, and the state transaction references only those immutable artifacts. Recovery rematerializes the view from them. No later state may depend on uncheckpointed temporary merge bytes.

### 8.5 Exactly-Once Boundary

Cliq promises:

- exactly-once commit for its own SQLite state transitions;
- effectively-once behavior for isolated workspace operations and external systems with idempotency or status lookup;
- explicit reconciliation for opaque external effects.

Cliq does not claim universal exactly-once side effects across SQLite and third-party systems.

## 9. Supervisor And Durable Admission

The Supervisor is a trusted per-user process managed by launchd on macOS and systemd user services on Linux.

It owns:

- durable Run admission;
- a minimal FIFO queue with bounded concurrency; insufficient capacity leaves a Run queued but ineligible and creates no wait state;
- lease acquisition, heartbeat, epoch fencing, and recovery scanning;
- preactivation handshakes and per-Run all-descendant process containments;
- approval, input, cancellation, and child wakeups;
- trusted model/effect brokering;
- local control-protocol connections;
- retention and garbage collection.

It does not own a workflow graph, role scheduler, distributed queue, or cloud worker registry.

### 9.1 Lease, Activation, And Process Containment

`leaseEpoch` increases monotonically per Run. Workers cannot access SQLite directly. A PID or process group is a signal target, never the proof boundary: shell children may reparent or create a new session. The authoritative launch record is:

```ts
type ProcessContainmentOwner =
  | {
      kind: 'worker_activation'
      runId: string
      intendedLeaseEpoch: number
      workerLaunchId: string
    }
  | {
      kind: 'run_invocation'
      runId: string
      intendedLeaseEpoch: number
      workerLaunchId: string
      opId: string
      attempt: number
      dispatchId: string
    }
  | {
      kind: 'admin_probe'
      adminOperationId: string
      attempt: number
      principalId: string
      method: 'mcp.register' | 'mcp.refresh'
      originalRequestDigest: string
      targetRef: ArtifactRef
      supervisorInstanceId: string
    }
  | {
      kind: 'local_inference_service'
      serviceId: string
      serviceLaunchId: string
      ownerPrincipalId: string
      serviceSpecRef: ArtifactRef
      supervisorInstanceId: string
    }

type SandboxRootImageV1 = {
  schemaVersion: 1
  format: 'cliq-sandbox-root-image-v1'
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  entryId: string
  entryVersion: string
  entryDigest: string
  protocol: 'cliq-fresh-empty-root-v1'
  filesystemKind: 'fresh_ephemeral_tmpfs'
  fixedDirectories: ['/home/cliq', '/tmp', '/work']
  ownerUid: number
  persistent: false
  networkConfiguration: 'none'
  imageDigest: string
}

type GuestExecutableIdentity = {
  logicalName: string
  canonicalGuestPath: string
  digest: string
  version: string
}

type GuestToolchainManifest = {
  schemaVersion: 1
  format: 'cliq-guest-toolchain-v1'
  guestImageRef: ArtifactRef
  guestImageDigest: string
  guestImageByteCount: number
  guestImageFormat: 'raw-ext4-v1'
  architecture: 'arm64' | 'x86_64'
  kernelAbi: string
  userspaceAbi: string
  worker: GuestExecutableIdentity
  shell: GuestExecutableIdentity
  git: GuestExecutableIdentity
  node: GuestExecutableIdentity
  packageManager?: GuestExecutableIdentity
  searchTools: readonly GuestExecutableIdentity[]
  verifiers: readonly GuestExecutableIdentity[]
  admittedExecutables: readonly GuestExecutableIdentity[]
  publisherKeyId: string
  manifestDigest: string
  signatureRef: ArtifactRef
}

type ProcessContainmentPlanV1 = {
  schemaVersion: 1
  format: 'cliq-process-containment-plan-v1'
  owner: ProcessContainmentOwner
  filesystemBinding:
    | { kind: 'run-generation'; generationRef: ArtifactRef }
    | { kind: 'isolated-empty-root'; rootImageRef: ArtifactRef; rootImageDigest: string }
  parentContainmentRef?: ArtifactRef
  launchNonceDigest: string
  backend:
    | {
        kind: 'linux'
        cgroupPath: string
        cgroupNameReservationDigest: string
        pidNamespaceReservationId: string
        subreaperStartToken: string
      }
    | {
        kind: 'macos-vm'
        vmReservationId: string
        guestImageRef: ArtifactRef
        guestImageDigest: string
        guestBootNonceDigest: string
      }
  createdAt: string
  planDigest: string
}

type SandboxRuntimeBindingV1 = {
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  sandboxBackend: 'linux_namespace' | 'macos_vm'
  toolchain:
    | { kind: 'none' }
    | {
        kind: 'guest_toolchain'
        guestToolchainManifestRef: ArtifactRef
        guestToolchainManifestDigest: string
        guestImageRef: ArtifactRef
        guestImageDigest: string
      }
  launcher: {
    executableId: string
    executableDigest: string
  }
  runtimeDigest: string
}

type SandboxExecutableIdentityV1 =
  | {
      kind: 'runtime_bundle'
      runtimeBundleRef: ArtifactRef
      runtimeBundleManifestDigest: string
      executableId: string
      role: 'worker' | 'tool_adapter' | 'mcp_server' | 'local_inference' | 'platform_helper'
      executionPath: string
      executableDigest: string
    }
  | {
      kind: 'guest_toolchain'
      guestToolchainManifestRef: ArtifactRef
      guestToolchainManifestDigest: string
      toolId: string
      role: 'worker' | 'shell' | 'tool' | 'verifier' | 'package_manager' | 'search' | 'mcp_server'
      executionPath: string
      executableDigest: string
    }
  | {
      kind: 'workspace_script'
      purpose: 'verifier'
      workspaceIdentityDigest: string
      canonicalRootRelativePath: string
      scriptDigest: string
      interpreterIdentityRef: ArtifactRef
      interpreterIdentityDigest: string
    }

type SandboxCapturedStdioV1 = {
  stdin: 'closed'
  stdout: 'captured'
  stderr: 'captured'
  extraFileDescriptors: 'authenticated_operation_channel_only'
}

type SandboxProcessInvocationV1 =
  | {
      kind: 'worker_entrypoint'
      purpose: 'worker_activation'
      recipe: 'cliq-worker-entrypoint-v1'
      runtimeSource: 'launch_runtime'
      executableSource: 'launch_executable'
      argvSource: 'fixed_empty'
      cwdSource: 'generation_root'
      stdio: {
        stdin: 'closed'
        stdout: 'captured'
        stderr: 'captured'
        extraFileDescriptors: 'authenticated_worker_channel_only'
      }
    }
  | {
      kind: 'local_inference_entrypoint'
      purpose: 'local_inference_service'
      recipe: 'cliq-local-inference-entrypoint-v1'
      runtimeSource: 'launch_runtime'
      executableSource: 'launch_executable'
      modelManifestSource: 'service_spec'
      argvSource: 'trusted_recipe_decode_of_service_spec'
      cwdSource: 'isolated_root'
      stdio: SandboxCapturedStdioV1
    }
  | ({
      kind: 'run_request'
      requestRef: ArtifactRef
      requestDigest: string
      targetRef: ArtifactRef
      targetDigest: string
      argvCwdSource: 'trusted_recipe_decode_of_request_and_target'
    } & (
      | { purpose: 'tool'; recipe: 'cliq-tool-launch-v1'; stdio: SandboxCapturedStdioV1 }
      | { purpose: 'verifier'; recipe: 'cliq-verifier-command-v1'; stdio: SandboxCapturedStdioV1 }
      | {
          purpose: 'mcp_stdio'
          recipe: 'cliq-mcp-stdio-launch-v1'
          stdio: {
            stdin: 'mcp_framed'
            stdout: 'mcp_framed'
            stderr: 'captured'
            extraFileDescriptors: 'none'
          }
        }
      | { purpose: 'dependency'; recipe: 'cliq-dependency-launch-v1'; stdio: SandboxCapturedStdioV1 }
      | { purpose: 'publication'; recipe: 'cliq-publication-launch-v1'; stdio: SandboxCapturedStdioV1 }
    ))
  | ({
      kind: 'admin_probe'
      targetRef: ArtifactRef
      targetDigest: string
      probePayloadCoreRef: ArtifactRef
      argvCwdSource: 'trusted_recipe_decode_of_admin_target_and_probe_core'
    } & (
      | {
          purpose: 'admin_mcp_stdio_probe'
          recipe: 'cliq-admin-mcp-stdio-probe-v1'
          stdio: {
            stdin: 'mcp_framed'
            stdout: 'mcp_framed'
            stderr: 'captured'
            extraFileDescriptors: 'none'
          }
        }
      | {
          purpose: 'admin_mcp_http_probe'
          recipe: 'cliq-admin-mcp-http-probe-v1'
          stdio: SandboxCapturedStdioV1
        }
    ))

type SanitizedSandboxEnvironmentV1 = {
  schemaVersion: 1
  format: 'cliq-sanitized-sandbox-environment-v1'
  controlledPath: string[]
  locale: { lang: string; lcAll: string }
  home: string
  tmpdir: string
  variables: Array<{ name: string; value: { kind: 'non_secret_literal'; value: string } }>
  inheritedHostEnvironment: false
  secretMaterial: 'none'
  brokerAccessAtSpawn: 'none'
  networkMode: 'none' | 'broker_ipc_only'
  environmentDigest: string
}

type SandboxFilesystemV1 =
  | {
      kind: 'run_generation'
      generationRef: ArtifactRef
      access: 'preactivated_readonly' | 'read_only' | 'read_write'
      sourceProjectionRef: ArtifactRef
      independentGit: true
    }
  | {
      kind: 'isolated_empty_root'
      rootImageRef: ArtifactRef
      rootImageDigest: string
      persistentWritableMounts: false
    }

type SandboxMountV1 =
  | {
      kind: 'cas_artifact'
      artifactRef: ArtifactRef
      artifactDigest: string
      targetPath: string
      access: 'read_only'
      purpose: 'runtime' | 'input' | 'executable'
    }
  | {
      kind: 'run_generation'
      generationRef: ArtifactRef
      canonicalRootRelativePath: string
      targetPath: string
      access: 'read_only' | 'read_write'
      purpose: 'source' | 'dependency' | 'cache' | 'output'
    }
  | {
      kind: 'private_ephemeral'
      privateRootId: string
      targetPath: string
      access: 'read_write'
      purpose: 'home' | 'tmp' | 'dependency' | 'cache' | 'output'
    }

type SandboxLaunchBaseV1 = {
  schemaVersion: 1
  format: 'cliq-sandbox-launch-v1'
  runtime: SandboxRuntimeBindingV1
  executable: SandboxExecutableIdentityV1
  environment: SanitizedSandboxEnvironmentV1
  filesystem: SandboxFilesystemV1
  mounts: SandboxMountV1[]
  mountsDigest: string
  sandboxProfileRef: ArtifactRef
  sandboxProfileDigest: string
  resources: SandboxResourceSpec
  resourcesDigest: string
  containmentPlanRef: ArtifactRef
  containmentPlanDigest: string
  createdAt: string
  launchSpecDigest: string
}

type SandboxLaunchSpecV1 =
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'worker_activation' }>
      purpose: 'worker_activation'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'worker_entrypoint' }>
      operationGrantRef?: never
      requestRef?: never
      requestDigest?: never
      targetRef?: never
      targetDigest?: never
      parentWorkerContainmentRef?: never
      adminTargetRef?: never
      adminTargetDigest?: never
      probePayloadCoreRef?: never
    })
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'run_invocation' }>
      purpose: 'tool' | 'verifier' | 'mcp_stdio' | 'dependency' | 'publication'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'run_request' }>
      operationGrantRef: ArtifactRef
      requestRef: ArtifactRef
      requestDigest: string
      targetRef: ArtifactRef
      targetDigest: string
      parentWorkerContainmentRef: ArtifactRef
      adminTargetRef?: never
      adminTargetDigest?: never
      probePayloadCoreRef?: never
    })
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'admin_probe' }>
      purpose: 'admin_mcp_stdio_probe' | 'admin_mcp_http_probe'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'admin_probe' }>
      adminTargetRef: ArtifactRef
      adminTargetDigest: string
      probePayloadCoreRef: ArtifactRef
      operationGrantRef?: never
      requestRef?: never
      requestDigest?: never
      targetRef?: never
      targetDigest?: never
      parentWorkerContainmentRef?: never
    })
  | (SandboxLaunchBaseV1 & {
      owner: Extract<ProcessContainmentOwner, { kind: 'local_inference_service' }>
      purpose: 'local_inference_service'
      processInvocation: Extract<SandboxProcessInvocationV1, { kind: 'local_inference_entrypoint' }>
      serviceSpecRef: ArtifactRef
      serviceSpecDigest: string
      operationGrantRef?: never
      requestRef?: never
      requestDigest?: never
      targetRef?: never
      targetDigest?: never
      parentWorkerContainmentRef?: never
      adminTargetRef?: never
      adminTargetDigest?: never
      probePayloadCoreRef?: never
    })

type ProcessContainment = {
  schemaVersion: 1
  planRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  owner: ProcessContainmentOwner
  filesystemBinding:
    | { kind: 'run-generation'; generationRef: ArtifactRef }
    | { kind: 'isolated-empty-root'; rootImageRef: ArtifactRef; rootImageDigest: string }
  parentContainmentRef?: ArtifactRef
  launchNonceDigest: string
  backend:
    | {
            kind: 'linux'
            pidNamespaceReservationId: string
            pidNamespaceId: string
        cgroupPath: string
        cgroupId: string
        namespaceInitStartToken: string
        subreaperStartToken: string
      }
    | {
            kind: 'macos-vm'
            vmReservationId: string
            vmInstanceId: string
        vmProcessStartToken: string
        guestBootId: string
        guestImageRef: ArtifactRef
        guestImageDigest: string
      }
  createdAt: string
}

type PlatformProcessIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-platform-process-identity-v1'
  platform: 'linux' | 'macos'
  pid: number
  processStartToken: string
  ownerUid: number
  executableImageDigest: string
  observedAt: string
  identityDigest: string
}

type StateRootIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-state-root-identity-v1'
  platform: 'linux' | 'macos'
  canonicalAbsolutePath: string
  ownerUid: number
  deviceId: string
  directoryFileId: string
  mode: 448
  openedNoFollow: true
  layoutVersion: 1
  identityDigest: string
}

type StateLockIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-state-lock-identity-v1'
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  canonicalRootRelativePath: 'runtime/state-owner.lock'
  deviceId: string
  fileId: string
  ownerUid: number
  mode: 384
  linkCount: 1
  identityDigest: string
}

type StateOwnerTransitionEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-state-owner-transition-evidence-v1'
  priorOwnerEpoch: number
  priorSupervisorInstanceId: string
  priorProcessIdentityRef: ArtifactRef
  priorProcessIdentityDigest: string
  stateLockIdentityRef: ArtifactRef
  stateLockIdentityDigest: string
  observedAt: string
  evidenceDigest: string
} & (
  | {
      kind: 'graceful_release'
      releasingProcessIdentityRef: ArtifactRef
      releasingProcessIdentityDigest: string
    }
  | {
      kind: 'superseded_after_owner_death'
      priorProcessObservation: 'absent_or_start_token_mismatch'
      successorOwnerEpoch: number
      successorSupervisorInstanceId: string
      successorRuntimeBundleRef: ArtifactRef
      successorRuntimeBundleManifestDigest: string
      successorProcessIdentityRef: ArtifactRef
      successorProcessIdentityDigest: string
      successorInstanceNonceDigest: string
    }
)

type StateOwnerAcquisitionEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-state-owner-acquisition-evidence-v1'
  ownerEpoch: number
  supervisorInstanceId: string
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  processIdentityRef: ArtifactRef
  processIdentityDigest: string
  stateLockIdentityRef: ArtifactRef
  stateLockIdentityDigest: string
  instanceNonceDigest: string
  acquiredAt: string
  evidenceDigest: string
} & (
  | {
      kind: 'genesis'
      kernelGenerationIdentityRef: ArtifactRef
      kernelGenerationIdentityDigest: string
      ownerTableObservation: 'empty'
      priorOwnerEpoch?: never
      priorTerminalRowDigest?: never
      priorTransitionEvidenceRef?: never
      priorTransitionEvidenceDigest?: never
    }
  | {
      kind: 'acquire_after_graceful_release'
      priorOwnerEpoch: number
      priorTerminalRowDigest: string
      priorTransitionEvidenceRef: ArtifactRef
      priorTransitionEvidenceDigest: string
      priorTerminalReason: 'graceful_release'
      kernelGenerationIdentityRef?: never
      kernelGenerationIdentityDigest?: never
      ownerTableObservation?: never
    }
  | {
      kind: 'takeover_after_owner_death'
      priorOwnerEpoch: number
      priorTerminalRowDigest: string
      priorTransitionEvidenceRef: ArtifactRef
      priorTransitionEvidenceDigest: string
      priorTerminalReason: 'superseded_after_owner_death'
      kernelGenerationIdentityRef?: never
      kernelGenerationIdentityDigest?: never
      ownerTableObservation?: never
    }
)

type StateOwnerRecordV1 = {
  schemaVersion: 1
  ownerEpoch: number
  supervisorInstanceId: string
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  supervisorEntryId: string
  supervisorEntryVersion: string
  supervisorExecutableDigest: string
  processIdentityRef: ArtifactRef
  processIdentityDigest: string
  stateLockIdentityRef: ArtifactRef
  stateLockIdentityDigest: string
  acquisitionEvidenceRef: ArtifactRef
  acquisitionEvidenceDigest: string
  instanceNonceDigest: string
  acquiredAt: string
  rowDigest: string
} & (
  | {
      state: 'active'
      rowVersion: 1
      releasedAt?: never
      terminalReason?: never
      transitionEvidenceRef?: never
      transitionEvidenceDigest?: never
    }
  | {
      state: 'terminal'
      rowVersion: 2
      releasedAt: string
      terminalReason: 'graceful_release' | 'superseded_after_owner_death'
      transitionEvidenceRef: ArtifactRef
      transitionEvidenceDigest: string
    }
)

type SupervisorInspectorIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-supervisor-inspector-identity-v1'
  supervisorInstanceId: string
  stateOwnerEpoch: number
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  supervisorEntryId: string
  supervisorEntryVersion: string
  supervisorExecutableDigest: string
  processIdentityRef: ArtifactRef
  processIdentityDigest: string
  stateLockIdentityRef: ArtifactRef
  stateLockIdentityDigest: string
  instanceNonceDigest: string
  activatedAt: string
  identityDigest: string
}

type ProcessContainmentNoSpawnEvidenceV1 = {
  schemaVersion: 1
  kind: 'containment_plan_quiescent'
  planRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  owner: ProcessContainmentOwner
  launchNonceDigest: string
  inspectorSupervisorInstanceId: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  backend:
    | {
        kind: 'linux'
        cgroupPath: string
        cgroupObservation:
          | { kind: 'absent' }
          | { kind: 'empty'; cgroupId: string; populated: 0 }
        pidNamespaceObservation:
          | { kind: 'never_created'; pidNamespaceReservationId: string }
          | { kind: 'dead_reaped'; pidNamespaceReservationId: string; namespaceInitStartToken: string }
        subreaperStartToken: string
        matchingLaunchNonceProcessCount: 0
      }
    | {
        kind: 'macos-vm'
        vmReservationId: string
        vmObservation:
          | { kind: 'never_created' }
          | {
              kind: 'stopped_reaped'
              vmInstanceId: string
              vmProcessStartToken: string
              guestBootId?: string
            }
        matchingLaunchNonceProcessCount: 0
      }
  observedAt: string
  evidenceDigest: string
}

type ProcessContainmentDeathEvidenceV1 = {
  schemaVersion: 1
  kind: 'containment_all_descendants_dead'
  containmentRef: ArtifactRef
  planRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  sandboxLaunchSpecDigest: string
  owner: ProcessContainmentOwner
  launchNonceDigest: string
  inspectorSupervisorInstanceId: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  backend:
    | {
        kind: 'linux'
        pidNamespaceReservationId: string
        pidNamespaceId: string
        cgroupPath: string
        cgroupId: string
        cgroupPopulated: 0
        namespaceInitStartToken: string
        namespaceInitDeadAndReaped: true
        subreaperStartToken: string
        remainingTrackedDescendants: 0
      }
    | {
        kind: 'macos-vm'
        vmReservationId: string
        vmInstanceId: string
        vmProcessStartToken: string
        vmProcessDeadAndReaped: true
        guestBootId: string
        guestRetired: true
      }
  observedAt: string
  evidenceDigest: string
}

type ProcessContainmentRef = ArtifactRef

type WorkerIdentity = {
  schemaVersion: 1
  executableRealpath: string
  executableDigest: string
  pid: number
  processStartToken: string
  spawnNonceDigest: string
  activationNonceDigest: string
  intendedLeaseEpoch: number
  launchId: string
  supervisorInstanceId: string
  processContainmentRef: ArtifactRef
}

type WorkerLaunch = {
  schemaVersion: 1
  launchId: string
  runId: string
  plannedRunRevision: number
  supervisorInstanceId: string
  spawnNonceDigest: string
  activationNonceDigest: string
  phase: 'reserved' | 'preactivated' | 'activated' | 'reconciling' | 'retired'
  workspaceGenerationRef: ArtifactRef
  containmentPlanRef: ArtifactRef
  sandboxLaunchSpecRef: ArtifactRef
  workerIdentityDigest?: string
  processContainmentRef?: ArtifactRef
  leaseEpoch?: number
  leaseVersion: number
  leaseExpiresAt?: string
  generationWriteState: 'preactivated_readonly' | 'active' | 'revoking' | 'checkpointing' | 'fenced_reconciling' | 'sealed'
  quiesceId?: string
  createdAt: string
  activationDeadlineAt: string
  activatedAt?: string
  retiredAt?: string
  retirementEvidenceRef?: ArtifactRef
}
```

The immutable identity binds PID/start token/spawn/activation nonce **and** an immutable `ProcessContainmentRef` whose backend identity covers every descendant for the lifetime of the activation. The containment owner is a closed union: a worker identity must reference `worker_activation` matching its Run/epoch/launch; an invocation containment must reference `run_invocation` matching the exact durable claim and a parent containment in the same Run activation; an admin row must reference `admin_probe` matching its operation/attempt/principal/method/request/target/Supervisor and may not contain Run/lease/worker fields; a local-inference launch must reference `local_inference_service` matching the exact service/launch/principal/spec/Supervisor row and may not contain Run, Journal, or admin fields. Worker activations use `run-generation`; admin probes and local inference use `isolated-empty-root`; invocation bindings follow the frozen tool contract. A top-level worker, admin, or local-inference containment has no parent, while a run invocation's parent chain must terminate at its exact worker activation.

Every spawn additionally resolves the exact `SandboxLaunchSpecV1`; no caller constructs an untyped process, argv, cwd, stdio, environment, mount, or backend bag. `runtimeDigest`, `environmentDigest`, `mountsDigest`, `resourcesDigest`, and `launchSpecDigest` are SHA-256 over RFC 8785/JCS with only the named digest member omitted where it is a member of that object. `containmentPlanDigest` and `sandboxProfileDigest` equal their decoded artifacts. `SandboxRootImageV1.imageDigest` likewise omits itself; its ref/digest resolves one non-executable signed RuntimeBundle `sandbox_root_profile` entry by id/version/digest. Fixed Supervisor code materializes a new empty tmpfs root with exactly the three listed owner-only directories, no device/socket/network state, and no persistent bytes. Plan, launch filesystem, and actual containment repeat the same ref/digest. A host directory, mutable base image, caller-selected root, reused writable layer, or merely empty-looking path is invalid. Mount targets are unique, byte-sorted, nonoverlapping canonical sandbox paths sourced only from verified CAS, the exact generation, or a Supervisor-created private ephemeral root; writable runtime/CAS, host paths, symlink sources, persistent admin/MCP mounts, ambient credential roots, devices, sockets, and untyped mounts are forbidden. Environment variables are unique/byte-sorted and cannot override the dedicated PATH/HOME/TMP/locale/broker/credential/activation/Supervisor channels; host environment and secret material are always absent at spawn.

A `local_inference_service` launch has one all-and-only model mount projection. Its registration's exact object closure is copied and rehashed into WP01 CAS before the launch artifact is published. The launch uses `isolated_empty_root`; every mount is `cas_artifact/read_only/input`; and, byte-sorted by target path, the set is exactly the signed model manifest at `/models/model-manifest.json`, its tokenizer at `/models/tokenizer`, and one entry per byte-sorted manifest file at `/models/files/<canonicalRelativePath>`. Paths are normalized absolute guest paths, remain under those literal roots, and cannot collide, escape, alias, or add an unlisted object. Ref/digest/size values equal the closure and decoded manifest; no state-root/source-package/host mount or writable model layer is legal. The fixed `cliq-local-inference-entrypoint-v1` recipe supplies exactly `['serve','--manifest','/models/model-manifest.json','--model-root','/models/files','--tokenizer','/models/tokenizer','--host','127.0.0.1','--port',<base-10 service port>]`, uses `/` as cwd, and resolves the executable only from the service spec's signed RuntimeBundle entry. This projection, its JCS `mountsDigest`, and argv are reproduced on recovery; an implementation-local cache path or model-server default is never launch authority.

Owner and recipe equality are exhaustive. A worker spec matches the exact WorkerLaunch/plan/Run/epoch/generation, is `preactivated_readonly`, has no parent or operation/admin fields, uses only the signed worker entrypoint recipe, and exposes only its activation-blocked authenticated worker channel. A run-invocation spec matches the exact permanent Journal claim and `OperationGrantV1`, request/target refs/digests, active parent worker containment, generation/mount envelope, and one fixed `tool|verifier|mcp_stdio|dependency|publication` recipe; verifier source is read-only with declared ephemeral writes, stdio MCP is an isolated empty root, and mutation writes only the active generation. An admin spec matches the exact AdminOperation/MCP target/static probe core, has no Run/lease/frontier/operation grant fields, and uses only the fixed stdio or HTTP probe recipe in an isolated empty root. A local-inference spec matches the exact service launch/spec, signed `local_inference` executable and model-manifest read-only mounts, has no Run/Journal/admin/grant fields or parent, and uses only `cliq-local-inference-entrypoint-v1` in a no-egress isolated root. Runtime/toolchain/executable/profile/resources resolve byte-for-byte from retained signed manifests and the exact Run assembly/admin/service target; verifier cannot select RuntimeBundle, RuntimeBundle MCP must have role `mcp_server`, and local inference must have role `local_inference`. Any process source, recipe, equality, forbidden field, role, digest, mount, environment, resource, or out-of-band IPC override fails before containment creation.

`WorkerLaunch.sandboxLaunchSpecRef` and `AdminOperation.sandboxLaunchSpecRef` are mandatory before their powerless preactivation. A Run invocation is different because its owner contains the permanent `dispatchId`: its `prepared` Journal row forbids `sandboxLaunchSpecRef`; `claimDispatch` chooses the unguessable dispatch id, publishes/validates the exact launch artifact, and atomically records that ref only on `dispatch_claimed`. Every later terminal/unknown/abandoned phase repeats the same ref, while a non-spawning operation forbids it on every phase. `ProcessContainment`, no-spawn evidence, and death evidence repeat that exact launch ref/digest plus plan/owner/nonce/backend closure. Thus no content-addressed cycle or pre-claim fictional dispatch id exists, and storage can prove which exact launch contract was—or was not—executed.

Every pre-spawn `containmentPlanRef` resolves to `ProcessContainmentPlanV1`; `planDigest` omits itself under JCS. Owner/filesystem/parent/nonce match the reserving WorkerLaunch/AdminOperation/claim exactly. The actual containment requires that plan ref and repeats those fields; Linux additionally matches cgroup path, PID-namespace reservation, and subreaper token, while macOS matches VM reservation and guest image. A preactivation failure accepts only `ProcessContainmentNoSpawnEvidenceV1` matching the exact plan/owner/nonce/backend locator and proving absent-or-empty planned resources plus zero matching process. Retirement, Checkpoint, result, verifier, MCP stop, or replacement accepts only `ProcessContainmentDeathEvidenceV1` matching the actual containment/plan/owner/backend identities and the complete zero-descendant observations.

`PlatformProcessIdentityV1.identityDigest`, `StateRootIdentityV1.identityDigest`, and `StateLockIdentityV1.identityDigest` each omit themselves under JCS. A process identity is a bounded current platform observation: positive safe-integer PID, platform-native start token normalized as NFC ASCII, same-user uid, and executable-image digest equal to the selected signed Supervisor entry. A state-root identity is produced only by opening the configured absolute root component-by-component with no-follow semantics and `fstat`ing the held same-user `0700` directory descriptor; its NFC absolute path contains no `.`/`..`/empty component, its device and directory-file ids are unsigned decimal strings, and its owner equals the effective uid. The ref rehashes to the exact artifact and its digest; replacement, rename, owner/mode change, or descriptor/path disagreement is a different state root and blocks authority rather than following it. A lock identity comes from `fstat` of the held no-follow same-user regular `${stateRoot}/runtime/state-owner.lock` descriptor: its state-root ref/digest must equal that exact held parent descriptor, canonical relative path, unsigned-decimal device/file ids, uid, literal `0600`, and link count one. Caller paths, PID without start token, a root opened by path after validation, or a reopened/replaced lock file are invalid.

`state_owners` stores only exact `StateOwnerRecordV1`. `ownerEpoch` is a positive safe integer, unique, contiguous, and strictly increasing; `rowDigest = SHA-256(JCS(row with rowDigest omitted))`. Every record's process, root/lock, and acquisition ref/digest decode the exact types above. `StateOwnerAcquisitionEvidenceV1.evidenceDigest` omits itself under JCS and every common identity equals its resulting row. `genesis` is legal only for epoch one with an empty owner table and exact `KernelGenerationIdentityV1`; its state-root ref/digest equals the lock, its database/CAS identities equal the opened generation, and its `fresh_empty|migrated_candidate` origin validates. `acquire_after_graceful_release` requires no active row, the latest row terminal with `graceful_release`, exact row/transition digests, and `ownerEpoch=priorOwnerEpoch+1`. `takeover_after_owner_death` requires the sole active predecessor to become the exact referenced `superseded_after_owner_death` terminal row in the same transaction and the acquisition evidence to reference that death transition; its successor fields and new row are byte-identical.

Every terminal transition references exact `StateOwnerTransitionEvidenceV1`; its digest omits itself under JCS, and prior epoch/instance/process/lock equal the active row. The bootstrap first acquires that exact same-user OS lock. While holding it, `superseded_after_owner_death` requires the bounded platform inspector to observe the decoded prior PID/start-token identity absent or mismatched, and the evidence's successor epoch/instance/bundle/process/nonce must equal the active row appended in the **same SQLite transaction** that terminalizes the prior row; both rows/evidence repeat the same root/lock identity. `successorOwnerEpoch=priorOwnerEpoch+1`. A graceful owner evidence repeats its own process identity, terminalizes only its own active row, then releases the exact descriptor lock; its transaction appends no successor. A later clean startup uses `acquire_after_graceful_release`, never genesis or a fabricated death. Terminal reason and evidence kind must match.

The universal owner gate has exactly three bootstrap/acquisition entrypoints, all while the caller holds and revalidates the decoded OS root/lock descriptor. `bootstrapStateOwner` requires an empty owner table plus one exact selected, as-yet-unowned `KernelGenerationIdentityV1` and atomically registers the prewritten content-addressed root/lock/process/acquisition object metadata with active epoch one. `fresh_empty` validates the fixed empty database/CAS closure; `migrated_candidate` validates the exact candidate/image/CAS/migration closure and is legal only after its matching Kernel authority marker is durable. Fresh bootstrap occurs before any ordinary Kernel mutation; migrated bootstrap is the first Kernel repository transaction after cutover authority publication and before admission/control release. `acquireStateOwnerAfterGracefulRelease` requires the latest exact graceful terminal row and atomically registers the new process/acquisition objects plus epoch `n+1`. `takeoverStateOwner` requires the sole active predecessor plus positive exact process-death observation and atomically registers transition/new-process/acquisition objects, terminalizes `n`, and appends active `n+1`. These transactions may write only the named artifact metadata and state-owner rows; they cannot mutate Run/Session/Journal/broker state or release capability. Content-addressed object bytes may be staged before the transaction but are unrooted and non-authoritative until it commits. Every other **Kernel repository** write requires the existing active row's exact process and held lock. The sole non-repository authority transition after graceful terminalization is section 16.3's already-staged, digest-bound legacy marker rename while that same process still holds every rollback lock; it cannot write SQLite/CAS or change the prepared bytes. At most one active row exists; OS-lock loss or row mismatch gates all writes immediately. Startup never resets/reuses an epoch, and rows/evidence are GC roots. A stale process cannot regain authority by presenting old bytes.

Every `inspectorIdentityRef` decodes only to `SupervisorInspectorIdentityV1`; `identityDigest = SHA-256(JCS(identity with identityDigest omitted))`, and the evidence repeats that digest. The referenced signed RuntimeBundle manifest must contain exactly the named executable entry with role `supervisor` and matching version/digest; its complete signed manifest rehashes to the named ref/digest. `supervisorInstanceId`, current `stateOwnerEpoch`, RuntimeBundle/entry, process identity, lock identity, and instance nonce must equal the sole active `StateOwnerRecordV1` held throughout the evidence transaction. The identity is published only after that active row commits while the process holds the exact OS lock; it becomes historical when ownership changes and cannot justify a later observation. Evidence digests omit themselves under JCS; `inspectorSupervisorInstanceId` must equal the **current** state-owning Supervisor and the decoded identity's instance, while the original spawner remains bound independently through the plan owner, WorkerLaunch/AdminOperation, and nonces. Observation time must be within the state transaction's bounded freshness window (default/max 5s). No PID exit, timeout, worker assertion, stale inspector identity, or schema-valid artifact with mismatched plan/nonce/owner/bundle is proof.

`workerIdentityDigest` resolves to that versioned artifact; a PID-shaped free string is never authority. Storage requires its `launchId`, `supervisorInstanceId`, `spawnNonceDigest`, `activationNonceDigest`, and `processContainmentRef` equal the owning row, and its `intendedLeaseEpoch` equal the epoch installed by the single activation transaction; the artifact cannot be rebound to another launch, containment, or epoch. `activationDeadlineAt = createdAt + 120s` and is never extended. `generationWriteState` is the sole mutable generation-write gate: preactivation is read-only, only `active` may write, and revocation/checkpoint/seal CASes bind a unique `quiesceId`. Phase/identity changes and retirement use revisioned storage operations; only `leaseVersion`/`leaseExpiresAt` use the narrow heartbeat CAS described in section 6.

Entering `running` uses a blocked preactivation handshake; the Supervisor never chooses between “spawn an unowned process” and “persist a fictional PID”:

1. materialize and verify the fresh private generation artifact; an orphan before state publication is harmless CAS/GC state;
2. while the Run remains queued, append/reserve the sole unretired `worker_launches` intent naming a unique nonce, Supervisor instance, planned backend-containment identity, generation, expiry, and Run revision;
3. create that containment and spawn a worker blocked on a private activation channel, with zero workspace-write, broker, model, MCP, credential, or child-spawn authority;
4. inspect PID/start token and the backend's all-descendant containment identity;
5. one transaction changes the launch to `activated`, installs its inspected worker/containment/generation, initial lease version/expiry, and new epoch, then transitions the Run `queued -> running`, increments Run revision/epoch, and installs `activeWorkerLaunchId`;
6. send a one-use activation token bound to the committed epoch/identity. Only then may the worker receive its writable generation handle or broker channel.

CAS loss, channel loss, timeout, or Supervisor crash forces termination and proof that the planned containment is empty; startup scans every unretired launch row and reaps it before requeue. A blocked child can never dispatch. A queued Run may have only the one bounded preactivation row and still has no active pointer. A `running` Run without an exact activated `activeWorkerLaunchId` row is invalid.

Strong containment is backend-specific but semantically identical:

- Linux uses bubblewrap with a private PID namespace plus a dedicated cgroup v2 subtree and Supervisor subreaper. Empty-cgroup proof, not `killpg`, establishes descendant death.
- macOS uses the bundled, signed Virtualization.framework Linux microVM backend. Each activation has a disposable guest PID namespace/cgroup and no host credentials or writable host mount; guest containment emptiness plus VM termination establishes death. Seatbelt without that VM may protect descriptor-safe non-Run inspection helpers, but it is not a Run execution backend because it cannot provide the required durable worker/claim/all-descendant recovery contract.

Every takeover first stops dispatch and performs one transaction that changes the old launch to `reconciling` with `generationWriteState='fenced_reconciling'`, creates the exact typed `worker_death` subject containing launch/identity/epoch/containment/generation/open attempts, CASes the generation from its current `active|revoking|checkpointing` phase to `fenced_reconciling` while retaining its prior snapshot/launch/epoch and binding that wait ref/digest/source phase/quiesce id, clears the Run's active pointer/lease, and installs the wait. This transaction is mandatory even when positive all-descendant death evidence is already immediately available; there is no direct pointer-bound generation-to-quarantine edge. The inspector then terminates or reobserves the old containment, and only a completed `WorkerRecoveryEvidenceV1` for that installed wait may drive `fenced_reconciling -> quarantined`. No second worker starts before that transition, and no branch falsely quarantines bytes before death proof.

The fenced generation retains `fencedJournalSeq`, the nonnegative safe-integer
Journal high-water committed by that same fence transaction (zero for an empty
Journal). It is required only in `fenced_reconciling` and cannot change while
that row remains fenced. `openInvocationRefs` exactly equal, in Journal order,
the canonical prepared-row references whose attempts were unresolved in that
prefix. Recovery rejects a missing/out-of-range cutoff, extra or omitted
witnesses, and preparations or dispatch claims after it. Later trusted
settlements or abandonment retain those original witnesses; their current
phases still come only from the Journal. Neither timestamps (which may be equal
on both sides of the fence) nor `run_events` reconstruct this historical cut.

A new Supervisor instance never adopts or reconnects an old worker, even when its persisted lease has not yet expired. Launch claims and broker channels are bound to the old `supervisorInstanceId`; takeover revokes them, kills/proves the entire containment, quarantines/restores through a Checkpoint, and uses a fresh launch/epoch. This removes an adoption protocol and prevents two trusted processes from sharing effect authority.

`quiesceGeneration` is the only route to a workspace snapshot or verifier/publication proof. It closes new dispatch, performs a worker barrier, may freeze only as a transient stop-the-world aid, then terminates/reaps and positively proves the full invocation containment empty before retirement/state release. It acquires the generation's exclusive write token, hashes and publishes artifacts while holding that token, revalidates bytes, and holds the token through the SQLite state commit. A frozen-but-live containment is never quiescent. A failure with positive death proof follows `checkpoint_failed -> quarantined`; indeterminate death follows the same atomic `fenced_reconciling` wait transition as takeover. Neither publishes a ready Checkpoint or receipt from possibly changing bytes, and a claimed attempt remains `unknown` until its own effect evidence closes.

### 9.2 Recovery Algorithm

```text
scan non-terminal Runs
-> inspect active worker-launch pointer, launch lease/version, and recorded containment identity
-> reap any blocked preactivation intent
-> terminate and prove death of stale all-descendant containment
   -> if unprovable: waiting(reconciliation)
-> inspect every open prepared/dispatch_claimed/unknown invocation
   -> prepared without a claim + fenced old epoch: fail as positive no-dispatch
   -> dispatch_claimed: append unknown unless positive terminal evidence exists
-> preserve the original invocation epoch and apply each ReplayClass
   -> if unresolved: waiting(reconciliation)
-> settle or retain every outstanding budget reservation
-> restore latest ready Checkpoint into a new workspace generation
-> validate RunSpec, artifact digests, assembly, typed frontier, and budgets
-> persist a preactivation intent and launch a blocked containment
-> atomically activate the inspected launch identity/generation, install the Run pointer, and acquire the new epoch
-> release the one-use activation token and resume the typed frontier, or remain waiting
```

Waiting Runs do not retain a worker or active execution lease.

Supervisor startup scans every nonterminal `local_inference_activation_cycles` row, every nonretired `local_inference_launches` row, and every nonterminal `admin_operations` row before serving model traffic or registry mutations. It never adopts an old process. For a reserved row it proves the exact plan/spec closure never spawned or is empty; for a preactivated/active/revoking row it fences traffic, terminates the exact containment, obtains current-inspector death evidence, and retires the row. It then resumes only the owning cycle's exact edge: finalize an already-active launch and bounded participant fanout, enter its fixed retry wait, reserve its sole second attempt, or publish its typed failure and participant results. A nonterminal cycle's attempt and participant history is never reset or reassigned to a new request after restart. Only after terminal cycle/launch closure may a genuinely new participant start the next ordinal cycle. A Run selecting `local_zero_cost` and lacking a fresh service follows the one total reducer above: settle/quiesce, remain queued on the same frontier while its joined cycle runs, become eligible on cycle success, or receive `runtime_failed/local_inference_unavailable` on cycle failure. It never reproduces old launch/containment ids or falls back to a raw loopback endpoint.

### 9.3 Durable Control Decisions

Approval, user input, and reconciliation are authoritative application-service commits, never transient callbacks or `run_events` facts. Every mutator includes an idempotent `requestId`, expected Run revision, exact `waitingOnRef`, authenticated local principal, and a closed decision/request. A stale revision/ref is rejected without partial change. Public reconciliation never accepts caller-selected adapter ids, status payloads, or opaque evidence bytes.

`run.approve` first publishes exactly one `ApprovalDecisionV1` and then switches on the canonical `ApprovalSubject`; there is no tool-shaped generic fallback. `decisionId = H(principalId,runId,waitingSubjectRef,requestId,requestDigest)`, `waitingSubjectDigest` and `subjectDigest` are SHA-256 of their exact JCS artifacts/projection, and `decisionDigest = SHA-256(JCS(decision with decisionDigest omitted))`. The artifact must repeat the authenticated principal and exact `channelIdentityRef/channelIdentityDigest`, current Run/revision/frontier, exact WaitingSubject ref/bytes/subject, and canonical control request id/digest; the control row retains the same pair. The subject's policy-channel evidence pair must decode, rehash, name this exact Run/frontier/op/request/target, and have `effectiveDisposition='ask'`; approval cannot substitute a different parse or policy channel. `requestedTtlMs` is present iff supplied on the wire. `grantExpiresAt` is required iff allow creates authority, equals the resulting grant expiry (delivery-plan approval uses Run deadline), and is absent on deny. A stale/different wait, subject, frontier, principal, channel, request, revision, parser evidence, or digest cannot reuse a decision ref. The decision, subject-specific item/result, optional grant, Run revision/frontier, event, and control response commit in one transaction:

- `tool_call`: allow creates a grant and preserves the same result-less call/tool frontier; deny appends exactly one normalized denied `ToolResultItem` and advances the ordered batch.
- `mcp_server_launch`: allow preserves the originating MCP call while authorizing the exact registered server lifecycle; deny appends a denied result for that originating call and advances its tool batch.
- `verifier_launch`: allow preserves the exact verify frontier. Denial of a required verifier records a policy-decision item and cancels the Run as `cancelled_by_user` without a fake verifier receipt; denial of an advisory verifier records a typed `skipped_by_user` audit item and advances the verifier plan without satisfying a gate.
- `delivery_plan`: allow grants only the exact immutable path plan and moves the delivery frontier to publication; deny records a delivery-decision item and cancels only the delivery Run as `cancelled_by_user`, leaving the source result and real workspace untouched. It never fabricates a ToolResult.
- `dependency_install_scripts`: allow grants only the exact candidate-bound plan/lock digest and preserves `verify:dependencies`; deny records a policy decision and fails the required verification path as `runtime_failed` without running package code or fabricating readiness.

`PolicyDecisionItem` is a closed direct-versus-interactive union. Both branches rehash the exact `policyChannelEvidenceRef/policyChannelEvidenceDigest` and repeat subject kind, op, principal, Run/frontier/request/target, and evidence disposition. `direct_policy` structurally forbids `waitingSubjectRef`, requires `decisionRef === policyChannelEvidenceRef`, and permits only the recomputed direct allow or deny; `interactive_approval` requires the current WaitingSubject, requires evidence disposition `ask`, and its `decisionRef` decodes exact `ApprovalDecisionV1` for that wait. Allow always requires the exact subject grant and forbids denial outcome; deny forbids a grant and requires one exact `PolicyDenialOutcomeV1` whose subject kind equals the item. Tool/MCP outcome points to the identity-matched denied result; required-verifier outcome points to the exact StopIntent (interactive user cancel or direct `policy_deny`); advisory-verifier outcome points to exact `VerifierSkipItem` (`skipped_by_user` for interactive or `skipped_by_policy` whose decision ref/digest is the channel evidence for direct); delivery/dependency outcome points to the exact interactive cancellation or direct `policy_deny` StopIntent. A direct verifier/delivery/dependency policy StopIntent rehashes that same evidence and maps verifier to `verification_failed`, delivery/dependency to `runtime_failed`; no ApprovalDecision or phantom wait exists. An item cannot replace evidence with display text, a reparsed command, a different policy snapshot, or an approval over a different `ask` result.

An allow grant binds principal, Run, subject kind, exact `opId`/target/digests, decision, creation/expiry, and a bounded `maxAttempts` or `maxLaunches`. The default expiry is `min(now + 1 hour, Run.deadlineAt)`; an explicit user TTL may only shorten or extend it up to `deadlineAt`. A normal grant covers contiguous policy-authorized attempts of that same op/target up to its bound, never another frontier. If it expires before `prepared`, the same subject returns to a new approval wait. If it expires after `prepared` but before `dispatch_claimed`, the state service appends a positive no-dispatch `failed`, releases the reservation, and creates a new approval subject for the same result-less frontier. Expiry after the claim does not revoke reality: terminal evidence is evaluated against grant validity at claim time, but no retry/relaunch uses the expired grant. No path silently auto-allows, errors away, or strands an expired grant.

`run.input` accepts only an `input` subject created by the built-in
`request_input` call. Its `InputRequestItem.promptRef/promptDigest` decodes
exact `InputPromptV1` and repeats the current Run/batch/call/index. The prompt
text is exact `ModelTextV1`; the closed response branch is either bounded NFC
text or bounded JSON under exact `InputResponseSchemaV1`. The public input kind
must equal that branch. The Supervisor validates/canonicalizes once, publishes
`UserInputPayloadV1`, and appends one `UserInputItem` plus the identity-matched
executed ToolResult in one transaction. The result's model-content value is
exactly the payload string or schema-normalized JSON value—never its principal,
prompt, schema, or audit refs. If more calls remain the transaction preserves a
tool frontier; otherwise it creates an agent frontier with cause `input`.

`request_input` is the closed built-in control contract: `access='control'`,
`replayClass='manual'`, adapter id `request_input`, version `1`, and no manifest
output schema. It is not an ordinary policy action and cannot mint an
OperationGrant, prepare/claim a Journal invocation, perform target I/O, or
charge a tool dispatch. A same-named MCP tool remains an ordinary MCP call.
Its native input is `{prompt,responseKind,maximumResponseBytes,responseSchema?}`:
prompt is nonempty NFC/no-NUL text of at most 262144 UTF-8 bytes; the byte limit
is required and `1..1048576`; `responseSchema` is required exactly for `json`.
The entire response schema is prevalidated with the whole native batch.
Other fields, unsupported schemas and malformed prompts reject the call before
any call in that batch dispatches. Requesting input does not grant any file,
command, network or child authority, in any policy mode.

The wait atomically appends the exact InputRequestItem, unchanged-workspace
ready Checkpoint and input WaitingSubject. If a worker exists, current-inspector
containment-death and unchanged-workspace snapshot proof seal its generation
and retire it in that transaction; competing unretired launches forbid waiting.
The request item is excluded from model content. Answering is a worker-free
control commit, retaining the exact WaitingSubject, canonical request identity
and authenticated channel in UserInputPayloadV1. Recovery replays the prompt
from the frozen native call and checks the exact control row and response.
Both wait and answer preserve the Journal and budget; continuation needs a
fresh worker activation. No synthetic external invocation is created.

Input ToolResults use `source='user_input'` and bind the committed UserInputItem
and payload, whereas externally dispatched ToolResults use `source='invocation'`
and bind their Journal completion. These branches are disjoint and cannot
substitute for each other. Input text must fit both its prompt UTF-8 limit and
the existing 1-MiB JCS model-content limit; JSON fits both limits in JCS bytes.

For normal prompt projection, defer UserInputItem user messages until all
ToolResults of their owning batch have been emitted, preserving input order
and emitting them before the next assistant message. This is the explicit
exception to raw-item emission order in section 11: native tool results must
remain contiguous after their assistant call batch. The durable item order
stays InputRequestItem, UserInputItem, ToolResult. Compaction selects whole
batches and uses this same model-message order, not audit-item order.

`run.reconcile(resolution='probe_now')` only asks the trusted Supervisor to run the exact inspection contract already frozen by `ReconciliationSubject` and its immutable Journal/registry/DeliveryPlan/containment graph. It is legal only with no probe in flight. The invocation form exists only for `opKind='mcp'` with `recovery='mcp_reconcile'` and repeats the immutable registry/profile/template/predicate refs and digests; model, verifier, MCP-server, ordinary built-in tool, retry, and manual invocations cannot enter that branch. Model/verifier unknowns use their frozen retry-or-runtime-stop reducers, MCP-server uncertainty uses exact instance/containment lifecycle recovery, publication has its own subject, and worker loss has its own subject. The control request supplies no target, adapter, predicate, or response payload and cannot widen frozen bytes.

An MCP subject observation contains only `McpRecoveryProbeEvidenceV1`; `evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`. Run/wait/op/attempt, automatic-or-user probe ordinal and in-flight nonce, registry/tool/profile/template/predicates, broker dispatch/target, and response ref/digest equal the current subject, outer probe wrapper, and exact secretless status request. The response is bounded canonical JSON under the registered status-output contract. `disposition` is `completed` iff only the completed predicate matches, `failed` iff only the failed predicate matches, otherwise `unresolved`; both/neither/schema failure is unresolved and cannot advance. A completed/failed disposition appends the matching Journal resolution plus normalized result/error and advances the exact tool frontier; unresolved only records the outer evidence and clears the nonce.

A publication subject observation wraps the exact appropriate `PublicationProofV1` branch and validates its path/operation/claim/inspector fields before appending a `PublicationPathResultItem` or retaining the wait. A worker subject observation wraps only `WorkerRecoveryEvidenceV1`; its omission digest, wait/launch/epoch/worker/containment/generation fields, exact `ProcessContainmentDeathEvidenceV1`, current `SupervisorInspectorIdentityV1`, and generation-disposition XOR must match. Its `generationTreeDigest` is the old generation row's last-verified tree, never a claim that unreadable dirty bytes were rehashed. `restored_from_checkpoint` requires `restoredCheckpointId`, `restoredWorkspaceStateRef`, and a distinct `replacementWorkspaceGenerationRef`; that id resolves the same Run's ready immutable Checkpoint, its workspace-state ref equals the evidence, and the replacement decodes an exact preactivated-readonly generation materialized from that Checkpoint. Both disposition branches publish a `WorkspaceGenerationQuarantineEvidenceV1(reason='worker_recovery')` that references this worker evidence and atomically CAS the old generation only from its exact `fenced_reconciling` wait to `quarantined`, retire the old launch, and clear the wait. `restored_from_checkpoint` additionally queues an unstopped Run against the exact replacement; `quarantined` forbids the three replacement fields and leaves the Run queued for later fresh materialization. No branch leaves the old dirty generation active, revoking, checkpointing, or selectable. Waiting `lastProbeEvidenceRef/digest` must decode to `ReconciliationProbeEvidenceV1`, whose wrapped branch is the sole one allowed by its subject. Positive evidence uses `assertEvidenceAuthority`; arbitrary schema-valid bytes, a public-client payload, or a worker assertion are not proof.

For an invocation whose subject has `recovery='manual'` and whose Journal ReplayClass is exactly `manual`, a local principal may choose only `abandon_run`: the exact-risk attestation appends `abandoned`, appends the terminal-only call-closure marker when applicable, and terminates the Run as `cancelled(cancelled_by_user)`. It produces no result and never feeds the marker to the model. `probe_now` is invalid for manual, and `abandon_run` is invalid for MCP-reconcile/publication/worker-death subjects; those remain explicitly actionable through no-new-effect `probe_now` even after automatic probes stop. Manual abandonment cannot continue a tool batch as though the effect succeeded/failed.

A successful subject reducer normally changes `waiting -> queued`, clears wait fields, installs its exact replacement frontier, and remains lease-free. If cancellation/deadline/parent-stop intent is already set, it instead evaluates terminal quiescence and never queues productive work. No reducer jumps directly to `running`; FIFO eligibility plus the blocked activation handshake is the only execution path.

Control items preserve audit and recovery truth but capability details are excluded from model-visible context; the model receives only a normalized allow/deny or reconciliation result. Secrets are never stored in decisions or grants.

### 9.4 Cancellation Reducer

`run.cancel` is an idempotent control transaction keyed by `requestId`; it does not attempt an unbounded whole-tree write. The acknowledged transaction proposes the target's typed `cancelled_by_user` StopIntent, sets `cancelRequested`, and thereby creates the durable cascade root. From that commit onward every child admission, approval/input/grant commit, repair authorization, activation, `claimDispatch`, and `releaseClaimedDispatch` walks the persisted parent chain (maximum depth 8) in the same SQLite snapshot and rejects if any ancestor has a stop intent. Thus the whole subtree is fenced at the first commit even before descendant rows are rewritten.

The Supervisor then traverses child relations in deterministic breadth-first batches of at most 100, proposing identity-bound `parent_cancelled` intents for direct children and continuing from durable parent StopIntent/child rows; restart derives the same remaining work, so no separate volatile queue is authority. Each child transaction is idempotent, applies fixed precedence, and signals/revokes its own activation. Direct user cancel outranks a parent intent regardless of race. The cancel API returns after the root fence commit, not after every descendant quiesces; `run.get` exposes stop/quiescence progress. A target cannot terminal until direct allocations settle, so cascade completion cannot be skipped by deleting ancestry.

Only a queued `tool` frontier or a call-origin local approval/input/MCP-launch wait appends an identity-matched `ToolResultItem(outcome='cancelled')` for its current call, then closes every undispatched suffix call with cancelled results. A queued agent/model/verifier/finalize/delivery continuation has no tool call and uses its operation-specific stop item/frontier closure; it never fabricates a ToolResult. All variants release/fail any prepared-without-claim attempt as positive no-dispatch, settle reservations, and terminal-cancel when otherwise quiescent. Child-await cancellation uses the stop-settlement rule in section 12. These stop-only closures never resume the model. Claimed effects, worker-death/publication reconciliation, unrolled-back generations, and child allocations remain explicit waits until death/evidence/rollback/child settlement makes the Run terminal-quiescent. Only bounded no-new-semantic-effect recovery evidence, the exact publication-envelope/abort maintenance gate in section 8.1, and descendant cancellation/settlement are accepted after the flag; no model repair, conditional retry, semantic delivery operation, or new permission is accepted.

Child terminal settlement never blindly wakes a cancelled or expired parent. If the parent is lease-free on the exact child subject, the satisfying transaction may settle the allocation, append normalized child results, and run terminal-quiescence; only an unstopped parent becomes queued. If the parent is running, child terminal changes only its allocation row and the parent settles it in its own next revisioned transaction. Repeated cancellation and recovery scans are no-ops after the same facts are committed.

## 10. Trusted Execution Boundary

The security order is mandatory:

```text
Workspace Trust
-> load trusted repo-controlled state
-> validate schemas
-> Tool Permission / durable grant
-> pre-effect Checkpoint and Journal prepared
-> OS Sandbox execution or trusted broker dispatch
-> Journal terminal fact
-> Run item / state transition
```

Trusting a workspace never grants tool permission and never disables the sandbox.

### 10.1 Initial Strong-Support Matrix

| Environment | Detached read-only | Detached mutation/exec |
|---|---:|---:|
| macOS with signed Virtualization.framework microVM backend | Yes | Yes |
| Linux with functioning bubblewrap + private PID namespace + cgroup v2/subreaper | Yes | Yes |
| macOS with Seatbelt only | No Run admission | No, fail closed |
| macOS/Linux without enforcement backend | No Run admission | No, fail closed |
| Native Windows | No | No, fail closed |

Non-Git workspaces are legal only through the same strong private-generation backend; Git presence never selects a weaker execution path. Seatbelt remains useful as host-side defense around the macOS VM launcher and descriptor-safe local inspection, but is not advertised as Run containment. There is no workerless restricted-read Run, weak worktree, or unsandboxed attached execution mode in the Kernel Cut. Native Windows is intentionally outside the new state/runtime authority: its compatibility binary exposes only `cliq state export`, which may read the legacy JSON store under its old locks and produce a verified portable handoff; every Kernel state/control command reports `UNSUPPORTED_PLATFORM`. It does not create/open the new SQLite/CAS store, migrate in place, inspect/administer it, or run a Supervisor. WSL2 is Linux only when the Linux service and complete Linux sandbox/containment probes pass. Native Windows state/runtime support requires a separate security/Supervisor RFC.

Admission is capability-complete: every `run.submit|run.apply` is rejected before Run creation with `UNSUPPORTED_PLATFORM` or `UNSUPPORTED_EXECUTION_IDENTITY` unless the corresponding strong backend, worker identity, and every pinned executable pass their probes. Cliq never accepts even a read-only/text-only Run into a state whose mandatory `running`/WorkerLaunch/claim path cannot execute it. A no-required-verifier request still needs explicit unverified consent, but consent never substitutes for the strong execution backend.

`sandboxProfileRef` freezes both reachability and resource governance:

```ts
type SandboxResourceSpec = {
  maxProcesses: number       // default 256; range 1..1024
  memoryBytes: number        // default 4 GiB; range 256 MiB..32 GiB, host-clamped
  cpuQuotaMicrosPerSecond: number // default 400000; range 10000..1600000
  maxOpenFiles: number       // default 1024; range 64..8192
  maxSingleFileBytes: number // default 2 GiB; range 1 MiB..16 GiB
  maxGenerationBytes: number // default 20 GiB; range 256 MiB..100 GiB
  maxInvocationOutputBytes: number // default 16 MiB; range 64 KiB..64 MiB
  maxIpcFrameBytes: number   // fixed 16 MiB
  maxQueuedIpcBytes: number  // fixed 64 MiB per Run
}

type SandboxProfileV1 = {
  schemaVersion: 1
  format: 'cliq-sandbox-profile-v1'
  backend: 'macos_vm' | 'linux_namespace'
  allowedOwners: Array<
    'worker_activation' | 'run_invocation' | 'admin_probe' | 'local_inference_service'
  >
  filesystemPolicy: 'typed_launch_spec_only'
  hostFilesystemReachability: 'none'
  networkAtSpawn: 'none'
  networkAfterRelease: 'typed_broker_only'
  credentialReachability: 'typed_broker_only'
  stateRootReachability: 'none'
  inheritedHostEnvironment: false
  resources: SandboxResourceSpec
  profileDigest: string
}
```

`profileDigest = SHA-256(JCS(profile with profileDigest omitted))`.
`allowedOwners` is nonempty, unique, byte-sorted, and every launch owner must
be listed. Run admission selects the one probed strong backend, fills every
missing public resource field with the displayed default, fixes both IPC
values, host-clamps only by rejecting an infeasible result, and publishes this
exact profile before Run creation. `RunSpec.sandboxProfileRef`, assembly
backend, every containment plan/launch ref+digest/backend, and the launch's
inline `resources` all decode and equal that one artifact; admin/local-service
producers publish the same type with their exact owner set. No caller may
increase, reinterpret, or replace it after admission.

All resource values are safe integers and admission fails rather than silently raising a host-infeasible request. Linux enforces PID/memory/CPU/I/O quotas with cgroup v2, `no_new_privs`, rlimits, namespace mounts, and a quota-backed generation. The macOS backend enforces the same limits inside the guest cgroup plus host VM memory/CPU/disk caps. PID/OOM/disk/output/IPC limit trips stop dispatch and become positive infrastructure evidence only after the complete containment is dead and generation state is quiescent; verifier attempts classify under section 13, while an ordinary tool receives one typed resource-limit error. An unproven death remains `unknown`, never `failed`. Output is truncated only at the declared artifact boundary; source/result state is never truncated.

The macOS VM executes Linux binaries, so `assemblyRef` must include the exact signed `GuestToolchainManifest` above. `manifestDigest` hashes JCS with `manifestDigest` and `signatureRef` omitted; `signatureRef` verifies that digest through the bundled Cliq release key. `guestImageRef` content-addresses the complete immutable raw-ext4 image bytes, `guestImageDigest` equals their SHA-256/ArtifactRef, and `guestImageByteCount` is their exact positive safe-integer size. Architecture, kernel/userspace ABI, and exact paths/digests/versions cover Cliq worker, shell, Git, Node/package manager, search tools, and every admitted executable. Plan, `SandboxRuntimeBindingV1`, actual containment, launch evidence, assembly GC, and reboot relaunch repeat and rehash the same image ref/digest; a digest without retained bytes or a current installed-image lookup is invalid. Verifier/tool identity is resolved against this execution environment—not a host Mach-O path—and the environment fingerprint includes the manifest. Unsupported host-only commands or incompatible native dependencies fail admission with `UNSUPPORTED_EXECUTION_IDENTITY`; Cliq never claims that host `node_modules` can execute in the guest. Dependency acquisition, when permitted, is a separately granted brokered locked-artifact fetch into the private guest generation and is Journaled; no guest shell receives ambient network.

The initial dependency contract is exact and deliberately Node-only:

```ts
type DependencyAcquisitionPlanBase = {
  schemaVersion: 1
  format: 'cliq-dependency-acquisition-plan-v1'
  ecosystem: 'node'
  guestToolchainManifestRef: ArtifactRef
  packageManifest: {
    canonicalRootRelativePath: 'package.json'
    contentRef: ArtifactRef
    contentDigest: string
  }
  lockfileRef: ArtifactRef
  lockfileDigest: string
  registryEndpoints: Array<{
    endpointRegistrationRef: ArtifactRef
    endpointIdentityDigest: string
    tlsPolicyDigest: string
  }>
  credentialGrantRefs: ArtifactRef[]
  allowInstallScripts: boolean
  maxPackages: number
  maxDownloadBytes: number
  planDigest: string
}

type DependencyAcquisitionPlan = DependencyAcquisitionPlanBase & (
  | { adapter: 'npm-ci-v1'; lockfilePath: 'package-lock.json' }
  | { adapter: 'pnpm-frozen-v1'; lockfilePath: 'pnpm-lock.yaml' }
  | { adapter: 'yarn-immutable-v1'; lockfilePath: 'yarn.lock' }
)

type PackageCacheFetchAttemptV1 = {
  attempt: 1 | 2 | 3
  outcome: 'transport_failed' | 'http_error' | 'integrity_mismatch' | 'completed'
  httpStatus?: number
  receivedBytes: number
  observationDigest: string
}

type PackageCacheEntryV1 = {
  packageName: string
  packageVersion: string
  endpointRegistrationRef: ArtifactRef
  canonicalPackagePath: string
  integrityAlgorithm: 'sha256' | 'sha512'
  integrityDigest: string
  blobRef: ArtifactRef
  blobDigest: string
  blobBytes: number
  fetchAttempts: PackageCacheFetchAttemptV1[]
}

type PackageCacheManifestV1 = {
  schemaVersion: 1
  format: 'cliq-package-cache-manifest-v1'
  runId: string
  resultSourceRef: ArtifactRef
  dependencyPlanRef: ArtifactRef
  lockfileRef: ArtifactRef
  lockfileDigest: string
  entries: PackageCacheEntryV1[]
  packageCount: number
  totalTransferredBytes: number
  manifestDigest: string
  createdAt: string
}
```

RunSpec freezes a `DependencyPolicy`, not a candidate plan:

```ts
type DependencyPolicy = {
  schemaVersion: 1
  mode: 'none' | 'locked_node'
  allowedAdapters: Array<DependencyAcquisitionPlan['adapter']>
  registryEndpoints: Array<{
    endpointRegistrationRef: ArtifactRef
    endpointIdentityDigest: string
    tlsPolicyDigest: string
  }>
  credentialGrantRefs: ArtifactRef[]
  installScriptsPolicy: 'deny' | 'exact_lockfile_grant'
  installScriptsGrantRef?: ArtifactRef
  maxPackages: number
  maxDownloadBytes: number
}

type DependencyInstallScriptsAuthorizationTemplateV1 = {
  schemaVersion: 1
  format: 'cliq-dependency-install-scripts-authorization-v1'
  runId: string
  ownerPrincipalId: string
  workspaceIdentityDigest: string
  sourceAuthorizationGrantId: string
  sourceConsumptionReceiptRef: ArtifactRef
  guestToolchainManifestRef: ArtifactRef
  allowedAdapters: Array<DependencyAcquisitionPlan['adapter']>
  lockfilePath: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock'
  lockfileRef: ArtifactRef
  lockfileDigest: string
  registryTargetsDigest: string
  maxCandidateGenerations: number
  maxDispatchedAttemptsPerPlan: 1
  expiresAt: string
  templateDigest: string
}
```

`run.submit dependency.mode='locked'` resolves the public endpoint/credential ids to immutable registration/grant refs, freezes canonical HTTPS endpoint identity plus TLS policy digests, and validates each credential grant is principal-owned and bound to the same endpoint/purpose, exact authority/service revision, secret generation, and external subject. Re-registering an id cannot redirect an admitted Run: every candidate plan copies these frozen refs/digests unchanged, and the broker redeems only the exact still-current frozen-generation platform item against that target or returns authorization-required without dispatch. Kernel Cut accepts one sharp Node layout only: literal root `package.json`, exactly one literal root lockfile, no `workspaces` member, no nested package manifest, and no second supported lockfile. `packageManifest.contentRef/digest` and `lockfileRef/digest` rehash those exact candidate `SourceManifest` file entries. `package-lock.json` selects only `npm-ci-v1`, `pnpm-lock.yaml` only `pnpm-frozen-v1`, and `yarn.lock` only `yarn-immutable-v1`; the selected pinned package-manager entry must exist in the guest toolchain. Missing integrity, nested/workspace layout, ambiguity, or unlocked resolution fails before Run creation/candidate verification rather than invoking a package-manager heuristic. `planDigest = SHA-256(JCS(plan with planDigest omitted))`.

At every FinalCandidate, trusted code derives a new immutable `DependencyAcquisitionPlan` from the **candidate** SourceManifest's exact root manifest/lockfile under that policy and binds it into `VerifierPlan`; it never reuses an admission-time plan against changed files. If scripts are authorized, admission consumes the exact `dependency_install_scripts` `AuthorizationGrantV1` and publishes the template above in the same transaction. `installScriptsGrantRef` names only that template. `registryTargetsDigest = SHA-256(JCS({registryEndpoints,credentialGrantRefs}))`, using the policy's byte-sorted endpoint tuples and byte-sorted unique credential refs exactly; `templateDigest = SHA-256(JCS(template with templateDigest omitted))`. Template workspace/lockfile/toolchain/allowed-adapter/registry-target bytes must equal the policy and admitted source. Its `sourceConsumptionReceiptRef` decodes to the identity-matched consumed grant and exact `{kind:'run_admission',runId,admissionIntentDigest}` consumer; it never binds the final admitted digest, which is computed only after the template and dependency-policy refs exist and then binds the complete closure. `maxCandidateGenerations = RunSpec.budgets.repairAttempts + 1`, and `expiresAt = Run.deadlineAt`. Each script-bearing candidate plan must retain the same lockfile digest and the exact endpoint/credential projection and consumes one of those generation ordinals through its exact Journal-backed `OperationGrantV1`; there is no resettable counter. A changed lock digest cannot reuse the template: scripts remain denied and the Run creates a typed approval subject for that candidate or fails in noninteractive deny mode. Defaults/maxima are 50,000/200,000 packages and 5/20 GiB downloaded. Repository registry config is declarative endpoints only; endpoints/credentials must be pre-registered user ids. The trusted broker fetches HTTPS package artifacts by frozen lockfile URL+integrity into CAS and may use the bounded integrity-GET exception; it passes no secret into the guest. A bundled adapter then performs a networkless, frozen-lockfile install. Install scripts are off by default; an exact lockfile template runs integrity-pinned package code inside the same strong secretless/networkless containment and never grants host access.

The whole acquisition is one built-in `opKind='tool'`, target `builtin:dependency-acquire`, `ReplayClass='workspace-rollback-retry'`, and one `toolCalls` reservation. Its request binds the complete plan. During it, the candidate source projection is mounted read-only; only plan-declared dependency/cache/temp roots are writable. Install scripts therefore cannot modify candidate source even when authorized. Before completion Cliq rehashes the exact candidate source and requires equality with the verify frontier's `resultSourceRef`; a detected/audited source write or digest drift quarantines the generation and fails as kernel integrity rather than verifying stale bytes. Partial CAS downloads are harmless orphans; a partial install is discarded with the generation.

Success publishes only exact `PackageCacheManifestV1`. `manifestDigest = SHA-256(JCS(manifest with manifestDigest omitted))`; Run/result/plan/lockfile equal the current verify frontier and decoded plan. Trusted lockfile parsing yields one canonical tuple `(packageName,packageVersion,endpointRegistrationRef,canonicalPackagePath,integrityAlgorithm,integrityDigest)` for each required package; manifest entries are unique and byte-sorted by that tuple and match that set exactly. Each entry's endpoint is one frozen plan endpoint, path is normalized absolute endpoint-relative HTTPS path with no credentials/query/fragment, blob ref/digest/size rehash exactly, and final attempt is `completed` with matching integrity. Attempts are contiguous from 1, maximum three, preceding attempts are non-completed, `httpStatus` is present only for `http_error`, received bytes are nonnegative safe integers, and every secret-free broker observation digest is retained. `packageCount=entries.length`; `totalTransferredBytes` is the checked sum of every attempt's received bytes and is at most plan `maxDownloadBytes`; entry count is at most plan `maxPackages`. An integrity mismatch may be recorded before a later fetch only when the mismatching partial bytes were discarded and never became `blobRef`. The ready transaction commits `DependencyReadyItem.packageCacheManifestRef` to this artifact, its `opId/attempt` to that same completed acquisition Journal fact, `readyCheckpointId` to the post-effect ready workspace Checkpoint created in the transaction, the budget settlement, and verify frontier `phase='verifiers'`. That Checkpoint belongs to the same Run, includes the ready item and completed Journal sequence, and its `workspaceStateRef` decodes exact `WorkspaceStateManifest`; that state's `entriesRef` decodes `WorkspaceEntryManifest`, and `DependencyReadyItem.installedTreeDigest` must equal its `treeDigest`. The state retains the exact candidate-derived base/projection/private-Git closure and the item `planRef` equals the current VerifierPlan dependency plan. Storage decodes/rechecks the manifest and all these equalities; a model may invoke the same built-in tool earlier only when that exact ready Checkpoint/plan/result graph matches. Other ecosystems or unlocked/networked package-manager execution are unsupported rather than hidden shell network.

### 10.2 Private Workspace Generations

Every mutating worker lease owns a unique private workspace generation with an independent `.git` directory. Ordinary Git worktrees are forbidden as the strong default because they share common Git metadata.

The sandbox prevents a worker from writing:

- the user's real workspace;
- the real repository's Git metadata;
- another Run or generation;
- Supervisor state, CAS metadata, or the SQLite database;
- undeclared external filesystem roots.

Each new lease restores into a new generation. Old generations are quarantined and later garbage-collected.

### 10.3 Base Workspace Manifest

For a supported Git repository, admission records:

- repository identity and `HEAD`;
- index tree/state without mutating the real index;
- current tracked working-tree bytes, including dirty files;
- ordinary non-ignored untracked files;
- symlink targets without following them outside the workspace;
- executable bits and path identity;
- configured explicit includes.

Capture uses a frozen safe Git profile, not the user's ambient Git runtime. The admitted root must contain a same-user, descriptor-validated real `.git` directory; linked worktrees/common gitdirs outside that root are rejected in the Kernel Cut. Cliq parses `.git/config` and in-root ignore files through no-follow handles, rejects `include|includeIf`, fsmonitor, filters/process helpers, external attributes/excludes, hooks, and any path-bearing config it cannot contain, then invokes only allowlisted read-only plumbing with explicit `GIT_DIR`/`GIT_WORK_TREE`, sanitized HOME, no system/global config, no optional locks, hooks/fsmonitor/attributes/external excludes disabled, and no credential/network helper. Source bytes are read directly through held descriptors rather than through clean/smudge filters. Frozen ignore rules come only from descriptor-validated in-root `.git/info/exclude` and `.gitignore`; an external `core.excludesFile`, `core.attributesFile`, or config include is rejected rather than followed. Workspace Trust never authorizes ambient host reads or helper execution.

Ignored inputs are not imported by default. The Kernel Cut does not admit arbitrary external filesystem inputs or mounts; every source selector is root-relative, and a trusted config request for an outside-root path is rejected. Cliq-managed secret-bearing inputs and all provider/tool credentials are opaque broker references only: the credential/keychain path never places their raw bytes in a general worker, workspace generation, prompt, Checkpoint, Journal payload, event, receipt, or result manifest. User-supplied verifier/MCP argv and environment values are accepted only as explicit `non_secret_literal` wrappers and are persisted/audited as ordinary data; the client is responsible for not mislabeling a secret, and the UI warns that such literals are not protected. Credential-bearing arguments must use a supported opaque broker handle or are unsupported. A future external/raw-secret input feature requires a separate RFC and cannot silently weaken this managed-secret non-persistence guarantee.

The initial strong contract rejects every Gitlink/submodule, Git LFS-filtered path, nested repository, unsupported special file, or path identity that cannot be represented safely, with a specific reason. It preserves bytes, safe symlink text, executable bits, and empty private-generation directories needed for recovery; hardlink identity, xattrs, ACLs, ownership, and timestamps are not source/result semantics. Physical copy-on-write and content deduplication are implementation optimizations behind one semantic workspace-image contract.

### 10.4 Recovery State Versus Deliverable Result

- `workspaceStateRef` is a full restorable execution state for crash recovery. It may include generated and ignored cache state created inside the private RunWorkspace, except brokered secret inputs and declared ephemeral paths.
- `resultSourceRef` is the immutable deliverable source manifest. It contains only admitted source scope and explicit result inclusions.
- declared ephemeral paths are never assumed after restore; recovery marks them invalidated and the Run or verifier must rebuild them before relying on them.

This separation prevents a dependency cache or build directory from becoming part of the user's patch while still allowing correct recovery.

### 10.5 Deterministic Source Projection

`sourceProjectionRef` freezes a `SourceProjectionSpec` at admission. Its hard exclusions are source `.git`, Cliq state, broker-managed credentials/known credential roots, external mounts, declared ephemeral paths, unsupported special files, and paths outside the admitted root; no include can override them. Next, explicit excludes win over authorized includes. Authorized includes may opt ordinary ignored files into the result. Otherwise the default projection contains:

```ts
type FrozenIgnoreRuleV1 = {
  order: number
  sourceIndex: number
  sourceLine: number
  baseDirectory: string
  negated: boolean
  directoryOnly: boolean
  anchored: boolean
  pattern: string
}

type FrozenIgnoreRulesV1 = {
  schemaVersion: 1
  format: 'cliq-frozen-ignore-rules-v1'
  matcherVersion: 'cliq-git-wildmatch-v1'
  repositoryIdentityDigest?: string
  sources: Array<{
    index: number
    kind: 'git_info_exclude' | 'gitignore'
    canonicalRootRelativePath: string
    baseDirectory: string
    contentRef: ArtifactRef
    contentDigest: string
  }>
  rules: FrozenIgnoreRuleV1[]
  rulesDigest: string
}

type SourceIncludeClassificationEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-source-include-classification-v1'
  principalId: string
  runId: string
  sessionId: string
  workspaceIdentityRef: ArtifactRef
  workspaceIdentityDigest: string
  selector: { path: string; scope: 'entry' | 'subtree' }
  selectorDigest: string
  admissionIntentDigest: string
  frozenIgnoreRulesRef: ArtifactRef
  frozenIgnoreRulesDigest: string
  gitIndexRef?: ArtifactRef
  gitIndexTreeObjectId?: string
  entries: Array<{
    path: string
    workspaceEntryDigest: string
    deviceId: string
    fileId: string
    linkCount: number
    classification: 'tracked_in_git_index' | 'nonignored_in_root'
  }>
  observedAt: string
  evidenceDigest: string
}

type SourceIncludeAuthorizationV1 = {
  schemaVersion: 1
  format: 'cliq-source-include-authorization-v1'
  principalId: string
  runId: string
  sessionId: string
  workspaceIdentityRef: ArtifactRef
  workspaceIdentityDigest: string
  selector: { path: string; scope: 'entry' | 'subtree' }
  selectorDigest: string
  admissionIntentDigest: string
  createdAt: string
  authorizationDigest: string
} & (
  | {
      kind: 'builtin_nonignored'
      frozenIgnoreRulesRef: ArtifactRef
      frozenIgnoreRulesDigest: string
      classification: 'tracked_or_nonignored_in_root'
      classificationEvidenceRef: ArtifactRef
      classificationEvidenceDigest: string
    }
  | {
      kind: 'consumed_user_read_grant'
      authorizationGrantId: string
      authorizationGrantTargetDigest: string
      consumptionReceiptRef: ArtifactRef
      consumptionReceiptDigest: string
    }
)

type SourceProjectionSpec = {
  schemaVersion: 1
  matcherVersion: 'cliq-exact-path-v1'
  frozenIgnoreRulesRef: ArtifactRef
  frozenIgnoreRulesDigest: string
  explicitIncludes: Array<{
    path: string
    scope: 'entry' | 'subtree'
    authorizationRef: ArtifactRef
  }>
  explicitExcludes: Array<{
    path: string
    scope: 'entry' | 'subtree'
  }>
  maxChangedPaths: number
  maxChangedBytes: number
  projectionDigest: string
}
```

`SourceProjectionSpec.projectionDigest = SHA-256(JCS(spec with projectionDigest omitted))`; every SourceManifest `sourceProjectionRef` decodes that exact artifact and `sourceProjectionDigest` equals its member, while every WorkspaceStateManifest copies the same value. `frozenIgnoreRulesRef` decodes only to `FrozenIgnoreRulesV1`; `rulesDigest = SHA-256(JCS(manifest with rulesDigest omitted))`. A Git manifest's optional repository digest is required/equal to the live identity; non-Git forbids it and uses the canonical empty sources/rules arrays. Sources are descriptor-held regular files: `.git/info/exclude` first when present, then every admitted `.gitignore` ordered by `(directoryDepth,canonicalRootRelativePath)` from root to deep; indices are contiguous. Content refs/digests rehash exact UTF-8 bytes. Trusted parsing implements the fixed `cliq-git-wildmatch-v1` profile (Git 2.45 `gitignore` pattern semantics with `/` separators and case-sensitive matching), rejects invalid UTF-8/NUL, and emits contiguous rules in source/line order with normalized base directory, negation, directory-only, anchoring, and pattern fields. For one path, only ancestor-base rules apply and the last matching rule wins; later/deeper sources therefore override earlier sources. SourceManifest and SourceProjection frozen-ignore ref/digest pairs must be identical. Recovery/result construction uses only this parsed artifact, never mutable Git config/files or an ambient Git version.

Every include's `authorizationRef` decodes only to `SourceIncludeAuthorizationV1`; `selectorDigest = SHA-256(JCS(selector))` and `authorizationDigest = SHA-256(JCS(authorization with authorizationDigest omitted))`. Principal/Run/Session/live workspace ref+digest, selector bytes, and admission-intent digest equal the admitted request/projection. For an ordinary tracked/non-ignored in-root selector, the Supervisor first publishes exact `SourceIncludeClassificationEvidenceV1`, then publishes `builtin_nonignored` with the identical evidence ref/digest and frozen-ignore pair. `evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`; its entries are nonempty, unique, byte-sorted paths and exactly cover the descriptor-walked entries selected for capture. Each `workspaceEntryDigest` equals `SHA-256(JCS(the exact captured WorkspaceEntry))`, the later SourceManifest entry set contains the same entries, and device/file/link-count observations come from the same no-follow descriptors. `tracked_in_git_index` is legal only when both Git-index fields are present, the ref equals the later SourceManifest Git index, and fixed canonical Git-index parsing proves that path tracked; any such entry requires the fields. `nonignored_in_root` re-evaluates under the exact frozen rules and requires a non-ignored result. If no entry is tracked, Git-index fields may be absent; if either Git-index field is present both are required. An ignored in-root selector requires `consumed_user_read_grant`: the supplied `readGrantId` resolves an active principal/workspace/path/scope-exact `AuthorizationGrantV1(read_scope)`, and the admission transaction consumes it once. The artifact's target and receipt digests must match; `AuthorizationConsumptionReceiptV1.consumer` is exactly `{kind:'run_admission',runId,admissionIntentDigest}`. The receipt never names the final admitted digest. Grant consumption, final admitted-digest computation, Run/Checkpoint/projection/control response, and receipt/ref installation commit atomically. A missing optional wire grant selects only the builtin branch and therefore cannot include ignored bytes; an unnecessary/mismatched grant is rejected rather than ignored. Outside-root/external selectors are rejected. A repository can request a selector but cannot manufacture either authorization form or reuse one across a Run/workspace/selector.

Normalization defaults to 10,000 changed paths and 512 MiB of changed/new file content; accepted maxima are 100,000 paths and 4 GiB. Exceeding either fails result construction with `runtime_failed` detail rather than truncating the result.

- every admitted tracked and ordinary non-ignored untracked path, including modification, deletion, executable-bit change, binary bytes, and safe in-root symlink-target change;
- every newly created ordinary file or safe in-root symlink under the admitted root that is not ignored by the **frozen admission-time** Git ignore rules;
- no cache/dependency/verifier-output path merely because it appeared in recovery state.

`cliq-exact-path-v1` has no glob, regex, brace, negation, or platform separator syntax. `path` is non-empty UTF-8 NFC with `/` separators, no leading/trailing slash, empty component, `.`, `..`, NUL, or backslash. `entry` matches that exact captured directory-entry spelling; `subtree` matches it plus descendants at `/` component boundaries. Matching is byte-exact against the manifest's canonical UTF-8 path, symlinks match only the link entry and are never followed, and normalization/case collisions are rejected. Excludes win on identical coverage.

CLI/API input or trusted `.cliq/config` may request root-relative selectors after Workspace Trust, but repository config is declarative only. Every ignored include remains inert until an explicit user-level read-scope policy or durable admission grant binds that exact workspace/selector; an external selector is unsupported. Noninteractive admission needs an API/CLI authorization or pre-existing user policy. Workspace Trust alone never authorizes capture into CAS/model/workspace/result. Known Cliq/provider credential stores remain hard-excluded. Cliq does not pretend filename heuristics can identify every secret inside user-authorized source bytes; the consent UI states that authorized bytes enter durable artifacts and may reach the model. The model cannot change selectors. A rename is represented deterministically as delete plus add. Unsafe symlinks, special files, case collisions, and result byte/count ceilings fail result construction instead of being silently omitted.

### 10.6 Trusted Model And Effect Broker

The sandbox worker receives a sanitized allowlisted environment. It does not receive provider API keys or the Supervisor's full `process.env`.

Provider calls, remote MCP calls, secret-bearing integrations, and final publication/materialization execute through a trusted broker. Each request is bound to:

- `runId`;
- `opId` and attempt;
- current `leaseEpoch`;
- capability grant;
- target and expiry.

The broker verifies the Run's exact activated launch pointer, launch epoch/identity, unexpired lease, and the invocation's claimed `dispatchId` immediately before dispatch. Network access from an arbitrary shell is denied by default. Explicit network access uses a sandbox-enforced egress boundary and remains journaled according to its recovery class.

## 11. Typed Agent Runtime

JSON remains appropriate for configuration, SQLite payload encoding, JSONL/RPC, JSON Schema tool arguments, and artifacts. It is removed only as a free-text model control envelope.

### 11.1 Internal Agent IR

The provider-neutral runtime consumes typed events for:

- text/reasoning deltas;
- tool-call start, argument delta, and completion;
- validated tool input;
- tool result and error;
- provider usage, retry, and failure;
- approval, child, waiting, checkpoint, and verification events.

Provider-native tool calls are the sole autonomous model protocol. There is no constrained-action envelope in Kernel Cut. Valid models without native capability are text-only; malformed or unverified evidence cannot authorize admission. OpenAI Responses and Pi-style typed continuation guide a small core: native conversion only at the provider boundary, one typed in-process result, no parsing of assistant text as control.

The core runner does not parse, repair, or extract a `ModelAction` from arbitrary assistant text.

Canonical completed-turn and in-process stream contracts:

```ts
type AgentNegotiatedMode = 'native-tools' | 'text-only';

type AgentToolCall = {
  callId: string;
  toolName: string;
  inputRef: ArtifactRef;
  inputDigest: string;
  index: number;
};

type AgentUsage = {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costMicros: number;
};

type AgentModelStreamEvent =
  | { type: 'start'; provider: RunAssemblyV1['provider']['name']; model: string; streaming: boolean }
  | { type: 'text_delta'; text: string }
  | { type: 'reasoning_delta'; text: string }
  | { type: 'tool_call_start'; index: number; wireCallId?: string; toolName?: string }
  | { type: 'tool_call_arguments_delta'; index: number; utf8: string }
  | { type: 'tool_call_complete'; index: number; wireCallId?: string; toolName?: string }
  | {
      type: 'usage';
      inputTokens: number;
      outputTokens: number;
      cacheReadTokens: number;
      cacheWriteTokens: number;
    }
  | { type: 'retry'; attempt: number; delayMs: 500 | 2000 }
  | { type: 'error'; code: string }
  | { type: 'end'; stopReason: 'end' | 'tool_calls' | 'length' | 'content_filter' | 'cancelled' | 'unknown' };

type AgentModelTurnBase = {
  continuation?: ProviderContinuation;
  schemaVersion: 1;
  format: 'cliq-agent-model-turn-v1';
  provider: RunAssemblyV1['provider']['name'];
  model: string;
  responseId?: string;
  usage?: AgentUsage;
  usageTrusted: false;
  negotiatedMode: AgentNegotiatedMode;
  promptProjectionRef: ArtifactRef;
  promptProjectionDigest: string;
  requestDigest: string;
  responseDigest: string;
};

type AgentModelTurn = AgentModelTurnBase & (
  | {
      stopReason: 'end';
      textRef: ArtifactRef;
      toolCalls: [];
      abortStopIntentRef?: never;
    }
  | {
      stopReason: 'tool_calls';
      textRef: ArtifactRef;
      toolCalls: [AgentToolCall, ...AgentToolCall[]];
      abortStopIntentRef?: never;
    }
  | {
      stopReason: 'cancelled';
      textRef: ArtifactRef;
      toolCalls: [];
      abortStopIntentRef: ArtifactRef;
    }
);

type ToolInvocation<TInput extends Record<string, unknown> = Record<string, unknown>> = {
  callId: string;
  index: number;
  toolName: string;
  input: TInput;
  replayClass: ReplayClass;
};
```

`continuation` contains only bounded provider-owned reasoning/signature blocks,
with the same provider/model as the turn. Storage and prompt reconstruction
preserve it; runtime never interprets it as tool authority. An event is
non-authoritative until the complete response passes central compilation.

### 11.2 Capability Negotiation

The Kernel Cut supports the current provider set through capability adapters:

- OpenAI
- Anthropic
- OpenRouter
- OpenAI-compatible
- Zhipu
- Ollama

Support for a provider name does not imply autonomous tool support. Each resolved model declares its negotiated capability. Misreported or absent capability fails closed to text-only mode.

### 11.3 Tool Calls And Parallelism

All tool calls returned by one model response are validated and processed in order. The runner does not silently discard calls after index zero. Once the typed assistant batch is committed, Run state advances to `nextStep='tool'`; each call result and the next index advance atomically, and only a complete batch advances back to `nextStep='agent'`.

In-response tool execution remains sequential to keep effect ordering deterministic. Parallelism is expressed through bounded child Runs, not concurrent mutation of one workspace.

Terminal truth cannot skip a typed frontier. Every call has exactly one identity-matched closure before terminal commit: ordinarily `ToolResultItem`, or only for terminal manual abandonment the non-result `ToolAbandonedItem`. A non-empty model turn with no calls becomes an agent final candidate only for positively normalized `stopReason='end'`, after the quiescent projected `resultSourceRef` and summary are durable; truncated, filtered, cancelled, unknown, or empty stops are not final candidates. Delivery creates an equivalent final-candidate item from its immutable merged artifacts. `commitRunResult` validates that the latest operation-appropriate candidate is current and has the exact same `resultSourceRef` as RunResult.

Cancellation, deadline, or failure atomically appends `cancelled` results for undispatched remaining calls before terminal stop. A dispatched/ambiguous current call first reaches its ReplayClass-specific terminal-quiescence condition; unresolved `reconcile|manual` effects block terminalization.

### 11.4 Durable Run-Context Compaction

Long horizon cannot depend on an ever-growing prompt or implicit provider truncation. The assembly freezes `C/O/H/T/R/S/K/P` under the estimate policy above and the exact `CompactionPromptEnvelopeV1`. Each of its three `ModelTextV1` members is valid NFC/no-NUL UTF-8, rehashes, and the combined fixed text is at most 256 KiB. The logical source placeholder cannot occur in fixed text and is not emitted. `K` estimates exactly system content and user prefix + empty source + suffix, plus two-message overhead; plan/source data do not participate in the envelope digest. A compaction response requests actual provider output cap `S` and accepts only complete nonempty Markdown of at most `min(262144,3*S)` UTF-8 bytes, whose text estimate is therefore at most `S`. Context estimates are not signed billing bounds or proof of provider context acceptance.

Before normal dispatch, trusted code estimates the next prompt. If `N<=T`, dispatch normally. Otherwise protect fixed admitted Session/parent context, instructions/skills/tools and every live frontier/wait/StopIntent/invocation/child/candidate/verifier reference. Protect newest whole segments until their model-visible content estimates total at least `R`, extending backward for other live references. Candidates are contiguous sequence-one prefixes ending at closed segment boundaries before the protected suffix. Their source is the current model-visible projection, including existing summaries but excluding control payloads. A legal source has estimated content `<=P` and `>=S+512`; choose the greatest `throughItemSeq`. Summary replacement reduces estimated source content by at least 512 units; admission of the replacement must also verify that the complete next-prompt estimate decreases (including message overhead). If `N>T` and no legal range exists, make no call and propose `runtime_failed(context_window_exhausted)` with exact manifest/estimate evidence. Never truncate, split an item, loosen protection or loop on the same summary.

For the chosen range, publish immutable `RunContextCompactionPlan`, set `phase='context_compaction'`, and use an ordinary tools-disabled Journaled model attempt with frozen retry/budget policy. Plan envelope pair, `C/O/T/R/S/K/P` and byte limit equal assembly; `promptOverheadTokens=K`; source range/digest/estimate equal the chosen projection. `RunContextCompactionItem.summaryRef` must be that highest/current completed turn's `AgentModelTurn.textRef`, decoding bounded NFC/no-NUL `ModelTextV1`; both item and replacement segment repeat its `textDigest`. A text-only provider may compact because the response is content, not a control envelope. Tool-bearing, non-end, malformed or oversized responses cannot become a summary. Raw items remain durable.

On success one transaction appends `RunContextCompactionItem`, publishes a context manifest that replaces exactly the covered prefix with the bounded summary while retaining the source range/digest and explicit preserved refs, restores the same normal-model agent frontier, and publishes a ready Checkpoint reusing the unchanged workspace-state artifact. The summary is model-visible; compaction control/evidence is not. Crash sees either the old manifest/frontier or the complete new manifest/item/Checkpoint. Pre-dispatch/transport `failed|unknown` attempts follow the frozen model retry policy. An executed tool-bearing, malformed, non-end, or oversize response is Journal `completed` with an unusable-response artifact and immediately proposes `runtime_failed(context_compaction_failed)`—a completed attempt is never retried. Budget exhaustion proposes the exact budget StopIntent. Cliq never silently drops tokens or asks an implementation to invent a pruning heuristic.

### 11.5 Closed Frontier Reducers

The Kernel Cut has no provider- or UI-specific continuation state. These are the only productive reducers:

| Current frontier | Required durable input | Atomic next frontier |
|---|---|---|
| `agent:context_compaction` | one highest/current completed tools-disabled compaction model attempt | `agent:model_turn` plus `RunContextCompactionItem`, new context manifest, and ready Checkpoint; never tool/final interpretation |
| `agent:model_turn` | one highest/current completed normalized model attempt | `tool` with a whole all-resolved `ToolBatchItem`; or, when identities are valid but any name/input is rejected, append the whole batch plus every deterministic invalid/error and `batch_not_executed` result and return directly to `agent` in one transaction; or child finalize settlement; or `verify` with a `FinalCandidateItem` only for nonempty positive `end`; otherwise terminal runtime/cancel policy |
| `tool` | one result/denial/input/child-merge result for `orderedCallIds[nextCallIndex]` | next index in `tool`, or `agent` after every call has exactly one result |
| `verify:dependencies` | completed exact `DependencyReadyItem` plus post-effect Checkpoint, or an already matching ready Checkpoint | `verify:verifiers` at index zero; no verifier launch before readiness |
| `verify:verifiers` | one matching verifier receipt/skip and its Journal evidence | same frontier/index or retry; `agent` for a counted assertion repair on agent Runs only; publish one closure and install `finalize` when `afterPass='finalize'`, or the proof-carrying `delivery:approval` frontier when `afterPass='delivery_approval'`; otherwise exact failure/cancel path |
| `finalize` | candidate + Journal-backed verification/provenance closure | `commitRunResult` and terminal state |
| `delivery:merge` | admission-owned immutable current-workspace capture plus merged candidate/diff/plan or conflict | shared `verify` frontier with `afterPass='delivery_approval'`, proof-carrying `delivery:approval` when identical provenance is valid, direct verified no-op projection/finalize when the plan is empty, or `runtime_failed(delivery_merge_conflict)` StopIntent/detail |
| `delivery:approval` | typed allow decision over the carried candidate/plan/closure | `delivery:publish` at path index zero preserving those refs; denial cancels |
| `delivery:publish` | one path receipt/reconciliation result for the exact index | next index preserving candidate/plan/closure, or publish forward projection evidence and install `finalize(operation='delivery')` with the same closure after all paths close |

`FinalCandidateItem` binds operation, originating model/delivery item, base/result source refs, diff, summary, and content digests. `VerifierPlan` binds that candidate, the frozen ordered unique verifier entries, required/advisory flags, exact retry ceilings, and environment. `DeliveryPlan` binds source B/S, captured A, merged desired M, the A-to-M diff, `cliq-diff3-v1`, and the complete ordered parent-directory/leaf operations with pre/post digests. `InputRequestItem`, `ToolBatchItem`, `ToolResultItem`, `ChildHandleItem`, `ChildResultItem`, `ChildMergeBatchItem`, verifier receipt items, and publication path result items have stable ids and identity references; the store rejects duplicates, skips, or cross-Run refs.

Every row of this table is implemented by a narrow typed state-service method. There is no caller-selected generic Run compare-and-swap or patch API, including for “non-frontier metadata”; each allowed metadata change has its own input type, preconditions, and field set. A private repository helper may perform the final SQL revision predicate only after a typed reducer has constructed and validated the complete mutation. This is how recovery knows exactly what to do after any committed boundary without reconstructing a workflow engine.

### 11.6 Normative Durable Artifact And Item Shapes

All named item/artifact objects use RFC 8785/JCS, reject unknown fields, carry `schemaVersion: 1`, use safe integers, and are content-addressed after their own digest field (when present) is omitted. Every `itemId` is unique within its owning Run, every referenced item is owned by that Run, and every ordered index is contiguous from zero.

For ordinary tools, `ToolRequestV1` binds the exact resolved `ToolCallInputV1`,
current tool frontier, assembly, batch/call/index and `ToolTargetV1`.
`opId = H('cliq-tool-operation-v1', runId, batchItemId, callId)` is stable across
attempts; attempts and physical generation/lease ownership belong to Journal
claims, not a mutable request. The target pins the logical admitted workspace
and **complete** frozen tool-manifest entry; its `toolContractDigest` hashes
that entry, not the separate MCP `execution.toolContractDigest`.
MCP alone requires
`idempotencyKey = H('cliq-mcp-tool-idempotency-v1', runId, opId, registryRevisionRef, serverToolName)`;
builtins forbid the field. The key is not evidence of server deduplication or
retry safety. Plan channels use an explicit normalized input `planId`, otherwise
`H('cliq-run-plan-v1', runId)`; they never consult a mutable Session plan pointer.
Request, target and observation semantic digests omit only their own named
digest field. Their ArtifactRefs always hash the **complete** retained JCS bytes.

The fixed Bash v1 golden grammar recognizes ASCII space/tab separation,
single/double quotes and escapes, simple command lists/pipelines/comments,
literal environment assignments and unflagged `env|command|exec|builtin|nohup|sudo`
wrappers (plus `--`), and shell `-c`/`--command` literal bodies through depth 8.
Command, backtick and process substitutions retain recognized nested deny
occurrences but never yield an outer allow-rule key. Repeated occurrences are
ordered by lexical position tuples, not deduplicated by head text, with a maximum
of 64 retained nested denies. Dynamic/unsupported wrapper options, delegation,
script interpreters, redirection, malformed syntax and over-depth bodies are
unsafe and have no trusted outer head. This is a bounded policy grammar, not a
claim to interpret every shell construct; unsupported syntax never selects a
host/legacy parser. Known literal deny occurrences survive loss of an outer head.

`ToolObservationV1` is retained post-dispatch evidence, never permission to
execute. It repeats the exact request, target, grant, attempt and permanent
dispatch id, with `claim.timestamp <= observedAt <= completion.timestamp`.
A successful `content` is a bounded JSON value of at most 1 MiB of JCS and must
satisfy the frozen output schema when present. Invalid output becomes a
`TOOL_PROTOCOL_ERROR` observation whose private diagnostic retains the original
observation ref; the ordinary model content contains only that error code.
An adapter error retains a canonical diagnostic whose `diagnosticDigest`
hashes the complete diagnostic bytes. Both executed and error-valued observations
close Journal as `completed` with `resultRef`, consume one reserved tool call,
and publish one ordered ToolResult. An error payload's `journalErrorRef` names
that completed error-valued observation, not a fabricated no-release/failed
attempt; only positively proven no-release follows the separate refund protocol.

For every non-read contract, `postEffect` is mandatory even on an error;
read-only contracts forbid it and preserve the preceding workspace state.
`checkpointId = H('cliq-tool-checkpoint-v1', runId, opId, String(attempt))` binds
the positive sealed snapshot to this exact observation. Its workspace, tree,
generation and retirement closure must agree with the quiesced owning launch;
the inspector binds the trusted signed Supervisor entry and current StateOwner
process/lock identities, not just an arbitrary matching instance-id string.
Journal completion, full tool charge, ordered result, context/frontier,
post-effect Checkpoint, generation seal and worker retirement commit together.
Recovery retains this closure through the observation after generation retirement
and checks the matching historical Checkpoint, so later checkpoints cannot hide
a pre-effect workspace substitution. The State consumer does not itself perform
tool I/O or OS inspection; the trusted WP03 producer and immediately-before-I/O
gate remain independently required.

```ts
type ModelTextV1 = {
  schemaVersion: 1
  format: 'cliq-model-text-v1'
  utf8: string
  byteCount: number
  textDigest: string
}

type ModelUnusableResponseV1 = {
  schemaVersion: 1
  format: 'cliq-model-unusable-response-v1'
  runId: string
  opId: string
  attempt: number
  request:
    | { kind: 'normal'; requestRef: ArtifactRef; requestDigest: string }
    | { kind: 'context_compaction'; requestRef: ArtifactRef; requestDigest: string }
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu' | 'ollama'
  model: string
  negotiatedMode: 'native-tools' | 'text-only'
  failureCode:
    | 'malformed_transport_payload'
    | 'response_too_large'
    | 'invalid_stop_call_shape'
    | 'stop_reason_length'
    | 'stop_reason_content_filter'
    | 'stop_reason_unknown'
    | 'missing_or_duplicate_call_id'
    | 'tool_calls_forbidden_by_mode'
    | 'context_compaction_requires_end_markdown'
    | 'capability_shape_mismatch'
    | 'provider_rejected_response'
  observedResponse:
    | {
        kind: 'complete'
        mediaType: 'application/json' | 'text/event-stream' | 'application/x-ndjson' | 'unknown'
        bytesRef: ArtifactRef
        bytesDigest: string
        byteCount: number
      }
    | {
        kind: 'prefix_over_limit'
        mediaType: 'application/json' | 'text/event-stream' | 'application/x-ndjson' | 'unknown'
        bytesRef: ArtifactRef
        bytesDigest: string
        byteCount: number
        responseLimitBytes: number
      }
  observedAt: string
  unusableDigest: string
}

type ObservedToolCallInputV1 = {
  schemaVersion: 1
  format: 'cliq-observed-tool-call-input-v1'
  byteCount: number
  observedInputDigest: string
} & (
  | { encoding: 'jcs_json'; value: unknown; utf8?: never }
  | { encoding: 'utf8_json_fragment'; utf8: string; value?: never }
)

type ToolCallInputBaseV1 = {
  schemaVersion: 1
  format: 'cliq-tool-call-input-v1'
  callId: string
  index: number
  toolName: string
  observedInputRef: ArtifactRef
  observedInputDigest: string
  inputDigest: string
}

type ToolCallInputV1 = ToolCallInputBaseV1 & (
  | {
      disposition: 'resolved'
      inputSchemaRef: ArtifactRef
      inputSchemaDigest: string
      value: Record<string, unknown>
      diagnosticRef?: never
      diagnosticDigest?: never
    }
  | {
      disposition: 'rejected_unknown_tool'
      inputSchemaRef?: never
      inputSchemaDigest?: never
      value?: never
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
    }
  | {
      disposition: 'rejected_invalid_input'
      inputSchemaRef: ArtifactRef
      inputSchemaDigest: string
      value?: never
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
    }
)

type ToolRequestV1 = {
  schemaVersion: 1
  format: 'cliq-tool-request-v1'
  runId: string
  opId: string
  frontierRef: ArtifactRef
  assemblyRef: ArtifactRef
  batchItemId: string
  callId: string
  callIndex: number
  toolName: string
  inputRef: ArtifactRef
  inputDigest: string
  targetRef: ArtifactRef
  targetDigest: string
  idempotencyKey?: string
  requestDigest: string
}

type ToolTargetV1 = {
  schemaVersion: 1
  format: 'cliq-tool-target-v1'
  runId: string
  workspaceIdentityRef: ArtifactRef
  workspaceIdentityDigest: string
  toolManifestRef: ArtifactRef
  toolManifestDigest: string
  toolName: string
  toolContractDigest: string
  execution: ToolContractManifestV1['entries'][number]['execution']
  targetDigest: string
}

type ToolObservationV1 = {
  schemaVersion: 1
  format: 'cliq-tool-observation-v1'
  runId: string
  opId: string
  attempt: number
  requestRef: ArtifactRef
  targetRef: ArtifactRef
  grantRef: ArtifactRef
  dispatchId: string
  observedAt: string
  observationDigest: string
  postEffect?: {
    workspaceStateRef: ArtifactRef
    snapshotEvidenceRef: ArtifactRef
    retirementEvidenceRef: ArtifactRef
  }
} & (
  | { outcome: 'executed'; content: unknown }
  | {
      outcome: 'error'
      code: 'TOOL_EXECUTION_FAILED' | 'TOOL_PROTOCOL_ERROR' | 'TOOL_RESOURCE_EXHAUSTED'
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
    }
)

type ModelTurnItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'model_turn'
  modelOpId: string
  modelAttempt: number
  modelTurnRef: ArtifactRef
  stopReason: 'end' | 'tool_calls' | 'cancelled'
  textRef: ArtifactRef
  abortStopIntentRef?: ArtifactRef
  createdAt: string
}

type CompactionPromptEnvelopeV1 = {
  schemaVersion: 1
  format: 'cliq-compaction-prompt-envelope-v1'
  systemInstructionRef: ArtifactRef
  systemInstructionDigest: string
  userPrefixRef: ArtifactRef
  userPrefixDigest: string
  sourcePlaceholder: '{{CLIQ_SOURCE_CONTEXT_UTF8}}'
  userSuffixRef: ArtifactRef
  userSuffixDigest: string
  resultContract: {
    toolsAllowed: false
    requiredStopReason: 'end'
    mediaType: 'text/markdown; charset=utf-8'
    summaryFormat: 'cliq-context-summary-markdown-v1'
  }
  envelopeDigest: string
}

type RunContextCompactionPlan = {
  schemaVersion: 1
  runId: string
  sourceContextManifestRef: ArtifactRef
  compactFromItemSeq: number
  compactThroughItemSeq: number
  preservedItemIds: string[]
  sourceItemsDigest: string
  summaryFormat: 'cliq-context-summary-markdown-v1'
  maxSummaryBytes: number
  contextLimitTokens: number
  reservedNormalOutputTokens: number
  triggerThresholdTokens: number
  protectedRecentTokens: number
  summaryTokenCap: number
  promptEnvelopeRef: ArtifactRef
  promptEnvelopeDigest: string
  promptOverheadTokens: number
  sourceInputTokenCap: number
  sourceProjectedTokens: number
  createdAt: string
}

type RunContextCompactionItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'context_compaction'
  planRef: ArtifactRef
  modelOpId: string
  modelAttempt: number
  summaryRef: ArtifactRef
  summaryDigest: string
  coveredFromItemSeq: number
  coveredThroughItemSeq: number
  sourceItemsDigest: string
  createdAt: string
}

type DeliveryMergeItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'delivery_merge'
  sourceRunResultRef: ArtifactRef
  sourceBaseRef: ArtifactRef
  sourceDesiredRef: ArtifactRef
  capturedWorkspaceRef: ArtifactRef
  resultSourceRef: ArtifactRef
  diffRef: ArtifactRef
  summaryRef: ArtifactRef
  deliveryPlanRef: ArtifactRef
  createdAt: string
}

type DeliveryMergeConflictItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'delivery_merge_conflict'
  sourceRunResultRef: ArtifactRef
  sourceBaseRef: ArtifactRef
  sourceDesiredRef: ArtifactRef
  capturedWorkspaceRef: ArtifactRef
  mergeAlgorithm: 'cliq-diff3-v1'
  conflictRef: ArtifactRef
  createdAt: string
}

type ToolCallRecord = {
  callId: string
  index: number
  toolName: string
  inputRef: ArtifactRef
  inputDigest: string
}

type ToolBatchItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'assistant_tool_batch'
  modelOpId: string
  modelAttempt: number
  modelTurnRef: ArtifactRef
  textRef: ArtifactRef
  calls: ToolCallRecord[]
  createdAt: string
}

type ToolResultItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'tool_result'
  batchItemId: string
  callId: string
  index: number
  opId?: string
  outcome: 'executed' | 'denied' | 'error' | 'batch_not_executed' | 'cancelled'
  resultRef: ArtifactRef
  createdAt: string
}

type ToolResultPayloadBaseV1 = {
  schemaVersion: 1
  format: 'cliq-tool-result-payload-v1'
  runId: string
  batchItemId: string
  callId: string
  index: number
  toolName: string
  modelContentRef: ArtifactRef
  modelContentDigest: string
  payloadDigest: string
}

type ToolResultModelContentV1 = {
  schemaVersion: 1
  format: 'cliq-tool-result-model-content-v1'
  callId: string
  index: number
  toolName: string
  outcome: 'executed' | 'denied' | 'error' | 'batch_not_executed' | 'cancelled'
  content: unknown
  contentDigest: string
}

type ToolResultPayloadV1 = ToolResultPayloadBaseV1 & (
  | {
      outcome: 'executed'
      source: 'invocation'
      opId: string
      attempt: number
      journalResultRef: ArtifactRef
      journalResultDigest: string
      outputSchemaRef?: ArtifactRef
      outputSchemaDigest?: string
    }
  | {
      outcome: 'executed'
      source: 'user_input'
      inputItemRef: ArtifactRef
      inputRef: ArtifactRef
      inputDigest: string
    }
  | {
      outcome: 'denied'
      denial:
        | { source: 'policy'; policyRef: ArtifactRef; decisionDigest: string }
        | { source: 'user'; approvalDecisionRef: ArtifactRef; approvalDecisionDigest: string }
      code: 'TOOL_CALL_DENIED'
    }
  | {
      outcome: 'error'
      code:
        | 'TOOL_NOT_FOUND'
        | 'TOOL_INPUT_INVALID'
        | 'TOOL_AUTHORITY_UNAVAILABLE'
        | 'TOOL_EXECUTION_FAILED'
        | 'TOOL_PROTOCOL_ERROR'
        | 'TOOL_RESOURCE_EXHAUSTED'
      diagnosticRef: ArtifactRef
      diagnosticDigest: string
      opId?: string
      attempt?: number
      journalErrorRef?: ArtifactRef
      journalErrorDigest?: string
    }
  | {
      outcome: 'batch_not_executed'
      code: 'BATCH_REJECTED_BEFORE_DISPATCH'
      invalidCallIds: string[]
    }
  | {
      outcome: 'cancelled'
      cancellationKind: 'undispatched_stop' | 'await_children_stop'
      stopIntentRef: ArtifactRef
      noticeRef: ArtifactRef
      noticeDigest: string
    }
)

type ManualAbandonAttestationV1 = {
  schemaVersion: 1
  format: 'cliq-manual-abandon-attestation-v1'
  principalId: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  requestId: string
  requestDigest: string
  runId: string
  waitingSubjectRef: ArtifactRef
  frontierRef: ArtifactRef
  opId: string
  attempt: number
  unknownJournalSeq: number
  operationRequestRef: ArtifactRef
  operationRequestDigest: string
  targetRef: ArtifactRef
  targetDigest: string
  ambiguityEvidenceRef: ArtifactRef
  ambiguityEvidenceDigest: string
  acknowledgedRisk: 'effect_may_have_occurred_result_will_not_be_used_and_run_will_stop'
  createdAt: string
  attestationDigest: string
}

type ToolAbandonedItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'tool_abandoned'
  batchItemId: string
  callId: string
  index: number
  opId: string
  attempt: number
  abandonedJournalSeq: number
  attestationRef: ArtifactRef
  createdAt: string
}

type BudgetSettlementV1 = {
  schemaVersion: 1
  format: 'cliq-budget-settlement-v1'
  runId: string
  opId: string
  attempt: number
  preparedJournalSeq: number
  terminalJournalSeq: number
  terminalPhase: 'completed' | 'failed' | 'unknown'
  reserved: BudgetUsage
  consumed: BudgetUsage
  released: BudgetUsage
  budgetConsumedBefore: BudgetUsage
  budgetConsumedAfter: BudgetUsage
  budgetReservedBefore: BudgetUsage
  budgetReservedAfter: BudgetUsage
  settledAt: string
  settlementDigest: string
}

type InvocationAmbiguityEvidenceBaseV1 = {
  schemaVersion: 1
  format: 'cliq-invocation-ambiguity-evidence-v1'
  runId: string
  frontierRef: ArtifactRef
  frontierDigest: string
  opId: string
  opKind: InvocationJournalEntry['opKind']
  attempt: number
  dispatchId: string
  dispatchJournalSeq: number
  operationRequestRef: ArtifactRef
  operationRequestDigest: string
  operationTargetRef: ArtifactRef
  operationTargetDigest: string
  claimingSupervisorInstanceId: string
  claimingStateOwnerEpoch: number
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  evidenceDigest: string
}

type InvocationAmbiguityEvidenceV1 = InvocationAmbiguityEvidenceBaseV1 & (
  | {
      ambiguityKind: 'claim_owner_lost'
      ownerTakeoverEvidenceRef: ArtifactRef
      ownerTakeoverEvidenceDigest: string
    }
  | {
      ambiguityKind: 'broker_channel_lost_after_claim'
      opKind: 'model' | 'tool' | 'mcp'
      brokerFenceTokenDigest: string
      failureCode: 'deadline_after_release_possible' | 'connection_lost_after_release_possible' | 'response_stream_interrupted'
      durableTerminalResultAbsent: true
    }
  | {
      ambiguityKind: 'sandbox_channel_lost_after_claim'
      opKind: 'tool' | 'mcp-server' | 'mcp' | 'verifier'
      sandboxLaunchSpecRef: ArtifactRef
      sandboxLaunchSpecDigest: string
      processContainmentRef: ArtifactRef
      processContainmentDigest: string
      observation:
        | {
            kind: 'live_unresponsive'
            responseDeadlineAt: string
            authenticatedOperationChannelClosedAt: string
          }
        | {
            kind: 'died_without_terminal_result'
            containmentDeathEvidenceRef: ArtifactRef
            containmentDeathEvidenceDigest: string
          }
    }
  | {
      ambiguityKind: 'publication_path_ambiguous'
      opKind: 'publish'
      publicationProofRef: ArtifactRef
      publicationProofDigest: string
    }
)

type PostClaimNoReleaseEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-post-claim-no-release-evidence-v1'
  runId: string
  opId: string
  attempt: number
  dispatchId: string
  dispatchJournalSeq: number
  operationRequestRef: ArtifactRef
  operationRequestDigest: string
  operationTargetRef: ArtifactRef
  operationTargetDigest: string
  operationGrantRef?: ArtifactRef
  claimingSupervisorInstanceId: string
  claimingStateOwnerEpoch: number
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
  closure:
    | {
        kind: 'broker_release_never_started'
        brokerFenceTokenDigest: string
        fenceAction: 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero'
        sandboxLaunchSpecRef?: never
        noSpawnEvidenceRef?: never
        noSpawnEvidenceDigest?: never
      }
    | {
        kind: 'process_spawn_never_started'
        sandboxLaunchSpecRef: ArtifactRef
        noSpawnEvidenceRef: ArtifactRef
        noSpawnEvidenceDigest: string
        brokerFenceTokenDigest?: never
        fenceAction?: never
      }
  evidenceDigest: string
}

type BrokerReleaseFenceEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-broker-release-fence-evidence-v1'
  runId: string
  opId: string
  attempt: number
  dispatchId: string
  dispatchJournalSeq: number
  operationRequestRef: ArtifactRef
  operationTargetDigest: string
  operationGrantRef: ArtifactRef
  claimingSupervisorInstanceId: string
  claimingStateOwnerEpoch: number
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  inspectorStateOwnerEpoch: number
  brokerFenceTokenDigest: string
  fenceAction: 'token_revoked_and_matching_active_release_count_zero'
  tokenRevokedAt: string
  noActiveReleaseObservedAt: string
  evidenceDigest: string
}

type InvocationDispatchClosureEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-invocation-dispatch-closure-evidence-v1'
  runId: string
  opId: string
  attempt: number
  dispatchId: string
  unknownJournalSeq: number
  closure:
    | {
        kind: 'containment_death'
        processContainmentRef: ArtifactRef
        processContainmentDigest: string
        deathEvidenceRef: ArtifactRef
        deathEvidenceDigest: string
      }
    | {
        kind: 'broker_release_fenced'
        brokerFenceEvidenceRef: ArtifactRef
        brokerFenceEvidenceDigest: string
      }
  observedAt: string
  evidenceDigest: string
}

type RetryUnknownCancelledResult = {
  schemaVersion: 1
  kind: 'retry_unknown_cancelled'
  opId: string
  attempt: number
  unknownJournalSeq: number
  budgetSettlementRef: ArtifactRef
  dispatchFenceOrDeathEvidenceRef: ArtifactRef
  message: 'Run stopped without using the ambiguous result'
}

type PolicyDenialOutcomeV1 =
  | {
      kind: 'tool_result_denied'
      subjectKind: 'tool_call' | 'mcp_server_launch'
      outcomeItemRef: ArtifactRef
    }
  | {
      kind: 'required_verifier_stopped'
      subjectKind: 'verifier_launch'
      stopIntentRef: ArtifactRef
    }
  | {
      kind: 'advisory_verifier_skipped'
      subjectKind: 'verifier_launch'
      verifierSkipItemRef: ArtifactRef
    }
  | {
      kind: 'delivery_stopped'
      subjectKind: 'delivery_plan'
      stopIntentRef: ArtifactRef
    }
  | {
      kind: 'dependency_install_scripts_stopped'
      subjectKind: 'dependency_install_scripts'
      stopIntentRef: ArtifactRef
    }

type PolicyDecisionItemBaseV1 = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'policy_decision'
  subjectKind: ApprovalSubject['kind']
  opId: string
  principalId: string
  decisionRef: ArtifactRef
  policyChannelEvidenceRef: ArtifactRef
  policyChannelEvidenceDigest: string
  createdAt: string
}

type PolicyDecisionItem = PolicyDecisionItemBaseV1 & (
  | ({
      decisionSource: 'direct_policy'
      waitingSubjectRef?: never
    } & (
      | { decision: 'allow'; grantRef: ArtifactRef; denialOutcome?: never }
      | { decision: 'deny'; grantRef?: never; denialOutcome: PolicyDenialOutcomeV1 }
    ))
  | ({
      decisionSource: 'interactive_approval'
      waitingSubjectRef: ArtifactRef
    } & (
      | { decision: 'allow'; grantRef: ArtifactRef; denialOutcome?: never }
      | { decision: 'deny'; grantRef?: never; denialOutcome: PolicyDenialOutcomeV1 }
    ))
)

type InputResponseSchemaV1 = {
  schemaVersion: 1
  format: 'cliq-input-response-schema-v1'
  dialect: 'https://json-schema.org/draft/2020-12/schema'
  schema: Record<string, unknown>
  schemaDigest: string
}

type InputPromptBaseV1 = {
  schemaVersion: 1
  format: 'cliq-input-prompt-v1'
  runId: string
  batchItemId: string
  callId: string
  index: number
  promptTextRef: ArtifactRef
  promptTextDigest: string
  maximumResponseBytes: number
  promptDigest: string
}

type InputPromptV1 = InputPromptBaseV1 & (
  | {
      responseKind: 'text'
      responseSchemaRef?: never
      responseSchemaDigest?: never
    }
  | {
      responseKind: 'json'
      responseSchemaRef: ArtifactRef
      responseSchemaDigest: string
    }
)

type UserInputModelContentV1 = {
  schemaVersion: 1
  format: 'cliq-user-input-model-content-v1'
  inputKind: 'text' | 'json'
  value: unknown
  contentDigest: string
}

type UserInputPayloadBaseV1 = {
  schemaVersion: 1
  format: 'cliq-user-input-payload-v1'
  runId: string
  inputRequestItemId: string
  batchItemId: string
  callId: string
  index: number
  promptRef: ArtifactRef
  promptDigest: string
  principalId: string
  waitingSubjectRef: ArtifactRef
  requestId: string
  requestDigest: string
  expectedRunRevision: number
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  byteCount: number
  modelContentRef: ArtifactRef
  modelContentDigest: string
  payloadDigest: string
}

type UserInputPayloadV1 = UserInputPayloadBaseV1 & (
  | { inputKind: 'text'; value: string }
  | { inputKind: 'json'; value: unknown }
)

type UserInputItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'user_input'
  inputRequestItemId: string
  batchItemId: string
  callId: string
  index: number
  promptRef: ArtifactRef
  promptDigest: string
  inputRef: ArtifactRef
  inputDigest: string
  modelContentRef: ArtifactRef
  modelContentDigest: string
  principalId: string
  createdAt: string
}

type VerifierRepairModelContentV1 = {
  schemaVersion: 1
  format: 'cliq-verifier-repair-model-content-v1'
  verifierId: string
  outcome: 'assertion_failed'
  message: string
  contentDigest: string
}

type VerifierRepairDiagnosticV1 = {
  schemaVersion: 1
  format: 'cliq-verifier-repair-diagnostic-v1'
  runId: string
  candidateItemId: string
  verifierPlanRef: ArtifactRef
  verifierId: string
  receiptRef: ArtifactRef
  receiptDigest: string
  stdoutRef: ArtifactRef
  stderrRef: ArtifactRef
  redactionAlgorithm: 'cliq-verifier-repair-redaction-v1'
  modelContentRef: ArtifactRef
  modelContentDigest: string
  diagnosticDigest: string
}

type RepairDiagnosticEntryV1 = {
  verifierId: string
  diagnosticRef: ArtifactRef
  diagnosticDigest: string
  modelContentRef: ArtifactRef
  modelContentDigest: string
}

type RepairDiagnosticItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'repair_diagnostic'
  candidateItemId: string
  verifierPlanRef: ArtifactRef
  failedVerifierResultItemIds: string[]
  diagnostics: RepairDiagnosticEntryV1[]
  repairOrdinal: number
  createdAt: string
}

type DependencyReadyItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'dependency_ready'
  planRef: ArtifactRef
  opId: string
  attempt: number
  packageCacheManifestRef: ArtifactRef
  readyCheckpointId: string
  installedTreeDigest: string
  createdAt: string
}

type VerifierExecutableIdentityV1 =
  | {
      kind: 'guest_toolchain'
      guestToolchainManifestRef: ArtifactRef
      guestToolchainManifestDigest: string
      toolId: string
      executionPath: string
      executableDigest: string
      abiFingerprint: string
    }
  | {
      kind: 'workspace_script'
      workspaceIdentityDigest: string
      canonicalRootRelativePath: string
      scriptDigest: string
      interpreterIdentityRef: ArtifactRef
      interpreterIdentityDigest: string
    }

type VerifierCommandV1 = {
  schemaVersion: 1
  format: 'cliq-verifier-command-v1'
  verifierId: string
  verifierVersion: string
  executable: VerifierExecutableIdentityV1
  argv: Array<{ kind: 'non_secret_literal'; value: string }>
  cwd: string
  commandDigest: string
}

type VerifierEnvironmentV1 = {
  schemaVersion: 1
  format: 'cliq-verifier-environment-v1'
  verifierId: string
  verifierVersion: string
  commandRef: ArtifactRef
  commandDigest: string
  variables: Array<{ name: string; value: { kind: 'non_secret_literal'; value: string } }>
  writableEphemeralPaths: string[]
  sourceProjectionRef: ArtifactRef
  sourceAccess: 'read_only'
  networkAccess: 'denied'
  sandboxProfile: 'cliq-verifier-readonly-v1'
  runtimeBundleRef: ArtifactRef
  runtimeBundleManifestDigest: string
  guestToolchainManifestRef?: ArtifactRef
  guestToolchainManifestDigest?: string
  environmentDigest: string
}

type VerifierSpec = {
  schemaVersion: 1
  format: 'cliq-verifier-spec-v1'
  verifiers: Array<{
    index: number
    id: string
    version: string
    gate: 'required' | 'advisory'
    commandRef: ArtifactRef
    commandDigest: string
    environmentRef: ArtifactRef
    environmentDigest: string
    timeoutMs: number
    retries: number
    outputLimitBytes: number
    entryDigest: string
  }>
  specDigest: string
}

type VerifierAuthorizationTemplateV1 = {
  schemaVersion: 1
  format: 'cliq-verifier-authorization-template-v1'
  runId: string
  verifierSpecRef: ArtifactRef
  verifierSpecDigest: string
  verifierIndex: number
  verifierId: string
  verifierVersion: string
  verifierEntryDigest: string
  commandRef: ArtifactRef
  commandDigest: string
  environmentRef: ArtifactRef
  environmentDigest: string
  sourceProjectionRef: ArtifactRef
  maxCandidateGenerations: number
  maxAttempts: number
  expiresAt: string
  decisionRef: ArtifactRef
  templateDigest: string
}

type VerificationReceipt = {
  schemaVersion: 1
  format: 'cliq-verification-receipt-v1'
  runId: string
  verifierId: string
  verifierVersion: string
  attempt: number
  outcome: 'passed' | 'assertion_failed' | 'infra_failed' | 'source_mutation'
  reasonCode?: string
  resultSourceRef: ArtifactRef
  sourceDigestBefore: string
  sourceDigestAfter: string
  commandRef: ArtifactRef
  commandDigest: string
  environmentRef: ArtifactRef
  environmentDigest: string
  startedAt: string
  endedAt: string
  durationMs: number
  terminationReason:
    | 'exit'
    | 'timeout'
    | 'signal'
    | 'spawn_error'
    | 'sandbox_denial'
    | 'resource_failure'
  exitCode?: number
  signal?: string
  stdoutRef: ArtifactRef
  stderrRef: ArtifactRef
  stdoutTruncated: boolean
  stderrTruncated: boolean
  leaseEpoch: number
  containmentEvidenceRef: ArtifactRef
  violationEvidenceRef?: ArtifactRef
  violationEvidenceDigest?: string
  receiptDigest: string
}

type WorkspaceDiffOperationV1 =
  | { path: string; kind: 'add'; after: WorkspaceEntry }
  | { path: string; kind: 'delete'; before: WorkspaceEntry }
  | { path: string; kind: 'modify'; before: WorkspaceEntry; after: WorkspaceEntry }

type WorkspaceDiffV1 = {
  schemaVersion: 1
  format: 'cliq-workspace-diff-v1'
  baseSourceRef: ArtifactRef
  resultSourceRef: ArtifactRef
  operations: WorkspaceDiffOperationV1[]
  diffDigest: string
}

type FinalCandidateItemBase = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'final_candidate'
  producingItemId: string
  baseSourceRef: ArtifactRef
  resultSourceRef: ArtifactRef
  diffRef: ArtifactRef
  summaryRef: ArtifactRef
  sourceDigest: string
  diffDigest: string
  createdAt: string
}

type FinalCandidateItem = FinalCandidateItemBase & (
  | { operation: 'agent'; producingOpId: string }
  | { operation: 'delivery'; producingOpId?: never }
)

type VerifierPlan = {
  schemaVersion: 1
  runId: string
  candidateItemId: string
  resultSourceRef: ArtifactRef
  verifierSpecRef: ArtifactRef
  verifierSpecDigest: string
  dependencyPlanRef?: ArtifactRef
  entries: Array<{
    index: number
    verifierId: string
    verifierSpecDigest: string
    verifierEntryDigest: string
    commandRef: ArtifactRef
    commandDigest: string
    environmentRef: ArtifactRef
    environmentDigest: string
    required: boolean
    maxAttempts: number
  }>
  planDigest: string
}

type InheritedVerificationProvenanceV1 = {
  schemaVersion: 1
  format: 'cliq-inherited-verification-provenance-v1'
  deliveryRunId: string
  sourceRunId: string
  sourceRunResultRef: ArtifactRef
  sourceRunResultDigest: string
  sourceVerificationClosureRef: ArtifactRef
  sourceVerificationClosureDigest: string
  resultSourceRef: ArtifactRef
  verifierSpecRef: ArtifactRef
  verifierSpecDigest: string
  verificationReceiptRefs: ArtifactRef[]
  verificationReceiptDigests: string[]
  createdAt: string
  provenanceDigest: string
}

type VerificationClosureV1 = {
  schemaVersion: 1
  format: 'cliq-verification-closure-v1'
  runId: string
  candidateItemId: string
  resultSourceRef: ArtifactRef
  verifierPlanRef: ArtifactRef
  dependency:
    | { kind: 'none' }
    | {
        kind: 'ready'
        dependencyPolicyRef: ArtifactRef
        dependencyPlanRef: ArtifactRef
        dependencyReadyItemId: string
        acquisitionOpId: string
        acquisitionAttempt: number
        completedJournalSeq: number
        readyCheckpointId: string
      }
  verification:
    | {
        kind: 'local'
        outcome: 'verified' | 'unverified'
        unverifiedConsentRef?: ArtifactRef
        entries: Array<{
          verifierIndex: number
          verifierId: string
          verifierSpecDigest: string
          verifierEntryDigest: string
          required: boolean
          disposition:
            | {
                kind: 'passed'
                verifierResultItemId: string
                opId: string
                attempt: number
                completedJournalSeq: number
                receiptRef: ArtifactRef
              }
            | {
                kind: 'advisory_nonpassing'
                outcome: 'assertion_failed' | 'infra_failed'
                verifierResultItemId: string
                opId: string
                attempt: number
                terminalJournalSeq: number
                receiptRef: ArtifactRef
              }
            | {
                kind: 'advisory_skipped'
                verifierSkipItemId: string
                decisionRef: ArtifactRef
              }
        }>
      }
    | {
        kind: 'inherited_verified'
        sourceRunId: string
        sourceRunResultRef: ArtifactRef
        sourceVerificationClosureRef: ArtifactRef
        inheritedProvenanceRef: ArtifactRef
      }
  closureDigest: string
  createdAt: string
}

type InputRequestItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'input_request'
  batchItemId: string
  callId: string
  index: number
  promptRef: ArtifactRef
  promptDigest: string
  createdAt: string
}

type ChildWaitSet = {
  schemaVersion: 1
  parentRunId: string
  purpose:
    | { kind: 'await_tool'; awaitBatchItemId: string; awaitCallId: string; awaitCallIndex: number }
    | { kind: 'finalize_settlement'; modelTurnItemId: string }
    | {
        kind: 'stop_settlement'
        stopIntentRef: ArtifactRef
        awaitOrigin?: { batchItemId: string; callId: string; callIndex: number }
      }
  childRunIds: string[]
}

type ChildMergeBatchItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'child_merge_batch'
  resume:
    | { kind: 'await_tool'; batchItemId: string; callId: string; callIndex: number }
    | { kind: 'finalize_settlement'; modelTurnItemId: string }
  childResultItemIds: string[]
  calls: Array<{
    index: number
    callId: string
    childRunId: string
    patchManifestRef: ArtifactRef
    admittedForkBaseRef: ArtifactRef
  }>
  createdAt: string
}

type VerifierStopItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'verifier_stop'
  candidateItemId: string
  verifierId: string
  opId: string
  attempt: number
  stopIntent: 'cancelled_by_user' | 'parent_cancelled' | 'budget_exhausted'
  containmentEvidenceRef: ArtifactRef
  createdAt: string
}

type VerifierResultItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'verifier_result'
  candidateItemId: string
  verifierPlanRef: ArtifactRef
  verifierIndex: number
  verifierId: string
  opId: string
  attempt: number
  outcome: 'passed' | 'assertion_failed' | 'infra_failed' | 'source_mutation'
  receiptRef: ArtifactRef
  createdAt: string
}

type VerifierSkipItemBaseV1 = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'verifier_skip'
  candidateItemId: string
  verifierPlanRef: ArtifactRef
  verifierIndex: number
  verifierId: string
  decisionRef: ArtifactRef
  createdAt: string
}

type VerifierSkipItem = VerifierSkipItemBaseV1 & (
  | { outcome: 'skipped_by_user'; policyChannelEvidenceDigest?: never }
  | { outcome: 'skipped_by_policy'; policyChannelEvidenceDigest: string }
)

type DeliveryDecisionItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'delivery_decision'
  deliveryPlanRef: ArtifactRef
  approvalOpId: string
  decision: 'allow' | 'deny'
  decisionRef: ArtifactRef
  grantRef?: ArtifactRef
  createdAt: string
}

type McpServerInstanceIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-server-instance-identity-v1'
  runId: string
  batchItemId: string
  callId: string
  callIndex: number
  registrationId: string
  registryRevisionRef: ArtifactRef
  registryManifestDigest: string
  lifecycleSeq: number
  launchOpId: string
  launchAttempt: number
  launchDispatchId: string
  sandboxLaunchSpecRef: ArtifactRef
  processContainmentRef: ArtifactRef
  initializeDigest: string
  capabilityDigest: string
  probedToolsListDigest: string
  instanceNonceDigest: string
  initializedAt: string
  identityDigest: string
}

type McpServerLaunchReceiptV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-server-launch-receipt-v1'
  instanceIdentityRef: ArtifactRef
  instanceIdentityDigest: string
  preparedJournalSeq: number
  claimedJournalSeq: number
  completedJournalSeq: number
  budgetSettlementRef: ArtifactRef
  stoppedItemId: string
  containmentDeathEvidenceRef: ArtifactRef
  stoppedAt: string
  receiptDigest: string
}

type McpServerStoppedItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'mcp_server_stopped'
  batchItemId: string
  callId: string
  callIndex: number
  serverManifestRef: ArtifactRef
  lifecycleSeq: number
  launchOpId: string
  instanceIdentityRef: ArtifactRef
  instanceIdentityDigest: string
  launchReceiptRef: ArtifactRef
  launchReceiptDigest: string
  cause: 'normal' | 'lease_release' | 'crash' | 'cancel' | 'deadline' | 'manifest_mismatch'
  containmentEvidenceRef: ArtifactRef
  createdAt: string
}

type PathState =
  | { kind: 'absent' }
  | { kind: 'directory'; mode: number; identityDigest?: string }
  | { kind: 'file'; digest: string; mode: number }
  | { kind: 'symlink'; target: string; digest: string }

type PublicationLeafState =
  | { kind: 'file'; digest: string; mode: number }
  | { kind: 'symlink'; target: string; digest: string }

type PublicationParent =
  | { kind: 'existing_directory'; expectedIdentityDigest: string }
  | { kind: 'planned_directory'; createdByOperationId: string }

type PublicationOperationBase = {
  index: number
  operationId: string
  path: string
  parent: PublicationParent
}

type PublicationOperation = PublicationOperationBase & (
  | {
      kind: 'mkdir'
      expected: { kind: 'absent' }
      desired: { kind: 'directory'; mode: 493 }
      stagingName?: never
      stagingExpected?: never
      quarantineName?: never
      quarantineExpected?: never
    }
  | {
      kind: 'create'
      expected: { kind: 'absent' }
      desired: PublicationLeafState
      stagingName: string
      stagingExpected: { kind: 'absent' }
      quarantineName?: never
      quarantineExpected?: never
    }
  | {
      kind: 'replace'
      expected: PublicationLeafState
      desired: PublicationLeafState
      stagingName: string
      stagingExpected: { kind: 'absent' }
      quarantineName: string
      quarantineExpected: { kind: 'absent' }
    }
  | {
      kind: 'delete'
      expected: PublicationLeafState
      desired: { kind: 'absent' }
      stagingName?: never
      stagingExpected?: never
      quarantineName: string
      quarantineExpected: { kind: 'absent' }
    }
)

type PublicationAbortOperation = {
  index: number
  operationId: string
  kind: 'abort_rmdir'
  path: string
  createdByOperationId: string
}

type DeliveryPlan = {
  schemaVersion: 1
  deliveryRunId: string
  sourceRunResultRef: ArtifactRef
  sourceBaseRef: ArtifactRef
  sourceDesiredRef: ArtifactRef
  capturedWorkspaceRef: ArtifactRef
  desiredSourceRef: ArtifactRef
  diffRef: ArtifactRef
  mergeAlgorithm: 'cliq-diff3-v1'
  publicationStateMachine: 'cliq-publish-v1'
  forwardOperations: PublicationOperation[]
  abortOperations: PublicationAbortOperation[]
}

type PublicationPathObservationV1 = {
  path: string
  state: PathState
  parentDeviceId: string
  parentFileId: string
  parentLinkCount: number
  entryDeviceId?: string
  entryFileId?: string
  entryLinkCount?: number
}

type PublicationProofBaseV1 = {
  schemaVersion: 1
  format: 'cliq-publication-proof-v1'
  deliveryRunId: string
  deliveryPlanRef: ArtifactRef
  workspaceIdentityRef: ArtifactRef
  workspaceIdentityDigest: string
  inspectorIdentityRef: ArtifactRef
  inspectorIdentityDigest: string
  observedAt: string
}

type PublicationProofV1 = PublicationProofBaseV1 & (
  | {
      kind: 'path_observation'
      observation: PublicationPathObservationV1
      proofDigest: string
    }
  | {
      kind: 'terminal_receipt'
      sequence: 'forward' | 'abort'
      operationIndex: number
      operationId: string
      opId: string
      attempt: number
      before: PublicationPathObservationV1
      after: PublicationPathObservationV1
      preservedPreimageRef?: ArtifactRef
      transientFinalObservations: PublicationPathObservationV1[]
      parentIdentityBeforeDigest: string
      parentIdentityAfterDigest: string
      directoryFsyncCompleted: true
      proofDigest: string
    }
  | {
      kind: 'planned_descendant'
      abortOperationId: string
      retainedDescendantOperationIds: string[]
      observationRefs: ArtifactRef[]
      proofDigest: string
    }
  | {
      kind: 'path_ambiguity'
      sequence: 'forward' | 'abort'
      operationIndex: number
      operationId: string
      opId: string
      attempt: number
      launchDispatchId: string
      failure:
        | 'descriptor_unreadable'
        | 'entry_identity_changed_during_observation'
        | 'transient_state_ambiguous'
        | 'parent_fsync_unconfirmed'
      lastKnownObservationRefs: ArtifactRef[]
      proofDigest: string
    }
  | {
      kind: 'transient_absence'
      transientPaths: string[]
      observationRefs: ArtifactRef[]
      proofDigest: string
    }
  | {
      kind: 'projection_closure'
      selectedBranch: 'forward_finalize' | 'abort'
      observedSourceRef: ArtifactRef
      observedPathEvidenceRefs: ArtifactRef[]
      forwardResultItemRefs: ArtifactRef[]
      unstartedForwardOperationIds: string[]
      abortResultItemRefs: ArtifactRef[]
      proofDigest: string
    }
  | ({
      kind: 'git_index_unchanged'
      proofDigest: string
    } & (
      | {
          repositoryKind: 'non_git'
          capturedIndexRef?: never
          capturedIndexDigest?: never
          observedIndexRef?: never
          observedIndexDigest?: never
        }
      | {
          repositoryKind: 'git'
          capturedIndexRef: ArtifactRef
          capturedIndexDigest: string
          observedIndexRef: ArtifactRef
          observedIndexDigest: string
        }
    ))
)

type DeliveryTerminalProjectionEvidence = {
  schemaVersion: 1
  deliveryRunId: string
  deliveryPlanRef: ArtifactRef
  selectedBranch: 'forward_finalize' | 'abort'
  observedSourceRef: ArtifactRef
  observedPathStates: Array<{
    path: string
    state: PathState
    evidenceRef: ArtifactRef
  }>
  forwardResultItemRefs: ArtifactRef[]
  unstartedForwardOperationIds: string[]
  abortResultItemRefs: ArtifactRef[]
  transientAbsenceEvidenceRef: ArtifactRef
  projectionClosureEvidenceRef: ArtifactRef
  gitIndexUnchangedEvidenceRef: ArtifactRef
  observedAt: string
  evidenceDigest: string
}

type PublicationPathProgressItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'publication_path_progress'
  deliveryPlanRef: ArtifactRef
  operationIndex: number
  operationId: string
  opId: string
  attempt: number
  state: 'desired_committed_cleanup_pending'
  destinationEvidenceRef: ArtifactRef
  preservedPreimageRef?: ArtifactRef
  transientObservationRef?: ArtifactRef
  createdAt: string
}

type PublicationPathResultItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'publication_path_result'
  deliveryPlanRef: ArtifactRef
  sequence: 'forward' | 'abort'
  operationIndex: number
  operationId: string
  opId: string
  attempt: number
  outcome: 'completed' | 'not_created' | 'retained_planned_descendant' | 'failed' | 'unknown'
  receiptRef?: ArtifactRef
  evidenceRef: ArtifactRef
  createdAt: string
}
```

`InheritedVerificationProvenanceV1` is the only artifact legal at `inheritedProvenanceRef` or a delivery `RunResult.verificationProvenanceRef`. `provenanceDigest = SHA-256(JCS(provenance with provenanceDigest omitted))`. The source Run must be terminal `succeeded(verified)` with the exact result/result digest and required `verificationClosureRef`; the source closure digest, result source, verifier spec/digest, and ordered receipt refs/digests must equal that immutable source graph. `deliveryRunId` is the consuming delivery Run, which must have produced the identical `resultSourceRef`; neither receipts nor source-owned ids are copied or relabeled. The delivery `VerificationClosureV1.inherited_verified` fields and final RunResult must repeat these exact refs. Storage decodes and re-walks the source result/closure/Journal/receipt graph before publishing or accepting the provenance; a loose list of passing receipts or equal directory bytes is insufficient.

Delivery source identity is one fixed four-manifest equation. Let **B** be `source RunResult.baseSourceRef`, **S** be `source RunResult.resultSourceRef`, **A** be this delivery Run's admitted `RunSpec.baseWorkspaceManifestRef === delivery:merge.capturedWorkspaceRef`, and **M** be the deterministic `cliq-diff3-v1(B,S,A)` merged SourceManifest. `DeliveryMergeItem` and `DeliveryPlan` repeat `sourceBaseRef=B`, `sourceDesiredRef=S`, and `capturedWorkspaceRef=A`; their merged/desired result is M and their `diffRef` decodes the exact A-to-M `WorkspaceDiffV1`. The merge summary decodes one bounded `ModelTextV1` derived only from that B/S/A/M/diff projection and is the sole delivery candidate/result summary. A conflict item repeats B/S/A and has no M or diff. The delivery `FinalCandidateItem` and `RunResult` both use `baseSourceRef=A`, `resultSourceRef=M`, that same A-to-M diff, and the merge summary; the VerifierPlan, VerificationClosure, delivery frontier, and terminal projection all bind M. No field is permitted to reinterpret “base” as B in one artifact and A in another.

`VerificationClosureV1` is the sole artifact allowed in any Run-frontier `verificationClosureRef`. `closureDigest = SHA-256(JCS(closure with closureDigest omitted))`; Run/candidate/result/plan equal the current verify/finalize/delivery frontier and every entry is contiguous, unique, and byte-for-byte aligned with `VerifierPlan.entries`. `passed` names an identity-matched `VerifierResultItem`, highest eligible verifier Journal `completed` fact, and its exact receipt. `advisory_nonpassing` is forbidden for required entries and names the correct completed assertion or positively failed infrastructure fact; `advisory_skipped` is likewise advisory-only and names the exact skip/decision. `local/verified` requires at least one required entry, every required entry passed, and no consent; `local/unverified` requires zero required entries and the exact RunSpec consent. Source mutation or a stopped/unresolved required verifier cannot produce a closure.

Dependency `none` is legal iff the frozen dependency policy is absent/disabled. `ready` must name the current candidate-derived policy/plan, the identity-matched `DependencyReadyItem`, acquisition `completed` Journal fact, and ready Checkpoint whose source digest still equals `resultSourceRef`. `inherited_verified` is legal only for delivery with identical result source and revalidates the source terminal RunResult, source closure, immutable provenance, verifier/dependency plan, receipts, and artifact digests; it never relabels receipts. The transaction that consumes the final verifier/dependency result publishes this closure first. For `afterPass='finalize'` it atomically installs the finalize frontier. For `afterPass='delivery_approval'` it atomically installs the proof-carrying delivery approval frontier; approval and publication preserve the same ref until the final forward projection transaction installs delivery finalize. `commitRunResult` accepts exactly that ref and re-walks the closure against storage; a schema-valid CAS artifact, alternate receipt list, caller-derived summary, or closure dropped/reconstructed across publication cannot finalize the Run.

`AgentModelTurn` and transport deltas use section 11.1's canonical schemas, implemented by work package 02; the durable `modelTurnRef` contains the exact provider/model/response identity, one `ModelTextV1` ref, ordered `AgentToolCall` input ref/digest pairs, normalized stop reason, negotiated mode, optional untrusted usage telemetry, and request/response digests. `usageTrusted` is literal `false`; no per-turn adapter claim changes budget authority. `ModelTextV1.textDigest`, `ObservedToolCallInputV1.observedInputDigest`, and `ToolCallInputV1.inputDigest` each omit themselves under JCS; text byte count is its exact UTF-8 length. Every `ToolCallInputV1.observedInputRef` rehashes its named observation. The assembled provider argument is bounded to 1,048,576 bytes. Valid JSON uses `encoding='jcs_json'`, retains the exact JSON-domain value, and counts its RFC 8785 bytes; otherwise `utf8_json_fragment` retains and counts the exact assembled UTF-8 text. This retained observation is the sole source for lossless assistant-call context reconstruction. A `resolved` input alone contains the validated schema-normalized object and exact selected tool schema ref/digest and alone may enter policy, grant, Journal, or dispatch. `rejected_unknown_tool` forbids schema/value and carries the deterministic diagnostic; `rejected_invalid_input` repeats the known schema, forbids value, and carries its validator diagnostic. Both rejected forms remain in an identity-valid batch solely to produce ordered synthetic results. `ModelTurnItem.textRef` equals the decoded turn's text ref. A call turn's ordered `(callId,index,toolName,inputRef,inputDigest)` list equals `ToolBatchItem.calls` byte-for-byte and its batch text ref is the same turn text. Its stop matrix is storage-enforced: `end` has zero calls and nonempty decoded final text; `tool_calls` has one or more complete call identities whose inputs are exact resolved/rejected artifacts; and `cancelled` has zero calls plus an exact `abortStopIntentRef` that was current before Cliq issued the authenticated abort for this invocation. `length|content_filter|unknown` never inhabit `AgentModelTurn` or `ModelTurnItem`; a positively received response with one of those normalized stops publishes `ModelUnusableResponseV1` with respectively `stop_reason_length|stop_reason_content_filter|stop_reason_unknown`, while any partial calls remain only in its private observed bytes. `ModelTurnItem` copies the abort member iff cancelled and otherwise forbids it. A provider/transport cancellation not caused by such an abort is never normalized into cancellation authority: a completed unusable response proposes generic runtime protocol failure, while uncertain dispatch remains Journal `unknown` under the frozen retry policy. Invalid stop/call/text pairs are `MODEL_PROTOCOL_ERROR`, fully charged when the response occurred, and create no candidate/batch. `VerificationReceipt` is the exact work package 05 schema and is additionally constrained by sections 13.2-13.4. `ChildHandleItem` and `ChildResultItem` use section 12's exact fields plus the common version/id/run/timestamp fields.

Native call identity is normalized before that validation. OpenAI, Anthropic,
OpenRouter, OpenAI-compatible, and Zhipu require a nonempty provider-native id
for every call and require those ids to be unique within the response. The
managed Ollama adapter ignores any optional wire id and deterministically sets
`callId = base64url(SHA-256(JCS({protocol:'cliq-ollama-native-call-v1',runId,opId,attempt,index})))`,
where `index` is the contiguous zero-based response order and the other fields
equal the claimed model Journal attempt. Re-decoding the same completed attempt
therefore reproduces the same ids, a different attempt cannot alias them, and
generic `ollama_call_N`, random ids, or worker-memory counters are forbidden.
Only after this provider-specific normalization does storage require every
call id to be nonempty and unique; missing/duplicate native ids from any other
provider remain a response-level protocol error with no assistant turn or
tool execution.

For a usable turn, `AgentModelTurn.responseDigest` is exactly SHA-256 of RFC 8785/JCS `{format:'cliq-agent-normalized-response-v1',provider,model,responseId?,continuation?,usage?,usageTrusted:false,negotiatedMode,requestDigest,stopReason,textRef,toolCalls,abortStopIntentRef?}`, with absent optional members omitted and calls in retained index order. Every value is copied byte-for-byte from the turn and storage recomputes this projection. It never hashes discarded provider wire bytes or the whole self-containing turn; raw unusable bytes are retained only by `ModelUnusableResponseV1`.

Run-item decoding is a closed discriminated union over the types in this appendix/sections 12-14; unknown kinds fail closed. Except for the dedicated fenced retry-unknown artifact, every `ToolResultItem.resultRef` decodes exact `ToolResultPayloadV1`, whose `payloadDigest = SHA-256(JCS(payload with payloadDigest omitted))` and whose Run/batch/call/index/tool/outcome equal the item and original call. `executed,source='invocation'` repeats the exact completed Journal op/attempt/result and selected output schema; `executed,source='user_input'` instead binds the authenticated input item and payload below. `denied` repeats either the immutable policy ref/decision digest or exact `ApprovalDecisionV1`. `error` uses only the closed code set, always carries one rehashed diagnostic, and carries op/attempt/Journal error all together iff dispatch created that op. `batch_not_executed` lists the complete unique byte-sorted invalid call-id set from the same prevalidation transaction. Ordinary `cancelled` repeats the winning StopIntent and deterministic notice. A fenced retry-unknown cancelled item instead points directly to exact `RetryUnknownCancelledResult` under the terminal rule above.

The model never receives the audit payload. Every ordinary payload's `modelContentRef` rehashes exact `ToolResultModelContentV1`, its call identity/outcome match, `contentDigest = SHA-256(JCS(content artifact with contentDigest omitted))`, and its canonical JSON content is at most 1,048,576 bytes. For `executed`, content is the selected output-schema-normalized result (or the registered contract's canonical schema-absent JSON result). Synthetic projections are exact and ref-free: denied is `{code:'TOOL_CALL_DENIED'}`; error is `{code}`; batch-not-executed is `{code:'BATCH_REJECTED_BEFORE_DISPATCH',invalidCallIds}`; cancelled is `{code:'TOOL_CALL_CANCELLED',cancellationKind}`. No principal, policy/grant/decision/StopIntent/Journal/diagnostic/attestation/containment ref or digest enters that artifact. Model context projection includes only these decoded model-content artifacts, `UserInputItem.modelContentRef`, `RepairDiagnosticItem` model-safe diagnostics, and `ChildResultItem.modelContentRef` when their owning frontier reducers admit them. It excludes the full input/ToolResult/child authority payload, grants, principal ids, policy artifacts, attestations, containment evidence, and `ToolAbandonedItem`; a `PolicyDecisionItem` is represented only by its ref-free denied content or stop outcome. Thus audit truth and prompt content are related by explicit projection, not by serializing authority artifacts.

Input artifacts are equally closed. `InputResponseSchemaV1.schemaDigest`,
`InputPromptV1.promptDigest`, `UserInputModelContentV1.contentDigest`, and
`UserInputPayloadV1.payloadDigest` each omit only themselves under JCS; all
ref/digest pairs rehash their named bytes. The
schema is at most 64 KiB JCS and uses the deterministic Cliq JSON-Schema-2020-12
subset: `type`, `properties`, `required`, `additionalProperties:false`,
`items`, `enum`, `const`, numeric min/max, string min/max length, and array
min/max items. `$ref`, remote ids, recursive/unevaluated composition, regex,
`format`, defaults, coercion, custom keywords, and unknown keywords are
rejected. Prompt text is NFC `ModelTextV1`; `maximumResponseBytes` is
`1..1048576`. Text input is NFC/no-NUL UTF-8 in that bound. JSON input is a
finite JSON-domain value, validates without coercion/default insertion, and
its RFC 8785/JCS bytes fit the same bound. Payload byte count is the exact text
UTF-8 or JSON JCS length.
Prompt, payload, request item, user item, waiting subject, originating
`request_input` call, and ToolResult all repeat Run/batch/call/index; principal
equals the authenticated request. The item input ref/digest rehashes the
payload. Payload/item model-content refs rehash the same exact
`UserInputModelContentV1`; its kind/value equal the payload and it contains no
principal, prompt/schema, request, Run/call, or authority ref. The executed
ToolResult model content value equals only that same kind-normalized payload
value and its call identity. A kind/schema/bound/identity mismatch commits nothing;
same request id/digest returns the already committed item/result/snapshot.

UserInputPayloadV1 additionally binds the exact waiting ref, request id/digest,
expected revision and authenticated channel pair. Its `requestDigest` is the
canonical `run.input` wire request, excluding the transport-injected principal
and channel; `(principalId,'run.input',requestId)` selects the durable control
row, whose digest/channel/commit time and immutable response must agree. A
fresh channel must authenticate even an idempotent replay; the retained channel
is historical audit, never authority to submit a new request. The executed
input ToolResult has no `opId`, attempt or Journal reference. The ordinary
executed-Journal rule above applies only to `source='invocation'`.

Every completed visible model attempt first appends one `ModelTurnItem`; a call turn's `ToolBatchItem.modelTurnRef` and `modelOpId/attempt` must match it. Every `FinalCandidateItem` decodes its base/result SourceManifests and exact `WorkspaceDiffV1`; the diff base/result refs equal the candidate, `sourceDigest` equals the result SourceManifest's `manifestDigest`, and `diffDigest` equals the decoded diff's self digest. The `agent` branch names a same-Run `ModelTurnItem(stopReason='end')`, requires `producingOpId === modelOpId`, and requires `summaryRef === textRef` where that `ModelTextV1` is nonempty. The `delivery` branch structurally forbids `producingOpId`, names the exact same-Run `DeliveryMergeItem`, and copies its captured-base/result/diff/summary refs; that summary also decodes `ModelTextV1`, while source Run, B/S/A/M, and plan fields satisfy the delivery equations above. No candidate points directly at an unowned provider artifact. `commitRunResult` requires its `baseSourceRef`, `resultSourceRef`, `diffRef`, and `summaryRef` to equal the current candidate byte-for-byte, then independently rehashes the result source and diff; `SessionRunTerminalItem.resultRef` names only that committed RunResult. A caller-derived summary, alternate diff, tree digest substituted for manifest digest, or delivery merge op invented after the fact is invalid.

`DeliveryPlan.forwardOperations` is contiguous, ancestor-before-descendant for creation, contains no duplicate path/operation id/transient sibling, and represents every semantic materialization action; `abortOperations` is a separately indexed deepest-first list over planned delivery-created directories. Both arrays may be empty only when the captured real-workspace source ref already equals `desiredSourceRef`; that no-op delivery creates no approval/publish frontier and proceeds directly through the shared verification/provenance and finalize closure. Otherwise forward operations are nonempty. The discriminated union is exact: `mkdir` has only expected absence and fixed mode `0755`; `create` has one absent staging sibling and no quarantine; `replace` has absent staging plus quarantine siblings; `delete` has one absent quarantine sibling and no staging. Every leaf expected/desired state is a file or symlink, never a directory. `parent` is present on every operation and either binds an already captured directory identity or the earlier exact mkdir operation that created it; no optional parent/transient field is inferred by kind.

Every publication receipt/evidence ref decodes only `PublicationProofV1`, and `proofDigest = SHA-256(JCS(proof with proofDigest omitted))`. Base fields equal the delivery Run, immutable plan, live Session workspace identity, and the exact current signed Supervisor inspector. A path observation is produced by no-follow descriptor traversal from that root: absent forbids all entry identity fields, every present state requires all three, and the file/symlink/directory state is rehashed or reidentified from the held entry. `PublicationPathProgressItem.destinationEvidenceRef` is the exact post-swap destination `path_observation`; optional `transientObservationRef` is present iff this plan operation has a staging/quarantine sibling still pending cleanup and decodes to the exact present sibling path/descriptor state frozen by the plan. It replaces any untyped transient identity handle. A terminal receipt matches one plan operation and Journal claim byte-for-byte; `before` equals its expected state, `after` equals desired for forward completion or the abort operation's exact postcondition, transient observations are unique byte-sorted and all absent, preserved preimage is required exactly when the leaf displaced bytes, the parent identities satisfy the plan parent edge, and `directoryFsyncCompleted` is the inspector's retained post-fsync fact. Journal `opKind='publish',phase='completed'` has `receiptRef` and `evidenceRef` equal to this terminal-receipt artifact, and the matching completed `PublicationPathResultItem` repeats it in both fields. `not_created` has no receipt and requires a `path_observation` proving exact absence plus no completed creating operation. `retained_planned_descendant` has no receipt and requires a `planned_descendant` proof whose operation ids are exactly still-retained completed plan descendants. `failed` has no terminal receipt and carries the exact final path observation. `unknown` carries only `path_ambiguity`: it repeats the claim dispatch/op/attempt/plan operation, a closed failure literal, and any unique byte-sorted last-known path-observation refs; an adapter string/exception is forbidden. Neither outcome satisfies forward or abort closure. Publish is `reconcile`, so this item has no abandoned outcome.

The three terminal-projection proof refs are likewise exact. `transient_absence` lists every plan-derived staging/quarantine path exactly once in byte order and its parallel observation refs all decode to absent `path_observation` proofs for those paths. `projection_closure` repeats the projection artifact's branch/source, its observed-path evidence refs in path order, its plan-ordered result refs, and its exact unstarted suffix. `git_index_unchanged` is the canonical all-absent four-field form for a non-Git workspace; for Git, all four fields are required, both refs rehash their digest members, captured fields equal captured manifest A, and observed digest/ref are byte-identical. No opaque adapter receipt, unhashed boolean, or alternate proof shape may advance publication or terminalize the Run.

`DeliveryTerminalProjectionEvidence.evidenceDigest = SHA-256(JCS(evidence with evidenceDigest omitted))`. Observed paths are canonical, unique, byte-sorted, and exactly cover every plan-touched destination/transient; each state/evidence ref is descriptor-derived from the admitted root and the Git-index proof matches the capture. `forward_finalize` requires every forward operation's plan-ordered completed result, empty abort/unstarted lists, no transient, and `observedSourceRef === DeliveryPlan.desiredSourceRef`. `abort` requires one non-unknown result for every started forward operation, the exact remaining contiguous forward-operation-id suffix in `unstartedForwardOperationIds`, and one plan-ordered non-unknown result for every abort operation. A known failed result may explain retained partial state but never proves rollback; abort `observedSourceRef` need equal neither base nor desired. Missing/unknown/unmatched evidence remains reconciliation. Successful delivery installs this artifact in the delivery finalize frontier and `RunResult`. A failed/cancelled delivery requires `TerminalDetail.deliveryTerminalProjectionEvidenceRef` only when a forward publication claim existed; merge conflict, approval denial, or cancellation before the first forward claim forbids it. The reason-bound `primaryEvidenceRef` follows the exact StopIntent branch matrix (and is the StopIntent ref for delivery merge/publication stops), while `publicationResultItemRefs` equals the abort evidence's forward-then-abort result refs. Therefore success and safe partial publication retain one authoritative projection proof without mutating or replacing StopIntent truth.

Terminal detail is also typed:

```ts
type TerminalReasonDetail =
  | {
      kind: 'verification'
      candidateItemId: string
      verifierPlanRef: ArtifactRef
    }
  | {
      kind: 'verifier_source_mutation'
      verifierOpId: string
      violationOrDigestEvidenceRef: ArtifactRef
      violationOrDigestEvidenceDigest: string
    }
  | {
      kind: 'budget_exhausted'
      stopIntentRef: ArtifactRef
    }
  | {
      kind: 'cancelled'
      stopIntentRef: ArtifactRef
    }
  | {
      kind: 'context_compaction_failed'
      compactionPlanRef: ArtifactRef
      modelOpId: string
      attempt: number
      evidenceRef: ArtifactRef
    }
  | {
      kind: 'context_window_exhausted'
      contextManifestRef: ArtifactRef
      nextPromptTokens: number
      triggerThresholdTokens: number
      hardPromptTokens: number
      protectedTokens: number
      sourceInputTokenCap: number
      evidenceRef: ArtifactRef
    }
  | {
      kind: 'dependency_source_integrity'
      dependencyPlanRef: ArtifactRef
      failingOpId: string
      integrityEvidenceRef: ArtifactRef
      integrityEvidenceDigest: string
    }
  | {
      kind: 'delivery_merge_conflict'
      deliveryMergeConflictItemRef: ArtifactRef
      conflictRef: ArtifactRef
    }
  | {
      kind: 'delivery_publication_failed'
      deliveryPlanRef: ArtifactRef
      sequence: 'forward' | 'abort'
      operationId: string
      evidenceRef: ArtifactRef
    }
  | {
      kind: 'local_inference_unavailable'
      activationCycleId: string
      serviceId: string
      frontierRef: ArtifactRef
      failureDetailRef: ArtifactRef
      evidenceRef: ArtifactRef
    }
  | {
      kind: 'policy_denied'
      subjectKind: 'verifier' | 'delivery' | 'dependency_install_scripts'
      opId: string
      policyChannelEvidenceRef: ArtifactRef
      policyChannelEvidenceDigest: string
    }
  | {
      kind: 'runtime'
      failingOpId: string
      runtimeFailureRef: ArtifactRef
      runtimeFailureDigest: string
    }

type TerminalDetail = {
  schemaVersion: 1
  runId: string
  reason: Exclude<RunTerminalReason, 'verified' | 'no_required_verifier'>
  reasonDetail: TerminalReasonDetail
  primaryEvidenceRef: ArtifactRef
  publicationResultItemRefs: ArtifactRef[]
  deliveryTerminalProjectionEvidenceRef?: ArtifactRef
  abandonedRetryInvocations: Array<{
    opId: string
    attempt: number
    unknownJournalSeq: number
    budgetSettlementRef: ArtifactRef
    dispatchFenceOrDeathEvidenceRef: ArtifactRef
  }>
  abandonedManualInvocation?: {
    opId: string
    attempt: number
    abandonedJournalSeq: number
    attestationRef: ArtifactRef
    toolAbandonedItemRef?: ArtifactRef
  }
  createdAt: string
}
```

Storage validates the reason-specific closure: verification reasons bind the candidate and matching verifier evidence; mutation binds violation evidence; runtime/budget bind their stop/error evidence; cancellation reason detail binds the **winning** StopIntent. `publicationResultItemRefs` is empty and `deliveryTerminalProjectionEvidenceRef` absent unless a stopped delivery had a forward publication claim; in that sole case the evidence ref is required and the list equals its plan-ordered `forwardResultItemRefs` followed by `abortResultItemRefs`, with no duplicate or unrelated item. `abandonedRetryInvocations` contains every and only terminally abandoned `retry` unknown, in strictly increasing `(unknownJournalSeq,opId,attempt)` order; each entry has positive dispatch-fence/death evidence and its exact conservative budget settlement. `abandonedManualInvocation` is allowed only for `cancelled_by_user` and the sole matching `manual` Journal `abandoned` row; a tool/MCP origin additionally requires the exact owned `ToolAbandonedItem` ref, while a non-call origin forbids it. If an earlier user/parent cancellation already wins at equal-or-higher precedence, `run.reconcile(abandon_run)` atomically appends that abandonment/closure evidence and terminalizes against the existing winner—it does not propose a competing StopIntent or replace its reason detail. If no stop exists, the explicit attestation may create `manual_abandon` as the winner. The publication and retry arrays are always present and empty when inapplicable; the manual field is absent when inapplicable. No terminal-detail field is populated by scanning for a “latest” candidate/diagnostic/receipt/child item.

## 12. Recursive Runs

A child is an ordinary Run with `parentRunId`. There is no separate Subagent aggregate or scheduler.

The only agent-facing recursion interface is two built-in typed tools:

```ts
type ChildCapabilityGrantV1 = {
  schemaVersion: 1
  format: 'cliq-child-capability-grant-v1'
  parentRunId: string
  delegateBatchItemId: string
  delegateCallId: string
  delegateCallIndex: number
  delegateOpId: string
  mode: 'read_only' | 'mutating'
  parentAssemblyRef: ArtifactRef
  parentPolicyRef: ArtifactRef
  granted: {
    builtinToolNames: string[]
    registeredMcpServerIds: string[]
    allowShell: boolean
    allowSourceWrite: boolean
  }
  childToolManifestRef: ArtifactRef
  childToolManifestDigest: string
  childAssemblyRef: ArtifactRef
  childPolicyRef: ArtifactRef
  verifierMode: 'inherit_parent' | 'none'
  childVerifierSpecRef: ArtifactRef
  childDependencyPolicyRef?: ArtifactRef
  childCredentialGrantRefs: ArtifactRef[]
  derivedUnverifiedConsentRef?: ArtifactRef
  grantedBudgets: RunSpec['budgets']
  childDeadlineAt: string
  grantCoreDigest: string
  grantDigest: string
}

type DelegateRequest = {
  objective: string
  mode: 'read_only' | 'mutating'
  context: {
    source: 'parent_current' | 'parent_summary'
    additionalArtifactRefs: ArtifactRef[]
  }
  requestedBudgets: RunSpec['budgets']
  capabilities: {
    builtinToolNames: string[]
    registeredMcpServerIds: string[]
    allowShell: boolean
    allowSourceWrite: boolean
  }
  verifierMode: 'inherit_parent' | 'none'
  allowUnverifiedHelper: boolean
}

type ChildHandleItem = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'child_handle'
  delegateBatchItemId: string
  delegateCallId: string
  delegateCallIndex: number
  delegateOpId: string
  childRunId: string
  admittedSpecRef: ArtifactRef
  mode: 'read_only' | 'mutating'
  createdAt: string
}

type AwaitChildrenRequest = {
  childRunIds: string[]
}

type DelegateResult = {
  schemaVersion: 1
  childHandleItemId: string
  childRunId: string
  admittedSpecRef: ArtifactRef
}

type AwaitChildrenResult = {
  schemaVersion: 1
  waitSetRef: ArtifactRef
  childResultItemIds: string[]
}

type ChildPatchManifest = {
  schemaVersion: 1
  childRunId: string
  admittedForkBaseRef: ArtifactRef
  resultSourceRef: ArtifactRef
  diffRef: ArtifactRef
  operations: Array<
    | { kind: 'add'; path: string; resultEntryDigest: string }
    | { kind: 'modify'; path: string; expectedEntryDigest: string; resultEntryDigest: string }
    | { kind: 'delete'; path: string; expectedEntryDigest: string }
    | { kind: 'mode'; path: string; expectedEntryDigest: string; resultEntryDigest: string }
    | { kind: 'symlink'; path: string; expectedEntryDigest?: string; resultEntryDigest: string }
  >
  patchDigest: string
}

type ChildResultModelContentV1 = {
  schemaVersion: 1
  format: 'cliq-child-result-model-content-v1'
  childRunId: string
  mode: 'read_only' | 'mutating'
  content:
    | {
        status: 'succeeded' | 'completed_unverified'
        summary: string
      }
    | {
        status: 'failed' | 'cancelled'
        terminalReason: RunTerminalReason
      }
  contentDigest: string
}

type ChildResultItemBase = {
  schemaVersion: 1
  itemId: string
  runId: string
  kind: 'child_result'
  delivery:
    | {
        kind: 'await_tool'
        waitSetRef: ArtifactRef
        awaitBatchItemId: string
        awaitCallId: string
        awaitCallIndex: number
      }
    | { kind: 'finalize_settlement'; waitSetRef: ArtifactRef; modelTurnItemId: string }
    | { kind: 'stop_settlement'; waitSetRef: ArtifactRef; stopIntentRef: ArtifactRef }
  childRunId: string
  inclusiveBudgetUsage: BudgetUsage
  modelContentRef: ArtifactRef
  modelContentDigest: string
  createdAt: string
}

type ChildResultItem = ChildResultItemBase & (
  | {
      mode: 'read_only'
      status: 'succeeded' | 'completed_unverified'
      resultRef: ArtifactRef
    }
  | {
      mode: 'mutating'
      status: 'succeeded' | 'completed_unverified'
      resultRef: ArtifactRef
      patchManifestRef: ArtifactRef
    }
  | {
      mode: 'read_only' | 'mutating'
      status: 'failed' | 'cancelled'
      terminalDetailRef: ArtifactRef
  }
)

type ChildAllocationTerminal =
  | {
      mode: 'read_only'
      status: 'succeeded' | 'completed_unverified'
      resultRef: ArtifactRef
      patchManifestRef?: never
      modelContentRef: ArtifactRef
      modelContentDigest: string
    }
  | {
      mode: 'mutating'
      status: 'succeeded' | 'completed_unverified'
      resultRef: ArtifactRef
      patchManifestRef: ArtifactRef
      modelContentRef: ArtifactRef
      modelContentDigest: string
    }
  | {
      mode: 'read_only' | 'mutating'
      status: 'failed' | 'cancelled'
      resultRef?: never
      patchManifestRef?: never
      terminalDetailRef: ArtifactRef
      modelContentRef: ArtifactRef
      modelContentDigest: string
    }

type ChildAllocationBase = {
  schemaVersion: 1
  parentRunId: string
  childRunId: string
  admissionKey: string
  delegateBatchItemId: string
  delegateCallId: string
  delegateCallIndex: number
  delegateOpId: string
  delegateOperationGrantRef: ArtifactRef
  capabilityGrantRef: ArtifactRef
  mode: 'read_only' | 'mutating'
  grantedAdditiveCeilings: BudgetUsage
  grantedChildDepth: number
  grantedChildConcurrency: number
  childDeadlineAt: string
  createdAt: string
}

type ChildAllocationV1 = ChildAllocationBase & (
  | {
      state: 'reserved'
      terminal?: never
      inclusiveBudgetUsage?: never
      terminalAt?: never
      childResultItemId?: never
      parentSettlementRevision?: never
      releasedUnusedBudget?: never
      settledAt?: never
    }
  | {
      state: 'child_terminal'
      terminal: ChildAllocationTerminal
      inclusiveBudgetUsage: BudgetUsage
      terminalAt: string
      childResultItemId?: never
      parentSettlementRevision?: never
      releasedUnusedBudget?: never
      settledAt?: never
    }
  | {
      state: 'settled'
      terminal: ChildAllocationTerminal
      inclusiveBudgetUsage: BudgetUsage
      terminalAt: string
      childResultItemId: string
      parentSettlementRevision: number
      releasedUnusedBudget: BudgetUsage
      settledAt: string
    }
)
```

`delegate` accepts one child per tool call; a model may return several delegate calls in one batch, and each admitted child becomes independently runnable immediately, so all isolated read-only **and mutating** children may execute concurrently within frozen budget/concurrency limits. Only parent integration is serial. Objective/context arrays, requested ceilings, and inline capability arrays (max 32 ids each) have ordinary schema/byte/count bounds; artifact references must already be readable by the parent. The model never supplies an authority/CAS grant ref: the Supervisor validates ids, intersects the inline request with parent capabilities/policy/mode, publishes `ChildCapabilityGrantV1`, and rejects `read_only` plus source-write. Provider call ids are not assumed Run-global: the stable delegate `opId` and idempotent `admissionKey` are derived from parent Run, owning `ToolBatchItem.itemId`, call index/id, and canonical request digest. `ChildHandleItem` preserves that full identity. The local admission effect is `retry` only because the key makes repeated admission return the identical child; it never aliases a later batch or creates a duplicate. Its durable operation/capability grants bind requested mode, ceiling, capability intersection, verifier mode, and any derived unverified-helper consent. A mutating-success `ChildPatchManifest` is deterministically derived from the admitted-fork and result `SourceManifest`s: `admittedForkBaseRef` equals the child RunSpec base, `resultSourceRef`/`diffRef` equal the decoded terminal child `RunResult`, operations are exactly the corresponding `WorkspaceDiffV1` projection, unique, and byte-sorted `cliq-exact-path-v1`; expected/result entry digests bind the canonical typed SourceManifest entry, and `patchDigest` is SHA-256 over the JCS manifest with that member omitted. Storage recomputes the operation set and `diffRef`; text patches or caller-selected changed-path lists are rejected.

Child terminal projection is exact. A success terminal's `resultRef` decodes the
child Run's sole committed `RunResult` and equals `Run.resultRef`; failed or
cancelled terminal bytes instead require `terminalDetailRef` equal the child
Run's exact terminal detail and structurally forbid a result. Allocation
terminal, owned `ChildResultItem`, child Run id/mode/status, result-or-detail,
patch ref, and inclusive usage are byte-identical. Every branch repeats one
`ChildResultModelContentV1` ref/digest; `contentDigest` omits itself under JCS.
For success, its summary string equals the UTF-8 in the child RunResult's exact
`ModelTextV1.summaryRef`; for failed/cancelled, it contains only the child's
status and terminal reason. It contains no result/detail/diagnostic/policy/
grant/evidence ref, principal, path, or credential. This bounded ref-free
artifact—and never the authority item—is the child payload admitted to parent
model context or an await ToolResult. A child row, unrelated RunResult, loose
diagnostic, or caller-composed summary cannot settle an allocation.

Child assembly/policy derivation is an equation, not an adapter choice. The child inherits the parent's exact provider/model/endpoint, runtime/guest, context/compaction, instruction, skill, model-retry, and algorithm identities. `zero_cost` and a still-valid trusted price table are copied exactly; no external pricing authority is created during delegation. The Supervisor filters the parent's `ToolContractManifestV1` to the byte-sorted requested-and-granted exposed built-in **names** and MCP registrations; `read_only` additionally removes every entry whose access is not `read|plan`, shell, source-write, publication, dependency scripts, and mutating delegation. `mcpServers`, exposed tool names, tool retry entries, and credential refs are recomputed exactly from that filtered manifest; every ref is a subset of the parent closure and no refreshed registry may enter. It emits a new child assembly/digest and a new `RunPolicySnapshotV1` with the same engine/mode/decision rules restricted by the grant, setting every ungranted action class to `deny`.

Verifier/dependency derivation is equally closed. `inherit_parent` sets `childVerifierSpecRef` to the exact parent verifier spec and `childDependencyPolicyRef` to the exact parent policy when present; `none` uses the canonical empty VerifierSpec, requires `childDependencyPolicyRef` absent, and requires the derived consent. `childCredentialGrantRefs` is the byte-sorted unique union recomputed from the child provider, filtered MCP revisions, and inherited dependency policy, contains no other ref, and is a subset of the parent's frozen union. `ChildCapabilityGrantV1` binds all those refs plus parent refs, full delegate identity, granted set, child assembly/tool/policy refs, verifier mode, budgets, and deadline. `grantCoreDigest` hashes JCS with both digest fields and `derivedUnverifiedConsentRef` omitted; `grantDigest` omits only itself. The child RunSpec must name the exact assembly/policy/verifier/dependency/credential/consent refs, and storage validates parent request + operation grant + capability grant + child allocation + child admission atomically. A child never inherits a broader parent manifest merely because the parent could use it.

Admission atomically reserves the direct parent's allocation, creates the child/spec/context/base fork, appends `ChildHandleItem`, and resolves the delegate call. `read_only` removes mutation/publish capabilities. `mutating` receives a private fork of the parent's current ready workspace state. `inherit_parent` freezes the applicable parent verifier set; `none` is legal only through the exact derived consent rule and its result cannot be delivered directly.

`await_children` accepts only unique direct child handles owned by this parent, in supplied deterministic order. It freezes that order plus the owning batch id/call id/call index into an `await_tool` child subject; provider call id alone is never identity. An empty list is invalid. If every child is already terminal, the same reducer runs without entering waiting. Otherwise it releases the parent lease. When the set becomes satisfied, one transaction settles allocations and appends exactly one wait-set/identity-matched `ChildResultItem` per child in order, then computes `successfulMutatingChildren` as precisely those items with `mode='mutating'` and `status='succeeded|completed_unverified'`. If that list is empty, an `await_tool` subject appends the normalized await `ToolResultItem` containing **all** ordered child results—including failed/cancelled mutating children—and advances the exact original batch; a `finalize_settlement` subject installs the `child_results` agent frontier with the same ordered results. Declared mutating mode alone never forces an empty merge frontier.

A model cannot finalize around live delegated work. If a positively complete no-tool model turn arrives while any direct child allocation is nonterminal or terminal-but-unsettled, storage durably keeps its `ModelTurnItem` but creates **no** `FinalCandidateItem`. Instead it freezes every outstanding direct child in Run-id order into a `finalize_settlement` child subject tied to that model turn and releases the lease. Once settled (and after any required serial patch merges), the premature final text remains excluded from the next context manifest, normalized `ChildResultItem`s enter context, and the reducer returns to an agent frontier with cause `child_results`. The model must produce a new complete final turn against those results. Thus child completion can neither be silently ignored nor force unverifiable text into finalization.

If a StopIntent arrives while any direct child allocation is nonterminal—even when the model never called `await_children`—the stop reducer creates a `stop_settlement` child subject over every outstanding direct child in deterministic Run-id order and cascades the stop. When replacing an active await subject it carries the exact await origin. Child terminal commits append audit-only `ChildResultItem`s bound to that StopIntent and settle allocations; they never return child-success payload to the model. After the last settlement, an await origin receives exactly one identity-matched `ToolResultItem(outcome='cancelled')` with a typed stop notice; a no-await stop creates no ToolResult. In either case the reducer closes the remaining batch suffix and evaluates terminal quiescence without resuming the model.

If `successfulMutatingChildren.length > 0`, that transaction instead installs a `ChildMergeBatchItem`/tool frontier containing synthetic stable merge call ids for only those successful patch-bearing children, preserving their relative wait-set order, and its exact resume kind (`await_tool` or `finalize_settlement`). Failed/cancelled and read-only `ChildResultItem`s remain in the ordered final await result/context but never create merge calls. Each merge is a separately claimed `workspace-rollback-retry` built-in tool and uses the atomic post-effect Checkpoint contract. A conflict appends a structured merge error and returns diagnostics plus every already known child result to the agent without applying later children. Otherwise the final merge either appends the await ToolResult containing all ordered child results and resumes the original batch, or installs the child-results agent frontier for finalize settlement. Cancellation/deadline skips undispatched merges and evaluates terminal quiescence. No child item, merge, or wake is inferred from Session text.

Rules:

- child capabilities and token/cost/tool/repair allocations are the intersection of its requested spec and the parent's durably reserved remaining ceilings;
- child wall time is capped by the parent's remaining absolute deadline; child depth and direct-nonterminal-child concurrency are enforced at durable admission;
- every child owns its own context items, lease, Journal, Checkpoints, and workspace generation;
- all independently isolated children may execute concurrently within the direct-child ceiling;
- mutating children return immutable patches/results;
- the parent merges child patches serially into its private workspace and verifies the combined result;
- parent and child never share a mutable working directory;
- waiting for children releases the parent's worker and execution lease.

`child_allocations` stores exactly `ChildAllocationV1`, uniquely keyed by `(parentRunId,childRunId)` and by the delegate identity/admission key. The row's additive reservation is exactly `grantedAdditiveCeilings: BudgetUsage`; wall authority is the absolute `childDeadlineAt`, while depth/concurrency are the separate normalized safe integers shown. `mode` equals both capability grant and terminal payload. `reserved` forbids every terminal/usage/settlement field. `child_terminal` requires exactly one status/mode-valid terminal payload plus nonnegative safe-integer inclusive usage no greater than the granted ancestor-inclusive additive ceilings and forbids settlement fields. `settled` preserves those terminal bytes, requires the identity-matched owned `ChildResultItem`, the exact parent revision that moved actual usage to consumed, and component-wise `releasedUnusedBudget = grantedAdditiveCeilings - inclusiveBudgetUsage`; it is immutable. A child terminal transaction always commits the child result/usage into that row, but **never mutates a running parent's row or revision**. The parent's reservation therefore remains conservatively held and a live parent worker does not become stale merely because a child finished. Direct-child concurrency slots derive from child Run terminal status, not settlement timing.

The parent settles `child_terminal` rows only inside its own next expected-revision state transaction, explicit await reducer, Checkpoint boundary, or stop reducer; settlement moves inclusive usage from `budgetReserved` to `budgetConsumed` exactly once and appends the appropriate ChildResult item. The sole asynchronous parent mutation is safe: when the parent is already lease-free waiting on the exact child set, the final child transaction may also settle that set and install its matching wake/merge/stop frontier atomically. If the parent is running or no longer has that subject, only the allocation row changes. Startup recovery idempotently scans satisfied child subjects/terminal allocations and performs the same revision-checked reducer, so a crash cannot strand a waiting parent or double-settle usage.

All parent/child and delivery drift merges use frozen `cliq-diff3-v1`; “may merge” is not an implementation choice. Per path, exact base/current/desired digest equality resolves unchanged/already-applied/one-sided changes first. Only same-type, same-mode regular UTF-8 files without NUL may text-merge. The algorithm splits while retaining line terminators, computes deterministic Myers shortest-edit scripts from base to current and base to desired with lowest-base-index then deletion-before-insertion tie breaks, represents edits as half-open base-line ranges, and accepts only disjoint edits or byte-identical replacements of the identical range. It applies accepted edits in base order without conflict markers. Every other overlap—binary, symlink, type/mode, delete/modify, add/add with different bytes, or overlapping nonidentical text—returns a structured conflict before verification/publication. `assemblyRef` pins the algorithm version.

Invocation retries remain Journal attempts inside the same Run. A user-requested retry after any terminal outcome is a new admitted Run; delivery is likewise a new `operation='delivery'` Run linked to, but never mutating, the source RunResult.

## 13. Verification And Bounded Repair

### 13.1 Verifier Source

Required verifier definitions come only from:

- explicit CLI/API input;
- trusted `.cliq/config` loaded after Workspace Trust.

`AGENTS.md`, skills, package scripts, and model suggestions may propose checks, but cannot silently add, remove, or weaken a required gate. The complete verifier spec, timeouts, retry policy, command identity, and environment requirements are frozen into the RunSpec.

A trusted `.cliq/config` verifier definition is a declarative gate request, not permission to inspect or execute its command or read an external input. Complete executable/environment identity and every external-read digest must be resolved **before** `run.submit` can commit: an interactive client may obtain the exact read/identity authorization and then submit, while noninteractive submission without it returns `AUTHORIZATION_REQUIRED` and creates no Run. On macOS strong execution, resolution is against the pinned guest toolchain identity, not the host path. RunSpec never contains an unresolved command.

The resolved chain is one exact set of immutable artifacts. `VerifierCommandV1.commandDigest`, `VerifierEnvironmentV1.environmentDigest`, `VerifierSpec.specDigest`, every verifier `entryDigest`, `VerifierAuthorizationTemplateV1.templateDigest`, and `VerifierPlan.planDigest` are SHA-256 over RFC 8785/JCS bytes with only their own digest member omitted. Verifier ids are unique; indices are contiguous from zero. Command argv retains request order and contains only bounded `non_secret_literal` values; environment variables are unique and byte-sorted by name; cwd and writable roots are canonical admitted-root-relative paths, with unique byte-sorted writable roots. The environment's command ref/digest must decode to the exact same id/version, its source projection and runtime/guest identities equal the RunSpec/RunAssembly, and guest refs are both present or both absent according to the selected backend. A workspace script's workspace identity/path/digest and mandatory interpreter ref/digest reproduce the consumed execution-identity grant exactly. `InterpreterIdentityV1.identityDigest` omits itself under JCS and resolves one retained signed guest-toolchain executable by id/path/version/digest using only `script_path_as_first_argument-v1`; shebang lookup, host PATH, ambient shell, and an optional implementation-chosen interpreter are forbidden. The spec entry repeats the exact command/environment refs and digests; the plan repeats the exact spec/entry/command/environment bytes and only adds the current candidate/result and attempt bound. Unknown fields, shell strings, raw secret arguments/environment, undeclared writes, network, mutable executable paths, and alternate command/environment artifacts fail admission or launch before I/O.

Execution permission is a second grant. Because a future candidate digest does not exist at admission, an admission-time allow creates one `VerifierAuthorizationTemplateV1` per verifier entry, bound to the exact Run/spec/index/id/version/entry, command and environment refs/digests, source projection, maximum candidate generations `repairAttempts+1`, that verifier's attempt ceiling, and Run deadline. When a candidate becomes durable, the Supervisor atomically consumes one bounded template allowance and mints the exact per-candidate launch grant binding `resultSourceRef`; the broker accepts only that grant. Without a matching template/user policy, the exact candidate produces a typed `verifier_launch` approval subject. Workspace Trust and pre-admission identity-read authorization never imply either template or launch permission.

### 13.2 Outcomes

- `passed`: produce a receipt for the exact immutable result source digest.
- `assertion-failed`: return structured diagnostics to the agent if repair budget remains.
- `infra-failed`: do not trigger model repair. It may be recorded only after positive evidence proves the verifier's complete process containment is dead and source/ephemeral effects are quiescent or rolled back. Once proved, apply only its frozen same-digest verifier retry count, then fail a required verifier as `verifier_infrastructure_failed`.
- `source-mutation`: a completed source digest change or an auditable sandbox violation that identifies a source-write syscall is a kernel safety violation and fails the Run as `verifier_mutated_source` without retry or repair. The kernel does not claim that a verifier-caught/ignored read-only filesystem error is observable as an attempt; the mount still prevents the byte mutation.

There is no automatic flaky classification. Any retry policy is explicit in the frozen verifier spec.

Resource scarcity detected by the Supervisor before a verifier `prepared` fact leaves the lease-free Run `queued` but temporarily ineligible; it consumes no attempt and FIFO eligibility is re-evaluated on a committed capacity/backend change. There is no `waiting(resource)` state or wake reducer. After a claim, verifier-owned timeout, signal, spawn error, sandbox denial unrelated to source mutation, missing executable, or resource failure becomes infrastructure only after all-descendant death/quiescence proof. Until then the attempt is `unknown`, its exact Journal/SandboxLaunch/containment graph remains the recovery frontier under the active Run, and no concurrent retry or gating receipt exists. The trusted Supervisor repeatedly performs only kill/fence/death inspection for that same containment; once positive proof exists it commits the exact failed/receipt/retry-or-stop reducer. It never creates a `ReconciliationSubject`, because verifier execution has no target status-query contract and public `probe_now` cannot resolve it.

Stop precedence is closed: detected source mutation/integrity violation is fatal first; otherwise a user/parent cancellation stops as the corresponding cancelled reason; otherwise Run deadline stops as `budget_exhausted`; only then may verifier-owned timeout/signal/launch/resource behavior classify as infrastructure. Cancellation/deadline termination produces a typed verifier-stop/evidence item after death proof, not an `infra_failed` receipt, and cannot consume verifier retry capacity or enter repair.

Advisory verifiers may use only their frozen same-digest retry count. Their pass, assertion, or infrastructure receipts are inspectable but never trigger agent repair, never gate or alter terminal status, and never compensate for a required verifier. A source-mutation or other kernel-integrity violation remains fatal even when the verifier is advisory. With no required verifiers, all nonfatal advisory outcomes still end as `completed_unverified(no_required_verifier)`.

A repair attempt is consumed at the authorization boundary, not when a later model response happens to arrive. When a required verifier set has an assertion failure and repair remains, one SQLite transaction appends the bounded diagnostic Run item, increments this Run's `repairCount`, increments `budgetConsumed.repairAttempts` (and retains any ancestor allocation), advances `nextStep='agent'`, increments revision, and emits the event. Recovery therefore sees either no authorized repair or one fully counted repair frontier; retries of that repair's model invocation do not increment the repair counter again.

Repair diagnostics have one closed audit-to-model projection. `VerifierRepairDiagnosticV1.diagnosticDigest` and `VerifierRepairModelContentV1.contentDigest` are SHA-256 over RFC 8785/JCS with only their own digest member omitted; every ref/digest pair rehashes the named artifact. Each diagnostic names an `assertion_failed` `VerificationReceipt` from the current candidate and verifier plan, copies that receipt's exact stdout/stderr refs, and matches its Run, verifier id, result source, and identity-matched `VerifierResultItem`. Raw stdout/stderr remain audit-only. `cliq-verifier-repair-redaction-v1` is deliberately content-minimizing rather than heuristic: it emits exactly `Verifier <JCS verifierId> failed an assertion (exit <base-10 exitCode>). Revise the candidate and try again.` as the NFC `message`, where the receipt must have `terminationReason='exit'` and a nonzero safe-integer exit code. It copies no stdout/stderr byte, path, environment value, secret-like substring, ref, digest, principal, or containment fact into `VerifierRepairModelContentV1`; the JCS artifact is at most 4,096 bytes.

`RepairDiagnosticItem.failedVerifierResultItemIds` and `diagnostics` are equal-length, nonempty, and ordered by the corresponding contiguous `VerifierPlan.entries` indices. Every result item is unique, required, assertion-failed for this candidate, and its exact receipt is the same receipt named by the same-index diagnostic. The entry repeats the diagnostic's verifier id, diagnostic ref/digest, and model-content ref/digest byte-for-byte; verifier ids and result item ids are unique. The repair reducer publishes all diagnostics and model-content artifacts before the single counter/frontier transaction. Normal prompt construction decodes only the ordered `VerifierRepairModelContentV1` artifacts; it never serializes the audit diagnostic or verifier output.

If required assertions still fail when the frozen repair budget is exhausted, the Run terminates as `failed` with reason `verification_failed`. Candidate source, diff, diagnostics, and failed receipts remain inspectable, but they are not a verified `RunResult` and cannot enter the safe delivery path. `completed_unverified` means only that the RunSpec declared no required verifier.

### 13.3 Verification Receipt

Each receipt contains at least:

- Run and verifier identity/version;
- `resultSourceRef` and source digest;
- exact `VerifierCommandV1` ref/digest and normalized arguments;
- exact `VerifierEnvironmentV1` ref/digest;
- start/end timestamps and duration;
- exit code and termination reason;
- stdout/stderr artifact references and explicit truncation flags;
- lease epoch, all-descendant containment/death-quiescence evidence reference, optional audited sandbox-violation evidence, and receipt digest.

The receipt digest is SHA-256 over the RFC 8785/JCS canonical receipt object with its `receiptDigest` member omitted; the CAS artifact digest is verified separately, so the schema is not self-referential. Its command/environment refs and digests must equal the current `VerifierPlan` entry, which equals the frozen spec/template and immutable Journal request. Storage rejects a receipt with a free-form or recomputed environment fingerprint, even when its source and exit fields otherwise look valid.

Verifiers execute against a frozen read-only source view. Any detected/auditable attempted source write or any completed source-byte mutation invalidates the receipt and terminates the Run as `failed(verifier_mutated_source)`; it is neither an assertion diagnostic nor eligible for agent repair. Cliq does not claim to observe a denied write that the program catches and the sandbox backend does not audit.

### 13.4 Terminal Invariant

```text
Run.status == succeeded
=> immutable RunResult exists
=> every required verifier passed
=> every required receipt binds RunResult.resultSourceRef
=> RunResult and receipts are durable before the terminal Run commit
```

This invariant is enforced at the storage API, not merely by the verifier reducer. Generic Run compare-and-swap cannot set any terminal status. `commitRunResult` is the sole transition to `succeeded|completed_unverified` and first requires `stopIntentRef` absent, `cancelRequested=false`, no active stop proposal, and the same terminal-quiescence/closed-frontier checks. `succeeded` validates the frozen required verifier set and exact receipt/inherited-provenance closure in the same transaction; `completed_unverified` validates that the frozen required set is empty. Required verifier ids are unique. Each required verifier maps one-to-one to a unique passed receipt, and that receipt must be the `receiptRef` of the highest eligible `opKind='verifier'` Journal `completed` attempt whose immutable request binds the exact verifier id/version, `VerifierSpec`, command, environment, and `resultSourceRef`; one receipt cannot satisfy two requirements. Dependency closure is equally storage-enforced: `RunResult.dependencyPlanRef` is absent iff `RunSpec.dependencyPolicyRef` is absent/disabled; otherwise it equals the current candidate's `VerifierPlan.dependencyPlanRef` and has a **current-Run-owned**, identity-matched `DependencyReadyItem`, completed acquisition attempt, unchanged candidate source digest, and exact ready Checkpoint whose id equals `readyCheckpointId` and whose decoded workspace-entry tree digest equals `installedTreeDigest` for that candidate/plan. Inherited delivery verification provenance revalidates only the source Run's identical Journal-backed verifier closure; it cannot stand in for the delivery Run's dependency readiness. For `RunSpec.operation='agent'`, both current finalize frontier and RunResult forbid `deliveryTerminalProjectionEvidenceRef`. For `operation='delivery'`, both require the same exact forward-finalize `DeliveryTerminalProjectionEvidence` ref, whose plan/result/result-item/projection fields revalidate against the carried closure/frontier and current descriptor observations. `commitTerminalStop` is the sole failure/cancellation path; it requires the current winning StopIntent, derives status/reason/detail from it, and enforces terminal quiescence in the same transaction.

## 14. Result And Delivery

```ts
type RunResult = {
  schemaVersion: 1
  runId: string
  baseSourceRef: ArtifactRef
  resultSourceRef: ArtifactRef
  diffRef: ArtifactRef
  dependencyPlanRef?: ArtifactRef
  verificationClosureRef: ArtifactRef
  deliveryTerminalProjectionEvidenceRef?: ArtifactRef
  verificationReceiptRefs: ArtifactRef[]
  verificationProvenanceRef?: ArtifactRef
  summaryRef: ArtifactRef
  createdAt: string
}
```

The default result is immutable and reviewable. A successful agent Run does not automatically write the user's real workspace.

`cliq apply <runId>` descriptor-captures current real-workspace SourceManifest A as part of admission, installs A in RunSpec/initial `delivery:merge`, installs its distinct restorable WorkspaceStateManifest W_A in the initial Checkpoint, and then creates a narrow delivery Run that:

1. uses the already-admitted immutable current-workspace capture without changing it;
2. applies the verified diff in a private merge view;
3. detects conflicts and result digest drift;
4. reruns required verifiers when the merged result reference differs; when it is the identical content-addressed `resultSourceRef`, validates and records explicit inherited-verification provenance instead of manufacturing delivery-owned receipts;
5. requests explicit materialization permission after the proof-carrying verification closure is durable;
6. journals each real-workspace path publication as a queryable/reconcilable effect using the operation-specific probed platform primitive: no-replace for create, exchange for replace, and no-replace move-to-quarantine for delete, with retained displaced preimages;
7. publishes the exact final workspace projection evidence and only then finalizes the delivery result with both verification and publication proof refs.

A delivery Run is deliberately non-agentic: its `RunSpec.objectiveRef` equals
the decoded source Run's exact `RunSpec.objectiveRef`, and it inherits the exact
source assembly/verifier identities, source projection, and immutable
`dependencyPolicyRef`; `run.apply` has no alternate objective field and the
final delivery admission digest binds that inherited ref. It does **not**
inherit an admission-time dependency plan or source-Run dependency readiness.
Each delivery merge candidate derives its own candidate-bound
`DependencyAcquisitionPlan` from that policy and exact manifest/lockfile
digest. When the policy is enabled, the delivery Run executes and records its
own setup even for an identical `resultSourceRef` and plan; only a ready
Checkpoint already owned by that same delivery Run may satisfy recovery without
another dispatch. The delivery Run sets `modelTokens=0`, `costMicros=0`,
`repairAttempts=0`, `childDepth=0`, and `childConcurrency=0`, and accepts only
wall/tool ceilings through `run.apply`. It never invokes a model or repairs
verifier assertions. Candidate-bound dependency setup consumes one delivery
tool charge on its first completed execution, then the verifier plan runs
against the merged candidate; an assertion proposes `verification_failed`,
while infrastructure follows the frozen verifier retry policy. Optional
verifier execution grant ids in `run.apply` mint delivery-scoped templates;
otherwise an exact launch may wait for approval. This keeps delivery
deterministic and makes a failed drift check return to a new agent Run rather
than smuggling an undefined repair frontier into apply.

Publication is descriptor-anchored. The broker opens and holds the admitted real-workspace root as a no-follow directory handle and revalidates device/file identity against the delivery capture. Every parent component is walked relative to that handle with no symlink traversal or escape: Linux uses `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`; macOS uses `openat(O_DIRECTORY|O_NOFOLLOW)` one component at a time plus `fstat` identity checks. Leaf temp/create/exchange/quarantine operations use only the resulting directory descriptors; an absolute path is never reopened after validation. Any root/ancestor identity change enters typed publication reconciliation before another write.

`DeliveryPlan.forwardOperations` includes every missing parent directory before its children and contains only `mkdir|create|replace|delete`. A directory create requires expected absence, `mkdirat`, normalized mode `0755`, descriptor re-open/no-follow verification, and directory fsync. Recovery may accept an already-created directory only when its identity/type/mode and contents are exactly the prefix permitted by this same immutable plan; unexpected contents wait for reconciliation. The separate immutable `abortOperations` list enumerates planned delivery-created directories deepest first. If its forward mkdir never completed, a read-only reducer proves there is no creation receipt and the path is still absent, appends `not_created`, and advances without a maintenance claim. Otherwise maintenance removes it only when its creation receipt belongs to this delivery and it is proven empty; it records `retained_planned_descendant` when the only contents are already-completed desired descendants, and waits on any unexpected content. It never removes a pre-existing directory. Each operation has a stable id, required evidence, and reconciliation predicate; multi-path publication remains explicitly non-atomic.

Every leaf plan freezes exactly the unpredictable sibling components required by its union branch, their expected absence, desired digest/type/mode, admitted destination preimage, parent identity/linkage, and operation id; none is derived after a crash. Replace reconciliation follows one versioned state machine: `none -> desired_staged_and_fsynced -> exchanged (destination=desired, staging=actual displaced) -> displaced_quarantined -> displaced_preserved_in_CAS -> leaf_completed`. Create uses its stage/no-replace subset; delete uses destination-to-quarantine/preserve and has no staging state. Each observation is descriptor-relative and validates all involved identities/digests; a field forbidden by the operation branch makes the plan invalid rather than ignored.

A leaf is one indivisible publication envelope and one `toolCalls` reservation: staging/exchange or no-replace, preservation of the actual displaced bytes in CAS, exact transient cleanup, and parent fsync. Before deleting a staging/quarantine sibling, the Supervisor commits a `PublicationPathProgressItem` that binds the destination evidence, actual preserved preimage CAS ref, and exact transient identity while the same Journal attempt remains open. A crash before that item leaves the sibling intact; a crash after it can prove either the exact pending sibling or its exact absence and cannot lose the preimage association. Journal `completed` plus `PublicationPathResultItem` is legal only after every transient for that leaf is absent and the directory is fsynced. “Destination has desired digest” alone is never completion.

Cancellation, deadline, or another StopIntent forbids a new semantic forward operation, but it cannot strand a claimed publication envelope. The already-reserved envelope may perform only bounded no-new-semantic-effect recovery after stop: status/identity queries, CAS preservation, removal of its exact staging/quarantine sibling, fsync, and terminal evidence. It then switches the delivery frontier to `abort_cleanup`; undispatched semantic forward operations are skipped, and the deterministic deepest-first abort list handles only delivery-created directories. Abort cleanup and completion of an already-claimed envelope consume no additional `toolCalls` and are allowed after deadline because they reduce external ambiguity rather than create new desired state. Failure to prove exact identity/emptiness remains `waiting(reconciliation)`; it is never guessed away. Normal success never executes the abort list. Thus one linear reducer never mixes success and rollback branches, and terminalization requires the chosen branch complete with no transient sibling.

Verification receipts always retain the `runId` that actually executed the verifier. A delivery Run may reuse source-Run receipts only when its normalized private merge view resolves to the exact same content-addressed `resultSourceRef`, the source Run is still `succeeded(verified)`, every receipt/artifact digest and the frozen `VerifierSpec` validate, and an immutable provenance artifact binds the delivery Run, source RunResult, identical result reference, verifier spec, and receipt set. If any condition differs, the delivery Run executes the required verifiers and produces receipts bound to its own `runId`. Arbitrary historical receipts or digest-only similarity are never proof.

If delivery fails, the original agent Run remains succeeded for its original immutable result. A partial or ambiguous materialization never rewrites that truth; the delivery Run waits for reconciliation or fails independently. Multi-path application is not claimed to be atomic, and the explicit apply UI requires a quiescent human workspace; same-user concurrent writers are outside global fencing, but any displaced bytes observed at an atomic swap must be preserved rather than silently lost.

Delivery adds no new terminal-reason enum. A deterministic `cliq-diff3-v1` conflict proposes `runtime_failed` with typed detail subtype `delivery_merge_conflict`; a positively failed forward/cleanup/abort operation proposes `runtime_failed` with subtype `delivery_publication_failed` and exact plan/operation/evidence refs. An ambiguous publication remains waiting and cannot be mislabeled failed. Cancellation/deadline/integrity StopIntent precedence still wins according to section 6.

## 15. Surfaces And Ecosystem Thin Waist

The kernel exposes one versioned local control protocol used by CLI, TUI, JSONL, and RPC adapters.

The exact initial method names are `control.hello`; `session.create|list|get|fork|compact|handoff.create`; `run.submit|list|get|attach|cancel|approve|input|reconcile|diff|result|apply`; `authorization.create|list|revoke`; `mcp.register|refresh|list`; `artifact.get`; and `supervisor.status`. Authorization and MCP registry methods are Supervisor-owned user administration, not adapter-specific Run lifecycle methods.

Session continuity remains first-class but non-executing. The exact public methods are `session.create`, `session.list`, `session.get`, `session.fork`, `session.compact`, and `session.handoff.create`. There is deliberately no public `session.append`, `session.items`, handoff import, bookmark mutation, global active-Session setter, Session lease, or Run-Checkpoint mutation. `session.get` is the bounded item read; root Run terminal publication is the only internal Session append path. `cliq resume` is client composition of `session.get` plus a new `run.submit`, never resumption of an old Session execution. Imported legacy bookmarks/handoffs appear as typed legacy Session items/artifact refs through `session.get` plus `artifact.get`; `session.fork` may use their preserved cursor, but no hidden compatibility mutation method exists. No CLI/TUI/RPC adapter writes SQLite or legacy JSON directly.

The v1 wire contract is generated from one canonical TypeScript/JSON-Schema package. The minimum request contract is closed:

| Method class | Required request identity | Result |
|---|---|---|
| `run.submit` | `requestId`, `admissionKey`, `sessionId`, `expectedContextRevision`, workspace path/identity, <=256 KiB UTF-8 objective, and bounded typed model/budget/policy/verifier/source options plus canonical request digest | authoritative Run snapshot; Supervisor validates/captures/publishes all refs; identical key+digest returns it |
| `run.list` | bounded status/session filter plus cursor/limit default 50/max 100 | snapshots plus next cursor |
| `run.get` | Run id plus independent item/Journal/Checkpoint cursors; each limit default 100/max 1000 and combined metadata max 1 MiB | authoritative snapshot plus ordered typed item refs, Journal metadata/evidence refs, Checkpoint refs, and next cursors |
| `run.attach` | Run id, `afterEventSeq`, max batch 1..1000 | one-transaction Run snapshot, retained earliest/latest/high-water bounds, ordered events through that high-water, and next cursor; explicit cursor-expired error |
| `run.cancel` | `requestId`, Run id, expected revision | post-reducer snapshot |
| `run.approve` | above plus exact waiting ref, `allow|deny`, optional bounded TTL | post-reducer snapshot and decision ref |
| `run.input` | above plus exact waiting ref and inline schema-matching UTF-8/JSON input (max 1 MiB) | Supervisor-published item and post-reducer snapshot |
| `run.reconcile` | above plus exact waiting ref and `probe_now|abandon_run`; no adapter id/evidence payload, and abandonment exists only for an invocation frozen as `manual` | `probe_now` atomically enqueues/returns the persisted dispatch descriptor and post-enqueue snapshot; abandonment returns exact attestation plus terminal snapshot |
| `run.apply` | `requestId`, `admissionKey`, verified source Run id, exact expected source `Run.resultRef`, and bounded inline delivery options | newly admitted delivery Run; Supervisor resolves/publishes refs |
| `authorization.create` | `requestId` plus one bounded read/identity/verifier-execution decision and TTL | opaque principal-owned grant id and canonical target digest; no caller artifact ref |
| `authorization.list` | kind/cursor, limit default 50/max 100 | redacted active/consumed/revoked grant summaries |
| `authorization.revoke` | `requestId`, grant id | active becomes revoked; revoked replay is stable; consumed is an idempotent `already_consumed` no-op summary |
| `mcp.register` | `requestId`, registration id, explicit stdio/HTTP target ids, credential grant ids, stateless assertion, bounded recovery requests | sandbox-probed immutable registry revision or fail-closed error |
| `mcp.refresh` | `requestId`, registration id, expected registry revision | copy current immutable transport/recovery/lifecycle inputs, reprobe, and append a revision; no replacement ids/target and admitted Runs retain the old digest |
| `mcp.list` | cursor, limit default 50/max 100 | redacted registry summaries and manifest digests |
| `run.result/diff` | result-bearing terminal Run id (`succeeded|completed_unverified`) | immutable artifact refs; every nonterminal/failed/cancelled Run returns typed `RESULT_UNAVAILABLE` |
| `artifact.get` | artifact digest, offset, length up to 4 MiB | verified base64 byte chunk, next offset, total size/digest, EOF |
| `session.list` | optional workspace filter, cursor, limit default 50/max 100 | Session summaries plus next cursor |
| `session.get` | Session id, `afterItemSeq`, limit default 100/max 1000 | snapshot plus ordered item refs capped at 1 MiB encoded metadata and next cursor |
| `session.create/fork` | `requestId`, admission key+digest, bounded workspace/source/cursor fields; fork also expected context revision | one idempotent Session snapshot |
| `session.compact` | `requestId`, request digest, Session id, expected context revision, bounded item range and <=256 KiB UTF-8 summary | idempotently replayable post-commit Session snapshot; raw items preserved |
| `session.handoff.create` | Session id, expected context revision and optional cursor | deterministic immutable JSON/Markdown artifact refs |

Every `requestId`, admission key, id, ref, integer, enum, and payload has a schema/count/byte bound before state access. Mutator responses are idempotently replayable by authenticated principal plus method/request id. The closed error union is `INVALID_REQUEST | INCOMPATIBLE_PROTOCOL | NOT_FOUND | REVISION_CONFLICT | WAIT_SUBJECT_MISMATCH | REQUEST_ID_CONFLICT | ADMISSION_KEY_CONFLICT | AUTHORIZATION_REQUIRED | POLICY_DENIED | MODEL_COST_UNKNOWN | BUDGET_EXHAUSTED | RESOURCE_EXHAUSTED | RESULT_UNAVAILABLE | RUN_TERMINAL | CANCEL_REQUESTED | UNSUPPORTED_PLATFORM | UNSUPPORTED_EXECUTION_IDENTITY | ARTIFACT_MISMATCH | RECOVERY_REQUIRED | EVENT_CURSOR_EXPIRED | RATE_LIMITED | INTERNAL`. Revision conflict inlines the exact current Session-or-Run snapshot, wait mismatch returns the exact current `WaitingSubject` ref/digest, and cursor expiry inlines the authoritative `RunSnapshotV1` captured with its bounds; other variants expose only their schema-required retry/range/resource/redacted fields. No generic current ref, snapshot artifact, or arbitrary stack data exists.

There is intentionally no general `artifact.put` write oracle. Client-originated objective, Session summary, input, approval, exact-risk abandonment acknowledgement, and admission/delivery options use their method-specific bounded inline schemas. A reconciliation probe accepts no caller evidence bytes. The Supervisor canonicalizes and publishes allowed inputs to CAS only after authentication, trust/policy validation, and size checks; the exact canonical inline bytes are part of request/admission digests. Internal adapters may pass already verified refs across the application-service boundary, but public JSONL/RPC clients never write the state directory or need a private CAS API.

Raw credential enrollment is intentionally outside this JSON control protocol. Local `cliq auth`/endpoint enrollment uses only the section 5 `CredentialAuthorityOperationV1` state machine and supported platform store under its exclusive per-user lock, then returns opaque `credentialGrantId`/`endpointRegistrationId`; it never writes Run SQLite/CAS, and JSONL/RPC/TUI cannot submit raw secrets. The Supervisor can only validate and redeem those ids through the latest `CredentialAuthorityRecordV1` plus immutable endpoint/binding artifacts. This is a separate secret-store authority, not a hidden Run lifecycle surface; missing/unavailable enrollment returns `AUTHORIZATION_REQUIRED` with a local CLI remediation command. Kernel migration invokes the same idempotent authority before backing up any legacy auth marker and never copies raw legacy keys.

Wire source selectors are requests, not authoritative projection entries. An optional `readGrantId` names a user-owned registered grant, not an artifact ref. The Supervisor maps every include to exact `SourceIncludeAuthorizationV1`: no grant is accepted only for descriptor-proven tracked/nonignored bytes; ignored bytes atomically consume the exact read-scope grant into its receipt-bound branch. Excludes carry no grant. Repository config can add requested selectors but cannot provide or choose an authorization ref.

Pre-admission authority uses the same thin waist. `authorization.create` canonicalizes and inspects an exact source scope bound to the canonical workspace identity, a verifier execution-identity target limited to a signed guest-toolchain entry or workspace script, an MCP-stdio target limited to a signed guest-toolchain or retained RuntimeBundle `mcp_server` executable, or an exact workspace+lockfile install-script decision. It records principal/target/digest/purpose/expiry as an opaque grant and returns only its id; it never executes the target or grants a Run effect. A verifier request must carry the matching target-kind identity grant, and may carry a matching verifier-execution grant whose canonical request digest/identity/bounds let admission mint the Run-scoped template in section 13.1. Without the latter the accepted Run may later wait for verifier-launch approval; without required identity/read/install-script authority submission returns `AUTHORIZATION_REQUIRED` and creates no Run. A grant cannot alias the same relative path in another workspace or a host binary to a guest tool id. Revocation prevents unused grants and future admissions, but cannot erase bytes already captured or silently rewrite an accepted Run; `run.cancel`/the Run's own approval subjects control accepted work. Verifier environment and argv values are explicitly non-secret literals only and the Supervisor binds that assertion into authorization/admission digests. Secrets and provider/MCP credentials travel solely as registered credential ids and broker handles, never as raw env/argv strings in a control request, CAS artifact, Journal row, or receipt.

The generated contract uses these exact mutator payloads (query methods use the cursor/limit fields and bounds in the table above):

```ts
type MutationBase = {
  protocolVersion: 1
  requestId: string
  requestDigest: string
}

type BudgetOptions = Partial<RunSpec['budgets']>

type NonSecretEnvValueRequest = {
  kind: 'non_secret_literal'
  value: string
}

type NonSecretArgumentRequest = {
  kind: 'non_secret_literal'
  value: string
}

type SourceSelectorRequest = {
  path: string
  scope: 'entry' | 'subtree'
  readGrantId?: string
}

type VerifierRequest = {
  id: string
  version: string
  required: boolean
  executable:
    | { kind: 'toolchain'; toolId: string }
    | { kind: 'workspace_script'; path: string; expectedDigest?: string }
  argv: NonSecretArgumentRequest[]
  cwd: string
  env: Record<string, NonSecretEnvValueRequest>
  writableEphemeralPaths: string[]
  identityReadGrantId: string
  executionGrantId?: string
  timeoutMs?: number
  retries?: number
  outputLimitBytes?: number
}

type DependencyRequest =
  | { mode: 'none' }
  | {
      mode: 'locked'
      registryEndpointIds: string[]
      credentialGrantIds: string[]
      allowInstallScripts: boolean
      installScriptsGrantId?: string
      maxPackages?: number
      maxDownloadBytes?: number
    }

type RunModelRequest =
  | {
      provider: 'ollama'
      model: string
      endpoint?: never
      modelCredentialGrantIds?: never
    }
  | {
      provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
      model: string
      endpoint: { kind: 'registered'; endpointRegistrationId: string }
      modelCredentialGrantIds: string[]
    }

type RunSubmitRequest = MutationBase & {
  method: 'run.submit'
  admissionKey: string
  sessionId: string
  expectedContextRevision: number
  workspacePath: string
  objective: string
  model: RunModelRequest
  policyMode: 'default' | 'accept-edits' | 'plan' | 'yolo'
  budgets?: BudgetOptions
  sandboxResources?: Partial<SandboxResourceSpec>
  verifiers: VerifierRequest[]
  dependency: DependencyRequest
  sourceIncludes: SourceSelectorRequest[]
  sourceExcludes: Array<Omit<SourceSelectorRequest, 'readGrantId'>>
  maxChangedPaths?: number
  maxChangedBytes?: number
  registeredMcpServerIds: string[]
  skillIds: string[]
  allowUnverified: boolean
}
```

The `RunModelRequest` discriminator is authoritative and unknown/forbidden fields are errors, never ignored. `ollama` has no endpoint or model-credential member and resolves only the exact same-user active `LocalModelRegistrationV1`/managed launch contract above. Every remote provider requires `endpoint.kind='registered'` plus its explicit id; a built-in default is simply an `EndpointRegistrationV1(registrationKind='bundled_default')` whose id the client obtained from `cliq auth`, never a hidden provider-to-endpoint lookup. Every billable branch requires `modelCredentialGrantIds` to contain 1..32 unique ids, each active, purpose `model_endpoint`, owner-matched, and bound to that exact resolved endpoint identity/TLS through the Run deadline. Empty/extra/duplicate/mismatched credentials, endpoint omission, a registered id on Ollama, or a credential member on Ollama fails before capability negotiation, provider/local-service I/O, CAS publication, or Run creation. These normalized branch bytes enter both request and admission-intent digests.

Admission normalizes `RunSubmitRequest.objective` exactly once to NFC, applies
the `RunObjectiveV1` scalar/UTF-8 bounds, publishes that artifact, and installs
its ref as `RunSpec.objectiveRef`; invalid Unicode, NUL, empty, or oversized
input is `INVALID_REQUEST`. The inline string is never a second durable source.

```ts
type AuthorizationCreateRequest = MutationBase & {
  method: 'authorization.create'
  ttlMs?: number
  decision:
    | {
        kind: 'read_scope'
        purpose: 'source'
        workspacePath: string
        expectedWorkspaceIdentityDigest?: string
        path: string
        scope: 'entry' | 'subtree'
        expectedDigest?: string
      }
    | {
        kind: 'execution_identity_read'
        purpose: 'verifier'
        target:
          | { kind: 'guest_toolchain'; guestToolchainManifestId: string; toolId: string }
          | {
              kind: 'workspace_script'
              workspacePath: string
              expectedWorkspaceIdentityDigest?: string
              path: string
              expectedDigest?: string
            }
      }
    | {
        kind: 'execution_identity_read'
        purpose: 'mcp_stdio'
        target:
          | { kind: 'guest_toolchain'; guestToolchainManifestId: string; toolId: string }
          | { kind: 'runtime_bundle_executable'; runtimeBundleId: string; executableId: string }
      }
    | {
        kind: 'verifier_execution'
        verifierId: string
        verifierRequestDigest: string
        executionIdentityGrantId: string
        maxCandidateGenerations: number
        maxAttemptsPerCandidate: number
      }
    | {
        kind: 'dependency_install_scripts'
        workspacePath: string
        expectedWorkspaceIdentityDigest?: string
        lockfilePath: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock'
        expectedLockfileDigest: string
      }
}

type AuthorizationRevokeRequest = MutationBase & {
  method: 'authorization.revoke'
  grantId: string
}

type McpRecoveryRequest =
  | { kind: 'manual' }
  | {
      kind: 'retry'
      acknowledgeDuplicateEffectRisk: true
      idempotencyKeyJsonPointer?: string
    }
  | {
      kind: 'reconcile'
      bundledAdapterId: string
      idempotencyKeyJsonPointer: string
    }

type McpRegisterRequest = MutationBase & {
  method: 'mcp.register'
  registrationId: string
  target:
    | {
        kind: 'stdio'
        executionIdentityGrantId: string
        argv: NonSecretArgumentRequest[]
      }
    | {
        kind: 'streamable_http'
        endpointRegistrationId: string
        credentialGrantIds: string[]
      }
  assertStatelessPerCall: true
  toolRecovery: Record<string, McpRecoveryRequest>
  lifecycle?: {
    launchTimeoutMs?: number
    callTimeoutMs?: number
    maxLaunchesPerCall?: number
  }
}

type McpRefreshRequest = MutationBase & {
  method: 'mcp.refresh'
  registrationId: string
  expectedRegistryRevision: number
}

type RunCancelRequest = MutationBase & {
  method: 'run.cancel'
  runId: string
  expectedRevision: number
}

type RunApproveRequest = MutationBase & {
  method: 'run.approve'
  runId: string
  expectedRevision: number
  waitingOnRef: ArtifactRef
  decision: 'allow' | 'deny'
  ttlMs?: number
}

type RunInputRequest = MutationBase & {
  method: 'run.input'
  runId: string
  expectedRevision: number
  waitingOnRef: ArtifactRef
  input: { kind: 'text'; value: string } | { kind: 'json'; value: unknown }
}

type RunReconcileRequest = MutationBase & {
  method: 'run.reconcile'
  runId: string
  expectedRevision: number
  waitingOnRef: ArtifactRef
  resolution:
    | { kind: 'probe_now' }
    | { kind: 'abandon_run'; acknowledgeExactRisk: true }
}

type RunApplyRequest = MutationBase & {
  method: 'run.apply'
  admissionKey: string
  sourceRunId: string
  expectedRunResultRef: ArtifactRef
  budgets?: { wallTimeMs?: number; toolCalls?: number }
  verifierExecutionGrantIds?: string[]
}

type SessionCreateRequest = MutationBase & {
  method: 'session.create'
  admissionKey: string
  workspacePath: string
  name?: string
}

type SessionForkRequest = MutationBase & {
  method: 'session.fork'
  admissionKey: string
  sessionId: string
  expectedContextRevision: number
  throughItemSeq: number
  name?: string
}

type SessionCompactRequest = MutationBase & {
  method: 'session.compact'
  sessionId: string
  expectedContextRevision: number
  fromItemSeq: number
  throughItemSeq: number
  summaryMarkdown: string
  retainedItemIds: string[]
}
```

Read-only/query payloads are one closed union and deliberately have no `requestId` or `requestDigest` member:

```ts
type ControlQueryRequestV1 =
  | {
      protocolVersion: 1
      method: 'control.hello'
      clientBuild: string
      controlSchemaRange: { min: number; max: number }
      headlessSchemaRange: { min: number; max: number }
      requestedFeatureIds: string[]
    }
  | { protocolVersion: 1; method: 'session.list'; workspacePath?: string; cursor?: string; limit?: number }
  | { protocolVersion: 1; method: 'session.get'; sessionId: string; afterItemSeq?: number; limit?: number }
  | {
      protocolVersion: 1
      method: 'session.handoff.create'
      sessionId: string
      expectedContextRevision: number
      throughItemSeq?: number
    }
  | {
      protocolVersion: 1
      method: 'run.list'
      sessionId?: string
      operation?: 'agent' | 'delivery'
      statuses?: RunStatus[]
      cursor?: string
      limit?: number
    }
  | {
      protocolVersion: 1
      method: 'run.get'
      runId: string
      afterItemSeq?: number
      afterJournalSeq?: number
      checkpointCursor?: string
      itemLimit?: number
      journalLimit?: number
      checkpointLimit?: number
    }
  | { protocolVersion: 1; method: 'run.attach'; runId: string; afterEventSeq: number; limit?: number }
  | { protocolVersion: 1; method: 'run.result' | 'run.diff'; runId: string }
  | {
      protocolVersion: 1
      method: 'authorization.list'
      targetKind?: AuthorizationGrantTargetV1['kind']
      state?: AuthorizationGrantV1['state']
      cursor?: string
      limit?: number
    }
  | { protocolVersion: 1; method: 'mcp.list'; cursor?: string; limit?: number }
  | { protocolVersion: 1; method: 'artifact.get'; digest: string; offset: number; length: number }
  | { protocolVersion: 1; method: 'supervisor.status' }

type ControlMutationRequestV1 =
  | RunSubmitRequest
  | RunCancelRequest
  | RunApproveRequest
  | RunInputRequest
  | RunReconcileRequest
  | RunApplyRequest
  | SessionCreateRequest
  | SessionForkRequest
  | SessionCompactRequest
  | AuthorizationCreateRequest
  | AuthorizationRevokeRequest
  | McpRegisterRequest
  | McpRefreshRequest

type ControlRequestV1 = ControlQueryRequestV1 | ControlMutationRequestV1

type ListMethodV1 = 'session.list' | 'run.list' | 'authorization.list' | 'mcp.list'

type ListCursorPayloadV1 = {
  schemaVersion: 1
  cutId: string
  afterOrdinal: number
  macBase64url: string
}

type ListReadCutEntryV1 = {
  schemaVersion: 1
  cutId: string
  ordinal: number
  sortCreatedAt: string
  stableId: string
  payload:
    | { method: 'session.list'; value: SessionSummaryV1 }
    | { method: 'run.list'; value: RunSnapshotV1 }
    | { method: 'authorization.list'; value: AuthorizationGrantSummaryV1 }
    | { method: 'mcp.list'; value: McpRegistrySummaryV1 }
  rowDigest: string
}

type ListReadCutV1 = {
  schemaVersion: 1
  cutId: string
  ownerPrincipalId: string
  method: ListMethodV1
  normalizedFilterDigest: string
  normalizedLimit: number
  createdAt: string
  expiresAt: string
  cursorSecretBase64url: string
  entryCount: number
  entriesDigest: string
  cutDigest: string
}
```

`statuses` is unique and byte-sorted with at most the closed `RunStatus` cardinality. List defaults/maxima, `run.get` independent defaults/maxima and combined 1 MiB metadata cap, attach `1..1000`, artifact `1..4 MiB`, and the hello feature maximum 64 are exactly the table values above. Safe-integer, unknown-field, principal, and path rules apply before any state read; an explicit `requestId|requestDigest|admissionKey` on a query is an unknown-field error, not silently ignored. List cursor strings use the exact cut protocol below and remain at most 512 UTF-8 bytes.

The public result side is equally closed; adapters do not project their own snapshots, cursor shapes, or redaction rules:

```ts
type ArtifactDescriptorV1 = {
  schemaVersion: 1
  ref: ArtifactRef
  digest: string
  sizeBytes: number
  mediaType: string
}

type SessionSnapshotV1 = {
  schemaVersion: 1
  session: Session
}

type SessionSummaryV1 = {
  schemaVersion: 1
  id: string
  workspaceIdentityRef: ArtifactRef
  name?: string
  parentSessionId?: string
  contextRevision: number
  latestItemSeq: number
  createdAt: string
  updatedAt: string
}

type RunSnapshotV1 = {
  schemaVersion: 1
  operation: 'agent' | 'delivery'
  run: Run
  latestRunItemSeq: number
}

type RunItemReferenceV1 = {
  schemaVersion: 1
  itemId: string
  itemSeq: number
  payloadRef: ArtifactRef
  payloadDigest: string
  createdAt: string
}

type AuthorizationGrantSummaryV1 = {
  schemaVersion: 1
  grantId: string
  state: AuthorizationGrantV1['state']
  targetKind: AuthorizationGrantTargetV1['kind']
  purpose: 'source' | 'verifier' | 'mcp_stdio' | 'dependency_install_scripts'
  targetDigest: string
  useCount: 0 | 1
  rowVersion: number
  createdAt: string
  expiresAt: string
  consumedAt?: string
  revokedAt?: string
}

type McpRegistrySummaryV1 = {
  schemaVersion: 1
  registrationId: string
  registryRevision: number
  transport: 'stdio' | 'streamable_http'
  stateModel: 'stateless_per_call'
  toolCount: number
  toolsListDigest: string
  manifestDigest: string
  registrationReceiptRef: ArtifactRef
  createdAt: string
}

type RuntimeBundlePublicSummaryV1 = {
  schemaVersion: 1
  runtimeBundleRef: ArtifactRef
  bundleDigest: string
  bundleVersion: string
}

type ControlMethodV1 =
  | 'control.hello'
  | 'session.create' | 'session.list' | 'session.get' | 'session.fork' | 'session.compact' | 'session.handoff.create'
  | 'run.submit' | 'run.list' | 'run.get' | 'run.attach' | 'run.cancel' | 'run.approve' | 'run.input'
  | 'run.reconcile' | 'run.diff' | 'run.result' | 'run.apply'
  | 'authorization.create' | 'authorization.list' | 'authorization.revoke'
  | 'mcp.register' | 'mcp.refresh' | 'mcp.list'
  | 'artifact.get' | 'supervisor.status'

type ControlResultV1 =
  | {
      method: 'control.hello'
      protocolVersion: 1
      serverBuild: string
      controlSchemaRange: { min: 1; max: 1 }
      headlessSchemaRange: { min: number; max: number }
      enabledFeatureIds: string[]
      supervisorInstanceId: string
      activeRuntimeBundle: RuntimeBundlePublicSummaryV1
    }
  | { method: 'session.create' | 'session.fork' | 'session.compact'; snapshot: SessionSnapshotV1 }
  | { method: 'session.list'; sessions: SessionSummaryV1[]; nextCursor?: string }
  | {
      method: 'session.get'
      snapshot: SessionSnapshotV1
      items: SessionItem[]
      highWaterItemSeq: number
      nextItemSeq: number
    }
  | {
      method: 'session.handoff.create'
      json: ArtifactDescriptorV1
      markdown: ArtifactDescriptorV1
    }
  | { method: 'run.submit' | 'run.cancel' | 'run.apply'; snapshot: RunSnapshotV1 }
  | { method: 'run.approve'; snapshot: RunSnapshotV1; decisionRef: ArtifactRef }
  | { method: 'run.input'; snapshot: RunSnapshotV1; inputItemRef: ArtifactRef }
  | {
      method: 'run.reconcile'
      snapshot: RunSnapshotV1
      resolution:
        | { kind: 'probe_enqueued'; dispatchDigest: string; userProbeCount: number }
        | { kind: 'abandoned'; evidenceRef: ArtifactRef }
    }
  | { method: 'run.list'; runs: RunSnapshotV1[]; nextCursor?: string }
  | {
      method: 'run.get'
      snapshot: RunSnapshotV1
      items: RunItemReferenceV1[]
      journal: InvocationJournalEntry[]
      checkpoints: Checkpoint[]
      highWaterItemSeq: number
      highWaterJournalSeq: number
      highWaterCheckpointCursor?: string
      nextItemSeq: number
      nextJournalSeq: number
      nextCheckpointCursor?: string
    }
  | {
      method: 'run.attach'
      snapshot: RunSnapshotV1
      earliestRetainedEventSeq: number
      latestRetainedEventSeq: number
      highWaterEventSeq: number
      events: RunEvent[]
      nextEventSeq: number
    }
  | { method: 'run.result'; runId: string; result: ArtifactDescriptorV1; verificationClosureRef: ArtifactRef }
  | { method: 'run.diff'; runId: string; diff: ArtifactDescriptorV1 }
  | { method: 'authorization.create'; grant: AuthorizationGrantSummaryV1 }
  | { method: 'authorization.list'; grants: AuthorizationGrantSummaryV1[]; nextCursor?: string }
  | {
      method: 'authorization.revoke'
      disposition: 'revoked' | 'already_revoked' | 'already_consumed'
      grant: AuthorizationGrantSummaryV1
    }
  | {
      method: 'mcp.register' | 'mcp.refresh'
      registry: McpRegistrySummaryV1
      registrationReceiptRef: ArtifactRef
    }
  | { method: 'mcp.list'; registrations: McpRegistrySummaryV1[]; nextCursor?: string }
  | {
      method: 'artifact.get'
      artifact: ArtifactDescriptorV1
      offset: number
      bytesBase64: string
      nextOffset: number
      eof: boolean
    }
  | {
      method: 'supervisor.status'
      health: 'starting' | 'ready' | 'draining' | 'degraded'
      supervisorInstanceId: string
      queue: { queuedRuns: number; runningRuns: number; capacity: number }
      stateSchemaVersion: number
      activeRuntimeBundle: RuntimeBundlePublicSummaryV1
      installedRuntimeBundles: RuntimeBundlePublicSummaryV1[]
      incompatiblePinnedRunCount: number
    }

type ControlErrorBaseV1 = { schemaVersion: 1; messageCode: string }

type ControlErrorV1 =
  | (ControlErrorBaseV1 & {
      code: 'INVALID_REQUEST'
      retryable: false
      issues: Array<{ path: string; issueCode: string }>
    })
  | (ControlErrorBaseV1 & {
      code: 'INCOMPATIBLE_PROTOCOL'
      retryable: false
      supportedControlRange: { min: 1; max: 1 }
      supportedHeadlessRange: { min: number; max: number }
      upgradeAction: 'upgrade_client' | 'upgrade_supervisor'
    })
  | (ControlErrorBaseV1 & {
      code: 'REVISION_CONFLICT'
      retryable: true
      currentRevision: number
      conflict:
        | { resourceKind: 'session'; currentSnapshot: SessionSnapshotV1 }
        | { resourceKind: 'run'; currentSnapshot: RunSnapshotV1 }
    })
  | (ControlErrorBaseV1 & {
      code: 'WAIT_SUBJECT_MISMATCH'
      retryable: true
      currentRevision: number
      currentWaitingSubjectRef: ArtifactRef
      currentWaitingSubjectDigest: string
    })
  | (ControlErrorBaseV1 & {
      code: 'RESOURCE_EXHAUSTED'
      retryable: true
      resourceKind:
        | 'run_queue'
        | 'worker_capacity'
        | 'admin_probe_capacity'
        | 'local_inference_activation_cycle'
        | 'state_storage'
      retryAfterMs: number
    })
  | (ControlErrorBaseV1 & {
      code: 'RECOVERY_REQUIRED'
      retryable: true
      recoveryKind: 'worker_death' | 'effect_reconciliation' | 'admin_probe' | 'local_inference_service'
      detailRef: ArtifactRef
    })
  | (ControlErrorBaseV1 & {
      code: 'EVENT_CURSOR_EXPIRED'
      retryable: false
      earliestEventSeq: number
      latestEventSeq: number
      snapshot: RunSnapshotV1
    })
  | (ControlErrorBaseV1 & {
      code: 'RESULT_UNAVAILABLE'
      retryable: true
      runId: string
      status: 'queued' | 'running' | 'waiting'
      currentRevision: number
    })
  | (ControlErrorBaseV1 & {
      code: 'RESULT_UNAVAILABLE'
      retryable: false
      runId: string
      status: 'failed' | 'cancelled'
      terminalDetailRef: ArtifactRef
    })
  | (ControlErrorBaseV1 & {
      code: 'RATE_LIMITED'
      retryable: true
      retryAfterMs: number
    })
  | (ControlErrorBaseV1 & {
      code: 'INTERNAL'
      retryable: false
      errorId: string
    })
  | (ControlErrorBaseV1 & {
      code:
        | 'NOT_FOUND'
        | 'REQUEST_ID_CONFLICT'
        | 'ADMISSION_KEY_CONFLICT'
        | 'AUTHORIZATION_REQUIRED'
        | 'POLICY_DENIED'
        | 'MODEL_COST_UNKNOWN'
        | 'BUDGET_EXHAUSTED'
        | 'RUN_TERMINAL'
        | 'CANCEL_REQUESTED'
        | 'UNSUPPORTED_PLATFORM'
        | 'UNSUPPORTED_EXECUTION_IDENTITY'
        | 'ARTIFACT_MISMATCH'
      retryable: false
      detailRef?: ArtifactRef
    })

type ControlErrorCodeV1 = ControlErrorV1['code']

type ControlApplicationResponseV1 =
  | { protocolVersion: 1; ok: true; result: ControlResultV1 }
  | { protocolVersion: 1; ok: false; method: ControlMethodV1; error: ControlErrorV1 }
  | {
      protocolVersion: 1
      ok: false
      rejectedMethodDigest: string
      error: Extract<ControlErrorV1, { code: 'INVALID_REQUEST' }>
    }
```

Every success carries exactly one method-discriminated result above and unknown fields fail validation. `run.result|run.diff` may return their success variants only when the Run has `resultRef`, hence only for `succeeded|completed_unverified`; a nonterminal Run returns the retryable `RESULT_UNAVAILABLE` variant, while `failed|cancelled` returns its nonretryable variant and exact terminal detail. No query selects an arbitrary failed candidate. `SessionItem`, Journal, Checkpoint, and Run-item metadata are returned only to the same local principal and contain refs/digests rather than artifact bytes; clients fetch bytes through `artifact.get`. Authorization summaries omit paths, executable names, argv, and receipt bodies; MCP summaries omit endpoint, credential, and argv bytes. `authorization.revoke` maps active to `revoked`, immutable revoked replay to `already_revoked`, and immutable consumed no-op to `already_consumed`; its summary state must be `revoked|revoked|consumed` respectively. `ControlErrorV1` is a strict discriminated union: its literal retryability and required metadata are part of the schema, unlisted members are forbidden, issue lists are at most 64 entries, issue path/code and message/error ids use the ordinary string bounds, and event/resource/rate integers are safe and range-checked. `currentRevision` occurs only for revision/wait conflicts and retryable `RESULT_UNAVAILABLE`; `retryAfterMs` occurs only for resource/rate errors. A method that parsed as a known discriminator uses the known-method error variant; an unknown/removed method uses only `rejectedMethodDigest = SHA-256(NFC UTF-8 method bytes)` plus the `INVALID_REQUEST` parse variant, so it can be rejected without echoing or pretending the method is known. Any `detailRef` is a same-principal bounded artifact. No error carries arbitrary stack text, raw rejected value, or adapter-local metadata. Transport adapters preserve their own request correlation id outside this application object but may not alter the result/error payload.

The four list methods use one exact materialized-cut protocol; they never keyset-page a changing live filter. Normalize omitted filters to their displayed absent values, `run.list.statuses` to its required unique byte-sorted sequence, and limit to the method default. Then `normalizedFilterDigest = SHA-256(JCS({ownerPrincipalId,method,workspacePath-or-null,sessionId-or-null,operation-or-null,statuses-or-empty,targetKind-or-null,state-or-null,normalizedLimit}))`, retaining only fields applicable to that method. A request without `cursor` performs one StateOwner-gated SQLite transaction: it captures current authoritative rows, applies owner and normalized filters, constructs each exact typed public summary, orders matches by canonical timestamp then bytewise NFC `stableId`, materializes ordinals `1..entryCount` into `list_read_cut_entries`, and inserts one `list_read_cuts` row. Stable ids are Session id, Run id, grant id, and registration id respectively. Session/Run fields are captured at that revision; authorization captures the current immutable grant row; MCP captures exactly the current registry head for each registration, never old revisions. Later state, status, revision, or registration changes cannot change membership/order/value in this cut. A fresh cursorless request creates a new cut and sees later state.

The cut id and cursor secret are independent CSPRNG 256-bit unpadded-base64url values. `createdAt` is the transaction's canonical time and `expiresAt=createdAt+15 minutes` using checked arithmetic. `ListReadCutEntryV1.rowDigest` omits itself; `entriesDigest=SHA-256(JCS(the complete rowDigest sequence in ordinal order))`; and `cutDigest=SHA-256(JCS(cut with cursorSecretBase64url and cutDigest omitted))`. The cache allows at most 100,000 matching rows and 64 MiB encoded typed summaries per cut; exceeding either returns `RESOURCE_EXHAUSTED(resourceKind='state_storage')` and publishes no partial cut. `list_read_cuts` and entries are non-authoritative query cache, cannot influence reducers/admission/recovery, and root their referenced artifacts only until expiry. Deletion is allowed only after expiry; corruption fails the request and deletes nothing authoritative.

Every issued cursor is unpadded base64url of the exact UTF-8 JCS `ListCursorPayloadV1`. Its `macBase64url = HMAC-SHA-256(cursorSecret, ASCII('cliq-list-cursor-v1\0') || JCS({schemaVersion:1,cutId,afterOrdinal}))`, rendered as unpadded base64url. `afterOrdinal` is zero only internally for the first page and otherwise the last ordinal returned by the page that issued this cursor. The server decodes canonical bytes, looks up the cut, authenticates the MAC in constant time, and requires current principal, method, normalized filter digest, normalized limit, unexpired canonical time fence, cut/entry digests, and exact ordinal range to match. Malformed base64/JCS, unknown/deleted/expired cut, noncanonical encoding, bad MAC, changed filter/limit/principal/method, or an unissued/out-of-range ordinal returns `INVALID_REQUEST` with a stable non-echoing list-cursor issue code. The cursor contains no trusted unsigned state and survives Supervisor restart because the cut and secret are SQLite rows.

A page returns the next `normalizedLimit` rows with `ordinal>afterOrdinal`, preserving the materialized order. Reusing the same valid cursor returns byte-identical summaries and next cursor. `nextCursor` is omitted exactly when the last returned ordinal equals `entryCount` or the cut is empty; otherwise it is the deterministic authenticated cursor for that last ordinal. There is no empty middle page, next-unread interpretation, live-row re-evaluation, duplicate, or skip. Equal `createdAt` values are harmless because the full membership and bytewise id tie-break are materialized before page one. Golden tests cover empty/one/exact-limit/multi-page lists, equal timestamps, all filters, MCP refresh and Run/auth status changes between pages, concurrent inserts before/after the cut, repeat/restart, changed limit/filter/principal/method, malformed/forged/future/end/expired cursors, capacity refusal, and cut GC.

`session.get` and `run.get` use one exact snapshot-pagination protocol. Omitted numeric sequence cursors normalize to zero; every explicit sequence, limit, high-water, and returned sequence is a nonnegative safe integer. Each request executes in one SQLite read snapshot and captures all of its high-waters before reading a page. A sequence cursor is exclusive: rows satisfy `(after, highWater]` and are returned in strictly increasing sequence order. A cursor greater than its captured high-water is `INVALID_REQUEST`; rows are not silently skipped, duplicated, or treated as a future subscription. `next*` is the last returned cursor, or the normalized supplied cursor when that stream returned no row. Equality of `next*` and the corresponding high-water means caught up through that captured cut; a later request from the same next cursor captures a new cut. Kernel v1 does not prune Session items, Run items, Journal facts, or Checkpoints, so these query cursors do not expire.

For `session.get`, the read snapshot fixes `snapshot.contextRevision`, `highWaterItemSeq=snapshot.latestItemSeq`, and the exact ordered `SessionItem[]`. `afterItemSeq` defaults to zero and `limit` defaults to 100 with range `1..1000`. The page contains the first qualifying items up to that limit whose complete `JCS(items)` encoding is at most 1 MiB; because each item is bounded metadata, the first item always fits. `nextItemSeq` follows the common rule above. The item payload remains an `ArtifactRef`; pagination never embeds or reserializes its bytes.

For `run.get`, the same read snapshot fixes the returned `RunSnapshotV1`, `highWaterItemSeq=snapshot.latestRunItemSeq`, `highWaterJournalSeq` as the greatest retained Journal sequence for the Run (zero only before any such row), and `highWaterCheckpointCursor` as the cursor of the greatest retained Checkpoint in strict `(createdAt,id)` order. Every admitted Run has an initial Checkpoint, so a valid public Run has that checkpoint high-water; the optional field exists only for decoder compatibility with a transaction-local pre-admission row that is never publicly returned. `afterItemSeq` and `afterJournalSeq` default to zero. Each of `itemLimit|journalLimit|checkpointLimit` defaults to 100 and is independently in `1..1000`. Run items and Journal rows use their increasing sequence; Checkpoints use increasing `(createdAt,id)`.

A Checkpoint cursor is unpadded base64url of `JCS({schemaVersion:1,runId,createdAt,checkpointId})`. The decoded `runId` must equal the request, the UTF-8 bytes and canonical time must round-trip exactly, and `(createdAt,checkpointId)` must name a retained Checkpoint for that Run; otherwise the request is `INVALID_REQUEST`. Omitted `checkpointCursor` means before the first Checkpoint. `nextCheckpointCursor` is the last returned Checkpoint cursor, or the exact normalized input cursor when none is returned; `highWaterCheckpointCursor` names the captured last Checkpoint. A cursor after the high-water, from another Run, or naming no exact retained row is invalid rather than empty or expired.

The combined run metadata limit is exactly 1 MiB for `JCS({items,journal,checkpoints})`. The server considers candidates deterministically in stream priority `items`, then `journal`, then `checkpoints`, preserving each stream's order and limit. It appends a candidate only if the resulting complete three-array encoding remains within the cap; the first candidate that would exceed the cap ends construction, leaving that candidate and every later candidate for the next request. This rule, the three next cursors, and the three captured high-waters are computed from the same snapshot, so clients can advance each stream independently without gaps even when the byte cap truncates a page. Golden fixtures cover initial, empty, exact-end, byte-truncated, future, wrong-Run, and malformed Checkpoint cursors.

Verifier `id` and `version` are required nonempty UTF-8 strings of at most 128 bytes; version is user-visible identity metadata while executable/command digests remain execution authority. `verifierRequestCoreDigest = SHA-256(JCS(VerifierRequest with executionGrantId omitted))`. `authorization.create(kind='verifier_execution')` binds that core digest plus the already resolved execution-identity grant; admission verifies the supplied grant against the same id/version/core and only then adds its id to the final Run admission digest. This ordering is non-circular and prevents one verifier grant from being replayed for a changed version, argv, cwd, or environment.

`run.get/list/attach`, `session.get/list`, `authorization.list`, `mcp.list`, `artifact.get`, `run.diff/result`, `session.handoff.create`, and `supervisor.status` are read-only and reject `requestId`. `session.handoff.create` is deterministic by Session/revision/cursor and returns identical CAS refs. `control.hello` carries `protocolVersion=1`, client build, schema range, requested feature ids (max 64), and returns server build/schema range/capabilities before any other request.

String ids are NFC UTF-8, 1..128 bytes; `requestId` is UUIDv7; admission keys are base64url, 22..128 bytes; digests are lowercase SHA-256. Workspace paths are absolute UTF-8, <=4096 bytes, no NUL, and are canonicalized/authorized by the Supervisor rather than trusted. Objective is 1..262144 bytes. Verifier ids are unique (max 32). Every public or retained non-secret argv/env literal is a well-formed Unicode-scalar string, NFC-normalized, contains no U+0000, and is measured after UTF-8 encoding; argv has max 128 entries/8192 bytes each. Environment has max 64 entries; names match ASCII `^[A-Za-z_][A-Za-z0-9_]{0,63}$`, are unique and byte-sorted after normalization, and values are at most 8192 bytes. An unrepresentable Node/POSIX argv/env value is rejected before any grant, command, launch, or admission artifact is published. Each verifier has max 32 `cliq-exact-path-v1` root-relative writable-ephemeral paths, all excluded from source/result; MCP ids/recovery entries max 128 tools, registration credential ids max 32; skill ids max 64; model credential grant ids max 32; source include/exclude arrays max 128 each; Session compaction retained ids are unique and max 256. Authorization TTL defaults to one hour and is capped at 24 hours; verifier candidate/attempt grants cannot exceed RunSpec limits. Inline text/JSON is at most 1 MiB after canonical encoding, max depth 32 and max 10,000 object members/array elements total. Unknown fields are errors. Omitted numeric options take sections 5/10/13 defaults; explicit zero follows their defined disable semantics.

For any `MutationBase`, `requestDigest = SHA-256(JCS(request with requestDigest omitted))`. Every admission-key method—`session.create`, `session.fork`, `run.submit`, and `run.apply`—also computes `admissionIntentDigest = SHA-256(JCS({principalId,method,request: normalized request with protocolVersion,requestId,requestDigest,admissionKey omitted}))`. The unique replay key is `(principalId,method,admissionKey)`. Lookup happens before reopening a workspace, rereading a Session revision, revalidating a source Run, or descriptor-capturing apply source A: same intent returns the already committed Session/Run/control result byte-for-byte, while a different intent is `ADMISSION_KEY_CONFLICT` and performs no state or filesystem read beyond the replay row. On first execution, the final admitted digest binds the intent plus every Supervisor-resolved artifact/ref/digest and the replay row commits with the Session/Run transaction. For `run.apply`, `expectedRunResultRef` must equal the source Run's current immutable `resultRef` before any capture; it is not a SourceManifest tree digest or diff digest. Public clients cannot substitute other artifact refs for inline fields. An `abandon_run` resolution is schema-legal only when the exact waiting invocation is `ReplayClass='manual'`; all other subjects reject it.

The initial Supervisor transport is a local Unix-domain socket protected with per-user filesystem permissions. Existing stdio JSON-RPC remains an adapter, not the runtime owner. The new control protocol has an explicit compatibility handshake; the headless event schema advances incompatibly rather than silently changing the meaning of process-local `runId`.

Long Runs survive package upgrades. Before admitting a Run, Cliq publishes a read-only, digest-addressed runtime bundle containing the exact Supervisor-compatible worker, provider/tool adapters, schemas, and platform helpers referenced by `assemblyRef`; guest image/toolchain manifests are retained by digest too. The user-service definition points to a stable state-root bootstrap and an atomically selected versioned Supervisor bundle, never directly to a replaceable global npm path. Bundles referenced by any nonterminal Run or retained audit/result cannot be garbage-collected.

An update stages and self-tests a new bundle. It may activate a new Supervisor only when that Supervisor declares compatibility with every nonterminal Run schema/assembly and can launch their pinned worker bundles; otherwise the current Supervisor remains active across reboot and the update reports `drain_required`. It is never killed or replaced under active incompatible Runs. After drain, the bootstrap atomically switches bundles with rollback-on-startup-failure. Thus an external reinstall can replace the client package without deleting the executable needed to recover an accepted Run.

The Kernel Cut includes:

- current provider adapters with typed capability negotiation;
- MCP **tools** over stdio and streamable HTTP with cancellation and capability discovery;
- `AGENTS.md` and `SKILL.md` compatibility;
- built-in file/search/shell/plan tools;
- CLI, TUI, JSONL, and local RPC surfaces;
- run-scoped cost/latency/retry/tool/verification telemetry;
- stable artifact and receipt inspection.

Repository JavaScript extensions and repository-defined command hooks are removed rather than carried across the trust boundary. Trusted workspace config may reference declarative policy, skills, registered MCP ids, and frozen verifiers, but it cannot register or auto-launch executable code. Any replacement command runs as an explicit built-in tool/verifier under permission, Journal, and sandbox gates. Workspace Trust is never execution permission.

MCP has a deliberately narrow launch boundary. Repository `.cliq/config` may reference only an MCP server id already registered by the user; it cannot supply an executable, URL, environment, or credential. Stdio registration accepts only a signed `GuestToolchainManifest` tool or retained signed `RuntimeBundle` executable; workspace scripts and mutable host paths are rejected. The registry/RunSpec retain that manifest/bundle digest and executable closure as GC roots, so detach/upgrade cannot replace it. Explicit `cliq mcp register/refresh` runs a consented sandboxed probe and freezes endpoint/executable identity, exact initialize/capability/tool-schema digest, `stateModel='stateless_per_call'`, and this closed per-tool recovery union:

Registration/refresh probe lifecycle uses the `admin_operations` crash fence, not a hidden child Run or direct CLI process. The Supervisor persists `prepared`, materializes a blocked strong containment, records `active` identity/lease, then releases only the one probe capability. A stdio probe is secretless/networkless; HTTP probe credentials remain broker handles. Completion first terminates/proves the entire probe containment and publishes its evidence. One transaction then marks the admin attempt completed, appends the immutable registry revision, and stores the idempotent control response. Supervisor loss kills/proves and records the closed retryable/final disposition; no new instance reconnects or launches a second probe until that proof and the fixed retry deadline. Same request-id replay returns the one committed final response, joins an existing attempt, or—only after a response-less `retryable_recovery` attempt—safely creates attempt 2 or 3 under the original request digest.

```ts
type RequestedMcpRecoveryV1 =
  | { kind: 'manual' }
  | {
      kind: 'retry'
      explicitRiskConsentRef: ArtifactRef
      explicitRiskConsentDigest: string
      safetyAssertionRef: ArtifactRef
      safetyAssertionDigest: string
      idempotencyKeyJsonPointer?: string
    }
  | {
      kind: 'reconcile'
      bundledAdapterId: string
      idempotencyKeyJsonPointer: string
    }

type McpProbedToolInterfaceV1 = {
  name: string
  version: 'mcp-tool-interface-v1'
  description: string
  access: 'exec'
  inputSchemaRef: ArtifactRef
  inputSchemaDigest: string
  outputSchemaRef?: ArtifactRef
  outputSchemaDigest?: string
  interfaceDigest: string
}

type McpRetryRiskConsentV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-retry-risk-consent-v1'
  ownerPrincipalId: string
  registrationId: string
  serverToolName: string
  recoveryRequestDigest: string
  acknowledgedRisk: 'prior_attempt_may_have_succeeded_and_retry_may_duplicate_effect'
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  createdAt: string
  consentDigest: string
}

type McpRetrySafetyAssertionV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-retry-safety-assertion-v1'
  ownerPrincipalId: string
  registrationId: string
  serverToolName: string
  recoveryRequestDigest: string
  assertion: 'no_server_safety_claim_duplicate_effect_remains_possible'
  idempotencyKeyJsonPointer?: string
  assertionDigest: string
}

type McpRecoveryAdapterManifestV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-recovery-adapter-v1'
  adapterId: string
  entryId: string
  version: string
  executableDigest: string
  protocol: 'cliq-mcp-reconcile-v1'
  profiles: Array<{
    profileId: string
    serverExecutionIdentityDigest: string
    serverToolName: string
    initializeDigest: string
    capabilityDigest: string
    probedToolsListDigest: string
    effectToolInterfaceDigest: string
    statusOperationName: string
    statusOperationSemantics: 'signed_read_only_status_query'
    statusToolInterfaceDigest: string
    statusInputSchemaDigest: string
    statusOutputSchemaDigest: string
    staticArgumentsRef: ArtifactRef
    staticArgumentsDigest: string
    completedPredicateRef: ArtifactRef
    completedPredicateDigest: string
    failedPredicateRef: ArtifactRef
    failedPredicateDigest: string
    profileDigest: string
  }>
  adapterDigest: string
  publisherKeyId: string
  signature: string
}

type McpRecoveryStatusRequestTemplateV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-recovery-status-template-v1'
  adapterRef: ArtifactRef
  adapterDigest: string
  profileId: string
  profileDigest: string
  registrationId: string
  registryRevision: number
  adminProbeTargetRef: ArtifactRef
  adminProbeTargetDigest: string
  probeResultRef: ArtifactRef
  probeResultDigest: string
  serverToolName: string
  serverExecutionIdentityDigest: string
  initializeDigest: string
  capabilityDigest: string
  probedToolsListDigest: string
  effectToolInterfaceDigest: string
  statusOperationName: string
  statusOperationSemantics: 'signed_read_only_status_query'
  statusToolInterfaceDigest: string
  statusInputSchemaDigest: string
  statusOutputSchemaDigest: string
  idempotencyKeyJsonPointer: string
  staticArgumentsRef: ArtifactRef
  staticArgumentsDigest: string
  templateDigest: string
}

type McpRecoveryPredicateExpressionV1 =
  | { op: 'exists'; jsonPointer: string }
  | { op: 'equals'; jsonPointer: string; value: null | boolean | string | number }
  | { op: 'and' | 'or'; operands: McpRecoveryPredicateExpressionV1[] }

type McpRecoveryPredicateV1 = {
  schemaVersion: 1
  format: 'cliq-mcp-recovery-predicate-v1'
  expression: McpRecoveryPredicateExpressionV1
  predicateDigest: string
}

type McpRecoveryContract =
  | { kind: 'manual' }
  | {
      kind: 'retry'
      explicitRiskConsentRef: ArtifactRef
      explicitRiskConsentDigest: string
      safetyAssertionRef: ArtifactRef
      safetyAssertionDigest: string
      idempotencyKeyInjection?: { jsonPointer: string }
    }
  | {
      kind: 'reconcile'
      adapterRef: ArtifactRef
      adapterDigest: string
      profileId: string
      profileDigest: string
      idempotencyKeyInjection: { jsonPointer: string }
      statusRequestTemplateRef: ArtifactRef
      statusRequestTemplateDigest: string
      completedPredicateRef: ArtifactRef
      completedPredicateDigest: string
      failedPredicateRef: ArtifactRef
      failedPredicateDigest: string
    }

type McpToolContract = {
  name: string
  version: 'mcp-tool-contract-v1'
  description: string
  access: 'exec'
  inputSchemaRef: ArtifactRef
  inputSchemaDigest: string
  outputSchemaRef?: ArtifactRef
  outputSchemaDigest?: string
  interfaceDigest: string
  recovery: McpRecoveryContract
  toolContractDigest: string
}

type McpRegistryRevision = {
  schemaVersion: 1
  format: 'cliq-mcp-registry-v1'
  registrationId: string
  registryRevision: number
  ownerPrincipalId: string
  transport:
    | {
        kind: 'stdio'
        executionIdentityGrantId: string
        executionIdentityConsumptionReceiptRef: ArtifactRef
        executionIdentityConsumptionReceiptDigest: string
        executable:
          | {
              kind: 'guest_toolchain'
              toolchainManifestRef: ArtifactRef
              toolId: string
              executionPath: string
              executableDigest: string
            }
          | {
              kind: 'runtime_bundle'
              runtimeBundleRef: ArtifactRef
              executableId: string
              executionPath: string
              executableDigest: string
            }
        argv: NonSecretArgumentRequest[]
      }
    | {
        kind: 'streamable_http'
        endpointRegistrationRef: ArtifactRef
        endpointIdentityDigest: string
        tlsPolicyDigest: string
        credentialGrantRefs: ArtifactRef[]
      }
  initializeDigest: string
  capabilityDigest: string
  probedToolsListDigest: string
  toolsListDigest: string
  stateModel: 'stateless_per_call'
  tools: McpToolContract[]
  lifecycle: {
    launchTimeoutMs: number
    callTimeoutMs: number
    maxLaunchesPerCall: number
  }
  registrationReceiptRef: ArtifactRef
  manifestDigest: string
  createdAt: string
}

type McpRegistrationReceipt = {
  schemaVersion: 1
  format: 'cliq-mcp-registration-receipt-v1'
  registrationId: string
  registryRevision: number
  ownerPrincipalId: string
  requestDigest: string
  adminOperationId: string
  adminAttempt: number
  dispatchId: string
  probeRequestDigest: string
  adminProbeTargetRef: ArtifactRef
  adminProbeTargetDigest: string
  probeResultRef: ArtifactRef
  probeResultDigest: string
  probeClosureEvidenceRef: ArtifactRef
  probeClosureEvidenceDigest: string
  initializeDigest: string
  capabilityDigest: string
  probedToolsListDigest: string
  toolsListDigest: string
  registryCoreDigest: string
  createdAt: string
  receiptDigest: string
}
```

The `mcp_registrations` row stores only owner, registration id, monotonic current revision, and the immutable current `McpRegistryRevision` ref; older revisions remain retained for admitted Runs. Revision zero is invalid, refresh requires the exact current revision, tool names are unique and byte-sorted, and schema refs/digests validate. Publication has an explicit acyclic order. Before probe I/O, `McpAdminProbeTargetV1.requestedToolRecovery` contains only `RequestedMcpRecoveryV1`: `manual`; prepublished retry consent/assertion refs plus an optional pointer; or the public reconcile adapter id and pointer. It contains no profile selection, status template, predicate, final `McpRecoveryContract`, tool-contract digest, tools-list digest, registry-core digest, or registry-manifest digest. The probe result contains only the raw interfaces and `probedToolsListDigest` defined above.

After that result is durable, the trusted reducer requires every explicitly requested tool name to match exactly one probed interface and builds the final byte-sorted `McpToolContract[]`; an unknown requested name or duplicate probed name rejects registration, while every unrequested probed interface deterministically receives `recovery.kind='manual'`. Every final row copies name/description/access/schema refs and digests plus `interfaceDigest` byte-for-byte from its probed row, changes only `version` to `mcp-tool-contract-v1`, appends the normalized final recovery contract, and computes `toolContractDigest = SHA-256(JCS(tool with toolContractDigest omitted))`; `toolsListDigest = SHA-256(JCS(the final full tools array))`. RunAssembly derives each MCP `ToolContractManifestV1` entry byte-for-byte from this retained final array: description/access/schema refs and digests match, `replayClass` equals the recovery kind, and the execution discriminator repeats the registry ref/manifest digest/server name/tool-contract digest. No probe order, adapter default, or later server description may change prompt or policy bytes.

`registryCoreDigest` is SHA-256 over the final JCS revision core with both `registrationReceiptRef` and `manifestDigest` omitted. The receipt binds that core plus the exact admin target, released attempt, raw probe result, positive closure evidence, raw `probedToolsListDigest`, and final `toolsListDigest`. The final revision then references the receipt and computes `manifestDigest` over JCS with only `manifestDigest` omitted; `receiptDigest = SHA-256(JCS(receipt with receiptDigest omitted))`. Its admin id/attempt/dispatch/request/target equal one completed `admin_operations` row; result ref/digest decodes exact `McpAdminProbeResultV1`; closure ref/digest decodes its exact `containment_dead` evidence; initialize/capability/probed-list digests equal the result; final tools are the deterministic projection above; and owner/registration/revision/core/final-list digests match the receipt and revision. The receipt and final revision artifacts are published first, then the completed row, registry-row CAS, revision/receipt roots, and `control_requests` response commit together. No earlier artifact names a later digest, so no fixed-point hash is required.

A stdio revision roots the signed toolchain/runtime bundle and exact entry/digest, never a mutable host/workspace path. For HTTP, `mcp.register` resolves the public endpoint/credential ids **before** creating the admin target/probe core: the revision stores the immutable endpoint registration ref plus exact identity/TLS digests and principal-owned `EndpointCredentialGrantBinding` refs whose purpose is `mcp_streamable_http` and whose endpoint fields match exactly. `mcp.refresh` is deliberately copy-only in v1: its request supplies no replacement target, credentials, recovery, or lifecycle fields, so the new target copies the exact current revision's immutable transport and reconstructs the same `RequestedMcpRecoveryV1` values from the retained final contracts, then only reprobes current initialize/capability/tool-interface bytes. Changing any target input requires a new `mcp.register` request for a different registration id; a refresh never re-resolves public ids or follows an id rebind. Revoked/expired copied bindings block the probe/dispatch without changing historical truth. Lifecycle defaults are launch 30s/call 10m/max launches 2, with accepted ranges 1s..5m, 1s..1h, and 1..3. Registration has 1..128 tools; names/argv/schema sizes use the public bounds in section 15.

Generic MCP metadata cannot make an operation queryable by assertion. Missing metadata is `manual`. For `retry`, the Supervisor canonicalizes the one tool's public recovery request and publishes both exact artifacts above: `recoveryRequestDigest = SHA-256(JCS(the normalized per-tool McpRecoveryRequest))`; consent/assertion registration, tool, owner, request digest, and optional RFC-6901 pointer must match; `consentDigest`/`assertionDigest` omit themselves under JCS. The assertion deliberately makes no server-side idempotency claim—the user has accepted that a prior attempt may already have succeeded—while a supplied pointer only freezes where Cliq injects the stable call idempotency key. Refresh copies these immutable refs/digests from the current revision and does not solicit or manufacture new consent.

`reconcile` is accepted only when `adapterRef` decodes to `McpRecoveryAdapterManifestV1` selected by the active RuntimeBundle's unique external `structuredArtifacts(kind='mcp_recovery_adapter',artifactId=adapterId)` record. The manifest deliberately contains no RuntimeBundle ref/digest: the outer signed record binds its complete-byte `adapterRef`, semantic `adapterDigest`, and `entryId/version/executableDigest` to one executable `mcp_recovery_adapter` entry, so the bundle never hashes an artifact that points back to itself. The profile catalog is independently release-signed: `adapterDigest = SHA-256(JCS(adapter with adapterDigest and signature omitted))`, `signature` signs the ASCII domain `cliq-mcp-recovery-adapter-v1\0` plus that digest, and `publisherKeyId` resolves through the same immutable Cliq release trust store as the RuntimeBundle. ArtifactRef still hashes the complete signed bytes. An authentic executable paired with unsigned, user-signed, unknown-key, digest-mismatched, later substituted, or differently bundle-bound profile metadata is invalid.

Every profile, status template, and predicate otherwise uses the digest-member-omission JCS rule. Kernel Cut `reconcile` profiles apply only to stdio registrations whose server executable and exact normalized argv were known to the release publisher; streamable HTTP and an unprofiled stdio target may use only `manual|retry`. For a stdio admin target, `serverExecutionIdentityDigest = SHA-256(JCS({executable: resolvedTransport.executable, argv: resolvedTransport.argv}))`. Profiles are nonempty, byte-sorted, and unique by both profile id and the tuple `(serverExecutionIdentityDigest,serverToolName,effectToolInterfaceDigest)`. A profile repeats only pre-final facts: that execution identity, normalized initialize/capability/probed-list digests, the effecting interface digest, and a **distinct** status operation's interface/input/output schema digests. The named effect and status interfaces must exist in the raw probe result and rehash exactly. `statusOperationSemantics` is the release publisher's narrow assertion that this exact profiled status interface on that exact signed executable/argv identity is a no-new-effect query; server annotations cannot supply or widen it. Public `bundledAdapterId` must equal the manifest adapter id, and the probe selects exactly one signed profile. Absence, ambiguity, HTTP transport, execution-identity drift, raw-list drift, status-interface mismatch, or schema mismatch rejects `reconcile` rather than falling back to a name match.

The Supervisor publishes the per-registration status template only after the raw result is durable. It copies every profile identity, operation, schema, static-argument, and predicate field exactly, adds the exact registration/revision, admin-target ref/digest, raw probe-result ref/digest, and public RFC-6901 idempotency pointer, then computes `templateDigest`. Those target and result refs rehash, `serverExecutionIdentityDigest` recomputes from the target, and initialize/capability/probed-list/effect/status interface digests equal the result. The template deliberately contains no registry ref, registry-core/manifest digest, final tool-contract/list digest, recovery-contract ref, or value derived from itself. The resulting final recovery contract names the adapter/profile/template/predicates, and only then does the reducer compute the final tool-contract/list/core/registry digests. This is the sole allowed publication direction: raw target/result -> signed profile -> per-registration template/final recovery contracts -> registry core/receipt/final revision.

The recovery contract repeats the same profile id/digest, and its injection pointer, the status template pointer, and the public per-tool request pointer are byte-identical. `recoveryRequestDigest` covers the normalized reconcile request `{kind,bundledAdapterId,idempotencyKeyJsonPointer}` and is included in the admin target/request digest; changed selection bytes cannot reuse the signed profile closure. The recovery contract's adapter/template/predicate refs/digests must equal that same signed profile, so no adapter iteration order or implementation default chooses semantics. The status template is bound to that adapter/profile/registration/revision/target/result/tool, one NFC operation name, one valid RFC-6901 key pointer, and bounded canonical JSON static arguments. Predicate expressions are the complete closed IR: maximum depth 8, maximum 64 nodes, nonempty `and|or`, finite safe-integer numbers, valid RFC-6901 pointers, and no script, regex, path, network target, or executable reference. Completed and failed predicates must be distinct, cannot both match a response, and any neither/both/schema-invalid result remains unresolved. At recovery time the invocation separately carries the immutable final registry ref/manifest digest and must equal the registration/revision/template target and tool; the signed adapter may issue only the template's exact no-new-effect status operation through that original stdio target. It cannot invoke the effecting tool, change executable/argv, use HTTP, call a same-named operation on another revision, or perform a conditional retry unless a separately Journaled retry transition is authorized. Repository or user executable bytes cannot define/load an adapter; the Kernel Cut has no trusted plugin ABI. Every MCP call freezes the exact `McpRegistryRevision` ref/manifest digest, tool contract, batch/call/index identity, and stable idempotency key into its request artifact.

The Kernel Cut never trusts a probe or server assertion to prove statelessness. It enforces the recoverable portion structurally. Every stdio tool call gets a fresh process/containment with a fresh empty private HOME/TMP, read-only registered executable/toolchain, no persistent writable mount, no network, and teardown/death proof after that call; no stdio instance is reused across calls. Streamable HTTP uses a fresh broker request with no cookie jar, session id, ambient header, or cross-call client state. External service state remains part of the target and therefore must be covered by the tool's `manual|retry|reconcile` contract. A server that requires client-held session state is unsupported rather than “proved safe” by registration. Recovery never checkpoints hidden server memory; a future stateful MCP mode requires a typed server-state/restore RFC.

A stdio instance is call-scoped while its registration is user-scoped. For the exact owning batch/call, `lifecycleSeq` starts at zero and stable launch `opId = H(runId, batchItemId, callIndex, callId, registryManifestDigest, lifecycleSeq)`. Launch uses `ReplayClass='retry'` only after any old call-scoped containment is proven dead. Every launch has fresh `prepared`, reservation, claim, and one `toolCalls` charge. After containment spawn, MCP initialize, capability validation, and exact `tools/list` digest match, the Supervisor publishes `McpServerInstanceIdentityV1`; `identityDigest = SHA-256(JCS(identity with identityDigest omitted))`. Its Run/batch/call/index, registry revision/manifest, lifecycle/op/attempt/dispatch, SandboxLaunch/containment, nonce, and initialize/capability/probed-tools-list digests must equal the exact call request, claim, containment, and immutable registry. Only that identity may receive the owning `tools/call`; no address, PID, socket, or adapter-local handle is authority.

The owning MCP call may make its result artifact durable while the server runs, but the `mcp-server` launch does not become Journal-terminal yet. After teardown, the Supervisor publishes `McpServerLaunchReceiptV1`; `receiptDigest = SHA-256(JCS(receipt with receiptDigest omitted))`, its identity ref/digest rehash exactly, its three Journal sequence numbers name that launch's one prepared/claim/completed chain, its settlement is the completed row's exact settlement, and its stopped item/death evidence prove the identity's complete containment dead. One transaction commits Journal `opKind='mcp-server',phase='completed'` with `resultRef=instanceIdentityRef` and `receiptRef=launchReceiptRef`, the identity-matched `McpServerStoppedItem`, visible `ToolResultItem`, budget settlement, and tool-frontier advance. The stopped item repeats full batch/call/index, registry manifest, lifecycle/op, identity and launch-receipt refs/digests; `containmentEvidenceRef` equals the receipt's exact `ProcessContainmentDeathEvidenceV1`. Unproven teardown leaves the current Journal/instance/containment lifecycle open under the same tool frontier and permits only fence/kill/death inspection; it creates no `ReconciliationSubject`, completed launch, ToolResult, or frontier advance. Terminal quiescence forbids any completed launch without that receipt, stopped item, and death evidence. No later call can address that instance. If an initialized instance dies before its owning call dispatch, replacement increments `lifecycleSeq` and uses a new opId; an ambiguous preterminal launch retries the same opId with a new attempt only after death proof. A lifecycle grant is scoped to the server/call identity, expiry, and bounded `maxLaunches`; each replacement journals, and expiry/exhaustion creates the exact batch/index-bound `mcp_server_launch` approval subject.

Stdio servers run in their own strong all-descendant containment, secretless, networkless, and unable to access RunWorkspace, real workspace, Cliq state, or another server. Streamable HTTP calls execute through the trusted broker with no ambient session. A manifest mismatch fails closed before `tools/call`; takeover never reuses an old instance or operation grant.

It does not require a general plugin marketplace, arbitrary in-process repository code, MCP resources/prompts parity, ACP, a cloud app server, or a multi-language SDK.

## 16. Migration And Kernel Cutover

Migration is itself a versioned crash-recovery protocol, not a set of
best-effort marker files. The following JCS documents are the only durable
cutover objects. They contain no credential bytes, platform-secret handles, or
free-form extension fields.

```ts
type MigrationFilesystemRootIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-migration-filesystem-root-identity-v1'
  purpose: 'legacy_state' | 'backup'
  canonicalAbsolutePath: string
  ownerUid: number
  deviceId: string
  directoryFileId: string
  mode: number
  openedNoFollow: true
  identityDigest: string
}

type WindowsLegacyRootIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-windows-legacy-root-identity-v1'
  canonicalAbsolutePath: string
  ownerSid: string
  volumeSerialNumber: string
  fileId128: string
  fileAttributes: 'directory'
  reparseTag: 'none'
  securityDescriptorDigest: string
  identityDigest: string
}

type WindowsOutputDirectoryIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-windows-output-directory-identity-v1'
  canonicalAbsolutePath: string
  ownerSid: string
  volumeSerialNumber: string
  fileId128: string
  fileAttributes: 'directory'
  reparseTag: 'none'
  securityDescriptorDigest: string
  identityDigest: string
}

type WindowsExportFileIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-windows-export-file-identity-v1'
  phase: 'temporary' | 'final'
  outputDirectoryIdentityRef: ArtifactRef
  outputDirectoryIdentityDigest: string
  baseName: string
  ownerSid: string
  volumeSerialNumber: string
  fileId128: string
  fileAttributes: 'regular_file'
  reparseTag: 'none'
  securityDescriptorDigest: string
  byteCount: number
  contentDigest: string
  identityDigest: string
}

type LegacyPortableProjectionSchemaV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-portable-projection-schema-v1'
  sourceSchemaId:
    | 'session-v1'
    | 'session-v2'
    | 'record-v1'
    | 'compaction-v1'
    | 'plan-v1'
    | 'handoff-v1'
    | 'bookmark-v1'
  outputKind: 'session' | 'legacy_record' | 'legacy_compaction' | 'legacy_plan' | 'legacy_handoff' | 'legacy_bookmark'
  mappings: Array<{
    sourceJsonPointer: string
    targetJsonPointer: string
    transform: 'copy_finite_json' | 'nfc_string' | 'canonical_time_or_omit' | 'safe_integer'
    required: boolean
  }>
  forbiddenSourceJsonPointers: string[]
  outputJsonSchema: Record<string, unknown>
  schemaDigest: string
}

type LegacyPortableSchemaManifestV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-portable-schema-manifest-v1'
  projectionVersion: 'cliq-legacy-export-projection-v1'
  schemas: Array<{
    sourceSchemaId: LegacyPortableProjectionSchemaV1['sourceSchemaId']
    schemaRef: ArtifactRef
    schemaDigest: string
  }>
  manifestDigest: string
}

type LegacyPortablePayloadV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-portable-payload-v1'
  kind: 'legacy_record' | 'legacy_compaction' | 'legacy_plan' | 'legacy_handoff' | 'legacy_bookmark'
  legacySessionId: string
  sourceSchemaId: LegacyPortableProjectionSchemaV1['sourceSchemaId']
  sourceOrdinal: number
  sourceCanonicalRootRelativePath: string
  content: null | boolean | number | string | unknown[] | Record<string, unknown>
  payloadDigest: string
}

type LegacyPortableSessionV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-portable-session-v1'
  legacySessionId: string
  name?: string
  legacyWorkspacePath?: string
  payloads: Array<{
    kind: LegacyPortablePayloadV1['kind']
    sourceOrdinal: number
    payloadRef: ArtifactRef
    payloadDigest: string
  }>
  sessionDigest: string
}

type LegacyPortableHandoffV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-portable-handoff-v1'
  exportId: string
  sourcePlatform: 'windows'
  sourceRootIdentityRef: ArtifactRef
  sourceRootIdentityDigest: string
  exporterVersion: string
  exporterExecutableDigest: string
  projectionRuntimeBundleRef: ArtifactRef
  projectionRuntimeBundleManifestDigest: string
  projectionCatalogEntryId: 'legacy_windows_export_profiles_v1'
  projectionCatalogEntryVersion: '1'
  projectionSchemaManifestRef: ArtifactRef
  projectionSchemaManifestDigest: string
  sessions: Array<{
    legacySessionId: string
    sessionRef: ArtifactRef
    sessionDigest: string
  }>
  objectRefs: ArtifactRef[]
  excludedAuthorityPaths: ['auth.json']
  credentialProjection: 'none_reenrollment_required'
  createdAt: string
  manifestDigest: string
}

type LegacyPortableHandoffExportReceiptV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-portable-handoff-export-receipt-v1'
  exportId: string
  handoffRef: ArtifactRef
  handoffDigest: string
  outputCanonicalAbsolutePath: string
  outputDirectoryIdentityRef: ArtifactRef
  outputDirectoryIdentityDigest: string
  temporaryFileIdentityRef: ArtifactRef
  temporaryFileIdentityDigest: string
  finalFileIdentityRef: ArtifactRef
  finalFileIdentityDigest: string
  outputVolumeSerialNumber: string
  outputFileId128: string
  outputOwnerSid: string
  outputSecurityDescriptorDigest: string
  archiveByteCount: number
  archiveDigest: string
  completedAt: string
  receiptDigest: string
}

type LegacyPortableHandoffVerificationResultV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-portable-handoff-verification-result-v1'
  exportId: string
  archiveCanonicalAbsolutePath: string
  handoff: LegacyPortableHandoffV1
  outputDirectoryIdentity: WindowsOutputDirectoryIdentityV1
  finalFileIdentity: WindowsExportFileIdentityV1
  archiveByteCount: number
  archiveDigest: string
  verifiedAt: string
  verificationDigest: string
}

type LegacyAuthFileIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-auth-file-identity-v1'
  legacyRootIdentityRef: ArtifactRef
  legacyRootIdentityDigest: string
  canonicalRootRelativePath: 'auth.json'
  ownerUid: number
  deviceId: string
  fileId: string
  mode: 384
  linkCount: 1
  byteCount: number
  contentDigest: string
  identityDigest: string
}

type LegacyAuthStoreObservationV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-auth-store-observation-v1'
  migrationId: string
  legacyRootIdentityRef: ArtifactRef
  legacyRootIdentityDigest: string
  canonicalRootRelativePath: 'auth.json'
  observedAt: string
  observationDigest: string
} & (
  | {
      presence: 'present'
      fileIdentityRef: ArtifactRef
      fileIdentityDigest: string
      noFollowLookupResult?: never
    }
  | {
      presence: 'absent'
      noFollowLookupResult: 'ENOENT'
      fileIdentityRef?: never
      fileIdentityDigest?: never
    }
)

type LegacyAuthNonSecretProjectionV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-auth-nonsecret-projection-v1'
  migrationId: string
  sourceObservationRef: ArtifactRef
  sourceObservationDigest: string
  activeProvider?: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
  providers: Array<{
    providerId: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
    model?: string
    endpointRegistrationRef: ArtifactRef
    endpointRegistrationDigest: string
    baseUrlWasExplicit: boolean
    streaming?: 'auto' | 'on' | 'off'
    credentialLegacyEntryIdentityDigest?: string
  }>
  projectionDigest: string
}

type KernelSchemaManifestV1 = {
  schemaVersion: 1
  format: 'cliq-kernel-schema-manifest-v1'
  stateSchemaVersion: 1
  sqliteApplicationId: 0x434c4951
  sqliteUserVersion: 1
  ddlStatements: string[]
  sqliteSchemaObjects: Array<{
    type: 'table' | 'index' | 'view' | 'trigger'
    name: string
    tableName: string
    sql: string | null
  }>
  schemaDigest: string
  manifestDigest: string
}

type KernelDatabaseImageIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-kernel-database-image-identity-v1'
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  canonicalRootRelativePath: 'kernel/state.sqlite'
  ownerUid: number
  deviceId: string
  fileId: string
  mode: 384
  linkCount: 1
  byteCount: number
  sqliteApplicationId: 0x434c4951
  sqliteUserVersion: 1
  schemaManifestRef: ArtifactRef
  schemaManifestDigest: string
  schemaDigest: string
  journalClosure: 'connections_closed_after_wal_checkpoint_truncate'
  walPathAbsent: true
  shmPathAbsent: true
  foreignKeyCheck: 'ok'
  integrityCheck: 'ok'
  contentDigest: string
  identityDigest: string
}

type CasNamespaceManifestV1 = {
  schemaVersion: 1
  format: 'cliq-cas-namespace-manifest-v1'
  snapshotBoundary: 'generation_birth' | 'rollback_final'
  namespaceId: string
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  canonicalRootRelativePath: string
  ownerUid: number
  deviceId: string
  directoryFileId: string
  mode: 448
  entries: Array<{
    artifactRef: ArtifactRef
    byteCount: number
  }>
  objectCount: number
  totalBytes: number
  rootDigest: string
  manifestDigest: string
}

type KernelGenerationIdentityV1 = {
  schemaVersion: 1
  format: 'cliq-kernel-generation-identity-v1'
  generationId: string
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  databaseImageRef: ArtifactRef
  databaseImageDigest: string
  databaseIdentityDigest: string
  databaseContentDigest: string
  casNamespaceManifestRef: ArtifactRef
  casNamespaceManifestDigest: string
  casNamespaceId: string
  casRootDigest: string
  stateSchemaVersion: 1
  generationDigest: string
} & (
  | {
      origin: 'fresh_empty'
      pristineSchemaManifestRef: ArtifactRef
      pristineSchemaManifestDigest: string
      pristineSchemaDigest: string
      candidateRef?: never
      candidateDigest?: never
      migrationId?: never
    }
  | {
      origin: 'migrated_candidate'
      candidateRef: ArtifactRef
      candidateDigest: string
      migrationId: string
      pristineSchemaManifestRef?: never
      pristineSchemaManifestDigest?: never
      pristineSchemaDigest?: never
  }
)

type ArchivedKernelDatabaseImageV1 = {
  schemaVersion: 1
  format: 'cliq-archived-kernel-database-image-v1'
  migrationId: string
  sourceGenerationIdentityRef: ArtifactRef
  sourceGenerationIdentityDigest: string
  sourceDatabaseImageRef: ArtifactRef
  sourceDatabaseImageDigest: string
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  canonicalRootRelativePath: string
  ownerUid: number
  deviceId: string
  fileId: string
  mode: 256
  linkCount: 1
  byteCount: number
  sqliteApplicationId: 0x434c4951
  sqliteUserVersion: 1
  schemaManifestRef: ArtifactRef
  schemaManifestDigest: string
  schemaDigest: string
  copyMethod: 'descriptor_copy_of_closed_checkpointed_source'
  sourceContentDigest: string
  contentDigest: string
  copiedAt: string
  imageDigest: string
}

type ArchivedKernelGenerationManifestV1 = {
  schemaVersion: 1
  format: 'cliq-archived-kernel-generation-v1'
  migrationId: string
  sourceGenerationIdentityRef: ArtifactRef
  sourceGenerationIdentityDigest: string
  sourceGenerationId: string
  databaseImageRef: ArtifactRef
  databaseImageDigest: string
  databaseContentDigest: string
  casNamespaceManifestRef: ArtifactRef
  casNamespaceManifestDigest: string
  casNamespaceId: string
  casRootDigest: string
  snapshotBoundary: 'globally_quiescent_after_rollback_draining_before_rollback_restoring'
  excludedDatabaseTail: 'rollback_restoring_receipt_and_state_owner_terminalization'
  archivedAt: string
  manifestDigest: string
}

type MigrationInventoryEntryV1 = {
  canonicalRootRelativePath: string
  ownerUid: number
  deviceId: string
  fileId: string
  mode: number
} & (
  | {
      kind: 'directory'
    }
  | {
      kind: 'regular_file'
      linkCount: 1
      byteCount: number
      contentDigest: string
    }
  | {
      kind: 'unfollowed_link_metadata'
      linkTextDigest: string
    }
)

type MigrationInventoryManifestV1 = {
  schemaVersion: 1
  format: 'cliq-migration-inventory-v1'
  migrationId: string
  sourceLegacyGenerationDigest: string
  legacyRootIdentityRef: ArtifactRef
  legacyRootIdentityDigest: string
  legacyAuthObservationRef: ArtifactRef
  legacyAuthObservationDigest: string
  entries: MigrationInventoryEntryV1[]
  entriesDigest: string
  createdAt: string
  manifestDigest: string
}

type CredentialRoundTripEvidenceV1 = {
  schemaVersion: 1
  format: 'cliq-credential-round-trip-evidence-v1'
  migrationId: string
  legacyEntryIdentityDigest: string
  ownerPrincipalId: string
  credentialGrantId: string
  authorityRecordRevision: number
  authorityRecordDigest: string
  credentialGrantRef: ArtifactRef
  credentialGrantDigest: string
  endpointRegistrationRef: ArtifactRef
  endpointRegistrationDigest: string
  purpose: 'model_endpoint'
  credentialHandleIdentityDigest: string
  platformItemIdentityDigest: string
  observedStore: 'macos_login_keychain' | 'linux_default_secret_service'
  comparison: 'submitted_secret_equals_immediate_round_trip_bytes'
  persistedSecretInEvidence: false
  observedAt: string
  evidenceDigest: string
}

type PlaintextLegacyCredentialConsentV1 = {
  schemaVersion: 1
  format: 'cliq-plaintext-legacy-credential-consent-v1'
  migrationId: string
  principalId: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  requestRef: ArtifactRef
  requestId: string
  requestDigest: string
  backupRef: ArtifactRef
  backupDigest: string
  acknowledgement: 'render_current_platform_secrets_into_legacy_plaintext_auth_file'
  createdAt: string
  consentDigest: string
}

type RollbackToLegacyRequestBaseV1 = {
  schemaVersion: 1
  format: 'cliq-rollback-to-legacy-request-v1'
  migrationId: string
  principalId: string
  channelIdentityRef: ArtifactRef
  channelIdentityDigest: string
  requestId: string
  currentAuthorityMarkerRef: ArtifactRef
  currentAuthorityMarkerDigest: string
  currentKernelGenerationIdentityRef: ArtifactRef
  currentKernelGenerationIdentityDigest: string
  backupRef: ArtifactRef
  backupDigest: string
  requestedAt: string
  requestDigest: string
}

type RollbackToLegacyRequestV1 = RollbackToLegacyRequestBaseV1 & (
  | { allowPlaintextLegacyCredentials: false }
  | { allowPlaintextLegacyCredentials: true }
)

type CredentialReadyManifestV1 = {
  schemaVersion: 1
  format: 'cliq-credential-ready-v1'
  migrationId: string
  legacyAuthObservationRef: ArtifactRef
  legacyAuthObservationDigest: string
  nonSecretProjectionRef: ArtifactRef
  nonSecretProjectionDigest: string
  records: Array<{
    legacyEntryIdentityDigest: string
    providerId: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'
    endpointRegistrationRef: ArtifactRef
    endpointRegistrationDigest: string
    credentialGrantRef: ArtifactRef
    credentialGrantDigest: string
    credentialGrantId: string
    authorityRecordRevision: number
    authorityRecordDigest: string
    platformItemIdentityDigest: string
    roundTripEvidenceRef: ArtifactRef
    roundTripEvidenceDigest: string
  }>
  recordsDigest: string
  createdAt: string
  manifestDigest: string
}

type MigrationBackupManifestV1 = {
  schemaVersion: 1
  format: 'cliq-migration-backup-v1'
  migrationId: string
  inventoryRef: ArtifactRef
  inventoryDigest: string
  credentialReadyRef: ArtifactRef
  credentialReadyDigest: string
  backupRootIdentityRef: ArtifactRef
  backupRootIdentityDigest: string
  copiedEntriesDigest: string
  verifiedAt: string
  manifestDigest: string
}

type KernelCandidateManifestV1 = {
  schemaVersion: 1
  format: 'cliq-kernel-candidate-v1'
  migrationId: string
  candidateGenerationId: string
  inventoryRef: ArtifactRef
  inventoryDigest: string
  credentialReadyRef: ArtifactRef
  credentialReadyDigest: string
  backupRef: ArtifactRef
  backupDigest: string
  databaseImageRef: ArtifactRef
  databaseImageDigest: string
  databaseIdentityDigest: string
  databaseContentDigest: string
  casNamespaceManifestRef: ArtifactRef
  casNamespaceManifestDigest: string
  casNamespaceId: string
  casRootDigest: string
  importedSessionCount: number
  importedLegacyBookmarkCount: number
  schemaVersionInstalled: 1
  importComplete: true
  verifiedAt: string
  manifestDigest: string
}

type LegacyGenerationManifestBaseV1 = {
  schemaVersion: 1
  format: 'cliq-legacy-generation-v1'
  migrationId: string
  legacyGenerationId: string
  backupRef: ArtifactRef
  backupDigest: string
  restoredEntriesDigest: string
  verifiedAt: string
  manifestDigest: string
}

type LegacyGenerationManifestV1 = LegacyGenerationManifestBaseV1 & (
  | {
      authOutcome: 'restored_absent'
      restoredAuthObservationRef: ArtifactRef
      restoredAuthObservationDigest: string
      renderedAuthFileIdentityRef?: never
      renderedAuthFileIdentityDigest?: never
      renderedAuthFileContentDigest?: never
      plaintextCredentialConsentRef?: never
      plaintextCredentialConsentDigest?: never
    }
  | {
      authOutcome: 'rendered_nonsecret'
      renderedAuthFileIdentityRef: ArtifactRef
      renderedAuthFileIdentityDigest: string
      renderedAuthFileContentDigest: string
      restoredAuthObservationRef?: never
      restoredAuthObservationDigest?: never
      plaintextCredentialConsentRef?: never
      plaintextCredentialConsentDigest?: never
    }
  | {
      authOutcome: 'rendered_with_credentials'
      renderedAuthFileIdentityRef: ArtifactRef
      renderedAuthFileIdentityDigest: string
      renderedAuthFileContentDigest: string
      plaintextCredentialConsentRef: ArtifactRef
      plaintextCredentialConsentDigest: string
      restoredAuthObservationRef?: never
      restoredAuthObservationDigest?: never
    }
)

type LegacyAuthMigratedMarkerV1 = {
  schemaVersion: 1
  format: 'cliq-auth-migrated-v1'
  migrationId: string
  sourceObservationRef: ArtifactRef
  sourceObservationDigest: string
  credentialReadyRef: ArtifactRef
  credentialReadyDigest: string
  records: Array<{
    endpointRegistrationId: string
    credentialGrantId: string
    authorityRecordDigest: string
  }>
  markerDigest: string
}

type MigrationReceiptV1 = {
  schemaVersion: 1
  format: 'cliq-migration-receipt-v1'
  migrationId: string
  completedAt: string
  receiptDigest: string
} & (
  | {
      kind: 'kernel_cutover'
      inventoryRef: ArtifactRef
      inventoryDigest: string
      credentialReadyRef: ArtifactRef
      credentialReadyDigest: string
      backupRef: ArtifactRef
      backupDigest: string
      candidateRef: ArtifactRef
      candidateDigest: string
      kernelGenerationIdentityRef: ArtifactRef
      kernelGenerationIdentityDigest: string
      authMarkerDigest: string
      sourceLegacyGenerationDigest: string
    }
  | {
      kind: 'legacy_rollback'
      rollbackRequestRef: ArtifactRef
      rollbackRequestDigest: string
      backupRef: ArtifactRef
      backupDigest: string
      legacyGenerationRef: ArtifactRef
      legacyGenerationDigest: string
      archivedKernelGenerationRef: ArtifactRef
      archivedKernelGenerationDigest: string
    }
)

type MigrationAuthorityMarkerV1 = {
  schemaVersion: 1
  format: 'cliq-state-authority-v1'
  generationId: string
  migrationId: string
  receiptRef: ArtifactRef
  receiptDigest: string
  publishedAt: string
  markerDigest: string
} & (
  | {
      authority: 'kernel'
      candidateRef: ArtifactRef
      candidateDigest: string
      kernelGenerationIdentityRef: ArtifactRef
      kernelGenerationIdentityDigest: string
    }
  | {
      authority: 'legacy'
      legacyGenerationRef: ArtifactRef
      legacyGenerationDigest: string
    }
)

type MigrationControlBaseV1 = {
  schemaVersion: 1
  format: 'cliq-migration-control-v1'
  migrationId: string
  controlRevision: number
  sourceGenerationDigest: string
  targetGenerationId: string
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  createdAt: string
  updatedAt: string
  controlDigest: string
}

type MigrationControlV1 =
  | (MigrationControlBaseV1 & {
      phase: 'cutover_preflight'
      inventoryRef?: never
      inventoryDigest?: never
      credentialReadyRef?: never
      credentialReadyDigest?: never
      backupRef?: never
      backupDigest?: never
      candidateRef?: never
      candidateDigest?: never
      legacyGenerationRef?: never
      legacyGenerationDigest?: never
    })
  | (MigrationControlBaseV1 & {
      phase: 'cutover_candidate_ready'
      inventoryRef: ArtifactRef
      inventoryDigest: string
      credentialReadyRef: ArtifactRef
      credentialReadyDigest: string
      backupRef: ArtifactRef
      backupDigest: string
      candidateRef: ArtifactRef
      candidateDigest: string
      legacyGenerationRef?: never
      legacyGenerationDigest?: never
    })
  | (MigrationControlBaseV1 & {
      phase: 'credential_cutover'
      inventoryRef: ArtifactRef
      inventoryDigest: string
      credentialReadyRef: ArtifactRef
      credentialReadyDigest: string
      backupRef: ArtifactRef
      backupDigest: string
      candidateRef: ArtifactRef
      candidateDigest: string
      legacyAuthMarkerDigest: string
      legacyGenerationRef?: never
      legacyGenerationDigest?: never
    })
  | (MigrationControlBaseV1 & {
      phase: 'rollback_draining'
      rollbackRequestRef: ArtifactRef
      rollbackRequestDigest: string
      backupRef: ArtifactRef
      backupDigest: string
      sourceKernelGenerationIdentityRef: ArtifactRef
      sourceKernelGenerationIdentityDigest: string
      inventoryRef?: never
      inventoryDigest?: never
      credentialReadyRef?: never
      credentialReadyDigest?: never
      candidateRef?: never
      candidateDigest?: never
      legacyGenerationRef?: never
      legacyGenerationDigest?: never
    })
  | (MigrationControlBaseV1 & {
      phase: 'rollback_restoring'
      rollbackRequestRef: ArtifactRef
      rollbackRequestDigest: string
      backupRef: ArtifactRef
      backupDigest: string
      sourceKernelGenerationIdentityRef: ArtifactRef
      sourceKernelGenerationIdentityDigest: string
      archivedKernelGenerationRef: ArtifactRef
      archivedKernelGenerationDigest: string
      legacyGenerationRef: ArtifactRef
      legacyGenerationDigest: string
      preparedReceiptRef: ArtifactRef
      preparedReceiptDigest: string
      preparedLegacyAuthorityMarkerDigest: string
      inventoryRef?: never
      inventoryDigest?: never
      credentialReadyRef?: never
      credentialReadyDigest?: never
      candidateRef?: never
      candidateDigest?: never
    })
```

Native-Windows export is one exact, state-free archive protocol rather than a
promise to write “some JSON.” The only command form is
`cliq state export --output <absolute-new-file>`; `--output` is required, the
destination must not exist on first execution, and no Kernel state path may be
supplied or created. The sole exception is the exact final-present crash-replay
branch below, which accepts only the already-complete byte-identical export for
that requested basename. The compatibility binary first acquires every discoverable legacy
Session/transaction/plan lock in canonical case-folded UTF-16 path order. Its
signed native Windows helper opens the root with `CreateFileW` using an
extended-length absolute path plus `FILE_FLAG_OPEN_REPARSE_POINT`, verifies the
handle identity, and opens every descendant with `NtCreateFile`/
`NtOpenFile` `OBJECT_ATTRIBUTES.RootDirectory` set to the continuously held
parent directory handle. Every component uses `OBJ_CASE_INSENSITIVE`,
`FILE_OPEN_REPARSE_POINT`, `FILE_SYNCHRONOUS_IO_NONALERT`, share-read only, and
the least read/attribute/synchronize access required; a component containing
`\\`, `/`, empty, `.`, or `..` is rejected. After each open, the helper checks
`FileAttributeTagInfo`, `FileIdInfo`, volume serial, owner/security descriptor,
and parent-relative inventory before reading, and holds all source handles
through archive publication. `CreateFileW` is never claimed to provide a
root-directory handle parameter. `WindowsLegacyRootIdentityV1`,
`WindowsOutputDirectoryIdentityV1`, and `WindowsExportFileIdentityV1` each
compute `identityDigest` as SHA-256 of their JCS artifact with that member
omitted; the canonical extended-length path, owner SID, volume serial/file id,
no-reparse directory type, and self-relative security-descriptor digest all
come from the held handle. A junction, symlink/reparse point, file-id change,
sharing violation, unreadable ACL, changing inventory, or live unlocked legacy
writer fails without an output file.

The exporter recognizes only the literal source schema ids in
`LegacyPortableProjectionSchemaV1`. `projectionRuntimeBundleRef` rehashes the
exact Cliq-release-signed RuntimeBundle selected by the compatibility binary;
its manifest digest matches, and its sole non-executable `schema` entry with
id/version `legacy_windows_export_profiles_v1`/`1` has complete-byte content
ref and signed entry digest both equal to `projectionSchemaManifestRef`.
Decoding those exact bytes yields `LegacyPortableSchemaManifestV1`, whose
independently recomputed self-omitting `manifestDigest` equals
`projectionSchemaManifestDigest`; the complete-byte ref and semantic digest
are never compared. The bundle's unique
`structuredArtifacts(kind='legacy_portable_schema',artifactId='legacy_windows_export_profiles_v1')`
record repeats that root pair and lists exactly the manifest's distinct schema
refs as signed `bundle_object` members, so fresh state-free Windows export can
resolve every profile without Kernel CAS or an ambient package path. The
manifest signs every profile ref/digest, so neither exporter nor verifier may
use an ambient mapping table. Each profile's `schemaDigest` omits itself; mappings
are unique and byte-sorted by target JSON Pointer, pointers are valid RFC 6901,
and the finite output schema uses the same bounded nonrecursive JSON subset as
control input. `forbiddenSourceJsonPointers` is unique/byte-sorted and includes
every structured auth/credential/api-key/token/cookie/header/env/execution-
owner/lease field known to that source schema. A forbidden field present with
any value rejects export rather than redacting heuristically. Mappings copy
only their named value with the displayed deterministic transform, unknown
source/output fields are rejected, and output validates the embedded schema.
Transform behavior is exact: `copy_finite_json` requires the source value
already satisfy the bounded finite nonrecursive JSON subset and copies its JCS
value; `nfc_string` requires one string, rejects NUL/unpaired surrogates, and
emits NFC; `canonical_time_or_omit` omits an absent/null optional source, but
otherwise requires and emits the global canonical UTC-millisecond timestamp;
`safe_integer` requires a JSON number that is a safe integer and emits that
same mathematical integer. A required absent/null value or any transform type,
range, normalization, or bound failure rejects the export. Target pointers
must be nonoverlapping leaves; parents are constructed only as required by the
finite output schema, in pointer order, with no merge/coercion/default rule.
The schema manifest is unique/byte-sorted by source schema id, rehashes every
profile, and its digest omits itself. An unknown legacy schema or profile
digest fails closed.

Each supported legacy Session becomes one `LegacyPortableSessionV1`; its
payload list is strictly increasing by source ordinal and contains the
all-and-only schema-projected records, compactions, plans, handoffs, and old
checkpoints/bookmarks. Each payload's source path and ordinal equal the held
inventory, its `content` is finite schema-normalized JSON, and
`payloadDigest` omits itself. Session name/workspace locator are NFC metadata
only; active/queued/lease/transaction/runner/checkpoint-execution state is not
projected. The workspace locator grants no authority on another host.
`auth.json`, credential-store material, environment/header/cookie/token fields,
raw credential bytes, and executable ownership are absent; credentials must be
re-enrolled. Arbitrary user-authored message text is preserved after NFC
normalization and is not falsely claimed to have undergone secret detection:
the credential-free guarantee covers Cliq's structured authority, not secrets
a user pasted into prose.

`sessionDigest`, `LegacyPortableHandoffV1.manifestDigest`, and the export
receipt digest each omit themselves under JCS. Sessions are unique and
byte-sorted by legacy id. `objectRefs` is the unique byte-sorted all-and-only
closure of the source-root identity artifact, projection RuntimeBundle
manifest, projection-schema manifest/profiles, Session artifacts, and payload
artifacts; every tuple ref/digest rehashes exact bytes. In particular,
`sourceRootIdentityRef` and `projectionRuntimeBundleRef` each occur exactly once
in `objectRefs`, so the state-free verifier can decode both authority roots. To avoid a
fixed point, `exportId = H('cliq-windows-legacy-export-v1',
sourceRootIdentityDigest,SHA-256(JCS(the handoff with exportId and
manifestDigest omitted)))`; the final `manifestDigest` then omits only itself.
`createdAt` uses canonical UTC milliseconds and is the sole intentional
per-export variation.

The archive bytes are exactly ASCII `CLIQ-LEGACY-HANDOFF-V1\n`, one unsigned
64-bit big-endian manifest-byte length, the exact JCS handoff bytes, then for
each `objectRefs` entry: its 64 lowercase-ASCII hex ref, one unsigned 64-bit
big-endian byte length, and the complete artifact bytes. There is no padding,
compression, filename, host path, permission, locale, random container id, or
timestamp outside the manifest. The reader rejects trailing bytes,
duplicate/missing/out-of-order objects, unsafe lengths, ref mismatch, or an
object not reachable from the manifest. `archiveDigest` is SHA-256 of that
complete byte sequence.

Publication opens the output parent component-by-component with the same
held-root `NtCreateFile`/`NtOpenFile` no-reparse protocol and publishes exact
`WindowsOutputDirectoryIdentityV1`; the final basename is one NFC, nonempty,
non-reserved Windows filename with no separator, trailing dot/space, device
name, alternate data stream, or case-fold collision. Under that continuously
held parent handle it derives the stable temporary basename
`.cliq-export-<H(outputDirectoryIdentityDigest,final-basename)>.tmp` with
lowercase hex and creates it with `NtCreateFile(RootDirectory=parent,
CreateDisposition=FILE_CREATE, FILE_NON_DIRECTORY_FILE |
FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT)`, owner-only security,
share-read only, and no replace. It writes and `FlushFileBuffers` all bytes,
rereads that same handle, verifies the archive, and only then publishes exact
immutable temporary `WindowsExportFileIdentityV1`; no identity claiming final
content is published before the write completes. It then calls
`SetFileInformationByHandle(FileRenameInfoEx)` with flags zero,
`RootDirectory=the same held parent`, and the final basename. Thus replace,
cross-directory, POSIX, and path-reparse rename semantics are all disabled.
It flushes the held parent directory handle, reopens the final basename
relative to that same handle, and publishes exact final
`WindowsExportFileIdentityV1`; temporary and final identities have the same
volume/file id, owner/security, byte count, and archive digest, differ only in
phase/name, and the temporary name is absent. The CLI returns exact
`LegacyPortableHandoffExportReceiptV1` on stdout; it is not stored in Kernel
state. Its directory/temp/final ref/digest pairs rehash those artifacts, its
final path is parent path plus basename, and the duplicate
volume/file/owner/security/count fields equal the decoded final identity.
`completedAt` is exactly the retained `LegacyPortableHandoffV1.createdAt`, not
a second post-rename clock read, and `receiptDigest` is SHA-256 of receipt JCS
with only itself omitted; therefore final-present replay reconstructs the
byte-identical receipt. An
existing target, parent/file identity change, cross-volume rename, partial
write, failed file/parent flush, or reparse/case-fold substitution leaves no
new final file. On entry and after any failure, the held parent checks exactly
the requested final basename and that one stable temp name. If the final
basename exists, the helper opens it relative to the held parent without
following a reparse point, verifies its owner/directory/file identity and
complete archive, derives the same retained handoff/export id/createdAt from
those bytes, reconstructs the post-write temporary and final identity artifacts
plus receipt, flushes the held parent, and returns that same logical export; a
simultaneous temp, unknown/reparse final, invalid archive, identity mismatch,
or bytes for another requested export block and are never overwritten or
deleted. If the final is absent and the stable temp is a complete
owner/parent/identity-valid archive, the command resumes its exact retained
manifest/createdAt through verification and rename and returns the same logical
export. If only the temp is partial or invalid on process re-entry, no durable
creation identity exists and the helper returns `RECOVERY_REQUIRED` with
bounded owner-only manual-cleanup guidance; it never deletes that
predictable-name file. Only the same live process that obtained `FILE_CREATE`
may remove an incomplete temp through its continuously held creation handle
after rechecking the identical volume/file id, then flush the parent. An
unknown/reparse/identity-changing temp also blocks rather than being followed
or deleted. Thus crashes at create, write, file flush, verification, rename, or
parent flush cannot leak an untracked series of context archives, reject a
correctly renamed export, or choose a scan result. `cliq state export --verify
<absolute-file>` is the sole v1 consumer. It opens the absolute parent/file by
the same held no-reparse protocol, performs the same bounded
parse/rehash/schema checks, and emits exact JCS
`LegacyPortableHandoffVerificationResultV1` without opening/creating Kernel
state. Its inline handoff is the decoded archive manifest; `exportId`, byte
count, and archive digest equal those bytes; the inline output-directory and
final-file identities are reobserved from the held handles, the file has
`phase='final'` and names/digests the inline directory identity, and its byte
count/content digest equal the archive. `verifiedAt` is the canonical fenced
time after the final reread, and `verificationDigest` is SHA-256 of result JCS
with only itself omitted. The result has no temporary identity or synthetic
completion time and is therefore total for an independently supplied valid
archive. Kernel Cut deliberately provides no Session/import mutation for this
archive; a later import requires a separate authority/mapping RFC. Thus
“portable” means a byte-exact independently verifiable preservation format,
not a hidden Windows importer.

Only the container self-digests `manifestDigest`, `markerDigest`,
`receiptDigest`, and `controlDigest` are SHA-256 of their complete RFC 8785/JCS
container with that one self-digest member omitted. Every ref/digest pair is
instead the hash of the exact referenced artifact bytes; source-generation,
identity, content, record, evidence, consent, database, and CAS digests follow
their separately named producer/type and are never rehashes of the migration
container. `entriesDigest = SHA-256(JCS(entries))`, and
`recordsDigest = SHA-256(JCS(records))`, and
`copiedEntriesDigest`/`restoredEntriesDigest` are SHA-256 of the byte-sorted
array of `{canonicalRootRelativePath,contentDigest}` reobserved from the copied
or restored regular files. Inventory entries and credential records are byte-sorted
by canonical path and `(providerId,legacyEntryIdentityDigest)` respectively,
are unique. Counts are nonnegative safe integers. Canonical paths are NFC,
root-relative, slash-separated, contain no empty/`.`/`..` component, and never
name `auth.json`; file identities come from the continuously held no-follow
descriptors. The backup's copied-entry digest must equal a descriptor-relative
rehash of every regular inventory entry, and its inventory and ready-manifest
refs must equal the candidate. The candidate digest covers the fsynced SQLite
image plus its private CAS namespace before either can become writable. A
legacy generation exactly rehashes the restored backup. Its auth outcome is a
closed union: `restored_absent` requires a fresh absent
`LegacyAuthStoreObservationV1`; `rendered_nonsecret` requires one rehashed
`LegacyAuthFileIdentityV1`/content and forbids consent; and
`rendered_with_credentials` requires that same identity/content plus exact
plaintext consent. No branch may retain fields from another outcome.

`LegacyAuthStoreObservationV1.observationDigest`,
`LegacyAuthNonSecretProjectionV1.projectionDigest`,
`CredentialRoundTripEvidenceV1.evidenceDigest`, and
`PlaintextLegacyCredentialConsentV1.consentDigest` omit themselves under JCS.
The source observation is created while the legacy-auth lock and root
descriptor are held. Its `present` branch rehashes one exact
`LegacyAuthFileIdentityV1`; its `absent` branch records descriptor-relative
no-follow `ENOENT` and structurally forbids a file identity. Inventory, ready
manifest, non-secret projection, and migrated marker all repeat that same
observation ref/digest. An absent observation requires an empty projection and
`records=[]`; a present recognized store may also have zero records.

The non-secret projection is the complete normalized ProviderAuthStore-v1
shape with every `apiKey` removed. Providers are unique and byte-sorted by id;
each exact endpoint-registration ref reproduces the accepted HTTPS `baseUrl`,
`baseUrlWasExplicit` controls whether the renderer emits it, and optional
model/streaming/active-provider presence is preserved. A provider entry with a
secret names exactly one `credentialLegacyEntryIdentityDigest`; one without a
secret forbids it. That identity is
`H(migrationId,providerId,endpointRegistrationDigest,model-or-null,streaming-or-null)`
and contains no secret-derived bytes.

Ready records are a bijection, not a partial enrollment list. Project the
provider entries having `credentialLegacyEntryIdentityDigest`, in their same
byte-sorted order, to `(providerId,credentialLegacyEntryIdentityDigest,
endpointRegistrationRef,endpointRegistrationDigest)`; the ready manifest has
exactly one record for every tuple and no other record, and each record repeats
all four fields byte-for-byte. Therefore absent and present-without-secret
sources have `records=[]`; omission, duplication, extra enrollment, provider
substitution, or endpoint splicing blocks marker publication.

Each ready record's evidence ref/digest repeats its migration/legacy entry,
owner, credential-grant id, latest active authority revision/digest, exact
endpoint and binding refs/digests, purpose, credential-handle identity, and
platform-item identity. `platformItemIdentityDigest =
SHA-256(JCS(CredentialAuthorityRecordV1.platformItem))`; the exact mapping is
`macos_keychain -> macos_login_keychain` and
`linux_secret_service -> linux_default_secret_service`. The credential binding decodes from the latest active record
byte-for-byte (owner/grant/revision/purpose/endpoint/TLS/handle/timestamps and
expiry), and the endpoint ref decodes the same owner's latest active endpoint
record. The round trip asserts only an immediate in-memory equality check
through that same-user platform item while the credential-authority lock is
held; it carries no secret or reusable handle. Splicing evidence, a platform
item, endpoint, or binding from another record is invalid. Every rollback
begins from exact `RollbackToLegacyRequestV1`, including outcomes that render
no secret. `requestDigest = SHA-256(JCS(request with requestDigest omitted))`;
its authority-marker ref/digest decodes the current Kernel branch, its
generation ref/digest equals that marker, and its backup ref/digest equals the
marker's kernel-cutover receipt. Both rollback control phases and the legacy
receipt repeat the same request pair. Rollback consent is created only from the
request's `allowPlaintextLegacyCredentials=true` branch: request and consent
migration/principal/channel/request id+digest/backup fields are byte-identical,
`requestRef` rehashes those exact bytes, and literal true maps only to the
consent's literal acknowledgement. The false branch permits
`restored_absent|rendered_nonsecret` but cannot derive consent or render any
secret. The legacy-generation consent ref/digest must decode that
artifact and is required only by `rendered_with_credentials`. A command-line
flag not normalized into this request, log line, environment variable, or
free-form text is not round-trip evidence or plaintext consent.

`LegacyAuthMigratedMarkerV1.records` is the byte-sorted exact projection of
the ready records to decoded endpoint-registration id, credential-grant id,
and latest authority-record digest; its source observation and ready ref/digest
are identical. It cannot omit, add, reorder semantically, or rewrite a record.

`MigrationFilesystemRootIdentityV1.identityDigest`,
`LegacyAuthFileIdentityV1.identityDigest`,
`KernelSchemaManifestV1.manifestDigest`,
`KernelDatabaseImageIdentityV1.identityDigest`,
`ArchivedKernelDatabaseImageV1.imageDigest`,
`CasNamespaceManifestV1.manifestDigest`, and
`KernelGenerationIdentityV1.generationDigest` omit only themselves under JCS.
Migration roots are absolute NFC same-user held directory descriptors with no
empty/`.`/`..` component; a backup root is mode `0700`, while an accepted
legacy root is not group/world writable. For a present source, the auth
identity's root ref/digest, `0600` regular file, link count, device/file id,
size, and content digest equal the original continuously held
ProviderAuthStore descriptor; for an absent source, no auth-file identity may
exist. Ready and inventory manifests repeat the exact observation rather than
inventing an empty file. A fresh Kernel generation
identity requires the fixed empty schema image and empty private CAS namespace.
A migrated identity requires an exact `KernelCandidateManifestV1`; migration
id, candidate generation id, database identity/content, CAS namespace/root,
and installed schema version match byte-for-byte.

`KernelSchemaManifestV1` is the sole v1 database-schema authority. Its complete
bytes must be the content of exactly one signed non-executable RuntimeBundle
entry with `role='schema'`, `entryId='kernel_state_schema_v1'`, and version
`1`; the active or candidate bundle entry digest equals its ArtifactRef and
fixed Supervisor code interprets it as data rather than spawning or
dynamically loading it. `ddlStatements` is the nonempty execution-order list
of exact NFC, no-NUL UTF-8 SQL statements and contains no transaction,
attach/detach, pragma, vacuum, extension, writable-schema, temp-object, or
external-function statement. After executing those statements in one fresh
empty SQLite database, setting the literal application/user versions, and
committing, the byte-sorted projection of every `sqlite_schema` row to
`(type,name,tbl_name AS tableName,sql)` equals `sqliteSchemaObjects` exactly;
SQLite-generated autoindexes are retained with `sql=null`, and no unlisted
table, index, view, trigger, temporary schema object, or host migration is
legal. Names and SQL text are the exact SQLite-returned NFC/no-NUL values;
object tuples are unique and byte-sorted by
`(type,name,tableName,sql-or-empty)`.
`schemaDigest = SHA-256(JCS({stateSchemaVersion,sqliteApplicationId,
sqliteUserVersion,ddlStatements,sqliteSchemaObjects}))`, while
`manifestDigest = SHA-256(JCS(manifest with manifestDigest omitted))`. Thus a
DDL file, `sqlite_master` dump, mutable migration registry, or merely equal
`PRAGMA user_version` cannot substitute for the signed schema profile.

`KernelDatabaseImageIdentityV1` is produced only with all database connections
closed after `PRAGMA wal_checkpoint(TRUNCATE)`, no `-wal`/`-shm` directory
entry, and file plus parent directory fsynced. Its held no-follow same-user
regular-file identity, `0600` mode, one link, byte count, application/user
versions, full-file SHA-256 `contentDigest`, and successful
foreign-key/integrity checks are exact; a logical dump, live WAL tuple, copied
main file with an uncheckpointed WAL, or reopened path is not the image.
Its schema-manifest ref/digest rehash that exact signed profile, its application
and user versions equal the profile, a fresh read transaction reproduces the
profile's complete `sqliteSchemaObjects` projection, and `schemaDigest` equals
the decoded profile's `schemaDigest`. `ArchivedKernelDatabaseImageV1` repeats
the same manifest ref/digest/schema digest as its source database image and
must reproduce the same projection after the descriptor copy.

`CasNamespaceManifestV1` is an immutable boundary snapshot, not a timeless
claim that an active append-only namespace can never grow. A
`generation_birth` snapshot covers exactly the candidate/fresh generation's
payload objects immediately before the authority marker or first StateOwner
transaction; the held publication gate requires a final all-and-only scan at
that boundary. After that authority transition, ordinary Run publication may
append objects to the same generation namespace. Revalidating the historical
birth snapshot rehashes every listed entry but does not classify later objects
as extraneous. A `rollback_final` snapshot is different: global no-write proof
remains current, it covers every object then present, and the namespace is
sealed read-only, so its all-and-only claim remains permanent. Both forms
exclude the manifest itself and migration-control artifacts. Their directory
is `${stateRoot}/cas/namespaces/<namespaceId>`, opened descriptor-relatively as
the held same-user `0700` identity. Entries are unique and byte-sorted by
`artifactRef`; each path is the fixed lowercase SHA-256 fanout
`sha256/<first-two-hex>/<full-hex>` for that raw ref, rehashes to it, and has the
exact nonnegative safe-integer byte count. `objectCount=entries.length`,
`totalBytes` is their checked sum, and `rootDigest=SHA-256(JCS(entries))`;
unknown/extraneous payload objects at the named snapshot boundary, missing
listed objects, symlinks, hardlinks, or mismatched bytes invalidate it.
Migration control, receipt, authority, archive-manifest, and other deliberately
out-of-generation objects use
`${stateRoot}/migration/artifacts/sha256/<first-two-hex>/<full-hex>` or their
separately fixed descriptor-held database/archive paths, so they are excluded
from the namespace manifest and the candidate cannot form a content-addressed
cycle.

Every candidate/generation database-image and CAS-manifest ref/digest rehashes
the exact artifacts above. `databaseIdentityDigest`/`databaseContentDigest`
equal the decoded database identity/content fields, and
`casNamespaceId`/`casRootDigest` equal the decoded namespace id/root. Candidate
and generation identities require `snapshotBoundary='generation_birth'` and
repeat those six values byte-for-byte; no adapter,
directory name, WAL timestamp, SQLite row count, or partial CAS scan may supply
one independently. A `fresh_empty` generation additionally requires
`pristineSchemaManifestRef|Digest` equal its decoded database image's exact
schema-manifest pair and `pristineSchemaDigest` equal both decoded artifacts'
`schemaDigest`. A `migrated_candidate` forbids those three pristine fields and
instead requires its candidate's decoded database image to carry the same
signed schema manifest/digest; the candidate's literal installed/state schema
version equals that manifest. No generation may splice a schema digest from a
different RuntimeBundle entry or image.

Rollback archives are a second, acyclic snapshot closure rather than a reuse
of the admission-time generation identity. After `rollback_draining` is
durable and every productive authority is globally quiescent, the Supervisor
closes all SQLite connections, performs the same checkpoint/integrity sequence,
and publishes a fresh `KernelDatabaseImageIdentityV1` for the exact current
live main-file bytes. While no Kernel write is possible it descriptor-copies
those bytes to
`${stateRoot}/migration/archive/<migrationId>/<sourceGenerationId>/state.sqlite`,
file- and directory-fsyncs the copy, changes it to read-only `0400`, and
publishes `ArchivedKernelDatabaseImageV1`. The archive path is derived exactly
from its migration/source-generation pair; its held same-user no-follow
regular-file identity has one link, its application/user/schema values equal
the source image, and `sourceContentDigest=contentDigest` equals a full rehash
of both source and copied bytes. A SQLite backup with different bytes, a live
WAL tuple, a mutable copy, or a path outside that derived directory is invalid.

At that same no-write boundary the Supervisor publishes a fresh
`CasNamespaceManifestV1(snapshotBoundary='rollback_final')` over every payload
object then reachable in the generation's complete private namespace and seals
that namespace read-only.
`ArchivedKernelGenerationManifestV1` repeats the current authority marker's
source-generation identity/id, the exact archived database image and content
digest, and that final CAS namespace/id/root; every ref/digest rehashes and
`manifestDigest` omits itself under JCS. Its two literal boundary fields state
the deliberate acyclic cut: the snapshot contains all productive state through
global drain, while the later `rollback_restoring` control/receipt and
StateOwner terminalization are excluded from the copied database. Those
excluded facts remain independently retained and digest-bound by the rollback
receipt, migration control, and StateOwner evidence; they are never claimed as
rows in the archived database image. Archive objects live outside the archived
CAS namespace, so neither snapshot hashes itself.

For `fresh_empty`, `generationId = H('fresh-kernel-generation',
stateRootIdentityDigest,databaseIdentityDigest,casNamespaceId)`; for
`migrated_candidate`, `generationId = H(migrationId,'kernel')`. It is stable
across content growth of that one authoritative generation, while
`generationDigest` binds its admission-time database/CAS roots. Within one migration,
`targetGenerationId = H(migrationId,targetAuthority)` where target authority is
`kernel` for cutover and `legacy` for rollback.
`KernelCandidateManifestV1.candidateGenerationId` and the cutover control equal
that Kernel target id; `LegacyGenerationManifestV1.legacyGenerationId` and the
rollback control equal that legacy target id. Every control revision, manifest,
receipt, and marker repeats the same migration id. The source-generation digest
is the current valid authority-marker digest, or for the one unmarked initial
legacy import `H('unmarked-legacy',legacyRootIdentityDigest)`; inventory and
cutover receipt repeat it. The Kernel receipt/authority marker repeat the same
generation-identity ref/digest and marker `generationId` equals that identity;
the legacy receipt/marker repeat the exact legacy manifest and id. No free
string, timestamp, or directory name is a generation identity.
For a fresh generation, `casNamespaceId =
H('fresh-cas-namespace',stateRootIdentityDigest,databaseIdentityDigest)`; for a
migrated candidate it is `H(migrationId,'kernel-cas')`. The rollback request
and `rollback_draining` control repeat the exact source
`KernelGenerationIdentityV1` named by the current Kernel authority marker.
Only after the globally quiescent snapshot exists may control advance to
`rollback_restoring`; that revision and the legacy receipt repeat the exact
`ArchivedKernelGenerationManifestV1` ref/digest. Its source identity equals the
request/current marker, and its database/CAS closure is the one produced at the
boundary above, so neither a birth image nor another generation's later
database/CAS pair can be substituted.

The sole sentinel is the exact JCS `MigrationControlV1` at
`${stateRoot}/migration/control-v1.json`; the phrases
`cutover-in-progress`, `credential-cutover-in-progress`, and
`rollback-in-progress` mean its corresponding phase, never another flag. The
authority decision is the exact `MigrationAuthorityMarkerV1` at
`${stateRoot}/migration/authority-v1.json`; rollback additionally copies the
same legacy branch marker to the held legacy root as
`.cliq-generation-v1.json`. `LegacyAuthMigratedMarkerV1` is the complete and
only accepted post-cutover body for `~/.cliq/auth.json`; it repeats the source
present/absent observation and is created in both branches so an old parser
cannot mistake an absent pre-cutover store for current authority. Every control,
authority, copied legacy-authority, and auth-marker filesystem document is
UTF-8 JCS without BOM/newline, mode `0600`, written through a
same-directory no-follow temporary regular file, file-fsynced, atomically
renamed, and parent-directory-fsynced. Their state-root/legacy-root descriptor
identity must remain the one frozen by the control/manifest throughout.

`controlRevision` starts at one and changes only by a same-migration-id atomic
replace through the closed spine
`cutover_preflight -> cutover_candidate_ready -> credential_cutover` or
`rollback_draining -> rollback_restoring`; revisions are contiguous and no
phase moves backward or crosses spines. Artifacts are published and rehashed
before the control revision that references them. The terminal receipt is
published after its branch bytes verify; the matching authority marker is
published **last**, points to that receipt, and is never referenced by the
receipt, so publication is acyclic. Only after that marker and its parent
directory are durable may startup treat the target authority as active or
delete the control file. Clearing the control file is cleanup, not an authority
transition.

Startup opens and validates the two exact paths under the migration/rollback
lock order before opening either runtime. A valid authority marker whose
receipt and generation closure rehash makes that branch authoritative and
allows only idempotent control cleanup. With no target authority marker,
cutover preflight/candidate phases leave legacy authoritative; a
`credential_cutover` phase must first restore the source observation before
legacy can run or the sentinel can clear. For `present`, it decodes the
non-secret projection, reads only the ready manifest's still-matching platform
items, and atomically installs the deterministic normalized
ProviderAuthStore-v1 rendering; for `absent`, it unlinks any migrated marker,
verifies descriptor-relative no-follow `ENOENT`, and parent-directory-fsyncs.
A rollback
phase leaves Kernel authority fenced and resumes drain/restore only; legacy
cannot run until the legacy receipt and both identical legacy authority markers
are durable. Missing, malformed, unknown-version, mismatched-id/digest,
split-brain, skipped-revision, or doubly authoritative files block both
runtimes with a typed recovery diagnostic. No timestamp, file-existence order,
or “most recent” heuristic chooses authority.

### 16.1 One-Time Import

`cliq state migrate --check` is a pure preflight, not an importer attempt. It
may hold existing advisory locks and descriptor-open legacy roots long enough
to run the same discovery, quiescence, auth-presence, schema, path, ownership,
and remediation planner used by migration, but it performs no platform-secret
write/round trip and creates or mutates no StateRoot, lock file, migration
control, credential/endpoint authority row, platform item, backup, CAS object,
SQLite database, auth marker, receipt, or authority marker. It publishes no
artifact and calls no fsync/rename/unlink path. Its bounded deterministic report
labels credential enrollment/round-trip and every later mutation as required,
not completed. The real command reruns all observations under the full lock
order and never trusts a prior report. Fault tests compare the complete legacy
tree, StateRoot existence/content, and platform-store inventory before and
after `--check`, including failure paths, before invoking the real importer.

The importer runs under a global Cliq state lock and:

1. installs a cutover-in-progress sentinel honored by the Kernel Cut binary and acquires, then continuously holds through step 8, the one canonical order: exclusive Kernel global/cutover gate plus current state-owner lock, local-model registry/object-store lock, legacy auth-store lock, every discoverable legacy Session/transaction/plan lock in canonical byte order, then the credential-authority lock;
2. on supported macOS/Linux (including qualifying WSL2), enumerates same-user processes with the shared legacy-quiescence inspector and refuses unless it can prove that no process executes the legacy package/entrypoint or holds an open descriptor below the legacy state roots. Because Cliq is a Node CLI, proof inspects permission-readable canonical argv/command lines, npm/npx/shebang launch chains, package realpath plus installed version/digest, executable image, locks, and open roots; seeing only `node` is insufficient. An unreadable/indeterminate process blocks migration. Native Windows never enters this importer; its exact export-only surfaces are `cliq state export --output <absolute-new-file>` and the state-free `--verify <absolute-file>` reader defined above, and neither creates or opens Kernel state;
3. before general inventory, observes `~/.cliq/auth.json` under the held root descriptor and auth lock. A present entry must be one same-owner regular-file/link-count-one/no-follow descriptor and decode the recognized ProviderAuthStore-v1 shape; an absent entry must be exact descriptor-relative `ENOENT`. Present entries run section 5 deterministic per-entry endpoint/credential enrollment, every secret platform item round-trips, and both branches publish the exact source observation, complete non-secret projection, and secret-free credential-ready manifest while leaving the original present bytes or exact absence authoritative;
4. inventories and hashes the complete **noncredential** legacy store, checks active/incomplete transactions, refuses unresolved state with an exact supported remediation command, excludes `auth.json` bytes, and records only its source observation plus the credential-ready manifest;
5. creates and verifies a timestamped read-only backup of that noncredential inventory and secret-free manifest; no raw key, credential file, platform secret, or premature migrated marker enters backup/CAS/SQLite/archive/logs;
6. rescans processes, revalidates the same auth observation (held file identity for `present`, no-follow `ENOENT` for `absent`), and rehashes the locked noncredential inventory immediately before publication; any presence, identity, file, or process change aborts;
7. builds a unique candidate SQLite/CAS generation; imports Sessions, records, compactions, plans, handoff references, old checkpoints only as `legacy-bookmark` artifacts, and resets ownerless legacy Session execution lifecycle fields to context-only state; then validates/fsyncs the complete candidate and atomically marks only that database's schema/import complete;
8. after every candidate byte verifies, publishes `credential_cutover`, atomically replaces a present file or creates over verified absence and directory-fsyncs `auth.json` with the secret-free `cliq-auth-migrated-v1` marker naming the source observation plus only migration/endpoint/grant ids and record digests, then publishes the Kernel authority/cutover receipt **last** and clears the control file.

Before step 8, legacy state and the observed auth state remain authoritative: raw ProviderAuthStore-v1 bytes for `present`, exact absence for `absent`. A crash may leave only replayable credential operations, the secret-free ready manifest, backup, or unpublished candidate. If a crash occurs after marker publication but before Kernel authority publication, the new binary restores the observed branch before clearing control. `present` reads the exact ready platform items and non-secret projection and deterministically renders, validates, file-fsyncs, atomically installs, and directory-fsyncs semantically identical normalized ProviderAuthStore-v1 bytes; it does not claim byte identity with arbitrary original whitespace/key order. `absent` unlinks the marker through the held parent descriptor, verifies no-follow `ENOENT`, and directory-fsyncs. Legacy remains usable in either case. After authority publication recovery completes/validates the marker. Unsupported/plain-HTTP/raw-Ollama/ambiguous entries, unavailable platform store, failed round trip/replacement/restoration, or observation drift blocks authority publication. The packaged command cannot admit new legacy work while control exists. A deliberately launched unsupported old binary from another installation is outside the same-user trust boundary; its later JSON writes never enter new authority, are detected as post-cutover divergence, and block downgrade rollback until exported. Migration fails closed when process enumeration, open-file inspection, platform-secret access, or legacy-lock acquisition is unavailable.

Inventory/backup never follows legacy links. Each declared legacy root is opened as a same-user directory handle and traversed component-by-component with descriptor-relative no-follow operations. A recognized state file must be a same-user regular file with link count one and stable device/inode/size/digest while its handle is held; a symlink, hardlink, special file, mount escape, ownership mismatch, or changed identity aborts. Unknown entries are preserved in the backup manifest only as non-followed metadata/link text unless they are safe regular files inside the root; they never become typed state. The second scan revalidates the same held identities immediately before authority publication.

Old checkpoints never become Run recovery checkpoints. No synthetic nonterminal Run is created from a legacy Session lifecycle flag.

### 16.2 No Long-Term Dual Write

After cutover, SQLite and CAS are authoritative. The runtime does not dual-write Session JSON and SQLite, and the old runner is not retained behind a long-lived compatibility flag.

### 16.3 Rollback

Rollback is an explicit command executed by the new binary before installing an old binary. The stable same-user bootstrap authenticates the local request and hands it to the current Supervisor; that Supervisor reuses its unforgeable already-held active `StateOwnerRecordV1`/OS-lock token. If no healthy Supervisor can receive it, the bootstrap must first use the exact death-proven `takeoverStateOwner` transition and then run rollback in that successor. The CLI never waits on, steals, or recursively acquires a lock held by the live Supervisor, and rollback is not an untyped public ControlMethod. It:

- first reuses that current held state-owner token and acquires the remaining locks in the one migration/rollback order—exclusive Kernel global/cutover gate, local-model registry/object-store lock, legacy auth-store, every legacy Session/transaction/plan lock in canonical byte order, then credential-authority—gates the control socket and every broker release, and rejects every new admission, Session/Run/admin/auth/MCP mutation, credential/local-model operation, local-service activation/join, worker/admin/invocation claim, and model/tool/provider request; under those locks it refuses and restores ordinary service without publishing a sentinel if any nonterminal Run exists;
- exports terminal Run results and audit references;
- durably publishes a non-authoritative rollback-in-progress sentinel that is also the persistent global rollback fence, names the selected verified backup/new legacy generation, and causes restart to resume only this drain/rollback path;
- closes every remaining nonterminal authority before touching legacy bytes: a prepared/active `admin_operations` attempt receives no further probe release, is no-spawn/death-proven, and advances through only bounded no-spawn recovery attempts to the existing terminal `retry_exhausted` response; every nonterminal local-inference activation cycle stops accepting participants, death/no-spawn retires its attempt, uses at most the already-defined second no-spawn attempt, and atomically fails all submission participants with `RECOVERY_REQUIRED(local_inference_service)`; every unretired worker/invocation/admin/local-inference launch or containment is revoked, killed, positively whole-containment-death/no-spawn proven, and retired through its exact typed branch; incomplete credential operations reach their existing committed/aborted terminal state under the credential-authority lock;
- closes the broker/control listener, proves the Supervisor has no released dispatch capability, live descendant process/VM, nonterminal admin operation/cycle, unretired launch, or pending credential write, and keeps all four locks through legacy credential rendering and authority publication. Any `unknown`, inaccessible containment, failed kill/death/no-spawn proof, unmatched platform-store state, or nonterminal row blocks rollback with the sentinel/fence intact; it is never waved through because there are zero Runs;
- while `rollback_draining` and that global no-write proof remain current, closes/checkpoints the database, publishes the exact current `KernelDatabaseImageIdentityV1`, copies and seals its bytes as `ArchivedKernelDatabaseImageV1`, publishes the complete current `CasNamespaceManifestV1(snapshotBoundary='rollback_final')`, and then publishes their `ArchivedKernelGenerationManifestV1`. The snapshot is rooted outside the archived namespace and must verify before any legacy byte is restored or control may advance to `rollback_restoring`; a crash resumes this same boundary and never silently substitutes the admission-time generation image;
- stages/restores every backed-up **noncredential** legacy byte, fsyncs files/directories, verifies the full manifest under those locks, and on crash resumes or rolls back this staging while the sentinel remains;
- resolves exactly one `LegacyGenerationManifestV1.authOutcome` from the source observation and ready records. Source `absent` requires `restored_absent`: remove the migrated marker if present, directory-fsync, publish a fresh absent observation, and render no file or consent. Source `present` with `records=[]` requires `rendered_nonsecret`: deterministically render only the non-secret projection, publish its exact file identity/content, and forbid consent. Source `present` with records requires `rendered_with_credentials`: accept exact `RollbackToLegacyRequestV1`, publish matching plaintext consent, read every still-active matching platform item, render one `0600` ProviderAuthStore-v1 file, and publish its exact identity/content. Each rendered branch stages, file-fsyncs, schema-validates, atomically installs, and directory-fsyncs before legacy authority. Missing/revoked/expired/unreadable/target-mismatched credentials block with re-enrollment instructions; no old runtime starts first and Kernel-only credentials absent from the original ready projection are not silently invented in legacy;
- only after the complete restored tree and global quiescence recheck verify, publishes/rehashes the exact legacy generation and `MigrationReceiptV1(legacy_rollback)`, stages identical state-root and legacy-root `MigrationAuthorityMarkerV1(authority='legacy')` bytes, and commits `MigrationControlV1(rollback_restoring)` whose request/receipt and archived-generation pairs equal the retained request/receipt and exact `ArchivedKernelGenerationManifestV1`, and whose `preparedLegacyAuthorityMarkerDigest` equals both staged markers. The final Kernel database transaction roots every receipt/evidence/archive manifest, publishes `StateOwnerTransitionEvidenceV1(graceful_release)`, and terminalizes the active StateOwner; it is the last Kernel repository mutation for that process. While still holding every lock, it may only rehash and rename the already-bound **legacy-root copy first**, directory-fsync it, then rename and directory-fsync `${stateRoot}/migration/authority-v1.json` as the global authority marker **last**, release locks, and exit. A crash after owner terminalization but before the state-root marker is durable uses exact `acquire_after_graceful_release`, remains fenced by `rollback_restoring`, revalidates/replays only missing prepared-marker publication, and gracefully terminalizes that successor as its own last Kernel transaction before the same legacy-root-first/state-root-last sequence. No successor is acquired after the state-root legacy marker is durable, and no Kernel DB mutation is legal after it. The valid state-root marker outranks the retained rollback control, whose later removal is idempotent inactive-generation cleanup rather than an authority transition;
- preserves the exact globally quiescent productive SQLite snapshot and complete CAS namespace named by the archive manifest as a read-only generation that the active runtime never reuses or merges. The former live database's later rollback-control/receipt/owner audit tail is retained separately but is not misrepresented as part of that acyclic snapshot.

Rollback makes legacy JSON authoritative and is one-way for that state generation. Plaintext credentials are reintroduced only by explicit rollback consent and current platform items, never by retained backup/CAS/archive bytes; no secure-erasure claim is made. Future Kernel re-entry is a brand-new migration id/generation over the then-current legacy store, with a fresh backup and fresh SQLite/CAS namespace; it never treats the archived import-complete database as current or silently merges post-rollback legacy changes with it. Exported prior Kernel results remain historical artifacts only.

An unsupported binary downgrade without this command is not presented as a safe rollback path.

## 17. Reuse, Replace, And Remove

### 17.1 Reuse

- Workspace Trust decision and load ordering.
- Tool permission grammar, policy composition, and approval subject concepts.
- Tool registry and JSON Schema definitions.
- Typed runtime event seam.
- Headless JSONL/RPC envelope and artifact-query concepts.
- Validators, diff generation, and crash-recovery lessons from transactions.
- Session fork, compaction, handoff, and skills behavior as context features.
- TUI rendering and interaction components as clients.

### 17.2 Replace Or Demote

- whole-Session JSON persistence;
- Session lifecycle as execution truth;
- `recordIndex`/`turn` checkpoints as recovery state;
- free-text `ModelAction` parsing and JSON repair;
- first-tool-call-only handling;
- edit overlay plus Bash real-workspace passthrough;
- `activeTxId` and the Transaction aggregate as the future execution model;
- in-process untrusted hooks/extensions;
- placeholder network/MCP permission claims without enforcement;
- in-process TUI/RPC ownership of Run lifetime.

Historical files remain readable and historical design documents remain in Git. The cutover docs identify which future-facing claims are superseded.

## 18. Non-Goals

The Kernel Cut does not include:

- a separate Task aggregate;
- DAG, YAML workflow, role, or organization schedulers;
- distributed leases or remote worker clusters;
- cloud accounts, teams, billing, or multitenancy;
- Desktop, Web, or mobile applications;
- general event sourcing and projections;
- a generic transaction filesystem;
- automatic publication to the real workspace or remote Git host;
- memory/RAG or a broad LSP platform;
- a plugin marketplace or arbitrary in-process repository extensions;
- provider-count competition;
- native Windows execution/Supervisor/sandbox support;
- universal exactly-once external effects.

## 19. Release Gates

The new runtime cannot become default until all of the following are demonstrated:

1. Every accepted Run remains discoverable after CLI death, worker death, Supervisor restart, and reboot.
2. Fault injection produces zero silently lost Runs and zero torn ready Checkpoints.
3. A stale worker cannot commit DB state, dispatch through the broker, write a new generation, or reach the real workspace.
4. A sandboxed worker cannot read provider credentials.
5. Every ambiguous effect is Journaled `unknown` and follows its frozen replay class: settled/fenced `retry` may retry or be abandoned, workspace effects require rollback proof, and unresolved `reconcile|manual` waits; opaque effects are never blindly replayed.
6. `succeeded` always has complete required receipts for the identical immutable result source digest.
7. No-check Runs display `completed_unverified`, never a verified success indicator.
8. Exhausted required assertions end `failed(verification_failed)`, never `completed_unverified`; verifier infrastructure failure never enters an agentic repair loop.
9. Real-workspace drift during detach is never overwritten; delivery re-verifies a changed content-addressed result reference and permits exact-reference receipt reuse only through validated provenance.
10. Child Runs cannot exceed inherited capability, depth, budget, or concurrency ceilings.
11. Trust is decided before any repository config, validator suggestion, instruction, or skill is loaded; repository extensions/hooks are rejected and never executed.
12. All provider-returned tool calls are handled; no autonomous path depends on free-text JSON repair.
13. Legacy import is repeatably idempotent, produces a validated backup, and never upgrades bookmarks into recovery claims.
14. Attach resumes from a monotonic event cursor without duplicating or omitting committed retained events.
15. Local p95 attach latency is below one second and recovery scheduling begins within five seconds of Supervisor startup.
16. The system completes a 24-hour run and a 50-real-repository fault campaign with at least ten injected crash locations.
17. Every terminal Run has a schema-valid authoritative status/reason pair and failed detail artifact; clients do not derive terminal truth from events.
18. Source projection includes every eligible new/change/delete/mode/binary/symlink result and fails rather than silently truncating unsafe or over-limit output.
19. Repository config cannot define or launch an MCP process; stdio launch is user-registered, separately permitted, journaled, strongly sandboxed, secretless, networkless, and workspace-inaccessible.
20. Native Windows has no hidden legacy/in-process execution path after cutover; unsupported execution fails explicitly, while WSL2 must pass Linux probes.
21. Migration proves old-process/open-file quiescence and identical locked inventories before authority changes; post-cutover legacy divergence cannot enter new state.

Required automated suites introduced by the Kernel Cut:

```bash
npm run build
npm test
npm run test:fault
npm run test:sandbox
npm run test:migration
npm run test:e2e
```

`test:fault` is the single Kernel-Cut fault release gate, not an alternative to
the storage suite. The root script must invoke `test:state-fault` and the
work-package 03 through 06 fault matrices, propagate every nonzero exit, and
fail when any required child suite is missing or skipped. A green aggregate is
therefore proof that the CAS/reducer/migration crash matrix ran, not merely that
one Supervisor-facing subset passed.

## 20. Product Success And Failure Criteria

Initial validation targets power users, repository maintainers, and CI/automation engineers running real 30-120 minute coding tasks.

Success requires:

- 15-20 target users complete real detached Runs;
- at least 70% actually leave the terminal during execution;
- at least two thirds voluntarily run another detached task within one week;
- user intervention per task falls by at least 30%;
- false-verified incidents remain zero;
- manual database or Session-file repair remains zero.

The direction fails if, after 500 eligible Runs, detach usage remains below 30%, users still babysit Runs, manual state repair is normal, or provider-specific branches invade the kernel's control semantics.

## 21. Implementation Work Packages

All work packages are required for the same Kernel Cut:

The [2026-09-26 design review](../kernel/2026-09-26-design-review.md) records
the refreshed source comparison, implementation status, module boundaries,
internal integration checkpoints and qualification workload definitions. Those
checkpoints organize implementation within this cut; they do not change the
semantic contract or create independent product releases.

1. [Durable State And Migration](../backlog/durable-verified-run-kernel/01-durable-state-and-migration.md)
2. [Typed Runtime And Provider Capabilities](../backlog/durable-verified-run-kernel/02-typed-runtime-and-provider-capabilities.md)
3. [Trusted Execution And Workspaces](../backlog/durable-verified-run-kernel/03-trusted-execution-and-workspaces.md)
4. [Detached Supervisor And Control Protocol](../backlog/durable-verified-run-kernel/04-detached-supervisor-and-control-protocol.md)
5. [Agentic Verification And Recovery](../backlog/durable-verified-run-kernel/05-agentic-verification-and-recovery.md)
6. [Ecosystem Surfaces And Kernel Cutover](../backlog/durable-verified-run-kernel/06-ecosystem-surfaces-and-kernel-cutover.md)

The relationship to existing GitHub issues is recorded in the [Issue Supersession And Dependency Map](../backlog/durable-verified-run-kernel/issue-supersession-map.md).

## 22. Supersession

This RFC supersedes future-facing architectural claims that conflict with it, including:

- JSON-over-text `ModelAction` as the stable runtime protocol;
- Session as execution or workflow ownership;
- transactional edit overlays/worktrees as the final isolation boundary;
- in-process RPC/TUI as the Run lifetime owner;
- daemon, sandbox, or external-effect correctness as optional post-runtime additions.

It does not rewrite the historical record of what prior releases implemented. Existing documents should receive short dated supersession notes only when implementation work touches them.

## 23. Finality

The following decisions are closed:

- product promise and target user;
- four control planes and their ownership;
- Run as the sole mutable execution truth;
- narrow append-only RunJournal instead of full event sourcing;
- quiescent Checkpoints and artifact-first publication;
- OS-managed local Supervisor with lease/epoch fencing;
- private independent workspace generations and real sandbox enforcement;
- trusted credential/effect broker;
- provider-native typed tool calls, with no free-text action fallback;
- immutable results, same-digest verifier receipts, and explicit delivery Runs;
- child Runs as the only recursive execution primitive;
- one-time migration, no long-term dual write, and one Kernel Cut.

Implementation may optimize storage, copy-on-write, batching, and internal library choices without changing these contracts. Any proposal that changes a closed decision requires a new RFC and must explain how it preserves the product promise and release invariants.
