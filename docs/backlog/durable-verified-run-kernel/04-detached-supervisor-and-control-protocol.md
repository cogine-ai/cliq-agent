# Detached Supervisor And Control Protocol

## Backlog Ready Spec

### Verdict

READY WITH RISKS

This package is implementable without further product decisions. The visible risks are whole-containment death proof, crash-safe preactivation, launchd/systemd lifecycle behavior, event-spool volume, and protocol upgrade handling. None permits process-local Run ownership, productive authority before lease activation, or a second worker while any prior containment is unproven.

### Source

Brief / issue / roadmap item:

- Work package 4 of the [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md).
- Product promise: **Delegate. Detach. Return to verified work.**
- This package owns durable admission, the per-user Supervisor, FIFO scheduling, worker launch intents/leases/containment lifecycle, typed waiting and stop reducers, restart recovery, and the versioned local control protocol used by every client surface.

Related issues:

- GitHub issue `#76` (TUI Run state) depends on this package's authoritative Run snapshot and event-cursor protocol; the TUI must not invent a separate lifecycle.
- GitHub issues `#62` and `#63` are dependencies through durable grants and trusted execution, not alternate supervisor implementations.
- The [issue supersession map](issue-supersession-map.md) is authoritative for closure and dependency wording.

Related code:

- `src/headless/contract.ts` defines the current versioned request/output/event concepts and a process-local `HeadlessRunStatus`.
- `src/headless/rpc.ts` implements newline-delimited stdio JSON-RPC, one active in-process Run, and cancellation when its transport closes.
- `src/headless/rpc.test.ts` codifies the current single-active-Run and stdin-close cancellation behavior that this package must intentionally supersede for durable Runs.
- `src/headless/jsonl.ts`, `events.ts`, and their tests provide reusable serialization and event-mapping seams.
- `src/headless/run.ts` currently creates and owns the runner, model client, policy, transactions, and Run lifetime in the caller process.
- `src/cli.ts` routes interactive, TUI, JSONL, and RPC execution directly into process-local runtime code.
- `src/tui/store.ts`, `src/tui/app.tsx`, and `src/tui/approval-bridge.ts` provide client-side state/rendering behavior that should consume control-protocol snapshots and events.
- `src/lib/path-lock.ts` provides a useful ownership/heartbeat pattern, but its five-second filesystem lock lease is not sufficient proof of worker process death.
- `src/protocol/runtime/events.ts` is the existing typed runtime-event seam.

### User Outcome

Once `cliq run --detach` returns an accepted `runId`, the user can close the terminal and later list, inspect, attach, cancel, approve, provide input, reconcile, or retrieve the result. CLI death, TUI death, broken pipes, Supervisor restart, worker death, and machine reboot never silently erase the Run or convert an ambiguous effect into success/failure by guesswork.

Attached and detached clients are views over the same durable Run. Closing a client only closes that attachment. It does not cancel the Run. Every client resumes display from a monotonic durable event cursor, while recovery continues to use the authoritative Run, Checkpoint, and RunJournal rather than UI events.

### Problem

The current headless/runtime ownership model is incompatible with durable delegation:

- `runId` is generated in the client/server process but is not backed by a durable authoritative Run row.
- stdio RPC allows one active Run, holds it in memory, and aborts it when stdin/stdout closes.
- JSONL events disappear with the process and have no durable cursor.
- there is no OS-managed Supervisor, durable queue, lease epoch, worker identity, takeover scan, or reboot recovery.
- cancel/approval/input are process callbacks rather than durable revision-checked state transitions.
- current clients combine runtime ownership, rendering, and transport, so disconnect and execution lifecycle are coupled.
- a stale worker is not fenced from state commits or trusted broker dispatch.

### Scope

In:

- Add one trusted per-user Supervisor managed by launchd on macOS and a systemd user service on Linux.
- Add idempotent durable Run admission with a caller-supplied `admissionKey` and a success acknowledgement only after all RFC detach prerequisites are durable.
- Require every `run.submit|run.apply`, including read-only/text-only/non-Git requests, to resolve `RunAssemblyV1.sandboxBackend` as exactly `macos_vm|linux_namespace` and pass work package 3's strong-backend, worker-identity, and pinned-executable probes before Run creation. There is no workerless/Seatbelt/weak fallback admission.
- Add one minimal global FIFO runnable queue with bounded admission and bounded worker concurrency; waiting Runs do not occupy workers.
- Add authoritative `worker_launches` rows, blocked preactivation, atomic Run-pointer/lease activation, narrow row-only heartbeat CAS, monotonic `leaseEpoch`, versioned worker identity, and work package 3 whole-descendant `ProcessContainmentRef`.
- Require work package 3's exact `SandboxLaunchSpecV1` validation before every worker, invocation, admin-probe, or managed local-inference containment creation; Supervisor orchestration cannot add a process recipe, argv/cwd/stdio/fd, env, mount, executable, resource, owner, or capability outside that closed launch union.
- On every Supervisor instance change, revoke all prior launch/broker authority and terminate/prove empty every exact prior `ProcessContainmentRef` before creating a fresh launch/generation—even when the recorded lease is unexpired. A new Supervisor never reconnects to or adopts an old worker; uncertain death persists the canonical `worker_death` subject and starts no replacement.
- Recover nonterminal Runs after Supervisor restart/reboot using authoritative Run state, Checkpoint closure, Journal reconciliation, and a fresh workspace generation.
- Add a versioned JSON-RPC 2.0 local control API over a per-user Unix-domain socket (UDS) with a compatibility handshake and bounded newline-delimited frames.
- Add methods for Session create/list/get/fork/compact/handoff; Run submit/list/get/attach/cancel/approve/input/reconcile/diff/result/apply; user authorization create/list/revoke; MCP registry register/refresh/list; bounded artifact reads; and Supervisor status.
- Route every internal reducer and server method through the exact canonical exports from `src/kernel/types.ts`, including `RepositoryIdentityV1`, `WorkspaceIdentityV1`, `RunPolicySnapshotV1`, `OperationGrantV1`, `AuthorizationGrantV1`, `AuthorizationConsumptionReceiptV1`, `ChildAllocationV1`, `DependencyInstallScriptsAuthorizationTemplateV1`, `VerificationClosureV1`, `DeliveryTerminalProjectionEvidence`, `InvocationAmbiguityEvidenceBaseV1`, `InvocationAmbiguityEvidenceV1`, `LocalInferenceActivationParticipantV1`, `LocalInferenceActivationFailureV1`, `LocalInferenceActivationCycleV1`, and `LocalInferenceServiceLaunchV1`. This package may orchestrate them but cannot define a wider local alias, generic ambiguity/effect flag, generic grant, generic approval authority, or alternate terminal/activation closure.
- Before any normal model Journal prepare, build the canonical `NormalPromptProjectionV1` only from the retained Run assembly/context closure. The instruction system message must use the exact all-scopes labeled workspace-instruction and ordered skill projections; the Supervisor never rereads mutable `AGENTS.md`, `SKILL.md`, user roots, or bundle-install paths.
- Freeze the canonical immutable `WaitingSubject` union: typed `ApprovalSubject`, exact input call identity, child `await_tool|finalize_settlement|stop_settlement`, and invocation/publication-path/worker-death `ReconciliationSubject` with durable bounded probe state. There is no generic clear-wait mutation and no `waiting(resource)` state.
- Persist typed `StopIntent` artifacts with deterministic precedence. Cancellation, deadline, verifier integrity/failure, runtime failure, parent stop, and manual abandonment fence productive work immediately but commit their target terminal state only after the exact recovery/quiescence closure is satisfied.
- Make `worker_launches` the sole durable Run-worker launch/generation-write authority, `local_inference_activation_cycles` the sole durable service-start singleflight/fanout authority, `local_inference_launches` the sole durable managed-local-process authority, `control_requests` the mutator replay boundary, and `child_allocations` the parent/child budget and wake boundary; none is a second Run lifecycle or event log.
- Add durable, non-authoritative `run_events` with monotonic per-Run `eventSeq`, retention, and cursor-expiry semantics.
- Convert `cliq run`, `cliq run --detach`, TUI, JSONL, and stdio RPC into clients/adapters of the same Supervisor protocol.
- Add OS-service, protocol, idempotency, disconnect, queue, lease, death-proof, recovery, cursor, and reboot-level tests.

Out:

- A `Task` aggregate, DAG/YAML workflow engine, priorities, role scheduler, organization scheduler, cron service, or general job orchestration platform.
- Distributed leases, remote workers, cloud queues, multitenancy, HTTP listeners, TCP listeners, or a Web service.
- A second control protocol for TUI or JSONL.
- Using `run_events` to reduce state, authorize actions, prove verification, or drive recovery.
- Sandbox backend implementation and workspace materialization, owned by work package 3.
- Typed provider/tool runtime internals, owned by work package 2.
- Verifier/repair/result/apply semantics, owned by work package 5; this package only routes their commands and events.
- Legacy Session import and final old-path deletion, owned by work packages 1 and 6. This package still owns the post-cutover Session control-method schemas.
- Automatic priority for child Runs; all runnable Runs use the same FIFO order and durable ceilings.

### Proposed Implementation Direction

Likely files/modules:

- Add `src/supervisor/types.ts`, `service.ts`, `admission.ts`, `scheduler.ts`, `launch-intent.ts`, `activation.ts`, `lease.ts`, `containment.ts`, `local-inference.ts`, `waiting.ts`, `stop-intent.ts`, `cancellation.ts`, `recovery.ts`, `probe.ts`, `retention.ts`, and `entrypoint.ts`.
- Add `src/supervisor/platform/types.ts`, `launchd.ts`, `systemd.ts`, `linux-containment.ts`, and `macos-vm-containment.ts` for user-service installation/activation and work package 3 `ProcessContainmentRef` inspection/termination proof. Keep Supervisor backends macOS/Linux-only. The shared interface exposes a narrower legacy-quiescence adapter to work package 1 migration without making native Windows a Supervisor backend.
- Add `src/control/contract.ts`, `framing.ts`, `server.ts`, `client.ts`, `errors.ts`, `compatibility.ts`, `peer-credentials.ts`, `channel-identity.ts`, `control-requests.ts`, `run-service.ts`, and `session-service.ts` for the UDS JSON-RPC protocol and its one application-service boundary. They import the canonical generated wire schemas plus kernel types, produce exact local peer/principal/channel identities, and return only canonical `ControlApplicationResponseV1` application results. Add `src/supervisor/canonical-clock.ts` as the sole adapter over work package 1's time-fence repository and `src/run/child-allocations.ts` as the narrow exact-`ChildAllocationV1` API over work package 1 storage.
- Add `src/run/events.ts` as the only API over durable `run_events`; storage implementation comes from work package 1.
- Add a dedicated worker entrypoint under `src/worker/entrypoint.ts` and a narrow Supervisor/worker IPC contract under `src/worker/protocol.ts`.
- Refactor `src/headless/run.ts` into a client submission/attachment adapter; execution assembly moves behind the Supervisor/worker boundary.
- Refactor `src/headless/rpc.ts` so stdio JSON-RPC proxies the local control protocol and never owns/aborts a Run when stdio closes.
- Update `src/headless/contract.ts`, `events.ts`, and `jsonl.ts` for the incompatible durable protocol/event schema and cursor fields.
- Update `src/cli.ts`, `src/tui/store.ts`, `src/tui/app.tsx`, and `src/tui/approval-bridge.ts` to consume Run snapshots and event cursors.
- Add focused tests beside new modules plus `src/supervisor/integration.test.ts`, `src/control/integration.test.ts`, and `src/worker/integration.test.ts`; update existing `src/headless/*.test.ts`, `src/cli.test.ts`, and TUI integration tests.

Implementation notes:

1. **One per-user owner.** The Supervisor runs as the invoking user, never root. launchd/systemd owns restart and boot/login activation. The runtime has one guarded state-owner process per `$CLIQ_HOME`; a contender that cannot acquire the exact lock connects to the existing UDS rather than splitting ownership.

   Bootstrap imports the RFC-exact `PlatformProcessIdentityV1`, `StateRootIdentityV1`, `StateLockIdentityV1`, `StateOwnerAcquisitionEvidenceV1`, `StateOwnerTransitionEvidenceV1`, and `StateOwnerRecordV1` from `src/kernel/types.ts`; no Supervisor-local identity shape is legal. It opens the configured root component-by-component no-follow, retains the same-user `0700` directory descriptor, publishes its normalized path/unsigned device+directory-file identity, and acquires/fstats only the no-follow same-user `0600` `runtime/state-owner.lock` descriptor with link count one and exact root ref+digest. It publishes a bounded exact platform PID/start-token/signed-executable observation.

   Exactly three WP01 entrypoints may establish authority while holding/revalidating those descriptors. `bootstrapStateOwner` requires an empty owner table, exact epoch-one genesis evidence, and one selected as-yet-unowned `KernelGenerationIdentityV1`: `fresh_empty` proves fixed empty database/CAS; `migrated_candidate` proves the matching durable Kernel authority marker plus exact candidate/image/CAS/migration closure and runs as the first post-cutover repository transaction before control/admission release. It registers only staged identity/acquisition metadata and epoch one. Clean acquisition and death takeover retain their exact predecessor/successor rules. None may mutate Run/Session/Journal or release capability. Every other repository write/release needs the active owner; only already-prepared rollback marker rename may follow graceful terminalization without DB/CAS mutation.

2. **Use a private, identity-bound UDS only.** Bind only literal `runtime/control-v1.sock` below the exact StateRoot, keeping the no-follow listener descriptor open; its directory is same-user `0700`, and the listener is a same-user `0600` Unix stream socket. For every accepted descriptor the Supervisor publishes exact `LocalSocketPeerObservationV1`: listener and accepted-socket `fstat` identities use canonical unsigned-decimal device/file strings; Linux samples atomic `SO_PEERCRED`, while macOS samples `getpeereid` plus `LOCAL_PEERPID`; it captures exact `PlatformProcessIdentityV1` for that pid and repeats the platform credential calls before publication. Both samples, pid/uid, process observation time, StateRoot, listener, and still-open accepted descriptor must match. Any missing API, symlink/replacement/drift, exited/reused pid, uid mismatch, non-stream socket, or caller-supplied pid/path/hash rejects and closes the connection. The accepted transport then publishes exact `LocalPrincipalIdentityV1` and `LocalControlChannelIdentityV1`; the UDS branch rehashes that peer observation, `openedAt` is canonical and not before observation, and `channelNonceDigest` hashes 32 fresh Supervisor bytes. In-process CLI/TUI/JSONL instead binds the signed current process. Caller JSON/environment can never supply or override principal/channel fields; handlers inject them. Do not open TCP or HTTP. Stale socket removal is allowed only after proving no live compatible Supervisor owns it.

3. **Version the protocol explicitly.** Use JSON-RPC 2.0 with newline-delimited frames capped at 8 MiB. The first request is `control.hello` with protocol/schema/client versions and desired features; the server returns its build/protocol range and capabilities. Incompatible clients receive `INCOMPATIBLE_PROTOCOL` before any mutating request. JSON is transport encoding, not a model control envelope.

   Every durable time is exact `YYYY-MM-DDTHH:mm:ss.sssZ`, year `1970..9999`, round-tripping through a nonnegative safe-integer Unix millisecond; comparison and duration addition use checked integer math. Every authoritative transaction obtains its sole `now` through the StateOwner-gated `CanonicalTimeFenceV1` singleton and advances that row in the same commit. Startup, heartbeat, dispatch, grant redemption, and retry compare wall time with the retained high-water; a regression atomically records `clock_regressed`, stops admission/lease renewal/capability redemption/productive dispatch/retry/expiry extension, and revokes or quiesces active external release gates. Only the current owner may restore `healthy`, and only once wall time reaches the retained high-water. In-process deadlines additionally use a monotonic clock anchored to the accepted sample; reboot or wall rollback never grants extra authority duration.

4. **Make submission retry-safe.** `run.submit` requires a UUIDv7 `requestId`, base64url client-generated `admissionKey`, and exact canonical request/admission-intent digests. `admissionIntentDigest = SHA-256(JCS({principalId,method,request: normalized request with protocolVersion,requestId,requestDigest,admissionKey omitted}))`, and work package 1 keys admission replay by exact `(principalId,method,admissionKey)` independently of `control_requests`. The replay lookup runs before Session/source-Run/workspace validation, descriptor capture, or artifact publication: equal intent returns the original `runId` and stored response/current snapshot byte-for-byte; unequal intent returns `ADMISSION_KEY_CONFLICT` with no state/filesystem read beyond that row. Reusing principal+method+requestId with different canonical request bytes returns `REQUEST_ID_CONFLICT`. If a client loses the response, it retries rather than creating a second Run. Before any first execution, the Supervisor requires exact `RunAssemblyV1.sandboxBackend='macos_vm'|'linux_namespace'` plus fresh process-lifetime work package 3 backend, signed worker, runtime, tool, and verifier identity probes. Failure returns pre-admission `UNSUPPORTED_PLATFORM` or `UNSUPPORTED_EXECUTION_IDENTITY`; read-only/text-only/no-tools/no-required-verifier/non-Git requests cannot bypass this gate.

   The selected execution Session owns one immutable exact `WorkspaceIdentityV1.kind='live'`. `session.create` may publish only that branch from same-principal descriptor-relative no-follow traversal: NFC absolute platform path, `fstat` owner, unsigned-decimal-string device/file ids, and recomputed digest. A Git root additionally requires exact `RepositoryIdentityV1` for literal in-root `.git`, with workspace repository ref+digest together; non-Git forbids both. `run.submit.workspacePath` must reopen to that same root/repository tuple; every workspace/repository digest in resolved policy/authorization/grant/source/instruction/verifier/dependency/child/delivery artifacts equals it. Root/`.git` replacement is `ARTIFACT_MISMATCH`, never implicit Session retargeting. Fork copies the exact ref. Imported `legacy_unavailable` Sessions/forks remain list/get/compact/handoff/export context but are rejected by `run.submit|run.apply`. Apply has no path parameter and derives/revalidates the source Run's live Session identity.

   Admission resolves and stores only the exact `RunPolicySnapshotV1` produced after Workspace Trust. Its `engine.profileEntryId` and `engine.version` match the sole signed non-executable RuntimeBundle `policy_engine` data entry; that entry's signed complete-file `entry.digest` equals `engine.profileRef`, while decoding those exact bytes and independently recomputing the self-omitting `PolicyEngineProfileV1.profileDigest` yields `engine.profileDigest`. The complete-byte ref and semantic digest are distinct hash domains and are never equated. Fixed signed Supervisor code alone interprets it, with no helper process, plugin load, or SandboxLaunch. It validates every user authority as exact `AuthorizationGrantV1` with its closed target/state union. When admission consumes an authorization it must do so through work package 1's same-transaction receipt path: exact `AuthorizationConsumptionReceiptV1` plus the exact Run/template/derivation consumer. In particular, dependency install-script authority becomes exact `DependencyInstallScriptsAuthorizationTemplateV1`; neither the consumed user row nor the template is an `OperationGrantV1` or direct dispatch authority.

   The local-model branch resolves one exact active `LocalModelRegistrationV1` and verifies its copied CAS objects plus `LocalInferenceServiceSpecV1`. The trusted derivation is fixed: `serviceSpecCoreDigest` hashes the complete semantic service spec with only `serviceId`, `createdAt`, `serviceSpecCoreDigest`, and `serviceSpecDigest` omitted; `serviceId` hashes `{ownerPrincipalId,provider:'ollama',model,serviceSpecCoreDigest}`; `serviceSpecDigest` then hashes the complete spec with only itself omitted. Missing, retired, widened, or identity-mismatched registration returns `UNSUPPORTED_EXECUTION_IDENTITY` before any launch or Run.

5. **Acknowledge only durable delegation.** Before `run.submit` succeeds, the Supervisor must have durably stored and verified: immutable `RunSpec`; admitted Session context; base workspace manifest; all referenced artifacts; initial ready Checkpoint; queued authoritative Run row; admission ownership. Artifact fsync precedes the single SQLite publication transaction. Queue-full or validation failure returns no accepted Run.

   For a valid local-model registration with no matching fresh active service, `run.submit` first artifact-publishes its exact secret-free request/admission intent and joins `ensureLocalInferenceActive`. This is a shared service-level activation cycle, not an acknowledged Run or a private retry loop: up to 128 exact submission and existing-Run-frontier participants share one cycle-owned prefix of at most two launches. A retained request id always replays to its original cycle/result; different bytes conflict. Each attempt has a fixed 120-second deadline. A positively retired attempt 1 must enter `retry_wait`, and attempt 2 starts only one second later; attempt 1 may terminal-fail only as exact `containment_unresolved` when retirement is unprovable and the blocking launch remains fenced. Attempt-2 failure is terminal after positive retirement or as unresolved containment; no third/background attempt is legal. The terminal cycle transaction admits/responds to every still-valid submission on success, or stores the same `RECOVERY_REQUIRED(recoveryKind='local_inference_service')` response without Runs on failure. Client disconnect/replay never resets the cycle.

   `run.apply` completes descriptor-safe immutable capture of the source Run Session's exact live descriptor-reopened workspace before admission and publishes distinct artifacts: exact `SourceManifest A` and exact recovery `WorkspaceStateManifest W_A`. It accepts no caller path and rejects a `legacy_unavailable` source Session/fork. `RunSpec.baseWorkspaceManifestRef=A`, initial `delivery:merge.capturedWorkspaceRef=A`, `W_A.baseWorkspaceManifestRef=A`, and the initial Checkpoint `workspaceStateRef=W_A`; every workspace/repository ref and digest equals the source Session artifacts. The Supervisor never passes `A` as a workspace-state ref or conflates deliverable source with private recovery state. There is no admitted delivery Run awaiting `delivery:capture`; a failed, drifted, root/`.git`-replaced, or cross-projection capture creates no Run/control success.

6. **Detach is attachment state, not Run state.** `cliq run` submits and repeatedly reads bounded `run.attach` pages; `cliq run --detach` submits and returns after durable acknowledgement. Client disconnect, EOF, output error, or terminal close ends only that client's paging loop. Public v1 has no implicit push subscription. Cancellation occurs only through a durable `run.cancel` request.

7. **Keep scheduling deliberately small.** The Supervisor orders runnable Runs by durable `(createdAt, id)` FIFO. There are no priorities. Default concurrency is `max(1, min(4, floor(availableParallelism / 2)))`, configurable within `1..16` in trusted user-level Cliq configuration. Admission allows at most 128 queued runnable Runs by default; a full queue returns `RESOURCE_EXHAUSTED(resourceKind='run_queue')` before acknowledgement. Parent/child budget and concurrency ceilings still apply and may lower eligibility.

   Capacity, backend slots, and transient memory/CPU scarcity detected before `prepared` leave the lease-free Run `queued` but temporarily ineligible. If discovered after worker activation, the Supervisor first uses `quiesceGeneration` to end that containment and publish the unchanged frontier before queueing; it does not keep an idle running lease. Eligibility is recomputed after a committed capacity/backend change and on the recovery scan. Scarcity consumes no attempt and creates no wait artifact. `WaitingReason` has no `resource` member, no `ResourceWaitingSubject` exists, and no resource-wake reducer or client command may be added.

8. **Freeze `WaitingSubject` as the canonical immutable typed artifact.** `Run.waitingOnRef` resolves to exactly one of these shapes, `Run.waitingReason` equals `kind`, and its `frontierRef` equals the Run's current immutable frontier:

    ```ts
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
    ```

   Subjects contain exact identity/proof requirements and no decision, mutable secret, generic effect/workspace shape, or inferred recovery state. An invocation reconciliation is only exact MCP `recovery='mcp_reconcile'` with the complete frozen registry/profile/status-template/predicate closure, or exact `recovery='manual'` for a `tool|mcp` Journal entry whose ReplayClass is manual. Model, verifier, MCP-server lifecycle, ordinary built-in tool, and retry uncertainty cannot enter the MCP-reconcile branch. A normal approval/input/child/invocation wait is entered only after work package 3 `quiesceGeneration` publishes changed context/workspace and ends the worker containment. `worker_death` is the exception: every worker loss, including immediately positive death, first atomically clears active Run ownership, preserves old epoch/identity/containment/generation/open invocations, installs the exact wait, moves the launch to `reconciling/fenced_reconciling`, and moves the authoritative generation from its exact `active|revoking|checkpointing` source phase to `fenced_reconciling` with wait ref/digest, source phase, and phase-valid quiesce id. No replacement may start until exact `WorkerRecoveryEvidenceV1` proves positive all-descendant death; both dispositions then publish exact `worker_recovery` quarantine evidence and quarantine the old row, while only restoration additionally selects a distinct preactivated generation.

   Reconciliation probe state is authoritative as the exact `ReconciliationProbeStateV1` XOR. A manual invocation has only `manual_only`. Every inspectable MCP-reconcile/publication/worker-death subject starts `automatic_pending(automaticProbeCount=0,userProbeCount=0,nextProbeAt=createdAt)` with both evidence members forbidden. At due time one Run-revision CAS enters `automatic_in_flight`, increments the automatic count, and persists one complete `ReconciliationProbeDispatchV1` before any query or inspection: `probeOrdinal=automaticProbeCount`, one unique nonce, `probeDeadlineAt=probeStartedAt+30s`, current owning Supervisor, omission-rule dispatch digest, and the subject-specific broker dispatch or inspector-task identity. An unresolved ordinal `n<8` returns to `automatic_pending` with `nextProbeAt=observedAt+[1s,5s,30s,2m,10m,30m,1h][n-1]` and a mandatory exact last-evidence pair; ordinal 8 enters `automatic_exhausted` with that pair. No post-probe pending/exhausted state may omit or half-store it. Counts, dispatch, and evidence survive reboot. Only the same live owning Supervisor may resume the exact persisted dispatch without incrementing again; a successor first closes the predecessor dispatch through the typed fence/join or owner-death branch and follows the unresolved edge.

   Authenticated `run.reconcile(probe_now)` is legal only from `automatic_exhausted` and is an enqueue mutation, not a synchronous probe result. Its idempotent control transaction increments positive-safe `userProbeCount`, enters `user_in_flight`, and persists a dispatch whose `probeOrdinal` equals that count, nonce/deadline are fresh, and `controlRequestId/controlRequestDigest` equal the public mutation. The same transaction publishes/stores canonical `ControlResultV1.resolution={kind:'probe_enqueued',dispatchDigest,userProbeCount}` plus the post-enqueue snapshot and `control_requests` row; only after commit may the no-new-effect probe perform I/O. Same request bytes replay the response and join the dispatch without probing twice; different bytes conflict. Async completion later stores evidence and advances the wait through the internal reducer and Run events, with no second public response. An unresolved result returns to `automatic_exhausted` with the new evidence pair and unchanged automatic count. Before exhaustion or for `manual_only`, `probe_now` is `INVALID_REQUEST`; manual accepts only exact-risk abandonment and synchronously returns only `{kind:'abandoned',evidenceRef}`.

   `ReconciliationProbeDispatchV1.dispatchDigest = SHA-256(JCS(dispatch with dispatchDigest omitted))`, and its subject digest rehashes the frozen `ReconciliationSubject`. The MCP branch persists deterministic `brokerDispatchId`, exact no-new-effect request/target digests, and an unguessable fence-token digest; broker release accepts only the still-current in-flight row and token. Publication/worker persist deterministic `inspectorTaskId` plus exact descriptor-only target digest, and those fixed in-process tasks have no broker, child-process, mutation, or credential capability. A dispatch/task/fence identity that existed only in memory is invalid.

   Every automatic or user probe result first publishes exact `ReconciliationProbeEvidenceV1`. Its omission digest, Run/wait digest, dispatch digest, kind/ordinal/nonce/start/deadline, current inspector, and observation time equal the persisted in-flight dispatch. `subject_observation` wraps exactly one subject-allowed artifact and rehashes its ref/digest: `McpRecoveryProbeEvidenceV1`, `PublicationProofV1`, or `WorkerRecoveryEvidenceV1`; MCP evidence repeats the same dispatch digest and broker identities. `probe_timeout` is legal only at or after the stored deadline and wraps exact `ReconciliationProbeTimeoutClosureV1`; its omission digest and every common dispatch/inspector field equal the wrapper/in-flight state. MCP timeout closure atomically revokes the exact persisted fence token, waits for its matching active-release count to reach zero, and records the same dispatch/target/token plus `noActiveReleaseForNonce=true`. Publication/worker closure repeats the persisted task id and exact subject target and uses exact `ReconciliationInspectorTaskClosureV1`: either the owning live Supervisor synchronously cancels and joins the task, or a successor names exact `StateOwnerAcquisitionEvidenceV1(takeover_after_owner_death)` proving the task owner's process died. Timeout proves no effect outcome, follows the same unresolved transition/backoff, and never authorizes a retry or frontier advance. A late response for a closed nonce is audit-only. Pending/exhausted `lastProbeEvidenceRef/digest` resolve to the wrapper, not directly to subject evidence; the reducer unwraps and validates the one legal branch before advancing. No client evidence payload, target, adapter, predicate, counter reset, automatic ninth probe, or liveness claim exists, and a global Supervisor semaphore bounds all probes.

9. **Use subject-specific wait reducers only.** Every client reducer requires `{runId, expectedRevision, waitingOnRef}` and rejects stale/mismatched subjects. There is no `clearWait` or arbitrary status mutation.

   Before preparing a normal model attempt, the Supervisor closed-decodes the current `ContextManifest.assemblyRef`, the exact `RunAssemblyV1.instructions`, mandatory `WorkspaceInstructionSourceManifestV1` plus `WorkspaceInstructionManifestV1`, and every ordered `SkillManifestV1` plus its `SkillSourceIdentityV1` and transitive content closure. The first system-message piece is the decoded base `ModelTextV1.utf8`; when workspace entries exist, the next piece is UTF-8 JCS of `{format:'cliq-workspace-instruction-prompt-v1',entries:[{order,canonicalRootRelativePath,appliesToSubtree:true,instructionUtf8}]}` using every entry once in retained order; then each assembly skill contributes UTF-8 JCS of `{format:'cliq-skill-instruction-prompt-v1',skillId,sourceScope,instructionUtf8}` in explicit assembly order. It omits only the empty base piece and empty workspace block, requires every skill instruction nonempty, and joins remaining pieces with exactly two LF bytes. Every ref/digest, source identity, content digest, workspace-identity/held-descriptor equality, path-containment rule, and branch-specific provenance equation revalidates before the prompt artifact and Journal request are published. Workspace instruction/skill capture is separate declarative context and confers no SourceManifest, read, tool, generation, result/diff, or publication authority. `sourceKind='assembly_instructions'` and `sourceId=assemblyRef`; `ContextManifest` contributes no duplicate instruction or skill arrays. Missing/widened provenance, duplicate unqualified skill ids, mutable-path reread, target-selected workspace subset, dynamic skill execution, or adapter-added prompt bytes fails before reservation/claim.

   A completed model Journal result is exact `AgentModelTurn XOR ModelUnusableResponseV1`. Both branches repeat the claim's exact normal `NormalModelRequestV1` or `CompactionModelRequestV1` ref/digest and Run/op/attempt/provider/model/mode, and consume that request's full reservation. An unusable artifact is legal only after a positively received malformed, oversized, capability-incompatible, operation-invalid, or provider-rejected response: it recomputes `unusableDigest`, retains either the exact complete response bytes within 1,048,576 bytes or exactly the first limit+1 bytes with `failureCode='response_too_large'`, and keeps the closed media/failure union. A provider rejection uses exact `failureCode='provider_rejected_response'`. The Journal `resultRef` names that artifact and phase is `completed`; it is fully charged and not retried, and any received `Retry-After` cannot change the frozen `[500ms,2000ms]` retry schedule because that response terminates the attempt. `RunAssemblyV1.retry.model` has exactly three dispatched attempts, zero hidden same-attempt transport retries, and no `maxRetryAfterMs` or adapter/provider delay override. For a normal request the Supervisor artifact-first publishes exact `RuntimeFailureEvidenceV1(failureKind='model_unusable_response')`, whose Run/frontier/failing op/current inspector and unusable ref/digest match; the generic-runtime StopIntent and TerminalDetail repeat that wrapper ref/digest/failing op. A context-compaction failure instead uses its dedicated StopIntent subtype and immutable StopIntent ref as terminal primary evidence. It creates no `ModelTurnItem`, batch, candidate, or summary. Uncertain response existence remains `unknown`; only literal `transport_exhausted` after the final exact failed attempt can produce `model_attempts_exhausted`.

   The model-turn reducer first closes the completed model Journal fact, then decodes exact `AgentModelTurn`, its required `ModelTextV1`, and every ordered `ToolCallInputV1` plus exact `ObservedToolCallInputV1`. Text/observation/input omission digests and byte counts, the retained valid-JSON value or malformed UTF-8 fragment, provider/model/response identity, request/response digests, op/attempt, and usage settlement must match. Only `disposition='resolved'` contains the selected schema-normalized JCS object and may reach policy, grant, Journal, or dispatch; unknown-tool and invalid-input branches retain exact observation plus deterministic diagnostic and forbid a dispatchable value. `ModelTurnItem.textRef` always equals the turn text ref. For `tool_calls`, the same transaction appends `ToolBatchItem` whose required `textRef` equals that turn and whose complete ordered `(callId,index,toolName,inputRef,inputDigest)` sequence equals the turn byte-for-byte. When all inputs are resolved it installs the exact `tool` frontier. When every call identity is valid but any input is rejected, it instead uses work package 1 `commitRejectedModelToolBatch`: atomically append the whole model/batch turn, one identity-matched `error(TOOL_NOT_FOUND|TOOL_INPUT_INVALID)` for every rejected call, and `batch_not_executed` for every remaining call carrying the complete unique byte-sorted rejected-call-id set, then install a new `agent` frontier. This branch performs zero grant, Journal prepare, broker release, child allocation, or tool execution, and crash/replay sees either none or the complete batch/results/frontier. `end` requires zero calls plus nonempty decoded final text; `cancelled` permits no call and requires the exact StopIntent that was current before the authenticated abort, copied by the item iff cancelled. Provider `length|content_filter|unknown` stop reasons are not usable turns: they produce exact fully charged `ModelUnusableResponseV1` failure codes and create no item, batch, or candidate. Invalid/missing/duplicate call identity or any other invalid stop/text/call/abort combination follows the same exact unusable-response path rather than widening `ModelTurnItem`.

   Every ordinary ToolResult producer artifact-first publishes exact `ToolResultModelContentV1` and exact `ToolResultPayloadV1`; both omission digests, Run/batch/call/index/tool/outcome, `modelContentRef`, and `modelContentDigest` must match before the item transaction. The audit payload's `executed` branch repeats the completed Journal op/attempt/result and selected output schema; `denied` names exact immutable policy evidence or `ApprovalDecisionV1`; `error` uses the closed code set, always names a rehashed diagnostic, and carries op/attempt/Journal-error fields all together iff dispatch created that op; `batch_not_executed` carries the complete unique byte-sorted rejected-call set from one prevalidation transaction; ordinary `cancelled` repeats the winning StopIntent and deterministic notice. Only the bounded model-content artifact enters context: normalized executed output, `{code:'TOOL_CALL_DENIED'}`, `{code}`, `{code:'BATCH_REJECTED_BEFORE_DISPATCH',invalidCallIds}`, or `{code:'TOOL_CALL_CANCELLED',cancellationKind}`. It is ref-free and cannot contain principal, policy/grant/decision/StopIntent/Journal/diagnostic/attestation/containment authority. The sole exception is terminal closure of a fenced `retry` unknown: its item points directly to exact `RetryUnknownCancelledResult` with settlement/dispatch-closure evidence, has no model-content artifact, and is never wrapped as `ToolResultPayloadV1`. No reducer serializes the audit payload or arbitrary provider/tool text into model context.

   - A prospective operation whose exact `PolicyChannelEvidenceV1.effectiveDisposition` is `allow|deny` never creates an approval wait. The direct reducer atomically appends exact `PolicyDecisionItem(decisionSource='direct_policy')`, forbids `waitingSubjectRef`, requires `decisionRef===policyChannelEvidenceRef`, and commits one closed allow-grant XOR deny-outcome plus the Run frontier/StopIntent/event. Allow requires exact `OperationGrantV1` and forbids denial outcome. Deny forbids grant and requires one subject-matched `PolicyDenialOutcomeV1`: tool/MCP appends the identity-matched denied ToolResult; required verifier publishes exact `origin='policy_deny',reason='verification_failed'`; advisory verifier appends exact `VerifierSkipItem(outcome='skipped_by_policy')` whose decision ref/digest equal the channel evidence and advances; delivery or dependency scripts publishes exact `origin='policy_deny',reason='runtime_failed'`. No ApprovalDecision, phantom wait, cross-subject outcome, or model-visible authority payload exists.
   - `resolveApproval` first artifact-publishes the exact `ApprovalDecisionV1`, then switches on the complete exact `ApprovalSubject`. It recomputes `decisionId=H(principalId,runId,waitingSubjectRef,requestId,requestDigest)`, exact JCS wait/subject digests, and `decisionDigest=SHA-256(JCS(decision with decisionDigest omitted))`; authenticated principal, Run/revision/frontier, exact wait bytes/subject, and canonical request id/digest must match. Tool calls preserve call index/name/contract/replay class plus the exact `ordinary_tool` XOR `child_delegate(read_only|mutating)` discriminator; verifier, MCP-server, delivery, and dependency subjects preserve every displayed candidate/source/plan/index/spec/registry/operation-set/install-script field. The mandatory `policyChannelEvidenceRef/policyChannelEvidenceDigest` closed-decodes exact `PolicyChannelEvidenceV1`, rehashes, and byte-matches this full subject, Run/policy/frontier/op/request/target/action class with `effectiveDisposition='ask'`; neither approval nor recovery may reparse or substitute a policy channel. `requestedTtlMs` is present iff supplied. `grantExpiresAt` is required iff allow creates authority, equals that exact grant expiry (delivery-plan approval uses Run deadline), and is absent on deny. The decision, exact `PolicyDecisionItem(decisionSource='interactive_approval')` preserving the identical evidence pair/current wait, optional grant XOR required subject-matched `PolicyDenialOutcomeV1`, replacement frontier or StopIntent progress, Run revision/event, response artifact, and `control_requests` row commit atomically. Allow mints only the RFC-exact `OperationGrantV1` whose full ordinary-tool/child-delegate or named-action identity, policy, provenance, use and expiry fields equal the subject/evidence, and forbids denial outcome; its `provenance.kind='user_approval'` repeats the identical channel-evidence pair and exact allow decision. Deny forbids grant. A generic capability, `AuthorizationGrantV1`, approval text/item, or template is invalid. `mcp_server_launch` allow is additionally bound to the exact registry revision/manifest, lifecycle, originating batch/call/index, and bounded launches. Tool/MCP denial appends the identity-matched denied ToolResult; required verifier denial records the required-verifier outcome and cancels without receipt; advisory denial appends exact `VerifierSkipItem(outcome='skipped_by_user')` with no policy digest and advances; delivery denial cancels only the delivery Run; dependency denial stops that required path without code execution or readiness. Dependency allow still requires the exact current template and one unused candidate ordinal.
   - `resolveInput` accepts only the exact current `input` subject created by built-in `request_input`. `InputRequestItem.promptRef/promptDigest` must decode exact `InputPromptV1` and repeat Run/batch/call/index; its exact NFC `ModelTextV1` prompt and `responseKind` branch carry the sole response contract. Text input is NFC/no-NUL and JSON input is finite, validates exact `InputResponseSchemaV1` without coercion/default insertion; both fit `maximumResponseBytes`. After authenticated principal and public kind match, the Supervisor canonicalizes once and artifact-first publishes exact `UserInputModelContentV1` plus exact `UserInputPayloadV1`; both omission digests validate, payload kind/value equals model content, and the latter contains no principal, prompt/schema, request, Run/call, or authority ref. One control-replay transaction appends exact `UserInputItem` repeating those model-content/input/prompt refs and digests plus the identity-matched executed `ToolResultPayloadV1`, matching Journal result, and `ToolResultModelContentV1` whose content is only that same normalized value. If calls remain it preserves the exact next tool frontier; otherwise it installs agent cause `input`. A schema/kind/bound/principal/identity/model-content mismatch commits nothing; retry of the same request returns the existing item/result/snapshot.
   - `evaluateChildWait` validates the referenced immutable `ChildWaitSet`. Before parent visibility, the child terminal reducer decodes the child's exact Run: success requires its sole `Run.resultRef`/`RunResult`; failed/cancelled instead requires exact `terminalDetailRef` and forbids result. Read-only success forbids a patch; mutating success publishes exact `ChildPatchManifest` whose admitted base, result, diff, and byte-sorted operation projection match child RunSpec/RunResult/`WorkspaceDiffV1`. Every branch artifact-first publishes exact `ChildResultModelContentV1`: successful summary is exact UTF-8 from RunResult `ModelTextV1.summaryRef`, while stop content contains only status and terminal reason. It contains no result/detail/diagnostic/policy/receipt/budget/ref. Allocation terminal and eventual parent-owned `ChildResultItem` repeat identical child/mode/status/result-or-detail/patch/model-content/inclusive-usage bytes. `await_tool` validates `awaitBatchItemId`/`awaitCallId`/`awaitCallIndex`, settles all satisfied allocations, appends those ordered items/merge work, and advances only that exact call; only `ChildResultItem.modelContentRef` enters model context. `finalize_settlement` settles the exact outstanding direct-child set tied to `modelTurnItemId`; it never promotes that premature model text to a final candidate, and after any separately claimed serial merges it returns to an agent frontier with cause `child_results`. `stop_settlement` accepts no productive merge and only drives the referenced StopIntent toward quiescence; optional `awaitOrigin` preserves the exact interrupted batch/call/index for typed cancelled closure without resuming it. A child terminal transaction always advances its own `child_allocations` row; it may also revise/settle/wake the parent only when the parent is lease-free on that exact child subject. If the parent is `running`, the allocation row changes without an asynchronous parent revision and the parent settles it in its own next revisioned transaction.

   `child_allocations` stores only exact `ChildAllocationV1`, keyed uniquely by `(parentRunId, childRunId)` and delegate identity/admission key. Child admission atomically appends one exact `ChildHandleItem`; its parent Run, owning delegate batch/call/index/op, child Run, admitted spec, and mode equal the allocation and deterministic child admission identity. A duplicate, skipped, cross-parent, cross-batch, caller-substituted, or independently appended handle is invalid. The allocation base freezes the exact delegate `OperationGrantV1`, capability grant, additive ceilings, depth/concurrency, absolute deadline, mode, and child identity. Its discriminated state is monotonic `reserved -> child_terminal -> settled`: forbidden-field XORs validate; child terminal writes one immutable result-or-detail, optional exact mutating patch, exact model-content pair, and bounded inclusive usage; parent settlement preserves those bytes, names the identity-matched owned `ChildResultItem`/parent revision, moves inclusive actual usage to consumed, and records component-wise released-unused capacity exactly once. No path refunds consumed/settled usage, changes terminal/model-content bytes, reverses state, detaches the child, or changes parent budget counters outside a parent revision transaction.
   - `resolveReconciliation` switches only on the closed `ReconciliationSubject` and accepts completed probe input only through exact `ReconciliationProbeEvidenceV1`. A `subject_observation` wrapper must name the sole evidence kind allowed by that subject. MCP-reconcile validates the exact unknown claim plus frozen registry/tool/profile/status-template/predicate closure, then unwraps exact `McpRecoveryProbeEvidenceV1`; its omission digest, wait/op/attempt, automatic-or-user ordinal/current nonce, registry/profile/template/predicates, broker dispatch/target, and bounded canonical-JSON response all match. Exactly one completed predicate yields `completed`, exactly one failed predicate yields `failed`, and both/neither/schema failure is `unresolved`. Completed/failed appends the matching Journal resolution, exact outcome-matched executed/error `ToolResultPayloadV1`, exact model-safe `ToolResultModelContentV1`, and `ToolResultItem`, then advances that exact MCP call; unresolved only installs the wrapper ref+digest and clears the nonce. `publication_path` unwraps only its canonical `PublicationProofV1` branch and validates plan/path/claim/inspector identity before appending `PublicationPathResultItem` or retaining the wait. `worker_death` unwraps only exact `WorkerRecoveryEvidenceV1`: omission digest, wait/launch/epoch/worker/containment/old-generation identities, exact `ProcessContainmentDeathEvidenceV1`, current `SupervisorInspectorIdentityV1`, and disposition XOR match. Both dispositions atomically publish exact `WorkspaceGenerationQuarantineEvidenceV1(reason='worker_recovery',fromPhase='fenced_reconciling')`, require it to bind the installed wait/current source row/deterministic target/observed state, and quarantine the old generation. `quarantined` forbids all three restore members. `restored_from_checkpoint` requires all three members; the Checkpoint is ready/same-Run, state matches, replacement differs from the old ref, and its exact authoritative row is `preactivated_readonly` with matching materialization snapshot. Only after old-generation quarantine may recovery retire its launch/generation and queue an unstopped Run or advance StopIntent quiescence. A `probe_timeout` wrapper unwraps only the subject-matched exact timeout closure, applies the ordinary unresolved transition, and cannot supply positive evidence. `lastProbeEvidenceRef/digest` always decode to the wrapper and then its sole subject-valid evidence/timeout closure; positive evidence passes `assertEvidenceAuthority`, never a client payload or worker assertion.

   - The sole evidence-free resolution is authenticated `abandon_run` with `acknowledgeExactRisk:true` for the exact current invocation with `recovery='manual'` and frozen ReplayClass `manual`. The Supervisor publishes exact `ManualAbandonAttestationV1`: principal/channel/control request, Run/current wait/frontier, unknown Journal op/attempt/seq, immutable operation request/ref+digest, target/ref+digest, ambiguity evidence/ref+digest, one risk literal, time, and `attestationDigest=SHA-256(JCS(attestation with attestationDigest omitted))` must match. One transaction appends Journal `abandoned`, repeats the unknown's budget settlement with zero new delta, uses that identical attestation ref in the manual Stop/Terminal closure and any call-origin `ToolAbandonedItem`, advances terminal quiescence, emits the event, and records the control response. An already-winning user/parent stop remains the winner; otherwise the attestation may create the canonical `manual_abandon` intent. `probe_now` is invalid for manual; `abandon_run` is invalid for MCP-reconcile/publication/worker-death. It never creates a ToolResult, resumes a batch, retries blindly, or treats an inspectable subject as abandoned.

   Current positive evidence passes `assertEvidenceAuthority` and may atomically append the terminal Journal fact, zero-additional settlement when resolving a charged `unknown`, operation-specific item/receipt, and exact subject/frontier reducer. Evidence for a superseded attempt/frontier/result is audit/billing-only: it cannot add a Run-visible item, change a wait, or advance a frontier.

   A successful reducer normally performs one lease-free `waiting -> queued` transition, clears both wait fields, installs its exact replacement frontier, and advances revision/event once. If proof remains it replaces `waitingOnRef` with the next canonical subject. If a winning StopIntent already exists, the same transaction evaluates terminal quiescence and either commits the target terminal state or preserves/replaces the required wait; it never queues productive work. No reducer jumps to `running`, and `run_events` never authorize one.

   Success terminal routing is equally closed. The Supervisor may call work package 1 `commitRunResult` only when the current finalize frontier and proposed RunResult name the identical exact `VerificationClosureV1`. The storage transaction re-walks its candidate/source/verifier-plan/dependency readiness, every required/advisory disposition, Journal/receipt/item identity and exact budget settlement, and unverified-consent closure. `inherited_verified` additionally requires the same exact `InheritedVerificationProvenanceV1` at closure and delivery `RunResult.verificationProvenanceRef`; storage recomputes its omission digest and re-walks the immutable source `succeeded(verified)` result, required source closure, identical result source/verifier spec, and ordered receipt refs/digests without copying or relabeling source-owned ids. Agent finalize/result forbid `deliveryTerminalProjectionEvidenceRef`; delivery finalize/result require the same exact forward-finalize `DeliveryTerminalProjectionEvidence` and revalidate its plan/source/path/result/projection/descriptor closure. This package cannot synthesize a receipt list, downgrade a required set, accept alternate provenance/closure/projection refs, or set `succeeded|completed_unverified` through a generic terminal route.

10. **Persist one typed StopIntent and apply deterministic precedence.** `Run.stopIntentRef` points to this canonical immutable union while invocation/containment/generation/publication/child closure delays terminal commit:

    ```ts
    type StopIntentBase = {
      schemaVersion: 1
      runId: string
      createdAt: string
    }

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
    ```

   The state service validates the artifact and monotonically selects any `origin='kernel_integrity'` above `cancelled_by_user > parent_cancelled > budget_exhausted > verification_failed > verifier_infrastructure_failed > ordinary runtime_failed`; `policy_deny` occupies its exact mapped reason's position. Equal-precedence intents retain the earliest committed intent, using artifact digest only as a same-transaction deterministic tie-break. `origin='budget'` is required for additive token/cost/tool/repair exhaustion and is valid only when `consumed + reserved + required > ceiling`; wall expiry uses only `origin='deadline'`. A higher-precedence later fact may replace the pointer; lower/equal facts remain audit-only. `cancelRequested` is only the monotonic dispatch index set by user/parent cancellation, not terminal-reason truth. Any `stopIntentRef` forbids productive dispatch. `commitTerminalStop` consumes the current winner only after full terminal quiescence and derives status/reason detail from it; restart never guesses from events or the last error.

   `StopIntentBase` deliberately carries no generic evidence. The terminal primary-evidence matrix is exact: verifier/dependency integrity use `integrityEvidenceRef`; parent cancellation uses `sourceStopIntentRef`; local-inference failure uses `failureDetailRef`; direct required-verifier/delivery/dependency policy denial uses `policyChannelEvidenceRef`; generic runtime uses `runtimeFailureRef`; manual abandon uses `attestationRef`; user cancellation, deadline/budget, verification, context-compaction/window, delivery-merge, and delivery-publication use the immutable winning `stopIntentRef` itself after publication. The corresponding `TerminalReasonDetail` copies only the exact branch fields and its evidence member, when present, equals that selected primary ref. Integrity verifier/plan/acquisition identities and observation-source XOR revalidate. `policy_deny` repeats exact op/subject/evidence and maps verifier to `verification_failed`, delivery/dependency scripts to `runtime_failed`; it cannot contain an ApprovalDecision or wait. Generic runtime requires exact `RuntimeFailureEvidenceV1`, repeats its ref/digest/failing op, recomputes `evidenceDigest`, validates a current five-second `SupervisorInspectorIdentityV1`, and re-walks exactly one closed branch: completed unusable response; final failed model attempt/request/Journal sequence; pre-target-I/O credential grant/endpoint/latest authority state; retry-unknown result/settlement/dispatch closure; current candidate dependency plan/final acquisition fact; or local provenance/spec/current boundary evidence. A caller cannot choose another reason-detail or primary ref, and generic diagnostic text, a boolean, untyped Journal error, worker assertion, or cross-branch member cannot stop a Run. Terminal closure arrays/abandonment fields are separately derived from exact Journal/items/receipts at commit. Thus a later `abandon_run` under an already-winning user/parent cancellation closes the unknown under the existing winner without replacing it; only when no stop exists can `manual_abandon` become the winner.

11. **Make grant expiry deterministic.** Every grant binds `runId`, `opId`/call, target digest, decision, and `expiresAt <= Run.deadlineAt`; secrets and lease identity are not embedded. Expiry is checked by both dispatch checks before target I/O.

   - If a grant expires before any `prepared` fact, the same call enters a fresh approval subject with no reservation.
   - If it expires after `prepared` but before `dispatch_claimed`, the Supervisor wins a no-claim/revision CAS against the dispatch arbiter, invokes `quiesceGeneration`, and in that publication transaction appends the exact pre-dispatch `failed` branch, releases the reservation with a zero-consumed settlement, and creates the fresh approval subject. That row forbids dispatch/Supervisor/state-owner/fence/spec/result/receipt/evidence/attestation fields; the transactional absence of any claim is the proof that target I/O never occurred. No worker remains active in the wait. A fresh allow decision is the explicit same-op retry authorization; it uses a new attempt and `grantRef` for the same `opId`, never an implicit policy-free retry.
   - If expiry races after `dispatch_claimed` but before successful `releaseClaimedDispatch`, the second gate releases no target capability/bytes and the trusted arbiter closes that permanent claim with positive no-target evidence and exact settlement. A replacement needs the frozen same-op retry policy plus fresh authority; it is never automatic merely because no target call occurred.
   - Once `releaseClaimedDispatch` succeeds, later one-shot grant expiry does not revoke, retry, or relabel that already-started invocation; operation timeout/cancel/deadline still bound it.
   - Stdio `mcp-server` launch authority is never long-lived. The lifecycle grant is bound to the exact registered manifest plus originating Run/batch/call/index, expiry, and `maxLaunches`; expiry/exhaustion creates that exact `mcp_server_launch` subject. Allow can launch only a fresh call-scoped instance, and the owning tool call still requires its own unexpired call grant/claim. Result or stop must retire the instance with whole-containment death evidence before the lifecycle closes or replacement is considered.

   Approval submitted after a StopIntent/cancel request/deadline is rejected as `CANCEL_REQUESTED` or `BUDGET_EXHAUSTED`; it cannot mint authority that the Run can no longer use.

12. **Use durable powerless preactivation.** The authoritative state service persists the sole launch/generation-write authority before the Supervisor creates a process or VM:

    ```ts
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

   Work package 1 stores this row in `worker_launches` and a separate exact `workspace_generations` row as the sole mutable generation authority; no in-memory lease or directory name is authoritative. `workspaceGenerationRef` closed-decodes exact immutable `WorkspaceGenerationIdentityV1`, while WorkerLaunch `generationWriteState` is only a same-transaction denormalized projection of exact `WorkspaceGenerationStateV1`. `workerIdentityDigest` resolves to one immutable versioned `WorkerIdentity` artifact, and `oldWorkerIdentity` carried by a wait is that exact digest, never a PID-shaped free string. `executableRealpath` is the canonical path inside the admitted execution environment; on macOS strong mode it is the signed `GuestToolchainManifest` guest path/digest, never a host Mach-O identity. Work package 3 creates the identity/state row in `materializing`, materializes/verifies the read-only fresh generation, publishes exact `WorkspaceGenerationSnapshotEvidenceV1`, CASes the row to `preactivated_readonly`, and constructs the deterministic containment plan before any process or VM exists. `reserveWorkerLaunch` inserts the sole unretired launch while the Run is lease-free `queued`, requires that exact generation row, and stores mandatory exact `SandboxLaunchSpecV1.worker_activation`; the spec must byte-match row/plan/generation at creation. `activationDeadlineAt = createdAt + 120s` and is never extended. `recordPreactivated` CASes `reserved -> preactivated`, binds inspected worker/containment identity, and keeps launch projection equal to generation `preactivated_readonly`. Actual containment/no-spawn/death evidence repeats that same spec/plan/owner/nonce/backend identity. Before activation the worker has only a one-purpose handshake channel and zero broker, sandbox-launch, generation-write, network, provider, MCP, credential, or child-spawn authority.

   The Run row no longer duplicates heartbeat identity. It retains only monotonic `leaseEpoch` and optional `activeWorkerLaunchId`. `activateWorkerLease` is one transaction that rechecks queued status/revision/frontier/Checkpoint/stop/cancel/deadline/eligibility, requires the exact `preactivated_readonly` generation state/snapshot, CASes launch to `phase='activated'/generationWriteState='active'` and generation to `active` with the identical launch/new epoch, installs `leaseExpiresAt`, sets the Run pointer, changes `queued -> running`, and emits the one Run revision/event. `running` requires the Run pointer, activated launch, and active generation row to match exactly; queued/waiting/terminal have no active pointer. Only after commit does the Supervisor send the single-use capability bound to Run revision/epoch, launch id, worker identity, containment, generation, and expiry.

   Heartbeat uses `renewWorkerLease(supervisorInstanceId, launchId, expectedLeaseVersion, runId, leaseEpoch, workerIdentityDigest,newLeaseExpiresAt)` and requires current StateOwner, exact Run pointer, activated launch/projection, and authoritative generation still `active`. It increments only launch `leaseVersion`/`leaseExpiresAt`; it never changes generation/Run revision, timestamps, items, or events, and cannot reopen a gate. Dispatch reads Run, pointed launch, and exact generation row in one snapshot and validates their active equality plus live lease. Lease expiry alone clears nothing. `beginGenerationRevocation` atomically moves generation `active -> revoking` and launch projection to revoking with one `quiesceId`; after positive all-descendant death, `beginGenerationCheckpoint` moves only `revoking -> checkpointing` with that id. Exact sealing snapshot evidence and ready Checkpoint then atomically move generation to `sealed`, copy launch projection, clear the Run pointer, and retire the workflow launch. Direct active-to-checkpointing or revoking-to-sealed is forbidden. Every worker loss/takeover path, even with immediately positive death, first uses one transaction to clear the Run pointer, install the exact worker-death wait, move launch to `reconciling/fenced_reconciling`, and move generation from exact `active|revoking|checkpointing` to `fenced_reconciling` with source phase/quiesce binding. Only then may exact worker recovery evidence publish the deterministic quarantine artifact and quarantine the old row; both dispositions do so, and restoration additionally names a distinct already-materialized preactivated generation. Each workflow pointer/status change emits one Run revision/event; heartbeat and generation-only CAS do not. Every other materialization/preactivation/launch/checkpoint failure uses its exact failure detail/reason/from-phase quarantine closure. Retirement accepts only exact sealed+last-launch-death or quarantined plus current literal zero authority counts. A successor never adopts an old process or generation.

13. **Separate dispatch authority from evidence authority.** Heartbeat runs every 5 seconds and the lease duration is 30 seconds. Worker activation is authorized only by note 12's atomic launch/Run CAS and grants no invocation authority.

   `claimDispatch` is the pre-claim state transaction. A process-spawning `prepared` row structurally has no `sandboxLaunchSpecRef`. Trusted code chooses the unguessable `dispatchId`, constructs and artifact-first publishes the exact `SandboxLaunchSpecV1.run_invocation` whose owner contains that id, then enters one database view. The transaction requires current Supervisor/admission ownership, `status='running'`, exact Run revision/epoch/`activeWorkerLaunchId`, the pointed row in `phase='activated'` with `generationWriteState='active'`, exact worker identity/containment/generation, a currently unexpired row lease/deadline, no `stopIntentRef` or cancel flag, the highest/current `prepared` attempt with no claim, matching frontier/op/target/request digest, matching budget reservation, and a `grantRef` that decodes only as exact `OperationGrantV1`. It revalidates that grant's Run/principal/policy/frontier/op/request/target/subject/provenance, expiry, dispatch/launch bounds, and attempt-derived use against current storage, plus exact launch owner/parent/plan/runtime/process/environment/filesystem/mount/resource/profile equality; `RunPolicySnapshotV1`, `AuthorizationGrantV1`, approval payloads, templates, and opaque refs cannot pass. It atomically appends the unique `dispatch_claimed` fact with that spec ref and returns its `dispatchId`; concurrent callers observe the one winning claim, while a lost race leaves only an unreachable CAS object. Every `completed|unknown|abandoned` and post-claim `failed` fact repeats the exact claim/spec ref; the pre-dispatch `failed` branch forbids them. Non-spawning operations forbid the spec in every phase.

   That same database view must also decode the launch's exact `WorkspaceGenerationIdentityV1` and require the corresponding `workspace_generations` row to be `phase='active'` with identical Run/generation/launch/epoch and row fields; launch `generationWriteState` alone is insufficient. A missing, quarantined, retired, revoking, checkpointing, sealed, stale-version, or mismatched generation row fails before claim.

   Immediately before releasing target capability, secret, executable start, or request bytes, every broker/sandbox/model/MCP/verifier/publish adapter calls `releaseClaimedDispatch`. It re-reads the same live Run pointer plus exact activated launch/lease and repeats the stop/cancel/deadline/frontier/reservation predicates and the complete exact `OperationGrantV1` decode/identity/use/expiry closure, but requires the exact just-created `dispatchId` as current instead of the now-false no-claim predicate. Any sandbox start additionally validates exact `SandboxLaunchSpecV1.run_invocation` equality to that owner/claim/grant/request/target, active parent containment, exact purpose-specific process source/recipe/argv/cwd/stdio mapping, filesystem/mounts, runtime/executable identity, sanitized environment, resources/profile, and containment plan. Failure closes or reconciles the claim without target I/O. Only a successful second check authorizes productive I/O. The immutable claim then singleflights the complete invocation, including later `unknown -> completed|failed`; it is never released/stolen and that attempt number is never redispatched after timeout, disconnect, lease loss, worker death, or restart.

   `releaseClaimedDispatch` repeats the same exact authoritative generation-row decode/equality in its post-claim view. Revocation of the generation row therefore fences release even if a stale launch projection or worker channel still says active.

   Every result/evidence passes work package 3 `assertEvidenceAuthority`; neither dispatch check is reused after I/O. In one snapshot evidence authority reads the Run, immutable request/claim, and retained original launch row, authenticates original epoch/launch/worker/containment/generation/target plus trusted adapter, broker, or death-inspection provenance, and grants no new I/O. It returns `current` only when the attempt is still highest and the exact frontier or reconciliation subject matches; that evidence may atomically settle and advance once even after lease clearing or post-dispatch stop/deadline/grant expiry. Evidence for a superseded attempt/frontier/result is audit/billing-only and cannot add a Run-visible item, alter a wait, or replace/advance the newer result.

   Every Journal `budgetDelta` is the complete four-counter `BudgetUsage`; partial/optional deltas and omitted-versus-explicit zeros are invalid. `prepared` holds the reservation, while `dispatch_claimed` and `abandoned` carry explicit all-zero values. Every `completed|failed|unknown` commit artifact-first publishes exact `BudgetSettlementV1` and writes its ref on the Journal row. The state transaction matches Run/op/attempt/prepared/terminal sequences and phase, requires all four budget counters as nonnegative safe integers, and checks component-wise `released=reserved`, `consumed=terminal budgetDelta`, `budgetConsumedAfter=budgetConsumedBefore+consumed`, and `budgetReservedAfter=budgetReservedBefore-released`. A pre-dispatch failure has error+settlement but no claim/evidence and consumes zero without dispatched-attempt capacity. Post-claim `failed` repeats the exact claim and accepts only two forms: exact `PostClaimNoReleaseEvidenceV1`, or `opKind='verifier'` with a cross-field-valid `infra_failed` receipt plus exact containment-death closure. The first form proves under the still-live same-owner second gate that broker release or process spawn never began and consumes zero; the verifier form consumes exact attempt usage. Every other claimed no-result state is `unknown`, and a typed target error is `completed` with its exact result artifact. Every released or possibly released model terminal/unknown consumes the exact `NormalModelRequestV1|CompactionModelRequestV1.reservation` in full; its six fields are request-digest-bound, derive from pinned input count/output ceiling/cache-worst-case vector and canonical price evidence, and project exactly to the prepared Journal reservation. `AgentModelTurn.usageTrusted` is literal false; provider/adapter usage, cache assertions, SDK counters, or later telemetry cannot reduce or refund settlement. Historical evidence reuses the charged settlement and cannot double-charge it. `PostClaimNoReleaseEvidenceV1` repeats the claim/request/target/optional grant, exact same still-live Supervisor/owner, and at-most-five-second current inspector. Its broker branch holds the release mutex, revokes the still-unreleased matching token, observes zero active releases, and commits evidence+failed+zero settlement before unlock; its process branch rehashes the exact SandboxLaunchSpec plus `ProcessContainmentNoSpawnEvidenceV1` and commits before spawn authority can release. Restart/owner change, missing token, observed process/release, partial rollback, generic death, adapter assertion, or inline boolean routes to `unknown`, not failed. A broker/no-child `dispatch_claimed` row stores one unguessable `brokerFenceTokenDigest` iff that release path applies; process-contained/non-broker claims and every prepared or pre-dispatch-failed row forbid it. Terminal abandonment of a `retry` unknown requires exact `InvocationDispatchClosureEvidenceV1` for its Run/op/attempt/dispatch/unknown sequence. `containment_death` rehashes exact containment and death-evidence pairs. `broker_release_fenced` rehashes exact `BrokerReleaseFenceEvidenceV1`: operation request/target/grant and claiming Supervisor/owner equal the claim, current inspector epoch is strictly newer, token digest equals the claim, and the trusted broker records the literal token-revoked-plus-matching-active-release-count-zero action and times. Lease expiry, socket loss, inline boolean, worker assertion, or Supervisor-id change alone is not closure proof.

   Entering `unknown` is itself a typed evidence transaction. Before the row append, the Supervisor publishes exact `InvocationAmbiguityEvidenceV1`; its omission digest and Run/frontier/op/kind/attempt/dispatch/claim sequence, request/target pairs, historical claiming Supervisor/StateOwner epoch, current inspector, and observation time must match. `claim_owner_lost` rehashes exact `StateOwnerAcquisitionEvidenceV1(takeover_after_owner_death)` and uses the strictly newer active owner. `broker_channel_lost_after_claim` is only model/tool/MCP with the claim's exact fence-token digest, the same still-live owner, one closed post-release deadline/connection/stream failure, and positive durable-terminal-result absence. `sandbox_channel_lost_after_claim` is only tool/MCP-server/MCP/verifier and rehashes the claim's exact SandboxLaunch/actual containment; it proves either same-owner post-deadline authenticated channel close with no result or exact all-descendant death before a terminal result was durably received. `publication_path_ambiguous` is only publish and rehashes exact `PublicationProofV1(kind='path_ambiguity')`. The same transaction stores that exact `evidenceRef/evidenceDigest` pair on `unknown` plus full conservative settlement. Op/mechanism mismatch, free error text, caller/worker assertion, missing/half pair, stale inspector, or evidence proving a definite result is invalid. `abandoned` forbids its own evidence pair; its `ManualAbandonAttestationV1` must repeat the prior unknown pair byte-for-byte, never a newer display or probe artifact.

   MCP registry probes do not reuse the Run path. The Supervisor uses exact `AdminOperation`; no sidecar. Prepared carries mandatory target/core/plan/spec ref+digest pairs before preactivation. Before containment, the Supervisor revalidates exact static core plus admin SandboxLaunch against operation/target/plan, fixed stdio-or-HTTP process recipe, isolated root, signed runtime, sanitized environment, resources and owner. Dynamic containment/claim/dispatch/credential/Run identity is absent. Only after active containment may claim create exact `AdminProbeBrokerRequest`, whose target and payload ref+digests equal the row/target/core; release gates it. Completion publishes exact `McpAdminProbeResultV1` plus `AdminProbeClosureEvidenceV1(containment_dead)`; failure publishes exact `AdminProbeErrorV1` plus its identical no-spawn/death closure. All row/result/closure/error/control-response digests and plan/spec repetitions match before terminal/control commit. No Run authority is fabricated.

   Managed `local_zero_cost` inference uses neither Run-worker nor admin-probe authority. `ensureLocalInferenceActive` joins or creates the one exact service-level `LocalInferenceActivationCycleV1`: `activationCycleId=base64url(SHA-256(JCS({ownerPrincipalId,serviceId,serviceSpecDigest,cycleOrdinal})))`, ordinal is a contiguous positive per-service sequence, and at most one `starting_launch|retry_wait` cycle exists. `run_submission` participants bind the retained request/digest/admission identity; `run_model_frontier` participants bind an exact queued Run revision/frontier. They are append-only in join order, identity-unique, capped at 128, and cross-cycle request lookup occurs before create/join; participant 129 returns `RESOURCE_EXHAUSTED(resourceKind='local_inference_activation_cycle')` without joining or I/O. `cycleDigest` and exact `LocalInferenceActivationFailureV1.failureDigest` each hash JCS with only itself omitted. Cycle creation atomically reserves attempt 1. Exact no-spawn/death retirement after any attempt-1 launch/timeout/health/capability failure must produce `retry_wait`, then attempt 2 after exactly one second; it cannot terminal-fail. Only inability to retire may terminal-fail attempt 1 as `LocalInferenceActivationFailureV1(finalAttempt=1,failureKind='containment_unresolved')`, retaining the fenced launch. Attempt-2 failure is terminal after positive retirement or terminal as `containment_unresolved` if proof remains impossible. Each failure artifact's attempt/reason/retirement closure must match this matrix; each cycle-linked launch repeats service/spec/cycle/attempt identity and has a fixed 120-second deadline. Restart/disconnect cannot mint attempt 3.

   Preactivation is blocked, secretless, no-egress, isolated-empty-root, and cannot accept model traffic. Exact health/capability inspection plus `LocalInferenceBoundaryEvidenceV1` CASes only the launch row to active and exposes its canonical loopback endpoint; heartbeat narrow-CASes only launch-row lease fields and emits no Run revision/event. Retirement is closed: `reserved -> retired/retirementKind='no_spawn'` forbids process/boundary/quiesce fields and requires exact no-spawn evidence; `preactivated -> retired/retirementKind='death'` or `revoking -> retired/retirementKind='death'` requires the exact created containment/quiesce/death evidence, with boundary evidence if and only if it reached active. Success terminalizes the cycle with that exact launch/boundary and atomically fans out admission/control responses plus existing-Run eligibility. Final failure publishes exact `LocalInferenceActivationFailureV1`, terminalizes the cycle, returns the same activation error to submissions, and proposes exact `runtime/local_inference_unavailable` StopIntent for still-matching Run frontiers; stale/stopped/moved participants are audit-only. Before each local model release, the broker requires the one active launch, live lease, dynamic containment/boundary/capability closure, and the Run assembly's exact `LocalZeroCostProvenanceV1.stableServiceIdentityDigest`. A successor never adopts an old service: it fences traffic, retires it through one proof branch, and may then create only the next cycle-authorized launch whose stable projection matches but whose dynamic identities are new. Ambient loopback services and copied old dynamic ids are invalid.

   A post-admission service death uses the same cycle. The Supervisor first settles the prior model attempt, quiesces/checkpoints and retires the Run worker, then atomically leaves the Run `queued` at the same agent frontier and joins that exact Run revision/frontier to the current/new cycle. No model reservation or claim remains live. Cycle success makes only that unchanged frontier eligible; bounded failure proposes its typed StopIntent. There is no `waiting(resource)`, ambient fallback, user-request-only retry counter, or implementation-selected infinite queue.

14. **Prove whole-containment death before replacement.** `WorkerIdentity` persists executable/start identity, Supervisor spawn nonce, activation identity, intended lease epoch, launch id, Supervisor instance, and `ProcessContainmentRef`; a root PID is diagnostic only. Linux proof requires the exact cgroup v2 subtree to report `populated=0`, its namespace init/subreaper to be dead/reaped, and the recorded cgroup/namespace identities not to have been reused. macOS proof requires the exact VM instance to be stopped, the matching VM process identity retired, and the guest boot identity no longer reachable. Termination first requests bounded graceful shutdown, then uses cgroup kill or forced VM stop and polls the full boundary.

   Permission errors, mismatched/reused identity, an inaccessible boundary, incomplete descendant census, or indeterminate VM/cgroup state are not death proof. For every worker loss—including an immediately positive observation—the Supervisor first atomically creates the canonical `waiting(reconciliation)` subject with `subject.kind='worker_death'` and exact `oldWorkerLaunchId`, clears `Run.activeWorkerLaunchId`, moves the referenced launch row to unrenewable/unretired `phase='reconciling'` with `generationWriteState='fenced_reconciling'`, and CASes the authoritative generation from its exact current `active|revoking|checkpointing` phase to `fenced_reconciling` with the wait ref/digest, source phase, and phase-valid quiesce id; it reserves no replacement. Only a subsequent exact positive `WorkerRecoveryEvidenceV1` can be wrapped by artifact-first exact quarantine evidence and move that old fenced row, under either disposition, through the deterministic no-replace move/fsync/original-absence proof. No wording or implementation may treat an expired heartbeat, root-process exit, PID token, process group, elapsed time, or a renamed-looking path as proof.

15. **Recover rather than restart blindly.** Before serving model traffic, registry mutations, or Runs, startup scans every nonterminal `local_inference_activation_cycles` row and its cycle-linked launches, every other nonretired `local_inference_launches` row, every nonterminal `admin_operations` row, every non-retired `worker_launches` row, every non-retired `workspace_generations` row, and then every nonterminal Run. The new `supervisorInstanceId` makes every older launch/channel non-adoptable regardless of remaining lease time. For a reserved local/admin/worker row it proves the exact plan/spec closure never spawned and terminalizes only through its no-spawn branch; for every created containment it fences traffic/dispatch, terminates the complete boundary, obtains current-inspector death evidence, and terminalizes only through the exact death branch. Local recovery preserves the cycle ordinal, participants, attempt prefix, retry deadline, and stable service projection while minting fresh dynamic identity only for the one next legal launch; admin retry observes its fixed attempt/backoff; neither adopts a process. An unprovable local containment publishes the exact activation failure, retains the blocking unretired launch, atomically fails the cycle/fans out participants, and prevents a later cycle. For every old active Run worker, startup first performs the mandatory one-transaction pointer clear, exact worker-death wait installation, launch `reconciling/fenced_reconciling` projection, and generation `fenced_reconciling` CAS from its exact prior `active|revoking|checkpointing` phase—even when current death proof is already available. It issues no fresh handle/dispatch. Only a subsequent exact WorkerRecovery reducer may publish deterministic quarantine evidence and quarantine that old fenced row; both dispositions do so. `quarantined` forbids restore fields, while `restored_from_checkpoint` additionally requires a same-Run ready Checkpoint/workspace state and a **distinct** `replacementWorkspaceGenerationRef` already materialized with exact snapshot evidence in `preactivated_readonly`. It never reconnects, renews, completes an old activation handshake, guesses quarantine/retirement, or schedules around an unresolved row. Signed broker/target/death evidence may still settle a claimed attempt through `assertEvidenceAuthority`, but an old worker assertion/channel is never evidence or adoption. Only after old-generation quarantine/retirement plus claimed-invocation reconciliation may an unstopped Run reserve a fresh launch/epoch against the replacement. A Run selecting `local_zero_cost` remains queued at its exact cycle participant frontier or follows the cycle's typed StopIntent until a fresh active service supplies the same stable projection and fresh boundary/capability evidence; it never falls back to the stale or ambient endpoint.

   The Run recovery closure is exactly immutable RunSpec + authoritative Run row + latest ready Checkpoint + ordered typed Run items after its item cursor + Journal facts after its journal cursor + every current/unretired Run-owned `worker_launches` row + every exact `ChildAllocationV1` row where the Run is parent/child +, when the assembly selects `local_zero_cost`, its exact current/historical Run-frontier activation participant/cycle/failure, all current/nonterminal cycles and cycle-linked launches for the service, terminal cycles required for request replay, and boundary/model/capability evidence + referenced immutable artifacts. Those references decode and cross-check the current `RunPolicySnapshotV1`, every applicable `OperationGrantV1`, needed `AuthorizationGrantV1`/`AuthorizationConsumptionReceiptV1`, `DependencyInstallScriptsAuthorizationTemplateV1`, frontier/wait/probe subject, winning StopIntent, admin probe core, all owner-specific SandboxLaunch/containment identities and evidence, local stable provenance/dynamic boundary closure, terminal child result/usage refs, any current/final `VerificationClosureV1`, and every forward-success or abort-stop `DeliveryTerminalProjectionEvidence` reachable from a frontier/result/TerminalDetail. The separate local-service startup closure contains every nonterminal activation cycle, every cycle-linked/unretired launch, terminal participant replay/failure truth, and their request/frontier/service/spec/plan/SandboxLaunch/containment/boundary/retirement graph even when no Run currently references them. Unknown/widened types or broken typed edges are `RECOVERY_REQUIRED`; `control_requests` responses and `run_events` are not reducer input.

   Recovery requeues eligible `queued` Runs; idempotently evaluates exact child subjects; preserves approval/input/manual invocation subjects; executes only the bounded reducer/query for invocation/publication-path/worker-death subjects; and drives StopIntent closure to a fixed point. For a fenced invocation, `prepared` without `dispatch_claimed` may become only the exact no-claim pre-dispatch `failed` row after launch/dispatch authority is fenced; its transaction forbids evidence and proves the claim is absent. A claim without terminal fact is possibly dispatched and that attempt is never reissued. The closed replay contract pessimistically settles before a policy-authorized `retry`, requires death plus generation quarantine/rollback for `workspace-rollback-retry`, permits only declared status/idempotency queries for `reconcile`, and preserves `manual` ambiguity.

   Stop/deadline forbids productive activation/retry/model/tool/MCP/verifier/publication but not the trusted no-new-semantic-effect recovery plane: containment kill/death proof, declared status/idempotency query, generation quarantine/rollback, child cancel/settlement, publication inspection, completion/cleanup inside an already-claimed publication envelope using its original claim, exact receipt-proven abort-only removal of a delivery-created empty directory through work package 3's zero-reservation/no-worker `claimRecoveryMaintenance`/`releaseRecoveryMaintenance`, and terminal commit remain bounded and allowed. The historical exact-plan decision/grant binding may support that cleanup after productive grant expiry, but cannot mint new authority. No new semantic publication envelope or desired-path mutation is recovery. A resumable unstopped Run restores the latest ready Checkpoint into a fresh generation, creates a new launch row, and only after activation continues authoritative `nextStep`.

16. **Enforce absolute wall deadlines and additive budget stops through one reducer.** Admission persists `deadlineAt`; the timer scan forbids new `prepared`, dispatch, child admission, grant activation, or worker activation at expiry. Worker/broker/verifier timeouts are capped to the remaining interval. Wall expiry proposes `origin='deadline'`; a reservation/admission transaction that would make an additive token/cost/tool/repair counter exceed its ceiling proposes the cross-field-valid `origin='budget'` intent instead of preparing work. Both carry `reason='budget_exhausted'`, apply the same precedence, and drive the same closed quiescence machinery as cancellation. Fully charged `retry` calls may be abandoned only after dispatch/containment fencing; `workspace-rollback-retry` closes only after quarantine/rollback proof; unresolved `reconcile|manual`, child allocations, or publication paths retain their typed subject until safe. Restart never extends the deadline, counters never reset/refund to evade the intent, and neither budget path is verifier infrastructure failure.

17. **Implement cancellation as a closed reducer, not a signal.** `run.cancel` is replayed through `control_requests`, compare-and-swaps the exact expected Run revision, proposes `user_cancel/cancelled_by_user`, applies StopIntent precedence, and monotonically sets `cancelRequested=true`. Parent cancellation proposes `parent_cancel/parent_cancelled`; child cancellation never propagates upward. An already-terminal Run returns the idempotently stored response without rewriting truth.

   The reducer is exhaustive and restart-idempotent:

   1. forbid every new productive `prepared`, dispatch, activation, approval grant, input continuation, retry, repair, child admission, verifier, model/tool/MCP call, and semantic publication envelope while retaining only the bounded no-new-effect recovery operations from note 15;
   2. retire a reserved/preactivated launch only with positive no-spawn/death evidence; revoke an activated row, clear the Run pointer into `worker_death` if death is not yet proven, and never create a replacement;
   3. close every undispatched typed continuation. Tool/MCP batch calls receive identity-matched `cancelled` results; model, MCP-server, verifier, and publish continuations receive their operation-specific cancelled/error/lifecycle item. A `prepared`-without-claim attempt gets the exact pre-dispatch `failed` row with zero-consumed settlement and reservation release; it carries no evidence because claim absence is verified in that transaction;
   4. request abort for a claimed invocation, then accept only `assertEvidenceAuthority` evidence. A current completed/failed result settles through its typed reducer; missing outcome becomes `unknown` with exact conservative full-charge `BudgetSettlementV1`. A `retry` unknown may close unused only after exact `InvocationDispatchClosureEvidenceV1` proves rehashed containment/death pairs or an exact `BrokerReleaseFenceEvidenceV1` bound to the claim's stored fence token; its cancelled result and terminal detail repeat both refs. Workspace mutation additionally requires quarantine/rollback; unresolved `reconcile|manual` stays on the exact invocation subject with `cancelRequested=true`. Only `ReplayClass='manual'` accepts explicit `abandon_run`, which publishes exact `ManualAbandonAttestationV1`, repeats the unknown settlement without another charge, and never continues the batch with a fabricated result;
   5. cascade typed parent StopIntents idempotently to direct nonterminal children. Parent allocations remain reserved until validated terminal settlement. A running parent receives no asynchronous revision: child terminal updates only the allocation row, while a lease-free exact child subject may settle/revise the parent and otherwise remains `waiting(child)`;
   6. approval/input waits close without granting/continuing; child `stop_settlement` and reconciliation `invocation|publication_path|worker_death` subjects execute only their no-new-effect recovery/settlement reducer. Each reducer replaces the exact subject or advances terminal quiescence;
   7. call `commitTerminalStop` only when every **Run-owned** WorkerLaunch/invocation containment is retired or proven empty, `activeWorkerLaunchId` is absent, no productive Run dispatch is live, every workspace/publication ambiguity is resolved, every typed frontier entry is closed, all child allocations are settled, and every `budgetReserved` counter is zero. A shared activation cycle/local-service launch is never a Run terminal dependency; only an open model invocation against it must settle, and a terminal/moved Run makes its participant obsolete. Cancellation never fabricates effect failure or discards evidence to reach terminal state.

   `TerminalDetail.primaryEvidenceRef` follows the exact branch matrix: integrity/source-stop/local-inference-failure/runtime-error/manual-attestation refs when those branches carry them, otherwise the immutable winning `stopIntentRef` itself. Only a stopped delivery Run with a claimed forward publication operation and exact completed abort projection may additionally retain `deliveryTerminalProjectionEvidenceRef`, and that artifact must be the abort-selected `DeliveryTerminalProjectionEvidence` revalidated against the carried proof frontier and Journal/path/descriptor facts. Agent stops, delivery merge conflict, approval denial, cancellation before the first forward claim, or incomplete abort closure forbid it. The surrounding closure is exactly `publicationResultItemRefs`, `abandonedRetryInvocations`, and optional `abandonedManualInvocation`; every retry entry repeats the exact unknown `budgetSettlementRef` plus `dispatchFenceOrDeathEvidenceRef`, while the manual entry repeats the identical `ManualAbandonAttestationV1` held by Journal and any `ToolAbandonedItem`. Candidate, diagnostic, verifier-receipt, and child-result facts stay in ordered items/Journal and are never copied into implementation-selected TerminalDetail lists.

18. **Persist display events, not recovery truth.** Assign `eventSeq` monotonically per Run in the same transaction as the related authoritative state transition when one exists. Persist state changes, typed waits, approvals, stop progress, tool/model invocation boundaries, verifier outcomes, final/result references, and errors. Store large stdout/stderr/model content as artifact refs; coalesce high-frequency progress deltas rather than filling SQLite with token chunks.

19. **Define cursor semantics as pure pagination.** `run.attach {runId, afterEventSeq, limit}` accepts a batch limit in `1..1000`. One SQLite snapshot captures the authoritative Run snapshot plus `earliestRetainedEventSeq`, `latestRetainedEventSeq`, and `highWaterEventSeq`, then returns at most `limit` committed events in sequence order from `(afterEventSeq, highWaterEventSeq]`. The earliest valid cursor is `max(0,earliestRetainedEventSeq-1)`: initial zero and exact earliest-minus-one are valid, a smaller cursor returns `EVENT_CURSOR_EXPIRED` with retained bounds/current snapshot, and `afterEventSeq>highWaterEventSeq` returns `INVALID_REQUEST`. `afterEventSeq=highWaterEventSeq` returns an empty page whose `nextEventSeq` is that same cursor. Otherwise `nextEventSeq` is the last returned sequence, or the supplied cursor when the page is empty. If `nextEventSeq < highWaterEventSeq`, the client must call `run.attach` again with `afterEventSeq=nextEventSeq`; equality means it is caught up only through that captured cut. A later call from the equal cursor captures a new high-water and returns events committed afterward. Public v1 defines no implicit push, subscription, follow stream, or out-of-band event envelope; a transport optimization is legal only if it preserves this exact request/result page sequence. Never fabricate missing history or accept a future cursor.

20. **Retain enough to return without deleting Runs.** Keep all Run events while nonterminal and terminal spools at least 30 days, always retaining the terminal anchor. There is no `run.delete` or automatic deletion of authoritative facts. Cursor pruning removes only display rows and cannot change truth. CAS/generation GC roots every approval/manual/settlement/dispatch closure including exact broker-fence or containment-death edge, inherited verification/source graph, complete MCP/admin graph, every reconciliation state with persisted in-flight dispatch plus wrapper/subject-or-timeout/inspector-task-owner-death closure, activation participants/failures, complete StateOwner identity/evidence chain, SandboxLaunch/local-service/model/provenance/boundary/containment graph, and every retained event ref under the RFC death/age/complete-reachability rules.

21. **Freeze one Run and Session method surface.** The initial control methods are exactly:

    ```text
    control.hello
    session.create
    session.list
    session.get
    session.fork
    session.compact
    session.handoff.create
    run.submit
    run.list
    run.get
    run.attach
    run.cancel
    run.approve
    run.input
    run.reconcile
    run.diff
    run.result
    run.apply
    authorization.create
    authorization.list
    authorization.revoke
    mcp.register
    mcp.refresh
    mcp.list
    artifact.get
    supervisor.status
    ```

   `control_requests` is the only final public-mutator replay boundary: unique `(principalId, method, requestId)`, canonical JCS/SHA-256 request digest, immutable response artifact ref/revision, and commit time. The service publishes the deterministic response artifact first, then writes the request row in the same transaction as the final state change. Same digest replays that response even if an expected revision/wait ref is now stale; different bytes return `REQUEST_ID_CONFLICT` and never rerun the reducer. Before that final row, exactly two closed crash fences may retain a public request: `admin_operations` for MCP probe recovery, and one `run_submission` participant in a shared `local_inference_activation_cycles` row for local-model admission. Cross-cycle participant lookup makes replay deterministic even when another request created the cycle; subordinate launch rows contain no request identity. Neither fence is a success response. Cycle finalization exhaustively admits or returns an error and writes `control_requests` for every submission participant in the same transaction; Run-frontier participants receive eligibility or typed StopIntent, never a control response. `run.get|list|attach`, `session.get|list`, `authorization.list`, `mcp.list`, `artifact.get`, `run.diff|result`, deterministic `session.handoff.create`, and `supervisor.status` are read-only, reject `requestId`, and need no row.

   Session contracts are context-only and exact:

   `run.reconcile(probe_now)` is an ordinary finalized public mutation at enqueue time, never a third pre-response fence: state transition to `user_in_flight`, persisted dispatch, `probe_enqueued` result/snapshot, response artifact, and `control_requests` row are one transaction before probe I/O. Later evidence is internal state progress only. Exact-risk `abandon_run` instead commits its attestation/terminal result and `{kind:'abandoned',evidenceRef}` response synchronously.

   - `session.create {requestId, requestDigest, admissionKey, workspacePath, name?}` descriptor-walks the absolute path no-follow, publishes one exact `WorkspaceIdentityV1.kind='live'` plus exact `RepositoryIdentityV1` iff literal in-root `.git` exists, and idempotently returns one Session snapshot. Root/`.git` `deviceId/fileId` remain canonical unsigned decimal strings rather than JS numbers; same-path replacement never rebinds the Session. `legacy_unavailable` is importer-only.
   - `session.list {workspacePath?, cursor?, limit?}` defaults to 50, permits `1..100`, and returns summaries plus next cursor.
   - `session.get {sessionId, afterItemSeq?, limit?}` runs in one read snapshot, fixes `snapshot.contextRevision` and `highWaterItemSeq=snapshot.latestItemSeq`, defaults its exclusive numeric cursor to zero and limit to 100 (`1..1000`), and returns the first strictly increasing items through that cut whose complete `JCS(items)` is at most 1 MiB. `nextItemSeq` is the last returned sequence or the supplied cursor on empty; cursor-above-high-water is `INVALID_REQUEST`, equality is caught-up, and the non-pruned item stream never expires.
   - `session.fork {requestId, requestDigest, admissionKey, sessionId, expectedContextRevision, throughItemSeq, name?}` requires cursor zero or a current segment boundary and creates one child lineage whose projection references the immutable ancestor prefix; it clones no item rows, freezes the fork cursor, initializes context revision 1, and rejects an in-segment cursor.
   - `session.compact {requestId, requestDigest, sessionId, expectedContextRevision, fromItemSeq, throughItemSeq, summaryMarkdown, retainedItemIds}` accepts at most 256 KiB UTF-8 and at most 256 unique retained ids. The range must equal whole current segment boundaries and every selected segment must be `raw`; any summary or `excluded_control` segment is ineligible. It publishes exact bounded `ModelTextV1`, repeats its `summaryRef/summaryDigest` in the exact `SessionCompactionItem` and summary segment, preserves raw items, and advances context exactly once through `control_requests` plus revision CAS. Straddling/nested/recompaction/control-range requests are `INVALID_REQUEST`.
   - `session.handoff.create {sessionId, expectedContextRevision, throughItemSeq?}` is read-only and captures Session/lineage/projection in one snapshot. Omitted cursor means the captured projection cut; explicit cursor is zero or an exact current segment end no greater than that cut. The service publishes exact `SessionHandoffV1`: raw root-terminal and summary entries plus excluded-control ranges are contiguous-indexed and in stored encounter order, every source/workspace/projection ref+digest rehashes, and `handoffDigest` omits itself. It renders JSON as exact JCS and Markdown only through the fixed RFC heading/JCS-session-id/base-10-number/LF-indented-content/excluded-count algorithm. The canonical result contains only `json` and `markdown` `ArtifactDescriptorV1`, each rehashing those bytes. Identical Session/revision/cursor returns identical descriptors; stale revision, inside-segment/future cursor, alternate renderer, hidden transcript, mutable path, timestamp/randomness, authority/audit body, or adapter field is rejected.

   Create/fork use admission-key+intent uniqueness and return `ADMISSION_KEY_CONFLICT` for different intent; every mutation rejects a stale context revision. There is deliberately no `session.resume`, public append/items/import/bookmark mutation, active-Session setter, Session lease, or client-facing Run-Checkpoint mutation. `cliq resume` composes `session.get` plus a new `run.submit`. Imported legacy bookmarks/handoffs appear only as typed items/artifact refs; ordinary fork may use their preserved cursor. Root Run terminal publication is the sole internal Session append.

   Method handlers call one application service; CLI, TUI, JSONL, and stdio RPC do not duplicate reducers or authorization. All four list methods use WP06/RFC's exact 15-minute materialized-list cut: one StateOwner-gated transaction freezes current typed summaries and `(createdAt,bytewise stableId)` order, normalized principal/method/filter/limit, row/cut digests, and a private 256-bit cursor secret. Canonical JCS/base64url cursors authenticate cut id/last-returned ordinal with domain-separated HMAC; replay is byte-identical, mutation after page one cannot alter membership/values, and malformed/forged/mismatched/expired/unknown cursors are `INVALID_REQUEST`. Cuts cap at 100,000 rows/64 MiB, root referenced artifacts only until expiry, and never drive authoritative state. `run.list` defaults 50/max 100. `run.get` uses one read snapshot to fix the Run snapshot and all three high-waters before reading: exclusive safe-integer item/Journal cursors default zero; each item/Journal/Checkpoint limit defaults 100 and permits `1..1000`; Checkpoints use strict `(createdAt,id)` order and an exact unpadded-base64url JCS cursor `{schemaVersion:1,runId,createdAt,checkpointId}` that round-trips to a retained row of that Run. Each `next*` is the last returned cursor or normalized input on empty; cursor-above-high-water, malformed/cross-Run/nonexistent Checkpoint cursor is `INVALID_REQUEST`, equality is caught-up, and no stream expires. The complete cap is exact `JCS({items,journal,checkpoints})<=1 MiB`: candidates are considered in fixed `items -> journal -> checkpoints` priority, preserving stream order/limit; the first non-fitting candidate and every later candidate remain for the next request. All high-waters/next cursors come from that same snapshot, so concurrent commits appear only on a later call without gaps. `run.diff|run.result` return only immutable refs for `succeeded|completed_unverified`. For `queued|running|waiting` they return exact retryable `RESULT_UNAVAILABLE {runId,status,currentRevision}`; for `failed|cancelled` they return exact nonretryable `RESULT_UNAVAILABLE {runId,status,terminalDetailRef}`. No failed candidate/diagnostic can become a query success. `artifact.get {digest, offset, length}` permits a 4 MiB maximum chunk and returns verified base64 bytes, total size/digest, next offset, and EOF below the 8 MiB frame cap. `authorization.create|revoke` and `mcp.register|refresh` are replay-safe user-administration mutators; their bounded semantic contracts and registry recovery behavior are frozen in work package 6, while this package owns UDS authentication, `control_requests`, and routing through the same Supervisor application-service boundary. `authorization.revoke` CASes active to revoked, replays revoked as `already_revoked`, and treats consumed as the canonical successful `already_consumed` no-op: it leaves exact `AuthorizationGrantV1` state `consumed`, receipt, row version, derived authority, and use truth unchanged.

   The server imports WP06's strict generated schemas and exact closed error union—`INVALID_REQUEST | INCOMPATIBLE_PROTOCOL | NOT_FOUND | REVISION_CONFLICT | WAIT_SUBJECT_MISMATCH | REQUEST_ID_CONFLICT | ADMISSION_KEY_CONFLICT | AUTHORIZATION_REQUIRED | POLICY_DENIED | MODEL_COST_UNKNOWN | BUDGET_EXHAUSTED | RESOURCE_EXHAUSTED | RESULT_UNAVAILABLE | RUN_TERMINAL | CANCEL_REQUESTED | UNSUPPORTED_PLATFORM | UNSUPPORTED_EXECUTION_IDENTITY | ARTIFACT_MISMATCH | RECOVERY_REQUIRED | EVENT_CURSOR_EXPIRED | RATE_LIMITED | INTERNAL`—rather than maintaining adapter-local names or string errors. The `RESOURCE_EXHAUSTED.resourceKind` union includes exact `run_queue|worker_capacity|admin_probe_capacity|local_inference_activation_cycle|state_storage`; adapters cannot collapse or rename the local-cycle branch.

   Every application handler returns only the generated canonical `ControlApplicationResponseV1`: `{protocolVersion:1,ok:true,result:ControlResultV1}` with exactly one method-discriminated result, or `{protocolVersion:1,ok:false,method,error:ControlErrorV1}`. Unknown fields and adapter-specific success/error envelopes are rejected. JSON-RPC/CLI/TUI/JSONL transport correlation stays outside that object; an adapter may frame or render it but cannot project a different result, cursor, authorization summary, redaction, error payload, or method-specific response. The exact serialized success/error artifact is the value stored by `control_requests` for mutators. `supervisor.status` retains its exact canonical fields: an unreconciled required local-inference launch or unavailable stable-identity replacement makes `health='degraded'`, but the handler adds no service row, endpoint, model path, containment id, credential, or adapter-local diagnostic field.

22. **Keep service updates safe.** Client startup ensures a compatible user service exists and asks launchd/systemd to activate it. Installing/updating the user-service definition is idempotent. An incompatible running Supervisor rejects admission rather than being killed underneath active Runs; replacement occurs only after drain or explicit safe service maintenance. Tests use injected service-manager adapters and never modify the developer's real service definition.

23. **Make package ownership explicit and keep the Supervisor small.** Work package 1 owns `src/kernel/types.ts`, SQLite/CAS schemas, exact artifact decoders, and atomic persistence APIs, including `worker_launches`, `local_inference_activation_cycles`, `local_inference_launches`, atomic activation participant fanout, `control_requests`, exact `ChildAllocationV1`, authorization rows/receipts, wait refs, Journal dispatch/evidence transactions, and terminal validation. Work package 2 owns model/tool/MCP typed item constructors and frontier rules. Work package 3 owns containment, generation quiescence, exact-`OperationGrantV1` `claimDispatch`/`releaseClaimedDispatch`, the local-inference boundary/launch-spec enforcement adapter, the narrow `claimRecoveryMaintenance`/`releaseRecoveryMaintenance` enforcement adapter, and `assertEvidenceAuthority`. This package owns scheduling, worker/admin/local-service cycle/launch orchestration, exact Run-frontier join routing, wait/StopIntent reducer routing, UDS authentication, control-request replay, and server-side protocol routing, but only by passing exact kernel types to work package 1. Work package 5 owns verifier/publication/child semantic evidence and `VerificationClosureV1` construction/abort-operation validators but returns typed mutations to this package's application service for one work package 1 transaction. Work package 6 owns generated public schemas/clients/command mapping plus authorization and MCP-registry semantic services consumed through this package's single control boundary; its public result is only `ControlApplicationResponseV1`. No package writes Run status directly, widens a canonical type, or creates a parallel lifecycle.

   Scheduler state is the Run row plus a minimal FIFO query. Child Runs are ordinary Runs. Do not add priority queues, workflow definitions, roles, cron, distributed coordination, repository polling, or plugin execution to this process.

24. **Quiesce the complete authority plane before rollback.** `cliq state rollback --to-legacy` publishes and retains exact `RollbackToLegacyRequestV1` bound to the current Kernel authority marker/generation and backup, reuses the live Supervisor's already-held StateOwner token, then acquires and continuously holds the remaining order: exclusive Kernel global/cutover gate, local-model registry/object-store lock, legacy auth-store lock, every legacy Session/transaction/plan lock in canonical byte order, then credential-authority. It gates the control socket and every broker/credential release under those locks; if any nonterminal Run exists it publishes no rollback control, releases the additional locks, and restores ordinary service. Otherwise it exports terminal audit truth, durably publishes `MigrationControlV1(rollback_draining)` as the global fence, and keeps the complete lock set through typed authority settlement, exact auth-outcome restore, and prepared marker publication. While fenced, every control/admin/authorization/MCP/admission/credential/local-model mutation, service activation/join, worker/admin/invocation claim, and model/tool/provider request is rejected; no internal handler bypass exists. The Supervisor drives every nonterminal admin operation and local-inference activation cycle to its exact typed terminal reducer, fences/kills and positively no-spawn/death-proves every worker/invocation/admin/local-inference containment, retires worker/admin/local launch rows, evidence-closes every invocation claim, and proves broker/control/credential quiescence. Unknown, unresolved, inaccessible, surviving, or unproven state blocks with the fence intact. After WP01 stages exact legacy generation/receipt and byte-identical marker documents and enters `rollback_restoring`, the Supervisor's last Kernel transaction publishes graceful StateOwner transition evidence and terminalizes itself. It may then rename/fsync only the prepared legacy-root marker first and state-root authority marker last, release locks, and exit. A crash in that interval permits only clean acquisition under the retained fence, missing-marker replay, and that successor's own graceful last transaction; after the state-root legacy marker no owner acquisition or Kernel mutation is legal. Socket removal, lease expiry, PID exit, timeout, or sentinel presence is not quiescence proof.

Reuse existing code:

- Reuse the versioned envelope, JSON serialization, artifact query, and typed event concepts from `src/headless/contract.ts`, `events.ts`, `jsonl.ts`, and `rpc.ts`.
- Reuse `AbortSignal` inside one worker lifetime, but not as durable cancellation truth.
- Reuse CLI and TUI rendering/state components as clients after replacing process-local lifecycle ownership.
- Reuse Workspace Trust and policy composition through admission; the Supervisor must revalidate the frozen admission inputs rather than trusting arbitrary client assertions.
- Reuse `src/lib/path-lock.ts` concepts for single-owner startup, but not stale-mtime alone as worker-death proof.

Preserve / do not touch:

- `Run` remains the sole workflow truth; its exact `activeWorkerLaunchId` joins to the narrow `worker_launches` lease/generation authority. Supervisor memory and `run_events` are caches/spools, not alternate state machines.
- Session remains context continuity and receives only terminal summary/result publication, not leases or queue state.
- Existing stdio JSON-RPC remains available as an adapter, but closing its transport cannot abort an accepted Run.
- JSONL remains a transport/rendering format and follows the same durable cursor.
- No client is allowed to write Run status directly; all mutations are revision-checked application-service operations.
- Do not add a Task, DAG, scheduler plugin ABI, HTTP server, TCP listener, remote worker, or automatic apply path.

### Acceptance Criteria

- [ ] Exactly one per-user Supervisor owns a `$CLIQ_HOME`; launchd/systemd restarts it. Only bootstrap for an exact as-yet-unowned `fresh_empty|migrated_candidate` generation, latest-graceful clean acquisition, or positive-death takeover may establish authority. Migrated bootstrap requires the durable matching Kernel marker/candidate/image/CAS closure and is the first post-cutover repository transaction. These APIs register only named metadata/owner rows under exact descriptors; every other write/release needs active equality, except already-prepared rollback marker rename after graceful finalization. Replacement/loss/mismatch gates authority and full history stays rooted.
- [ ] The control listener is exact root-relative `runtime/control-v1.sock` below a same-user `0700` StateRoot directory, remains held open, is descriptor-verified mode `0600`, rejects unsafe/symlinked/replaced paths, and exposes no TCP/HTTP listener. Every accepted UDS connection publishes exact `LocalSocketPeerObservationV1` from listener/accepted-socket fstat plus twice-identical Linux `SO_PEERCRED` or macOS `getpeereid`+`LOCAL_PEERPID` samples around exact `PlatformProcessIdentityV1`; root/platform/uid/pid/time/descriptor equality is mandatory. The resulting exact principal/channel artifacts use a fresh 32-byte nonce digest and are injected into requests. Caller-supplied identity, unavailable APIs, reused/exited pid, listener drift, or sample mismatch closes without application dispatch.
- [ ] Every durable timestamp uses the fixed canonical UTC-millisecond grammar and checked safe-integer arithmetic. Every authoritative transaction uses and advances the one StateOwner-gated `CanonicalTimeFenceV1` sample. Wall-clock regression persists `clock_regressed`, blocks admission/lease/grant/capability/dispatch/retry/expiry extension and revokes/quiesces release gates until the current owner observes the retained high-water. Reboot, wall rollback, or adapter time cannot extend authority; fake-clock tests cover regression before heartbeat, claim, second release gate, approval, retry, and recovery-to-healthy.
- [ ] An incompatible client fails during `control.hello` before any submission or mutation.
- [ ] `session.create|fork` and `run.submit|apply` compute the exact admission-intent formula and key replay by `(principalId,method,admissionKey)`. Equal intent returns the first Session/Run/control result before Session/source/workspace validation, descriptor capture, or artifact publication; unequal intent returns `ADMISSION_KEY_CONFLICT` with no state/filesystem read beyond replay. A lost submit response returns the same `runId`; concurrent first execution is rechecked under the admission write transaction.
- [ ] `session.create` publishes only exact live `WorkspaceIdentityV1` from same-principal no-follow descriptor traversal; root device/file ids are canonical unsigned decimal strings never carried in JS number and owner uid is safe integer. Git requires exact `RepositoryIdentityV1` ref+digest for literal in-root `.git` with the same decimal identity/object format; non-Git forbids both. Fork preserves the exact workspace ref. `run.submit.workspacePath` must resolve to a live Session and every workspace/repository digest equals it. `run.apply` has no path and derives a live source Session. Root/`.git` replacement or identity drift returns `ARTIFACT_MISMATCH`; imported `legacy_unavailable` Sessions/forks are context-only and create no Run/effect.
- [ ] Every `run.submit|run.apply` validates `RunAssemblyV1.sandboxBackend` as exactly `macos_vm|linux_namespace` plus the selected strong backend, worker identity, and every pinned executable probe before creating a Run. Read-only, text-only, no-tool, no-required-verifier, and non-Git requests receive no workerless/Seatbelt/weak fallback; probe failure is exact pre-admission `UNSUPPORTED_PLATFORM|UNSUPPORTED_EXECUTION_IDENTITY`.
- [ ] Admission accepts `RunPolicySnapshotV1.engine` only when `engine.profileEntryId` and `engine.version` select the sole signed non-executable RuntimeBundle `policy_engine` data entry, the signed complete-file `entry.digest` equals `engine.profileRef`, and decoding those exact bytes independently yields self-omitting `PolicyEngineProfileV1.profileDigest===engine.profileDigest`. The complete-byte ref and semantic digest are distinct hash domains and are never equated. Fixed signed Supervisor code is the only evaluator; policy helper spawn, dynamic/native plugin load, executable profile, semantic-version substitution, or policy SandboxLaunch is rejected before Run creation.
- [ ] Every mutator commits its deterministic response artifact and `(principalId, method, requestId, requestDigest)` `control_requests` row with the final state change. Same bytes replay that response after revision drift; different bytes return `REQUEST_ID_CONFLICT` without rerunning. Before a response, only exact MCP `admin_operations` and one exact local activation-cycle `run_submission` participant may persist; cross-cycle lookup makes replay return the same cycle/result even when another request created it. Launch rows contain no request identity. Read methods and `session.handoff.create` reject `requestId`.
- [ ] Submit success is emitted only after RunSpec, context/base manifests, artifacts, initial ready Checkpoint, queued Run row, and Supervisor admission ownership are durable. A local-model submit additionally requires the exact active service/boundary closure before Run assembly/admission; an in-flight activation has no Run or success response. Pathless `run.apply` descriptor-reopens the live source Session and publishes exact `SourceManifest A` plus distinct recovery `WorkspaceStateManifest W_A`: RunSpec base and `delivery:merge.capturedWorkspaceRef` equal `A`, `W_A.baseWorkspaceManifestRef=A`, Checkpoint `workspaceStateRef=W_A`, and all workspace/repository refs/digests equal the Session. Storage recomputes entry count/checked bytes/tree digest, SourceManifest entry/tree/omission digest and live repository XOR, plus WorkspaceState independent entry/base/projection/private-Git/invalidated-path/omission digest equations. Passing `A` directly as workspace state, accepting a caller path/legacy-unavailable/root-or-`.git` replacement, cross-identity/projection/digest mismatch, self-referential digest rule, or `delivery:capture` is rejected.
- [ ] Killing the CLI/TUI/stdio RPC immediately after submit acknowledgement does not cancel or lose the Run; reconnecting can list and attach to it.
- [ ] Closing stdio input/output no longer invokes durable Run cancellation. Only explicit `run.cancel` or the validated parent-cancellation cascade changes `cancelRequested`; transport state and display events never do.
- [ ] Queue order is durable FIFO by `(createdAt, id)`, concurrency is bounded, and a full queue rejects before acknowledgement. Pre-dispatch scarcity leaves a Run queued/ineligible with no attempt or wait artifact; `waiting(resource)`, resource subjects, resource wake reducers, and resource client commands do not exist.
- [ ] Before process/VM creation, the exact immutable workspace-generation identity has an authoritative `workspace_generations` row already materialized to `preactivated_readonly` with exact snapshot evidence, and one unretired `worker_launches` row selects it. The blocked worker has zero broker/sandbox/generation-write/network/provider/MCP/credential/child authority; only one transaction that activates generation+launch+Run pointer/epoch followed by the exact single-use capability makes it productive.
- [ ] Supervisor orchestration creates no worker/invocation/admin/local-service containment until work package 3 validates exact owner-specific `SandboxLaunchSpecV1`. Worker launch matches the reserved row, fixed blocked-entrypoint process recipe, and preactivated-read-only generation; invocation launch matches the current claim/grant/parent containment and purpose-specific process recipe; admin launch matches exact `AdminOperation`, target/static `probePayloadCoreRef` process recipe, and isolated root, while its post-containment BrokerRequest/dispatch fields remain absent until claim; local service matches exact owner/service launch/spec, signed `local_inference` executable/model, fixed entrypoint, isolated root, and no-egress loopback envelope. No orchestration path may pass out-of-band argv, cwd, stdio/fd, payload, or adapter IPC. Any cross-owner field, process/runtime/executable/env/mount/resource/profile/plan drift, or forbidden authority fails before process/VM/I/O.
- [ ] Crash/CAS/handshake tests cover launch phase `reserved -> preactivated -> activated -> retired`, worker-loss `activated -> reconciling -> retired`, authoritative generation success `materializing -> preactivated_readonly -> active -> revoking -> checkpointing -> sealed -> retired`, and mandatory worker-loss `active|revoking|checkpointing -> fenced_reconciling -> quarantined -> retired` plus every permitted reason/from-phase quarantine edge. Direct phase skips fail. No boundary produces an untracked productive worker; no row is replaced until exact wait/containment/quarantine/retirement evidence is durable.
- [ ] The Run stores only monotonic `leaseEpoch` plus optional `activeWorkerLaunchId`; activated `worker_launches` stores versioned worker identity, immutable generation ref, containment, `leaseExpiresAt`, and `leaseVersion`, while exact `workspace_generations` is the sole mutable generation authority and the launch write state is its same-transaction projection. A 5-second heartbeat narrow-CASes only the exact still-active launch after rechecking the authoritative active generation, without changing either generation or Run revision/`updatedAt`/item/Event; it cannot reopen a revoked gate, while activation/retirement atomically change the Run pointer/revision and required generation state.
- [ ] Lease expiry fences dispatch but does not silently clear `activeWorkerLaunchId` or queue the Run. Every worker-loss recovery uses one revisioned transaction to clear the pointer, install exact `worker_death`, move the sole launch to `reconciling/fenced_reconciling`, and move the generation from its exact current pointer-bound phase to `fenced_reconciling`; every workflow ownership change emits exactly one revision/event.
- [ ] A new Supervisor instance never reconnects to, adopts, renews, or completes activation for an older worker, even with an unexpired lease. It fences old channels and enters the same exact fenced wait before using any immediately available death evidence. Exact recovery then quarantines the old generation for both dispositions and retires its authority; only restoration additionally uses a fresh launch/epoch against a distinct preactivated identity. Uncertain death remains `waiting(reconciliation)` with old generation/launch fenced and no replacement.
- [ ] `local_inference_activation_cycles` is the sole service-start singleflight/fanout authority. Its exact participant union binds retained submission bytes or one exact queued Run revision/frontier; participants are append-only/ordered/unique and capped at 128, with participant 129 returning `RESOURCE_EXHAUSTED(resourceKind='local_inference_activation_cycle')` without mutation/I/O. Cycle ids/ordinals are deterministic/contiguous, only one cycle is nonterminal per owner/service, the exact phase/attempt/launch-cardinality and retry/failure/boundary XORs hold, and every mutation recomputes `cycleDigest`. Same request bytes replay the retained cycle/result; changed bytes conflict; a moved/stopped Run participant cannot affect a newer frontier.
- [ ] `local_inference_launches` is the sole managed local-process authority. Each row binds exact `activationCycleId` and `activationAttempt: 1|2`; cycle-owned attempts are contiguous/capped at two, each has a fixed 120-second deadline, and attempt 2 requires exact positive attempt-1 retirement plus `retryNotBeforeAt=retiredAt+1s`. Its row graph includes `reserved -> preactivated -> active -> revoking -> retired`, `reserved -> retired(no_spawn)`, and `preactivated -> retired(death)`; preactivation accepts no model traffic, activation requires exact boundary evidence, and heartbeat changes only launch-row lease fields. `retirementKind='no_spawn'` is reserved-only with exact no-spawn evidence and no process/boundary/quiesce fields; `retirementKind='death'` from preactivated or revoking requires exact containment/quiesce/death evidence and boundary evidence if and only if active. A positive attempt-1 retirement must enter retry wait and forbids terminal failure; only an unprovable attempt-1 containment may terminal-fail as exact `containment_unresolved` with the launch retained. Attempt-2 failure is terminal only after positive retirement or as unresolved containment. Startup adopts nothing and permits no successor outside the owning cycle.
- [ ] The trusted local-service producer recomputes the full semantic `serviceSpecCoreDigest`, derives `serviceId` from owner/provider/model/core, and then recomputes `serviceSpecDigest`; changed endpoint/backend/resources/runtime/executable/model/profile semantics cannot reuse a service id. Final cycle failure validates exact `LocalInferenceActivationFailureV1` and atomically returns the same replayable `RECOVERY_REQUIRED(recoveryKind='local_inference_service')` to every submission without Runs while proposing exact `runtime/local_inference_unavailable` StopIntent for every still-matching existing Run. Success atomically admits/responds to submissions and makes still-matching queued frontiers eligible without revision change. Crash, replay, disconnect, or concurrent participants cannot split fanout or mint attempt 3.
- [ ] A local-service replacement preserves the exact `LocalZeroCostProvenanceV1.stableServiceIdentityDigest` projection but mints fresh launch/containment/plan/SandboxLaunch/inspector/observation identities. Each local model release requires the one active live row plus current dynamic boundary/capability evidence; a stale/ambient loopback endpoint reaches no provider. A shared cycle/launch never blocks an otherwise quiescent Run terminal commit; cancellation makes its Run-frontier participant obsolete.
- [ ] A process-spawning `prepared` row forbids `sandboxLaunchSpecRef`. `claimDispatch` chooses the permanent `dispatchId`, artifact-first publishes the exact `run_invocation` spec, and atomically validates the Run pointer, exact activated launch, matching authoritative workspace-generation row `active`, identical Run/generation/launch/epoch, live lease, stop/cancel/deadline/frontier/attempt/reservation predicates, full exact `OperationGrantV1` subject/provenance/use/expiry identity, and launch owner/parent/plan/process closure before binding that ref only to `dispatch_claimed`. Every later phase repeats it; non-spawning operations forbid it throughout. Policy snapshots, authorization rows, approval payloads, templates, and opaque refs are rejected as grants. `releaseClaimedDispatch` repeats every live check including the authoritative generation, exact grant, and bound launch-spec closure for that `dispatchId` immediately before target I/O; failure produces no target call. Every post-I/O fact uses `assertEvidenceAuthority`; current typed evidence may settle/advance once, while superseded evidence is audit/billing-only.
- [ ] Two concurrent requests for one prepared attempt create one durable `dispatch_claimed` fact and one target invocation. The claim remains permanent through initial outcome and any later unknown resolution; disconnect, timeout, lease loss, worker death, or Supervisor restart never redispatches that attempt number.
- [ ] Every actual `ProcessContainment`, `ProcessContainmentNoSpawnEvidenceV1`, and `ProcessContainmentDeathEvidenceV1` repeats the exact owner-specific `sandboxLaunchSpecRef` and recomputed digest. Worker/AdminOperation/local-service preactivation rows bind their specs before spawn; Run Journal binds its invocation spec only at claim. Owner/plan/nonce/backend/spec substitution cannot activate, dispatch, retire, checkpoint, publish, or enable replacement.
- [ ] Every prepared admin row carries exact target/core/plan/spec ref+digest pairs. Embedded dispatch moves only blocked->claimed->released; both gates validate exact operation/request/target/core/containment/Supervisor/lease/deadline/endpoint and BrokerRequest repeats target/payload digests. Exact result/closure/error artifacts and all plan/spec/terminal/control pairs revalidate; only canonical deterministic/recovery dispositions commit. No Run identity or byte release crosses a failed gate.
- [ ] Linux takeover proves the exact cgroup v2 subtree empty and namespace init/subreaper dead; macOS proves the exact VM stopped and guest identity retired. Before either positive or indeterminate outcome is applied, canonical `reconciliation.subject.kind='worker_death'` clears the Run pointer and binds the old launch/generation as `reconciling/fenced_reconciling`; no replacement starts. Positive evidence validates the exact WorkerRecovery disposition XOR, and both branches wrap it in exact generation-quarantine evidence for the old row. Restore additionally requires the third mandatory distinct replacement-generation ref already proven preactivated from the same ready Checkpoint before old-generation retirement.
- [ ] Every `waitingOnRef` exactly validates the canonical Approval/Input/Child/Reconciliation union, including `createdAt`, input item/batch/call identity, child `await_tool` batch/call/index, `finalize_settlement` model-turn identity, optional stopped-await origin, exact MCP-reconcile versus manual invocation union, publication-path/worker-death identities (including `oldWorkerLaunchId`), and exact `ReconciliationProbeStateV1` XOR. No generic clear-wait/status API or legacy effect/workspace/containment shape exists.
- [ ] Reconciliation CAS enforces `manual_only|automatic_pending|automatic_in_flight|automatic_exhausted|user_in_flight` exactly: automatic count is capped at eight; count-zero pending forbids last evidence; count-1..7 pending and count-8 exhausted require the exact pair; only due pending increments; every in-flight state embeds one digest-valid `ReconciliationProbeDispatchV1` with exact subject digest, kind/count/ordinal/nonce/30-second deadline/current Supervisor and broker-or-task identity before I/O; and the seven backoffs are fixed. At automatic exhaustion, idempotent `probe_now` atomically increments positive-safe `userProbeCount`, persists one user dispatch with exact public `controlRequestId/controlRequestDigest`, and commits the canonical `probe_enqueued` result/post-enqueue snapshot plus `control_requests` before any probe I/O. Completion is later internal progress and emits no second response; exact-risk abandonment uses only the separate synchronous `abandoned` result. Before exhaustion/manual, probe is `INVALID_REQUEST`. Duplicate timer, response, crash resume, or request replay cannot double-query/increment/advance, reset automatic count, create probe nine, substitute an in-memory dispatch, or create a third pre-response fence.
- [ ] Model completion decodes exact `AgentModelTurn`, required `ModelTextV1`, and ordered `ToolCallInputV1` plus `ObservedToolCallInputV1` artifacts before item publication. `ModelTurnItem.textRef` and any `ToolBatchItem.textRef` equal the turn; batch calls equal its complete ordered call-input identities byte-for-byte. Text/observation/input omission digests, bounded byte counts, retained valid-JSON or malformed-UTF-8 observation, disposition/schema/value/diagnostic XOR, op/attempt, and stop/abort matrix validate. `end` is nonempty call-free text, `tool_calls` is one-or-more complete resolved/rejected calls, unusable stops have no executable call, and only authenticated pre-abort cancellation carries the current StopIntent. Every positively received provider rejection completes as exact fully charged nonretried `ModelUnusableResponseV1(provider_rejected_response)`; it cannot become failed or change the exact three-attempt/zero-hidden-retry/`[500,2000]` schedule through `Retry-After`. Only final literal `transport_exhausted` may authorize `model_attempts_exhausted`. An all-resolved batch alone installs `tool`; any identity-valid rejected batch uses one `commitRejectedModelToolBatch` transaction to append the whole batch, every input-error and `batch_not_executed` result, and the next `agent` frontier with zero grant/Journal/dispatch. Missing/duplicate call identities or any other mismatch settles as charged `MODEL_PROTOCOL_ERROR` without batch/candidate.
- [ ] Normal prompt production revalidates the exact immutable assembly instruction closure before Journal prepare: mandatory all-and-only root-to-deep workspace `AGENTS.md` entries, exact labeled workspace JCS, exact source-identity-backed nonempty skill instruction JCS in assembly order, empty-piece omission, and two-LF join. Every workspace/user/bundled source equation, ref/digest, bound, source-manifest/workspace identity, descriptor containment, and signed bundle closure matches work package 1. `ContextManifest` names only `assemblyRef`; recovery produces byte-identical prompt bytes without rereading mutable paths. Tests reject late target-subset selection, duplicate unqualified skills, missing/extra/reordered files, links/escapes, mutable resource substitution, executable inclusion, dynamic load, and adapter-added instruction bytes before reservation or claim.
- [ ] Every ordinary ToolResult producer publishes exact identity/outcome-matched `ToolResultModelContentV1` plus `ToolResultPayloadV1` before the item transaction. Executed Journal/result/output-schema, policy-or-user denial, closed-code diagnostic plus all-or-none dispatched-error fields, complete unique byte-sorted batch-invalid ids, and ordinary StopIntent/notice cancellation branches validate. Model content is bounded, identity/outcome matched, and exactly the normalized executed output or closed ref-free synthetic projection; approval/input/reconciliation/child/tool paths cannot serialize the audit payload, authority refs, arbitrary text, or an untyped result into context. The sole exception is terminal fenced `retry` unknown: its result ref directly names exact `RetryUnknownCancelledResult` with matching settlement/dispatch closure, has no model-content projection, and is never wrapped in the ordinary payload union.
- [ ] Direct policy `allow|deny` never enters `waiting(approval)`. One transaction writes exact `PolicyDecisionItem(decisionSource='direct_policy')`, requires `decisionRef===policyChannelEvidenceRef`, and commits exact grant XOR subject-matched `PolicyDenialOutcomeV1`. Tool/MCP denial emits the identity-matched denied result; required verifier emits exact `policy_deny/verification_failed`; advisory verifier emits `VerifierSkipItem(skipped_by_policy)` with the same evidence digest; delivery/dependency scripts emit exact `policy_deny/runtime_failed`. No ApprovalDecision, phantom wait, grant-on-deny, denial-on-allow, cross-subject outcome, or model-visible authority bytes are accepted.
- [ ] `run.approve` publishes exact `ApprovalDecisionV1`, validates principal/Run/current wait/frontier/subject/request/revision plus all decision/wait/subject omission digests and TTL/grant-expiry XOR, and requires the subject's exact `PolicyChannelEvidenceV1` pair to rehash, match policy/frontier/op/request/target/action, and carry `effectiveDisposition='ask'`. It then atomically commits that decision, exact `PolicyDecisionItem(decisionSource='interactive_approval',waitingSubjectRef=current wait)`, subject result, grant XOR subject-matched `PolicyDenialOutcomeV1`, frontier/StopIntent progress, event, response, and replay row. Allow forbids denial outcome, preserves the exact unresolved frontier, and mints only subject-matched `OperationGrantV1`; its `user_approval` provenance repeats the same channel-evidence pair, its `decisionRef` decodes to that exact allow decision and equal grant expiry, while verifier-template provenance decodes instead to the exact template-producing `AuthorizationConsumptionReceiptV1`. MCP-server allow binds exact registration/lifecycle/batch/call/index and only a fresh call-scoped instance. Deny forbids grant and preserves the same evidence pair: tool and MCP-server produce the identity-matched denied result; required verifier proposes user cancellation without receipt; advisory verifier records `VerifierSkipItem(skipped_by_user)` with no policy evidence digest and advances; delivery denial cancels only the delivery Run without ToolResult or real-workspace change; dependency-install-script allow requires exact `DependencyInstallScriptsAuthorizationTemplateV1` and mints one unused-ordinal template-provenance grant, while deny records policy failure and produces neither package execution nor readiness. Reparse, parser substitution, policy-text substitution, phantom direct-policy wait, or cross-subject outcome commits nothing.
- [ ] `run.input` resolves only the exact current built-in request. `InputRequestItem`/`InputPromptV1`/prompt text/optional `InputResponseSchemaV1`, public kind, authenticated principal, and `UserInputPayloadV1` bounds/digests all match Run/batch/call/index. Payload/item repeat one exact ref-free `UserInputModelContentV1` whose kind/value equal the normalized input; one replay-safe transaction appends exact `UserInputItem` plus executed audit payload and ToolResult model content with that same value, then preserves the next tool call or installs agent cause `input`. Authority/audit refs in model content, any mismatch, or partial publication commits nothing; replay cannot duplicate it. Child admission atomically appends one exact `ChildHandleItem` with parent/batch/call/index/op/child/spec/mode equal to its allocation and deterministic admission identity; no duplicate or independent handle append exists. `await_tool` settles/merges only its exact batch/call/index; `finalize_settlement` settles the exact direct-child set, excludes the premature model final from candidacy/context, performs separately claimed serial merges when required, and returns to `child_results`; `stop_settlement` performs no productive merge and uses optional await origin only for exact cancelled closure. Every allocation row validates exact `ChildAllocationV1` and its exact `ChildResultModelContentV1`: success result equals child RunResult, failed/cancelled detail equals child terminal detail, mutating success patch exactly projects child base/result/diff, allocation/item terminal bytes match, and only ref-free success-summary or stopped status/reason content reaches the model. State XORs, inclusive usage, parent settlement revision, and released-unused equation all validate. A running parent's child terminal changes only the allocation row, never parent revision/event; a lease-free exact subject may settle and revise/wake or stop the parent once.
- [ ] Reconciliation invocation is either exact MCP `recovery='mcp_reconcile'` with full registry/profile/status-template/predicate closure or exact `recovery='manual'` for `tool|mcp`; other op kinds/recovery classes are structurally rejected. Every automatic/user completion publishes exact `ReconciliationProbeEvidenceV1` matching wait digest, current persisted dispatch digest and all kind/ordinal/nonce/start/deadline/Supervisor fields, plus current inspector. `subject_observation` wraps only exact subject-valid `McpRecoveryProbeEvidenceV1|PublicationProofV1|WorkerRecoveryEvidenceV1`; MCP repeats the dispatch/broker identities, completed/failed predicates advance exactly once, publication/worker proofs satisfy their exact reducers, and unresolved stores only the wrapper pair. `probe_timeout` is legal only after the deadline with exact subject-matched `ReconciliationProbeTimeoutClosureV1`: MCP revokes and drains the persisted broker dispatch/target/fence, while publication/worker repeat the persisted task/target and prove either same-owner cancellation-and-join or successor acquisition after owner death through exact `ReconciliationInspectorTaskClosureV1`. Timeout never asserts an effect outcome and follows unresolved backoff. Late closed-nonce evidence is audit-only. Current wrapped positive evidence may replace/advance; superseded evidence cannot. `abandon_run` is legal only for the exact current manual unknown and authenticated risk acknowledgement; exact `ManualAbandonAttestationV1` must match principal/channel/request/wait/frontier/Journal/request/target and repeat the unknown row's exact `InvocationAmbiguityEvidenceV1` pair byte-for-byte. Its identical attestation ref atomically reaches Journal `abandoned`, Stop/Terminal closure, and any call-origin `ToolAbandonedItem`; the abandoned row forbids its own evidence pair, and no newer display/probe evidence, result, ToolResult, retry, or batch continuation is substituted. It is invalid for every inspectable subject, which remains actionable only through exhausted-state `probe_now`.
- [ ] Worker-death reconciliation validates exact `WorkerRecoveryEvidenceBaseV1` plus the closed disposition only against the installed `fenced_reconciling` generation/wait/launch. Both dispositions require exact worker-recovery quarantine evidence and atomically quarantine the old row before retirement; `quarantined` forbids checkpoint/state/replacement. `restored_from_checkpoint` additionally requires all three restore fields, including a distinct exact replacement generation whose authoritative row/snapshot prove `preactivated_readonly` from the named ready same-Run Checkpoint. Missing replacement, reused old identity, inferred/direct quarantine, stale generation phase, or launch/generation projection mismatch cannot queue or terminalize the Run.
- [ ] Every subject reducer normally performs one lease-free `waiting -> queued`, but a winning StopIntent instead runs terminal-quiescence and never queues productive work. Remaining proof atomically replaces the subject; no reducer jumps to `running`.
- [ ] StopIntent accepts exactly verifier-source and dependency-acquisition kernel-integrity, user/parent cancel, wall-deadline, additive-budget, verification, direct policy deny, ordinary runtime, and manual-abandon variants and applies the frozen reason precedence with every kernel-integrity intent highest. `StopIntentBase` has no generic evidence ref. Integrity branches carry exact `integrityEvidenceRef`/digest and validate the complete subject/observation XOR. Direct `policy_deny` carries exact op/evidence plus verifier XOR delivery/dependency subject, maps to `verification_failed|runtime_failed`, and is produced only by the no-wait direct deny reducer. Runtime subtype `local_inference_unavailable` is legal only from exact failed-cycle fanout and repeats its failure ref. Ordinary `runtimeSubtype='runtime'` requires identical StopIntent/TerminalReasonDetail `failingOpId` and exact `runtimeFailureRef/runtimeFailureDigest`; storage recomputes `RuntimeFailureEvidenceV1`, current-inspector freshness, and the branch-specific Journal/request/credential/dependency/retry/local-service closure. Terminal primary evidence is exactly integrity ref, parent source-stop ref, local failure ref, direct-policy channel-evidence ref, generic runtime-failure ref, manual attestation ref, or otherwise the immutable winning StopIntent ref; reason detail copies the same branch fields/ref. `origin='budget'` proves its counter equation while wall expiry uses only `origin='deadline'`; lower/equal later facts cannot replace truth, `cancelRequested` is only a monotonic dispatch fence, and terminal status/reason/detail come solely from the winning intent at quiescence.
- [ ] Recovery and GC retain each exact direct/interactive `PolicyDecisionItem`, its channel evidence, approval wait/decision only for interactive source, exact allow grant XOR `PolicyDenialOutcomeV1`, and the denial's ToolResult, StopIntent, or `VerifierSkipItem`. `skipped_by_policy` repeats channel-evidence decision ref/digest; `skipped_by_user` repeats the approval decision and forbids the digest. Broken source/outcome/subject/evidence edges fail recovery and are never pruned.
- [ ] A grant expiring before `prepared` returns to approval without reservation; expiry after `prepared` but before claim records the exact pre-dispatch failed branch with no claim/spec/evidence, zero consumed settlement, reservation release, and a fresh approval subject; expiry after claim but before release yields positive no-target closure and requires explicit same-op retry authority; expiry after successful release cannot rewrite the started outcome. Stdio MCP lifecycle expiry/`maxLaunches` exhaustion creates the exact batch/index-bound approval, and every allowed instance is fresh/call-scoped and death-proven after its one call.
- [ ] Supervisor restart/reboot first establishes exact state-owner authority through only genesis, latest-graceful clean acquisition, or same-transaction death takeover with complete process/root/lock/acquisition/transition closure; only then does it reconcile nonterminal local activation cycles and their cycle-linked/unretired service launches, nonterminal admin rows, and Runs. Run recovery uses complete RunSpec+Run+Checkpoint+post-cursor items/Journal+Run-owned-worker-launch+exact-child-allocation+artifact closure, including exact AgentModelTurn/model-text/ordered observed+resolved-or-rejected tool input/ordinary audit-payload+model-content result or dedicated retry-unknown closure, exact workspace-instruction and ordered skill source/manifest/instruction/resource closure, every unknown row's exact `InvocationAmbiguityEvidenceV1` and branch-transitive owner/broker/sandbox/publication proof, policy, approval decisions, operation grants, authorization/receipt, dependency template, budget settlements, dispatch-closure evidence, manual attestations, verification/inherited provenance, complete MCP registry-transitive graph, exact `ReconciliationProbeStateV1` plus every retained `ReconciliationProbeEvidenceV1` and its subject-valid evidence or `ReconciliationProbeTimeoutClosureV1`, and all owner-specific SandboxLaunch/containment/inspector identity/evidence refs, not control responses/events. The normal system message reprojects byte-identically from the assembly closure alone; recovery never rereads mutable instruction/skill paths or accepts duplicated ContextManifest ref lists. A manual abandoned row's attestation repeats its unknown ambiguity pair and cannot replace it with later evidence. A `local_zero_cost` Run closure includes exact stable provenance, its cycle participant/failure when present, current/nonterminal cycles, cycle-linked launches, and boundary/model/capability closure. Recovery preserves item text/observation/input/audit-payload/model-content identity/outcome equality, rejected-batch atomic closure, probe phase/count/nonce/deadline/wrapper/closure XOR, participant order, cycle ordinal, attempt prefix, retry time, and atomic fanout; it fails `RECOVERY_REQUIRED` on widened/broken types, never adopts an old process, preserves typed waits/StopIntent, and resumes only an unstopped Run from a ready Checkpoint after old death/quarantine through a fresh generation/launch/activation.
- [ ] After any StopIntent, only bounded no-new-effect death/query/quarantine/rollback/child-settlement/publication-inspection/terminal operations, cleanup on an existing publication claim, and work package 3's zero-reservation/no-worker receipt-proven empty-directory abort claim may run. Productive retry, model/tool/MCP/verifier, a new semantic publication envelope, desired-path mutation, and new authority remain forbidden.
- [ ] `run.cancel` is control-request replay-safe: it proposes the typed StopIntent, fences productive work, revokes launch rows and retires them only after proof, closes undispatched typed continuations, settles/preserves claimed invocations by authenticated evidence, cascades to direct children, and converges across restart.
- [ ] Every Journal row carries a required complete four-counter `BudgetUsage`: prepared is the reservation; claim and abandoned are explicit zero; every evidence ref has its digest or both are absent. `failed` is exact pre-dispatch XOR post-claim. Pre-dispatch has no claim/spec/evidence/receipt, consumes zero through exact `BudgetSettlementV1`, releases the reservation, and does not consume dispatched retry capacity. Post-claim repeats the claim/spec and accepts only exact `PostClaimNoReleaseEvidenceV1`, or for a verifier exact `infra_failed` receipt plus exact containment-death closure. The no-release evidence binds same live owner/current inspector and proves broker-token revoke+zero release under mutex or exact SandboxLaunch no-spawn before authority release; it alone consumes zero. Verifier infrastructure consumes exact attempt usage. Every other claimed no-result state is `unknown`, while typed target errors are `completed`. Every `unknown` row repeats a claim, requires exact settlement, and carries one exact `InvocationAmbiguityEvidenceV1` pair matching the sole owner-loss/broker-channel/sandbox-channel/publication-path mechanism; unknown consumes its reservation and later evidence cannot refund/double-charge. Abandoned forbids a new evidence pair and its attestation repeats the unknown pair. Every released/possibly-released post-claim model outcome consumes the exact request-digest-bound six-field normal-or-compaction reservation in full, and literal `usageTrusted=false` telemetry cannot reduce/refund it. Claim stores `brokerFenceTokenDigest` iff broker/no-child and forbids it otherwise. A terminally unused `retry` unknown additionally requires matching `InvocationDispatchClosureEvidenceV1`: containment branch repeats exact containment/death ref+digests, while broker branch repeats exact `BrokerReleaseFenceEvidenceV1` bound to request/target/grant/claim/owner/current-inspector/newer epoch/stored token and positive revoked-plus-zero-release observation. Its cancelled item's result ref directly decodes exact `RetryUnknownCancelledResult`, and that artifact plus TerminalDetail repeat settlement/closure refs; no `ToolResultPayloadV1` wrapper, inline boolean, lease/socket/worker/Supervisor drift is sufficient.
- [ ] Terminal stop commit is impossible while a Run-owned WorkerLaunch/invocation containment is unproven, an invocation needs reconciliation/rollback, a child allocation is outstanding, a typed call is unclosed (neither the exact `ToolResultItem` nor the terminal-only `ToolAbandonedItem` closure exists), a publication path is unresolved, an active worker pointer remains, or any `budgetReserved` counter is nonzero. A shared local activation cycle/service launch is never a Run terminal dependency; only an open model invocation against it must settle, and terminalization makes the Run participant obsolete. `TerminalDetail.primaryEvidenceRef` follows the exact branch-specific matrix and uses the winning StopIntent ref only for branches without a separate authoritative evidence ref. Its delivery projection ref is allowed only for a post-forward-claim delivery stop with exact completed abort projection and is forbidden for agent/merge-conflict/approval-deny/pre-first-claim/incomplete-abort paths. Retry entries repeat exact settlement/dispatch-closure refs and the manual entry repeats the exact attestation ref; only exact publication/manual/retry closure fields exist. Candidate/diagnostic/verifier-receipt/child-result lists are rejected. Ambiguity remains the exact typed wait under the winning StopIntent.
- [ ] Success terminal routing calls only `commitRunResult`, requires the finalize frontier and RunResult to name the identical exact `VerificationClosureV1`, and revalidates its full candidate/source/dependency/required-advisory/Journal/receipt/consent closure. `inherited_verified` additionally requires the same exact `InheritedVerificationProvenanceV1` in closure/result and re-walks its immutable source verified result, required closure, identical result source/verifier spec, and ordered receipts/digests. Agent finalize/result forbid `deliveryTerminalProjectionEvidenceRef`; delivery finalize/result require the identical exact forward-finalize evidence and revalidate its complete plan/source/path/result/projection/descriptor closure. No alternate receipt/provenance/projection list, generic terminal setter, or schema-valid but storage-inconsistent closure can produce `succeeded|completed_unverified`.
- [ ] Absolute Run deadlines continue through wait/detach/reboot, cap dispatched timeouts, propose `deadline/failed/budget_exhausted`, and invoke the same closure. Additive ceiling overflow proposes `budget/failed/budget_exhausted` with frozen counter evidence before new work. Either stop forbids activation/dispatch/child/grant work; unresolved invocation/worker-death/child/publication ambiguity blocks terminalization and never becomes verifier infrastructure failure.
- [ ] The exact Session surface uses requestId/requestDigest replay for create/fork/compact; list defaults 50/max100, get defaults 100/max1000 with <=1 MiB metadata, compact is <=256 KiB and raw-preserving, and `artifact.get` chunks are <=4 MiB. Handoff is deterministic/read-only: cursor is omitted/current cut or zero/exact segment end, exact `SessionHandoffV1` entries/excluded ranges/workspace/projection/digest validate from one snapshot, fixed JSON/Markdown bytes rehash to the two canonical descriptors, and identical inputs return identical refs. The same frozen surface includes `authorization.create|list|revoke` and `mcp.register|refresh|list`; only their mutators use `control_requests`. `authorization.revoke` returns canonical revoked/already-revoked behavior, while a consumed grant is an `already_consumed` success no-op that preserves exact consumed row/receipt/derived authority. No Session or registry method owns Run execution state.
- [ ] All four list handlers delegate to the exact storage-owned `ListReadCutV1` protocol. The first call materializes owner/filter/limit-bound typed summaries and stable `(createdAt,id)` ordinals in one StateOwner-gated transaction; subsequent calls accept only the exact domain-separated HMAC cursor for the retained 15-minute cut. Repeated pages are byte-identical across restart, mutation after page one cannot change membership/order/values, and next cursor is absent exactly at empty/end. Equal timestamps, concurrent inserts/status changes/MCP refresh, all filters, changed principal/method/filter/limit, forged/malformed/unissued/future/end/expired cursors, capacity refusal, and cut expiry/GC have cross-adapter golden fixtures.
- [ ] Every handler emits only exact `ControlApplicationResponseV1` with one canonical method-discriminated `ControlResultV1` or closed `ControlErrorV1`; the stored mutator response is those exact bytes. UDS JSON-RPC, CLI, TUI, JSONL, and stdio RPC keep correlation/framing outside the application object and cannot add adapter-local results, cursors, summaries, redactions, fields, or error envelopes.
- [ ] Rollback retains exact `RollbackToLegacyRequestV1`, reuses the active owner token, and continuously holds Kernel global/state-owner -> local-model registry/object-store -> legacy auth-store -> byte-sorted legacy-state -> credential-authority. It gates control/broker/credential release and refuses nonterminal Runs before `rollback_draining`. Every public/internal authority path checks the fence. Every admin/cycle is terminal, all four containment owners are no-spawn/death-proven, worker/admin/local rows are retired, invocation claims are evidence-closed, and broker/Supervisor/credential release is quiescent before `rollback_restoring`. Exact auth outcome and request boolean govern secret rendering. The final owner transaction is graceful terminalization; only prepared legacy-root-first/state-root-last marker publication follows. A pre-marker successor performs only clean fenced replay then gracefully terminalizes; a durable state-root legacy marker forbids owner acquisition and all Kernel mutation. Unknown or incomplete proof blocks with locks/fence intact.
- [ ] `run_events` assigns monotonic per-Run `eventSeq`; each `run.attach` captures Run snapshot/retained bounds/high-water in one transaction and returns only the next bounded page through that cut. `max(0,earliestRetainedEventSeq-1)` is the earliest valid cursor: zero/earliest-minus-one are valid, smaller is `EVENT_CURSOR_EXPIRED`, above high-water is `INVALID_REQUEST`, and equal high-water is an empty page with the same cursor. While `nextEventSeq < highWaterEventSeq`, clients continue with that cursor; equality ends that cut, and a later attach captures later commits. Terminal retention keeps at least the terminal event anchor. Golden protocol tests prove these bounds, repeated-cursor determinism, concurrent-commit next-call behavior, and absence of any push/subscription/follow envelope.
- [ ] `run.result|run.diff` succeeds only for `succeeded|completed_unverified`. Queued/running/waiting returns exact retryable `RESULT_UNAVAILABLE` with current revision; failed/cancelled returns exact nonretryable `RESULT_UNAVAILABLE` with terminal detail. `RESOURCE_EXHAUSTED` preserves the exact `local_inference_activation_cycle` resource kind.
- [ ] An expired cursor returns explicit bounds plus the current authoritative snapshot. Event pruning never changes recovery or verification outcome.
- [ ] There is no `run.delete` or automatic authoritative Run/Session/result/receipt/Journal/control-request/worker-launch/local-inference-cycle/local-inference-launch/child-allocation/state-owner deletion; event pruning affects only terminal display rows after retention and records the earliest cursor. GC roots every retained model turn/text, ordered input observation/resolution/schema/diagnostic, ordinary audit payload/model content/branch closure, every `InvocationAmbiguityEvidenceV1` plus exact owner-takeover/broker-token/SandboxLaunch/containment/death/publication-proof branch, dedicated fenced retry-unknown result/settlement/dispatch closure, approval/manual/settlement/dispatch-closure/inherited-provenance/source-verification artifact, complete instruction/skill declarative-context closure, complete MCP registry-transitive recovery graph, reconciliation state plus MCP/publication/worker evidence closure, activation participant request/frontier/failure, state-owner process/root/lock/transition/inspector/bundle identity, and launch/spec/service/model/provenance/boundary/containment/evidence edge and deletes nothing on incomplete decoding.
- [ ] Diff/result methods return refs and `artifact.get` streams verified bounded chunks below the frame cap with stable offsets, cancellation, and no filesystem-path exposure.
- [ ] CLI, TUI, JSONL, and stdio RPC observe the same Session/Run ids, status, typed waiting subject, result references, and cursor semantics through the one frozen method surface.
- [ ] Local p95 attach latency is below one second under the release fixture load.
- [ ] Recovery scheduling begins within five seconds of Supervisor startup.
- [ ] Forced crashes at admission, acknowledgement, every preactivation/lease boundary, heartbeat, containment shutdown, dispatch claim/result, wait-subject replacement, grant expiry, cancellation cascade, Checkpoint restore, event append, and terminal commit produce zero silently lost accepted Runs and zero duplicate productive attempts.
- [ ] The Supervisor contains no DAG, priority, role, distributed-worker, HTTP, cloud, or plugin scheduler path.

### Validation

Automated:

- `npm run build`
- `npm test`
- `npm run test:e2e` (added for service/client, UDS, CLI/TUI/JSONL/RPC, cursor, and reboot/restart scenarios)
- `npm run test:fault` (admission/approval-decision/authorization-receipt/template/control-response loss, exact instruction-source/skill-source-to-prompt publication and immutable recovery closure, exact model-text/tool-input/model-turn/batch/result-payload publication and branch closure, all four invocation-ambiguity publication-to-unknown edges and abandoned-attestation pair preservation, direct fenced-retry-unknown result closure, exact four-owner `SandboxLaunchSpecV1` owner/forbidden-field mismatch at every pre-create boundary, every worker-launch/write-gate/activation phase, local-service cycle create/request and Run-frontier participant join/cross-cycle replay/bound-129 rejection/attempt-1 and attempt-2 reserve/preactivate/activate/lease/revoke/no-spawn-or-death retirement/retry-wait/one-second gate/failure artifact/atomic fanout and stable replacement, unexpired-old-process Supervisor takeover with no adoption, lease expiry, Supervisor kill/restart, containment uncertainty, exact-grant claim/spec-publication-to-release dispatch races, embedded admin dispatch/static probe core, current/superseded evidence, exact budget settlement/dispatch-closure/manual-attestation edges, wait/probe/StopIntent reducers, exact allocation settlement, verification-closure/inherited-provenance terminal commit, complete MCP recovery-root closure, cancellation cascade, event commit, and Checkpoint recovery locations)
- `npm run test:sandbox` for the stale-worker/broker/generation fence shared with work package 3
- Platform CI uses injected launchd/systemd adapters for unit tests and one isolated real user-service integration job per supported OS.
- Deterministic fake-clock/containment adapters verify 5-second row-only worker/local-service heartbeats and no Run revision/event churn, 30-second leases, grant/deadline edges, local boundary-evidence validity, termination escalation, cgroup/VM identity reuse, both no-spawn/death retirement branches, and indeterminate-death branches without timing-flaky sleeps.
- Table-driven reducer tests cover every AgentModelTurn stop/text/call/abort combination, ordered observation plus resolved/rejected `ToolCallInputV1` equality, all-resolved dispatch versus atomic whole-batch rejected synthesis, every ordinary `ToolResultPayloadV1`/`ToolResultModelContentV1` outcome/identity/forbidden-field/projection branch and the direct unprojected fenced retry-unknown exception; every canonical Approval/Input/Child/Reconciliation variant including exact input and child model-content projections, child result-vs-detail XOR, mutating patch base/result/diff equality, and allocation/item byte equality; exact `ApprovalDecisionV1` digest/TTL/grant-expiry matrix and atomic state/control commit; exact user-approval versus verifier-template `OperationGrantV1` provenance; exact dependency-template ordinal use; every `ChildAllocationV1` state/forbidden-field matrix; every StopIntent/precedence pair including both exact `KernelIntegrityEvidenceV1` subject/observation-source branches and TerminalReasonDetail equality; normal versus stopped subject resolution; persisted probe dispatch crash/replay; required full `BudgetUsage`; prepared/claim broker-fence-token XOR; pre-dispatch failed claim/spec/evidence-forbidden zero settlement versus post-claim failed exact claim/evidence/consumed settlement; exact owner-loss/broker-channel/sandbox-live/sandbox-death/publication-path `InvocationAmbiguityEvidenceV1` op/claim/authority/XOR branches and abandoned same-pair rule; claimed current/superseded evidence; exact `BudgetSettlementV1`; both `InvocationDispatchClosureEvidenceV1` branches plus exact `BrokerReleaseFenceEvidenceV1`; manual attestation; fixed model retry shape/provider-rejection completion; zero-reservation terminal validation; exact verification closure; and stale revision/subject rejection.
- Protocol contract tests freeze every generated Session/Run/authorization/MCP/artifact/Supervisor method, request, `ControlApplicationResponseV1` result/error schema, and unknown-field rejection; exercise exact `WorkspaceIdentityV1` create/fork/path/root-replacement/apply derivation, `control_requests` replay/conflict, both exact pre-response fence exceptions, cross-cycle submission replay, multi-request local activation success/error fanout, exact local-cycle resource exhaustion, active/revoked/consumed authorization revoke (including immutable consumed no-op), exact list/get/compact/artifact bounds, pure `run.attach` earliest/future/equal-high-water/page/terminal-anchor semantics, read-method requestId rejection, successful versus retryable/nonretryable `run.result|run.diff`, `supervisor.status` degraded local-service health without extra fields, and prove all adapters call the same application service without projecting a local response envelope.
- Rollback-fence fault tests crash at each canonical lock acquisition, retained rollback-request/control edge, nonterminal-Run refusal, admin/cycle settlement, four-owner containment proof, launch retirement, invocation closure, broker quiescence, each auth outcome, StateOwner graceful terminalization, legacy-root marker, and state-root marker. They prove the complete lock order remains held, the fence rejects every authority release, a successor performs only clean fenced replay before its own graceful terminalization, unknown state never becomes proof, and state-root marker-last is the sole legacy authority transition.
- A load fixture verifies FIFO, 128-entry default admission bound, concurrency ceilings, cursor ordering, and local p95 attach latency.

Manual:

- Submit with `cliq run --detach`, close the terminal immediately after acknowledgement, inspect the Run from a new shell, and attach through completion.
- Repeat submission after deliberately dropping the acknowledgement connection and confirm the same `admissionKey` returns the same `runId`.
- Create a Session, replace its root directory at the same path, and verify `run.submit`, pathless `run.apply`, capture, and publication return `ARTIFACT_MISMATCH` with no new Run/effect. Exercise a maximum-width device/file id fixture to prove the protocol/storage path never rounds through JS number.
- Kill the worker, leave a contained descendant, then kill the Supervisor; confirm launchd/systemd recovery scans `worker_launches` first and either proves the boundary empty before fresh activation or reports the exact typed `worker_death` subject.
- Restart the Supervisor while an old worker still has an unexpired lease; confirm the new instance rejects reconnect/heartbeat/broker traffic, kills and death-proves the old containment, quarantines its generation, and uses a fresh row/epoch rather than adopting it.
- Submit two concurrent local-model Runs with no active service, disconnect and replay around every activation boundary, and verify both requests join one service cycle while each retained request replays only that cycle/result and changed bytes conflict. Verify no Run/control response for either participant while in flight. Force attempt-1 launch/timeout/health/capability failure after positive retirement and require `retry_wait`, then attempt 2 exactly one second later; force unprovable attempt-1 containment and require terminal exact `containment_unresolved(finalAttempt=1)` with its blocking launch retained; force positively retired and unresolved attempt-2 failures and require terminal failure. Verify no attempt 3 exists, and one terminal transaction admits/responds to both or returns the same `RECOVERY_REQUIRED(local_inference_service)` without Runs.
- Kill/death-prove the active local service between model calls for an existing Run. Verify the Supervisor settles the prior invocation, quiesces/checkpoints/retires the worker, queues the unchanged agent frontier as a cycle participant, and either makes it eligible on cycle success or proposes exact `runtime/local_inference_unavailable` on failure; cancel/move the Run before fanout and verify it becomes obsolete without affecting newer state.
- Restart before spawn and after activation of a managed local-inference service. Verify respectively exact `no_spawn` and `death` retirement, no adoption/traffic during recovery, fresh dynamic identities on the cycle-authorized next launch, stable-service identity equality, and `supervisor.status.health='degraded'` while the required service cannot be safely replaced.
- Leave an unkillable/indeterminate cgroup/VM fixture and verify no second launch intent is created.
- Cancel once in each queued, preactivated, running, approval/input/child/reconciliation, and claimed-effect state; restart midway and verify the closed reducer converges without new productive I/O or premature reservation release.
- Expire a grant before prepare, between prepare/claim, between claim/release, and after successful release; verify the four distinct frozen outcomes and no duplicate target call.
- Pause after `claimDispatch`, expire/revoke the launch lease or install a StopIntent, and verify `releaseClaimedDispatch` refuses target I/O while evidence/recovery closes the permanent claim.
- Exercise `session.create/list/get/fork/compact/handoff.create`, `authorization.create/list/revoke`, and `mcp.register/refresh/list`; verify revisions/idempotency, consumed-revoke `already_consumed` no-op/receipt preservation, raw-item preservation, bounded reads, and read-method requestId rejection. For handoff, test omitted/zero/every segment-end cursor, reject inside/future cursors and revision drift, recompute exact entry/excluded-range order plus handoff digest, byte-compare the fixed JCS/Markdown renderers and descriptors, and repeat the same call for identical refs. Verify exact `ControlApplicationResponseV1` parity across every adapter and absence of Session/registry execution state.
- Complete a child while its parent is running and verify only `child_allocations` changes; then let the parent perform its next revisioned settlement and verify exactly-once budget/child wake behavior.
- Attach two simultaneous clients at zero and `earliestRetainedEventSeq-1`, page each until `nextEventSeq === highWaterEventSeq`, verify equality returns an empty same-cursor page and a future cursor is `INVALID_REQUEST`, commit a later event, and confirm only a new attach captures it. Prune a terminal spool and verify its terminal anchor remains; verify deterministic repeated pages and no implicit subscription/push envelope.
- Close a TUI and a stdio RPC pipe while a Run is active; verify the Run continues. Then issue explicit cancel and verify durable cancellation behavior.
- With all Runs terminal, enter rollback while worker, invocation, admin, and local-inference lifecycle fixtures remain. Verify the canonical Kernel-global/state-owner -> local-model registry/object-store -> legacy-auth -> byte-sorted legacy-state -> credential-authority locks remain held, exact rollback request/control pairs survive restart, the fence blocks every authority release, exact reducers/containment proofs/retirements/Journal closure converge, and unknown state blocks. Verify the active owner gracefully terminalizes as its final DB mutation, a mid-marker crash allows only clean fenced replay plus successor graceful terminalization, and state-root marker-last forbids any later owner acquisition.

### Risks And Dependencies

- Whole-containment identity/death proof differs between Linux PID-namespace+cgroup/subreaper and the signed macOS microVM. Any uncertainty must reduce availability by a typed containment wait; it must not reduce safety by double-running.
- Crash-safe preactivation adds a durable intent/activation handshake to the critical path. Its persistence API, one-intent uniqueness, and startup scan must ship with fault injection before detached mutation admission is enabled.
- Moving heartbeat/worker/generation authority into `worker_launches` reduces Run churn but makes pointer-row cross-field constraints and row retention security-critical. Activation/retirement, row-only renewal, dispatch snapshot validation, and worker-death exception paths require transactional fault tests.
- The managed local service is shared non-Run authority and a bounded pre-response admission/recovery fence: treating it as a Run launch can deadlock terminalization, omitting its cycle/launch rows can send requests to an untracked process, and losing its service-level participant/attempt prefix can create duplicate starts or an unbounded restart loop. Exact separate storage, semantic service identity, multi-participant cycle/two-attempt recovery, atomic fanout, stable-versus-dynamic identity, no-adoption startup ordering, and both retirement branches are release gates.
- The no-adoption rule deliberately trades restart latency for single-owner safety: every Supervisor change kills/death-proves/quarantines even a healthy unexpired worker. Recovery SLOs may be optimized through faster containment proof and Checkpoint restore, never by reconnecting or sharing broker authority.
- launchd/systemd service definitions can become stale across package upgrades or binary relocation. Compatibility handshake, idempotent installation, and drain-before-replacement are mandatory.
- SQLite event volume can affect state commits and attach latency. Coalescing progress and storing large payloads in CAS are required; `run_events` must not become a transcript database.
- UDS filesystem permissions protect the initial local transport. Multi-user or remote authentication is intentionally out of scope.
- Reboot integration tests are expensive and platform-sensitive; release evidence must include a real service restart/recovery job, not only mocked service managers.

Required sequence:

1. Work package 1 must expose atomic Run/Session admission, `control_requests` replay, revision compare-and-swap, canonical wait/StopIntent refs, `worker_launches` pointer/phase/write-gate/row-heartbeat APIs, exact `local_inference_activation_cycles` participant/singleflight/two-attempt/fanout plus `local_inference_launches` phase/retirement/row-heartbeat and recovery APIs, both closed pre-response fences, `child_allocations`, Journal claim/current-or-superseded evidence transactions, closed terminal validation, and non-authoritative `(runId, eventSeq)` storage.
2. Control contract, service-manager adapters, event cursor, and scheduler can be implemented in parallel against those interfaces.
3. Work package 3 must provide strong four-owner containment launch, blocked worker/admin/local-service preactivation, `ProcessContainmentRef` inspection/termination, local-service boundary enforcement, generation create/quiesce/quarantine through `worker_launches`, mandatory `claimDispatch` plus `releaseClaimedDispatch`, narrow publication `claimRecoveryMaintenance` plus `releaseRecoveryMaintenance`, `assertEvidenceAuthority`, and broker singleflight integration before mutating workers or managed local traffic are admitted.
4. Work package 2 must provide a resumable typed worker entrypoint and deterministic `nextStep` handling.
5. Work package 5 supplies verifier/publication/child evidence validators called by this package's subject-specific reducers; it does not own Run status or a parallel transaction.
6. Work package 6 supplies the generated v1 Session/Run/authorization/MCP schemas plus registry/grant semantics consumed by this package's handlers, then switches every client surface and removes process-local ownership only after the full fault, sandbox, migration, and end-to-end gates pass in one Kernel Cut.

Rollback (only for hard-to-reverse changes):

- Before Kernel Cut, stop admitting new durable Runs, drain or explicitly cancel existing Runs, and retain SQLite/CAS/generations for diagnosis. Do not convert accepted durable Runs back into in-process headless calls.
- If a service build is incompatible, the old compatible Supervisor continues owning existing Runs until drained; an installer must not kill it opportunistically.
- After cutover, use the RFC's exact retained rollback request: reuse current StateOwner authority, acquire the canonical Kernel-global/state-owner -> local-model registry/object-store -> legacy-auth -> byte-sorted legacy-state -> credential-authority order, refuse nonterminal Runs before control publication, hold `rollback_draining|rollback_restoring` plus locks, close every typed authority, stage the exact auth outcome and prepared markers, gracefully terminalize the owner as its final Kernel transaction, then publish legacy-root first and state-root authority last. A crash permits only clean fenced marker replay and successor graceful terminalization; unknown/unprovable state blocks, and archived database/CAS remains read-only.
- Removing a socket, lease, intent, containment reference, wait subject, event range, or generation is never a rollback mechanism; each has its own ownership/retention proof.

### Open Questions

- None. OS ownership, UDS transport, durable acknowledgement, FIFO/no-resource-wait scheduling, powerless worker/admin/local-service preactivation, no-adoption whole-containment takeover, service-level multi-participant two-attempt activation and atomic final fanout, separate local-service lifecycle and retirement XOR, stable local replacement identity, row-only heartbeat, dual dispatch, call-scoped MCP lifecycle subjects, typed waits, operation-specific reconciliation, grant expiry, additive-budget/deadline/cancellation StopIntents, Session/Run/administration method schemas, pure paginated event cursors, and no-DAG scope are closed by this Kernel Cut. Changing one requires a new RFC.

### GitHub Issue Body

**Title:** `feat: add detached Supervisor and durable local control protocol`

Implement work package 4 from `docs/backlog/durable-verified-run-kernel/04-detached-supervisor-and-control-protocol.md` and the canonical Durable Verified Run Kernel RFC.

Admission must require exact `RunAssemblyV1.sandboxBackend='macos_vm'|'linux_namespace'` plus successful strong-backend, worker-identity, and pinned-executable probes for every Git/non-Git/read-only/text-only Run; there is no Seatbelt, workerless, or weak fallback.

Session creation must publish exact descriptor-derived `WorkspaceIdentityV1`, preserving device/file ids as unsigned decimal strings. `run.submit` path must resolve to that identity; `run.apply` accepts no path and derives the source Session; root replacement is `ARTIFACT_MISMATCH`.

Deliver the launchd/systemd per-user Supervisor, idempotent durable admission, bounded FIFO/no-resource-wait scheduling, durable blocked worker/admin/local-service preactivation, exact local-service semantic identity plus a retained service-level max-128-participant/two-attempt cycle shared by submissions and existing Run frontiers with atomic final fanout, exact four-owner `SandboxLaunchSpecV1` orchestration including closed `SandboxProcessInvocationV1` process derivation, no-adoption whole-descendant containment takeover with row-only heartbeat, exact managed-local-service retirement/stable-replacement identity, exact-`OperationGrantV1` dual dispatch/evidence authority, claim-time invocation launch-spec binding, invocation-lifetime `dispatch_claimed` singleflight, exact `InvocationAmbiguityEvidenceV1` publication for every unknown mechanism and byte-identical manual-abandon carry-through, batch/index-bound call-scoped MCP lifecycle approvals, exact `ApprovalDecisionV1` atomic approval, exact `ManualAbandonAttestationV1`, `BudgetSettlementV1`, `InvocationDispatchClosureEvidenceV1`, `InheritedVerificationProvenanceV1`, `RunPolicySnapshotV1`, authorization/receipt/allocation/dependency-template/verification typed reducers, canonical typed wait/StopIntent reducers including `local_inference_unavailable` and additive budget exhaustion, exact all-scopes labeled workspace-instruction plus source-identity-backed ordered skill prompt projection with immutable recovery, exact three-attempt/zero-hidden-retry/`[500,2000]` model scheduling with fully charged nonretried provider rejections, closed cancellation/deadline recovery, frozen Session/Run/authorization/MCP UDS JSON-RPC methods, restart recovery with complete MCP registry-transitive roots, pure paginated non-authoritative durable event cursors, and rollback that holds the canonical Kernel/legacy/credential lock order while terminalizing admin/cycle authority, death-proving all four containment owners, retiring worker/admin/local rows, and evidence-closing invocation claims before marker-last restore. `run.apply` keeps deliverable `SourceManifest A` in RunSpec/delivery merge and distinct recovery `WorkspaceStateManifest W_A` in the initial Checkpoint with `W_A.baseWorkspaceManifestRef=A`. Consumed authorization revoke is the canonical successful no-op, and every public result is exactly `ControlApplicationResponseV1`. Make CLI, TUI, JSONL, and stdio RPC clients of this one protocol; transport disconnect must not cancel an accepted Run or reset/fork a local activation cycle.

Done means every acceptance criterion and automated/manual validation item in the local spec passes. Do not activate a worker before its lease CAS, do not start a replacement until the prior `ProcessContainmentRef` is proven empty, do not use `run_events` for recovery, and do not add DAG/distributed/HTTP scheduler scope.
