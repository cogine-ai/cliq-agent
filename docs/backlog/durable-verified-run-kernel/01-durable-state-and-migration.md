# Durable State And Migration

## Backlog Ready Spec

### Verdict

READY WITH RISKS

Reviewed against main `0f2fa146` on 2026-09-26. The
[cross-package review](../../kernel/2026-09-26-design-review.md) records current
implementation, source evidence and integration gates. Shared schemas remain
owned by the RFC; this package owns their storage enforcement.

The canonical RFC and work package 4 close the storage, fencing, migration, and rollback decisions required to implement this package. The remaining risks are SQLite/CAS cross-resource crash windows, legacy-state quiescence proof, schema migration durability, and restoring legacy authority without exposing a half-restored tree. Those are implementation risks covered by artifact-first publication, narrow typed transactions, platform-specific fail-closed import, fault injection, and authority-marker-last rollback; none permits a second state owner or a compatibility dual write.

### Source

Brief / issue / roadmap item:

- Work package 1 of the [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md).
- Product promise: **Delegate. Detach. Return to verified work.**
- Work package 4's [Supervisor and control protocol contract](04-detached-supervisor-and-control-protocol.md), especially `worker_launches`, `control_requests`, `child_allocations`, current-versus-historical evidence, and terminal-quiescence rules.

Related issues:

- No existing issue implements the complete SQLite/CAS authority, typed transaction layer, legacy import, and rollback protocol.
- GitHub issue `#46` contributes crash-durability lessons only. Its `Transaction` aggregate, overlay lifecycle, and `activeTxId` are historical import inputs, not the new execution model.
- The [issue supersession map](issue-supersession-map.md) is normative for duplication and dependency handling.

Legacy production code and current Kernel implementation:

- `src/state/store.ts`, `src/state/reducers/`, `src/state/native-owner.ts`, and
  `src/state/recovery-closure.ts` already implement the hidden admission/state
  core and substantial typed continuation. Reuse them; do not start a second
  repository/reducer hierarchy from the illustrative file list below.
- [M2 implementation boundaries](../../kernel/m2-state-core.md) distinguish
  completed owner takeover and quarantine primitives from pending descriptor
  I/O, containment integration and migration.

- `src/session/store.ts` and `src/session/types.ts` persist whole Session JSON documents and currently mix context, lifecycle, records, checkpoints, plans, and `activeTxId`.
- `src/session/checkpoints.ts` and `src/session/checkpoints.test.ts` manage bookmark-style checkpoint metadata and expirable Git ghost commits; they do not publish a complete recoverable Run cut.
- `src/session/store.test.ts`, `src/session/compaction.ts`, and `src/session/fork.ts` contain legacy ids, ordering, compaction, fork, locking, and migration behavior that the importer must preserve as context.
- `src/workspace/transactions/store.ts`, `recovery.ts`, `apply.ts`, and `abort.ts` contain reusable file/directory `fsync`, deterministic-id, lock-order, and crash-recovery techniques. Their state machine is not reusable as Run authority.
- `src/plans/store.ts` and `src/handoff/export.ts` identify legacy plan, progress, and handoff artifacts that import must retain.
- `src/lib/path-lock.ts` is suitable for migration/rollback serialization only; it is not a worker lease or Run revision mechanism.
- `src/headless/contract.ts`, `events.ts`, and `artifacts.ts` provide versioned envelope/event/artifact seams, but current headless execution remains process-owned.
- `src/config.ts` currently defines `SESSION_VERSION` and legacy paths but no Kernel schema, authority generation, SQLite, or CAS layout.
- `package.json` has `test:state`, `test:state-fault`, `test:state-probe`,
  `test:agent-runtime`, and sandbox-probe commands. The complete migration and
  aggregate Kernel-Cut suites below are still required, not existing green gates.

### User Outcome

Once a Run is acknowledged, its immutable spec, initial ready Checkpoint, authoritative revision/frontier, Journal facts, worker-launch fencing identity, child allocations, approvals, and result remain recoverable after client exit, Supervisor death, worker death, or reboot. Recovery reads one typed SQLite/CAS closure; it never guesses from Session JSON, display events, directories, or the last error.

Users upgrading on supported macOS or Linux retain legacy Sessions, ordered context, compactions, plans, handoffs, and bookmark references through one verified import. Legacy execution flags never become synthetic Runs. Native Windows does not create or open Kernel state: it may only export a verified portable legacy handoff and returns `UNSUPPORTED_PLATFORM` for migration/runtime authority. Rollback restores a fully verified legacy generation before publishing legacy authority, preserves the former SQLite/CAS generation read-only, and never exposes a marker that points at a partial restore.

### Problem

The legacy production persistence path cannot satisfy the durable delegation contract:

- whole-Session JSON is both context and de facto execution state;
- writes replace a complete aggregate and coordinate through path locks rather than Run revisions and launch fencing;
- `SessionCheckpoint` is bookmark metadata, not a complete context/workspace/Journal cut;
- there is no non-optional initial Run Checkpoint or atomic durable submit acknowledgement;
- there is no authoritative typed Run frontier, StopIntent, Journal claim, worker-launch write gate, child allocation, control replay record, authorization registry, MCP registry, or admin probe fence;
- existing lease-like state is process/file-owned and cannot prove stale-worker exclusion;
- current code can publish workspace and Session facts in separate writes;
- late authenticated evidence cannot be correctly distinguished between still-current evidence that advances a reducer and superseded historical evidence that must not;
- migration and rollback can fail between file writes unless authority remains unchanged until a fully verified generation is ready.

The replacement must be current-state storage plus a narrow append-only Journal, not event sourcing, a generic mutation bag, or a second workflow engine.

### Scope

In:

- Make `src/kernel/types.ts` the single field-for-field export of the canonical RFC types for `RepositoryIdentityV1`, `WorkspaceIdentityV1`, `WorkspaceEntryManifest`, `GitIndexSnapshotV1`, `GitObjectPackV1`, `GitObjectClosureV1`, `SourceManifest`, `SanitizedGitConfigV1`, `PrivateGitStateManifest`, `WorkspaceStateManifest`, `WorkspaceGenerationIdentityV1`, `WorkspaceGenerationSnapshotEvidenceV1`, `WorkspaceGenerationFailureDetailV1`, `WorkspaceGenerationQuarantineEvidenceV1`, `WorkspaceGenerationRetirementEvidenceV1`, `WorkspaceGenerationStateBaseV1`, `WorkspaceGenerationStateV1`, Session, SessionItem, `RunObjectiveV1`, RunSpec, `RunAssemblyV1`, Run, RunFrontier, WaitingSubject, StopIntent, Checkpoint, RunJournal, RunEvent, WorkerIdentity, WorkerLaunch, MCP registrations, admin operations, local-inference service specifications/activation cycles/launches/evidence, and ArtifactRef. It must also export without local widening or reinterpretation the exact `FrozenIgnoreRuleV1`, `FrozenIgnoreRulesV1`, `SourceIncludeAuthorizationV1`, `SourceProjectionSpec`, `RunPolicySnapshotV1`, `PolicyChannelEvidenceBaseV1`, `PolicyChannelEvidenceV1`, `PolicyDecisionItem`, `ApprovalDecisionV1`, `OperationGrantV1`, `AuthorizationGrantV1`, `AuthorizationConsumptionReceiptV1`, `ChildAllocationV1`, `DependencyAcquisitionPlanBase`, `DependencyAcquisitionPlan`, `DependencyReadyItem`, `DependencyInstallScriptsAuthorizationTemplateV1`, `KernelIntegrityEvidenceV1`, `RuntimeFailureEvidenceBaseV1`, `RuntimeFailureEvidenceV1`, `VerificationClosureV1`, `InheritedVerificationProvenanceV1`, `DeliveryTerminalProjectionEvidence`, `ManualAbandonAttestationV1`, `BudgetSettlementV1`, `InvocationAmbiguityEvidenceBaseV1`, `InvocationAmbiguityEvidenceV1`, `PostClaimNoReleaseEvidenceV1`, `BrokerReleaseFenceEvidenceV1`, `InvocationDispatchClosureEvidenceV1`, `RequestedMcpRecoveryV1`, `McpProbedToolInterfaceV1`, `McpRetryRiskConsentV1`, `McpRetrySafetyAssertionV1`, `McpRecoveryAdapterManifestV1`, `McpRecoveryStatusRequestTemplateV1`, `McpRecoveryPredicateExpressionV1`, `McpRecoveryPredicateV1`, `McpRecoveryContract`, `McpRecoveryProbeEvidenceV1`, `WorkerRecoveryEvidenceBaseV1`, `WorkerRecoveryEvidenceV1`, `ReconciliationProbeDispatchV1`, `ReconciliationInspectorTaskClosureV1`, `ReconciliationProbeTimeoutClosureV1`, `ReconciliationProbeEvidenceV1`, `ReconciliationLastProbeEvidenceV1`, `ReconciliationProbeStateV1`, `McpRegistryRevision`, `McpRegistrationReceipt`, `McpAdminProbeTargetV1`, `McpAdminProbeResultV1`, `AdminProbePayloadCoreV1`, `AdminProbeClosureEvidenceV1`, `AdminProbeErrorV1`, `AdminProbeDispatchState`, `AdminOperationBase`, `AdminOperation`, `GuestExecutableIdentity`, `GuestToolchainManifest`, `InterpreterIdentityV1`, `SandboxRootImageV1`, `SandboxResourceSpec`, `SandboxProfileV1`, `SandboxRuntimeBindingV1`, `SandboxExecutableIdentityV1`, `SandboxCapturedStdioV1`, `SandboxProcessInvocationV1`, `SanitizedSandboxEnvironmentV1`, `SandboxFilesystemV1`, `SandboxMountV1`, `SandboxLaunchBaseV1`, `SandboxLaunchSpecV1`, `ProcessContainmentOwner`, `ProcessContainmentPlanV1`, `ProcessContainment`, `ProcessContainmentRef`, `PlatformProcessIdentityV1`, `StateRootIdentityV1`, `StateLockIdentityV1`, `StateOwnerAcquisitionEvidenceV1`, `StateOwnerTransitionEvidenceV1`, `StateOwnerRecordV1`, `SupervisorInspectorIdentityV1`, `ProcessContainmentNoSpawnEvidenceV1`, `ProcessContainmentDeathEvidenceV1`, `LocalModelObjectClosureV1`, `LocalInferenceServiceSpecV1`, `LocalInferenceActivationParticipantV1`, `LocalInferenceActivationFailureV1`, `LocalInferenceActivationCycleBaseV1`, `LocalInferenceActivationCycleV1`, `LocalInferenceServiceLaunchBaseV1`, `LocalInferenceServiceLaunchV1`, `LocalInferenceBoundaryEvidenceV1`, and `LocalZeroCostProvenanceV1` definitions.
- Export the canonical `CanonicalTimeFenceV1`, `LocalPrincipalIdentityV1`, `LocalSocketPeerObservationV2`, and `LocalControlChannelIdentityV1` field-for-field in `src/kernel/types.ts`; time, principal, peer observation, and transport-channel identity are global storage/authority primitives, never adapter-local strings.
- Export exact `ListMethodV1`, `ListCursorPayloadV1`, `ListReadCutEntryV1`, and `ListReadCutV1`; they are storage-owned authenticated read-cut/cache authority and may not be replaced by an adapter cursor, live keyset query, or untyped cache row.
- Export `PolicyEngineProfileV1` field-for-field and validate the revised `RunPolicySnapshotV1.engine` profile-entry/ref/digest closure; policy is interpreted only by fixed signed Supervisor code over a signed non-executable RuntimeBundle data profile, never by spawning or dynamically loading policy code.
- Export the canonical `PolicyDenialOutcomeV1`, `PolicyDecisionItemBaseV1`, direct-versus-interactive `PolicyDecisionItem`, `VerifierSkipItemBaseV1`, and `VerifierSkipItem` field-for-field. Direct policy and interactive approval are distinct storage authority and may not be collapsed into a nullable wait/ref bag.
- Export the canonical `EndpointModelNegotiationRequestV1`, `EndpointModelNegotiationResponseV1`, `ModelTextV1`, `NormalPromptToolCallV1`, `NormalPromptMessageV1`, `NormalPromptProjectionV1`, `ModelRequestV1`, `ModelUnusableResponseV1`, `ObservedToolCallInputV1`, `ToolCallInputBaseV1`, `ToolCallInputV1`, `ModelTurnItem`, `ToolCallRecord`, `ToolBatchItem`, `ToolResultItem`, `ToolResultPayloadBaseV1`, `ToolResultModelContentV1`, `ToolResultPayloadV1`, `InputResponseSchemaV1`, `InputPromptBaseV1`, `InputPromptV1`, `UserInputModelContentV1`, `UserInputPayloadBaseV1`, `UserInputPayloadV1`, `InputRequestItem`, and `UserInputItem` field-for-field in that same module. They close the retained model-capability, deterministic normal/compaction provider-body request, unusable-response, ordinary model/tool item, and authenticated input audit/model-content boundaries; the dedicated `RetryUnknownCancelledResult` remains a distinct direct result artifact and is never widened into `ToolResultPayloadV1`.
- Export the canonical `WorkspaceDiffOperationV1`, `WorkspaceDiffV1`, `FinalCandidateItemBase`, and operation-discriminated `FinalCandidateItem` field-for-field. Diff comparison and candidate provenance are storage authority rather than producer hints; no generic candidate bag or adapter-local diff is accepted.
- Export the canonical `ChildHandleItem`, `ChildPatchManifest`, `ChildResultModelContentV1`, `ChildResultItemBase`, `ChildResultItem`, `ChildAllocationTerminal`, `ChildAllocationBase`, and `ChildAllocationV1` field-for-field. Child admission identity, terminal audit truth, model projection, patch/result/detail identity, allocation settlement, and parent wake are one closed storage graph.
- Export the canonical `VerifierRepairModelContentV1`, `VerifierRepairDiagnosticV1`, `RepairDiagnosticEntryV1`, and updated `RepairDiagnosticItem` field-for-field. Repair guidance is an explicit minimized model projection of retained verifier audit evidence; raw stdout/stderr can never become prompt content by treating an audit ref as text.
- Export the canonical `SessionRunTerminalItem`, `SessionHandoffEntryV1`, `SessionHandoffV1`, `ContextSegment`, `ContextManifest`, and `RunContextCompactionItem` field-for-field. Session handoff is one immutable snapshot projection with fixed JSON/Markdown renderers; both Session and Run context summaries repeat exact `ModelTextV1` ref/digest pairs, while terminal Session rendering and compaction visibility remain closed storage rules rather than adapter choices.
- Export `SourceIncludeClassificationEvidenceV1` field-for-field in that same canonical type module; it is part of the closed source-authority graph, not an implementation-local capture receipt.
- Export the canonical `McpServerInstanceIdentityV1`, `McpServerLaunchReceiptV1`, `McpServerStoppedItem`, `PathState`, `PublicationLeafState`, `PublicationParent`, `PublicationOperationBase`, `PublicationOperation`, `PublicationAbortOperation`, `PublicationPathObservationV1`, `PublicationProofBaseV1`, and `PublicationProofV1` field-for-field in the same module. They are typed recovery/receipt authority, not adapter-local payloads.
- Import the exact WP06 `RuntimeBundleStructuredArtifactBaseV1`, kind-discriminated `RuntimeBundleStructuredArtifactV1`, and `RuntimeBundleManifest` into `src/kernel/types.ts`; storage/GC/recovery must closed-decode the complete signed root/member graph rather than treating the bundle or structured records as opaque external metadata.
- Export exact `WorkspaceInstructionSourceManifestV1`, `WorkspaceInstructionManifestV1`, `BundledSkillClosureV1`, `SkillSourceFileBytesV1`, `DescriptorCapturedSkillSourceFileV1`, `BundledSkillSourceFileV1`, `SkillSourceIdentityBaseV1`, `SkillSourceIdentityV1`, and revised `SkillManifestV1` field-for-field. Instruction and skill provenance is immutable declarative-context authority, never SourceManifest/tool authority; `ContextManifest` retains only `assemblyRef` and never duplicates instruction/skill ref arrays.
- Export the canonical `ReconciliationProbeDispatchV1`, `ReconciliationInspectorTaskClosureV1`, `MigrationFilesystemRootIdentityV1`, `WindowsLegacyRootIdentityV1`, `WindowsOutputDirectoryIdentityV1`, `WindowsExportFileIdentityV1`, `LegacyPortableProjectionSchemaV1`, `LegacyPortableSchemaManifestV1`, `LegacyPortablePayloadV1`, `LegacyPortableSessionV1`, `LegacyPortableHandoffV1`, `LegacyPortableHandoffExportReceiptV1`, `LegacyPortableHandoffVerificationResultV1`, `LegacyAuthFileIdentityV1`, `LegacyAuthStoreObservationV1`, `LegacyAuthNonSecretProjectionV1`, `KernelSchemaManifestV1`, `KernelDatabaseImageIdentityV1`, `CasNamespaceManifestV1`, `KernelGenerationIdentityV1`, `ArchivedKernelDatabaseImageV1`, `ArchivedKernelGenerationManifestV1`, `MigrationInventoryEntryV1`, `MigrationInventoryManifestV1`, `CredentialRoundTripEvidenceV1`, `PlaintextLegacyCredentialConsentV1`, `RollbackToLegacyRequestBaseV1`, `RollbackToLegacyRequestV1`, `CredentialReadyManifestV1`, `MigrationBackupManifestV1`, `KernelCandidateManifestV1`, `LegacyGenerationManifestBaseV1`, `LegacyGenerationManifestV1`, `LegacyAuthMigratedMarkerV1`, `MigrationReceiptV1`, `MigrationAuthorityMarkerV1`, `MigrationControlBaseV1`, and `MigrationControlV1` field-for-field. Migration and portable-export files are exact typed authority, not best-effort sentinels or implementation-local JSON.
- Add SQLite current-state storage plus immutable SHA-256 CAS under one private same-user state root.
- Create exactly one `canonical_time_fence` singleton authority table plus at least these physical tables: `sessions`, `items`, `runs`, `checkpoints`, `run_journal`, `run_events`, `worker_launches`, `workspace_generations`, `control_requests`, `list_read_cuts`, `list_read_cut_entries`, `child_allocations`, `authorization_grants`, `mcp_registrations`, `admin_operations`, `local_inference_activation_cycles`, `local_inference_launches`, `state_owners`, and `artifacts`, plus a schema/import metadata table if needed.
- Store Session create/fork admission keys and digests, plus each Run's admission key, pre-resolution `admissionIntentDigest`, and final admitted-request digest, without adding lifecycle meaning to those storage columns.
- Make every accepted Run start with the revision-0 virtual cut, an initial ready Checkpoint, a `revision=1` queued Run, event sequence 1, and a replayable control response in one SQLite transaction.
- Expose only typed repository/reducer transactions. There is no generic `compareAndSwapRun(mutation)`, arbitrary status setter, generic item-and-budget bag, or production raw-SQL escape.
- Make `worker_launches` the sole durable worker identity, lease expiry/version, containment, generation, and generation-write-gate authority. `Run` retains only monotonic `leaseEpoch` plus optional `activeWorkerLaunchId`.
- Implement durable `control_requests` replay in the exact state-changing transaction for every public mutator.
- Implement typed current-evidence and historical-evidence commit paths: current authenticated evidence may settle and advance the exact current reducer; superseded evidence is Journal/audit/billing-only.
- Persist exact `ChildAllocationV1` and `AuthorizationGrantV1` rows, exact authorization-consumption receipts, append-only MCP registration revisions, crash-fenced admin probe operations, service-level local-inference activation cycles, and managed local-inference launch rows with their closed ownership and transition rules. Validate every referenced policy, operation grant, install-script template, verification closure, sandbox launch spec, containment plan/actual containment, local activation failure, local boundary evidence, and no-spawn/death evidence artifact before it can become authoritative.
- Publish artifacts before SQLite references, publish Checkpoints only at quiescent cuts, and return the full recovery closure including unretired launches and parent/child allocation rows.
- Store non-authoritative monotonic `run_events` for attach cursors without using them in reducers or recovery.
- Import legacy state once on supported macOS/Linux, after process/open-file/lock quiescence proof and a verified read-only backup.
- Before general inventory, invoke work package 6's exact auth preflight under the legacy locks: publish a closed present-or-absent observation plus non-secret projection; only a recognized present store deterministically enrolls supported entries in Keychain/Secret Service and round-trips authority, while exact absence remains authoritative. General migration records only the secret-free observation/projection/ready graph and excludes auth bytes. Final cutover publishes `cliq-auth-migrated-v1` for either branch immediately before Kernel authority last; pre-authority recovery restores the present rendering or exact absence. Raw keys never enter backup, CAS, SQLite, archives, or logs.
- Make native Windows export-only for legacy portable handoff; it must not create/open/migrate/administer SQLite/CAS or run a Supervisor.
- Implement exact `MigrationControlV1`-first staging and verification with typed receipts/generations and authority marker published last.
- Add schema, repository, CAS, migration, rollback, platform, and crash-injection tests.

Out:

- Supervisor scheduling, queue policy, timers, process launch, process containment, or OS-service installation; work package 4 owns orchestration and calls this package's typed APIs.
- Sandbox, private-generation materialization, quiesce implementation, broker transport, or all-descendant death inspection; work package 3 supplies evidence and containment operations.
- Provider/tool/model execution, typed runtime normalization, verification policy, result construction, or delivery semantics; other packages supply schema-valid artifacts/evidence to these storage gates.
- A generic repository plugin API, direct worker SQLite access, distributed database, remote state server, event-sourced reducer, DAG, `Task`, `EffectPlan`, or retained `Transaction` aggregate.
- Run-owned `leaseExpiresAt`, `leaseVersion`, `workerIdentity`, `processContainmentRef`, or `workspaceGenerationRef` fields.
- Optional initial Checkpoints, revision-0 persisted Runs, recovery from `run_events`, or recovery from directory inspection.
- Long-term JSON/SQLite dual write, synthetic Runs from legacy lifecycle fields, or legacy bookmarks inserted into `checkpoints`.
- Native Windows Kernel import, SQLite/CAS authority, Supervisor, or execution.
- Automatic deletion of Sessions, Runs, results, receipts, Journal facts, control records, launch history, state-owner history, child allocations, registry revisions, or migration archives.

### Proposed Implementation Direction

Likely files/modules:

- Add `src/kernel/types.ts` as a verbatim field/discriminator/optionality export of the canonical RFC domain types, with no SQLite, UI, provider, or service imports. Work-package-local aliases, wider unions, optionalized required fields, legacy compatibility members, and opaque `Record<string, unknown>` substitutes are forbidden.
- Add `src/state/driver.ts`, `sqlite-driver.ts`, `schema.ts`, `transactions.ts`, `canonical-time.ts`, `local-identities.ts`, and `errors.ts` for the private binding, pragmas, schema versions, transaction modes, exact UTC millisecond parsing/checked arithmetic/fencing, local principal/channel artifact validation, and typed storage errors.
- Add `src/state/artifacts.ts`, `artifact-schemas.ts`, and `artifact-reachability.ts` for verified CAS publication, exact canonical schema decoding, typed reference validation, roots, and orphan enumeration.
- Add repositories under `src/state/repositories/`: `canonical-time-fence.ts`, `sessions.ts`, `runs.ts`, `checkpoints.ts`, `journal.ts`, `events.ts`, `worker-launches.ts`, `control-requests.ts`, `child-allocations.ts`, `authorization-grants.ts`, `mcp-registrations.ts`, `admin-operations.ts`, `local-inference-activation-cycles.ts`, `local-inference-launches.ts`, `state-owners.ts`, and `artifacts.ts`.
- Add typed transaction reducers under `src/state/reducers/`: `admission.ts`, `invocation.ts`, `evidence.ts`, `waiting.ts`, `stop-intent.ts`, `terminal.ts`, `workspace-transition.ts`, and `child-settlement.ts`. They validate canonical artifacts and call repositories through one internal transaction object; they do not expose a mutation bag.
- Add `src/state/recovery-closure.ts` and `invariants.ts` for cross-table validation and exact recovery reads.
- Add migration modules under `src/state/migration/`: `inventory.ts`, `legacy-readers.ts`, `quiescence.ts`, `credential-preflight.ts`, `credential-cutover.ts`, `backup.ts`, `import.ts`, `authority.ts`, `export.ts`, `rollback.ts`, and `index.ts`. The credential modules only orchestrate WP06's exact authority/enrollment, ready-manifest, marker, rematerialization, and consent-gated rollback APIs; they never persist secrets in Kernel state or invent a fallback store.
- Add macOS/Linux legacy-quiescence adapters under `src/state/migration/platform/`; WSL2 uses the Linux adapter only after the ordinary Linux qualification checks. Add a Windows legacy-export-only adapter that never imports or opens Kernel state.
- Add focused `*.test.ts` files beside these modules and child-process crash fixtures under `src/state/test-fixtures/`.
- Update `src/config.ts` with state schema id/version, authority-generation, SQLite, CAS, socket-adjacent state, backup/archive, and the exact control/authority document paths.
- Wire `cliq state migrate --check`, `cliq state migrate`, `cliq state export`, and `cliq state rollback --to-legacy <migrationId>` through `src/cli.ts`. On native Windows only verified legacy `state export` is available; Kernel state commands return `UNSUPPORTED_PLATFORM` without touching Kernel paths.
- Add `test:state`, `test:migration`, and `test:state-fault` scripts to `package.json`; WP06's root `test:fault` aggregator must invoke `test:state-fault` and fail if it is absent, skipped, or nonzero.

Implementation notes:

#### 1. Keep semantic ownership smaller than physical storage

SQLite stores current authoritative rows plus the narrow immutable invocation Journal. The physical database is not a new control plane:

- Session owns context continuity only.
- Run owns the current revisioned execution frontier and StopIntent pointer.
- Checkpoint owns an immutable recoverable context/workspace cut.
- RunJournal owns nondeterministic invocation facts.
- WorkerLaunch owns worker/lease/generation-write authority.
- RunEvent owns display history only.
- Artifact owns immutable bytes only.

The state root is a real same-user, non-symlink directory opened descriptor-relatively with mode `0700`. SQLite/WAL/SHM, mutable metadata, sockets, temp files, exact control/authority documents, and manifests are `0600`; published immutable CAS/backup bytes are `0400`; verified owner-executable helpers are `0500`. Reject symlink components, mount escape, ownership mismatch, special files, and authoritative regular files with link count other than one. Do not depend on umask.

Use foreign keys, `PRAGMA application_id`, transactional `PRAGMA user_version` migrations, bounded five-second busy timeout, `synchronous=FULL`, and WAL only after a local-filesystem locking/durability probe. A supported rollback journal is the fail-closed fallback; in-memory or unverified network-filesystem state is forbidden. Keep the concrete Node SQLite binding behind `SqliteDriver` and run the same conformance suite against every binding.

#### 2. Freeze the complete physical schema

The schema contains these minimum tables and constraints:

| Table | Required authoritative content and constraints |
|---|---|
| `canonical_time_fence` | Exactly one `CanonicalTimeFenceV1` row under StateOwner authority. Every member is exact and `fence_digest` is recomputed. A healthy write uses one sampled canonical UTC millisecond as sole transaction `now`, requires it at or after `last_accepted_at`, and advances the row in the same transaction. Regression atomically records `clock_regressed`; only current-owner recovery after wall time reaches the retained high-water returns to healthy. No generic setter, reset, deletion, or second row exists. |
| `sessions` | Canonical Session fields; immutable `workspace_identity_ref` resolving only to exact `WorkspaceIdentityV1`; `parent_session_id/forked_through_item_seq` lineage; monotonic context revision/latest logical item sequence; verified context projection ref; admission key+intent digest unique by exact `(principal_id,method,admission_key)`, where create/fork is derived from the lineage branch; optional unique legacy source identity/digest. Fork copies the exact ref. No execution fields. |
| `items` | Immutable `item_id`, exclusive `session_id XOR run_id`, closed kind, verified payload ref, timestamp. Run-owned rows are contiguous Run-local. A Session's **logical** sequence is contiguous, but a fork physically inherits its frozen ancestor prefix without cloning rows, so child-owned rows start at `forkedThroughItemSeq+1`; unique physical `(session_id,item_seq)` and `(run_id,item_seq)` plus root terminal uniqueness by Session+Run. |
| `runs` | Every canonical Run field plus `admission_key` unique by exact `(principal_id,method,admission_key)`, exact `admission_intent_digest`, and exact final `admitted_request_digest`; submit/apply method is derived from the Run operation and cannot be changed. `latest_checkpoint_id` is non-null. Only `lease_epoch` and optional `active_worker_launch_id` represent launch ownership. Every RunSpec requires literal `schemaVersion=1`; every frontier/result policy, template, and verification-closure ref is type-checked against the exact canonical artifact before commit. |
| `checkpoints` | Exact immutable Checkpoint fields with literal `schemaVersion=1` and verified refs; owner/cursor/revision consistency; no legacy bookmark row and no update/delete repository method. |
| `run_journal` | Exact `InvocationJournalEntry`; monotonic per-Run `seq` with primary key `(run_id,seq)`, unique `(run_id,op_id,attempt,phase)`, closed phase/op-kind fields, append-only triggers, contiguous attempts. Every `grant_ref` resolves only to exact `OperationGrantV1`; a policy decision, approval body, authorization row, or template is not substitutable. Every `budget_delta` is the complete four-counter `BudgetUsage`. `prepared` forbids dispatch/Supervisor/state-owner/fence fields. `dispatch_claimed` requires exact dispatch/Supervisor/state-owner; iff the trusted broker releases without child containment it additionally stores one unguessable `brokerFenceTokenDigest`, while process-contained/non-broker claims forbid it. For a process-spawning attempt `prepared` forbids `sandbox_launch_spec_ref`, claim publishes/binds exact `SandboxLaunchSpecV1`, and every post-claim phase repeats it; non-spawning attempts forbid it. `failed` is exact pre-dispatch XOR post-claim: pre-dispatch proves no claim, forbids all claim/evidence fields, and settles zero consumed; post-claim repeats the exact claim and is legal only with exact `PostClaimNoReleaseEvidenceV1`, or for an `opKind='verifier'` infrastructure failure with its cross-field-valid `infra_failed` receipt plus exact containment-death closure. The no-release branch consumes zero; verifier infrastructure consumes exact attempt usage. Every other claimed no-result failure is `unknown`, while a typed negative target response is `completed`. `unknown` requires the exact claim, full settlement, and one ref+digest pair decoding exact mechanism-valid `InvocationAmbiguityEvidenceV1`. `abandoned` repeats that claim/settlement and manual attestation, forbids its own evidence pair, and the attestation repeats the unknown row's ambiguity pair byte-for-byte. Every evidence ref has its digest or both are absent. |
| `run_events` | Primary key `(run_id,event_seq)`, bounded canonical event payload/ref and timestamp; per-Run monotonic allocation in the workflow transaction. Retain/prune metadata includes earliest available cursor, and every retained event payload/message ref is an artifact-GC root even though events are never reducer input. |
| `worker_launches` | Exact `WorkerLaunch` below; at most one unretired reserved/preactivated row for a queued Run and exactly the pointed activated row for a running Run; `leaseVersion` CAS is heartbeat-only. `workspace_generation_ref` decodes an exact immutable identity and `generationWriteState` is a same-transaction denormalized projection of the authoritative `workspace_generations` phase, never an independent gate. Mandatory `containmentPlanRef` and `sandboxLaunchSpecRef` resolve to an exact plan plus `SandboxLaunchSpecV1.worker_activation` before preactivation; pre-spawn retirement and post-spawn retirement accept only matching exact no-spawn or death evidence that repeats that launch ref/digest. |
| `workspace_generations` | One exact `WorkspaceGenerationStateV1` mutable row per immutable `WorkspaceGenerationIdentityV1`, unique by `generation_id` and immutable generation/source fields. Positive `rowVersion` increments by one on every narrow CAS; the phase XOR, exact snapshot/failure/quarantine/retirement evidence pairs, launch/epoch/quiesce/wait bindings, success spine `materializing -> preactivated_readonly -> active -> revoking -> checkpointing -> sealed -> retired`, worker-loss edge through `fenced_reconciling -> quarantined`, and only the canonical materialization/preactivation/launch/checkpoint failure edges to `quarantined -> retired` are storage constraints. WorkerLaunch `generationWriteState` is only a denormalized index and changes in the same transaction as this row. |
| `local_inference_activation_cycles` | Exact `LocalInferenceActivationCycleV1` below; unique `activation_cycle_id`, unique contiguous positive `(owner_principal_id,service_id,cycle_ordinal)`, and at most one `starting_launch|retry_wait` cycle per owner/service. Participants are append-only in join order, unique by exact submission or Run-frontier identity, bounded to 128, and cross-cycle replay-safe. The phase/attempt/launch-id cardinality matrix, `rowVersion`, retry gate, terminal evidence, and recomputed `cycleDigest` are storage constraints. |
| `local_inference_launches` | Exact `LocalInferenceServiceLaunchV1` below; at most one unretired row per `(owner_principal_id,service_id)`, unique `(activation_cycle_id,activation_attempt)`, exact cycle/service/spec/attempt equality, exact phase/forbidden-field constraints, and narrow row-version/lease-version CAS. Reserved rows require the immutable service spec, containment plan, and exact `SandboxLaunchSpecV1.local_inference_service` before spawn; attempt 2 additionally requires its cycle's attempt 1 positively retired and `retryNotBeforeAt` reached. Activation requires exact boundary evidence. Terminal state is the exact `retirementKind='no_spawn'|'death'` XOR with matching no-spawn or whole-containment death evidence and phase-valid boundary/quiesce fields. This row never owns a Run, Journal attempt, frontier, budget, Checkpoint, admin operation, or credential. |
| `control_requests` | Unique `(principal_id,method,request_id)`, exact first-commit `channel_identity_ref/channel_identity_digest`, canonical request digest, immutable verified response ref, response/current revision, committed timestamp. The channel pair closed-decodes the authenticated principal/client artifact and is never rewritten by later replay. No standalone write path. |
| `list_read_cuts` | Exact `ListReadCutV1` keyed by `cut_id`; owner principal/method/normalized-filter digest/normalized limit are immutable, timestamps use the canonical time fence, cut id and cursor secret are independent CSPRNG 256-bit unpadded-base64url values, and `expires_at=created_at+15m`. `entries_digest` and `cut_digest` rehash exactly. The row is a non-authoritative query cache and has no reducer/admission/recovery edge. |
| `list_read_cut_entries` | Exact `ListReadCutEntryV1` keyed by `(cut_id,ordinal)` with contiguous ordinals `1..entry_count`, unique `(cut_id,stable_id)`, exact canonical timestamp/bytewise-id ordering, closed method/payload discriminator, and recomputed `row_digest`. A foreign key cascades only after the owning expired cut is eligible for deletion; otherwise rows are immutable. |
| `child_allocations` | One exact `ChildAllocationV1`, unique by `(parent_run_id,child_run_id)` and delegate identity/admission key. Its discriminated state is monotonic `reserved -> child_terminal -> settled`; forbidden-field XORs, mode-valid terminal payload, inclusive usage, parent settlement revision, and released-unused-budget equation are storage constraints, not reducer convention. |
| `authorization_grants` | One exact `AuthorizationGrantV1`, never a generic target JSON blob. The row reconstructs the closed target/state union, digests, owner, source request, `maxUses=1`, row version, expiry, and forbidden-field XORs; a consumed row references one exact `AuthorizationConsumptionReceiptV1`. It never stores raw credentials. |
| `mcp_registrations` | One owner-scoped row per registration: principal, registration id, monotonic nonzero current revision, and immutable current `McpRegistryRevision` ref. Older immutable revisions/receipts stay addressable through CAS for admitted Runs. No secret bytes. |
| `admin_operations` | Exact discriminated `AdminOperation` below; unique principal/method/request plus contiguous attempt, at most one nonterminal attempt, row-version CAS, and immutable terminal rows. Mandatory preactivation `probe_payload_core_ref` and `sandbox_launch_spec_ref` resolve to the exact static probe core and admin plan/target/core closure. Completed requires exact result/evidence/control-response ref+digest pairs; failed requires exact evidence/error pairs and only final branches require control response; every forbidden field is constrained. It cannot own Runs, tools, children, budgets, or Checkpoints. |
| `state_owners` | Exact `StateOwnerRecordV1`; positive safe-integer `owner_epoch` is unique, contiguous, and strictly increasing; at most one `active` row; every process/lock/root/acquisition ref+digest closed-decodes exact canonical artifacts; every row requires exact `StateOwnerAcquisitionEvidenceV1`; active forbids transition evidence and terminal requires exact ref+digest; version/state/released-at/reason/evidence XOR is enforced; row digest is recomputed. Genesis is epoch one for one exact as-yet-unowned `KernelGenerationIdentityV1`: either verified `fresh_empty`, or `migrated_candidate` only after its exact durable Kernel authority marker/candidate/database-image/CAS closure and as the first repository transaction after cutover. After a graceful latest terminal row, only clean acquisition may append `n+1`; death takeover terminalizes+appends atomically after exact process absence/mismatch proof. History is immutable and retained. |
| `artifacts` | Canonical raw 64-character lower-case hexadecimal SHA-256 ref, declared media/schema kind, byte length, verified publication state, created time. Verified metadata is immutable and a typed reference becomes legal only after publication and exact schema/digest validation; a caller-selected kind tag never substitutes for decoding the bytes. |

A completed `opKind='model'` Journal row has one closed result XOR. `resultRef` decodes either an exact usable `AgentModelTurn` satisfying the normal/compaction request and stop/call/text contract, or exact `ModelUnusableResponseV1`; no other artifact is legal. The unusable artifact repeats Run/op/attempt, exact normal-or-compaction request ref/digest, provider/model/mode, and omission digest. `complete` retains the exact positively received bytes at `bytesRef===bytesDigest` within 1,048,576 bytes and forbids `response_too_large`; `prefix_over_limit` retains exactly limit+1 bytes, fixes the 1,048,576-byte limit, and requires only that failure code. A positively received provider rejection is exact `failureCode='provider_rejected_response'`, is `completed`, consumes the full request reservation, and is never semantically retried; it cannot masquerade as pre/post-claim `failed`. The Journal `resultRef` names that unusable artifact. For a normal request, trusted code publishes exact `RuntimeFailureEvidenceV1(failureKind='model_unusable_response')` rehashing it, and the generic-runtime StopIntent/TerminalDetail repeat that wrapper's ref/digest/failing op; a context-compaction failure instead uses its dedicated StopIntent subtype and immutable StopIntent ref as terminal primary evidence. It appends no model/batch/candidate/summary item. A response not positively known remains `unknown`; only literal `transport_exhausted` after the final exact failed attempt may authorize `model_attempts_exhausted`.

The Journal and retry-closure evidence are field-for-field canonical:

```ts
type ArtifactRef = string

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
```

A small `state_metadata` table may store only schema generation, active migration id, import receipt ref, and earliest event cursors; it is not execution authority. All schema constraints and typed repository validation apply to production, importer, recovery, and test helpers equally.

`state-owners.ts` exposes only the narrow owner lifecycle: read the sole active row/history; `bootstrapStateOwner`; `acquireStateOwnerAfterGracefulRelease`; `takeoverStateOwner`; and graceful terminalization. It stages exact process/root/lock/acquisition artifacts and validates their complete closure. Bootstrap requires an empty owner table, exact epoch-one `genesis` evidence, and one as-yet-unowned `KernelGenerationIdentityV1`: `fresh_empty` revalidates fixed empty database/CAS; `migrated_candidate` revalidates exact candidate/database-image/CAS/migration closure plus the matching already-durable Kernel authority marker and is the first Kernel repository transaction after cutover before admission/control release. The transaction may register only those staged artifact metadata and the owner row. Clean acquisition requires the latest exact graceful terminal row/evidence and epoch `n+1`; takeover validates exact predecessor process absence/mismatch and atomically terminalizes+appends the matching successor. Every other repository write/broker release requires current active process/root/lock equality. The only post-terminal non-repository exception is the already-prepared rollback marker rename; it cannot mutate DB/CAS. No reset, generic patch, or evidence-free transition exists.

The canonical artifact/storage boundary is closed as follows. `src/kernel/types.ts` exports these definitions exactly as written in the RFC, and `artifact-schemas.ts` rejects unknown fields, alternate discriminator spellings, missing required fields, illegal optional members, unsafe integers, or a locally invented superset before any typed transaction uses a ref:

```ts
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

type LocalSocketPeerObservationV2 = {
  schemaVersion: 2
  format: 'cliq-local-socket-peer-observation-v2'
  platform: 'macos' | 'linux'
  stateRootIdentityRef: ArtifactRef
  stateRootIdentityDigest: string
  endpoint: {
    canonicalRootRelativePath: 'runtime/control-v1.sock'
    fileType: 'unix_stream_socket'
    deviceId: string
    fileId: string
    ownerUid: number
    mode: 384
  }
  listenerSocket: {
    socketFamily: 'AF_UNIX'
    socketType: 'SOCK_STREAM'
    deviceId: string
    fileId: string
  }
  acceptedSocket: {
    socketFamily: 'AF_UNIX'
    socketType: 'SOCK_STREAM'
    deviceId: string
    fileId: string
  }
  credentialApi: 'macos_getpeereid' | 'linux_so_peercred'
  peerUid: number
  peerGid: number
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

type PolicyEngineProfileV1 = {
  schemaVersion: 1
  format: 'cliq-policy-engine-profile-v1'
  evaluator: 'cliq-policy-evaluator-v1'
  permissionGrammar: 'cliq-permission-grammar-v0'
  bashParser: 'cliq-bash-head-parser-v1'
  profileDigest: string
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

type RunObjectiveV1 = {
  schemaVersion: 1
  format: 'cliq-run-objective-v1'
  utf8: string
  byteCount: number
  objectiveDigest: string
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
```

| Canonical type | Required storage validation |
|---|---|
| `CanonicalTimeFenceV1` | Every durable time matches exact `YYYY-MM-DDTHH:mm:ss.sssZ`, Gregorian year `1970..9999`, valid fields, no leap second/24:00/offset/alternate fraction, and round-trips through one nonnegative safe-integer Unix millisecond. Comparisons/duration additions use checked integer math. One StateOwner-gated singleton samples one wall time per transaction, never accepts a value below its retained high-water, and commits fence advancement with the state mutation. Regression records `clock_regressed`, revokes/quiesces release gates, and rejects admission, lease renewal, grant/capability redemption, productive dispatch/retry, or expiry extension until current-owner recovery observes time at/above the high-water. |
| `LocalPrincipalIdentityV1` + `LocalSocketPeerObservationV2` + `LocalControlChannelIdentityV1` | Each omission digest rehashes. `principalId=H('cliq-local-principal-v1',stateRootIdentityDigest,platform,effectiveUid)`, and StateRoot owner uid equals the trusted process effective uid. In-process identity binds the signed current Supervisor process. RPC holds the listener and accepted sockets continuously; the separately observed root-relative filesystem endpoint is the same-uid mode `0600` Unix socket. Listener/accepted descriptor `fstat` identities and native `AF_UNIX`/`SOCK_STREAM` types are checked independently of the endpoint inode. Linux obtains peer uid/gid through `SO_PEERCRED`; macOS uses `getpeereid`. The peer uid equals the StateRoot owner. PID/start/image are diagnostic only. The UDS branch rehashes the V2 observation; the live connection capability is runtime-only, owner-epoch scoped, checked before replay/dispatch and revoked on close, owner loss or endpoint drift. The channel nonce hashes 32 fresh Supervisor bytes. Principal/channel fields are injected, never accepted from caller JSON/environment. A later authenticated channel may replay a retained response without changing original provenance. |
| `RunObjectiveV1` | Admission normalizes the public objective exactly once to NFC, rejects NUL and unpaired surrogate, requires exact UTF-8 `byteCount` in `1..262144`, and recomputes `objectiveDigest=SHA-256(JCS(objective with objectiveDigest omitted))`. `RunSpec.objectiveRef` is required, the final admitted-request digest and every normal prompt bind the same ref, and no inline request string, Session label, argv, worker field, or alternate artifact may reconstruct/replace it. |
| `EndpointModelNegotiationRequestV1` + `EndpointModelNegotiationResponseV1` | Every retained `EndpointModelNegotiationReceiptV1` must resolve both refs to these exact closed artifacts. The request repeats receipt owner, endpoint/TLS, provider/model, and adapter bytes, uses fixed protocol `cliq-model-capability-query-v1`, and contains the literal ordered five-claim tuple with `requestDigest` omitting itself. The response rehashes that exact request pair, repeats the protocol, contains the complete exact six-field `NormalizedModelCapabilityClaimsV1`, observation/validity times, and no diagnostic, raw body, extension, credential, header, cookie, or default-filled field; `responseDigest` omits itself and canonical JSON is at most 1 MiB. Receipt claims/times and every RunAssembly capability projection equal the decoded response byte-for-byte. |
| `RunAssemblyV1.retry.model` | The closed object is exactly `{maxDispatchedAttempts:3,maxZeroByteTransportRetriesPerAttempt:0,postAttemptDelaysMs:[500,2000]}`. There is no `maxRetryAfterMs`, adapter override, hidden same-attempt transport retry, or provider-controlled delay. A received `Retry-After` is part of a positively received response and cannot alter the schedule: provider rejection completes once as exact `ModelUnusableResponseV1(provider_rejected_response)`, consumes the full reservation, and is never retried. Only a genuinely failed/unknown dispatch follows the fixed attempt schedule and Run deadline. |
| `NormalPromptProjectionV1` + `ModelRequestV1` | Recompute omission digests and exact Run/op/attempt/assembly/projection identity. Normal projection equals the current RunSpec, ready ContextManifest, frontier and revision, with contiguous messages/calls/tools from frozen sources only; schemas/descriptions/refs equal the full exposed manifest. The common request binds exact native body bytes/path/count, streaming, output cap and fixed reservation. Re-preparation from retained typed data reproduces it. A compaction request additionally binds the current plan and its exact two-message envelope/source projection. Journal delta and completed turn request/projection pairs match. Context estimates never become hard-budget authority. |
| `WorkspaceInstructionSourceManifestV1` + instruction/skill provenance | `RunAssembly.instructions.workspaceInstructionsRef` always closed-decodes an exact `WorkspaceInstructionManifestV1`, including the empty case. Workspace Trust authorizes one separate declarative-context capture and grants no SourceManifest, private-generation, result/diff, publication, tool, or read authority. The instruction source workspace pair rehashes the Session's held live `WorkspaceIdentityV1`; `sourceDigest` omits itself. Descriptor-relative no-follow traversal captures every and only regular literal `AGENTS.md` or suffix `/AGENTS.md`; source entries are unique byte-sorted paths with exact depth, complete raw ref/digest/count, unchanged descriptor, literal mode `0600|0644`, link count one, matching workspace owner, and `sourceEntryDigest=SHA-256(JCS({canonicalRootRelativePath,directoryDepth,fileDescriptor,rawBytesRef,rawBytesDigest,rawByteCount}))`. More than 64 files/1 MiB total bytes, executable/group-or-other-writable/link/special/external input, owner/descriptor drift, scan race, or invalid text rejects admission. The instruction manifest repeats that source pair/workspace digest, orders all-and-only entries root-to-deep by `(directoryDepth,path)` with contiguous order, matches each `instructionSourceEntryDigest`, and decodes byte-identical NFC/LF-normalized NUL-free `ModelTextV1`; its digest omits itself. Every selected `SkillManifestV1` resolves one exact `SkillSourceIdentityV1`, exact nonempty `ModelTextV1` instruction, and all resources; all three provenance digests and `BundledSkillClosureV1.closureDigest` use canonical omit-self equations. Source files are the unique byte-sorted all-and-only `SKILL.md` plus resource set with exact raw refs/digests/counts. Descriptor-captured skill files are unchanged same-owner regular link-count-one files with literal `0600|0644|0700|0755`; executable modes remain data-only under `executable-disabled`. Workspace roots are held same-owner `0700|0755` and hash `{sourceScope:'workspace',workspaceIdentityDigest,rootDescriptor,canonicalRelativePath,fileDescriptor,rawBytesRef,rawBytesDigest,rawByteCount}`; user roots are owner-only `0700` and use the analogous principal projection. Neither joins SourceManifest or grants tool authority. Bundled identity files project byte-for-byte to the exact closure sequence and each hashes `{sourceScope:'bundled',bundledClosureDigest,canonicalRelativePath,rawBytesRef,rawBytesDigest,rawByteCount}`. The signed RuntimeBundle entry is exactly `role='skill_bundle',executable=false`, its signed complete-file `entry.digest` equals the content-addressed `bundledClosureRef`, and decoding those exact bytes yields `BundledSkillClosureV1` whose independently recomputed self-omitting `closureDigest` equals `bundledClosureDigest`; the complete-byte ref and semantic digest are distinct hash domains and are never required to equal. The graph is acyclic. Resources are bounded to 128/16 MiB, descriptor-contained, cycle/escape-free, byte-identical to source, and never executable by inclusion. `(sourceScope,skillId)` is unique, duplicate unqualified ids across scopes reject admission, and assembly order is authoritative. The normal system message is the exact nonempty-piece/two-LF join of base `systemPromptRef`, one all-scopes labeled workspace JCS block when nonempty, then one labeled skill JCS block per assembly skill in order. `ContextManifest` retains only `assemblyRef`; it cannot duplicate or reinterpret instruction/skill refs. |
| `RepositoryIdentityV1` | A live Git workspace opens literal in-root `.git` from the held root descriptor and rejects `.git` files, links, outside/linked directories, and owner/type/link-count mismatch. Directory device/file ids are unsigned decimal strings, owner uid is safe integer, object format is normalized `sha1|sha256`, and `repositoryIdentityDigest` is recomputed. |
| `WorkspaceIdentityV1` | `session.create` may publish only `kind='live'`: descriptor-walk an absolute path no-follow, require a same-principal-owned directory, canonicalize NFC platform spelling, and validate the exact root tuple. `rootIdentity.deviceId/fileId` are canonical unsigned decimal strings with no sign/leading zero and are never stored through a JS number; `ownerUid` is a safe integer. A live Git identity carries both exact repository ref+digest or a live non-Git identity carries neither. Import alone may publish `kind='legacy_unavailable'` with only audit path/reason/time; it has no root/repository fields and is execution-ineligible. Storage recomputes `identityDigest`, makes the Session ref immutable across fork, and requires every RunPolicy/grant/authorization/SourceManifest/instruction/verifier/dependency/child/delivery workspace/repository digest to equal the retained live artifacts. |
| `WorkspaceEntryManifest` + `SourceManifest` + `WorkspaceStateManifest` | Entry validation requires `entryCount=entries.length`, checked `byteCount=sum(file sizes + symlink-target UTF-8 bytes)`, and `treeDigest=SHA-256(JCS({schemaVersion:1,format:'cliq-workspace-entries-v1',entries}))`, with every blob/size/target digest revalidated. Source `entriesRef` decodes that exact manifest, repeats its tree digest, repeats the exact projection's frozen-ignore ref/digest, and uses `manifestDigest=SHA-256(JCS(SourceManifest with manifestDigest omitted))`; its workspace identity is live and Git member is present iff the retained repository identity exists. Workspace state independently decodes a complete entry manifest, resolves its exact base SourceManifest, matches projection/repository identity, requires `privateGitStateRef` iff Git, validates sorted unique disjoint invalidated paths, and uses `stateDigest=SHA-256(JCS(WorkspaceStateManifest with stateDigest omitted))`. Checkpoint owner Run/base ref/runId must match. |
| `GitIndexSnapshotV1` + `GitObjectPackV1` + `GitObjectClosureV1` + private Git types | Every Git index ref decodes the canonical version-2 semantic snapshot, rehashes exact retained bytes/count/tree/object format/repository identity, and rejects unmerged/gitlink/intent-to-add/split/sparse/unknown-mandatory/path-invalid/missing-object input before fixed normalization. Descriptor-held raw input and expanded canonical index each have a 64 MiB ceiling. An exactly absent literal `.git/index` under unchanged held root/Git descriptors normalizes to an empty v2 index only after a second absence check; case aliases, links and a newly appearing index reject. Every pack rehashes exact pack/index bytes and counts; fixed trusted `index-pack` validation proves trailer, unique byte-sorted object ids, object hashes, delta closure, and deterministic v2 index. The closure's unique byte-sorted packs contain every and only object reachable from private HEAD/refs/index, with every reachable object in exactly one pack; `packDigest`/`closureDigest` omit only themselves. `PrivateGitStateManifest` rehashes the exact index/object-closure/config pairs and its omission digest; the config is the displayed closed non-executable allowlist only. Every hook/remote/credential/include/helper/alias/pager/filter/attribute/diff/merge/fsmonitor/sshCommand/worktree/system/global/environment key is absent, and non-Git forbids the private-Git ref. |
| Workspace-generation identity/state/evidence | Every generation ref closed-decodes exact `WorkspaceGenerationIdentityV1` and rehashes `identityDigest`; its Run/live-workspace/source-Checkpoint/workspace-state/tree and StateRoot-backed platform locator match. `generationId=H(runId,sourceCheckpointId,sourceWorkspaceStateRef,creationNonceDigest)`. The one state row preserves those base fields, positive contiguous `rowVersion`, exact phase XOR, and canonical lifecycle. Snapshot evidence rewalks the exact generation/Checkpoint/entries/private-Git state, requires descriptor/file/directory fsync, and rehashes its omission digest. Every worker loss from `active|revoking|checkpointing` first commits `fenced_reconciling`, binds the exact `worker_death` wait plus prior phase/quiesce id, clears the Run pointer, and projects the sole WorkerLaunch to `reconciling/fenced_reconciling`; it cannot dispatch, checkpoint, seal, or be selected. Exact `WorkspaceGenerationQuarantineEvidenceV1` binds the current `sourceRowVersion`, derives the sole target `quarantine/workspace-generations/H(generationId,base-10 sourceRowVersion)`, proves no-replace descriptor rename, original-locator absence, directory fsync, current inspector, and exact `observedState=complete_tree|unreadable_partial`. Its closed matrix is materialization failure, preactivation failure, launch abort/no-spawn, launch death-before-activation/death, worker recovery only from `fenced_reconciling`, or checkpoint failure from `revoking|checkpointing`. Exact retirement is sealed+worker-dead or quarantined plus current-row literal zero counts for active pointers, nonretired launches, live containments, active mounts, and releasable broker claims. WorkerLaunch write state is a same-transaction denormalized projection. |
| `WorkerRecoveryEvidenceV1` | The base rehashes and equals the current worker-death wait, old launch/epoch/identity/containment, exact containment death proof, old immutable generation's last verified tree, and current inspector. Both dispositions must be wrapped by exact `WorkspaceGenerationQuarantineEvidenceV1(reason='worker_recovery',fromPhase='fenced_reconciling')` and atomically quarantine the old generation. `quarantined` forbids all restore fields. `restored_from_checkpoint` requires all three restore fields; the Checkpoint is ready and belongs to this Run, the workspace state matches it, and `replacementWorkspaceGenerationRef` is distinct from the old generation and decodes a separately materialized `preactivated_readonly` generation from that Checkpoint. Neither branch reopens or rewinds the old mutable directory. |
| `ModelTextV1` + `ObservedToolCallInputV1` + `ToolCallInputV1` | Model text uses exact UTF-8 byte length and `textDigest=SHA-256(JCS(text with textDigest omitted))`. Each assembled provider argument is at most 1,048,576 bytes and first becomes one exact observation: valid JSON is `jcs_json` with its retained JSON-domain value and RFC 8785 byte count; otherwise `utf8_json_fragment` retains and counts the exact assembled UTF-8. `observedInputDigest` omits itself, and the resolved/rejected input rehashes that observation, repeats the owning `AgentToolCall` id/index/name, and uses `inputDigest=SHA-256(JCS(input with inputDigest omitted))`. Only `resolved` contains the selected immutable input-schema ref/digest and schema-normalized object, forbids diagnostics, and may enter policy/grant/Journal/dispatch. `rejected_unknown_tool` forbids schema/value and requires its deterministic rehashed diagnostic; `rejected_invalid_input` requires the known schema and diagnostic but forbids value. Reparse, repair, alternate schema, missing observation, or disposition widening fails closed. |
| `ModelUnusableResponseV1` + `ModelTurnItem` + `ToolBatchItem` | A completed model Journal result is exact `AgentModelTurn XOR ModelUnusableResponseV1`. A usable turn alone can create items: both items require `textRef` and resolve `modelTurnRef` to that same turn; Run/model op/attempt/request match the completed Journal fact. Storage recomputes `AgentModelTurn.responseDigest` as `SHA-256(JCS({format:'cliq-agent-normalized-response-v1',provider,model,responseId?,continuation?,usage?,usageTrusted:false,negotiatedMode,requestDigest,stopReason,textRef,toolCalls,abortStopIntentRef?}))`, omitting absent optional members and retaining calls in index order; every value is copied byte-for-byte from the turn. It never hashes provider wire bytes or the self-containing turn. Each `textRef` equals the turn's sole `ModelTextV1` ref. For `tool_calls`, the complete ordered `(callId,index,toolName,inputRef,inputDigest)` sequence equals `ToolBatchItem.calls` byte-for-byte, and every input is one exact resolved/rejected artifact; its batch text ref equals that same turn text. An all-resolved batch alone may install a `tool` frontier. If any input is rejected while every call identity is valid, the same transaction appends the whole batch, one deterministic `error` for every rejected call, and `batch_not_executed` for every remaining call, then returns directly to `agent` with no dispatch. `end` has no calls and nonempty decoded text; `cancelled` has no call and requires the exact current pre-abort `abortStopIntentRef`. Provider `length|content_filter|unknown` maps to exact unusable failure codes and can never appear in `ModelTurnItem.stopReason`. Every positive unusable response—including exact `provider_rejected_response`—retains the exact complete bytes or exact limit+1 prefix, repeats request/provider/model/mode, rehashes its omission digest, consumes the full request reservation, and is a completed Journal result; for a normal request its generic-runtime stop is authorized only by exact `RuntimeFailureEvidenceV1(failureKind='model_unusable_response')`, while context compaction uses its dedicated StopIntent and immutable StopIntent primary ref. It creates no item/candidate/summary and no semantic retry. Unknown/no-response outcomes cannot masquerade as unusable, and a received rejection cannot become failed/retryable. |
| `RuntimeFailureEvidenceBaseV1` + `RuntimeFailureEvidenceV1` | `evidenceDigest=SHA-256(JCS(evidence with evidenceDigest omitted))`; Run/frontier/failing op equal the proposed Run and its current frontier, while inspector ref/digest decodes the current signed `SupervisorInspectorIdentityV1` within the five-second freshness bound. `model_unusable_response` rehashes the exact normal-model completed Journal result, including a positively received `provider_rejected_response`. `model_attempts_exhausted` names the final contiguous failed model attempt, its exact normal/compaction request and terminal Journal sequence, and only literal `transport_exhausted`; a received provider rejection cannot enter this branch. `credential_redemption_failed` is published under the credential-authority lock before target I/O and binds the assembly endpoint/grant, latest authority record/revisions, and exact time/platform-store failure. `retry_unknown_exhausted` rehashes the exact dedicated result and its Journal/settlement/dispatch-closure chain. `dependency_acquisition_failed` equals the current candidate plan plus final acquisition attempt/sequence. `local_service_identity_mismatch` rehashes the assembly provenance/service spec and current boundary evidence observed before provider release. Branch members are mutually exclusive. The generic-runtime StopIntent and TerminalReasonDetail repeat exactly this ref/digest and `failingOpId`; diagnostics, booleans, untyped Journal errors, or cross-branch fields are invalid. |
| `ToolResultItem` + `ToolResultPayloadV1` + `ToolResultModelContentV1` | Except for the dedicated fenced retry-unknown result below, every result ref closed-decodes exact `ToolResultPayloadV1`, recomputes `payloadDigest=SHA-256(JCS(payload with payloadDigest omitted))`, and repeats the item's Run/batch/call/index/tool/outcome plus the original call identity. `executed` names the exact completed Journal op/attempt/result and selected output schema pair. `denied` names either the immutable policy/decision digest or exact user `ApprovalDecisionV1`. `error` uses only the closed code set, always rehashes one diagnostic, and has `opId`, `attempt`, `journalErrorRef`, and `journalErrorDigest` all present together iff dispatch created that op. `batch_not_executed` stores the complete unique byte-sorted rejected call-id set from the same prevalidation transaction. Ordinary `cancelled` repeats the winning StopIntent and deterministic notice. Every ordinary payload also rehashes one exact identity/outcome-matched `ToolResultModelContentV1`; its canonical JSON is at most 1,048,576 bytes and is exactly normalized executed output or the closed ref-free synthetic projection for denied/error/batch-rejected/cancelled. Authority, audit, principal, policy, decision, StopIntent, Journal, diagnostic, attestation, and containment refs/digests are forbidden from model content. A terminally unused fenced `retry` unknown instead points directly to exact `RetryUnknownCancelledResult`; wrapping it in either ordinary artifact, projecting it to the model, or using that dedicated type for an ordinary result is invalid. |
| `InputResponseSchemaV1` + `InputPromptV1` + `UserInputModelContentV1` + `UserInputPayloadV1` + input items | `schemaDigest`, `promptDigest`, `contentDigest`, and `payloadDigest` each omit only themselves; every ref/digest rehashes exact bytes. The schema is at most 64 KiB JCS and accepts only the deterministic Cliq JSON-Schema-2020-12 subset (`type`, `properties`, `required`, `additionalProperties:false`, `items`, `enum`, `const`, numeric/string/array bounds), rejecting refs, remote ids, recursion/unevaluated composition, regex, format, defaults, coercion, custom/unknown keywords. Prompt text is exact NFC `ModelTextV1`, `maximumResponseBytes` is `1..1048576`, and the text branch forbids schema while JSON requires it. Text payload is NFC/no-NUL within the bound; JSON is finite, schema-valid without coercion/defaults, and its JCS bytes fit the bound; `byteCount` is exact. Prompt, payload, request item, user item, waiting subject, originating `request_input` call, and executed ToolResult repeat Run/batch/call/index; item `inputRef/inputDigest` rehashes the payload and principal equals authenticated request. Payload/item model-content refs equal one exact `UserInputModelContentV1` whose kind/value equal the payload and which forbids principal, prompt/schema, request, Run/call, and authority refs. The executed ToolResult model content equals only the same normalized value. |
| `VerifierRepairModelContentV1` + `VerifierRepairDiagnosticV1` + `RepairDiagnosticItem` | Each diagnostic and model-content digest omits only itself, every ref/digest rehashes exact bytes, and each diagnostic names the exact current-candidate/current-plan required verifier result and its `assertion_failed` receipt/stdout/stderr. The redaction algorithm accepts only `terminationReason='exit'` with a nonzero safe-integer exit code and deterministically emits the canonical NFC sentence `Verifier <JCS verifierId> failed an assertion (exit <base-10 exitCode>). Revise the candidate and try again.` into a <=4096-byte model artifact. It copies no stdout/stderr byte, path, environment, secret-like substring, authority, containment, principal, ref, or digest. Item result ids and entries are equal-length/nonempty/unique and ordered by contiguous verifier-plan index; each entry repeats its diagnostic/model-content pairs byte-for-byte. Prompt construction decodes only ordered model-content artifacts. |
| `SandboxProfileV1` | `profileDigest=SHA-256(JCS(profile with profileDigest omitted))`; `allowedOwners` is nonempty, unique, byte-sorted, and every launch owner is listed. Admission selects exactly one probed `macos_vm|linux_namespace` backend, fills missing public resource members with the RFC defaults, fixes IPC values to 16/64 MiB, and rejects rather than raises a host-infeasible request. RunSpec, RunAssembly backend, every plan/launch/profile ref+digest/backend, and each launch's inline resources/digest equal the decoded artifact. Admin/local-service producers use the same type with their exact owner set. Fixed policies permit only typed launch specs, no host/state-root/environment/network-at-spawn reachability, and typed broker-only post-release network/credentials; caller or worker widening is invalid. |
| `DependencyAcquisitionPlanBase` + `DependencyAcquisitionPlan` | Each candidate publishes one exact Node-only plan with `planDigest=SHA-256(JCS(plan with planDigest omitted))`. The package manifest is exactly root `package.json` with an exact content ref/digest; the selected adapter has exactly its literal root lock path (`npm-ci-v1 -> package-lock.json`, `pnpm-frozen-v1 -> pnpm-lock.yaml`, `yarn-immutable-v1 -> yarn.lock`) and matching ref/digest. Storage rejects workspace declarations, nested manifests/lockfiles, multiple supported root lockfiles, adapter/path mismatch, ambiguous roots, unpinned toolchain, unordered/duplicate endpoint or grant projections, and any alternate ecosystem. Every VerifierPlan/dependency policy/template/grant/cache/effect repeats the identical plan pair. |
| `DependencyReadyItem` | The ready reducer accepts only the current candidate-derived plan and exact completed dependency-acquisition Journal `opId/attempt`; `packageCacheManifestRef` decodes the exact matching cache manifest. In the same transaction it appends the item, budget settlement, and a post-effect ready Checkpoint, sets `readyCheckpointId` to that Checkpoint, and moves the unchanged verify frontier to `phase='verifiers'`. The Checkpoint belongs to the same Run and includes this item plus the completed Journal sequence. Its `workspaceStateRef` decodes exact `WorkspaceStateManifest`; that state's `entriesRef` decodes exact `WorkspaceEntryManifest`; and `installedTreeDigest` equals that entry manifest's `treeDigest`. A caller-supplied digest, pre-effect Checkpoint, different plan/op/attempt/cache, or independently committed item/Checkpoint is invalid. |
| `WorkspaceDiffOperationV1` + `WorkspaceDiffV1` | Both refs decode exact SourceManifests for one workspace/projection lineage. Storage compares their decoded unique byte-sorted path maps and requires `operations` to be the exact unique byte-sorted-by-path difference: only-result is `add` with the exact result entry, only-base is `delete` with the exact base entry, unequal entries are `modify` with exact before/after, and equal entries emit no operation. Path/kind/entry branch fields are closed; duplicate, unsorted, omitted, extra, or no-op operations fail. `diffDigest=SHA-256(JCS(diff with diffDigest omitted))`, and every consumer's base/result refs must equal the decoded diff. |
| `FinalCandidateItemBase` + `FinalCandidateItem` | Candidate base/result refs equal its exact decoded `WorkspaceDiffV1`; `sourceDigest` equals the decoded result `SourceManifest.manifestDigest`, and `diffDigest` equals the decoded diff's digest. `operation='agent'` requires `producingItemId` to name the exact positively completed `ModelTurnItem(stopReason='end')`, requires `producingOpId` to equal that item/Journal model op, and requires `summaryRef` to equal the producing turn's required `ModelTextV1` ref. `operation='delivery'` requires `producingItemId` to name the exact `DeliveryMergeItem`, requires `summaryRef` to equal that item's summary ref, and forbids `producingOpId`. Finalize and `RunResult` must repeat candidate base/result/diff and the identical `summaryRef`; an alternate summary, digest-only match, cross-operation producer, or optionalized discriminator member is invalid. |
| `SessionRunTerminalItem` | Exactly one item per root Run uses format `cliq-session-run-terminal-v1`; `itemKey` is literal ``run-terminal:${Run.id}``, `runId===Run.id`, `operation===decoded RunSpec.operation`, and `admittedSessionItemSeq===decoded AdmittedContextManifest.throughSessionItemSeq` reached through that RunSpec. Status/reason equal the terminal Run. Success/unverified requires exact Run `resultRef`, forbids terminal detail, and requires `summaryRef/summaryDigest` equal decoded `RunResult.summaryRef` and that exact `ModelTextV1.textDigest`; failed/cancelled requires `terminalDetailRef===Run.terminalDetailRef` and forbids result/summary. The terminal transaction atomically appends it and one never-coalesced one-item Session raw segment. Model rendering is exactly JCS `{kind,runId,operation,status,terminalReason,resultRef?,summaryRef?}` with absent optionals omitted; admitted Session cursor, terminal detail, and summary digest remain audit-only. Child Runs never append this item. |
| `SessionHandoffEntryV1` + `SessionHandoffV1` | One read snapshot validates Session revision and a cursor that is zero or an exact current segment end. Raw terminal and summary entries/excluded ranges are complete, contiguous-indexed, and in stored encounter order; source refs/digests and workspace/projection refs/digests rehash exactly. `handoffDigest` omits itself. JSON is exact JCS; Markdown uses the one fixed RFC renderer and exact UTF-8 digest. Same Session/revision/cursor returns identical refs. Mutable paths, checkpoints, principals, credentials/grants/receipt bodies, hidden transcripts, timestamps/randomness, adapter render options, or legacy/control payloads are forbidden. |
| `ContextSegment` + `RunContextCompactionItem` | A summary segment and its compaction item repeat the exact completed tools-disabled compaction turn `ModelTextV1` `summaryRef/summaryDigest`, covered range, and source digest; `summaryDigest` equals decoded `textDigest`. Raw ranges name every exact item; excluded-control ranges project no model content. Compaction publishes item/new ContextManifest/ready Checkpoint atomically, preserves raw items, and replaces only the authorized range. Caller/worker-substituted summary text, digest-only match, tool-bearing/non-end/oversize response, missing preserved ref, or alternate segment interpretation is invalid. |
| `FrozenIgnoreRulesV1` + `SourceProjectionSpec` + `SourceIncludeClassificationEvidenceV1` + `SourceIncludeAuthorizationV1` | The rules manifest closed-decodes `cliq-frozen-ignore-rules-v1`, recomputes its omission digest, enforces exact `cliq-git-wildmatch-v1` source/rule ordering and content refs/digests, requires repository digest iff Git, and uses empty source/rules arrays for non-Git. Projection requires `schemaVersion=1`, exact matcher, rules ref/digest equality, bounded root-relative selectors, and `projectionDigest=SHA-256(JCS(spec with projectionDigest omitted))`. Every include authorization recomputes selector/authorization digests and matches principal/Run/Session/live workspace/admission intent. `builtin_nonignored` requires exact `cliq-source-include-classification-v1` evidence: a nonempty unique byte-sorted entry set exactly covers the descriptor-selected captured entries; every `workspaceEntryDigest=SHA-256(JCS(exact WorkspaceEntry))`; device/file decimal ids and link count come from those held no-follow descriptors; each entry is either proven tracked by the identical retained Git index or nonignored under the exact frozen rules; optional Git-index ref/tree fields are both present iff required; and `evidenceDigest=SHA-256(JCS(evidence with evidenceDigest omitted))`. Its authorization repeats that exact evidence ref/digest. `consumed_user_read_grant` requires the exact read-scope grant target and `AuthorizationConsumptionReceiptV1(run_admission)`. Outside-root or unauthenticated ignored inclusion is invalid. |
| `PolicyEngineProfileV1` + `RunPolicySnapshotV1` + `PolicyChannelEvidenceV1` | Every `policyRef` decodes as `schemaVersion=1/format='cliq-run-policy-v1'`; principal/workspace/tool-manifest identities equal the admitted Run assembly, `policyDigest` is recomputed, and `decisionRules` remains the exact closed `cliq-permission-grammar-v0` program including `named-action`. The engine's RuntimeBundle equals the assembly; `profileEntryId` and engine version equal the sole signed non-executable `policy_engine` data entry, that entry's signed complete-file `entry.digest` equals `engine.profileRef`, and decoding those exact bytes yields `PolicyEngineProfileV1` whose independently recomputed self-omitting `profileDigest` equals `engine.profileDigest`. The complete-byte ref and semantic digest are distinct hash domains and are never required to equal. Fixed signed Supervisor code alone interprets its three literal evaluator/grammar/parser ids; no executable helper, plugin load, or SandboxLaunch exists. Before approval/grant/denial/Journal prepare, that fixed interpreter and retained profile publish one evidence artifact, and storage reruns them over the immutable request/target to compare complete JCS output. Evidence rehashes policy/principal/Run/frontier/op/request/target/action/time and exactly one channel projection: nonempty unique byte-sorted canonical paths; registered MCP id/tool; normalized plan identity; exact argv/shell-text plus the fixed Bash parser's outer head, lexical nested builtin-deny heads, and unsafe flag; or exact named verifier/dependency/delivery/MCP-server/child identity plus canonical literal `identityKey`. Named-action branch fields/action class equal the prospective subject/grant/request/target. Rule precedence, matched-rule cardinality, mode fallback, repository narrowing, empty/unsafe Bash behavior, and effective disposition recompute exactly. Caller/worker booleans, host-shell reparse, mutable engine/parser/profile, alternate primary key, executable helper, or semantic-version compatibility are invalid. |
| `ApprovalDecisionV1` + policy decision/denial/skip types | Every approval decision closed-decodes `format='cliq-approval-decision-v1'`, recomputes `decisionId`, `waitingSubjectDigest`, `subjectDigest`, and `decisionDigest=SHA-256(JCS(decision with decisionDigest omitted))`, and repeats the authenticated principal, Run, exact current wait/frontier/subject, request id/digest, and expected Run revision. Its `ApprovalSubject` contains the exact ask-evidence pair and complete closed subject: a tool call includes call index/name/contract/replay class plus `ordinary_tool` XOR `child_delegate(childMode)`, while named verifier/MCP-server/delivery/dependency fields preserve every canonical source/plan/index/spec/registry/operation-set/install-script identity. The evidence rehashes and byte-matches that full subject, policy/frontier/op/request/target. `requestedTtlMs` is present iff supplied; `grantExpiresAt` is present iff an allow creates authority and equals that grant's expiry, otherwise absent. `PolicyDecisionItem` is the exact direct-versus-interactive union: `direct_policy` forbids `waitingSubjectRef`, requires `decisionRef===policyChannelEvidenceRef`, and accepts only recomputed allow/deny; `interactive_approval` requires the exact current wait and an exact `ApprovalDecisionV1` whose evidence disposition was `ask`. Allow requires exact grant and forbids denial outcome. Deny forbids grant and requires exactly one subject-matched `PolicyDenialOutcomeV1`: tool/MCP denied result; required-verifier StopIntent; advisory-verifier skip; delivery StopIntent; or dependency-script StopIntent. `VerifierSkipItem` is `skipped_by_user` with no evidence digest or `skipped_by_policy` with `decisionRef===policyChannelEvidenceRef` and matching digest. Direct required verifier/delivery/dependency denial uses exact `origin='policy_deny'` StopIntent with the same evidence pair; interactive branches use their approval outcome and no phantom direct wait. A decision/item cannot cross a wait, parser result, subject, target, frontier, request, principal, revision, or outcome branch. |
| `OperationGrantV1` | Every Journal, broker, verifier, MCP, delivery, dependency, and child-delegate `grantRef` decodes as `format='cliq-operation-grant-v1'`. Storage recomputes `grantDigest`, validates the full subject/provenance union and exact Run/principal/policy/frontier/op/request/target identity, and derives bounded use from immutable attempts/lifecycle rows rather than a resettable counter. `provenance.kind='policy_snapshot'` requires exact `PolicyChannelEvidenceV1` with `effectiveDisposition='allow'`, identical action/rules/request/target/policy/frontier/op, and the canonical decision digest. `provenance.kind='user_approval'` requires the exact committed allow `ApprovalDecisionV1` for that wait/request/frontier/target, repeats its exact ask-evidence pair, and has identical `grantExpiresAt`; `provenance.kind='verifier_template'` instead requires the exact `AuthorizationConsumptionReceiptV1` that created the template. None may decode or reparse another artifact kind. |
| `AuthorizationGrantV1` + `AuthorizationConsumptionReceiptV1` | `targetDigest`, `grantCoreDigest`, `rowDigest`, and `receiptDigest` are recomputed. Only `active(rowVersion=1,useCount=0) -> consumed(rowVersion=2,useCount=1)` or `active -> revoked(rowVersion=2,useCount=0)` is legal; consumption and its identity-matched Run-admission, MCP-registration, or authorization-derivation consumer commit atomically. `consumer.kind='run_admission'` binds the exact `runId` plus pre-resolution `admissionIntentDigest`, never the later final admitted-request digest; this is the acyclic receipt boundary. Terminal rows are immutable. |
| `ChildHandleItem` + `ChildResultModelContentV1` + `ChildResultItem` + `ChildAllocationV1` | Child admission appends one handle whose parent Run, owning delegate batch/call/index/op, child Run, exact admitted spec, and mode equal the newly reserved allocation and deterministic child admission identity; duplicate, skipped, cross-batch, cross-parent, or caller-substituted handles are invalid. Success terminal `resultRef` equals the child Run's sole committed `Run.resultRef` and decodes exact `RunResult`; failed/cancelled structurally forbids result and requires exact `Run.terminalDetailRef`. Read-only success forbids patch; mutating success requires exact `ChildPatchManifest` whose base equals child RunSpec, result/diff equal RunResult, operations equal the exact byte-sorted `WorkspaceDiffV1` projection, and omission digest revalidates. Every item/allocation terminal repeats one identical model-content pair: success summary is exact UTF-8 from RunResult `ModelTextV1.summaryRef`; stop content contains only status and terminal reason. No result/detail/diagnostic/policy/receipt/budget/ref enters it. Delivery wait identity, child id/mode/status, result-or-detail, patch, model content, and inclusive usage are byte-identical across allocation and parent-owned item. `reserved` forbids terminal fields; `child_terminal` binds that exact terminal and bounded usage; `settled` preserves them, names the owned item/parent revision, and proves component-wise `releasedUnusedBudget = grantedAdditiveCeilings - inclusiveBudgetUsage`. |
| `DependencyInstallScriptsAuthorizationTemplateV1` | `DependencyPolicy.installScriptsGrantRef` may name only this type. Admission consumes the exact dependency-script authorization and atomically publishes a template whose Run/principal/workspace/receipt/toolchain/adapter/lockfile/registry/deadline/candidate bounds match the admitted Run; `templateDigest` is recomputed. |
| `VerificationClosureV1` + `InheritedVerificationProvenanceV1` + `DeliveryTerminalProjectionEvidence` | Only the verification closure may satisfy a finalize frontier or `RunResult.verificationClosureRef`. Storage recomputes `closureDigest`, validates candidate/source/plan/dependency and every required/advisory disposition against items, Journal facts, receipts, Checkpoints, and consent, then re-walks the same closure in `commitRunResult`. An `inherited_verified` closure or delivery `RunResult.verificationProvenanceRef` accepts only `format='cliq-inherited-verification-provenance-v1'`; `provenanceDigest=SHA-256(JCS(provenance with provenanceDigest omitted))`, the immutable source must be `succeeded(verified)`, and its exact result/result digest, required source closure/ref/digest, result source, verifier spec/ref/digest, and ordered receipt refs/digests must match while `deliveryRunId` and identical result source name the consumer. Agent finalize/result forbid delivery projection evidence. Delivery finalize/result require the identical exact forward-finalize projection evidence ref; storage recomputes its digest and revalidates delivery Run/plan/selected branch/source/path-state/result-item/unstarted-operation/abort/transient/projection/git-index observations. |
| `InvocationAmbiguityEvidenceV1` | `evidenceDigest=SHA-256(JCS(evidence with evidenceDigest omitted))`; the Run/frontier/op/kind/attempt/dispatch/claim sequence, immutable request/target pairs, claiming Supervisor/StateOwner epoch, current inspector, and observation time equal the exact claimed attempt and transaction entering `unknown`. `claim_owner_lost` rehashes exact `StateOwnerAcquisitionEvidenceV1(takeover_after_owner_death)` and requires the strictly newer active owner. `broker_channel_lost_after_claim` is only model/tool/MCP with the claim's stored broker-token digest, same live owner, one closed post-release failure code, and durable-terminal-result absence. `sandbox_channel_lost_after_claim` is only tool/MCP-server/MCP/verifier with the claim's exact SandboxLaunch/containment and either same-owner post-deadline authenticated channel close or exact all-descendant death, both with no durable terminal result. `publication_path_ambiguous` is only publish and exact `PublicationProofV1(kind='path_ambiguity')`. Mechanism/op mismatch, free error text, missing digest pair, stale inspector, caller/worker payload, or evidence proving a definite outcome is invalid. |
| `ManualAbandonAttestationV1` | Storage accepts only `format='cliq-manual-abandon-attestation-v1'` created from authenticated `acknowledgeExactRisk:true`. Principal/channel/request id+digest, Run/current wait/frontier, exact unknown Journal op/attempt/seq, immutable operation request/ref+digest, target/ref+digest, and the exact unknown row's `InvocationAmbiguityEvidenceV1` ref+digest must match byte-for-byte; `acknowledgedRisk` is the one canonical literal and `attestationDigest=SHA-256(JCS(attestation with attestationDigest omitted))`. The abandoned Journal row forbids its own evidence pair; the identical attestation ref is required by Journal `abandoned`, the manual Stop/Terminal closure, and the terminal-only `ToolAbandonedItem` when call-originated. |
| `BudgetSettlementV1` + `PostClaimNoReleaseEvidenceV1` + dispatch closure | Storage recomputes every omission digest and exact Journal identity. Settlement sequences/phase/counters satisfy the canonical equations; pre-dispatch failure and exact post-claim-no-release consume zero, while every released or possibly released model terminal/unknown consumes the full request-bound reservation. `PostClaimNoReleaseEvidenceV1` repeats the exact claim/request/target/optional grant and same still-live claiming Supervisor/StateOwner, uses a current inspector observed within five seconds, and proves exactly one closed branch before the second release gate: under the broker mutex revoke the still-unreleased matching token and observe zero active releases, or rehash the exact SandboxLaunchSpec plus exact `ProcessContainmentNoSpawnEvidenceV1`. It commits atomically with post-claim `failed` and zero settlement before releasing the corresponding mutex/spawn authority. Restart, owner change, missing token, observed release/process, partial rollback, generic death, adapter assertion, or inline boolean cannot produce it. Retry-unknown terminal abandonment accepts only exact `InvocationDispatchClosureEvidenceV1`: `containment_death` rehashes the actual containment plus exact death evidence; `broker_release_fenced` is legal only for a broker/no-child claim with stored token digest and rehashes one exact `BrokerReleaseFenceEvidenceV1`. That artifact repeats request/target/grant/dispatch/claiming owner, current inspector with strictly newer owner epoch, identical token digest, and the literal revoked-plus-zero-active-release action/times. Lease/socket/Supervisor drift or an inline boolean is never proof. |
| `KernelIntegrityEvidenceV1` | Storage recomputes the omission digest and requires Run/source projection/generation/current inspector to match the frozen RunSpec and exact verifier or dependency Journal claim. `audited_write_attempt` is accepted only from the strong filesystem/broker blocked boundary, repeats exact request/containment/SandboxLaunch/path/access/enforcement identity, proves `sourceBeforeRef===sourceAfterRef` and equal digests, and forbids changed entries. `source_digest_drift` rehashes unequal exact SourceManifests plus a nonempty unique byte-sorted changed-entry set and enforces its source XOR: `trusted_out_of_containment_rehash` forbids containment/spec, while `claimed_process_rehash` requires both and matches the owning claim. Verifier versus dependency subject fields form an exact XOR. Both kernel-integrity StopIntent branches require `integrityEvidenceRef` and digest to name this identical artifact; TerminalReasonDetail and terminal primary evidence repeat that branch ref, while `StopIntentBase` has no generic evidence. Dependency readiness/completion and generic/text/adapter evidence are forbidden. |
| MCP recovery artifacts | `RequestedMcpRecoveryV1` and `McpProbedToolInterfaceV1` closed-decode as the pre-probe intent and raw interface types: the request contains no final profile/template/predicate/contract/registry digest, while each byte-sorted unique interface recomputes `interfaceDigest` and carries no recovery. `McpRetryRiskConsentV1`, `McpRetrySafetyAssertionV1`, `McpRecoveryAdapterManifestV1`, `McpRecoveryStatusRequestTemplateV1`, and `McpRecoveryPredicateV1` closed-decode with their exact formats, omission-rule digests, bounded predicate IR, signed RuntimeBundle adapter role, and registration/tool/request identities. The trusted reducer requires every explicitly requested tool name to match exactly one raw interface, applies that intent only to the matching final `McpToolContract`, and assigns exact `manual` recovery to every unrequested discovered interface; extra valid interfaces are retained rather than rejected. `McpRegistryRevision` recovery refs/digests must then reach those exact artifacts and schemas/transport/receipt closure. The registry core -> probe receipt -> final revision publication remains acyclic and no mutable executable, script, regex, alternate endpoint, or unrooted transitive ref is accepted. |
| Loaded model authority and native requests | Verify the exact retained adapter/runtime, signed capability/pricing ceilings, tool/schema closure, system prompt and three-member compaction envelope once on load/recovery. Per-attempt validation binds changing typed projection/invocation, exact native bytes, output cap and full reservation through `ModelRequestV1`; copied or substituted authority cannot change it. There are no custom tokenizers, framed prompts, request profiles or runtime golden-vector interpretation. |
| `McpServerInstanceIdentityV1` + `McpServerLaunchReceiptV1` | Identity and receipt omission digests are recomputed. Instance Run/batch/call/index, registration/revision and `registryManifestDigest`, lifecycle, launch Journal op/attempt/dispatch, SandboxLaunch, containment, nonce, initialize/capability/`probedToolsListDigest`, and time must equal the exact call request, immutable registry, claim, and actual call-scoped containment. The receipt rehashes that identity, names the same launch's prepared/claimed/completed Journal sequence chain and exact completed `BudgetSettlementV1`, and resolves the identity-matched stopped item plus exact whole-containment death evidence. Only one transaction may commit `mcp-server/completed`, the receipt, stopped item, visible ToolResult, settlement, and frontier advance; an unproven or incomplete teardown remains open and cannot be represented by a completed launch or reused instance. |
| `ReconciliationProbeStateV1` + probe evidence | Waiting storage validates the exact five-phase probe-state XOR: manual-only zeros; count-zero pending forbids evidence; count-1..7 pending and count-8 exhausted require an exact wrapper pair; and each in-flight branch embeds one complete `ReconciliationProbeDispatchV1` with kind/ordinal/count, nonce, 30-second deadline, owning Supervisor, subject digest, and subject-specific broker/task identity. Every completion first closed-decodes exact `ReconciliationProbeEvidenceV1`, recomputes its omission digest, and matches Run/wait digest plus the complete persisted dispatch digest/fields, inspector, and observation time. `subject_observation` rehashes exactly one subject-valid `McpRecoveryProbeEvidenceV1|PublicationProofV1|WorkerRecoveryEvidenceV1`; MCP evidence repeats the dispatch and broker identities. `probe_timeout` is accepted only at/after the deadline and rehashes exact `ReconciliationProbeTimeoutClosureV1`: MCP positively revokes and drains the named dispatch/target/fence, while publication/worker use exact `ReconciliationInspectorTaskClosureV1` to prove same-owner cancellation-and-join or successor takeover after owner death. Timeout is unresolved-only. No public payload, in-memory-only dispatch, generic/direct last-evidence ref, late closed-nonce advance, or mismatched wrapper/branch is accepted. |
| `PublicationPathObservationV1` + `PublicationProofV1` | Every proof closed-decodes the exact base plus one canonical branch and recomputes `proofDigest` with only that member omitted. Delivery Run/plan, live workspace identity, current exact `SupervisorInspectorIdentityV1`, and observation time match the delivery frontier and transaction. Each observation validates a canonical root-relative path, exact `PathState`, unsigned-decimal descriptor identities, positive link counts, and the entry-field XOR. Branch validators enforce the exact operation/Journal/dispatch, before/after, directory-fsync, preserved-preimage, descendant, ambiguity, transient-absence, projection-closure, and captured-versus-observed Git-index fields; every observation/result/preimage ref is rehashed and identity-matched. A generic boolean, path string, worker assertion, or proof kind substituted across a reconciliation, Journal, delivery, abort, or terminal edge is invalid. |
| `SandboxLaunchSpecV1` | Storage closed-decodes the exact four-owner union and every runtime/process-invocation/environment/filesystem/mount/resource/profile/plan digest and forbidden field. Worker/admin/local-service rows require their exact preactivation ref. A process-spawning Journal attempt forbids it while `prepared`, binds one exact `run_invocation` spec at `dispatch_claimed`, and repeats the same ref thereafter; non-spawning attempts forbid it. |
| `InterpreterIdentityV1` + `SandboxRootImageV1` | A workspace-script verifier accepts a mandatory interpreter ref+digest only. Storage recomputes the interpreter omission digest and requires the exact retained signed guest-toolchain manifest/tool/path/version/executable plus literal `script_path_as_first_argument-v1` to equal the consumed execution-identity grant, verifier command, and SandboxExecutable. Root-image omission digest resolves one non-executable signed RuntimeBundle `sandbox_root_profile` entry by ref/manifest/id/version/digest and fixes the fresh tmpfs/directories/uid/no-network/nonpersistent contract. Every isolated-root plan, SandboxFilesystem, and actual containment repeats that identical root-image pair. Optional/ambient interpreter, missing digest, or host/mutable/reused/caller-selected root is invalid. |
| `GuestToolchainManifest` | Storage recomputes `manifestDigest=SHA-256(JCS(manifest with manifestDigest and signatureRef omitted))`, verifies `signatureRef` through the bundled Cliq release key, and validates unique bounded executable identities. `guestImageRef` resolves the complete immutable `raw-ext4-v1` bytes, `guestImageDigest` equals their SHA-256/ArtifactRef, and `guestImageByteCount` is their exact positive safe-integer length. Every macOS containment plan, `SandboxRuntimeBindingV1`, actual containment, launch evidence, assembly/recovery closure, and reboot relaunch repeats the identical image ref/digest; a digest-only/current-installed-image lookup is invalid. |
| `ProcessContainmentPlanV1` + `ProcessContainment` | Every worker/admin/invocation/local-service pre-spawn plan validates `planDigest`, the exact discriminated owner, filesystem/parent XOR, launch nonce, and backend reservation against its reserving row/claim. The actual containment repeats the plan, owner/filesystem/parent/nonce/backend identities and the exact launch-spec ref/digest; no root PID or alternate owner is substitutable. |
| `PlatformProcessIdentityV1` + `StateRootIdentityV1` + `StateLockIdentityV1` + StateOwner evidence/record | All identity types recompute omission digests and exact held descriptor/process facts. `StateOwnerAcquisitionEvidenceV1` common identity equals the resulting row and distinguishes genesis, latest-graceful clean acquisition, and same-transaction death takeover. Genesis names exact as-yet-unowned `KernelGenerationIdentityV1`; `fresh_empty` proves empty image/CAS, while `migrated_candidate` proves the durable matching Kernel authority marker and exact candidate/image/CAS closure and occurs first post-cutover. Transition evidence/row digests and all prior/successor fields are exact; graceful has no successor and takeover atomically terminalizes+appends after exact process death. Epochs remain positive, unique, contiguous, never reused. Only three acquisition transactions bypass active ownership and write only named artifact metadata/rows; every other repository mutation needs the decoded active process and held root/lock. |
| `SupervisorInspectorIdentityV1` | The artifact closed-decodes only `schemaVersion=1/format='cliq-supervisor-inspector-identity-v1'`; `identityDigest=SHA-256(JCS(identity with identityDigest omitted))`. Its signed RuntimeBundle manifest rehashes to the exact ref/digest and contains exactly the named role-`supervisor` executable entry with matching entry version and executable digest. Supervisor instance, current `stateOwnerEpoch`, RuntimeBundle/entry, exact process ref+digest, exact lock ref+digest, instance nonce, and activation time match the sole active `StateOwnerRecordV1` held throughout evidence inspection/commit. An identity becomes historical on ownership change and cannot justify later evidence. |
| `ProcessContainmentNoSpawnEvidenceV1` | Pre-spawn failure/retirement accepts only exact plan/launch-spec ref+digest/owner/nonce/backend-locator equality plus the canonical absent-or-empty resource and zero-matching-process observations. `inspectorIdentityRef` resolves to exact `SupervisorInspectorIdentityV1`; the evidence repeats its digest, names the same current state-owning Supervisor, and is no older than the canonical default/max five seconds inside the transaction. |
| `ProcessContainmentDeathEvidenceV1` | Post-spawn retirement, Checkpoint, result, verifier, MCP, replacement, or terminal closure accepts only exact containment/plan/launch-spec ref+digest/owner/nonce/backend equality plus all-descendants-dead observations. `inspectorIdentityRef` resolves to exact `SupervisorInspectorIdentityV1`; the evidence repeats its digest, names the same current state-owning Supervisor, and is no older than the canonical default/max five seconds inside the transaction. |
| `AdminProbePayloadCoreV1` | The preactivation core is exactly `format='cliq-admin-probe-payload-core-v1'`, binds probe kind, signed runtime/adapter identity, fixed `mcp-initialize-capabilities-tools-list-v1` recipe, response bound, and recomputed `payloadCoreDigest`, and contains no containment, lease, dispatch, request-claim, credential, or Run identity. `AdminOperation`, admin SandboxLaunch, and later BrokerRequest must point to the same ref. |
| Admin probe terminal artifacts | `McpAdminProbeResultV1`, `AdminProbeClosureEvidenceV1`, and `AdminProbeErrorV1` closed-decode their literal formats and omission digests; every other ref/digest pair rehashes exact bytes. Result is released-dispatch-only and repeats operation/attempt/request/target/core/containment; bounded secret-free initialize/capability/tools responses reproduce the protocol projections, while unique byte-sorted raw `McpProbedToolInterfaceV1` rows recompute their `interfaceDigest` values and `probedToolsListDigest`. The result forbids requested recovery intent, final recovery/profile/template/predicate/tool-contract, `toolsListDigest`, registry-core, and registry-manifest fields. Closure is exact pre-release no-spawn XOR actual-containment-dead with phase-valid dispatch/request and current inspector. Error repeats that closure and a bounded redacted diagnostic; its deterministic-rejection union exactly controls `final_rejection` versus recovery `retryable_recovery|retry_exhausted`. Admin row terminal result/evidence/error/control-response pairs must equal these artifacts and are forbidden in every other phase. |
| `LocalModelObjectClosureV1` | The closure rehashes the exact current `StateRootIdentityV1`, fixes literal store path `local-models/objects`, and binds one signed model manifest. `objects` is all-and-only one manifest entry, one tokenizer entry, then the manifest's byte-sorted model-file entries; every ref equals its digest and rehashes the exact object at its content-addressed store path, logical paths and positive safe-integer sizes equal the manifest, `objectCount` equals length, `totalBytes` is the checked sum, and `closureDigest` omits itself. A `LocalModelRegistrationV1.objectClosure` and `expectedObjectClosureRef` must decode to byte-identical JCS; opaque store ids, mutable lookups, download caches, or post-enrollment paths are invalid. |
| `LocalInferenceServiceSpecV1` + activation-cycle types + `LocalInferenceServiceLaunchV1` | The service spec binds one owner, signed RuntimeBundle entry with role `local_inference`, signed model manifest, canonical loopback endpoint, backend/profile/resources, and the canonical `serviceSpecCoreDigest -> serviceId -> serviceSpecDigest` derivation; the selected registration separately retains its exact `LocalModelObjectClosureV1`. The cycle validates exact ordered request/Run-frontier participants, service-level ordinal/singleflight, phase/attempt/launch-id cardinality, retry time, boundary/failure XOR, `cycleDigest`, and exact `LocalInferenceActivationFailureV1`. The launch closed-decodes `reserved|preactivated|active|revoking|retired`, enforces every required/forbidden field, exact cycle/attempt identity, one unretired launch, exact spec/plan/SandboxLaunch equality, and row-only lease renewal. |
| `LocalInferenceBoundaryEvidenceV1` + `LocalZeroCostProvenanceV1` | Boundary evidence repeats owner/service/spec/launch/runtime/model/containment/plan/SandboxLaunch/backend identity, proves denied external egress and loopback-only traffic, and is current-Supervisor/freshness bound. Provenance retains only the stable service projection; a Run using `local_zero_cost` must reach the matching current launch/evidence/model/capability closure through its assembly. |

These are artifacts where the RFC defines artifacts and rows where it defines rows; this package does not create duplicate policy/grant/template/closure/containment sidecar tables or a second mutable authority. A verified hash alone is insufficient: every consuming transaction follows the typed references and revalidates the cross-row identity it relies on.

Session projection artifacts use the exact canonical shapes:

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

`createSession` must build only `WorkspaceIdentityV1.kind='live'` before the Session transaction by descriptor-relative no-follow traversal, not `realpath` string hashing. It holds/revalidates the root descriptor, exact owner, `deviceId`/`fileId` decimal strings, artifact digest, and canonical path through publication. For Git it also opens literal in-root `.git` from that descriptor, publishes exact `RepositoryIdentityV1`, and requires workspace repository ref+digest together; non-Git requires both absent. `forkSession` copies the exact immutable `workspaceIdentityRef`; it never recaptures or retargets a child. Every later capture, authorization, admission, apply, and publication requires `kind='live'`, reopens `canonicalRootPath` no-follow, and validates the same root tuple plus exact repository artifact when present. Root/`.git` move or replacement, repository-identity mismatch, or artifact/digest mismatch returns `ARTIFACT_MISMATCH` and requires a new Session. `legacy_unavailable` Sessions and every fork that retains such a ref remain context-readable/compactable/exportable but are structurally rejected by Run admission and `run.apply`.

The Session repository resolves a logical immutable `1..latestItemSeq` stream across the exact ancestor chain rather than requiring every sequence to be physically owned by the child. Projection segments are ordered, nonoverlapping, cover `1..throughItemSeq`, and match the Session id/revision/latest sequence. A raw segment names exactly one validated `{sourceSessionId,itemSeq,itemId,kind,payloadRef}` per logical sequence; that source must be the Session itself or an immutable reachable ancestor, and inherited sequences cannot cross any lineage fork cursor. Summary and excluded-control segments bind the ordered logical `{itemSeq,kind,payloadRef}` digest independent of physical owner/item id. Summary `retainedItemIds` are unique, at most 256, belong to that exact covered source range, and project in stable logical item order. `projectionDigest` is SHA-256 over RFC 8785/JCS with `projectionDigest` omitted.

`compactSession` accepts only a range whose endpoints are complete current segment boundaries and whose selected segments are all raw, rejects any range containing a summary or excluded-control segment, and atomically appends one child-owned compaction item at `latestItemSeq+1` while replacing the projection and incrementing context revision. Public Markdown is normalized to exact bounded `ModelTextV1`; `summaryRef` names it and `summaryDigest` equals its `textDigest` in the item and summary segment. That appended control item is represented only by an exact one-item `excluded_control` segment whose source digest binds its `{itemSeq,kind,payloadRef}` tuple; it is never raw/model-visible. `forkSession` accepts only zero or the end of a current segment; it creates `contextRevision=1`, `latestItemSeq=forkedThroughItemSeq`, a projection retaining exact ancestor `sourceSessionId/itemId` identities, and **no cloned item rows**. The first child-owned append is `forkedThroughItemSeq+1`. A later parent append/compaction cannot enter the frozen inherited prefix. Straddling, nested, recompact, source-lineage mismatch, or cursor-inside-segment requests return `INVALID_REQUEST`.

`createSessionHandoff` is read-only and takes one Session/lineage/projection snapshot at `expectedContextRevision`. Omitted `throughItemSeq` selects that projection's cut; an explicit cursor is zero or an exact current segment end no greater than the cut. The walk emits contiguous indexed entries in stored encounter order: raw `run_terminal` uses its payload ref, `SHA-256(JCS(SessionRunTerminalItem))`, and exact model-visible terminal JCS; a summary uses its compaction item ref, `summaryDigest`, and decoded `ModelTextV1.utf8`; excluded-control ranges are copied in encounter order and legacy kinds never become entries. Workspace/projection refs and digests match the snapshot, every ref rehashes, and `handoffDigest=SHA-256(JCS(handoff with handoffDigest omitted))`. The JSON artifact is exact UTF-8 JCS of `SessionHandoffV1`. Markdown is rendered only from that object with the RFC-fixed heading, JCS session id, base-10 revision/cursor/entry numbering, LF-normalized indented content lines, and excluded-range count; its digest covers those exact UTF-8 bytes. No timestamp, random id, mutable path, checkpoint, principal, credential/grant/receipt body, hidden Run transcript, or renderer option enters either artifact. Identical Session/revision/cursor returns identical JSON/Markdown refs.

The `runs` table must reject every legacy lease column. Its launch contract is exactly: nonterminal `running` requires `activeWorkerLaunchId` to reference an activated row for the same Run/epoch; queued, waiting, and terminal Runs have no active pointer. Lease expiry never silently clears the pointer or queues the Run.

#### 3. Make initial admission indivisible and non-optional

For every admission-key method, `admissionIntentDigest = SHA-256(JCS({principalId,method,request: normalized request with protocolVersion,requestId,requestDigest,admissionKey omitted}))` and the unique replay identity is `(principalId,method,admissionKey)`. The typed read-only replay gate runs before reopening a workspace, reading a Session revision, revalidating an apply source Run, descriptor-capturing source A, or publishing any resolved artifact. Equal intent returns the already committed Session/Run/control result byte-for-byte; unequal intent returns `ADMISSION_KEY_CONFLICT` and performs no state or filesystem read beyond the replay row. A concurrent first execution is rechecked under the admission write transaction before any authoritative row commits.

`run.submit` computes `requestDigest = SHA-256(JCS(request without requestDigest))`. Before RunSpec construction, the trusted Supervisor normalizes the public objective exactly once to NFC, rejects NUL/unpaired surrogate and UTF-8 length outside `1..262144`, publishes exact `RunObjectiveV1`, and installs only its ref as `RunSpec.objectiveRef`; the inline request is never retained as a second source. Storage additionally computes/validates `admissionIntentDigest` without `requestId`, `requestDigest`, or `admissionKey`, so an idempotent retry can be answered before workspace recapture. Its selected Session identity must be exact `WorkspaceIdentityV1.kind='live'`; the required `workspacePath` is descriptor-reopened no-follow and must resolve byte-for-byte to it, while every admitted `workspaceIdentityDigest` and Git repository ref/digest must equal the retained artifacts. `legacy_unavailable` and its forks are rejected before any capture/Run. Root or `.git` move/replacement is `ARTIFACT_MISMATCH`, not recapture. The final admitted-request digest binds the objective ref and every Supervisor-resolved artifact, Session cursor, optional parent/delegate identity, RunSpec, consent, base workspace, assembly, policy, sandbox, verifier/dependency policy, credential grant ref, source selector/authorization/classification evidence, frozen-ignore/projection, and workspace/repository identity. Trusted capture descriptor-reads and publishes exact `FrozenIgnoreRulesV1`, then exact `SourceProjectionSpec(schemaVersion=1)` whose omission-rule digest and rules ref/digest are repeated by every SourceManifest and reached by WorkspaceState through its base/projection digest. A no-grant include is legal only after publishing exact `SourceIncludeClassificationEvidenceV1`: its nonempty unique byte-sorted entries exactly cover the selected descriptor-captured entries; each WorkspaceEntry digest/device/file/link identity matches the later SourceManifest; and each entry is proven tracked by the identical retained Git index or nonignored under the exact frozen rules. `SourceIncludeAuthorizationV1.kind='builtin_nonignored'` repeats that exact evidence ref/digest and frozen rules. An ignored include requires `kind='consumed_user_read_grant'` and the exact active principal/workspace/path/scope read grant; its `AuthorizationConsumptionReceiptV1.consumer.run_admission` names the exact Run and **pre-resolution `admissionIntentDigest`**, never the later final admitted-request digest. Grant consumption, receipt, final-digest computation, include authorization, Run/Checkpoint/projection, response, and replay row commit atomically without a digest cycle. Missing, unnecessary, mismatched, reused, repository-manufactured, or outside-root authority creates no Run. `run.apply` has no workspace-path or objective parameter: trusted code requires the delivery `RunSpec.objectiveRef` to equal the source RunSpec's exact `RunObjectiveV1` ref byte-for-byte, derives the source Run's live Session identity, descriptor-reopens that exact root/`.git`, then captures and publishes two different canonical artifacts. `A` is the exact captured `SourceManifest`; both `RunSpec.baseWorkspaceManifestRef` and initial `delivery:merge.capturedWorkspaceRef` equal `A`. `W_A` is the exact full recovery `WorkspaceStateManifest`; `W_A.baseWorkspaceManifestRef` equals `A`, and the initial Checkpoint's `workspaceStateRef` equals `W_A`. Both carry/derive the same exact workspace/repository identity and projection/rules digests. Every agent or delivery RunSpec requires an exact `RunObjectiveV1` ref already bound into its final admitted-request digest. Storage requires literal `RunSpec.schemaVersion=1` and `Checkpoint.schemaVersion=1`, decodes all types, recomputes their digests/projections, and rejects absent/alternate objective refs, `A`/`W_A` identity collapse, root/repository identity drift, or any cross-field mismatch rather than creating a post-admission capture step.

`admitRun` accepts only a fully typed `AdmitRunCommit`. After the replay gate confirms first execution, artifact publication happens first. Its one SQLite transaction:

1. checks the exact `control_requests` identity and returns its immutable response or rejects a conflicting digest without creating a placeholder row;
2. rechecks exact `(principalId,method,admissionKey)` uniqueness and same-key/same-intent idempotency under the write lock;
3. validates the final digest, verified RunSpec, exact `RunObjectiveV1` and required sole `objectiveRef`, admitted Session revision/cursor and immutable live `WorkspaceIdentityV1` plus optional exact `RepositoryIdentityV1`, descriptor-reopened root/`.git` tuple, exact frozen-ignore/projection/include-classification/include-authorization graph, initial context/workspace refs, deadline/budgets, verifier set, and required unverified consent; it atomically consumes every needed ignored-path read grant into its exact admission-intent-bound receipt and include-authorization ref, while ordinary includes require exact descriptor-held classification evidence matching the captured entries and final SourceManifest. For delivery it additionally requires objective-ref equality to the source RunSpec, exact live source-Session identity, exact `SourceManifest A`, exact `WorkspaceStateManifest W_A`, `W_A.baseWorkspaceManifestRef=A`, and operation-specific projection/rules equality;
4. inserts the initial Checkpoint with `reason='initial'` at virtual `basedOnRunRevision=0`, `runItemSeq=0`, and `journalSeq=0`; its `workspaceStateRef` names `W_A`, never `A`;
5. inserts the queued Run at `revision=1` with the operation-derived initial frontier—`agent` only for `operation='agent'`; exact `delivery:merge {sourceRunResultRef,capturedWorkspaceRef:A}` only for `operation='delivery'`, with `RunSpec.baseWorkspaceManifestRef=A`—plus `leaseEpoch=0`, no active launch, non-null `latestCheckpointId`, zero reserved/consumed budgets, and fixed deadline;
6. appends `RunEvent(kind='state_changed', eventSeq=1, runRevision=1)`;
7. inserts the deterministic response artifact reference and `control_requests` row;
8. commits once.

No revision-0 Run row is visible. No API can insert a Run without that Checkpoint. A failed transaction leaves only unreachable verified CAS objects and no accepted Run. Same key+intent returns the original response/snapshot without rereading a drifted workspace; same key with different intent is `ADMISSION_KEY_CONFLICT`. Same principal+method+request id with different request bytes is `REQUEST_ID_CONFLICT`.

The Checkpoint/Run insertion cycle uses explicit `DEFERRABLE INITIALLY DEFERRED` foreign keys and is validated before commit; foreign keys are never disabled to make admission work. `session.create` and `session.fork` apply the same admission-key+intent rule through their Session storage columns and `control_requests`, so changing `requestId` cannot create a duplicate Session.

Child admission uses the same initial-Checkpoint rule and additionally commits the parent allocation reservation, `child_allocations` row, parent `ChildHandleItem`/frontier reducer, and child Run/Checkpoint/event in one typed transaction.

#### 4. Expose typed transactions, never a mutation bag

Production callers receive repository interfaces, not a database handle. The minimum write surface is closed:

- Session: `createSession`, `forkSession`, `compactSession`, and internal `appendRootRunTerminalItem`.
- Admission: `admitRun` and `admitChildRun`; their discriminated commits resolve the exact `RunPolicySnapshotV1`, consume any required `AuthorizationGrantV1` with its exact receipt/consumer, and publish the exact dependency-script template or child allocation in the same transaction rather than through a free-standing consume API.
- Invocation: `prepareInvocation`, `failPreparedWithoutDispatch`, `claimDispatch`, `releaseClaimedDispatch`, `claimRecoveryMaintenance`, and `releaseRecoveryMaintenance`; every productive prepare/claim accepts only the exact current `OperationGrantV1` closure. A process-spawning prepare structurally forbids `sandboxLaunchSpecRef`; after selecting the unguessable `dispatchId`, `claimDispatch` artifact-first publishes the exact `SandboxLaunchSpecV1.run_invocation` and atomically binds its ref to the claim. Every later phase repeats it byte-for-byte. Non-spawning operations forbid it throughout.
- Evidence: `commitCurrentInvocationEvidence` and `commitHistoricalInvocationEvidence`.
- Model/tool frontier: `commitResolvedModelToolBatch`, `commitRejectedModelToolBatch`, `commitAgentFinalCandidate`, `commitModelUnusableResponse`, and `commitToolResult`. `commitModelUnusableResponse` accepts only the exact positive-response artifact/Journaling/full-reservation closure above; for a normal request it artifact-first publishes and validates exact `RuntimeFailureEvidenceV1(failureKind='model_unusable_response')` and binds that ref/digest/failing op into the generic-runtime StopIntent/TerminalDetail, while context compaction uses only its dedicated subtype. It structurally forbids every model/batch/candidate/summary item or semantic retry. `commitRejectedModelToolBatch` alone accepts an identity-valid usable `tool_calls` turn containing any rejected input; one transaction appends its exact `ModelTurnItem` and whole `ToolBatchItem`, the deterministic input-error result for every rejected call, `batch_not_executed` for every remaining call with the complete rejected-id set, a replacement `agent` frontier, one Run revision/event, and no Journal prepare, grant, dispatch, or tool frontier. The other methods structurally reject that state, and no producer may append one member of either closure separately.
- Waiting: `resolveApproval`, `resolveInput`, `replaceReconciliationProbeSubject`, `resolveReconciliation`, and `settleChildWait`. `resolveApproval` accepts the exact published `ApprovalDecisionV1`. `resolveInput` accepts only exact authenticated `UserInputPayloadV1` for the current `InputPromptV1`/`InputRequestItem`, requires payload/item equality to one exact ref-free `UserInputModelContentV1`, and atomically appends the exact `UserInputItem`, executed audit payload and ToolResult model content, replacement frontier, event, response, and replay row. `resolveReconciliation(abandon_run)` accepts the exact published `ManualAbandonAttestationV1`. None accepts inline reconstructed proof or a partial item/result closure.
- Run closure: `proposeStopIntent`, `commitTerminalStop`, `commitRunResult`, and `commitCheckpointedWorkspaceTransition`; `commitRunResult` accepts and re-walks only the exact current operation-discriminated `FinalCandidateItem`, its producer/summary/base/result/`WorkspaceDiffV1` closure, the exact `VerificationClosureV1` named by the finalize frontier and RunResult, the exact `InheritedVerificationProvenanceV1` when inheritance is selected, plus the identical exact `DeliveryTerminalProjectionEvidence` ref required by delivery finalize/result and forbidden by agent finalize/result. RunResult base/result/diff/summary refs must equal that candidate.
- Launch: the exact WorkerLaunch methods in note 6 plus `joinOrCreateLocalInferenceActivationCycle`, `reserveLocalInferenceRetryLaunch`, `completeLocalInferenceActivationCycle`, `recordLocalInferencePreactivated`, `activateLocalInferenceService`, `renewLocalInferenceLease`, `beginLocalInferenceRevocation`, and `retireLocalInferenceLaunch`; these are disjoint typed cycle/row/fanout APIs and cannot accept one another's owner union.
- Administration: `createAuthorizationGrant`, `deriveVerifierExecutionAuthorization`, `revokeAuthorizationGrant`, `prepareAdminOperation`, `recordAdminActive`, `claimAdminProbe`, `releaseAdminProbe`, `completeMcpRegistrationRevision`, and `failAdminOperation`. `prepareAdminOperation` requires the exact static `AdminProbePayloadCoreV1` and matching admin SandboxLaunch before preactivation. Completion accepts only exact `McpAdminProbeResultV1` plus `AdminProbeClosureEvidenceV1(containment_dead)` and final response; failure accepts only exact `AdminProbeErrorV1` plus its identical closure and phase-valid optional final response. Every method validates and persists the canonical ref+digest pairs; there is no untyped result/evidence/error setter. Authorization consumption is available only inside the named derivation/admission/registration transactions that publish the matching `AuthorizationConsumptionReceiptV1`; there is no generic consume-and-return-authority method.
- Reads: bounded Session/Run lists, independent item/Journal/Checkpoint cursors, event cursor, artifact metadata/chunks, registry/grant summaries, `readRecoveryClosure`, and `readLocalInferenceRecoverySet`.

Every write method accepts its own discriminated request and validates the exact current revision/frontier/wait/attempt/claim/launch/grant/budget facts it needs. It emits only its operation-specific item/fact/event/response. There is no public `compareAndSwapRun`, `updateRun(patch)`, `commitInvocationFact(..., runMutation)`, generic `{items,budget,status}` object, arbitrary status transition, or direct SQL callback. A Run revision increments exactly once per authoritative workflow mutation. Narrow activated-launch heartbeat and generation-write-state CAS do not touch Run revision, `updatedAt`, items, or events; replacing the immutable reconciliation probe subject is a typed Run workflow mutation and therefore revisioned.

`resolveApproval` is one artifact-first, request-idempotent transaction. It recomputes the exact `ApprovalDecisionV1` decision/wait/subject digests, closed-decodes its authenticated `channelIdentityRef/channelIdentityDigest`, validates that pair plus principal and current Run revision/wait/frontier/subject and canonical request id/digest, then atomically installs the decision ref, subject-specific `PolicyDecisionItem`/result, optional exact `OperationGrantV1`, replacement frontier or StopIntent progress, Run revision/event, deterministic response artifact, and `control_requests` row carrying the identical channel pair. An allow grant's `user_approval.decisionRef` must decode to this exact allow decision and have the identical `grantExpiresAt`; a verifier-template grant instead points only to the template-producing `AuthorizationConsumptionReceiptV1`. Crash before the transaction leaves only an unreachable decision artifact; crash after it replays the same control response without rewriting first-commit channel provenance.

The prospective-operation policy reducer uses a separate typed direct transaction, never `resolveApproval`. It artifact-first publishes exact `PolicyChannelEvidenceV1`, recomputes the fixed evaluator result, and for `allow|deny` atomically appends exact `PolicyDecisionItem(decisionSource='direct_policy')` plus the one subject grant or denial outcome and Run frontier/StopIntent/event change. Direct deny creates no WaitingSubject or ApprovalDecision: tool/MCP appends the identity-matched denied result; required verifier proposes exact `policy_deny/verification_failed`; advisory verifier appends exact `VerifierSkipItem(skipped_by_policy)` and advances; delivery or dependency scripts proposes exact `policy_deny/runtime_failed`. The decision ref and any skip evidence digest equal the same policy-channel evidence; a direct transaction with an interactive wait/decision, missing outcome, grant-on-deny, or denial-on-allow is rejected.

`resolveReconciliation(abandon_run)` similarly publishes and validates one exact `ManualAbandonAttestationV1` before its transaction. It is legal only for the current `ReplayClass='manual'` invocation subject and authenticated `acknowledgeExactRisk:true`; the attestation's ambiguity pair must be byte-identical to the unknown Journal row's exact `InvocationAmbiguityEvidenceV1` pair. The same transaction appends Journal `abandoned` with its own evidence pair forbidden, repeats the prior unknown `budgetSettlementRef` with no new charge, uses the identical attestation ref in Stop/Terminal closure and any call-origin `ToolAbandonedItem`, advances terminal quiescence, emits the event, and stores the control response. If an earlier user/parent stop already wins, the attestation closes that exact unknown under the existing winner rather than replacing it; otherwise it may create the canonical `manual_abandon` intent. No branch creates a ToolResult, resumes a batch, substitutes newer display/probe evidence, or abandons publication/other reconciliation subjects.

Typed method inputs import the canonical symbols from `src/kernel/types.ts`; repository modules may normalize physical column names but cannot redefine those unions. Each transaction decodes referenced artifacts before its first state predicate and repeats any identity-sensitive validation in the committing database view. Test-only builders must use the same decoders and cannot bypass forbidden-field or cross-reference checks.

Every typed reducer revalidates the complete Run matrix inside its write transaction:

- every nonterminal Run has non-null `nextStep` plus a verified `frontierRef` whose `RunFrontier.kind` matches; terminal Runs have neither;
- queued Runs have no active launch pointer or wait, running Runs point to the exact activated launch for the same Run/epoch, and waiting Runs have no active pointer plus a canonical `waitingOnRef` whose kind/frontier matches `waitingReason`/current frontier;
- only subject-specific approval, input, child, and reconciliation reducers may replace a wait. They normally perform lease-free `waiting -> queued`, but a winning StopIntent runs terminal quiescence instead; no control reducer transitions directly to running;
- delivery frontiers are proof-carrying and closed: `merge` preserves exact source result plus admission capture; `approval` carries candidate/result/verifier-plan/verification-closure/delivery-plan refs; `publish|abort_cleanup` preserves all of those plus the exact next path index. No reducer drops/reconstructs those refs, reintroduces `delivery:capture`, or installs delivery finalize without the same closure plus exact terminal projection evidence;
- `resultRef` exists exactly for `succeeded|completed_unverified`; failed/cancelled require terminal detail and retain the winning StopIntent, while nonterminal and successful Runs forbid terminal-only fields;
- terminal status/reason mapping is closed, every reservation is zero, and no active launch/frontier/wait, unclosed tool call, unresolved `reconcile|manual` invocation, unrolled-back workspace attempt, live MCP containment, outstanding child allocation, or unresolved publication path remains;
- every terminal call has exactly one identity-matched `ToolResultItem`, except the sole non-result closure: an identity-matched `ToolAbandonedItem` for the same manual invocation named by `TerminalDetail.abandonedManualInvocation`, with the same exact `ManualAbandonAttestationV1` ref as its Journal `abandoned` row. A fully settled `retry`-unknown tool/MCP call instead closes only at terminal stop with `ToolResultItem(outcome='cancelled')` whose result ref is the exact `RetryUnknownCancelledResult`, after exact `BudgetSettlementV1` plus `InvocationDispatchClosureEvidenceV1`; a non-call retry unknown creates no call item;
- `StopIntentBase` has no generic evidence ref. `TerminalDetail.primaryEvidenceRef` is derived by the closed branch matrix: verifier/dependency integrity use `integrityEvidenceRef`; parent cancellation uses `sourceStopIntentRef`; local inference failure uses `failureDetailRef`; direct required-verifier/delivery/dependency policy denial uses `policyChannelEvidenceRef`; generic runtime uses the exact `runtimeFailureRef`; manual abandon uses `attestationRef`; user cancellation, deadline/budget, verification, context-compaction/window, delivery-merge, and delivery-publication use the immutable winning `stopIntentRef` itself. A direct-policy StopIntent/TerminalReasonDetail repeats the exact evidence pair/op/subject and maps verifier to `verification_failed`, delivery/dependency scripts to `runtime_failed`. Generic runtime StopIntent and TerminalReasonDetail repeat the exact `RuntimeFailureEvidenceV1` ref/digest plus its matching `failingOpId`. `deliveryTerminalProjectionEvidenceRef` is present only for a stopped delivery Run that had a forward publication claim and completed the exact abort projection; it must decode as the matching abort-selected `DeliveryTerminalProjectionEvidence`. Merge conflict, interactive approval denial before publication, cancellation before the first forward claim, agent Runs, and every unrelated stop forbid the field;
- StopIntent selection is monotonic with any `origin='kernel_integrity'` highest, then `cancelled_by_user`, `parent_cancelled`, `budget_exhausted`, `verification_failed`, `verifier_infrastructure_failed`, and ordinary `runtime_failed`; a `policy_deny` intent occupies the precedence of its exact mapped reason (`verification_failed` for required verifier, `runtime_failed` for delivery/dependency scripts). Equal precedence retains the earliest committed intent with artifact digest as the deterministic same-transaction tie-break, and only a later higher-precedence intent may replace the pointer. Additive token/cost/tool/repair exhaustion requires `origin='budget'` plus proof that `consumed + reserved + required > ceiling`; wall expiry uses only `origin='deadline'`; `manual_abandon` is the closed cancellation form for the exact manual invocation;
- budget consumed/repair count/lease epoch never decrease, `cancelRequested` is monotonic, and immutable `deadlineAt` continues through wait/reboot and caps child deadlines.

Root Run terminal publication appends exactly one idempotent exact `SessionRunTerminalItem` and advances the Session context projection/revision in the same transaction as terminal Run truth. It derives literal ``itemKey=run-terminal:${Run.id}``, exact Run id, operation from decoded RunSpec, and `admittedSessionItemSeq` from that RunSpec's decoded `AdmittedContextManifest.throughSessionItemSeq`; status/reason equal the Run. Success/unverified requires the Run's exact result and decoded RunResult/`ModelTextV1` summary ref/digest and forbids terminal detail; failed/cancelled requires the Run's exact terminal detail and forbids result/summary. It always adds a new, never-coalesced, one-item `raw` segment containing the exact child-owned tuple `{sourceSessionId=sessionId,itemSeq,itemId,kind='run_terminal',payloadRef}`. Its model-visible bytes are exactly RFC 8785/JCS `{kind:'run_terminal',runId,operation,status,terminalReason,resultRef?,summaryRef?}` with absent optionals omitted; `admittedSessionItemSeq`, `terminalDetailRef`, and `summaryDigest` remain audit/control-only. Child Runs never append directly to Session.

The finalize gate is not receipt-counting shorthand. `commitRunResult` first decodes the exact current operation-discriminated `FinalCandidateItem` and exact `WorkspaceDiffV1`, recomputes the sorted base/result comparison, requires candidate `sourceDigest` to equal result SourceManifest `manifestDigest` and candidate `diffDigest` to equal the diff, and revalidates the producer: agent uses its exact positive-end model op/text, while delivery uses its exact merge summary and forbids `producingOpId`. RunResult base/result/diff/summary refs equal that candidate exactly. It then requires the current finalize frontier's `verificationClosureRef` and `RunResult.verificationClosureRef` to be the same exact `VerificationClosureV1`, recomputes its digest, and walks candidate/source/plan, dependency readiness, verifier entry ordering, highest eligible Journal facts and their exact budget settlements, receipt/item identities, required/advisory constraints, and direct/inherited consent/provenance. For `inherited_verified`, `inheritedProvenanceRef` and delivery `RunResult.verificationProvenanceRef` must be the same exact `InheritedVerificationProvenanceV1`; storage recomputes `provenanceDigest` and re-walks the immutable source `succeeded(verified)` result, its required source closure, identical result source, verifier spec, and ordered receipt refs/digests without relabeling source-owned ids. For `operation='agent'`, both frontier and result must forbid `deliveryTerminalProjectionEvidenceRef`. For `operation='delivery'`, both must require the identical exact ref, decode `DeliveryTerminalProjectionEvidence`, require `selectedBranch='forward_finalize'`, recompute `evidenceDigest`, and revalidate delivery Run id, plan, observed source/path states, forward result items, unstarted forward operations, empty/valid abort closure, transient absence, projection closure, Git-index unchanged evidence, and current descriptor observations. A schema-valid candidate, diff, verification, inherited provenance, or delivery-projection closure with a missing, superseded, mismatched, reordered, alternate-summary, or abort-selected storage fact cannot terminalize the Run.

`commitTerminalStop` separately derives `TerminalDetail` from the winning immutable StopIntent and current closure. It applies the exact primary-evidence matrix above and rejects a caller-selected substitute; each `TerminalReasonDetail` copies only the matching branch fields and, where it has an evidence member, repeats that same selected ref. Generic runtime additionally re-decodes exact `RuntimeFailureEvidenceV1`, recomputes its omission digest, matches Run/frontier/failing op/current inspector, and re-walks the branch-specific Journal/request/credential/dependency/retry/local-service closure before copying its ref/digest/failing op. Only a delivery Run with at least one claimed forward publication operation may carry `deliveryTerminalProjectionEvidenceRef`, and then it must be the exact abort-selected projection evidence reached through the proof-carrying `abort_cleanup` frontier and revalidated against Journal/path/result/descriptor truth. Agent stops, delivery merge conflicts, approval denial, pre-first-claim cancellation, and any delivery stop with no completed abort projection forbid that field. The only surrounding closure is exact `publicationResultItemRefs`, `abandonedRetryInvocations`, and optional `abandonedManualInvocation`; each retry entry repeats the exact unknown `budgetSettlementRef` plus matching `InvocationDispatchClosureEvidenceV1`, while the manual entry repeats the one exact `ManualAbandonAttestationV1` ref held by Journal and any `ToolAbandonedItem`. Candidate, diagnostic, verifier-receipt, and child-result facts remain in ordered items/Journal and are never copied into `TerminalDetail`. This closure never changes the winning terminal reason.

#### 5. Keep Journal transitions and evidence disposition exact

The Journal transition graph is closed:

```text
prepared         -> dispatch_claimed | failed
dispatch_claimed -> completed | failed | unknown
unknown          -> completed | failed | abandoned
```

Rows are immutable. Attempts are contiguous from zero, and only the highest prepared attempt can remain current. Every `budgetDelta` is the complete four-counter `BudgetUsage`; omission, partial objects, and omitted-versus-explicit zero encodings are invalid. `prepared` atomically reserves that complete delta and binds request/target/replay class/epoch/grant. `dispatch_claimed` is unique for the attempt, carries an unguessable `dispatchId` plus Supervisor instance, uses the exact all-zero delta, and forbids `budgetSettlementRef`. No target I/O is legal before `claimDispatch` and the second live `releaseClaimedDispatch` check. A claim is permanent singleflight; restart never redispatches that attempt. `completed|unknown` and post-claim `failed` repeat the exact claim and require the exact settlement ref published for that Journal pair. Pre-dispatch `failed` instead requires the exact prepared row plus error/settlement with all-zero consumed delta, proves no claim exists, and structurally forbids dispatch/Supervisor/state-owner/fence/result/receipt/evidence/attestation fields. Post-claim `failed` repeats dispatch/Supervisor/state-owner/fence identity, requires error plus positive evidence that release never occurred or every effect is rolled back/quiescent, and carries the exact consumed delta. `abandoned` is legal only after a `manual` unknown and repeats the unknown claim and settlement ref with zero additional budget delta.

The sandbox-launch phase matrix is equally closed. `prepared.sandboxLaunchSpecRef` is absent because a `run_invocation` owner cannot exist before the permanent `dispatchId`. For a process-spawning operation, trusted `claimDispatch` chooses that id, constructs and publishes the exact spec before opening the SQLite transaction, then the transaction revalidates its owner/plan/grant/request/target/active-parent equality and appends `dispatch_claimed` with the ref. A losing claim leaves only an unreachable CAS object. `completed|unknown|abandoned` and post-claim `failed` repeat the one claim ref exactly; pre-dispatch `failed` forbids it with every other claim field. A non-spawning operation has no spec ref in any phase. Storage rejects a pre-claim fictional owner, post-claim substitution, spawning claim without a spec, pre-dispatch failure with a spec/claim, or non-spawning claim with one.

`assertEvidenceAuthority` from work package 3 authorizes no I/O and is revalidated inside the storage transaction. The two commit paths are not aliases:

- `commitCurrentInvocationEvidence` requires the attempt is still highest and is named by the exact current frontier or reconciliation subject. It may append the terminal Journal fact, settle once, append the operation-specific item/receipt, install the post-effect Checkpoint when required, and advance/replace the exact frontier/wait or terminal closure even after the original launch was cleared or stop/deadline/grant expiry occurred after dispatch.
- `commitHistoricalInvocationEvidence` requires a newer attempt/frontier/result already won. It may append the authenticated late Journal resolution and exact audit/billing evidence, with zero additional settlement for an already charged `unknown`, but it cannot append a Run-visible item, replace a wait, change frontier/status/result/Checkpoint, or overwrite newer evidence.

If a caller presents a stale `current` classification, the write transaction recomputes disposition and routes it to historical handling or rejects it; it never allows TOCTOU advancement. Conversely, genuinely current evidence is not degraded to audit-only merely because its old lease/launch is no longer live. Worker assertions without trusted broker/adapter/query/containment provenance are invalid for both paths.

Every `workspace-rollback-retry` completion or kernel-owned mutating transition that changes bytes must use `commitCheckpointedWorkspaceTransition`: Journal terminal fact, deterministic result/merge item, budget settlement, verified post-effect Checkpoint, frontier, Run revision, launch retirement/pointer clear, and event commit together. Snapshot failure quarantines the generation and leaves no completed/current-visible result.

Every terminal/unknown transaction publishes and decodes exact `BudgetSettlementV1` before appending its Journal ref. It requires matching Run/op/attempt and `preparedJournalSeq`; `terminalJournalSeq` and `terminalPhase` equal the appended row; `released=reserved`; `consumed` equals the terminal row's `budgetDelta`; and the before/after consumed/reserved equations hold component-wise with checked nonnegative safe-integer arithmetic. An `unknown` consumes its entire reservation. Every post-claim model completion, failure, cancellation, protocol error, or `unknown` consumes the exact six-field request-bound reservation from `ModelRequestV1` in full; `AgentModelTurn.usageTrusted` is literal false, and provider/adapter usage, cache assertions, SDK counters, or later telemetry cannot lower/refund it. Late evidence reuses the already charged settlement rather than refunding or charging twice.

Terminal closure of a `retry` unknown additionally decodes exact `InvocationDispatchClosureEvidenceV1`. Its Run/op/attempt/dispatch/unknown sequence must equal the claimed-to-unknown chain. `containment_death` rehashes the exact invocation containment ref/digest plus its exact `ProcessContainmentDeathEvidenceV1` ref/digest. `broker_release_fenced` is legal only for a broker/no-child claim whose Journal row stored `brokerFenceTokenDigest`; its exact `BrokerReleaseFenceEvidenceV1` ref/digest repeats the request/target/grant/dispatch/claiming Supervisor/epoch, current inspector with strictly newer epoch, and identical token digest, then proves `token_revoked_and_matching_active_release_count_zero` at retained times. Lease expiry, socket loss, a new Supervisor id alone, inline boolean, or worker assertion is insufficient. `RetryUnknownCancelledResult` and `TerminalDetail` repeat these exact settlement/closure refs.

#### 6. Persist the exact worker-launch and write-gate authority

The immutable identity and mutable launch row are:

Canonical types: `WorkerIdentity`, `WorkerLaunch`.
Import their complete definitions from
[RFC 9.1 Lease, Activation, And Process Containment](../../rfcs/2026-08-11-durable-verified-run-kernel.md#91-lease-activation-and-process-containment).
This package enforces that contract without a second schema copy.

Storage exposes these exact CAS operations:

- `createWorkspaceGeneration` artifact-first publishes exact `WorkspaceGenerationIdentityV1`, inserts its sole `workspace_generations` row in `materializing`, and rejects any mismatched Run/source-Checkpoint/state/tree/locator or repeated id. `recordGenerationMaterialized` CASes only `materializing -> preactivated_readonly` with exact `WorkspaceGenerationSnapshotEvidenceV1(purpose='materialized_from_checkpoint')` after descriptor rewalk and all fsyncs.
- `reserveWorkerLaunch` inserts the sole unretired intent for a lease-free queued Run before process/VM creation; it requires the pre-published exact worker `sandboxLaunchSpecRef` to match the row/plan/Run and an exact `preactivated_readonly` generation row, fixes `activationDeadlineAt=createdAt+120s`, and copies `generationWriteState='preactivated_readonly'` only as a same-transaction denormalized index.
- `recordPreactivated` CASes `reserved -> preactivated` and binds the immutable WorkerIdentity digest and exact ProcessContainmentRef while leaving the worker powerless/read-only.
- `activateWorkerLease` atomically revalidates queued Run revision/frontier/Checkpoint/stop/cancel/deadline, CASes the launch to activated/active and the exact generation row from `preactivated_readonly -> active` with the same launch/epoch and initial 30-second lease from the trusted transaction clock, increments Run `leaseEpoch`, installs `activeWorkerLaunchId`, changes queued to running, increments Run revision, and emits one state event.
- `renewWorkerLease(supervisorInstanceId,launchId,expectedLeaseVersion,runId,leaseEpoch,workerIdentityDigest,newLeaseExpiresAt)` runs on the 5-second heartbeat cadence and changes only launch `leaseVersion` and `leaseExpiresAt` after rechecking the exact active Run pointer and row. Storage accepts `newLeaseExpiresAt` only when it is the canonical trusted-transaction time plus 30 seconds; a caller cannot choose a longer lease, renew after expiry, or renew a row whose Supervisor, identity, epoch, phase, or write gate no longer matches.
- `beginGenerationRevocation` CASes the authoritative generation row `active -> revoking` with one `quiesceId`; after positive descendant death, `beginGenerationCheckpoint` CASes only that same row `revoking -> checkpointing` with the same `quiesceId`. Each transaction copies the same phase into WorkerLaunch and cannot reopen, skip, choose checkpointing directly from active, or diverge.
- `sealGenerationWithCheckpoint` artifact-first publishes exact `WorkspaceGenerationSnapshotEvidenceV1(purpose='sealed_to_checkpoint')`, then atomically commits the intended ready Checkpoint, CASes the generation row from `checkpointing -> sealed`, copies `sealed` to WorkerLaunch, and clears the Run pointer/retire path as required by the workflow. A rescan without this transaction is not current state.
- `enterWorkerDeathReconciliation` is mandatory for every worker loss from `active|revoking|checkpointing`, even when death proof is already available. One transaction clears the Run pointer, installs the exact `worker_death` WaitingSubject, CASes the authoritative generation to `fenced_reconciling` with the exact wait ref/digest, `fencedFromPhase`, and phase-valid `quiesceId`, and copies `phase='reconciling',generationWriteState='fenced_reconciling'` into the sole WorkerLaunch. The row is unrenewable, read-only, and cannot dispatch, checkpoint, seal, or be selected by a replacement.
- `quarantineWorkspaceGeneration` artifact-first publishes exact `WorkspaceGenerationQuarantineEvidenceV1` and CASes only a canonical source phase to `quarantined`. `sourceRowVersion` equals the current row and the sole target is `quarantine/workspace-generations/H(generationId,base-10 sourceRowVersion)`. Its matrix is total and closed: materialization failure with exact failure detail; preactivation failure with exact failure detail; preactivation launch abort with exact no-spawn evidence; preactivation launch death with exact death evidence; worker recovery only from the exact installed `fenced_reconciling` wait; or checkpoint failure from `revoking|checkpointing` with exact launch/quiesce/death evidence. The transaction verifies the no-replace quarantine rename, new descriptor identity, original-locator absence, directory fsync, current inspector, and exact `observedState=complete_tree|unreadable_partial`, then makes the generation permanently unselectable. Crash recovery retries only the same derived target; both-present, both-absent, identity drift, or any other target blocks.
- `retireReconciledWorkerLaunch` accepts only positive whole-containment death plus exact generation quarantine/restore evidence. Restore requires a **distinct** replacement `WorkspaceGenerationIdentityV1` already in `preactivated_readonly` from the named ready Checkpoint; it may then make an unstopped Run recovery-eligible or advance StopIntent quiescence. `retireWorkspaceGeneration` CASes only `sealed|quarantined -> retired` with exact `WorkspaceGenerationRetirementEvidenceV1`; it cannot delete the identity, evidence, or locator history.

The immutable WorkerIdentity artifact must equal its owning row on `launchId`, `supervisorInstanceId`, `spawnNonceDigest`, `activationNonceDigest`, and `processContainmentRef`; its `intendedLeaseEpoch` must equal the epoch installed by the one activation transaction. Neither identity nor containment can be rebound.

`reserveWorkerLaunch` and `prepareAdminOperation` accept only a pre-published exact `ProcessContainmentPlanV1` plus the owner-specific exact `SandboxLaunchSpecV1`; their owner, filesystem binding, parent-containment XOR, launch nonce, backend reservation, plan ref/digest, runtime/process/environment/mount/resource/profile closure, and spec digest match the reserving row. A preactivated/no-process failure can retire only through `ProcessContainmentNoSpawnEvidenceV1` for that exact plan/spec; any created containment can retire, checkpoint, publish a result, stop a verifier/MCP process, or enable replacement only through `ProcessContainmentDeathEvidenceV1` for the exact actual containment, plan, and launch spec. Both evidence paths validate the current state-owning Supervisor inspector identity and bounded freshness inside the transaction. PID exit, timeout, inaccessible state, or a schema-correct artifact with a mismatched spec/owner/nonce/backend is rejected.

A successor Supervisor never renews/adopts an older row, even before lease expiry. An expired heartbeat, dead PID, process group, or elapsed timeout is not death proof. Until the old containment is positively dead, no replacement row may activate and the old generation cannot become a Checkpoint/result.

Managed local inference has a separate, non-Run launch authority. Storage exports and persists this exact canonical row without borrowing WorkerLaunch, Run, Journal, admin, frontier, budget, Checkpoint, or credential fields:

```ts
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
```

`joinOrCreateLocalInferenceActivationCycle` accepts one exact `LocalInferenceActivationParticipantV1`. For `run_submission`, the request bytes are already artifact-first retained at `runSubmitRequestRef`; request digest, admission key, and admission-intent digest must match that artifact and the public call. For `run_model_frontier`, the transaction requires the exact still-queued, unstopped Run revision/frontier and its frozen service spec. Storage first searches every retained cycle participant: the same submission request id plus identical bytes returns that cycle/result, different bytes return `REQUEST_ID_CONFLICT`, and an exact Run/frontier identity cannot join twice. A new participant joins the one matching `starting_launch|retry_wait` cycle, or creates the next contiguous service-level cycle only when the prior cycle is terminal and every blocking launch is positively retired. `activationCycleId = base64url(SHA-256(JCS({ownerPrincipalId,serviceId,serviceSpecDigest,cycleOrdinal})))`. Participant order is append-only, the two identity variants are unique, and the 129th participant returns `RESOURCE_EXHAUSTED(resourceKind='local_inference_activation_cycle')` without mutation or I/O. `cycleDigest` and `LocalInferenceActivationFailureV1.failureDigest` each equal SHA-256 over JCS with only that digest field omitted.

Cycle creation and launch reservation are one typed transaction after the exact plan and `SandboxLaunchSpecV1.local_inference_service` are published. It inserts `starting_launch(activationAttempt=1,launchIds=[launchId],currentLaunchId=launchId)` plus the exact launch row with the same cycle/service/spec/attempt and `activationDeadlineAt=createdAt+120s`. `reserveLocalInferenceRetryLaunch` is legal only from `retry_wait(activationAttempt=1)` after the first launch's positive retirement and trusted time reaches `retryNotBeforeAt=retiredAt+1s`; it atomically moves the cycle to `starting_launch(2)`, appends exactly one fresh launch id, and inserts the sole attempt-2 row with another fixed 120-second deadline. No attempt 3, launch-id gap/reorder, request-specific counter, or cycle reset is representable. Every cycle mutation increments `rowVersion` and recomputes `cycleDigest`; every launch mutation uses its own row/lease CAS.

`recordLocalInferencePreactivated` binds the exact inspected containment while traffic remains blocked. `activateLocalInferenceService` requires the exact current-Supervisor health/capability observation and `LocalInferenceBoundaryEvidenceV1`, then CASes only that launch row to `active` with its initial lease. `renewLocalInferenceLease` narrow-CASes only `leaseVersion/leaseExpiresAt`. `beginLocalInferenceRevocation` removes traffic authority and binds one `quiesceId`. `retireLocalInferenceLaunch` has two and only two terminal writes: `reserved -> retired/retirementKind='no_spawn'` forbids containment/boundary/quiesce and requires matching exact `ProcessContainmentNoSpawnEvidenceV1`; `preactivated -> retired/retirementKind='death'` and `revoking -> retired/retirementKind='death'` require the exact created containment/quiesce plus `ProcessContainmentDeathEvidenceV1`, with `boundaryEvidenceRef` present if and only if that launch reached `active`. Failure follows one mandatory matrix. If attempt 1 is positively retired, its transaction must move the cycle to `retry_wait` with `retryNotBeforeAt=retiredAt+1s`; it cannot terminal-fail for launch/timeout/health/capability failure. Attempt 1 may terminal-fail only when retirement cannot be proved, with exact `LocalInferenceActivationFailureV1(finalAttempt=1,failureKind='containment_unresolved')` while the launch remains fenced/unretired. Any attempt-2 failure is terminal after its positive retirement, or is terminal `containment_unresolved` when retirement remains unprovable. The failure artifact's final attempt/reason/retirement closure must satisfy that matrix. A successor Supervisor never adopts, renews, or sends model traffic to an older launch: it fences traffic, proves the exact plan/spec/containment closure empty when possible, and follows only the cycle-authorized next transition.

`completeLocalInferenceActivationCycle` is one bounded, exhaustive transaction over at most 128 immutable participants. Success validates the exact active current launch/boundary, sets the cycle `active`, admits every still-valid `run_submission`—or stores its exact non-activation admission error—with that request's ordinary `control_requests` response, and makes every still-matching queued `run_model_frontier` eligible without changing its revision/frontier. Failure validates exact `LocalInferenceActivationFailureV1`, sets the cycle `failed`, stores the same typed `RECOVERY_REQUIRED(recoveryKind='local_inference_service')` response for every submission without a Run, and proposes exact `runtime/local_inference_unavailable` StopIntent for every still-matching Run using cycle/service/frontier/failure refs; moved/stopped/terminal Run participants are audit-only. Cycle terminal state and participant fanout cannot split across a crash. A replacement may change only dynamic launch/containment/plan/SandboxLaunch/inspector/observation identities; the exact `stableServiceIdentityDigest` projection must remain equal. `readLocalInferenceRecoverySet` returns every nonterminal cycle, all cycle-linked launches, every terminal cycle needed for participant replay, and their exact request/frontier/service/spec/failure/plan/SandboxLaunch/containment/boundary/retirement closure.

#### 7. Make control, child, grant, MCP, and admin rows independently durable

`control_requests` is the only public mutator replay boundary. Every typed mutator first checks `(principalId,method,requestId)`:

- same canonical request digest returns the immutable first response even when the request's expected revision/wait ref is now stale;
- different bytes return `REQUEST_ID_CONFLICT` and do not invoke a reducer;
- on first execution, the deterministic response artifact is published before SQLite, then the response row and logical method result commit in the same transaction;
- no successful logical method result can commit and add the replay row later, and there is no cleanup policy that deletes replay truth automatically.

There are exactly two bounded pre-response fences. An executable MCP registry probe may persist `admin_operations` `prepared|active` or a response-less `failed/retryable_recovery` attempt. A `run.submit` that must start managed local inference may persist one `run_submission` participant in a shared service-level `local_inference_activation_cycles` row plus its subordinate launch attempts before any Run or that request's control response exists. Neither fence is a successful public mutation or replay response. Every joined request remains permanently discoverable in its cycle: same bytes replay/join that cycle/result, changed bytes conflict, and concurrent requests share the cycle's two attempts rather than acquiring private counters. The final cycle transaction writes each joined request's ordinary `control_requests` success/non-activation-error response with Run admission, or the same final activation error without a Run. Existing Run-frontier participants have no control response; the same transaction makes an exact queued frontier eligible or proposes its typed local-inference StopIntent. The admin path writes its response only on `completed`, `failed/final_rejection`, or final-attempt `failed/retry_exhausted`. No other response-less durable public-method state is legal.

Read-only `run.get|list|attach`, `session.get|list`, `authorization.list`, `mcp.list`, `artifact.get`, `run.diff|result`, deterministic `session.handoff.create`, and `supervisor.status` reject `requestId` and create no control row. `run.result|run.diff` return a success ref only when the Run is `succeeded|completed_unverified` with its authoritative `resultRef`; a queued/running/waiting Run returns exact retryable `RESULT_UNAVAILABLE` with `currentRevision`, while failed/cancelled returns exact nonretryable `RESULT_UNAVAILABLE` with `terminalDetailRef`. Storage never selects an earlier candidate or diagnostic artifact as a result.

The storage-owned list cache uses these exact canonical types:

Canonical types: `ListMethodV1`, `ListCursorPayloadV1`, `ListReadCutEntryV1` and 1 related definitions.
Import their complete definitions from
[RFC 15. Surfaces And Ecosystem Thin Waist](../../rfcs/2026-08-11-durable-verified-run-kernel.md#15-surfaces-and-ecosystem-thin-waist).
This package enforces that contract without a second schema copy.

`createListReadCut` normalizes exactly the authenticated principal, method, applicable filters, and defaulted limit, then computes `normalizedFilterDigest` from the RFC projection. In one StateOwner-gated SQLite transaction it captures current owner-visible rows, constructs the exact typed summaries, sorts by `(canonical createdAt,bytewise NFC stableId)`, inserts contiguous entries and the cut, and returns the first page. Stable ids are Session id, Run id, grant id, and registration id; MCP materializes only each registration's current registry head. Later status, revision, authorization, registration, or insertion changes cannot alter that cut. More than 100,000 entries or 64 MiB encoded summaries returns `RESOURCE_EXHAUSTED(state_storage)` and commits no partial cache.

`rowDigest` omits itself, `entriesDigest` hashes the complete ordinal-ordered row-digest sequence, and `cutDigest` omits only `cursorSecretBase64url` and itself. An issued cursor is unpadded base64url of exact JCS `ListCursorPayloadV1`; its MAC is `HMAC-SHA-256(secret,ASCII('cliq-list-cursor-v1\0') || JCS({schemaVersion:1,cutId,afterOrdinal}))`. Resume constant-time authenticates the MAC and exact principal/method/filter/limit/cut/entry digests, canonical encoding, expiry, and issued ordinal before reading the next `normalizedLimit` rows. The same valid cursor returns byte-identical summaries/cursor; `nextCursor` is absent exactly for an empty or exhausted cut. Unknown, forged, malformed, noncanonical, cross-principal/method/filter/limit, unissued, future, deleted, or expired cursors are `INVALID_REQUEST`. Cuts and their referenced-artifact roots may be deleted only after expiry and are never reducer or recovery input.

`readSessionPage(sessionId,afterItemSeq=0,limit=100)` runs in one SQLite read snapshot, captures `snapshot.contextRevision` and `highWaterItemSeq=snapshot.latestItemSeq`, then returns the first strictly increasing items in `(afterItemSeq,highWaterItemSeq]` subject to `limit in 1..1000` and deterministic complete `JCS(items)` metadata size at most 1 MiB. The first bounded metadata row always fits. `nextItemSeq` is the last returned sequence or the normalized supplied cursor for an empty page. A cursor above high-water is `INVALID_REQUEST`; equality is a valid empty page. Session items are not pruned, so the cursor never expires.

`readRunPage(runId,afterItemSeq=0,afterJournalSeq=0,checkpointCursor?,itemLimit=100,journalLimit=100,checkpointLimit=100)` likewise captures one exact `RunSnapshotV1`, item and Journal high-waters, and the greatest retained Checkpoint in strict `(createdAt,id)` order before reading any stream. Item and Journal cursors are numeric exclusive safe integers; each independent limit is `1..1000`. A Checkpoint cursor is unpadded base64url of exact `JCS({schemaVersion:1,runId,createdAt,checkpointId})`; it must round-trip, name that Run and an exact retained Checkpoint, and not exceed the captured last Checkpoint. Omission means before the first Checkpoint. Each stream returns strictly increasing rows through its captured high-water; each `next*` is the last returned cursor or normalized input on an empty page. The combined cap is exact complete `JCS({items,journal,checkpoints})<=1 MiB`: candidates are considered deterministically in stream priority `items`, then `journal`, then `checkpoints`, preserving each stream's order/limit; the first candidate whose complete three-array encoding would exceed the cap ends construction and leaves it plus every later candidate for the next request. The three next cursors and high-waters remain independent and come from the same snapshot; an individual bounded row always fits. A public admitted Run always has `highWaterCheckpointCursor`; its optional representation exists only for transaction-local pre-admission decoder compatibility. Kernel v1 never prunes these rows, so invalid/future/cross-Run/nonexistent cursors are `INVALID_REQUEST`, not expiration or silent skipping.

`child_allocations` stores exactly `ChildAllocationV1`, including its immutable delegate operation grant/capability grant/admission identity, additive ceilings, depth/concurrency, absolute child deadline, and mode. Child terminal always CASes `reserved -> child_terminal` with the canonical mode/status-valid terminal union and inclusive usage bounded by the granted ancestor-inclusive ceilings. Success binds exact child `Run.resultRef`/RunResult; failure/cancellation binds exact `terminalDetailRef`; the two are structural alternatives. Mutating success additionally binds the recomputed base/result/diff-exact `ChildPatchManifest`. Every branch carries one exact `ChildResultModelContentV1` pair whose success summary equals RunResult summary text or whose stopped content is only status/reason; allocation and eventual parent-owned `ChildResultItem` repeat those bytes. If the parent is running, that row-only change does not asynchronously revise the parent; the parent settles in its next revisioned transaction. If the parent is lease-free on the exact child WaitingSubject, the same child-terminal transaction may CAS to `settled`, move actual inclusive usage to consumed, release exactly the component-wise unused grant, append the identity-matched ordered `ChildResultItem`/merge items, record `parentSettlementRevision`, and queue or stop the parent once. No transition refunds consumed use, changes terminal/model-content bytes, reverses settlement, detaches ancestry, or loses a wake across restart.

`authorization_grants` stores exactly `AuthorizationGrantV1`, not an opaque target bag, secret store, Run status, or `OperationGrantV1`. Creation starts only at `active(rowVersion=1,useCount=0)`. Consumption publishes an exact `AuthorizationConsumptionReceiptV1` first and atomically installs `consumed(rowVersion=2,useCount=1,consumptionReceiptRef)` with its identity-matched Run-admission, MCP-registration, or derived-authorization consumer. Revocation CASes only active to `revoked(rowVersion=2,useCount=0)`; replaying revoked is stable, while revoking consumed is a successful no-op that preserves the receipt and reports already consumed. Target, owner, source request, purpose, expiry, digest, version, and forbidden fields validate on every transition. Revocation blocks unused/future authority but cannot erase captured artifacts, revoke already derived authority, or rewrite a claimed invocation. Secret values remain in the external trusted credential service.

For `DependencyPolicy.installScriptsGrantRef`, admission must consume the exact active `AuthorizationGrantV1` with target `dependency_install_scripts` and publish the one exact `DependencyInstallScriptsAuthorizationTemplateV1` in the same transaction. The template binds the admitted Run/principal/workspace, source grant and receipt, guest toolchain, allowed adapters, exact lockfile ref/path/digest, registry-target digest, `maxCandidateGenerations = repairAttempts + 1`, one dispatched attempt per plan, and `expiresAt = Run.deadlineAt`. Candidate script dispatch never consumes the user row again: its exact Journal-backed `OperationGrantV1` uses `provenance.kind='dependency_install_scripts_template'` and one previously unused candidate ordinal. A changed lockfile, registry projection, toolchain, policy, Run, or ordinal cannot reuse the template.

`mcp_registrations` points at the current immutable registry revision while CAS retains every older revision. Revision zero is invalid; `mcp.register`/`refresh` require the exact owner/current revision and a completed matching `admin_operations` probe, then advance the row by one. Before I/O the target contains only byte-sorted unique tool names plus exact `RequestedMcpRecoveryV1` intent; it contains no final recovery profile/template/predicate/contract or registry digest. The completed probe result contains only raw byte-sorted unique `McpProbedToolInterfaceV1` rows and `probedToolsListDigest`, with no requested recovery or final contract. The trusted reducer requires every explicitly requested name to match exactly one raw interface, rejects missing/duplicate/mismatched requested names or duplicate raw names, retains additional valid raw interfaces with exact `manual` recovery, copies every interface field/digest unchanged, appends the selected/default final `McpRecoveryContract`, and computes each `toolContractDigest` plus final `toolsListDigest`. Publication is deliberately acyclic: `registryCoreDigest = SHA-256(JCS(final revision core with registrationReceiptRef and manifestDigest omitted))`; the receipt binds that core, exact admin target/released attempt/raw result/positive closure, raw `probedToolsListDigest`, and final `toolsListDigest`; the final `McpRegistryRevision` references the receipt and computes `manifestDigest = SHA-256(JCS(final revision with manifestDigest omitted))`. Receipt and final revision artifacts publish first, then the registry-row CAS, completed admin operation, revision/receipt roots, and `control_requests` response commit together. Admitted Runs retain their exact old revision ref/manifest digest. Registration and refresh never overwrite old bytes, trust server assertions as proof of statelessness, or store credentials.

Storage uses the exact closed admin-probe row:

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

`admin_operations` is a small executable-probe crash fence, not a Run. Identity is `(principalId,method,requestId,attempt)`; attempts are contiguous `1..3` for the exact request digest/target and permit at most one nonterminal row. Every base ref has a mandatory exact digest: target, static probe core, containment plan, and SandboxLaunchSpec. `targetRef` resolves only to `McpAdminProbeTargetV1`; register/refresh XOR, request/target digest, executable/argv/endpoint/TLS/grant/recovery/lifecycle all match the row, plan/spec, broker request, result, receipt, and registry core. A stdio target carries the exact consumed execution-identity grant id plus `AuthorizationConsumptionReceiptV1` ref/digest; storage rehashes that receipt, requires it to consume the named grant for this registration/probe target, and requires its resolved signed executable/argv to equal the SandboxLaunchSpec. The BrokerRequest `stdio` branch is exactly `{kind:'stdio'}` and carries no opaque/duplicate executable ref: the broker decodes that target and requires its stdio transport to equal the admin SandboxLaunchSpec/process identity. `probePayloadCoreRef` resolves exact static `AdminProbePayloadCoreV1`, is published before the row, excludes dynamic identities, and equals the launch field and later broker `payloadRef`; `AdminProbeBrokerRequest` repeats both target and payload digests. Deadline is normalized target launch timeout and never extends. Phase/dispatch CASes are only canonical edges. Prepare commits before action; active binds blocked containment; claim binds exact request; release rechecks row/principal/Supervisor/containment/target/core/decoded stdio process identity or endpoint/grants/lease/deadline/dispatch immediately before capability release. Neither gate reads Run authority.

Completed storage validates exact `McpAdminProbeResultV1`: the released operation/attempt/dispatch/request/target/core/containment match, every bounded secret-free response rehashes, normalized protocol projections match, tools are unique and byte-sorted, and the result digest is recomputed. Every terminal row validates exact `AdminProbeClosureEvidenceV1`: `no_spawn` is pre-release-only and wraps matching exact no-spawn evidence while forbidding process/dispatch/request fields; `containment_dead` repeats actual containment and phase-valid dispatch/request plus exact death/current-inspector closure. A failed row additionally validates exact `AdminProbeErrorV1`, including matching closure/diagnostic ref+digest and the closed deterministic-versus-recovery code union. `final_rejection` requires deterministic true; `retryable_recovery|retry_exhausted` require false. The row's result/evidence/error/control-response ref+digest pairs are exact and forbidden outside their canonical branches. Timeout, lease expiry, Supervisor loss, or inaccessible containment is never closure proof. Startup never adopts or renews an old active probe.

A deterministic probe/target rejection is `final_rejection` on any attempt and commits its error response/control row. A death-proven Supervisor/transport/preactivation recovery failure is `retryable_recovery` on attempt 1 or 2, commits no response/control row, and permits the next attempt only after respectively 1s or 5s; the same failure on attempt 3 is `retry_exhausted` and commits the final error response/control row. Concurrent or same-request retries join the one current row. Completion commits the result, new MCP revision/receipt, exact response ref, and `control_requests` row together. Thus the public mutator has exactly one immutable final response while crash recovery remains bounded. No admin row has a prompt, Session transcript, worker Run pointer, budget, child, Checkpoint, or resume surface.

#### 8. Publish immutable artifacts and Checkpoints safely

`ArtifactRef` is imported verbatim from the canonical RFC as `type ArtifactRef = string`, and its runtime decoder accepts exactly raw `^[0-9a-f]{64}$` complete-byte SHA-256 values. No prefix or alternate spelling is legal. Ordinary Kernel CAS objects live only below `${stateRoot}/cas/namespaces/<current KernelGenerationIdentityV1.casNamespaceId>/sha256/<first-two-hex>/<full-hex>` and are never addressed by caller paths. Candidate publication uses its candidate namespace id at the same relative fanout. Migration control, receipt, authority, archive-manifest, and other deliberately out-of-generation artifacts instead use `${stateRoot}/migration/artifacts/sha256/<first-two-hex>/<full-hex>` (or their separately fixed descriptor-held database/archive paths) and never appear in `CasNamespaceManifestV1`.

Publication order is: create a same-directory `O_EXCL` temporary file; stream and hash; `fsync` file; no-replace publish or verify an identical existing regular file; `fsync` directory; insert verified immutable `artifacts` metadata; only then let another SQLite row reference it. Crashes may leave unreachable verified objects, never committed dangling refs. Reads revalidate type, length, digest, and the exact canonical schema selected by the consuming field. CAS GC may remove only proven-unreachable orphans older than seven days after a complete reachability walk rooted in every Session/item including exact `SessionRunTerminalItem` result/detail/summary and Session compaction summary pairs, every retained/generated `SessionHandoffV1` JSON/Markdown descriptor and its workspace/projection/entry/excluded-range/source closure, Run/spec/result/objective, endpoint-negotiation request/response, every SourceManifest's exact `SourceProjectionSpec`/`FrozenIgnoreRulesV1`/rule-source-content/`SourceIncludeClassificationEvidenceV1`/`SourceIncludeAuthorizationV1`/grant-consumption closure, every Git WorkspaceState's exact `PrivateGitStateManifest`/`SanitizedGitConfigV1`/index/ref/pack graph, every dependency plan's root package/lock/toolchain/endpoint/grant/cache graph, every normal/compaction model request and its exact prompt projection/messages/tools/context/retained-adapter/native-body/compaction-envelope graph, every model/tool/input item and its exact text/observation/schema/diagnostic/audit/model-content graph, every `RunContextCompactionItem` plan/turn/summary plus replacement ContextManifest segment, every `RepairDiagnosticItem` audit receipt/stdout/stderr plus minimized model-content edge, every proof-carrying delivery frontier/`DeliveryTerminalProjectionEvidence`/TerminalDetail projection edge, Checkpoint, Journal, every retained `run_events` payload/message ref, every unexpired `ListReadCutEntryV1` typed-summary artifact edge, WorkerLaunch/AdminOperation/local-inference activation cycle and launch, every participant request/frontier and activation-failure ref, control response, exact `ChildAllocationV1` including child handle/result/detail/patch/model content, exact `AuthorizationGrantV1` and consumption receipt, exact `ApprovalDecisionV1`, every `PolicyDecisionItem` and their exact `PolicyChannelEvidenceV1` plus signed-engine/parser/source closure, every exact `InvocationAmbiguityEvidenceV1` plus owner-takeover, broker-token, SandboxLaunch/containment/death, or publication-path-proof branch closure, exact `ManualAbandonAttestationV1`, every `BudgetSettlementV1`, every `PostClaimNoReleaseEvidenceV1` plus its inspector/token-or-no-spawn closure, `InvocationDispatchClosureEvidenceV1` and its exact `BrokerReleaseFenceEvidenceV1` or containment/death closure, and `KernelIntegrityEvidenceV1` with its before/after source/claim/containment/spec/inspector closure, MCP revision/receipt plus every registry-transitive schema/transport/runtime/endpoint/binding/risk-consent/safety-assertion/adapter/status-template/static-arguments/predicate/admin/death-evidence ref, every admin target/payload-core/result/closure/error/diagnostic/response edge, policy and `OperationGrantV1`, dependency install-script template, `VerificationClosureV1`, every `InheritedVerificationProvenanceV1`, and all of their source result/closure/receipt/evidence edges, every `SandboxProfileV1` and `SandboxLaunchSpecV1` reachable from a RunSpec, WorkerLaunch, AdminOperation, local-inference launch, claimed Journal phase, ProcessContainment, or containment evidence, local model registration plus its exact `LocalModelObjectClosureV1` state-root/manifest/tokenizer/all-model-object graph, local service/capability/boundary/provenance closure, wait/StopIntent, containment plan/actual containment/no-spawn/death evidence, every referenced `SupervisorInspectorIdentityV1` plus its signed RuntimeBundle manifest and exact supervisor executable-entry closure, every retained `GuestToolchainManifest` plus signature and complete guest-image bytes propagated through plan/runtime/containment/evidence/relaunch, runtime bundle, backup, and archive. Event/list-cache authoritativeness and artifact reachability are separate: pruning a terminal display row removes its event-root edge only in the same retention transaction, and deleting an expired cut removes only that cache's edges; a retained event or unexpired cut can never point to a collected artifact. An unknown schema, broken typed edge, or incomplete walk deletes nothing.

Every `PolicyDecisionItem` root is branch-transitive. Direct policy roots its exact channel evidence as both evidence and decision plus the subject-specific grant or `PolicyDenialOutcomeV1`; interactive approval additionally roots the exact WaitingSubject and `ApprovalDecisionV1`. A denied outcome roots its exact ToolResult, required/advisory verifier StopIntent or `VerifierSkipItem`, delivery StopIntent, or dependency-script StopIntent. `skipped_by_policy` roots the same channel evidence pair, while `skipped_by_user` roots the approval decision and forbids the policy digest. Every generic-runtime stop likewise roots exact `RuntimeFailureEvidenceV1`, current inspector, and its sole branch-specific Journal/request/authority/provenance closure. A missing or widened branch makes the walk incomplete and deletes nothing.

For avoidance of doubt, the private-Git root above is the complete exact `GitIndexSnapshotV1 -> GitObjectClosureV1 -> GitObjectPackV1 -> raw pack/index bytes` graph, not an opaque pack-ref list. It retains every and only reachable object. Every `workspace_generations` row also roots its immutable identity, source Checkpoint/workspace state, materialization/sealing snapshot, quarantine evidence and reason-specific failure/no-spawn/recovery/death closure, retirement evidence, StateRoot locator, inspector, and any distinct replacement generation. Quarantined and retired rows remain roots while authoritative history or retention refers to them.

The singleton `canonical_time_fence` row is retained for the Kernel generation and cannot be GC'd or reset. Every retained `LocalPrincipalIdentityV1` and `LocalControlChannelIdentityV1` is an artifact root for its StateRoot/process identity; a UDS channel additionally roots its exact `LocalSocketPeerObservationV2` and the distinct endpoint/listener/accepted-socket observations. The live accepted-connection capability is not serializable, a GC root, or recoverable from these bytes. Control responses may replay through a later authenticated channel, but the original authority-bearing request/decision remains rooted by its original channel identity.

Every active or archived migration authority/control/receipt is also a permanent root for its complete typed graph: root/auth observation and file identity, non-secret projection, endpoint/binding/round-trip evidence, inventory/backup, exact source and archived database images, live/final CAS namespace manifests and entries, source/candidate/generation identity, exact archived-generation manifest, rollback request/consent, legacy generation/auth outcome, and both prepared/published authority markers. The StateOwner genesis acquisition roots its exact Kernel generation identity, so migrated bootstrap cannot outlive or collect the marker/candidate/image/CAS closure it proves. No migration control cleanup or authority switch deletes the prior generation graph automatically.

Every retained `StateOwnerRecordV1`, exact `StateOwnerAcquisitionEvidenceV1`, and terminal `StateOwnerTransitionEvidenceV1` are permanent authority. Each row/evidence roots every referenced exact `PlatformProcessIdentityV1`, `StateLockIdentityV1`, and lock-transitive `StateRootIdentityV1`; the row/acquisition roots its signed RuntimeBundle manifest plus exact role-`supervisor` executable-entry closure. Clean/takeover acquisition roots the prior terminal row/transition; takeover transition additionally roots the successor RuntimeBundle/process identity it names. Inspector identity roots the same process/lock/root/bundle closure. None of these acquisition/transition identities are retention-pruning candidates, so genesis, clean restart, takeover/graceful release, and every inspector proof remain auditable through the complete epoch chain and current active row.

Every reconciliation wait roots exact `ReconciliationProbeStateV1`. In-flight state roots its complete `ReconciliationProbeDispatchV1`, including persisted broker request/target/fence or inspector task target. Post-probe pending/exhausted roots exact wrapper evidence; subject observations follow only the valid MCP/publication/worker closure, and timeouts follow the exact dispatch plus broker drain or `ReconciliationInspectorTaskClosureV1`, including any owner-death acquisition evidence. Count-zero pending forbids evidence. Missing dispatch, task closure, wrapper, or ref/digest edge makes reachability fail closed.

Every retained Run roots its RunSpec's exact `RunObjectiveV1`; no Session label, request replay bytes, argv, or worker field is a substitute. Every retained `ModelTurnItem` roots its exact `AgentModelTurn` and required `ModelTextV1`. Every `ToolBatchItem` repeats that text root and additionally roots the complete ordered `ToolCallInputV1` set, every exact `ObservedToolCallInputV1`, the selected input schema for resolved/known-invalid branches, and each rejected-input diagnostic. Every `InputRequestItem` roots its exact `InputPromptV1`, prompt `ModelTextV1`, and optional exact `InputResponseSchemaV1`; every `UserInputItem` roots that request/prompt plus exact authenticated `UserInputPayloadV1` and its separate exact `UserInputModelContentV1`. Every `ChildResultItem` and terminal `ChildAllocationV1` root the exact child Run result-or-terminal-detail edge, shared `ChildResultModelContentV1`, and, for mutating success, the complete `ChildPatchManifest` base/result/diff/operation entry closure. Every ordinary `ToolResultItem` roots its exact `ToolResultPayloadV1`, exact `ToolResultModelContentV1`, and the branch-specific Journal result/output schema, policy/approval decision, diagnostic/Journal error, invalid-call set, or StopIntent/notice closure. The sole fenced retry-unknown exception roots direct `RetryUnknownCancelledResult` plus its settlement and dispatch-closure evidence and must not be traversed as a tool-result payload or model content. Every `FinalCandidateItem` roots its producing model/delivery item, summary, base/result SourceManifests, exact `WorkspaceDiffV1`, and every diff operation entry/blob; a RunResult additionally roots the identical candidate summary. Missing objective/text/observation/input-prompt/input-payload/input-model-content/child-result-or-patch/tool-model-content/result/diff/candidate refs, branch edges, or ref/digest equality makes the walk incomplete and GC a no-op.

Every retained RunAssembly/context plan roots and closed-decodes the exact signed `RuntimeBundleManifest` plus every selected `RuntimeBundleStructuredArtifactV1` root/member edge. It roots the retained signed provider adapter, system/compaction prompt closure, every common ModelRequestV1, its typed projection and exact native body bytes. No custom tokenizer or prompt/profile graph is required. When capability source is endpoint negotiation, it also roots the exact `EndpointModelNegotiationReceiptV1`, its closed request/response artifacts, exact credential-binding sequence, endpoint/TLS/adapter identity, and the response's complete five-claim projection. Every open or completed MCP-server lifecycle roots its exact `McpServerInstanceIdentityV1`; a completed lifecycle additionally roots its `McpServerLaunchReceiptV1`, prepared/claimed/completed Journal chain, exact budget settlement, stopped item, call-scoped SandboxLaunch/containment, registry revision, and death evidence. Every `PublicationProofV1` root follows its exact delivery plan/workspace/inspector base plus all branch-specific observation, preserved-preimage, result-item, ambiguity, transient-path, projection, and Git-index refs. No retained Journal, item, frontier, wait, result, StopIntent, TerminalDetail, Checkpoint, or event may point to one of these artifacts after its transitive closure is collected; unknown proof, RuntimeBundle kind/member, or manifest branches make GC a no-op.

Every retained workspace-script execution grant/command/spec/launch roots its exact `InterpreterIdentityV1` and signed guest-toolchain entry closure. Every isolated-root containment plan, SandboxLaunch, actual containment, no-spawn/death evidence, admin/local/MCP lifecycle, and retained event that reaches one roots the identical `SandboxRootImageV1` plus its signed RuntimeBundle `sandbox_root_profile` entry. A missing ref/digest edge or inconsistent repetition fails the reachability walk and prevents collection.

Every Checkpoint has non-null verified context/workspace refs and the exact canonical shape. `publishCheckpoint` is not a generic pointer update: it validates the quiescent cut, item/Journal sequence continuity, frontier, artifacts, and `basedOnRunRevision`, then inserts the immutable Checkpoint, installs `latestCheckpointId`, advances the Run exactly one revision, and emits the workflow event in one transaction. An open invocation remains in RunJournal and cannot be hidden inside the Checkpoint.

#### 9. Return the complete recovery closure and keep events non-authoritative

`readRecoveryClosure(runId)` returns and cross-validates:

```text
immutable RunSpec
+ authoritative Run row
+ latest ready Checkpoint
+ ordered typed Run items after Checkpoint.runItemSeq
+ RunJournal facts after Checkpoint.journalSeq
+ every current or unretired worker_launches row
+ every child_allocations row where the Run is parent or child
+ when the assembly selects local_zero_cost, its matching local_inference_activation_cycles participant/cycle/failure rows plus every current/unretired cycle-linked local_inference_launches row and boundary/model/capability evidence
+ referenced model-turn/text/tool-input/tool-result payload/workspace-diff/final-candidate producer+summary, policy/frontier/wait/probe/StopIntent/approval-decision/manual-attestation/operation-grant/authorization receipt/template/budget-settlement/dispatch-closure/sandbox-launch/containment plan/evidence/inspector-identity/child/verification-closure/inherited-provenance/result artifacts
```

The closure decodes and cross-validates every requested canonical type rather than returning untyped refs. It begins with RunSpec's exact sole `RunObjectiveV1` and revalidates its Unicode/byte-count/digest bounds. It follows every base/result SourceManifest through exact `SourceProjectionSpec`, `FrozenIgnoreRulesV1`, source-content refs, and each `SourceIncludeAuthorizationV1` plus its exact `SourceIncludeClassificationEvidenceV1` descriptor/captured-entry/Git-index/frozen-rule closure or consumed read-grant receipt; rules/projection/source/workspace digests and identities must remain equal. Each Git workspace additionally follows exact `SanitizedGitConfigV1` through `PrivateGitStateManifest` Head/index/refs/packs/config; no omitted Git config becomes runtime state. It follows every `ModelTurnItem` through exact `AgentModelTurn` and `ModelTextV1`, every `ToolBatchItem` through the same required text and complete ordered resolved/rejected `ToolCallInputV1` sequence plus each exact observation/schema/diagnostic closure, every input request/user item through exact prompt/text/optional schema/authenticated payload and identity-matched executed result/model-content closure, every `RepairDiagnosticItem` through its ordered verifier-result/receipt/stdout/stderr audit diagnostics plus only their exact minimized `VerifierRepairModelContentV1` projections, and every other ordinary `ToolResultItem` through exact identity/outcome-matched `ToolResultPayloadV1`, its exact ref-free `ToolResultModelContentV1`, and branch closure; only fenced retry-unknown follows direct `RetryUnknownCancelledResult` and yields no model-content edge. Every `FinalCandidateItem` follows the exact producing model/delivery item, summary, base/result SourceManifests, and sorted exact `WorkspaceDiffV1`; source/diff digests, operation discriminator/producer fields, and eventual RunResult summary equality are revalidated. Every dependency frontier follows the exact root-only `DependencyAcquisitionPlan`, root package/one lockfile/toolchain/endpoint/grant closure, and matching cache/template/grant/effect facts. It follows the assembly's exact signed provider adapter, system/compaction envelope closure and RuntimeBundle entries, and any endpoint-negotiated capability evidence through exact `EndpointModelNegotiationReceiptV1`, fixed-query request, closed full-five-claim response, and endpoint/TLS/adapter equality; `RunPolicySnapshotV1` and every live/reconciling `OperationGrantV1`, including exact allow `ApprovalDecisionV1` or verifier-template `AuthorizationConsumptionReceiptV1` provenance; exact `AuthorizationGrantV1`/receipt/template dependencies still needed by admission-derived authority; both parent/child `ChildAllocationV1` rows; every Journal terminal/unknown `BudgetSettlementV1`, every post-claim-failed `PostClaimNoReleaseEvidenceV1` or verifier-infrastructure receipt plus containment-death closure, retry dispatch-closure evidence, and manual-abandon attestation; any finalize/result `VerificationClosureV1`, exact `InheritedVerificationProvenanceV1`, and every source result/closure/receipt fact they prove; every complete registry-transitive MCP recovery artifact graph plus each open/completed `McpServerInstanceIdentityV1` and completed `McpServerLaunchReceiptV1` lifecycle closure; every WaitingSubject's exact `ReconciliationProbeStateV1` plus each retained `ReconciliationProbeEvidenceV1` wrapper and its subject-valid MCP/`PublicationProofV1`/worker evidence or exact `ReconciliationProbeTimeoutClosureV1`; every publication proof reachable from Journal, delivery frontier/result/StopIntent/TerminalDetail; every WorkerLaunch/AdminOperation/local-inference-launch/claimed-Journal `SandboxLaunchSpecV1`; and every active or retained `ProcessContainmentPlanV1`, no-spawn/death evidence, actual containment edge, and evidence-referenced exact `SupervisorInspectorIdentityV1` with its signed RuntimeBundle/supervisor-executable closure. For a `local_zero_cost` assembly it additionally validates the exact `LocalZeroCostProvenanceV1` stable-service projection, the Run's exact current or historical `run_model_frontier` cycle participant when present, every current/nonterminal cycle and cycle-linked launch for that owner/service/spec, terminal cycles required for participant replay, exact `LocalInferenceActivationFailureV1`, and the service/model/capability/boundary/containment closure; dynamic replacement identities may differ only where excluded from `stableServiceIdentityDigest`. It enforces model-turn/text/observation/call-input/input-prompt/input-payload/repair-diagnostic/item/audit-payload/model-content stop/outcome/identity equality; exact diff comparison/candidate producer/summary/source/result equality; model request/capability/provider/model/bundle equality, deterministic context estimates and signed reservation reproducibility; MCP instance/receipt/Journal/stopped-item/settlement/death-evidence equality; publication base/branch/observation/Journal/delivery equality; participant uniqueness/order/bounds; cycle ordinal/phase/attempt/launch cardinality; launch-to-cycle equality; reconciliation phase/count/ordinal/nonce/deadline/wrapper/subject-or-timeout-closure XORs; the absent-prepared/same-ref-post-claim/non-spawning-forbidden Journal matrix including pre-dispatch-failed claim/evidence absence and the exact two-form post-claim-failed closure; exact settlement equations; and exact launch-ref/digest/inspector-state-owner equality through actual containment and evidence. It fails `RECOVERY_REQUIRED` on any missing artifact, unknown/widened type, digest mismatch, sequence gap, invalid frontier/wait/probe pairing, impossible launch/cycle pointer or phase, broken objective/model-item/input/repair/diff/candidate/source/private-Git/dependency/allocation/authorization/decision/template/settlement/closure/model-request/capability/MCP-instance/publication-proof/launch-spec/local-service/reconciliation/containment/inspector relation, invalid Journal transition, or incompatible schema/runtime bundle. It never consults a `control_requests` response or `run_events` to choose execution; the authoritative activation cycle and current Run decide unfinished fanout.

For every generation ref in that closure, storage also decodes the exact `WorkspaceGenerationIdentityV1`, its authoritative `WorkspaceGenerationStateV1`, and every snapshot/failure/quarantine/retirement/worker-recovery evidence edge. Any worker loss must be represented by an exact `fenced_reconciling` row bound to the current worker-death wait and sole reconciling launch. Both recovery dispositions must resolve the same exact worker-recovery quarantine artifact for the old row; `restored_from_checkpoint` additionally resolves a distinct replacement identity in `preactivated_readonly` from the exact named ready Checkpoint. Broken Git object-closure equality, stale generation phase, missing StateRoot locator, wrong deterministic quarantine target/source version/observed-state union, selectable quarantined identity, or WorkerLaunch/generation projection divergence is `RECOVERY_REQUIRED`.

For every `local_zero_cost` assembly, that recovery walk additionally decodes the selected exact active `LocalModelRegistrationV1`, requires its embedded `LocalModelObjectClosureV1` to be byte-identical to `expectedObjectClosureRef`, and follows the complete exact StateRoot/model-manifest/tokenizer/byte-sorted model-file object graph. Every object ref/digest/path/size/count/checked-total and closure digest revalidates; an opaque store id, mutable lookup, cache entry, or post-enrollment path is `RECOVERY_REQUIRED`.

Every generic-runtime stop in that recovery closure additionally roots exact `RuntimeFailureEvidenceV1`. Recovery recomputes its omission digest and current-inspector freshness, requires Run/frontier/failing-op equality to the winning StopIntent and TerminalDetail, and follows exactly one branch: completed unusable response; final failed model attempt/request/Journal sequence; credential grant/endpoint/latest authority records under the pre-I/O failure; retry-unknown result plus settlement/dispatch closure; candidate dependency plan plus final acquisition fact; or local provenance/spec/current boundary evidence. Missing, widened, cross-branch, diagnostic-only, or worker-asserted runtime evidence returns `RECOVERY_REQUIRED`.

For every prepared/completed model attempt, recovery decodes the common `ModelRequestV1`, its exact native body and typed normal/compaction projection; recomputes omission digests; and reconstructs frozen instruction, Session, objective, ContextManifest, tool-schema and model-content sources. It reloads the retained model session and re-prepares identical bytes/caps/reservations; the Journal and completed turn repeat that request/projection pair. The normalized response digest includes optional provider-bound opaque continuation and untrusted usage, with absent fields omitted and calls in retained index order. Recovery also validates each `SessionRunTerminalItem` status/result/detail/summary matrix, never-coalesced Session raw segment, and compaction item/summary range/source/ref/digest equality. Adapter-local prompt assembly, omitted/extra projected items, audit/verifier bytes, changed continuation or substituted summaries are `RECOVERY_REQUIRED`.

`run_events` allocates `eventSeq` in the same transaction as each authoritative Run workflow mutation and supports retained attach strictly after a cursor. In the one attach snapshot, `earliestValidCursor=max(0,earliestRetainedEventSeq-1)`: cursor `0` and exactly `earliestRetainedEventSeq-1` are valid, a smaller cursor returns `EVENT_CURSOR_EXPIRED`, a cursor above `highWaterEventSeq` returns `INVALID_REQUEST`, and equality with high-water returns an empty page with the identical cursor. Progress is bounded/coalescible display telemetry. Cursor pruning may delete only terminal display rows after at least 30 days, records the earliest retained sequence, and retains at least the terminal `state_changed` row as a nonempty anchor. It cannot change recovery, authorization, budget, verification, or scheduling truth.

#### 10. Import legacy authority once on macOS/Linux

Migration persists only the following canonical RFC 8785/JCS authority documents; no implementation-local sentinel, optional property bag, or credential byte is legal:

Canonical types: `MigrationFilesystemRootIdentityV1`, `WindowsLegacyRootIdentityV1`, `WindowsOutputDirectoryIdentityV1` and 33 related definitions.
Import their complete definitions from
[RFC 16. Migration And Kernel Cutover](../../rfcs/2026-08-11-durable-verified-run-kernel.md#16-migration-and-kernel-cutover).
This package enforces that contract without a second schema copy.

The migration decoder applies the canonical omission equations exactly: each container self-digest omits only itself; every ref/digest pair rehashes the named artifact bytes; `entriesDigest` and `recordsDigest` hash their complete arrays; and copied/restored-entry digests hash the byte-sorted reobserved regular-file projections. It enforces canonical path, sort, uniqueness, safe-integer count, descriptor identity, fixed-mode/link-count, source-observation, non-secret projection, credential-authority/binding, and closed auth-outcome rules. `ArchivedKernelDatabaseImageV1.imageDigest` omits itself, while its `sourceContentDigest=contentDigest` equals a full rehash of both the exact closed source image and read-only copied bytes; all source identity, application/user/schema, derived path, ownership, mode, link-count, and byte-count fields cross-match. `ArchivedKernelGenerationManifestV1.manifestDigest` omits itself and its source identity/id, archive-image/content, and final CAS namespace/id/root fields exactly equal their decoded artifacts. `fresh_empty` and `migrated_candidate` generation ids/digests use the RFC formulas; no directory name, timestamp, or free string is generation authority.

`KernelSchemaManifestV1` is the sole v1 database-schema authority. Its exact bytes are one signed non-executable RuntimeBundle `schema` entry `kernel_state_schema_v1@1`, and fixed Supervisor code interprets it only as data. `ddlStatements` is a nonempty ordered NFC/no-NUL list with transaction/attach/detach/pragma/vacuum/extension/writable-schema/temp/external-function SQL forbidden. Executing it in a fresh database with the literal application/user versions yields exactly the unique byte-sorted complete `sqlite_schema` projection, including autoindexes with null SQL and no unlisted object. `schemaDigest=SHA-256(JCS({stateSchemaVersion,sqliteApplicationId,sqliteUserVersion,ddlStatements,sqliteSchemaObjects}))`; `manifestDigest` omits itself.

`KernelDatabaseImageIdentityV1` is published only after all connections close, `wal_checkpoint(TRUNCATE)` completes, `-wal`/`-shm` are absent, and the exact same-user no-follow `0600` one-link database plus parent directory are fsynced. Its schema ref/digest rehashes that signed profile; application/user versions, a fresh `sqlite_schema` projection, and `schemaDigest` equal it exactly, alongside the full-file digest and successful foreign-key/integrity checks. `ArchivedKernelDatabaseImageV1` repeats the same profile pair/schema projection after descriptor copy. Fresh generation `pristineSchemaManifestRef|Digest` equals its database image and `pristineSchemaDigest`; migrated candidates forbid those three fields but their decoded image carries the same signed schema authority. `CasNamespaceManifestV1` is an immutable boundary snapshot below `${stateRoot}/cas/namespaces/<namespaceId>/sha256/<first-two-hex>/<full-hex>`, excludes itself/control/archive artifacts, byte-sorts unique raw ArtifactRefs, rehashes every fixed fanout object, and enforces checked `objectCount`, `totalBytes`, and `rootDigest=SHA-256(JCS(entries))`. A `generation_birth` manifest is all-and-only under the held publication gate immediately before authority/genesis; candidate and generation identities require that literal and repeat its ref/digest, namespace, and root. Active Run publication may then append to the same namespace, and later objects do not invalidate the historical birth snapshot. A `rollback_final` manifest instead requires current global no-write proof, covers the complete current namespace, and remains all-and-only after that namespace is sealed read-only. Migration-only control/receipt/authority/archive-manifest objects use the separate `${stateRoot}/migration/artifacts/sha256/<first-two-hex>/<full-hex>` fanout or their exact database/archive path and never enter a generation manifest. At the durable globally quiescent `rollback_draining` boundary, trusted code publishes a fresh current database identity, descriptor-copies the same bytes to the exact migration/source-generation archive path, fsyncs, seals them `0400`, publishes exact `ArchivedKernelDatabaseImageV1`, publishes `CasNamespaceManifestV1(snapshotBoundary='rollback_final')`, seals the complete current CAS namespace, then publishes exact `ArchivedKernelGenerationManifestV1` outside that namespace. Its literal snapshot boundary includes all productive state through drain and explicitly excludes only the later restoring receipt/control and StateOwner terminalization tail. A live WAL tuple, logical dump, SQLite backup with different bytes, mutable/wrong-path archive, partial/extraneous boundary scan, reopened path, symlink, hardlink, self-hashing archive object, or mismatched byte makes the boundary ineligible.

Every rollback starts from retained exact `RollbackToLegacyRequestV1`, including non-secret outcomes. Its omission digest covers the current Kernel authority marker, exact current `KernelGenerationIdentityV1`, and selected backup. `rollback_draining` repeats that request and exact source-generation identity pair; only after its globally quiescent archive verifies may `rollback_restoring` and the legacy receipt repeat both the same source identity and exact `ArchivedKernelGenerationManifestV1` pair. A birth image, pre-drain CAS root, or another generation cannot be substituted. `allowPlaintextLegacyCredentials=false` may produce only `restored_absent|rendered_nonsecret`; only the `true` branch may derive matching `PlaintextLegacyCredentialConsentV1` and `rendered_with_credentials`.

The only control document is `MigrationControlV1` at `${stateRoot}/migration/control-v1.json`; only contiguous same-id `cutover_preflight -> cutover_candidate_ready -> credential_cutover` and `rollback_draining -> rollback_restoring` replacements are legal. The only authority document is `MigrationAuthorityMarkerV1` at `${stateRoot}/migration/authority-v1.json`; its matching receipt and complete generation closure are published before the marker, which is file-fsynced, atomically renamed, and directory-fsynced last. Control cleanup never changes authority. Startup closed-decodes both paths before opening either runtime; malformed, skipped, crossed, split-brain, or doubly authoritative state starts neither runtime.

`src/state/migration/authority.ts` exposes only typed phase-CAS entrypoints for those five control branches, the rollback-boundary archive publication, receipt preparation, authority-marker publication, and idempotent post-authority cleanup. Each receives the exact expected control ref/digest/revision plus the continuously held current StateOwner token and full ordered-lock witness; rollback entry additionally requires exact `RollbackToLegacyRequestV1` and source Kernel generation pair. The restoring transition accepts only that same source identity, exact verified `ArchivedKernelGenerationManifestV1`, already-verified legacy generation, prepared receipt, and prepared marker digest. There is no generic sentinel writer, phase setter, “latest file” chooser, marker patch, or cleanup-before-authority API. Rollback's owner-terminal transaction and the two prepared marker renames are separate typed operations: after terminalization the process cannot call any repository method, and a successor may invoke only the clean-acquire plus retained-restoring-marker replay path.

`cliq state migrate --check` and `cliq state migrate` share only a pure descriptor-held discovery/quiescence/normalization/validation planner. `--check` may hold already-existing advisory locks, but it creates or mutates no StateRoot/lock file, control document, endpoint/credential authority row, platform item, backup, CAS object, SQLite database, auth marker, receipt, or authority marker; it performs no platform-secret round trip, fsync, rename, or unlink. Its bounded deterministic report labels credential enrollment and every mutating step as required rather than completed. The real migration reruns every observation under the complete lock order and never trusts the report. Migration is supported only on macOS/Linux, including WSL2 only when it qualifies as Linux. The mutating command's exact order is:

1. acquire and then continuously hold through final control cleanup the one order: exclusive Kernel global/cutover gate plus current state-owner lock, local-model registry/object-store lock, legacy auth-store lock, every discoverable legacy Session/transaction/plan lock in canonical byte order, then the credential-authority lock. Under that complete held set publish exact `MigrationControlV1(phase='cutover_preflight',controlRevision=1)`; there is no release/reacquire window, recursive owner-lock acquisition, or alternate order;
2. use the platform legacy-quiescence inspector to prove no same-user process executes the legacy package/entrypoint and no process holds an open descriptor under a legacy root; inspect canonical argv, npm/npx/shebang chain, package realpath/version/digest, executable image, locks, and open roots rather than accepting the string `node`;
3. before general inventory, create exact `LegacyAuthStoreObservationV1` by descriptor-relative no-follow lookup while holding the root/auth locks. `present` requires one held same-owner `0600` regular/link-count-one `LegacyAuthFileIdentityV1` and recognized ProviderAuthStore-v1; `absent` requires exact `ENOENT` and structurally forbids a file identity. Publish exact `LegacyAuthNonSecretProjectionV1` with all secrets removed, preserving the normalized active provider/model/streaming/explicit-base-URL presence and exact endpoint refs; absent requires an empty projection;
4. for every present secret, invoke WP06's deterministic credential-enrollment request, require latest active endpoint/binding/authority equality and immediate same-user Keychain/Secret-Service round trip, and publish exact secret-free `CredentialRoundTripEvidenceV1`. Then publish/fsync exact `CredentialReadyManifestV1`; its records are unique/byte-sorted, `recordsDigest` rehashes the complete array, and absent auth requires `records=[]`. The original present raw file remains byte-identical and held while legacy is authoritative;
5. descriptor-walk, inventory, and hash the complete noncredential legacy roots without following links; reject ownership/type/link-count/mount/path instability and unresolved transactions with an exact supported remediation command. Exact `MigrationInventoryManifestV1` excludes `auth.json` bytes and repeats only the observation ref/digest;
6. publish and reverify exact `MigrationBackupManifestV1` for a read-only descriptor-relative backup containing every safe noncredential inventory byte, non-followed metadata, and the secret-free credential-ready graph—never raw auth bytes, platform secrets, or a migrated marker;
7. rescan processes, revalidate the held auth observation plus every credential authority/endpoint/binding/platform-item record, and rehash the locked noncredential inventory. Any identity, content, authority, or process change aborts before publication;
8. build a unique candidate SQLite/private-CAS generation, import in one transaction, validate all cross-field invariants, run `foreign_key_check` and `integrity_check`, fsync the database/CAS/parents, publish exact `KernelCandidateManifestV1` plus `KernelGenerationIdentityV1(origin='migrated_candidate')`, and atomically replace control with contiguous `cutover_candidate_ready`;
9. map legacy Sessions and ordered records to context-only Session rows/items. Construct exact live `WorkspaceIdentityV1` plus optional `RepositoryIdentityV1` only from held descriptor proof; otherwise publish exact execution-ineligible `legacy_unavailable`. Map compactions/plans/progress/handoffs/forks/ids to immutable context, old checkpoint/Git ghost refs only to `legacy_bookmark`, reset lifecycle fields without creating Runs, and create/adopt no local-inference cycle or launch;
10. after the candidate and complete closure reverify, first atomically replace/fsync control with contiguous `credential_cutover` naming the already-prepared exact `LegacyAuthMigratedMarkerV1` digest; only then replace/create and directory-fsync that secret-free marker at `auth.json` for both source-presence branches. Revalidate all held observation/credential records again;
11. publish the exact Kernel `MigrationReceiptV1` and matching `MigrationAuthorityMarkerV1` **last**, fsync the marker and parent directory, then clear the control file as cleanup and release locks. Only that verified authority marker permits Kernel startup.

Before step 11, legacy remains authoritative. Re-entry joins deterministic credential operations and validates the exact control revision. A crash after `credential_cutover` but before marker installation finds the original present bytes or exact absence unchanged and may clear control only after revalidation. A crash after marker installation but before Kernel authority restores the source observation: for `present`, it deterministically renders the exact non-secret projection plus still-matching frozen credential-generation platform items into a validated ProviderAuthStore-v1 and atomically installs/fsyncs it; for `absent`, it unlinks the migrated marker, proves descriptor-relative `ENOENT`, and directory-fsyncs. Unsupported/plain-HTTP/raw-Ollama/ambiguous entries, unavailable platform store, failed round trip/rematerialization, or identity/authority drift blocks publication. After authority publication, SQLite/CAS alone are authoritative; no runtime dual-writes legacy JSON. A later legacy write is divergence, is never imported automatically, and blocks rollback until exported.

Native Windows never runs steps 1-11 and never creates or opens Kernel SQLite/CAS, a migration sentinel, credential preflight, or authority marker. Its only producer is `cliq state export --output <absolute-new-file>`; output is required, must be outside Kernel state, and the destination basename must be absent on first execution. The sole final-present exception is exact crash replay of the already-complete byte-identical export for that requested basename; any other existing destination is rejected without overwrite. The signed helper acquires all discoverable legacy locks in canonical case-folded UTF-16 path order, opens only the root with `CreateFileW(...FILE_FLAG_OPEN_REPARSE_POINT)`, then opens every descendant relative to a continuously held parent with `NtCreateFile|NtOpenFile(OBJECT_ATTRIBUTES.RootDirectory=parent)` and no-reparse/least-access/share-read flags. It never pretends `CreateFileW` accepts a root-directory handle. Exact `WindowsLegacyRootIdentityV1`, `WindowsOutputDirectoryIdentityV1`, and temporary/final `WindowsExportFileIdentityV1` come from held-handle owner SID, volume/file identity, attributes/reparse tag, and security descriptor; replacement, junction, symlink, changing inventory, sharing ambiguity, or unreadable identity fails closed.

The exporter applies only exact `LegacyPortableProjectionSchemaV1` mappings signed through the selected Cliq RuntimeBundle's sole non-executable `legacy_windows_export_profiles_v1@1` schema catalog. The catalog entry's signed complete-file digest equals `projectionSchemaManifestRef`; decoding those exact bytes independently recomputes `LegacyPortableSchemaManifestV1.manifestDigest===projectionSchemaManifestDigest`, and the RuntimeBundle structured record lists exactly the schema refs as signed member objects. Complete-byte and semantic digests are never equated, and native Windows needs neither Kernel CAS nor an ambient package path. Mapping pointers/transforms, forbidden authority fields, finite output schema, and byte-sorted manifest are deterministic; `auth.json`, structured credentials/tokens/cookies/headers/environment, executable ownership, and legacy lifecycle authority are excluded, while user prose is retained without a false secret-scan claim. Session/payload/self digests rehash, and `LegacyPortableHandoffV1.objectRefs` is the unique byte-sorted all-and-only closure including the source-root identity, projection RuntimeBundle/catalog, schema profiles, Sessions, and payloads. The archive has the exact canonical header/length/JCS/object encoding and no compression, filename, host path, or ambient timestamp.

Publication holds the output parent, validates the final basename, and uses the sole stable temp `.cliq-export-<H(outputDirectoryIdentityDigest,final-basename)>.tmp`. It creates by relative `NtCreateFile` with no replace, writes/flushes/rereads/verifies the complete archive, and publishes the temporary identity only after successful verification. It then uses no-replace same-parent `SetFileInformationByHandle(FileRenameInfoEx)`, flushes the parent, reopens/verifies the final by relative handle, publishes the final identity, and returns exact `LegacyPortableHandoffExportReceiptV1`. The receipt requires `completedAt === LegacyPortableHandoffV1.createdAt`, and `receiptDigest=SHA-256(JCS(receipt with receiptDigest omitted))`; final-present replay therefore reconstructs the byte-identical receipt rather than reading a new clock. On re-entry, a valid final reconstructs the same handoff/temp/final identities and receipt, and a valid complete stable temp resumes verification/rename. A partial/invalid temp from an earlier process has no published creation identity and is therefore never automatically deleted: it blocks with owner-only manual-cleanup guidance. Only the process that successfully used `FILE_CREATE` may delete an incomplete temp through its continuously held creation handle before exit after rechecking the same file id; it then flushes the parent. Unknown/reparse/identity-changing temp, simultaneous temp+final, invalid final, or different export bytes likewise block and are never overwritten. `cliq state export --verify <absolute-file>` is the sole state-free consumer. It opens the parent/final file through the same held no-reparse protocol, repeats the bounded archive parse, schema, closure, and digest checks, and emits exact JCS `LegacyPortableHandoffVerificationResultV1` without opening or creating Kernel state. Its inline handoff is the decoded archive manifest; `exportId`, archive count/digest, inline output-directory identity, and inline final-file identity equal the reobserved held handles and archive bytes; the final identity is `phase='final'`. `verifiedAt` is canonical fenced time after the final reread, and `verificationDigest=SHA-256(JCS(result with verificationDigest omitted))`. It contains no temporary identity or synthetic completion time. Credentials require explicit re-enrollment; all Kernel migrate/inspect/admin/runtime commands return `UNSUPPORTED_PLATFORM`. WSL2 is Linux only after Linux qualification.

#### 11. Restore fully before publishing rollback authority

`cliq state rollback --to-legacy <migrationId>` is explicit and new-binary-owned. The stable bootstrap authenticates and publishes exact `RollbackToLegacyRequestV1`, which always binds the current Kernel authority marker/generation and selected backup; `--allow-plaintext-legacy-credentials` or exact interactive consent selects only its boolean branch. The live Supervisor reuses its already-held active StateOwner/OS-lock token; an unavailable owner must first be replaced only by exact death-proven takeover. The command then:

1. acquires and continuously holds the remaining canonical order—exclusive Kernel global/cutover gate plus current state-owner token, local-model registry/object-store lock, legacy auth-store lock, every legacy Session/transaction/plan lock in canonical byte order, then credential-authority—and gates the control socket and every broker release. It rejects every control/admin/authorization/MCP/admission/credential/local-model mutation, service activation/join, worker/admin/invocation claim, and model/tool/provider request. If any nonterminal Run exists it releases the additional locks and restores service without publishing rollback control;
2. exports terminal results/audit/context plus secret-free registry/grant summaries, then atomically publishes `MigrationControlV1(phase='rollback_draining')` with exact request, backup, and source `KernelGenerationIdentityV1` pairs from the current Kernel authority marker. This is the persistent global rollback fence; no archive pair exists in this phase, read-only export/status cannot create authority, and no lock is released or reordered;
3. terminalizes every nonterminal admin operation and activation cycle only through its bounded typed reducer; revokes, kills, whole-containment death/no-spawn proves, and retires every worker, invocation, admin, and local-inference authority; evidence-closes invocation Journal claims; and terminalizes credential operations. The broker/control listener closes and the Supervisor proves zero released dispatch, descendant process/VM, nonterminal admin/cycle, unretired launch, or pending credential write. Any unknown or unprovable state leaves rollback fenced;
4. while that exact drain and no-write proof remain current, closes/checkpoints SQLite and publishes a fresh `KernelDatabaseImageIdentityV1` for the exact current live bytes; descriptor-copies and seals those bytes as exact `ArchivedKernelDatabaseImageV1`; publishes a fresh complete `CasNamespaceManifestV1(snapshotBoundary='rollback_final')` and seals the namespace; then publishes exact `ArchivedKernelGenerationManifestV1`. The manifest is rooted outside its archived namespace, source identity equals the request/current marker, every database/CAS ref and digest revalidates, and the archive must verify before any legacy byte is restored or control can advance;
5. stages/restores every backed-up noncredential byte, fsyncs each file/directory, and verifies exact `MigrationBackupManifestV1` under the held descriptors;
6. derives exactly one `LegacyGenerationManifestV1.authOutcome`. Source `absent` requires `restored_absent`, removes any migrated marker, fsyncs, and publishes a fresh absent observation. Source `present` with `records=[]` requires `rendered_nonsecret`, deterministically renders only the exact non-secret projection, and forbids consent. Source `present` with records requires request `allowPlaintextLegacyCredentials=true`, exact matching consent, and current matching platform items before one validated `0600` ProviderAuthStore-v1 render. The false request branch cannot render a secret. Missing/revoked/expired/mismatched items block rollback;
7. publishes and rehashes the exact legacy generation plus `MigrationReceiptV1(legacy_rollback)`, stages byte-identical legacy/state-root `MigrationAuthorityMarkerV1(authority='legacy')` documents, and advances control to `rollback_restoring` with the exact request/source-generation/archive-manifest/receipt pairs and prepared marker digest;
8. as the last Kernel repository mutation for this process, commits every retained receipt/evidence/archive root, publishes exact graceful StateOwner transition evidence, and terminalizes the active owner. While all locks remain held, it may only rehash/rename the already-bound legacy-root marker **first** and directory-fsync, then rename/directory-fsync `${stateRoot}/migration/authority-v1.json` **last**, release locks, and exit. No Kernel mutation is legal after the state-root legacy marker;
9. if a crash occurs after owner terminalization but before the state-root marker, the successor may use only exact `acquire_after_graceful_release`, remains fenced by `rollback_restoring`, revalidates and publishes only missing prepared marker bytes, and gracefully terminalizes itself as its last Kernel transaction before the same legacy-root-first/state-root-last sequence. Once the state-root legacy marker is durable no successor is acquired; retained control cleanup is inactive-generation idempotence, not authority change. The archived image/CAS manifest remains a read-only evidence generation that legacy authority never mutates, reuses, or merges.

The same request id/digest is replay-stable across crashes. Plaintext credentials are reintroduced only by its exact true branch and current platform items, never retained backup/CAS/archive bytes. Future Kernel re-entry creates a new migration id, backup, database image, CAS namespace, and credential preflight. Unsupported binary downgrade without this command is never advertised as safe.

Reuse existing code:

- Reuse current Session id/timestamp/workspace identity conventions where canonical and legacy validation permit.
- Reuse Session/compaction/fork/plan/handoff readers behind importer-only adapters; never call their write functions from Kernel state.
- Extract file and directory `fsync`, same-directory temporary publication, deterministic id, and recovery techniques from `src/workspace/transactions/store.ts`.
- Reuse `withPathLock` only for migration/rollback/global file publication; SQLite revisions and launch-row CAS own Run concurrency.

Preserve / do not touch:

- Workspace Trust, tool permission, sandbox, broker, verifier, and delivery ownership boundaries.
- Legacy bytes and Git ghost refs inside the verified backup/archive.
- Public legacy Session ids and ordered context semantics during import.
- The distinction between Session, Run, Checkpoint, RunJournal, RunEvent, WorkerLaunch, ControlRequest, ChildAllocation, registration/grant state, and Artifact.
- Existing legacy runtime behavior until work package 6 performs the single Kernel Cut; do not advertise it as durable detach.

### Implementation refinement — 2026-09-26

**Build on the real storage module.** `StateStore` owns transactions, recovery
cuts and all mutable authority. The existing loaded-Run interface is the seam
for typed continuation. Static assembly decoding belongs to a loaded immutable
handle; current owner/revision/lease/stop/time/grant checks stay inside the typed
commit or release operation. A caller supplies intent and exact observations,
never a selected next status, refund amount or arbitrary patch. Factor common
private validation only when it removes duplicated checks without moving their
authority into the caller. Do not expose the private SQLite connection.

**Bound physical work without weakening the recovery cut.** Read the complete
required relational cut in one consistent transaction, then validate its CAS
closure. Use a bounded artifact I/O pool/work queue rather than `Promise.all`
over every reference. Deduplicate refs within that validation and report the
maximum in-flight reads. A cache may avoid repeated immutable decoding within
the loaded closure; it cannot turn path existence or old digest metadata into
fresh byte-integrity evidence. No partial walk is a valid recovery closure.

Startup discovery and list/attach reads must use bounded indexed queries instead
of loading all terminal history. Keep authenticated `list_read_cuts` semantics;
do not substitute moving live keyset pagination for a retained read cut. Close
read transactions before waiting on a client, provider or filesystem copy.
Measure WAL growth, writer delay and memory under simultaneous attach, heartbeat
and typed commits. Preserve synchronous transaction callbacks and rollback
poisoning; an async transaction body is not a batching optimization.

**Treat migration as a first-class operation.** Reuse `MigrationControlV1` and
its existing phases for restart/progress. Large inventory/copy/verification may
be internally batched, but the candidate remains non-authoritative until the
complete locked inventory, credentials, database image and CAS closure validate.
Estimate required staging/backup space before work; a later disk-full failure
preserves the authoritative generation. Do not add a startup backfill shortcut,
second migration marker or indefinite JSON/SQLite dual write.

Shared workloads and measurements are in the
[scale qualification plan](../../kernel/2026-09-26-design-review.md#7-scale-and-latency-qualification).
Run integrity and reachability checks on the resulting state, not merely on
counts emitted by the importer. Separate database-open, discovery, per-Run
closure validation and safely resumed work in timing reports.

### Acceptance Criteria

- [ ] `node scripts/kernel/check-design-contracts.mjs` passes; ordinary
  invocation results and authenticated user-input results retain their exact
  distinct RFC payloads, including wait/request/revision/channel bindings.
- [ ] New continuation, verifier and control integration tests use the actual
  StateStore/CAS. Pure planner tests may use values; fake storage is insufficient
  for an atomicity, recovery, idempotency or settlement claim.
- [ ] Artifact fan-out is processed with bounded concurrency and complete
  closure coverage. Missing/corrupt objects, disk-full and interrupted scans
  release no execution or GC authority.
- [ ] The shared development/release workloads record query plans, memory,
  WAL/write latency and startup/attach timings; unrelated terminal history does
  not require full hydration for startup/list/attach.
- [ ] Large import/rollback is restartable through the existing control phases,
  exposes progress and disk needs, and preserves marker-last authority at every
  injected I/O failure.

- [ ] `src/kernel/types.ts` exports the RFC definitions field-for-field, including exact discriminators and required/optional/forbidden members for Run objective/endpoint negotiation/normal prompt+request/model/tool/input/repair-diagnostic, exact `ModelRequestV1`/ `WorkspaceInstructionSourceManifestV1`/`WorkspaceInstructionManifestV1`/`BundledSkillClosureV1`/`SkillSourceFileBytesV1`/`DescriptorCapturedSkillSourceFileV1`/`BundledSkillSourceFileV1`/`SkillSourceIdentityBaseV1`/`SkillSourceIdentityV1`/`SkillManifestV1`, Session terminal and Run-context compaction, exact workspace diff/final candidate, exact Git index/object closure and workspace-generation identity/state/snapshot/recovery evidence, root-only dependency plan plus `DependencyReadyItem`, frozen-ignore/projection/include-classification/include-authorization, `RuntimeBundleStructuredArtifactBaseV1`, `RuntimeBundleStructuredArtifactV1`, `RuntimeBundleManifest`, `ListMethodV1`, `ListCursorPayloadV1`, `ListReadCutEntryV1`, `ListReadCutV1`, `RunPolicySnapshotV1`, `PolicyChannelEvidenceBaseV1`, `PolicyChannelEvidenceV1`, `PolicyDecisionItem`, `ApprovalDecisionV1`, `OperationGrantV1`, `AuthorizationGrantV1`, `AuthorizationConsumptionReceiptV1`, `ChildAllocationV1`, `DependencyInstallScriptsAuthorizationTemplateV1`, `KernelIntegrityEvidenceV1`, `RuntimeFailureEvidenceBaseV1`, `RuntimeFailureEvidenceV1`, `VerificationClosureV1`, `InheritedVerificationProvenanceV1`, `ManualAbandonAttestationV1`, `BudgetSettlementV1`, `InvocationAmbiguityEvidenceBaseV1`, `InvocationAmbiguityEvidenceV1`, `PostClaimNoReleaseEvidenceV1`, `BrokerReleaseFenceEvidenceV1`, `InvocationDispatchClosureEvidenceV1`, the complete reconciliation dispatch/wrapper/timeout/subject evidence types, exact MCP/admin artifacts, publication proofs, Interpreter/root image/SandboxProfile/SandboxLaunch/containment types, complete StateOwner identities/evidence/record, and the complete exact Migration/generation/control/request/archive graph including `LegacyPortableHandoffVerificationResultV1`, without local widening. Golden compile/schema fixtures fail on every added, removed, optionalized, or renamed field.
- [ ] Policy evaluation artifact-first publishes exact `PolicyChannelEvidenceV1` from fixed signed Supervisor code interpreting the retained exact `PolicyEngineProfileV1` before approval/grant/denial/Journal prepare. Snapshot engine entry id/version matches the sole signed non-executable RuntimeBundle `policy_engine` data entry; its signed complete-file `entry.digest` equals `engine.profileRef`, while decoding those bytes and independently recomputing the self-omitting semantic digest yields `engine.profileDigest`. These hash domains are distinct and are never equated. No helper spawn or plugin load exists. Storage reruns the exact interpreter/profile and validates the closed filesystem/Bash/MCP/plan/named-action channel projections, deterministic Bash parse, named verifier/dependency/delivery/MCP-server/child identity key, rule/mode precedence, ask/allow/deny result, and omission digest. `ApprovalSubject`, `ApprovalDecisionV1`, direct/interactive `PolicyDecisionItem`, and policy/user `OperationGrantV1` provenance preserve the exact evidence pair; reparse, mutable engine/parser/profile, host-shell interpretation, coarse mode-only proof, or cross-request/frontier/target evidence is rejected. GC and recovery retain the evidence plus profile/RuntimeBundle/source closure.
- [ ] Exact `PolicyDecisionItemBaseV1`/`PolicyDecisionItem`, `PolicyDenialOutcomeV1`, and `VerifierSkipItemBaseV1`/`VerifierSkipItem` enforce the closed direct-versus-interactive matrix. Direct decisions forbid waits, use the channel evidence as decision, and atomically commit only exact grant XOR subject-matched denial outcome; interactive decisions require the exact ask wait and `ApprovalDecisionV1`. Direct tool/MCP denial emits the identity-matched denied result; required verifier/delivery/dependency denial emits exact `policy_deny` StopIntent with the same evidence; advisory verifier emits `skipped_by_policy` with the same digest. Interactive advisory skip is `skipped_by_user` and forbids that digest. GC/recovery follows every outcome edge and rejects phantom waits, cross-subject outcomes, grant-on-deny, denial-on-allow, or widened skip provenance.
- [ ] `CanonicalTimeFenceV1`, `LocalPrincipalIdentityV1`, `LocalSocketPeerObservationV2`, and `LocalControlChannelIdentityV1` are exact exports and closed decoder targets. Every durable time obeys the fixed UTC-millisecond grammar and checked safe-integer math. The one StateOwner-gated time row advances with each healthy authority transaction and persists `clock_regressed` before fail-closing admission, lease renewal, grant/capability redemption, productive dispatch/retry, and expiry extension until the high-water is reached. Principal identity derives only from StateRoot/platform/effective uid. A UDS channel requires separate held-parent endpoint identity/mode checks, held native listener/accepted socket checks, OS peer uid equal to StateRoot owner, a fresh nonce, and a runtime-only live capability checked before replay. Caller-provided principal/channel fields reject. Golden tests cover endpoint/listener replacement, uid/API drift, disconnect/delegation, clock rollback/recovery, and replay through a later authenticated channel. PID/start/image are diagnostic only and do not prove PID-reuse rejection.
- [ ] The same exact export and closed decoder include `ModelTextV1`, `ObservedToolCallInputV1`, `ToolCallInputBaseV1`, `ToolCallInputV1`, `ModelTurnItem`, `ToolCallRecord`, `ToolBatchItem`, `ToolResultItem`, `ToolResultPayloadBaseV1`, `ToolResultModelContentV1`, and `ToolResultPayloadV1`. Text/observation/input byte lengths and omission digests, retained JSON-or-UTF-8 observation, resolved/rejected schema/value/diagnostic XOR, required text refs, AgentModelTurn/ordered-call equality, stop/abort matrix, and every audit-payload/model-content outcome/identity/ref/digest/XOR are storage-validated. `AgentModelTurn.responseDigest` rehashes only the exact canonical normalized projection with literal `usageTrusted:false`, omitted absent optionals, and retained call-index order; raw provider wire bytes never define a usable turn digest and remain only inside exact unusable artifacts. Invalid model turns settle as `MODEL_PROTOCOL_ERROR` without a batch/candidate. An all-resolved batch alone enters `tool`; any identity-valid rejected batch atomically appends the whole batch, every input-error/remaining-call result, and next `agent` frontier with zero dispatch. Every ordinary result uses both exact payload artifacts; only terminal fenced retry-unknown uses direct exact `RetryUnknownCancelledResult` with its settlement/dispatch closure and no model projection.
- [ ] The instruction/skill decoder enforces the complete immutable declarative-context provenance graph. Workspace instructions are all-and-only the separately captured regular `AGENTS.md` entries in unique byte-sorted source order and contiguous root-to-deep render order, with exact held-descriptor projection hashes and byte-identical normalized `ModelTextV1`; they do not enter SourceManifest or create read/tool/publication authority. Workspace, authenticated owner-only user, and signed bundled skill branches each satisfy their exact source identity equation, path containment, all-and-only file sequence, raw byte counts, closure linkage, and omission digests; limits, duplicate ids, cycles, escapes, links, mutable paths, and executable-by-inclusion resources reject admission. For a bundled skill, the signed complete-file `skill_bundle` entry digest equals `bundledClosureRef`; decoding those exact bytes independently yields the self-omitting `closureDigest===bundledClosureDigest`, and the complete-byte ref is never equated with that semantic digest. The exact normal system message uses the canonical labeled workspace and per-skill JCS projections, explicit skill order, empty-piece omission, and two-LF join. Recovery reproduces identical bytes from CAS without rereading any workspace/user/bundle-install path, and `ContextManifest` carries only the authoritative `assemblyRef`.
- [ ] `NormalPromptToolCallV1`, `NormalPromptMessageV1`, `NormalPromptProjectionV1`, `ProviderContinuation` and common `ModelRequestV1` close normal/compaction model input. Projection Run/revision/frontier/spec/assembly/context and digest equal the dispatch cut; message/call/tool indices are contiguous and every source is the canonical frozen ref-free projection. Full tool definitions match the loaded manifest. The request binds exact body/path/count, mode, output cap, estimate and signed reservation; re-preparation reproduces bytes. Compaction binds the current plan/envelope. Journal delta and completed turn request/projection pairs match, including identity-bound opaque continuation. No hidden adapter inputs or telemetry-based settlement reduction is accepted.
- [ ] The single ModelRequestV1 binds exact native body bytes/path/count, assembly/projection, streaming, output cap and full signed reservation. Loading retained authority and re-preparing its typed input reproduces identical bytes and digests without profiles, fake framing or an internal JSON round trip. Storage rejects substitutions; the broker releases only those exact bytes and no SDK/default/redirect/retry mutation.
- [ ] Exact `InputResponseSchemaV1`, `InputPromptV1`, `UserInputModelContentV1`, `UserInputPayloadV1`, `InputRequestItem`, and `UserInputItem` export/decoding enforces every omission/ref digest, deterministic schema subset/64 KiB bound, prompt NFC text, text-vs-JSON schema XOR, `1..1048576` response bound, finite/coercion-free normalized payload and exact byte count. Prompt/payload/request/user/wait/originating-call/result identities and authenticated principal match; payload/item repeat one ref-free kind/value-equal input model-content artifact, and one `resolveInput` transaction commits user item, executed audit/model-content ToolResult, frontier, event, response, and replay row or nothing.
- [ ] Exact `SandboxProfileV1` export/decoding enforces omission digest, one strong backend, nonempty unique byte-sorted owner set, fixed typed-launch/no-host/no-state-root/no-host-environment/no-network-at-spawn/broker-only policies, defaults/ranges/fixed IPC resources, and host feasibility. RunSpec/assembly/plan/launch backend, profile refs/digests, owner, and inline resources match byte-for-byte; admin/local profiles follow the same type and no caller/repository/recovery path widens it.
- [ ] Exact `WorkspaceDiffOperationV1`/`WorkspaceDiffV1` export and storage validation compare decoded base/result SourceManifest path maps and require the complete unique byte-sorted add/delete/modify set with exact branch entries and omission digest. Exact operation-discriminated `FinalCandidateItem` repeats those refs/digests, uses result `manifestDigest` as `sourceDigest`, and preserves one producer/summary closure: agent requires its `end` ModelTurn item/text plus matching `producingOpId`; delivery requires its `DeliveryMergeItem.summaryRef` and forbids `producingOpId`. Finalize and RunResult repeat candidate base/result/diff and identical summary. Tests reject missing/extra/unsorted/no-op diffs, source/diff drift, cross-operation producers, alternate summaries, and widened optional fields.
- [ ] A fresh store creates all twenty required tables, including the one-row `canonical_time_fence`, authoritative `workspace_generations`, and non-authoritative `list_read_cuts/list_read_cut_entries`, plus only narrowly justified metadata, with versioned transactional schema, deferred admission-cycle foreign keys, immutable-row constraints, secure permissions, bounded busy timeout, and crash-durable synchronization.
- [ ] Production state access goes only through `SqliteDriver` and typed repositories/reducers; static tests reject raw SQL outside the state implementation and reject generic Run patch/mutation-bag APIs.
- [ ] `sessions` contains no status, lease, wait, budget, Journal, worker, generation, or Run frontier field. Its logical item stream is immutable and contiguous across validated lineage; a fork clones no item rows, freezes the exact ancestor prefix through a segment boundary, and starts child-owned rows at `forkedThroughItemSeq+1`.
- [ ] Every Session stores one immutable exact `WorkspaceIdentityV1`. Normal create permits only `kind='live'`, uses held no-follow descriptor traversal, and validates same principal/platform/NFC absolute canonical root plus `fstat` owner/device/file identity. Device/file ids are canonical unsigned decimal strings and never pass through JS number; owner uid is safe integer. Git requires exact retained `RepositoryIdentityV1` ref+digest together for literal in-root `.git`; non-Git forbids both. Import alone may create `legacy_unavailable`, which has only its exact audit fields. Fork copies either ref unchanged. Every later capture/authorization/admission/apply/publication requires live and reopens the same root/repository tuple; root/`.git` replacement returns `ARTIFACT_MISMATCH`. Legacy-unavailable Sessions remain context-capable but execution-ineligible.
- [ ] Every `SessionContextProjection` matches Session id/context revision/latest logical sequence; its ordered nonoverlapping segments cover the entire logical prefix, every raw `sourceSessionId` resolves through the exact immutable ancestor chain without crossing a fork cursor, and all source/projection digests validate.
- [ ] `compactSession` accepts only whole segment boundaries whose selected segments are all `raw`, never a range containing a summary or `excluded_control`, and validates at most 256 unique retained ids from the exact logical source range. Item and summary segment repeat one exact bounded `ModelTextV1` `summaryRef/summaryDigest`; its new compaction item is covered by one exact digest-bound `excluded_control` segment and is never raw/model-visible. `forkSession` accepts only zero or a current segment end; straddling, nested/recompaction, inside-segment, and lineage-substitution requests return `INVALID_REQUEST` without mutation.
- [ ] `runs` contains the exact canonical Run plus admission digests and has no lease expiry/version, worker identity, containment, or generation column.
- [ ] Every Session create/fork or Run submit/apply derives the exact intent formula and keys replay by `(principalId,method,admissionKey)`. Equal intent returns the exact first Session/Run/control result before Session/source-Run/workspace validation, descriptor capture, or artifact publication; different intent returns `ADMISSION_KEY_CONFLICT` with no state/filesystem read beyond the replay row. The first-execution transaction rechecks the key under its write lock, and final admitted-digest mismatch creates no Session/Run.
- [ ] Every accepted Run is born in one transaction with literal `RunSpec.schemaVersion=1`, an exact required `RunObjectiveV1` as its sole objective source, initial Checkpoint literal `schemaVersion=1` and `basedOnRunRevision=0/runItemSeq=0/journalSeq=0`, queued Run `revision=1`, operation-specific initial frontier, non-null latest checkpoint, event sequence 1, and matching control replay response. `run.submit` normalizes objective once to NFC, rejects NUL/unpaired surrogate or UTF-8 length outside `1..262144`, and binds its omission-digest artifact ref into final admission; no inline/Session/argv/worker objective remains. `run.submit.workspacePath` must descriptor-resolve to the Session identity and every workspace digest/repository identity must equal it. Agent starts only at its initial agent frontier. `run.apply` accepts no path/objective, requires delivery `RunSpec.objectiveRef` byte-equal to the source RunSpec ref, derives/reopens the source Run's Session identity, descriptor-captures before admission, and publishes exact `SourceManifest A` plus exact recovery `WorkspaceStateManifest W_A`; `RunSpec.baseWorkspaceManifestRef=A`, `delivery:merge.capturedWorkspaceRef=A`, `W_A.baseWorkspaceManifestRef=A`, and the initial Checkpoint `workspaceStateRef=W_A`. Tests reject missing/alternate objective refs, delivery objective substitution, root replacement with `ARTIFACT_MISMATCH`, `workspaceStateRef=A`, cross-identity/projection/digest mismatch, nonliteral/missing schema versions, `delivery:capture`, revision-0, checkpoint-less, or capture-less delivery Runs.
- [ ] Workspace-entry counts/bytes/tree digest, SourceManifest entry-tree/manifest digest/live workspace+repository/frozen-ignore closure, and WorkspaceStateManifest entry/base/projection/private-Git/invalidated-path/state digest equations are recomputed exactly. `FrozenIgnoreRulesV1` sources/rules/digest and `SourceProjectionSpec(schemaVersion=1)` matcher/rules/includes/excludes/bounds/omission digest are closed and immutable; SourceManifest repeats the exact projection plus frozen-ignore ref/digest, while WorkspaceState repeats `sourceProjectionDigest` and reaches those rules only through its exact base SourceManifest/projection. Result SourceManifest preserves the admitted workspace/repository/head/index/ignore/projection identity. Self-referential or adapter-local digest formulas, mutable Git-ignore/config interpretation, SourceManifest-as-Checkpoint, Git/private-state XOR mismatch, and wrong Run/base refs fail before authority.
- [ ] Every explicit include has exact `SourceIncludeAuthorizationV1` matching principal/Run/Session/live workspace/selector/admission intent. Descriptor-proven tracked/nonignored bytes use only `builtin_nonignored` under the exact frozen rules and exact `SourceIncludeClassificationEvidenceV1`: nonempty unique byte-sorted entries exactly cover the selector's captured entries, WorkspaceEntry/descriptor identities match, and each classification is proven by the identical retained Git index or frozen-rule evaluation. Ignored bytes require the exact active path/scope read grant and atomically commit its `AuthorizationConsumptionReceiptV1(run_admission)` with include authorization, Run/Checkpoint/projection, response, and replay row. That receipt's consumer binds the exact `runId` plus pre-resolution `admissionIntentDigest`, never final admitted-request digest; fault tests prove the graph is acyclic. Missing/unnecessary/mismatched/reused/repository-manufactured grants and external selectors create no Run.
- [ ] Empty required-verifier admission is rejected unless its exact direct or derived-child unverified-consent artifact validates against the final admitted request.
- [ ] Every authoritative Run mutation uses an operation-specific typed reducer, increments revision exactly once, and commits its required items/Journal/budget/Checkpoint/event/control response atomically.
- [ ] There is no public generic status setter, `compareAndSwapRun(mutation)`, arbitrary `{items,budget,frontier}` transaction, or terminal mutation bypass.
- [ ] Every policy ref validates exact `RunPolicySnapshotV1`; every Journal/Broker/child-delegate grant ref validates exact `OperationGrantV1` and full subject/provenance/current-identity closure. `user_approval` provenance decodes only the exact committed allow `ApprovalDecisionV1` for the current wait/request/frontier/target and equal grant expiry; `verifier_template` provenance decodes only the exact template-producing `AuthorizationConsumptionReceiptV1`. Policy items/text, authorization rows, templates, and opaque artifacts are rejected as dispatch grants.
- [ ] Loading/recovery validates the retained signed adapter, system prompt, compaction envelope and all-and-only members before producing immutable model authority. Context `C/O/H/T/R/S/K/P` equations use the fixed byte estimate, with independently valid normal/compaction output caps; estimates cannot authorize hard spend. Remote reservation uses the complete signed four-component request ceiling, substantiated during release qualification. Missing/unverifiable ceilings fail `MODEL_COST_UNKNOWN`. No custom BPE/profile/golden execution runs per request; actual local-model tokenizer files remain retained inference assets.
- [ ] `resolveApproval` publishes and validates exact `ApprovalDecisionV1`, including all principal/Run/wait/frontier/subject/request/revision/digest/TTL/grant-expiry equations, then commits the decision plus subject-specific item/result, optional exact grant, frontier/StopIntent progress, event, response artifact, and `control_requests` row atomically. A crash/replay cannot commit a decision without its state/result or reuse it across identity drift.
- [ ] Every delivery frontier is exact and proof-carrying: merge retains source result/admission capture; approval retains candidate/result/verifier-plan/verification-closure/delivery-plan; publish/abort preserves those refs plus next path index. Reducers cannot drop/reconstruct them, and only the last forward projection may install delivery finalize with the same verification closure plus exact `DeliveryTerminalProjectionEvidence`.
- [ ] Only `commitRunResult` can commit `succeeded|completed_unverified`; it requires the exact operation-valid candidate producer/summary plus sorted exact WorkspaceDiff and identical RunResult base/result/diff/summary, then requires identical finalize/RunResult `VerificationClosureV1` refs and re-walks the complete candidate/source/dependency/verifier/receipt/consent closure. `inherited_verified` additionally requires exact `InheritedVerificationProvenanceV1`, recomputed omission digest, immutable source `succeeded(verified)` result/required closure, identical result source/verifier spec, and ordered receipt refs/digests; the final delivery result repeats the same provenance ref. Agent finalize/result forbid `deliveryTerminalProjectionEvidenceRef`; delivery finalize/result require the identical exact forward-finalize evidence ref and revalidate its plan/source/path/result/unstarted/abort/transient/projection/Git-index/descriptor closure. Only `commitTerminalStop` can commit `failed|cancelled`, and both enforce the canonical result/reason/detail/StopIntent/terminal-quiescence matrix.
- [ ] `commitTerminalStop` enforces the exact acyclic primary-evidence matrix: integrity/source-stop/local-failure/runtime-error/manual-attestation branches use their named ref; user cancel, deadline/budget, verification, context-compaction/window, and delivery merge/publication use the immutable winning StopIntent ref itself. `StopIntentBase` has no generic evidence ref, and reason detail repeats only the selected branch fields/ref. The optional delivery projection ref is legal only for a delivery Run with a claimed forward operation and exact completed abort projection; it decodes/revalidates abort-selected `DeliveryTerminalProjectionEvidence`. Agent stops, merge conflict, approval denial, pre-first-claim cancellation, and incomplete/no-abort projection forbid it. Terminal detail contains only the exact publication/manual/retry closure; locally invented candidate/diagnostic/verifier-receipt/child-result lists are rejected.
- [ ] Root terminal commit appends exactly one idempotent exact `SessionRunTerminalItem` in the same transaction: literal ``itemKey=run-terminal:${Run.id}``, equal Run id, decoded RunSpec operation, decoded `AdmittedContextManifest.throughSessionItemSeq`, Run status/reason, and exact result-or-detail/summary matrix all match. It increments Session sequence/revision once and adds a new never-coalesced one-item raw projection segment with the exact canonical model rendering. Success/unverified requires exact Run result plus RunResult/`ModelTextV1` summary pair and forbids terminal detail; failed/cancelled requires `terminalDetailRef===Run.terminalDetailRef` and forbids result/summary. Rendering omits audit-only admitted Session cursor/detail/summary digest; child terminal Runs never append directly to Session.
- [ ] Every `RunContextCompactionItem` and replacement `ContextSegment(kind='summary')` repeats the exact highest/current completed tools-disabled compaction turn's `ModelTextV1.summaryRef/textDigest`, covered range, and source digest. The reducer appends item, replaces exactly the range, and publishes the ready unchanged-workspace Checkpoint atomically. Tool-bearing/non-end/oversize/substituted summaries never become context; raw items remain retained.
- [ ] A completed model Journal result is exact usable `AgentModelTurn` XOR exact `ModelUnusableResponseV1`. Only usable `end|tool_calls|cancelled` creates `ModelTurnItem`, and its `responseDigest` is the exact JCS normalized-turn projection rather than raw wire or the complete self-containing artifact. Provider length/content-filter/unknown stops and every positively received provider rejection use the exact unusable failure codes, complete once, consume the full request reservation, and create no turn/item/batch/candidate/summary or semantic retry. `RunAssemblyV1.retry.model` is exactly three dispatched attempts, zero hidden same-attempt retries, delays `[500,2000]`, and no `maxRetryAfterMs`; `Retry-After` never alters it. Only literal final `transport_exhausted` may authorize `model_attempts_exhausted`. For a normal request the generic-runtime stop carries exact `RuntimeFailureEvidenceV1(model_unusable_response)` wrapping that Journal result; context-compaction terminal primary evidence remains the immutable StopIntent ref.
- [ ] Every ordinary `runtimeSubtype='runtime'` stop and TerminalReasonDetail require identical `failingOpId` plus exact `runtimeFailureRef/runtimeFailureDigest`; `TerminalDetail.primaryEvidenceRef` equals that ref. Storage recomputes the evidence omission digest, current-inspector freshness, Run/frontier/op identity, and exactly one closed branch over model unusable, exhausted model attempts, pre-I/O credential redemption, retry-unknown exhaustion, dependency-acquisition exhaustion, or local-service identity mismatch. Each branch re-walks its exact Journal/request/authority/provenance closure; generic errors, diagnostics, booleans, cross-branch members, and worker assertions are rejected and cannot become terminal authority.
- [ ] Checkpoint and workspace-transition commits reject missing artifacts, sequence gaps, non-quiescent cuts, or a changed generation without its matching Journal/result/settlement/post-effect Checkpoint.
- [ ] Journal rows are immutable and enforce the exact phase graph, op-kind fields, contiguous attempts, one claim per attempt, replay-class retry bounds, required complete four-counter `budgetDelta`, and conservative one-time budget settlement. Every `evidenceRef` has its digest or both are absent. `prepared` holds the reservation; claim and abandonment use explicit all-zero deltas. `failed` is closed pre-dispatch XOR post-claim: pre-dispatch proves claim absence, forbids every claim/spec/evidence/receipt field, consumes zero, releases the reservation, and does not consume effect retry capacity; post-claim repeats exact claim/spec/fence identity and accepts only exact `PostClaimNoReleaseEvidenceV1`, or for `opKind='verifier'` an exact cross-field-valid `infra_failed` receipt plus exact containment-death closure. The former consumes zero; the verifier form consumes exact attempt usage. Every other claimed no-result state is `unknown`, and typed target errors are `completed` with their result artifact. `unknown` repeats the exact claim, consumes its full settlement, and requires one exact `InvocationAmbiguityEvidenceV1` pair whose closed mechanism matches the op/claim/owner/channel/containment/publication state; `abandoned` repeats the claim/settlement with zero new delta, forbids its own evidence pair, and its attestation repeats the unknown pair byte-for-byte. Every released or possibly released post-claim model terminal/unknown consumes its request-bound reservation in full; only exact `PostClaimNoReleaseEvidenceV1` consumes zero, and `usageTrusted=false` telemetry cannot lower/refund either rule. Process-spawning `prepared` forbids `sandboxLaunchSpecRef`; `claimDispatch` chooses the permanent id, artifact-first publishes/validates one exact `run_invocation` spec, and binds it only on `dispatch_claimed`; every post-claim phase repeats the same ref. Non-spawning operations forbid it throughout, and a failed claim leaves only an unreachable CAS artifact.
- [ ] `dispatch_claimed` stores `brokerFenceTokenDigest` iff a trusted-broker/no-child release path exists and otherwise forbids it; prepared forbids it. Terminal closure of a `retry` unknown requires exact `InvocationDispatchClosureEvidenceV1` matching Run/op/attempt/dispatch/unknown. Containment closure rehashes containment plus death evidence; broker closure rehashes exact `BrokerReleaseFenceEvidenceV1` whose request/target/grant/claim/owner/inspector/newer epoch/token/action/times match the Journal and active authority. `RetryUnknownCancelledResult` and `TerminalDetail` repeat the exact settlement/closure refs; inline booleans, lease/socket/worker/Supervisor drift are never proof.
- [ ] Kernel-integrity StopIntent accepts only exact `KernelIntegrityEvidenceV1`. Verifier and dependency subjects match their exact Journal/frontier identities; audited blocked writes repeat the exact request/containment/SandboxLaunch/path/access/enforcement point and prove identical before/after source; digest drift rehashes unequal SourceManifests plus a nonempty unique byte-sorted changed-entry set and accepts only trusted-out-of-containment with both claim refs forbidden or claimed-process with both required/equal. Branch `integrityEvidenceRef`/digest, `TerminalReasonDetail`, terminal primary ref, and verifier mutation receipt when applicable all repeat that one artifact; no generic base evidence exists. Dependency readiness/completion, generic evidence, half-present claim identity, or cross-subject evidence is rejected.
- [ ] `resolveReconciliation(abandon_run)` is legal only for the exact current manual unknown and authenticated `acknowledgeExactRisk:true`. It validates one exact `ManualAbandonAttestationV1` against principal/channel/control request/wait/frontier/Journal/request/target and requires its ambiguity pair byte-equal to the unknown row's exact `InvocationAmbiguityEvidenceV1`; then it atomically uses the same attestation ref in Journal `abandoned`, Stop/Terminal closure, and any call-origin `ToolAbandonedItem`. The abandoned row carries no replacement evidence pair; the reducer returns no result, creates no ToolResult, substitutes no later probe/display evidence, and never resumes the batch.
- [ ] `claimDispatch` and `releaseClaimedDispatch` both validate the same exact active Run pointer/launch/epoch/identity/generation/containment/lease plus stop/cancel/deadline/grant/frontier/reservation predicates; only the second successful check releases I/O.
- [ ] Current authenticated evidence for the still-highest exact frontier/subject can atomically settle and advance once even after old lease clearing or post-dispatch stop; it is never forced into audit-only handling merely for being late.
- [ ] Superseded authenticated evidence can append only historical Journal/audit/billing facts and cannot add a Run-visible item, change wait/frontier/status/result/Checkpoint, or replace newer evidence.
- [ ] A stale evidence classification is recomputed inside the write transaction, preventing current-to-historical TOCTOU from advancing the wrong frontier.
- [ ] Reconciliation storage accepts only the exact subject union and exact probe graph. Manual is permanently `manual_only`; inspectable subjects start count-zero pending with evidence forbidden; due CASes enter 30-second automatic in-flight only after atomically persisting exact digest-valid `ReconciliationProbeDispatchV1`; unresolved ordinals 1..7 use the fixed seven backoffs and require the resulting wrapper pair; ordinal 8 exhausts with that mandatory pair; and only exhausted-state replay-safe `probe_now` increments positive-safe user count into one user dispatch. The dispatch freezes subject digest, current Supervisor, kind/count/ordinal/nonce/deadline and exact broker request/target/fence or descriptor-task target before I/O. Exact `ReconciliationProbeEvidenceV1(subject_observation)` repeats the dispatch digest and unwraps only subject-valid MCP/publication/worker evidence; exact `probe_timeout` repeats that digest and requires either MCP fence revocation plus zero active release or exact `ReconciliationInspectorTaskClosureV1(cancelled_and_joined|owner_process_dead)` before taking the unresolved edge. No automatic ninth probe, counter reset, public/direct evidence payload, in-memory-only dispatch, duplicate request/timer increment, late closed-nonce advance, or cross-subject wrapper is accepted.
- [ ] Every initialized stdio MCP lifecycle publishes exact `McpServerInstanceIdentityV1` bound to the owning Run/batch/call/index, immutable registry ref/`registryManifestDigest`, lifecycle Journal claim, exact SandboxLaunch/containment, nonce, and negotiated initialize/capability/`probedToolsListDigest`. Completion requires exact `McpServerLaunchReceiptV1` binding that identity, one prepared/claimed/completed Journal chain, completed budget settlement, identity-matched stopped item, and whole-containment death evidence; one transaction commits them with the visible ToolResult and frontier advance. Missing/mismatched teardown remains open, cannot be terminalized or reused, and is recovered only through its retained exact closure.
- [ ] Every `PublicationProofV1` closed-decodes the exact base plus one branch, recomputes the omission digest, and matches the current delivery Run/plan/live workspace/current inspector. Descriptor-derived observations and branch-specific operation/index/op/attempt/dispatch, before/after/fsync/preimage/descendant/ambiguity/transient/projection/Git-index fields and refs validate against the Journal and delivery state. Generic, cross-branch, stale-workspace, stale-inspector, path-only, or ref/digest-mismatched evidence cannot advance reconciliation, publication, abort, result, or terminal state.
- [ ] `workspace_generations` stores one exact mutable `WorkspaceGenerationStateV1` per immutable exact `WorkspaceGenerationIdentityV1`. Creation derives the generation id from Run/source Checkpoint/state/nonce and verifies the platform locator; materialization and sealing require exact descriptor-rewalk/fsync snapshot evidence; phase/field XORs and the exact success spine are storage-enforced. Every worker loss from `active|revoking|checkpointing` first atomically becomes `fenced_reconciling`, binds the exact `worker_death` wait/prior phase/quiesce id, clears the Run pointer, and projects the sole launch to `reconciling/fenced_reconciling`. Quarantine binds current `sourceRowVersion`, the deterministic sole target, exact complete-tree-or-unreadable observed state, and the full materialization/preactivation/launch-abort/launch-death/worker-recovery/checkpoint-failure matrix; worker recovery is legal only from `fenced_reconciling`, and both recovery dispositions quarantine the old row. Retirement requires exact sealed+death or quarantined plus current literal zero counts for every selectable authority. Restore additionally requires a distinct preactivated replacement from the named ready Checkpoint. Tests reject reuse, rewind, rescan-as-authority, stale CAS, alternate quarantine target, missing evidence, and cross-Run/source/locator substitution.
- [ ] `worker_launches` stores the exact versioned identity, phase, immutable generation ref, mandatory preactivation `sandboxLaunchSpecRef`, containment, denormalized generation write state, lease, activation deadline, and retirement evidence. Every reserve/activate/revoke/checkpoint/seal/quarantine/retire workflow transaction CASes the authoritative generation row and identical WorkerLaunch projection together; heartbeat changes neither. Reservation accepts only the exact worker launch spec matching its plan/Run/epoch/generation/runtime/process/environment/mount/resource/profile closure.
- [ ] Activation and deterministic fake-clock tests freeze the 30-second lease and 5-second heartbeat cadence. Heartbeat updates only `worker_launches.leaseVersion/leaseExpiresAt`, never Run revision/updatedAt/items/events, cannot extend an expired lease, and cannot reopen a non-active write gate.
- [ ] Activation atomically installs the Run pointer/new epoch and event; lease expiry alone never clears it. Every worker loss atomically clears the pointer, moves the launch to `reconciling/fenced_reconciling`, moves the generation from its exact current `active|revoking|checkpointing` phase to `fenced_reconciling`, binds the exact worker-death wait and source phase, and permits no replacement or productive release.
- [ ] A new Supervisor instance cannot renew/adopt an old launch even when its lease is unexpired; only exact containment death plus the canonical worker recovery XOR settles it. Both dispositions publish the same exact `worker_recovery` quarantine artifact and quarantine the old `fenced_reconciling` row before retirement. `quarantined` creates no replacement; `restored_from_checkpoint` names a ready same-Run Checkpoint and a distinct exact generation already proven `preactivated_readonly`. No old generation is reopened or attached to the new launch.
- [ ] `local_inference_activation_cycles` stores only exact `LocalInferenceActivationCycleV1`. `activationCycleId` derives from owner/service/spec/contiguous positive ordinal; at most one `starting_launch|retry_wait` cycle exists per owner/service; participants are append-only, ordered, identity-unique, digest/ref-valid, and capped at 128. A retained `run_submission` request replays only its original cycle/result and conflicting bytes fail; `run_model_frontier` joins only an exact queued Run revision/frontier. Phase/attempt/launch-id cardinality, retry/failure/boundary XORs, row version, and `cycleDigest` are enforced. A positively retired attempt 1 must enter `retry_wait` and can never terminal-fail; only unprovable retirement may fail at attempt 1 as exact `containment_unresolved` while retaining the blocking launch. Attempt-2 failure is terminal only after positive retirement or as `containment_unresolved`; every failure artifact's final attempt/reason/evidence matches this matrix.
- [ ] `local_inference_launches` stores only exact `LocalInferenceServiceLaunchV1`, including required `activationCycleId` and `activationAttempt: 1|2`; permits one unretired row per owner/service; and enforces `reserved -> preactivated -> active -> revoking -> retired`, `reserved -> retired(no_spawn)`, and `preactivated -> retired(death)` plus every forbidden field. Launch cycle/service/spec/attempt equals its owning cycle; attempts form one cycle-owned prefix capped at two, each deadline is exactly 120 seconds, and attempt 2 requires positive attempt-1 retirement plus `retryNotBeforeAt=retiredAt+1s`. Reservation binds exact service/plan/`SandboxLaunchSpecV1.local_inference_service`; activation requires exact `LocalInferenceBoundaryEvidenceV1`; heartbeat changes only launch-row lease fields and no Run/Event.
- [ ] Local-service spec validation recomputes the full semantic `serviceSpecCoreDigest` with only `serviceId`, `createdAt`, `serviceSpecCoreDigest`, and `serviceSpecDigest` omitted, derives `serviceId` from owner/provider/model/core digest, and then recomputes `serviceSpecDigest`. Any changed endpoint/backend/resources/runtime/executable/model/profile semantic field changes the core and service id; created time cannot perturb semantic identity.
- [ ] Local-service retirement has the exact closed XOR. `retirementKind='no_spawn'` is reserved-only, forbids containment/boundary/quiesce, and requires matching `ProcessContainmentNoSpawnEvidenceV1`; `retirementKind='death'` from preactivated or revoking requires the exact containment/quiesce/death evidence, with boundary evidence present if and only if the launch reached active. A new Supervisor adopts nothing and creates no successor before terminal proof.
- [ ] Every selected local registration closed-decodes exact `LocalModelObjectClosureV1`: current StateRoot pair, literal object-store path, signed manifest pair, all-and-only manifest/tokenizer/byte-sorted model-file objects, exact paths/ref-equals-digest/positive sizes/count/checked total, omission digest, and byte-identical `expectedObjectClosureRef`. `LocalZeroCostProvenanceV1.stableServiceIdentityDigest` is recomputed from the exact stable owner/service/spec/runtime/model/backend/no-egress projection. Recovery and replacement may change dynamic launch/containment/plan/SandboxLaunch/inspector/observation identity only; they never copy old dynamic ids into a new row, consult mutable object lookups, or substitute an ambient loopback service.
- [ ] Exact `LocalInferenceActivationFailureV1` validates cycle/owner/service/spec/final-attempt identity, closed reason, launch-id prefix, evidence refs, time, and digest. Cycle finalization is one transaction over all participants: success validates the active launch/boundary, atomically admits or returns an exact non-activation admission error for every still-valid submission with its `control_requests` row, and makes each still-matching queued Run frontier eligible without revising it; failure returns the same typed `RECOVERY_REQUIRED(local_inference_service)` to submissions without Runs and proposes exact `runtime/local_inference_unavailable` StopIntent for still-matching Runs. Stale/stopped/moved Run participants are audit-only. Fault tests prove no partial fanout.
- [ ] Every public mutator replays through `control_requests`; same digest returns the first response after revision drift and different bytes return `REQUEST_ID_CONFLICT`. No successful logical result can commit without its replay row or vice versa. Before a final response, only an in-flight MCP probe may retain its same-request `admin_operations` fence and only a local-model `run.submit` may remain as a participant in a bounded shared activation cycle. An existing queued Run may join that same cycle without a control response. Crash/replay cannot reset a cycle or its two-attempt bound.
- [ ] `session.list|run.list|authorization.list|mcp.list` use exact `ListMethodV1`, `ListCursorPayloadV1`, `ListReadCutEntryV1`, and `ListReadCutV1` storage. A cursorless call atomically materializes one owner/filter/limit-bound typed-summary cut ordered by `(createdAt,bytewise stableId)`; each current MCP registration contributes only its current head. Row/entries/cut digests, independent 256-bit cut id/secret, 15-minute expiry, 100,000-row/64-MiB refusal, domain-separated constant-time HMAC, contiguous issued ordinals, deterministic page replay, exact end omission, restart survival, and expiry-only deletion are enforced. Golden/fault tests cover equal timestamps, all filters, concurrent mutation/insertion, status/revision/refresh changes, restart, repeat, malformed/forged/cross-principal/method/filter/limit/future/end/expired cursors, cache capacity, cut GC, and proof that list cache never affects reducers or recovery.
- [ ] Child admission reserves capacity and appends one exact `ChildHandleItem` with parent/batch/call/index/op/child/spec/mode byte-equal to its `ChildAllocationV1` and deterministic admission identity; duplicate, skipped, cross-parent, cross-batch, or independently appended handles are rejected. `child_allocations` enforces every state-union forbidden field and moves monotonically through `reserved -> child_terminal -> settled`. Success repeats exact child RunResult; failure/cancellation repeats exact terminal detail; mutating success requires the recomputed base/result/diff-exact `ChildPatchManifest`; every branch repeats one exact ref-free `ChildResultModelContentV1` whose success summary equals RunResult summary text or stopped content is only status/reason. Allocation terminal and parent `ChildResultItem` bytes match, and inclusive-usage/released-unused-budget settlement occurs exactly once.
- [ ] Child terminal while parent running changes only the allocation row; lease-free exact child wait may settle/wake/stop the parent once in a parent revision transaction, and recovery loses no wake.
- [ ] `authorization_grants` stores only exact `AuthorizationGrantV1`. Create begins at active version 1; the only consuming transition atomically installs exact `AuthorizationConsumptionReceiptV1` plus its named consumer at version 2; revoke changes only active to revoked, revoked replay is immutable, and consumed revoke is a successful no-op that preserves the receipt. Grants are principal/digest/target/purpose/use/expiry bounded, contain no secret bytes, and are never dispatch grants.
- [ ] Script-bearing dependency admission consumes the exact lockfile authorization and atomically publishes exact `DependencyInstallScriptsAuthorizationTemplateV1`; template policy/workspace/receipt/toolchain/adapter/lockfile/registry/candidate/deadline fields validate, and each candidate uses one exact unused-ordinal `OperationGrantV1` rather than reusing the authorization row or a resettable counter.
- [ ] Dependency success is one atomic ready transaction: `DependencyReadyItem.planRef/opId/attempt/packageCacheManifestRef` match the current candidate-derived plan and completed acquisition Journal; `readyCheckpointId` names the same-transaction post-effect ready Checkpoint containing that item and Journal sequence; and `installedTreeDigest` equals the decoded Checkpoint `WorkspaceStateManifest.entriesRef -> WorkspaceEntryManifest.treeDigest`. No pre-effect or independently committed Checkpoint/item may advance to verifiers.
- [ ] MCP register/refresh stores only exact `RequestedMcpRecoveryV1` intent before I/O and only exact raw `McpProbedToolInterfaceV1[]` plus `probedToolsListDigest` in the result. It rejects final recovery/profile/template/predicate/contract/registry fields in either artifact, requires every explicit requested name to match exactly one raw interface, preserves additional valid discovered interfaces with exact `manual` recovery, and deterministically constructs final `McpToolContract[]`. Tests cover missing/duplicate/mismatched requested names, accepted unrequested interfaces, distinct raw/final list digests, the acyclic `registry core -> probe receipt -> final revision` construction, and the same-transaction final revision, receipt, registry-row CAS, completed admin operation, and control response. The owner-scoped row advances to one monotonic immutable revision tied to that probe; old admitted manifest refs remain recoverable, no credential bytes enter SQLite/CAS, and every registry-transitive request, raw interface, retry consent/safety assertion, signed adapter, status template/static arguments, predicate, schema, transport/runtime/endpoint/binding, probe, receipt, and death-evidence ref closed-decodes and remains a GC/recovery root.
- [ ] Admin operation attempts use the exact discriminated field matrix, mandatory target/core/plan/spec ref+digest pairs before preactivation, contiguous `1..3` attempts, one nonterminal row, closed CAS edges, and exact terminal XORs. Target/core/spec/plan/owner all match before containment; post-containment dynamic identity cannot enter static artifacts. BrokerRequest repeats target and payload digests. Result, closure, error, diagnostic, response, tools, protocol and every ref/digest revalidate; closure repeats plan/spec digests. Deterministic errors alone map final rejection, recovery errors retryable/exhausted. Terminal rows are immutable and no generic setter exists.
- [ ] `state_owners` enforces exact record/acquisition/transition types, contiguous never-reused epochs, one active row, closed phase XORs, and complete identity closure. Genesis is epoch one for one exact as-yet-unowned `KernelGenerationIdentityV1`: `fresh_empty` validates empty image/CAS, while `migrated_candidate` requires the matching durable Kernel authority marker plus candidate/image/CAS closure and is the first post-cutover repository transaction. Clean acquisition follows only latest graceful terminal; death takeover binds prior process absence, transition, acquisition, identical lock/root, and successor atomically. Only three named acquisition APIs write staged artifact metadata/rows without active ownership. Every other write/release requires exact active authority; the sole rollback exception is already-prepared marker rename after graceful terminalization and cannot mutate DB/CAS.
- [ ] Every launch/admin/invocation containment plan decodes as exact `ProcessContainmentPlanV1` and matches owner/filesystem/parent/nonce/backend reservation. Every actual containment and no-spawn/death evidence additionally repeats the exact `sandboxLaunchSpecRef`/`sandboxLaunchSpecDigest`. Every evidence inspector ref decodes exact `SupervisorInspectorIdentityV1`, repeats its digest, proves the signed RuntimeBundle role-`supervisor` executable and sole active `StateOwnerRecordV1` epoch/process/nonce identity, and meets the at-most-five-second freshness bound. Active admin completion/failure, worker/invocation retirement, Checkpoint, and result publication require matching fresh exact `ProcessContainmentDeathEvidenceV1`; preactivation failure requires matching exact `ProcessContainmentNoSpawnEvidenceV1`. Timeout, expiry, Supervisor loss, stale inspector identity, PID exit, or inaccessible containment never terminalizes the row, and no successor adopts/renews it or starts another attempt before proof. Fake-clock tests prove retryable attempts 1/2 have no control response and gate attempts 2/3 by 1s/5s; deterministic rejection or attempt-3 exhaustion commits the only final error response, while completion commits registry revision/receipt and the only success response.
- [ ] CAS verifies hash/length/type, flushes file and directory, no-replace publishes, deduplicates identical bytes, rejects symlink/hardlink/special targets, and never leaves a committed dangling reference.
- [ ] `readRecoveryClosure` returns RunSpec+Run+latest Checkpoint+post-cursor items/Journal+all current/unretired worker launches+every referenced/current/quarantined workspace-generation row+all parent/child exact `ChildAllocationV1` rows and closed-decodes the complete objective, normal prompt projection/model request/AgentModelTurn request pair, model-turn/text/ordered observed+resolved-or-rejected tool-input/ordinary audit-payload+model-content result, exact workspace-instruction and ordered skill source/manifest/instruction/resource closure, Session terminal, Run-context compaction summary, workspace-diff/final-candidate producer+summary, frozen-source, exact Git index/object closure, generation identity/snapshot/recovery state, model request/compaction envelope, policy/grant/authorization/child, every unknown Journal row's exact `InvocationAmbiguityEvidenceV1` and branch-transitive owner/broker/sandbox/publication proof, settlement plus `BrokerReleaseFenceEvidenceV1` dispatch closure, verification/provenance, MCP instance/receipt, admin, publication, interpreter/root-image, SandboxLaunch, containment, and StateOwner graphs. RunSpec objective ref is exact and sole; normal messages/tools are reconstructed in canonical order and rerendered/recounted; the system message is reproduced only from the assembly's exact base/workspace/skill refs with labeled JCS pieces and no mutable-path reread; model/batch text and ordered calls equal the exact `AgentModelTurn`; ordinary ToolResult payload/model-content identity/outcome/closure equals its item, while fenced retry-unknown alone follows the direct dedicated artifact. A manual abandoned row's attestation repeats its prior unknown ambiguity pair; no later display/probe artifact replaces it. Diff operations equal the sorted base/result comparison, candidate source/diff/producer/summary fields revalidate, and RunResult repeats its summary. Every reconciliation wait includes the exact state, persisted in-flight `ReconciliationProbeDispatchV1`, retained wrapper, subject evidence/timeout, `ReconciliationInspectorTaskClosureV1`, owner-death acquisition edge, and the worker evidence disposition XOR; restored recovery additionally validates a distinct replacement generation materialized from the named Checkpoint. Local-zero-cost closure includes matching cycle/launch/provenance/boundary/model/capability facts. Any missing/widened ref, digest, XOR, phase, identity, or transitive edge returns `RECOVERY_REQUIRED`.
- [ ] `run_events` is monotonic and attachable but absent from every recovery, permission, budget, verification, launch, and terminal reducer dependency.
- [ ] Attach snapshots enforce `earliestValidCursor=max(0,earliestRetainedEventSeq-1)`: initial zero and exact earliest-minus-one are valid, smaller returns `EVENT_CURSOR_EXPIRED`, above high-water returns `INVALID_REQUEST`, and equal high-water returns an empty page with the same cursor. Terminal pruning retains at least the terminal `state_changed` anchor.
- [ ] `run.result|run.diff` succeeds only for `succeeded|completed_unverified` with the authoritative result. Queued/running/waiting returns exact retryable `RESULT_UNAVAILABLE` plus current revision; failed/cancelled returns exact nonretryable `RESULT_UNAVAILABLE` plus terminal detail. No failed candidate or diagnostic is promoted to result.
- [ ] `session.get` and `run.get` each capture snapshot plus all stream high-waters in one read transaction. Numeric cursors are exclusive safe integers with omitted value zero, `next*` is last-returned or input on empty, equality is caught-up, and future cursors are `INVALID_REQUEST`; these non-pruned streams never expire. Session items are ordered and capped by complete `JCS(items)<=1 MiB`. Run items, Journal, and exact `(createdAt,id)` Checkpoint cursors use independent default-100/max-1000 limits and deterministic `items -> journal -> checkpoints` candidate order under complete `JCS({items,journal,checkpoints})<=1 MiB`; the first non-fitting candidate and every later candidate remain for the next request. Checkpoint cursors round-trip exact unpadded-base64url JCS, same Run, canonical time, and retained row. Golden fixtures cover initial, empty, exact-end, byte-truncated, future, wrong-Run, malformed, and concurrent-new-row cuts without gaps or duplicates.
- [ ] No automatic retention path deletes authoritative truth; every retained event ref remains a root, and every unexpired materialized list cut roots only its exact typed-summary artifact edges until its canonical expiry. GC closed-decodes each exact `RuntimeBundleManifest` and roots the all-and-only selected structured roots, complete-byte entries, and signed transitive members. It also roots every Run objective and endpoint negotiation request/response, normal request/projection/message/tool/context/native-body/compaction-envelope closure, the complete workspace-instruction source/descriptor/raw-byte/manifest/text graph and every selected skill manifest/source identity/instruction/resource/raw-file/bundled-closure/RuntimeBundle/workspace-or-principal root, Session terminal result/detail/summary and Session compaction pair, Run-context compaction plan/turn/summary/replacement segment, model turn/text, ordered input observation/resolution/schema/diagnostic and exact user-input model projection, ordinary audit payload/model content and branch edge, every verifier repair audit/stdout/stderr/model-content/item edge, every invocation-ambiguity artifact plus exact owner-takeover/broker-token/SandboxLaunch/containment/death/publication-proof branch closure, dedicated fenced retry-unknown artifact/settlement/closure, workspace diff/base/result/operation-entry closure, candidate producer/summary, every exact Git index byte/object-pack/object-closure/private-state edge, every workspace-generation identity/state/snapshot/recovery/retirement edge, root-only dependency plan/package/lock/toolchain/endpoint/grant plus `DependencyReadyItem`/cache/ready-Checkpoint/state/tree closure, approval/manual/settlement/dispatch closure including exact broker-fence evidence, complete MCP/admin/publication/interpreter/root-image/StateOwner/migration graph including `KernelSchemaManifestV1`, `ArchivedKernelDatabaseImageV1`, `ArchivedKernelGenerationManifestV1`, every retained portable-export RuntimeBundle/catalog/profile/source/session/payload/object edge, and exact `LegacyPortableHandoffVerificationResultV1` inline closure, every reconciliation state plus in-flight dispatch/wrapper/subject-or-timeout/task-closure/owner-death edge, and the complete policy/grant/authorization/template/verification/local-service/model/containment closure. It obeys age/death/expiry limits and deletes nothing on incomplete decoding or reachability.
- [ ] Every retained generic-runtime StopIntent/TerminalDetail additionally roots its exact `RuntimeFailureEvidenceV1`, current-inspector identity, and branch-transitive unusable-response, model-request/Journal, credential-authority/endpoint, retry-result/settlement/dispatch, dependency-plan/acquisition, or local-provenance/spec/boundary graph. GC refuses deletion when that closed branch cannot be decoded or cross-validated.
- [ ] Legacy auth preflight holds root/auth locks and publishes exact present-or-absent `LegacyAuthStoreObservationV1`. Present requires held no-follow same-owner `0600` regular/link-count-one recognized store; absent requires exact `ENOENT`. Both publish exact non-secret projection and secret-free ready manifest; only present secret entries create deterministic endpoint/binding/round-trip evidence, and original bytes or absence remain authoritative until marker publication. Unsupported/drifted state publishes no Kernel authority.
- [ ] Inventory/backup/CAS/SQLite/archive/log/export exclude raw keys and retain the exact observation/projection/ready graph. Exact control moves contiguously to candidate-ready then credential-cutover; migrated marker repeats the observation for both branches, and Kernel authority is last. Pre-authority recovery deterministically renders the present branch from current platform items or restores exact absence by unlink+ENOENT+directory-fsync; post-authority validates the marker.
- [ ] Every rollback retains exact request/current-authority/source-generation/backup pairs. `rollback_draining` repeats the source `KernelGenerationIdentityV1` and forbids an archive ref; after global drain the implementation publishes and validates a fresh current database identity, exact read-only descriptor copy, final complete CAS namespace, and exact `ArchivedKernelGenerationManifestV1`; only `rollback_restoring` and `MigrationReceiptV1(legacy_rollback)` may bind that archive pair, together with the unchanged source identity. Source absent uses `restored_absent`; present with zero secret records uses `rendered_nonsecret` without consent; present with records requires request true plus exact consent and current matching platform items for `rendered_with_credentials`. Request false cannot render secrets. No raw credential comes from retained bytes and no old runtime starts before both legacy markers.
- [ ] macOS/Linux migration continuously holds one exact lock order—exclusive Kernel global/state-owner, local-model registry/object-store, legacy auth-store, every discoverable legacy Session/transaction/plan lock in canonical byte order, then credential-authority—from exact preflight control through record/inventory revalidation, auth-observation marker publication, Kernel authority marker-last, and control cleanup. It proves processes/open files and identical inventories twice, creates/reverifies a read-only backup, validates exact closed database-image/private-CAS generation artifacts, and publishes Kernel authority only as the final cutover action; release/reacquire or order inversion fails closed.
- [ ] Legacy Sessions, ordered records, compactions, plans, progress, handoffs, forks, and ids survive as context/artifacts; old checkpoints are only `legacy_bookmark`; no lifecycle/turn/transaction field creates a Run. Import builds exact live workspace/repository identity where descriptor proof succeeds and otherwise exact `legacy_unavailable` without failing unrelated context migration or fabricating execution identity; that branch and its forks cannot submit/apply.
- [ ] Every injected crash before cutover authority leaves legacy authoritative; every crash after it converges idempotently to the one verified Kernel generation without duplicate items or dual write.
- [ ] Native Windows `state export --output` implements the exact state-free portable protocol: the destination is absent on first execution, with only exact byte-identical final-present crash replay accepted; `CreateFileW` opens only the root; all descendants use held-parent `NtCreateFile|NtOpenFile(RootDirectory=...)`; root/output/temp/final identities rehash exact held descriptors; the signed projection RuntimeBundle/catalog and finite profiles produce the all-and-only source-root+bundle+schema+Session+payload object closure; and exact archive bytes exclude `auth.json`/credential authority. Publication uses one stable deterministic temp, post-write identity publication, no-replace same-parent rename, parent flush, and an exact receipt whose `completedAt` equals the handoff `createdAt` and whose omission digest makes replay byte-identical. Crash recovery returns that exact verified final receipt or resumes a verified complete temp; a partial/invalid temp seen on re-entry blocks with manual-cleanup guidance and is never deleted by predictable name. Only the same live creator may delete through its continuously held `FILE_CREATE` handle after identity recheck and parent flush. Unknown/reparse/mismatched/simultaneous state likewise blocks. State-free `--verify` emits exact `LegacyPortableHandoffVerificationResultV1` with inline handoff/output-directory/final-file identity, archive count/digest, post-reread fenced time, and omission digest. Neither command opens/creates Kernel SQLite/CAS or authority markers; migrate/runtime/admin return `UNSUPPORTED_PLATFORM`.
- [ ] Every fresh, migrated, live, and archived database image resolves the exact signed non-executable `KernelSchemaManifestV1(kernel_state_schema_v1@1)`. Storage recomputes its ordered DDL and complete byte-sorted `sqlite_schema` projection/digests; database/application/user/schema fields and archive copies match it exactly; fresh generation pristine-schema fields repeat it, while migrated-candidate branches forbid those fields and validate their candidate image. An ambient migration registry, DDL file, matching user-version alone, unlisted object, or unsigned schema cannot establish authority.
- [ ] Rollback holds the full canonical order and global fence, closes all typed authority, proves broker/Supervisor/credential quiescence, snapshots the exact post-drain/pre-restoring database and CAS into the closed archive manifest, restores one exact auth outcome, then publishes exact generation/receipt and prepared identical markers. The active owner's final DB transaction roots that archive and is graceful terminalization; only legacy-root marker first and state-root marker last follow. A pre-final-marker successor uses clean acquisition only, remains fenced, publishes missing prepared bytes, and gracefully terminalizes itself. Unknown state blocks; after state-root legacy authority no owner acquisition or Kernel mutation is legal.
- [ ] A rollback crash never exposes a partial legacy tree or substitutes the admission-time image for the drained snapshot. Completed rollback preserves exact `ArchivedKernelDatabaseImageV1` plus final CAS closure through `ArchivedKernelGenerationManifestV1` read-only, while the declared restoring/owner-terminal database tail remains independently rooted by receipt/control/StateOwner evidence; future migration creates a fresh generation rather than reusing/merging it.
- [ ] `npm run build`, `npm test`, `npm run test:state`, `npm run test:migration`, and `npm run test:state-fault` pass.

### Validation

Automated:

- `npm run build`
- `npm test`
- `npm run test:state` for canonical kernel-type golden/schema rejection (including exact Run objective and endpoint negotiation request/response; normal prompt message/projection/request and AgentModelTurn request-pair; exact workspace-instruction-source/workspace-instruction/bundled-skill/source-file/source-identity/skill-manifest provenance; Session terminal and Run-context compaction summary types; model text/observed+resolved-or-rejected tool input/model-turn/batch/tool-result audit-payload+model-content; input prompt/schema/payload/model-content; verifier repair audit/model-content/item; child result/model-content/allocation; workspace-diff/final-candidate unions; sanitized private-Git config/state; root-only dependency-plan and SandboxProfile unions; frozen-ignore/projection/include-classification/include-authorization; native request/compaction envelope/signed request ceilings; approval decision, operation grant provenance, authorization/template, invocation-ambiguity/budget-settlement/dispatch-closure/manual-attestation, verification/inherited provenance, MCP recovery plus instance/launch-receipt graph, complete reconciliation wrapper/timeout and `PublicationProofV1` unions, four-owner sandbox-launch/containment, process/root/lock/acquisition/transition `StateOwnerRecordV1`, `SupervisorInspectorIdentityV1`, and local-inference unions), canonical separate declarative-context capture, all-scopes labeled instruction/skill JCS and two-LF join, source-branch equations/path containment/bounds/no-execution/no-mutable-reread, prompt-source order/contiguous indices/excluded-control invisibility/tool projection/request equality/rerendered-token count, fixed model retry shape/provider-rejection completion, terminal status/result/detail/summary plus exact Run/RunSpec/admitted-context equality matrix, Run-context compaction range/source/summary equality, AgentModelTurn text/ordered-call/stop-matrix equality, atomic all-resolved versus rejected-batch routing, every ordinary audit/model-content result outcome/XOR and direct unprojected fenced-retry-unknown exception, exact sorted diff comparison plus agent/delivery candidate producer-summary and RunResult equality, adapter conformance, deterministic rendered-byte/token-count reproduction, logical Session lineage/projection/segment-boundary fork/compaction, admission rev0-to-rev1 with operation-derived frontier, exact builtin descriptor/Git-index/frozen-rule classification, atomic ignored-include read-grant consumption, and distinct pre-admission delivery `SourceManifest A`/recovery `WorkspaceStateManifest W_A`, proof-carrying delivery-frontier preservation, forward-success versus abort-stop `DeliveryTerminalProjectionEvidence` matrices, exact publication/manual/retry-only TerminalDetail, typed reducers, status/frontier/wait/StopIntent/terminal invariants, Journal launch-ref/evidence-pair/settlement/MCP-instance-receipt phase matrix and transitions, all four ambiguity mechanisms plus abandoned-attestation equality, current-versus-historical evidence, worker/local launch CASes and retirement XORs, exact local `serviceSpecCoreDigest -> serviceId -> serviceSpecDigest` derivation, service-level cycle singleflight/request replay/Run-frontier join/mandatory attempt-1-retire-to-retry versus unresolved-final-fail/attempt-2-terminal matrix/atomic participant fanout and exact local-cycle resource exhaustion, both permitted pre-response fences, control replay, child settlement, acyclic MCP registry publication/admin static-core state and registry-transitive recovery roots, CAS/typed reachability including every publication-proof branch and retained-event payload/message refs plus atomic prune-edge removal, Run and local-service recovery closure, exact attach cursor bounds/terminal anchor, and `RESULT_UNAVAILABLE` result/diff routing.
- Workspace/repository-identity fixtures include maximum-width unsigned decimal device/file ids, leading-zero/sign/unsafe-owner rejection, literal in-root `.git` directory/object-format/ref+digest validation, `.git` file/link/outside/owner/type rejection, live-versus-legacy-unavailable forbidden fields, symlink/root/`.git` replacement races, Session fork ref preservation, `run.submit` path equality, pathless `run.apply` source-Session derivation, legacy execution rejection, and cross-artifact workspace/repository-digest mismatch.
- `npm run test:migration` for representative `SESSION_VERSION` fixtures, process/open-file inspection, exact continuous Kernel-global/state-owner -> local-model registry/object-store -> legacy-auth -> byte-sorted legacy-state -> credential-authority lock ordering, exact Migration-control spine, no-follow inventory, live `WorkspaceIdentityV1`/`RepositoryIdentityV1` reconstruction versus exact `legacy_unavailable`, present/absent auth observation, non-secret projection, credential binding/round-trip evidence, secret-free ready manifest, closed database-image/CAS-generation identity, marker-plus-authority ordering, pre-authority restoration of both auth branches, all three rollback auth outcomes, retained rollback request/generation pairs, owner-terminal/legacy-root-first/state-root-last recovery, raw-key absence, malformed identities, unresolved transactions, backup/import/bookmark mapping, Windows export-only first-run absence/final-present replay and exact `LegacyPortableHandoffVerificationResultV1`, idempotency, divergence, and fail-closed rollback quiescence.
- `npm run test:state-fault` kills around CAS/artifact publication; every typed reducer/evidence/control edge; broker fence-token/closure; reconciliation dispatch/task closure; StateOwner genesis/clean/takeover; admin/local/worker containment; and every migration observation/projection/round-trip/inventory/backup/database-image/CAS-manifest/candidate/control/receipt/marker boundary. Rollback faults cover request/control, every auth outcome, full drain, owner graceful terminalization, legacy-root marker, state-root marker, and clean fenced successor replay.
- Run `PRAGMA foreign_key_check`, `PRAGMA integrity_check`, cross-field invariant scans, and CAS reachability/digest verification in state/migration/fault suites.
- Static dependency tests prove production recovery never imports/queries `run_events` or `control_requests` responses, workers cannot import state drivers, and Kernel modules never call `saveSession`, `mutateSession`, legacy checkpoint writers, or transaction-store writers.
- Platform CI runs real macOS and Linux legacy-quiescence/import fixtures. Native Windows CI proves export-only operation and zero Kernel-state filesystem creation.

Manual:

- Copy a populated legacy state tree to a temporary same-user location, run `cliq state migrate --check` and `cliq state migrate`, and compare Session ids/order, compactions, plans, handoffs, bookmark counts, backup digest, database integrity, and absence of synthetic Runs.
- Migrate both present and absent auth fixtures, interrupt observation/projection/round-trip/ready/control/marker/authority boundaries, and verify exact branch restoration, binding equality, secret-free backup, and fail-closed publication. Roll back absent, present-with-zero-records, and present-with-records; only the last requires the retained true request/exact consent, and missing/revoked items block before old runtime start.
- Kill migration at every control revision, observation/projection, backup, rescan, closed database-image/CAS candidate, fsync, receipt, and final-authority point; verify exactly one side remains authoritative and rerun converges.
- Submit a Run, kill the client immediately after acknowledgement, reopen from another process, and inspect its revision-1 initial Checkpoint/event/control replay and complete recovery closure without any JSON/event-based reducer input.
- Exercise `end`, all-resolved `tool_calls`, identity-valid rejected `tool_calls`, unusable, and authenticated-abort model turns. Verify model/batch `textRef`, ordered observation/input refs/digests and disposition XORs, and stop/abort fields match the exact `AgentModelTurn`; malformed identities/combinations settle as `MODEL_PROTOCOL_ERROR` without a batch/candidate, while a rejected batch commits every synthetic result plus next-agent frontier atomically and executes nothing. Produce every ordinary tool-result outcome and confirm exact audit payload plus bounded ref-free model-content projection, then terminalize one fenced retry-unknown call and confirm its result ref points directly to `RetryUnknownCancelledResult` with no ordinary payload/model-content artifact.
- Produce agent and delivery candidates over base/result manifests with add/delete/modify/equal paths. Verify the exact byte-sorted `WorkspaceDiffV1`, result-manifest `sourceDigest`, diff digest, agent end-turn text/`producingOpId`, delivery merge summary/no-op-id XOR, and RunResult summary equality; perturb each relation and verify no candidate/final result commits.
- Run `cliq apply` and verify real-workspace capture completes before Run creation; `SourceManifest A` appears only in RunSpec base and initial `delivery:merge`, while the initial Checkpoint names distinct `WorkspaceStateManifest W_A` whose base points to `A`. Verify `A` cannot be restored as a workspace state and no `delivery:capture` state exists. Complete one forward publication and one stopped post-claim abort: success requires the same forward projection ref in finalize/RunResult, while stop keeps StopIntent primary evidence and carries only the exact abort projection. Merge conflict, approval denial, and pre-first-claim cancellation carry no projection ref.
- Replace a Session root directory at the same path after `session.create`; verify `run.submit`, pathless `run.apply`, capture, and publication return `ARTIFACT_MISMATCH`, create no new Run/effect, and require a new Session rather than silently rebinding.
- Activate a worker, restart the Supervisor before lease expiry, and verify the new instance cannot renew/adopt it; heartbeat changes only the launch row and no replacement activates before death proof.
- Submit two concurrent local-model Runs with no active service and verify both request participants join one cycle/two-attempt budget; replay either request returns that cycle/result and changed bytes conflict. Disconnect/restart throughout activation, prove no `control_requests` response or Run appears while its submission remains in flight, force every attempt-1 failure after positive no-spawn/death retirement and verify mandatory `retry_wait` then attempt 2 one second later, force an unprovable attempt-1 containment and verify immediate exact `containment_unresolved(finalAttempt=1)` with the blocking launch retained, force both positively retired and unresolved attempt-2 failures and verify terminal failure, prove no attempt 3, and verify one terminal transaction admits/responds to every valid submission or returns the same `RECOVERY_REQUIRED(local_inference_service)` without any Run.
- Death-prove an active local service while an admitted Run is between model calls; verify its exact queued Run revision/frontier joins the next service cycle, successful activation makes that unchanged frontier eligible, and exhausted activation atomically proposes `runtime/local_inference_unavailable` with the exact failure ref. Moving/stopping the Run before fanout makes the participant obsolete rather than stopping a newer frontier.
- Reserve and activate a managed local-inference service, restart the Supervisor before lease expiry, and verify it never adopts the old service: traffic is fenced, the exact row retires through the no-spawn/death XOR, and a permitted replacement preserves only the stable service projection while receiving new launch/containment identities.
- Deliver current evidence after clearing the old launch and verify it advances the exact waiting/current frontier; then create a higher attempt and deliver old evidence, verifying only historical Journal/audit/billing changes.
- Complete a child while the parent is running, verify only `child_allocations` changes, then let the parent settle in its next revision transaction exactly once.
- Fork a Session at a valid segment boundary, verify that the child projection retains the ancestor `sourceSessionId/itemId` identities with zero cloned rows and that its first local append uses `forkedThroughItemSeq+1`; reject an inside-segment fork and any compaction that straddles or includes a summary/`excluded_control`, and verify item/segment `summaryRef/summaryDigest` equality to the exact `ModelTextV1`.
- On native Windows, run `cliq state export --output` and `--verify`; verify exact signed profile transforms, source-root+bundle object closure, archive bytes, descriptor identities, first-run destination absence, stable-temp/final byte-identical receipt replay with `completedAt === handoff.createdAt`, exact inline `LegacyPortableHandoffVerificationResultV1`, and zero Kernel-state creation. Inject crashes at temp create/write/file flush/verification/rename/parent flush; prove complete temp/final resume returns the same receipt, only the exact partial owned temp is removed, and unknown/reparse/mismatched state blocks without overwrite.
- Crash rollback at request/control, lock, drain, live-image checkpoint, descriptor archive copy/seal, final CAS manifest, archive manifest, each auth outcome, receipt, owner graceful-terminal, legacy-root-marker, and state-root-marker boundary. Verify `rollback_draining` retains only the source identity, `rollback_restoring`/receipt bind the same source plus exact archive manifest, crash resume cannot substitute a birth image or partial CAS root, clean fenced successor replay is exact, no DB mutation follows owner terminalization except successor's own finalization, state-root marker is last authority, and archived database-image/CAS closure remains read-only.

### Risks And Dependencies

- SQLite and CAS cannot share one physical transaction. Artifact-first publication deliberately turns the gap into safe unreachable objects; dangling committed refs remain forbidden.
- `node:sqlite` behavior may drift across supported Node versions. `SqliteDriver` conformance and a frozen on-disk schema isolate that risk.
- WAL/locking are unsafe on some filesystems. Startup must probe and fail closed or use the tested FULL-synchronous rollback journal; never weaken durability silently.
- Legacy JSON/transaction trees may be malformed, contradictory, concurrently owned, or inaccessible to process/open-file inspection. Migration preserves bytes and stops with exact remediation rather than inventing context or recovery truth.
- Legacy credential migration is destructive at the pathname once final cutover publishes the marker and depends on the same-user platform credential store plus WP06's deterministic authority API. Held-descriptor checks, raw-file-preserving preflight, deterministic replay, round-trip/fsync, secret-free ready manifest, pre-authority rematerialization, marker-then-authority-last ordering, and consent-gated reconstruction only for the secret-bearing present-source rollback branch are release blockers; raw-key backup is forbidden even as a convenience fallback.
- The authority-marker-last protocol depends on descriptor-relative, same-filesystem publication and directory `fsync`; unsupported filesystem behavior blocks migration/rollback.
- Work package 4 depends directly on activation-cycle/launch rows, row-only heartbeat, both closed pre-response fences, service-level participant join/two-attempt/fanout CAS, control replay, child allocation, wait/StopIntent transactions, current/historical evidence, and recovery closure from this package.
- Work packages 2, 3, and 5 must publish typed artifacts/evidence through these gates; none may write SQLite/CAS or Run state independently.
- Work package 6 owns final client cutover and deletion of legacy writer paths; this package must land and pass fault tests first.

Required sequence:

1. Land canonical kernel types, secure state root, SQLite driver/schema, and CAS publication/verification.
2. Land all twenty table repositories, including canonical-time fencing, workspace-generation authority, and the authenticated non-authoritative list-cut cache, plus typed state-owner, admission, Journal/evidence, Checkpoint, worker/local-service cycle and launch, bounded local activation fanout, control, child, grant, MCP, admin, and terminal reducers with fault tests.
3. Freeze the repository interfaces with work packages 3 and 4; no detached worker or broker dispatch is admitted until dual dispatch gates, launch fencing, and recovery closure pass.
4. Integrate WP06's exact credential-authority preflight/cutover/rematerialization/rollback APIs, then land macOS/Linux migration, Windows export-only, secret-free backup/import, the three exact rollback auth outcomes with consent only for `rendered_with_credentials`, and authority-marker-last fault suites.
5. Work packages 2, 3, 4, and 5 integrate against the frozen typed interfaces in parallel where safe.
6. Work package 6 performs one Kernel Cut only after build/test/state/migration/fault/sandbox/e2e release gates pass; it removes legacy writers and does not ship an intermediate mixed-authority runtime.

Rollback (hard-to-reverse changes):

- Before Kernel authority publication, discard only unpublished candidate/staging files after validating their identity; legacy remains authoritative.
- After cutover, use only `cliq state rollback --to-legacy <migrationId>` from the new binary. Retain exact `RollbackToLegacyRequestV1`, reuse the active owner token, and continuously hold Kernel-global/state-owner -> local-model registry/object-store -> legacy-auth -> byte-sorted legacy-state -> credential-authority through the typed global fence and complete quiescence. The request's boolean and source observation select the sole legal auth outcome. The final owner transition is graceful; publish the prepared legacy-root marker first and state-root authority marker last. Never hand-edit a marker or install an old binary first.
- While any new nonterminal Run exists, rollback is refused; finish, cancel, or reconcile it to terminal quiescence first.
- Rollback exports new terminal/audit/context refs, restores and verifies a fresh legacy generation, consent-gates and verifies current-platform-item credential reconstruction, publishes its authority marker last, and archives the former SQLite/CAS read-only.
- Never delete the new database, CAS, backup, export, or migration archive as an automatic rollback step. Future Kernel entry always creates a fresh authority generation.

### Open Questions

None. SQLite binding choice, query batching, CAS copy optimization, and internal index layout may change only if every schema, transaction, recovery, migration, and fault invariant above remains exact.

### GitHub Issue Body

**Title:** `feat: add durable Kernel state and authority-safe legacy migration`

Implement work package 1 from `docs/backlog/durable-verified-run-kernel/01-durable-state-and-migration.md` and the canonical Durable Verified Run Kernel RFC.

Deliver the complete twenty-table SQLite/CAS authority, including the singleton `canonical_time_fence`, exact `workspace_generations`, authenticated non-authoritative `list_read_cuts/list_read_cut_entries`, one verbatim `src/kernel/types.ts`, typed repositories/reducers, exact retained `state_owners` fencing, mandatory revision-0-to-initial-Checkpoint-to-Run-revision-1 admission with operation-derived frontier, exact `worker_launches`, `local_inference_activation_cycles`, and `local_inference_launches` authority, same-transaction `control_requests`, child/grant/MCP/admin persistence, current-versus-historical evidence, complete recovery closure, and non-authoritative event cursor. Session creation must publish exact live no-follow descriptor-derived `WorkspaceIdentityV1` plus exact `RepositoryIdentityV1` iff Git; device/file ids remain unsigned decimal strings, fork preserves the ref, every workspace/repository digest matches, and root/`.git` replacement is `ARTIFACT_MISMATCH`. Import may instead retain exact execution-ineligible `legacy_unavailable` context. `run.submit` path must resolve to a live identity; `run.apply` has no path and derives a live source Session. Admission freezes exact ignore rules/projection and requires every include to carry exact builtin classification or atomically consumed read-grant authorization. It also freezes the separate exact workspace-instruction and workspace/user/bundled-skill provenance graph, including the distinct RuntimeBundle complete-file ref versus structured semantic-digest domains. Apply admission must keep captured deliverable `SourceManifest A` separate from recovery `WorkspaceStateManifest W_A`: RunSpec base and delivery merge point to `A`, the initial Checkpoint points to `W_A`, and `W_A.baseWorkspaceManifestRef=A`. Every generation is an immutable `WorkspaceGenerationIdentityV1` plus one authoritative mutable `WorkspaceGenerationStateV1`; WorkerLaunch only denormalizes its phase, and worker recovery quarantines the old generation or restores a distinct preactivated replacement. Local inference storage must implement exact semantic service identity plus one shared retained service-level cycle: up to 128 request/Run-frontier participants, two cycle-owned 120-second launches, positive-retirement-plus-one-second retry, no third attempt, cross-cycle request replay protection, exact failure evidence, and crash-indivisible participant fanout to Run admission/error or queued eligibility/typed stop. Storage must decode and cross-check the RFC-exact source authorization, Git-index/object closure, policy/approval/operation-grant/authorization+receipt/child-allocation/dependency-template/budget-settlement/`InvocationAmbiguityEvidenceV1`/post-claim-no-release/dispatch-closure/manual-attestation/verification/inherited-provenance/MCP-recovery/admin-probe-core/four-owner-sandbox-launch/local-cycle/service/provenance/boundary/containment-plan/actual-containment/state-owner/inspector/no-spawn/death-evidence types; no work-package-local widening is legal. Process-spawning Journal state binds the launch spec only from claim onward, while WorkerLaunch/AdminOperation/local-inference launch bind it before preactivation. Model retry is the exact three-attempt/zero-hidden-retry/`[500,2000]` schedule; a positively received provider rejection completes once as fully charged `ModelUnusableResponseV1` and `Retry-After` never mutates that schedule. GC roots include that complete typed graph, every retained `run_events` payload/message ref, and every unexpired list-cut edge.

Import legacy state once only on supported macOS/Linux with proven quiescence, continuously holding Kernel-global/state-owner -> local-model registry/object-store -> legacy-auth -> byte-sorted legacy-state -> credential-authority through the exact `MigrationControlV1` spine, source present/absent observation, credential projection/evidence, secret-free backup, closed database-image/CAS generation, auth marker, and Kernel authority marker-last. Pre-authority recovery restores the exact source branch. Raw keys never enter retained state; native Windows remains export-only. Rollback retains the exact request/current-generation/backup pair, keeps that lock order and global fence through typed quiescence and the closed three-way auth outcome, gracefully terminalizes the owner as its last DB mutation, then publishes legacy-root first and state-root authority last; only clean fenced successor replay is allowed before that final marker.

Do not add a generic Run mutation API, Run-owned lease identity, optional initial Checkpoint, event-sourced reducer, JSON/SQLite dual write, Windows importer, synthetic legacy Run, or marker-first restore.

Done means every acceptance criterion and validation item in the local spec passes, including `npm run build`, `npm test`, `npm run test:state`, `npm run test:migration`, and `npm run test:state-fault`.
