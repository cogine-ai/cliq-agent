# Agentic Verification And Recovery

## Backlog Ready Spec

### Verdict

READY WITH RISKS

Reviewed against main `0f2fa146` on 2026-09-26. The product contracts are defined,
but verification/delivery is not yet integrated. Build against the existing real
StateStore and typed continuation now; use fakes only at external execution
boundaries that are not available yet. Real containment and installed-process
evidence remain mandatory before completion. The
[cross-package review](../../kernel/2026-09-26-design-review.md) defines the
integration checkpoints and the additional repair-utility gate.

### Source

Brief / issue / roadmap item:

- Work package 05 of the [Durable Verified Run Kernel RFC](../../rfcs/2026-08-11-durable-verified-run-kernel.md).
- Product promise: `Delegate. Detach. Return to verified work.`

Related issues:

- #46 is superseded; verification and delivery do not continue the Transaction aggregate.
- #62 supplies permission concepts but cannot grant child Runs or delivery Runs broader authority than their parent/source Run.
- #76 consumes the durable verification and waiting states through work package 06.

Related code:

- `src/validators/types.ts`, `src/validators/runner.ts`, `src/validators/registry.ts`, and `src/validators/shell.ts` contain reusable validator execution and result-normalization behavior.
- `src/validators/builtin/*` contains reusable diff, index, and size checks, but those checks are not implicit proof that a Run is verified.
- `src/workspace/transactions/diff.ts`, `apply.ts`, `snapshot.ts`, and `recovery.ts` contain reusable diff and conflict/recovery lessons; the Transaction aggregate is not retained.
- `src/session/fork.ts` and `src/handoff/export.ts` contain context-fork and handoff behavior to preserve as Session features, not child-Run execution state.
- `src/runtime/runner.ts` currently treats a model final message as completion and must delegate completion to the verification gate.
- `src/protocol/runtime/events.ts` is the typed event seam to extend with result, child, repair, and verification events.

### User Outcome

A user can delegate a long-running coding Run, detach, and later receive an immutable patch/result with an honest verification state. A `succeeded` Run always has receipts proving that every required verifier passed against the exact delivered source digest. Failed assertions may trigger bounded repair in the same Run; infrastructure failures never cause the model to edit code. Parallel agent work uses ordinary child Runs with isolated workspaces, and writing a result into the real workspace is a separate, explicit delivery Run.

### Problem

Current validators are tied to mutable transaction workspace views and `txId`; their results are not immutable receipts bound to a deliverable digest. The current runner can return a final message without producing a source manifest or satisfying declared checks. Session fork creates another Session rather than a durably scheduled child execution. Transaction apply writes the real workspace directly and cannot preserve the truth of an already verified immutable result when the real workspace has drifted.

Without a single completion gate, Cliq could report success for an unverified candidate, reuse receipts after source changes, repair infrastructure problems by changing code, or let child/apply behavior bypass Run ceilings.

### Scope

In:

- Add immutable `VerifierSpec`, `VerificationReceipt`, `VerificationClosureV1`, and `RunResult` artifacts and schema validation. The closure, not a caller-supplied receipt list, is the sole proof accepted by proof-carrying delivery/finalize frontiers and `commitRunResult`.
- Normalize verifier definitions only from explicit CLI/API input and trusted `.cliq/config`, after Workspace Trust. `AGENTS.md`, skills, package scripts, and model output may suggest checks but cannot modify the frozen required set.
- Treat every repository verifier definition as a declarative request only. Exact executable/environment identity and external reads must be authorized and resolved before admission; noninteractive failure returns `AUTHORIZATION_REQUIRED` and creates no Run. Execution is separately authorized by an admission-time bounded `VerifierAuthorizationTemplateV1` that later mints an exact per-candidate launch grant, or by a typed candidate-time approval. Trust/read identity alone cannot execute or expose host bytes.
- Provide a read-only verifier suggestion pass after trust. Interactive admission may show package/config/AGENTS suggestions and turn only user-confirmed entries into explicit required verifier input; noninteractive/detached admission never promotes a suggestion without flags/config.
- Support verifier gates `required` and `advisory`. Advisory pass/assertion/infrastructure outcomes produce inspectable non-gating receipts, may use only their frozen same-digest retry count, never trigger model repair, and never alter terminal status. The absence of required verifiers always yields `completed_unverified` with `terminalReason='no_required_verifier'` for every nonfatal advisory outcome. Source mutation and kernel-integrity violations remain fatal even from an advisory verifier.
- Bind every receipt to the `runId` that executed it, verifier identity/version, `resultSourceRef`, exact `VerifierCommandV1` and `VerifierEnvironmentV1` refs/digests, timestamps/duration, exit/termination data, stdout/stderr artifacts and truncation flags, lease epoch, and a non-self-referential receipt digest.
- Classify a completed verifier process with a nonzero exit as `assertion-failed`. A spawn failure, verifier-owned timeout, signal, non-source sandbox denial, missing executable, or resource failure becomes `infra-failed` only after positive whole-containment death and source/ephemeral quiescence/rollback evidence; otherwise Journal records `unknown`, the Run waits on typed reconciliation, and no concurrent retry/receipt exists. Stop precedence is source mutation/integrity, then user/parent cancel, then Run deadline, then ordinary verifier outcome; cancel/deadline produce a typed stop item and no infra receipt/retry.
- Permit only the explicit verifier retry count frozen in `VerifierSpec`; omitted retry count means zero. Retries run against the same immutable digest and never invoke the model.
- Feed `assertion-failed` diagnostics back to the same Run only while all frozen repair ceilings remain. The default `RunSpec.budgets.repairAttempts` normalization is `2`; the hard accepted maximum is `5`.
- After each repair, create a new `resultSourceRef`, invalidate all prior candidate receipts for gating, and rerun the complete required verifier set.
- End with `failed` and `terminalReason='verification_failed'` when required assertions remain after repair budget exhaustion. End with `failed` and `terminalReason='verifier_infrastructure_failed'` when explicit verifier retries are exhausted. `completed_unverified` is reserved for Runs whose frozen verifier spec contains no required verifier. A verifier that attempts or completes a source-byte mutation fails with `terminalReason='verifier_mutated_source'`; its receipt cannot gate completion.
- Implement child admission as an ordinary Run with `parentRunId`, its own context/items, Checkpoints, Journal, lease, and private workspace generation.
- Intersect child capability, token/cost/tool/repair allocation, absolute wall deadline, ancestry depth, and direct-nonterminal-child requests with the parent's remaining ceilings. Parent cancellation cascades to nonterminal children; child cancellation does not cancel the parent.
- Atomically reserve each child's granted token/cost/tool/repair allocation against the parent before child admission and persist a `child_allocations` row. Child terminal records inclusive descendant use/result in that row but never mutates a running parent's revision; the parent settles it exactly once in its own state transaction, or atomically on a lease-free exact child wait. Child deadline is the earlier of its requested deadline and the parent's immutable deadline. `childConcurrency` counts direct nonterminal child rows and releases a slot at child terminal truth, independent of later parent settlement.
- For a helper child with no required verifier, derive `unverifiedConsentRef` only from the exact authorized delegate op/grant when it explicitly allows an unverified helper. Such a child can return artifacts only to its parent merge/reverification path and cannot be directly applied/delivered.
- Expose only the canonical typed `delegate` and `await_children` built-ins. All isolated read-only and mutating children may run concurrently within the frozen ceiling; mutating children return immutable patches/results and the parent integrates them serially through `ChildMergeBatchItem`. A merge conflict becomes a structured parent diagnostic, never a write to the real workspace.
- Release the parent worker/lease for an exact `await_tool` child subject. A premature final model turn with outstanding allocations enters `finalize_settlement`; its text is excluded from the next model context and cannot become a candidate. A stopped parent uses `stop_settlement`; if it replaced an active await call, final settlement appends exactly one identity-matched cancelled `ToolResultItem` and never resumes the model. Only a lease-free exact wait may be atomically settled/woken by child terminal; a running parent is not asynchronously revision-bumped. Recovery scans all three subject variants idempotently.
- Require the parent to verify the combined final `resultSourceRef`; child receipts do not prove the parent result.
- Build immutable default output as `RunResult` with `baseSourceRef`, `resultSourceRef`, `diffRef`, the exact `VerificationClosureV1` ref, closure-derived receipt refs, optional exact-result delivery provenance, candidate-bound dependency-plan provenance, and summary. Failed candidates and unresolved facts remain reachable only through typed terminal details/audit items; they are never fields of a successful result.
- Implement `cliq apply <runId>` as a new `operation='delivery'` Run. It captures the current real-workspace base, applies the source Run diff in a private merge view, re-runs required verifiers whenever the content-addressed merged result reference differs, obtains explicit materialization permission, and journals publication as a queryable/reconcilable effect. Exact-reference reuse requires an immutable inherited-verification provenance artifact; receipt ownership is never rewritten.
- Preserve the original source Run and its receipts when delivery conflicts, fails, or becomes ambiguous.
- Close delivery terminal truth by branch. Only successful forward/finalize may require the observed real-workspace projection to equal the verified `DeliveryPlan.desiredSourceRef`. A failed/cancelled delivery may terminalize after the abort branch without claiming either successful delivery or rollback to the captured base, but only when every started forward operation and every selected abort operation has a non-unknown terminal receipt, every unstarted forward operation is enumerated, all staging/quarantine transients are absent, every plan-touched path has an unambiguous descriptor-relative observation, and the Git index is unchanged. Its `TerminalDetail` must name the exact result-item set and a typed observed partial-projection artifact. Any unknown, unexpected, unmatched, or insufficiently evidenced state remains `waiting(reconciliation)`.

Out:

- Infrastructure lease recovery, sandbox construction, broker fencing, and Checkpoint restoration; those are work packages 03 and 04.
- A separate Task/Subagent/Delivery aggregate, workflow graph, or concurrent writes to one workspace.
- Automatic application to the user's real workspace or remote Git publication.
- Treating advisory checks, model claims, child success, or arbitrary historical receipts as proof of the current result. The sole reuse case is a source Run's validated receipts for the identical content-addressed `resultSourceRef`, frozen verifier spec, and successful source RunResult, bound into an explicit delivery provenance artifact.
- Automatic flaky-test detection or model repair for verifier infrastructure failures.
- Retaining the Transaction aggregate or `activeTxId` as the delivery mechanism.

### Proposed Implementation Direction

Likely files/modules:

- Create `src/run/result.ts` and `src/run/result.test.ts` for `RunResult` construction, `VerificationClosureV1` graph validation, digest binding, and terminal invariants.
- Create `src/run/verification.ts` and `src/run/verification.test.ts` for verifier scheduling, outcome classification, receipt/closure publication, and the `nextStep='verify'` gate.
- Create `src/run/repair.ts` and `src/run/repair.test.ts` for bounded assertion diagnostics and repair-budget transitions.
- Create `src/run/children.ts` and `src/run/children.test.ts` for the pre-admission pricing guard, deterministic child assembly/policy derivation, `ChildCapabilityGrantV1`, `ChildAllocationV1`, inherited ceilings, waiting/wakeup, cancellation, settlement, and serial patch merge.
- Create `src/run/delivery.ts` and `src/run/delivery.test.ts` for private merge, drift detection, re-verification, permission, and publication reconciliation.
- Refactor `src/validators/*` into Run-oriented verifier adapters; keep execution/result-normalization code but replace `txId`, `workspaceView`, and mutable artifact semantics with `runId`, frozen source view, and immutable receipts.
- Extend `src/protocol/runtime/events.ts`; work package 06 maps those events to the versioned control/JSONL/RPC surfaces.
- Integrate the completion reducer into the typed runner from work package 02 and the Run store transaction API from work package 01.

Freeze these artifact contracts:

```ts
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
  | { kind: 'path_observation'; observation: PublicationPathObservationV1; proofDigest: string }
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
  | { kind: 'transient_absence'; transientPaths: string[]; observationRefs: ArtifactRef[]; proofDigest: string }
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

type ChildResultModelContentV1 = {
  schemaVersion: 1
  format: 'cliq-child-result-model-content-v1'
  childRunId: string
  mode: 'read_only' | 'mutating'
  content:
    | { status: 'succeeded' | 'completed_unverified'; summary: string }
    | { status: 'failed' | 'cancelled'; terminalReason: RunTerminalReason }
  contentDigest: string
}

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

Admission rejects duplicate verifier ids, requires the bounded public verifier version, obtains read/identity authorization, and resolves the exact execution identity before Run creation. Linux resolves against its pinned execution-toolchain manifest; macOS strong Runs resolve against the signed Linux guest `GuestToolchainManifest`, never a host Mach-O path. Unsupported host-only commands/native dependencies fail with `UNSUPPORTED_EXECUTION_IDENTITY`. Interactive clients may obtain the authorization and then submit; noninteractive failure creates no partial Run. A launch template covers at most `repairAttempts+1` candidate generations and the frozen per-verifier attempts; when a candidate exists the Supervisor atomically mints its exact `resultSourceRef` launch grant or creates `waiting(approval)`.

The command/environment chain is imported field-for-field from the canonical RFC. Each digest is SHA-256 over RFC 8785/JCS with only its own digest member omitted. Verifier indices are contiguous; command argv stays ordered and contains only bounded non-secret literals; environment variables are unique and byte-sorted; writable roots are unique, byte-sorted, and canonical admitted-root-relative. The environment points to the exact command, source projection, RuntimeBundle, and optional paired GuestToolchain identity. A workspace script always carries an exact `InterpreterIdentityV1` ref/digest resolving one signed guest-toolchain executable and fixed script-path invocation protocol; host PATH, shebang search, and an optional implementation-selected interpreter are forbidden. `VerifierSpec`, `VerifierAuthorizationTemplateV1`, `VerifierPlan`, the Journal request, and `VerificationReceipt` repeat those exact refs/digests; storage rejects a free-form fingerprint, alternate executable/environment, or a receipt whose plan/template chain differs by one byte.

Omitted verifier values normalize to `timeoutMs=600000`, `retries=0`, and `outputLimitBytes=4194304`; accepted bounds are 1 second through 60 minutes, 0 through 3 retries, and 64 KiB through 16 MiB output. `cwd` and writable ephemeral paths are canonical root-relative paths. Verifiers receive direct argv, never a shell string, no raw secret, and no direct network. Source is read-only; only declared ephemeral output roots are writable. A post-run digest change or auditable sandbox violation identifying a source-write syscall records `outcome='source_mutation'` and terminates `failed(verifier_mutated_source)`; a verifier-caught/ignored read-only filesystem denial may be unobservable, but cannot mutate bytes. `KernelIntegrityEvidenceV1.evidenceDigest` omits itself under JCS and matches the exact Run/projection/generation/current inspector plus verifier Journal op/attempt/result source. Its audited-write branch repeats the request/containment/SandboxLaunch/path and proves a broker/sandbox block before write with equal before/after source; its drift branch rehashes unequal SourceManifests and a nonempty unique byte-sorted changed-entry list. Drift either forbids both containment/spec refs for a trusted Supervisor rehash outside a child process or requires both and matches one owning claim/actual containment; ref-only/spec-only combinations fail. Receipt violation ref/digest are both required only for `source_mutation` and equal that artifact; equal source digests require audited denial, unequal digests require drift. The fatal StopIntent and TerminalDetail repeat the same ref/digest. Output truncation is explicit and cannot turn a non-pass into a pass. `durationMs` is the nonnegative monotonic elapsed duration. `receiptDigest` is SHA-256 over the RFC 8785/JCS canonical receipt object with the `receiptDigest` member omitted; the CAS artifact digest is checked independently.

Verifier outcome precedence and Journal mapping are closed. First, a changed source digest or audited source-write violation is `source_mutation` regardless of exit/timeout/signal and commits Journal `completed` plus the fatal receipt. Otherwise a user/parent/deadline StopIntent produces no receipt: after containment death/quiescence proof it commits positive Journal `failed` plus the canonical `VerifierStopItem`; until proof it is `unknown`/reconciliation and no retry starts. Otherwise normal exit zero is `passed`, normal nonzero is `assertion_failed`, and both commit Journal `completed` plus receipt. Remaining spawn/timeout/signal/sandbox/resource failures become `infra_failed` only after full containment death and unchanged-source/quiescence proof; they commit Journal `failed` with `receiptRef`, `errorRef`, and `evidenceRef`, enabling only the frozen same-op retry. Unproven death commits `unknown` with no receipt.

Cross-field storage validation enforces that every receipt has matching `containmentEvidenceRef`; `passed` requires exit zero/no signal and both source digests equal `digest(resultSourceRef)`; `assertion_failed` requires normal nonzero exit/no signal and unchanged exact source; `source_mutation` requires the exact paired integrity ref/digest and its audited-equal or drift-unequal branch; `infra_failed` requires unchanged source, a non-normal termination class, and positive death/quiescence evidence. `exitCode` exists iff termination is `exit`; `signal` exists iff termination is `signal`; both violation fields are forbidden unless source mutation. Each gating passed receipt is the unique `receiptRef` of the matching highest `opKind='verifier'` Journal `completed` attempt/request for that verifier/spec/environment/result. Storage rejects every other phase/outcome/field combination.

`VerificationClosureV1` is the sole artifact allowed in any Run-frontier `verificationClosureRef`. `closureDigest = SHA-256(JCS(closure with closureDigest omitted))`. Its Run, candidate, result, and plan must equal the current verify/finalize/delivery frontier; `entries` is contiguous by `verifierIndex`, unique, and byte-for-byte aligned with `VerifierPlan.entries`. A `passed` disposition names the identity-matched `VerifierResultItem`, the highest eligible verifier Journal `completed` fact, and that fact's exact receipt. `advisory_nonpassing` is forbidden for required entries and names the correct completed assertion or positively failed infrastructure fact; `advisory_skipped` is likewise advisory-only and names the exact skip/decision. `verification.kind='local'` with `outcome='verified'` requires at least one required entry, every required entry `passed`, and no `unverifiedConsentRef`. `outcome='unverified'` requires zero required entries and the exact admitted RunSpec consent; advisory entries may still be passed, nonpassing, or skipped without changing that outcome. Source mutation or a stopped/unresolved required verifier cannot produce a closure.

The dependency branch is equally closed. `dependency.kind='none'` is legal iff the frozen dependency policy is absent or disabled. `ready` names the current candidate-derived policy/plan and a **current-Run-owned**, identity-matched `DependencyReadyItem`, acquisition Journal `completed` fact, and ready Checkpoint whose source digest still equals `resultSourceRef`. Source-Run dependency readiness is never inherited or relabeled. `inherited_verified` is delivery-only, requires an identical result source, and revalidates the source terminal `RunResult`, immutable verification provenance, verifier plan, receipts, and artifact digests; the delivery closure still carries its own `none|ready` dependency branch.

The reducer that consumes the final verifier/dependency result publishes the immutable closure before one state transaction. For an agent result it installs the finalize frontier. For `afterPass='delivery_approval'` it instead installs the canonical delivery approval frontier carrying unchanged candidate/result/verifier-plan/closure/plan refs; allow preserves all five through publish/abort, and the last successful forward observation installs delivery finalize with that same closure plus `DeliveryTerminalProjectionEvidence`. `commitRunResult` then accepts exactly those refs and re-walks the graph from authoritative storage. It rejects a merely schema-valid CAS artifact, alternate receipt list, caller-derived summary, stale candidate/plan, changed dependency readiness, or a closure reconstructed after publication. `RunResult.verificationClosureRef` equals the current finalize frontier ref. For a local closure, `verificationReceiptRefs` is exactly the unique entry-order list of every `passed|advisory_nonpassing` receipt and contains no receipt for a skipped entry; for inherited verification it exactly equals the validated source `RunResult` receipt list. `dependencyPlanRef` agrees with the closure's dependency branch, and `verificationProvenanceRef` is present exactly for `inherited_verified` and equals its validated provenance. `deliveryTerminalProjectionEvidenceRef` is absent for agent Runs and required/equal to the finalize frontier for delivery Runs.

`commitRunResult` is the only storage method that can set `succeeded|completed_unverified`. In the same terminal transaction it requires no `stopIntentRef`, no cancellation or active stop proposal, terminal quiescence, a closed frontier, the exact current candidate/result/diff/summary refs, and a fully reachable closure. `local/verified` or valid `inherited_verified` maps to `succeeded(verified)`; `local/unverified` maps only to `completed_unverified(no_required_verifier)`. Generic Run compare-and-swap cannot create either terminal state.

The Kernel Cut performs no automatic deletion of a Run, `RunResult`, closure, receipt, publication projection, or provenance. The installed delivery/finalize `RunFrontier.verificationClosureRef`, then `RunResult.verificationClosureRef`, roots the closure and its transitive candidate, source/diff/summary, verifier plan/spec/result items, Journal facts, receipts/output/evidence, dependency policy/plan/ready item/Checkpoint, consent, and inherited source-result/provenance graph. A delivery finalize/RunResult additionally roots the exact terminal projection evidence and every referenced publication result/observation. An artifact published but never installed in an authoritative frontier/result is only an unreferenced CAS orphan and follows work package 01's delayed reachability collection; collection never breaks an installed proof graph.

`RunResult.verificationProvenanceRef` is absent for ordinary locally verified results. For a delivery merge that normalizes to the exact source `resultSourceRef`, it references only canonical `InheritedVerificationProvenanceV1`; `provenanceDigest` omits itself under JCS. The artifact binds `deliveryRunId`, source Run/result/result digest, source verification closure/ref digest, the identical result source, verifier spec/digest, and the source closure's entry-ordered receipt refs/digests. The referenced receipts keep `sourceRunId`; they are not copied or relabeled. Storage re-walks the terminal source result, closure, Journal, and receipt graph and requires the delivery closure/RunResult to repeat the same provenance ref. A changed artifact ref, verifier spec, source terminal truth, or failed integrity check forces fresh delivery-owned receipts.

Child assembly and policy derivation is a storage-validated equation, not an adapter choice. Let `P_A`, `P_M`, and `P_P` be the exact parent `RunAssemblyV1`, `ToolContractManifestV1`, and `RunPolicySnapshotV1`, `R` the canonical `DelegateRequest`, and `G` the resulting `ChildCapabilityGrantV1`. Kernel Cut pricing is already the closed `zero_cost|trusted_price_table` union, so child derivation creates no external pricing authority. The Supervisor computes `G.granted` as the byte-sorted intersection of `R.capabilities`, the parent's exposed built-in names and MCP registrations, the exact delegate `OperationGrantV1`, parent policy/mode, and kernel constraints. `read_only` forces `allowShell=false` and `allowSourceWrite=false` and removes every manifest entry outside `read|plan` plus shell, source-write, publication, dependency-script, and mutating-delegation entries.

The remaining derivation is exact:

```text
childPricing = P_A.provider.pricing
childToolEntries = byteSort(filter(P_M.entries, requested-and-granted by G and legal for G.mode))
childMcpServers = byteSort(P_A.mcpServers referenced by childToolEntries)
childExposedToolNames = childToolEntries.names for native-tools, otherwise []
childToolRetries = P_A.retry.tools restricted to childExposedToolNames in that order
childPolicyDecision[a] = P_P.decisions[a] when a is granted and legal for G.mode, otherwise deny
childDeadlineAt = min(parent.deadlineAt, admissionCreatedAt + normalize(R.requestedBudgets.wallTimeMs))
allocation.mode = G.mode
allocation.grantedAdditiveCeilings = pick(G.grantedBudgets, modelTokens, costMicros, toolCalls, repairAttempts)
allocation.grantedChildDepth = G.grantedBudgets.childDepth
allocation.grantedChildConcurrency = G.grantedBudgets.childConcurrency
allocation.childDeadlineAt = G.childDeadlineAt
```

The child assembly copies the parent's exact provider/model/endpoint, provider capability evidence, adapter, model credential bindings, runtime/guest, context/compaction, instructions, skills, model-retry, and algorithm identities. Pricing copies the exact `zero_cost` provenance or already-frozen trusted table with `calculationAlgorithm='cliq-price-ceil-v1'`; the latter remains valid because `childDeadlineAt <= parent.deadlineAt`. Only the deterministically filtered tool manifest, MCP set, exposed tool names, tool retry entries, digest, and creation time differ. The child policy copies the parent's principal, workspace identity, mode, engine, and applicable decision rules in original order, points at the child tool manifest, never widens any disposition, and sets every ungranted action class to `deny`. No refreshed registry, credential binding, mutable instruction/skill, or broader parent contract may enter either artifact.

Verifier/dependency derivation is equally closed. `inherit_parent` sets `childVerifierSpecRef` to the exact parent verifier spec and `childDependencyPolicyRef` to the exact parent policy when present. `none` uses the canonical empty `VerifierSpec`, requires `childDependencyPolicyRef` absent, and requires `derivedUnverifiedConsentRef`. `childCredentialGrantRefs` is the byte-sorted unique union recomputed from the child provider, filtered MCP revisions, and inherited dependency policy, contains no extra ref, and is a subset of the parent's frozen credential union.

`ChildCapabilityGrantV1` binds the parent refs, complete delegate batch/call/index/op identity, mode, granted set, child manifest/digest, child assembly/policy/verifier/dependency/credential/consent refs, budgets, and deadline. `grantCoreDigest = SHA-256(JCS(grant with grantCoreDigest, grantDigest, and derivedUnverifiedConsentRef omitted))`; `grantDigest = SHA-256(JCS(grant with grantDigest omitted))`. The child RunSpec must name those exact refs. One admission transaction validates `R`, the delegate operation grant, capability grant, child allocation, all derived refs, parent revision/ceilings, and child admission; it reserves `grantedAdditiveCeilings`, validates the absolute deadline plus depth/concurrency fields, inserts `ChildAllocationV1(state='reserved')`, creates the child/spec/context/base fork, appends `ChildHandleItem`, and resolves the delegate call. A retry with the same admission identity returns the same child; different bytes conflict.

`ChildAllocationV1` is a closed XOR state machine. Its mode, additive projection, depth, concurrency, and deadline equal the equations above and the exact capability grant; terminal mode must agree. `grantedAdditiveCeilings` is the parent's actual reservation, while `childDeadlineAt`, `grantedChildDepth`, and `grantedChildConcurrency` are separate normalized authorities. `reserved` forbids every terminal, usage, and settlement field. `child_terminal` requires exactly one mode/status-valid `ChildAllocationTerminal`, nonnegative safe-integer inclusive descendant usage no greater than the granted additive ceilings, and `terminalAt`, while forbidding every settlement field. `settled` preserves those terminal/usage/time bytes unchanged and additionally requires the identity-matched parent-owned `ChildResultItem`, the exact parent revision that moved usage, `settledAt`, and component-wise `releasedUnusedBudget = grantedAdditiveCeilings - inclusiveBudgetUsage`; it is immutable. A read-only success forbids a patch, a mutating success requires one, and both require `resultRef` equal the child Run's committed `RunResult`; failed/cancelled terminal payloads forbid result/patch and require `terminalDetailRef` equal the child Run. Every branch repeats exact `ChildResultModelContentV1`: successful content copies only the decoded RunResult `ModelTextV1` summary string, failure content contains only status/reason, and no authority ref enters parent model context. Allocation terminal and owned `ChildResultItem` repeat those refs/digests byte-for-byte; a mutating patch exactly projects the child's base/result/diff.

A child terminal commit always changes the child Run and its allocation from `reserved` to `child_terminal`; it never changes a running parent's row or revision. Ordinarily the parent's reservation stays conservative and only that allocation row changes. Settlement occurs exactly once in the parent's next expected-revision reducer, Checkpoint boundary, or stop reducer. The sole asynchronous exception is the final-child transaction when the parent is lease-free on the exact child wait; it may settle that set and install its matching wake/merge/stop frontier atomically. Settlement subtracts the full granted additive reservation from `budgetReserved`, adds `inclusiveBudgetUsage` to `budgetConsumed`, exposes only the computed unused difference, appends the identity-matched `ChildResultItem`, and records `parentSettlementRevision`. Cancellation, crash, or ambiguity never refunds a reservation early. Startup recovery repeats the same revision-checked reducer, and unique allocation/delegate/admission identities plus immutable `settled` prevent duplicate admission or double settlement.

Implementation notes:

1. When the agent produces a candidate, materialize `resultSourceRef`, `diffRef`, candidate-derived dependency plan, and verifier plan, quiesce/retire the active launch, then atomically install a lease-free `status='queued'`, `nextStep='verify'` frontier. A later activation alone enters `running`; verification never inherits a retired worker implicitly.
2. Execute verifiers in the frozen private source view. Runtime safety checks and artifact-integrity checks remain kernel invariants; they are not user verifier receipts.
3. Publish stdout/stderr and receipt artifacts before committing the Journal terminal fact and Run transition.
4. Work package 01's storage-level `commitRunResult` is the sole completion path. It accepts only the current finalize frontier's `VerificationClosureV1`, re-walks its Journal/artifact/dependency graph, requires `RunResult.verificationClosureRef` and closure-derived receipt/provenance fields to match exactly, and commits the immutable `RunResult` with the terminal Run transition. Agent results forbid `deliveryTerminalProjectionEvidenceRef`; delivery results require it to equal the current finalize frontier and a valid forward-finalize projection. `succeeded(verified)` requires at least one required verifier and all required entries passed, or valid identical-result inherited verification; `completed_unverified` requires the frozen required set to be empty even if advisory entries exist. Generic Run CAS cannot bypass this gate.
5. A failed required assertion authorizes a repair only after publishing the canonical diagnostics and their model-safe projections. `VerifierRepairDiagnosticV1.diagnosticDigest` and `VerifierRepairModelContentV1.contentDigest` omit only themselves under JCS; all ref/digest pairs rehash. Each diagnostic names the exact current-candidate, current-plan `assertion_failed` receipt and identity-matched result item, and repeats that receipt's stdout/stderr refs for audit only. `cliq-verifier-repair-redaction-v1` copies none of those bytes: for a nonzero safe-integer exit code it emits exactly `Verifier <JCS verifierId> failed an assertion (exit <base-10 exitCode>). Revise the candidate and try again.` as an NFC, ref-free model message of at most 4,096 JCS bytes. `RepairDiagnosticItem.failedVerifierResultItemIds` and `diagnostics` are equal-length, nonempty, unique, and plan-index ordered; each same-index entry repeats the diagnostic/receipt/model-content closure byte-for-byte. One state transaction then appends that item, increments this Run's `repairCount` and inclusive `budgetConsumed.repairAttempts`, advances `nextStep='agent'`, increments revision, and emits the event. Ancestor allocation remains reserved until child settlement. Recovery sees the counted frontier atomically; later retries of that repair's model invocation do not increment repair again. Normal prompt assembly decodes only the ordered `VerifierRepairModelContentV1` artifacts. Verifier output remains audit data, never an instruction layer.
6. A delivery Run may source only a `succeeded` Run with a durable `RunResult`. `completed_unverified` results and failed-verification candidate artifacts remain inspectable/exportable but are not accepted by the safe `cliq apply` path.
7. Implement the RFC-exact `delegate` and `await_children` built-ins—no untyped spawn API. `delegate` accepts bounded inline exposed built-in names and MCP registration ids, validates objective, `read_only|mutating` mode, parent-current/summary context refs, complete requested ceilings, `inherit_parent|none` verifier mode, and explicit unverified-helper permission; the model never supplies an authority/CAS grant ref. Its stable `opId`/`admissionKey` derive from parent Run, owning batch item id, call index/id, and canonical request digest; admission is retry-safe and appends exactly one identity-complete `ChildHandleItem`. Multiple calls can admit isolated children that run concurrently. `await_children` accepts a unique ordered list of direct handles, freezes batch/call/index identity in `ChildWaitSet`, and produces exactly one ordered discriminated `ChildResultItem` per child. Each item/terminal revalidates the exact terminal child Run result-or-detail and carries only its bounded ref-free `ChildResultModelContentV1` into the model. The reducer branches only on successful patch-bearing mutating results: zero appends the normalized await result/advances the original batch (or returns finalize settlement to `agent:child_results`), even if mutating children failed/cancelled; one or more installs a `ChildMergeBatchItem` for only those successful patches in wait order. Failed/cancelled/read-only child results remain in the final ordered result/context and never create merge calls.
8. Child admission compare-and-swaps the parent, child, and `child_allocations` row in one transaction: it reserves granted token/cost/tool/repair ceilings, caps deadline, checks ancestry/direct-nonterminal slot, and records full delegate identity. An ancestor already reserved that parent's subtree ceiling. Child terminal writes inclusive descendant usage/result into the allocation row without changing a running parent revision. The parent settles terminal rows once in its own expected-revision transaction; only a lease-free exact `await_tool|finalize_settlement|stop_settlement` subject may settle atomically with the final child terminal. Direct concurrency slots derive from child terminal rows. Own repairs increment own and inclusive usage; wall time is neither summed nor reserved. Cancellation/unresolved effects retain conservative reservations until settlement evidence. A no-tool final turn cannot create `FinalCandidateItem` while any direct allocation is nonterminal or unsettled: `finalize_settlement` returns child results to a fresh agent frontier and requires a new complete final turn.
9. A mutating child returns a canonical file-operation manifest, not an untrusted text patch. Each operation is `add | modify | delete | mode | symlink` with canonical path and expected/result identity. The parent rejects a base different from the admitted fork. Serial application MUST use `cliq-diff3-v1`; every merge call is a kernel `workspace-rollback-retry` with pre-effect Checkpoint and stable opId, and `completed` + ChildMergeBatch result + settlement + post-effect Checkpoint + frontier/revision/event commit through work package 01's `commitWorkspaceEffect`. No merged state commits first.
10. `run.apply` descriptor-captures immutable real-workspace SourceManifest A before admission, stores A in RunSpec and `delivery:merge.capturedWorkspaceRef`, materializes A into a private delivery generation, and publishes distinct WorkspaceStateManifest W_A as the initial Checkpoint `workspaceStateRef`; no accepted delivery Run lacks either artifact and there is no post-admission capture phase. Let B be the source RunResult base, S its verified result, and M=`cliq-diff3-v1(B,S,A)`. The merge item/plan repeat `sourceBaseRef=B`, `sourceDesiredRef=S`, `capturedWorkspaceRef=A`; the plan desired/result is M and its diff is A-to-M. The delivery candidate and RunResult use `baseSourceRef=A`, `resultSourceRef=M`, and the identical A-to-M diff. Conflict repeats B/S/A but has no M/diff and proposes the exact `runtimeSubtype='delivery_merge_conflict'` StopIntent carrying `deliveryMergeConflictItemRef`/`conflictRef` before permission/publication. Positively failed publication proposes `runtimeSubtype='delivery_publication_failed'` with exact plan/forward-or-abort/operation/evidence. `commitTerminalStop` projects those fields one-to-one into their identically named TerminalReasonDetail; no generic detail is caller-selected. The private merge view is disposable. CAS-first publication stores the normalized candidate/diff and canonical `DeliveryPlan` before frontier advance. A delivery Run inherits the source `DependencyPolicy`, never a stale plan or source readiness; each merge candidate derives its lockfile-bound plan and, when enabled, executes delivery-owned setup unless the same delivery Run already has the exact ready Checkpoint from recovery. Delivery is non-agentic (`modelTokens=costMicros=repairAttempts=childDepth=childConcurrency=0`): verifier assertion fails the delivery Run and never opens repair. Exact source result reuses receipts only through validated inherited verification provenance; otherwise delivery runs the same required verifier spec and owns fresh receipts. Permission binds the complete plan digest and receives the already-published verification closure.
11. Publication holds a no-follow real-workspace root descriptor and revalidates root identity. Linux walks every ancestor with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`; macOS walks each component using `openat(O_DIRECTORY|O_NOFOLLOW)` plus `fstat`. Every operation uses only parent descriptors and the exact `PublicationOperation` union: mkdir has no transient, create has staging only, replace has staging plus quarantine, delete has quarantine only, and every operation has an existing-directory identity or earlier planned-mkdir parent. Forbidden/omitted kind fields invalidate the plan. `DeliveryPlan.forwardOperations` is ordered ancestor-first; a separate deepest-first `abortOperations` contains only planned delivery-created directories. A forward mkdir is mode 0755, identity-checked and fsynced. Abort records `not_created` without I/O when no matching creation receipt exists, otherwise uses the Supervisor-only recovery-maintenance gate to remove only this delivery's proven-empty directory; unexpected identity/content waits. Normal success never executes abort operations and no absolute-path reopen or check-then-overwrite fallback exists.
12. Every leaf freezes the kind-specific unpredictable sibling name(s), expected absence, exact pre/desired leaf state, parent linkage, and stable opId. Create uses one staging sibling and the probed no-replace primitive; replace uses staging plus quarantine and exchange; delete uses only no-replace quarantine—Linux/macOS flags are mutually exclusive. One leaf is one indivisible Journal/tool-budget envelope: stage/swap where applicable, CAS-preserve actual displaced bytes, commit `PublicationPathProgressItem`, remove the exact transient, fsync the parent, then commit Journal `completed` plus `PublicationPathResultItem`. A separate cleanup attempt is forbidden. Recovery inspects descriptor-relative identities and the durable progress item; desired destination bytes alone never prove completion. Stop/deadline may finish this already-claimed no-new-semantic-effect envelope and zero-charge abort maintenance, but may start no new forward publication.
   Every receipt/evidence edge above decodes only canonical `PublicationProofV1`. Its base must match the delivery Run, plan, live workspace identity, and current signed inspector, and `proofDigest` omits itself under JCS. Descriptor path observations have exact absent-vs-present identity XORs. `PublicationPathProgressItem.destinationEvidenceRef` is the post-swap path observation; `transientObservationRef` replaces any untyped identity handle and is present exactly for the plan-derived sibling still pending cleanup. A completed path uses the same `terminal_receipt` artifact for Journal receipt/evidence and result receipt/evidence; it matches claim/operation/pre/post/transient/preimage/parent/fsync facts exactly. No-I/O `not_created`, retained planned descendants, concrete failed observations, `path_ambiguity` unknowns, transient absence, projection closure, and Git-index equality each use their own closed branch. The Git branch requires two exact canonical `GitIndexSnapshotV1` refs/digests and byte-identical snapshot authority; non-Git forbids them all. The projection's observed path refs and three closure refs must decode to those exact branches and repeat its ordered path/result/source values. An adapter-local JSON receipt, raw `.git/index` blob, inode/time comparison, or bare assertion cannot complete a leaf or terminalize delivery.
13. Successful delivery terminalization and any failed/cancelled delivery after a forward publication claim validate one immutable `DeliveryTerminalProjectionEvidence`; `evidenceDigest` is JCS/SHA-256 with itself omitted. For `selectedBranch='forward_finalize'`, every forward operation has exactly one plan-ordered `completed` result, `abortResultItemRefs` and `unstartedForwardOperationIds` are empty, and `observedSourceRef` equals the verified `DeliveryPlan.desiredSourceRef`; the finalize frontier and RunResult retain that exact evidence ref. For `selectedBranch='abort'`, every claimed/dispatched forward operation has exactly one non-`unknown` terminal result, `unstartedForwardOperationIds` equals the remaining contiguous plan-ordered suffix after the last started forward operation, and every abort operation has exactly one plan-ordered non-`unknown` terminal result. A positively evidenced `failed` result may explain a known retained path; it never proves rollback. Both branches require exhaustive byte-sorted canonical observations for every plan-touched path, all transients absent, no unexplained or ambiguous state, and the Git index unchanged. Failed/cancelled abort terminalization requires `TerminalDetail.deliveryTerminalProjectionEvidenceRef` to reference this artifact and `TerminalDetail.publicationResultItemRefs` to equal its ordered forward-then-abort result refs; `primaryEvidenceRef` remains the immutable winning StopIntent evidence. The observed partial `observedSourceRef` need equal neither the desired result nor the captured base. Merge conflict, approval denial, or cancellation before any forward claim forbids the projection field and uses its ordinary typed terminal evidence. Missing receipts, an `unknown` result, an unmatched path, or incomplete closure evidence remains `waiting(reconciliation)` and is not terminal. The source Run is unchanged.

Reuse existing code:

- Reuse validator cancellation, duration accounting, exception normalization, and `onResult` failure propagation.
- Reuse diff generation, index-baseline checking, atomic file replacement, fsync, and partial-write recovery lessons behind the delivery effect implementation.
- Reuse Session compaction/fork/handoff content as inputs to admitted child context, without copying Session execution lifecycle.

Preserve / do not touch:

- Preserve Workspace Trust before repository verifier/config loading.
- Preserve policy and sandbox as independent layers; verifier success never grants permission.
- Preserve old Session checkpoints and transaction artifacts as historical/read-only migration inputs.
- Do not let the worker write SQLite, CAS metadata, the real workspace, or another child/parent workspace directly.

### Implementation refinement — 2026-09-26

**Implement the smallest complete proof path first.** Start with one root Run,
one immutable candidate, one explicit required verifier and `commitRunResult`
against the actual SQLite/CAS store. Connect it to I1's installed execution
boundary before extending children and delivery. This is an internal dependency
order, not a release without those features. An in-memory repository can test a
pure classification function but cannot prove atomic receipts, budget settlement
or recovery after a verifier process exits.

Keep three narrow responsibilities: plan verification for the frozen candidate,
classify positively established execution evidence, and propose the closed
repair/result/delivery commit. WP03 owns process execution and evidence; WP01
owns the transaction and sole terminal gate; WP04 owns scheduling and waits.
Do not let a verifier adapter or model callback write Run status. Use the same
classification/plan logic for live completion and recovered evidence.

| Observation | Permitted continuation |
| --- | --- |
| At least one required check, all passing against the exact result | Build the complete verification closure and propose success through StateStore |
| No required checks | `completed_unverified`; advisory passes cannot promote it |
| Required assertion fails with quiescent evidence | Bounded model repair within frozen ceilings, then a new candidate and the complete required verifier set |
| Infrastructure fails | Frozen same-digest verifier retry; never model edits to fix infrastructure |
| Source mutation/integrity violation | Integrity stop, including for advisory checks; no valid success receipt |
| Effect/process outcome unresolved | Journal ambiguity and the exact reconciliation wait; neither success nor a guessed failure receipt |
| User/parent stop or deadline races completion | Existing StopIntent precedence and quiescent drain; no opportunistic terminal shortcut |

**Make the proof useful to its consumer.** The result view must distinguish
source candidate, executing verifier identity, required/advisory role, outcome,
and inherited-delivery provenance using the exact existing closure. Retain raw
stdout/stderr as audit artifacts with truncation indicators. Model context reads
only the permitted repair projection; clients must not label a candidate or an
advisory pass as verified success.

The current `cliq-verifier-repair-redaction-v1` projection intentionally supplies
only a verifier identity and exit code. Its practical repair value is unproven.
Add a fixed corpus of repairable type, test and lint failures across supported
repositories, execute the actual projection under the default two-repair budget,
and report solved tasks, additional inspection/model work and exhausted repairs.
Freeze the corpus, selected model, scoring rules and minimum repair success
threshold before execution; include every attempted case in the report. Use the
same verifier set, model and budgets in any diagnostic comparison.
The quality gate requires evidence that the selected release model can recover
useful failures with this projection; passing state transitions alone is
insufficient. If missing diagnostic information prevents repair, propose a
separate bounded, versioned diagnostic projection with source-bound locations,
fixed parser identities, injection/secret tests and compatibility rules. Do not
silently pass raw verifier logs or weaken required checks to make the gate pass.

**Add concurrency and publication by extending that proof.** A repaired candidate
invalidates previous candidate gating; a merged child result requires parent
verification. A delivery Run reuses receipts only through exact-source provenance
and otherwise verifies its new merge. Fault injection must distinguish the
immutable successful agent result from a failed, stopped or ambiguous delivery;
multi-path publication remains non-atomic and preserves displaced bytes.

### Acceptance Criteria

- [ ] A real-store, real-containment required-verifier path produces a durable
  same-source closure/result and survives process death before and after receipt
  publication. No-required-check and advisory-only paths remain unverified.
- [ ] Table-driven classification crosses required/advisory, exact/changed
  source, known/unknown execution and stop races. Infrastructure never triggers
  model repair; unresolved containment never produces a completed receipt.
- [ ] A repair-utility report exercises the actual v1 projection and frozen
  budgets on the selected qualified model. Missing useful diagnostics is an
  explicit product blocker, not a reason to alter the frozen redaction policy
  inside an implementation PR.
- [ ] Child merge, delivery drift and post-exchange crashes preserve exactly
  one allocation settlement, the appropriate verification closure and displaced
  bytes, with the original agent result unchanged.

- [ ] `Run.status='succeeded'`/`terminalReason='verified'` is impossible unless a durable `RunResult` exists and every frozen required verifier has a `passed` receipt for exactly `RunResult.resultSourceRef`.
- [ ] `VerificationClosureV1` decodes as the closed canonical schema, hashes with only `closureDigest` omitted, is the sole legal proof in every verification-closure-bearing delivery/finalize frontier, and exactly aligns its Run/candidate/result/plan plus contiguous unique entry identities with the current `VerifierPlan`.
- [ ] The final verifier/dependency reducer publishes the closure before atomically installing its exact ref in agent finalize or, for `afterPass='delivery_approval'`, the proof-carrying delivery approval frontier. Approval/publish/abort preserve candidate/result/verifier-plan/closure/plan refs byte-for-byte; the last successful forward projection installs delivery finalize with that same closure and its exact projection-evidence ref. Recovery never sees a caller-assembled half-proof or reconstructs a dropped closure.
- [ ] `local/verified` has at least one required entry, every required entry is `passed`, and no consent. `local/unverified` has zero required entries and the exact admitted consent; advisory entries may still pass, fail, or be skipped without changing `completed_unverified(no_required_verifier)` or emitting verified-success.
- [ ] Direct/generic Run mutation cannot create verified or unverified completion. Storage `commitRunResult` re-walks the exact current closure, Journal, receipts, dependency readiness, consent/provenance, and terminal-quiescence state in one transaction; a valid-looking closure or alternate receipt list cannot bypass it.
- [ ] `RunResult.verificationClosureRef` equals the finalize frontier ref; its receipt list, dependency-plan ref, and inherited provenance are exactly closure-derived. Agent results forbid `deliveryTerminalProjectionEvidenceRef`; delivery results require it equal the finalize frontier's forward-finalize evidence. Local closure receipt order follows verifier entries, while inherited verification preserves the validated source result's receipt identities and owning Run ids.
- [ ] Retaining a Run/result/audit record retains the closure and its complete transitive verification/dependency/provenance graph as GC roots. No automatic Run/result/receipt deletion or orphan collection can break an installed proof graph.
- [ ] Suggested checks are visibly attributed and inert until explicit user confirmation; unattended admission never silently promotes package scripts, AGENTS text, skill text, or model output into a required gate.
- [ ] Changing one source byte changes `resultSourceRef` and prevents reuse of all prior candidate receipts as completion gates.
- [ ] A verifier that changes source bytes cannot produce a valid gating receipt.
- [ ] Receipt/Journal validation enforces the exact phase mapping: pass/assertion/source-mutation are `completed`; death-proven infra is `failed` with receipt/error/evidence; cancel/deadline has a stop item/no receipt; unproven death is `unknown`/waiting. Source mutation outranks every termination class, and every gating receipt is uniquely backed by its matching completed verifier request.
- [ ] Every receipt carries whole-containment quiescence evidence; equal-digest mutation requires audited violation evidence. Invalid pass/exit/signal/digest/outcome combinations are rejected at storage.
- [ ] Verifier specs normalize to pinned toolchain/GuestToolchain or workspace-script identity, argv/environment/bounds; unsupported host-only binaries fail admission, and no shell string, secret, undeclared writable path, or direct network reaches a verifier.
- [ ] Repository config can request but never authorize identity read or launch. Identity/read permission is complete before admission; a bounded template may mint exact per-candidate grants, otherwise the candidate waits on typed approval.
- [ ] Normal nonzero verifier exits can enter bounded agentic repair; spawn, timeout, signal, sandbox, missing-tool, and resource failures never enter model repair.
- [ ] Pre-dispatch resource scarcity leaves queued/ineligible without an attempt. Post-claim infra retries only after full death/quiescence proof; Run cancel/deadline stops have precedence and never become verifier infra/retry.
- [ ] Advisory assertion/infrastructure outcomes remain non-gating receipts with no agent repair or terminal-state effect; absence of required checks still yields `completed_unverified`, while advisory source mutation remains fatal.
- [ ] Explicit verifier retries run only against the same digest and stop at the frozen count; no implicit flaky retry exists.
- [ ] Exhausted required-assertion repair ends `failed(verification_failed)` with failed receipts and inspectable candidate artifacts; exhausted infrastructure retry ends `failed(verifier_infrastructure_failed)` with a durable detail artifact.
- [ ] Repair count, model/time/cost/tool budgets, and the required verifier set survive worker and Supervisor recovery without reset.
- [ ] Repair authorization atomically appends diagnostics, increments own/inclusive repair counters once, and advances to agent; crash/retry cannot obtain a free repair or double-count one repair cycle.
- [ ] Every repair diagnostic is a one-to-one, verifier-plan-ordered projection of an identity-matched assertion-failed result/receipt. Raw stdout/stderr remain audit-only; the model sees only the exact bounded, ref-free `VerifierRepairModelContentV1` sentence, and storage rehashes every diagnostic/model-content edge before the atomic repair transition.
- [ ] Every child is a normal durable Run with its own workspace, lease, Checkpoints, Journal, and result; no mutable directory is shared with its parent or sibling.
- [ ] Child admission cannot exceed parent capability, remaining budget, depth, or concurrency ceilings, including after recovery races.
- [ ] Child assembly/policy derivation exactly filters the parent's frozen exposed built-in names/MCP closure, recomputes exposed names/tool retries/credential union, preserves the canonical parent provider/runtime/context/instruction/skill/model-retry identities, and maps every ungranted policy action to `deny`. Child pricing copies only exact `zero_cost` provenance or a still-valid signed `ModelPriceTableV1` using `cliq-price-ceil-v1`; a refreshed registry, credential, instruction, skill, price authority, or broader contract is rejected.
- [ ] `ChildCapabilityGrantV1` binds the complete delegate batch/call/index/op identity, parent assembly/policy, exact granted intersection, child manifest/assembly/policy/verifier/dependency/credential/consent refs, budget, and deadline. `grantCoreDigest` omits both digest fields plus derived consent; `grantDigest` omits only itself. The child RunSpec and atomic admission must name those exact refs and cannot accept model-supplied authority.
- [ ] Canonical `delegate`/`await_children` schemas, stable op/admission ids, ChildHandle/WaitSet/Result/Merge items, verifier/consent modes, and capability/budget intersections are validated end-to-end. All isolated children may execute concurrently; integration alone is serial. Failed/cancelled mutating-only and mixed read-only/failed-mutating wait sets take the zero-successful-patch branch and resolve with all ordered child results; mixed success/failure merges only successful patches and retains every failure in the final result.
- [ ] `ChildAllocationV1` enforces the closed `reserved|child_terminal|settled` XOR. Its mode/deadline/depth/concurrency equal the capability grant and its additive ceiling is exactly the four-counter projection of `grantedBudgets`; mode/status-specific result/patch/diagnostic fields are closed. Forbidden fields, usage above `grantedAdditiveCeilings`, changed terminal bytes, and any transition from immutable `settled` are rejected.
- [ ] Parallel child admissions reserve token/cost/tool/repair allocations and `child_allocations` rows atomically. Child terminal never revision-bumps a running parent; settlement subtracts the full grant from reserved, adds inclusive descendant usage to consumed, records the exact parent revision/owned `ChildResultItem`, and exposes only `granted-inclusive` unused budget exactly once. Success result refs equal the child RunResult, failure detail refs equal the child terminal detail, mutating patches equal its base/result/diff, and only exact ref-free `ChildResultModelContentV1` enters parent context. Cancellation/ambiguity cannot refund early, recovery cannot double-settle, and direct slots derive from child terminal truth.
- [ ] Child `modelTokens` is one fungible total; inclusive input+output usage settles it once and cannot receive separate input/output ceilings.
- [ ] An `await_tool` parent holds no lease and may wake atomically only on the exact wait. `finalize_settlement` prevents a final candidate around outstanding children and returns normalized results to a new agent turn. `stop_settlement` never resumes the model; when it replaces an open await call it closes that exact call with one cancelled ToolResult after settlement. A running parent is never asynchronously mutated by child completion, and recovery cannot strand/double-settle any variant.
- [ ] Mutating child patches merge serially through one Journaled workspace transition whose merge item, post-merge Checkpoint, budget settlement, parent frontier/revision, and event commit atomically; conflicts become structured parent diagnostics and the parent re-verifies the combined digest.
- [ ] Child and delivery drift use pinned `cliq-diff3-v1` exactly: deterministic Myers tie breaks, half-open base ranges, only disjoint/identical text edits, and structured conflicts for every other overlap; no implementation-selected merge or conflict markers.
- [ ] `cliq apply <runId>` creates a delivery Run and never changes the source Run's status or receipt truth.
- [ ] `cliq apply <runId>` rejects any source Run that is not `succeeded`; it never silently materializes a `completed_unverified` result.
- [ ] Real-workspace drift is merged in a private view. If its content-addressed result ref differs, required verifiers rerun against that exact ref before materialization; exact-ref reuse is provenance-gated.
- [ ] `run.apply` descriptor-captures SourceManifest A before admission, stores A only in RunSpec/initial delivery frontier, stores the distinct W_A recovery image in the initial Checkpoint, and installs `delivery:merge` as the first frontier; no delivery Run begins with an absent base/recovery image or a post-admission capture phase. The merge directory is disposable: authoritative state references only immutable A/W_A/result/diff/publication-plan artifacts committed before frontier advance, and recovery restores from W_A without inventing a workspace-effect cut.
- [ ] Publication requires explicit permission and is Journaled; partial or ambiguous publication becomes `waiting(reconciliation)` or an independent delivery failure.
- [ ] Verification receipts retain the executing Run id. Identical-result delivery reuse succeeds only through a validated provenance artifact for the exact same content-addressed ref/spec/source RunResult; digest-only or unrelated historical receipts are rejected, and changed results produce delivery-owned receipts.
- [ ] Delivery permission binds the complete immutable plan. `PublicationOperation` is a strict four-branch union with required/forbidden staging/quarantine fields and exact parent identity/creation linkage; malformed or inferred fields are rejected. A held root dirfd and beneath/no-follow ancestor walk prevent symlink/rename escape; forward mkdir/leaf operations and the separate receipt-derived abort branch are ordered, fsynced, and independently reconcilable. An unexecuted mkdir advances abort with positive absence/no-receipt evidence; only delivery-created proven-empty directories may be removed.
- [ ] Startup probes distinct no-replace/exchange primitives. Frozen staging/quarantine names and `cliq-publish-v1` recover every crash state; desired destination alone is not completion. Each leaf is one indivisible claimed envelope and completes only after actual displaced bytes are CAS-referenced, durable progress exists, the exact transient is absent, and the parent directory is fsynced—there is no separately budgeted cleanup operation.
- [ ] Successful delivery forward/finalize has one plan-ordered `completed` result per forward operation, no abort/unstarted entries, exhaustive path/transient/index evidence, and an observed source projection exactly equal to the verified `DeliveryPlan.desiredSourceRef`.
- [ ] Delivery admission publishes SourceManifest A plus distinct restorable WorkspaceStateManifest W_A; RunSpec/frontier use A and Checkpoint uses W_A. With source B/S, every merge item/plan repeats B/S/A, M is exactly `cliq-diff3-v1(B,S,A)`, plan diff is A-to-M, and candidate/closure/RunResult are exactly base A/result M/diff A-to-M; conflict has B/S/A and no invented M.
- [ ] Failed/cancelled delivery abort terminalization does not require equality with the verified result or captured base. It requires one non-unknown terminal result for every started forward operation and every abort operation, an exact list of never-started forward operations, no transient/unexpected/ambiguous state, and a typed observed partial projection referenced by `TerminalDetail.deliveryTerminalProjectionEvidenceRef`; `primaryEvidenceRef` remains the winning StopIntent evidence and `publicationResultItemRefs` exactly match the projection. Any incomplete or unknown branch remains `waiting(reconciliation)`.
- [ ] Delivery Runs inherit `DependencyPolicy`, derive the exact plan for each merged candidate, and always establish delivery-owned readiness when enabled; only an exact ready Checkpoint already owned by that same delivery Run may avoid redispatch after recovery. They never relabel or reuse source-Run dependency readiness. They have zero model/repair/child budgets, so verifier assertion cannot enter an agent repair frontier.
- [ ] Cancelling a parent requests cancellation of nonterminal children without deleting their audit history; cancelling a delivery Run leaves the source result intact.

### Validation

Automated:

- `npm run build`
- `npm test`
- `node --test --test-concurrency=1 --import tsx "src/run/*.test.ts" "src/verifiers/*.test.ts"`
- `npm run test:fault` with crash points before/after receipt artifact flush, Journal commit, `VerificationClosureV1` publication, finalize-frontier installation, `commitRunResult`, child `reserved -> child_terminal`, parent settlement/wakeup, each forward envelope boundary, abort-result publication, transient cleanup, and delivery terminal projection publication. The matrix proves no partial proof graph, no double child settlement, exact desired-source equality only for forward/finalize, typed partial projection for failed/cancelled abort, and waiting for every unknown/unmatched state.
- `npm run test:e2e` with required verified closure, zero-required plus advisory pass/failure/skip closures, inherited delivery closure, detached assertion repair, verifier infrastructure failure, successful zero-cost/signed-table child assembly, child assembly/policy narrowing, allocation crash recovery, child patch merge/conflict, real-workspace drift, successful delivery equality, known partial delivery followed by complete abort terminalization, and ambiguous delivery scenarios that remain waiting.

Manual:

- Run a detached coding task with a required test command, deliberately introduce one repairable assertion failure, detach, and confirm the same Run repairs and returns a same-digest receipt.
- Repeat with a missing verifier executable and confirm the model does not edit code.
- Run with zero required and one failing advisory verifier; confirm the closure retains the advisory receipt but the Run is `completed_unverified(no_required_verifier)`, never verified.
- Start two mutating children and confirm their private workspaces are distinct and their patches merge serially.
- Crash between child terminal commit and parent settlement, restart, and confirm the exact allocation settles once with no parent budget drift.
- Modify the real workspace while a source Run is detached, then apply it and confirm merge-view re-verification before the permission prompt.
- Inspect the source and delivery Runs independently after a forced publication interruption: confirm an unresolved observation remains waiting, then reconcile to a fully evidenced abort terminal and verify that `TerminalDetail` exposes the exact observed partial projection without claiming desired-result or captured-base equality.

### Risks And Dependencies

- Depends on work package 01 for atomic Run/Journal/artifact commits and durable budget counters.
- Depends on work package 02 for the typed candidate/final boundary and complete tool-call handling.
- Depends on work package 03 for frozen source views, `workspaceStateRef`/`resultSourceRef` separation, private generations, sandboxed verifiers, and brokered materialization.
- Depends on work package 04 for leases, waiting/wakeup, cancellation, recovery, and the delivery command transport.
- Verifier commands can be nondeterministic or hostile. They run sandboxed with bounded output/time and cannot mutate the frozen source view or provide instruction-layer content.
- Patch merge semantics across rename, mode, symlink, submodule, and binary cases are correctness-sensitive; unsupported cases must fail explicitly rather than degrade to text patch heuristics.

Required sequence:

1. Implement artifact schemas and completion/ceiling reducers against actual StateStore/CAS; test pure planning with values and substitute only missing external workspace/process adapters.
2. Add verifier execution and receipt publication on frozen views.
3. Add bounded repair and same-digest terminal gate.
4. Add child admission/wakeup and serial patch merge.
5. Add delivery Run and journaled publication.
6. Extend the already integrated path with child/delivery crash, sandbox, repair-utility and end-to-end gates before Kernel Cut; do not defer real-store integration until the end.

Rollback (only for hard-to-reverse changes):

- Before the Kernel Cut, keep this path unreachable from the default old runner.
- After cutover, rollback uses the RFC migration rollback command; it never converts new Runs back into legacy transactions or Session lifecycle state.
- A failed deployment preserves SQLite/CAS, immutable RunResults, receipts, and source/delivery audit records. Cleanup may remove only unreferenced artifacts and quarantined workspaces.

### Open Questions

None. Changing terminal semantics, receipt digest binding, repair classification, child isolation, or explicit delivery requires a new RFC.

### GitHub Issue Body

```markdown
## Outcome

Implement work package 05 of the Durable Verified Run Kernel: immutable closure-backed Run results, same-digest verifier receipts, bounded assertion repair, deterministically narrowed child Runs, exact child-budget settlement, and explicit delivery Runs.

## Required behavior

- `VerificationClosureV1` is the sole finalize proof; `commitRunResult` revalidates its Journal/dependency/provenance graph and `RunResult.verificationClosureRef` exactly.
- Local verified completion requires at least one required verifier and every required entry passed. No required checks means `completed_unverified`, even when advisory entries exist.
- Assertion failures may repair within frozen budgets and end `failed(verification_failed)` if still unresolved; verifier infrastructure failures never trigger model repair.
- Every child is an ordinary Run whose tool assembly and policy are an exact narrowing of the parent, bound by `ChildCapabilityGrantV1`; parent patch merges are serial and the combined result is reverified. Child pricing copies only exact local-zero-cost or signed-table authority.
- `ChildAllocationV1` enforces `reserved|child_terminal|settled` XOR and moves inclusive descendant use from parent reserved to consumed exactly once.
- `cliq apply <runId>` creates a delivery Run, handles drift in a private merge view, reverifies changed digests, and journals explicit materialization.
- Source Runs, closures, receipts, and their transitive proof graph remain immutable and GC-reachable when delivery fails.

## Validation

Run `npm run build`, `npm test`, `npm run test:fault`, and `npm run test:e2e`. Cover closure publication/commit crashes, zero-required advisory outcomes, digest invalidation, assertion versus infrastructure failure, successful signed-table/local-zero child derivation, allocation settlement recovery, merge conflicts, drift, and ambiguous publication.

## Dependencies

Work packages 01-04. This work is required for the same Kernel Cut and must not extend the legacy Transaction aggregate.
```
