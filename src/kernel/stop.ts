import type { ArtifactRef, BudgetUsage, RunStatus, RunTerminalReason } from './types.js';

type StopIdentity = { schemaVersion: 1; runId: string; createdAt: string };

/** The token trigger retains its original closed shape. Byte exhaustion is a
 * separate, reproducible pre-dispatch fact, never an arbitrary caught error. */
export type ContextWindowExhaustionCause = {
  contextManifestRef: ArtifactRef; nextPromptTokens: number; triggerThresholdTokens: number;
  hardPromptTokens: number; protectedTokens: number; sourceInputTokenCap: number;
} & (
  | { trigger?: never; modelVisiblePromptDigest?: never; requestBodyBytes?: never; requestBodyLimitBytes?: never }
  | { trigger: 'request_body_bytes'; modelVisiblePromptDigest: ArtifactRef;
      requestBodyBytes: number; requestBodyLimitBytes: 1048576 }
);

/** Implemented model-response branch of the RFC's closed RuntimeFailureEvidenceV1 union. */
export type ModelResponseFailureEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-runtime-failure-evidence-v1'; runId: string;
  frontierRef: ArtifactRef; frontierDigest: string; failingOpId: string;
  inspectorIdentityRef: ArtifactRef; inspectorIdentityDigest: string; observedAt: string; evidenceDigest: string;
  failureKind: 'model_unusable_response'; unusableResponseRef: ArtifactRef; unusableResponseDigest: string;
};

/** Pre-I/O refusal, never a model response, dispatch permission or a retry hint. */
export type CredentialRedemptionFailureEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-runtime-failure-evidence-v1'; runId: string;
  frontierRef: ArtifactRef; frontierDigest: string; failingOpId: string;
  inspectorIdentityRef: ArtifactRef; inspectorIdentityDigest: string; observedAt: string; evidenceDigest: string;
  failureKind: 'credential_redemption_failed'; credentialGrantRef: ArtifactRef; credentialGrantDigest: string;
  endpointRegistrationRef: ArtifactRef; endpointRegistrationDigest: string;
  credentialAuthorityRecordDigest: string; authorityRevision: number; credentialServiceRevision: number;
} & (
  | { failureCode: 'expired' | 'revoked' | 'credential_binding_changed' | 'platform_item_absent' | 'platform_store_unavailable';
      endpointAuthorityRecordDigest?: never; endpointAuthorityRevision?: never }
  | { failureCode: 'endpoint_revoked'; endpointAuthorityRecordDigest: string; endpointAuthorityRevision: number }
);

/** Implemented closed branches; other RFC runtime failures still need their owners. */
export type RuntimeFailureEvidenceV1 = ModelResponseFailureEvidenceV1 | CredentialRedemptionFailureEvidenceV1;

/** RFC stop authority. Individual reducers accept only the branches whose evidence they can prove. */
export type StopIntent = StopIdentity & (
  | { origin: 'kernel_integrity'; targetStatus: 'failed'; reason: 'verifier_mutated_source';
      verifierOpId: string; integrityEvidenceRef: ArtifactRef; integrityEvidenceDigest: string }
  | { origin: 'kernel_integrity'; targetStatus: 'failed'; reason: 'runtime_failed'; source: 'dependency_acquisition';
      dependencyPlanRef: ArtifactRef; failingOpId: string; integrityEvidenceRef: ArtifactRef; integrityEvidenceDigest: string }
  | { origin: 'user_cancel'; targetStatus: 'cancelled'; reason: 'cancelled_by_user'; requestId: string; principalId: string }
  | { origin: 'parent_cancel'; targetStatus: 'cancelled'; reason: 'parent_cancelled'; sourceRunId: string; sourceStopIntentRef: ArtifactRef }
  | { origin: 'deadline'; targetStatus: 'failed'; reason: 'budget_exhausted'; deadlineAt: string }
  | { origin: 'budget'; targetStatus: 'failed'; reason: 'budget_exhausted'; counter: keyof BudgetUsage;
      ceiling: number; consumed: number; reserved: number; required: number }
  | { origin: 'verification'; targetStatus: 'failed'; reason: 'verification_failed' | 'verifier_infrastructure_failed';
      candidateItemId: string; verifierPlanRef: ArtifactRef }
  | ({ origin: 'policy_deny'; targetStatus: 'failed'; opId: string; policyChannelEvidenceRef: ArtifactRef; policyChannelEvidenceDigest: string } & (
      | { subjectKind: 'verifier'; reason: 'verification_failed' }
      | { subjectKind: 'delivery' | 'dependency_install_scripts'; reason: 'runtime_failed' }))
  | ({ origin: 'runtime'; targetStatus: 'failed'; reason: 'runtime_failed' } & (
      | { runtimeSubtype: 'context_compaction_failed'; compactionPlanRef: ArtifactRef; modelOpId: string; attempt: number }
      | ({ runtimeSubtype: 'context_window_exhausted' } & ContextWindowExhaustionCause)
      | { runtimeSubtype: 'delivery_merge_conflict'; deliveryMergeConflictItemRef: ArtifactRef; conflictRef: ArtifactRef }
      | { runtimeSubtype: 'delivery_publication_failed'; deliveryPlanRef: ArtifactRef; sequence: 'forward' | 'abort'; operationId: string }
      | { runtimeSubtype: 'local_inference_unavailable'; activationCycleId: string; serviceId: string; frontierRef: ArtifactRef; failureDetailRef: ArtifactRef }
      | { runtimeSubtype: 'runtime'; failingOpId: string; runtimeFailureRef: ArtifactRef; runtimeFailureDigest: string }))
  | { origin: 'manual_abandon'; targetStatus: 'cancelled'; reason: 'cancelled_by_user'; requestId: string;
      principalId: string; opId: string; attempt: number; attestationRef: ArtifactRef }
);

export type TerminalReasonDetail =
  | { kind: 'verification'; candidateItemId: string; verifierPlanRef: ArtifactRef }
  | { kind: 'verifier_source_mutation'; verifierOpId: string; violationOrDigestEvidenceRef: ArtifactRef; violationOrDigestEvidenceDigest: string }
  | { kind: 'budget_exhausted' | 'cancelled'; stopIntentRef: ArtifactRef }
  | { kind: 'context_compaction_failed'; compactionPlanRef: ArtifactRef; modelOpId: string; attempt: number; evidenceRef: ArtifactRef }
  | ({ kind: 'context_window_exhausted'; evidenceRef: ArtifactRef } & ContextWindowExhaustionCause)
  | { kind: 'dependency_source_integrity'; dependencyPlanRef: ArtifactRef; failingOpId: string; integrityEvidenceRef: ArtifactRef; integrityEvidenceDigest: string }
  | { kind: 'delivery_merge_conflict'; deliveryMergeConflictItemRef: ArtifactRef; conflictRef: ArtifactRef }
  | { kind: 'delivery_publication_failed'; deliveryPlanRef: ArtifactRef; sequence: 'forward' | 'abort'; operationId: string; evidenceRef: ArtifactRef }
  | { kind: 'local_inference_unavailable'; activationCycleId: string; serviceId: string; frontierRef: ArtifactRef; failureDetailRef: ArtifactRef; evidenceRef: ArtifactRef }
  | { kind: 'policy_denied'; subjectKind: 'verifier' | 'delivery' | 'dependency_install_scripts'; opId: string;
      policyChannelEvidenceRef: ArtifactRef; policyChannelEvidenceDigest: string }
  | { kind: 'runtime'; failingOpId: string; runtimeFailureRef: ArtifactRef; runtimeFailureDigest: string };

export type TerminalDetail = {
  schemaVersion: 1; runId: string; reason: Exclude<RunTerminalReason, 'verified' | 'no_required_verifier'>;
  reasonDetail: TerminalReasonDetail; primaryEvidenceRef: ArtifactRef; publicationResultItemRefs: ArtifactRef[];
  deliveryTerminalProjectionEvidenceRef?: ArtifactRef;
  abandonedRetryInvocations: Array<{ opId: string; attempt: number; unknownJournalSeq: number;
    budgetSettlementRef: ArtifactRef; dispatchFenceOrDeathEvidenceRef: ArtifactRef }>;
  abandonedManualInvocation?: { opId: string; attempt: number; abandonedJournalSeq: number; attestationRef: ArtifactRef; toolAbandonedItemRef?: ArtifactRef };
  createdAt: string;
};

export type SessionRunTerminalItem = {
  schemaVersion: 1; format: 'cliq-session-run-terminal-v1'; kind: 'run_terminal'; itemKey: `run-terminal:${string}`;
  runId: string; operation: 'agent' | 'delivery'; admittedSessionItemSeq: number;
  status: Extract<RunStatus, 'succeeded' | 'completed_unverified' | 'failed' | 'cancelled'>; terminalReason: RunTerminalReason;
  resultRef?: ArtifactRef; terminalDetailRef?: ArtifactRef; summaryRef?: ArtifactRef; summaryDigest?: string;
};

export type RunCancel = {
  principalId: string; channelIdentityRef: ArtifactRef; channelIdentityDigest: string;
  requestId: string; expectedRunRevision: number;
};
