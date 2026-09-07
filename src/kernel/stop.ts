import type { ArtifactRef, BudgetUsage, RunStatus, RunTerminalReason } from './types.js';

type StopIdentity = { schemaVersion: 1; runId: string; createdAt: string };

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
      | { runtimeSubtype: 'context_window_exhausted'; contextManifestRef: ArtifactRef; nextPromptTokens: number;
          triggerThresholdTokens: number; hardPromptTokens: number; protectedTokens: number; sourceInputTokenCap: number }
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
  | { kind: 'context_window_exhausted'; contextManifestRef: ArtifactRef; nextPromptTokens: number; triggerThresholdTokens: number;
      hardPromptTokens: number; protectedTokens: number; sourceInputTokenCap: number; evidenceRef: ArtifactRef }
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
