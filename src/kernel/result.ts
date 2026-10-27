import type { ArtifactRef, WorkspaceEntry } from './types.js';

export type WorkspaceDiffOperationV1 =
  | { path: string; kind: 'add'; after: WorkspaceEntry }
  | { path: string; kind: 'delete'; before: WorkspaceEntry }
  | { path: string; kind: 'modify'; before: WorkspaceEntry; after: WorkspaceEntry };

export type WorkspaceDiffV1 = {
  schemaVersion: 1;
  format: 'cliq-workspace-diff-v1';
  baseSourceRef: ArtifactRef;
  resultSourceRef: ArtifactRef;
  operations: WorkspaceDiffOperationV1[];
  diffDigest: string;
};

export type FinalCandidateItemBase = {
  schemaVersion: 1;
  itemId: string;
  runId: string;
  kind: 'final_candidate';
  producingItemId: string;
  baseSourceRef: ArtifactRef;
  resultSourceRef: ArtifactRef;
  diffRef: ArtifactRef;
  summaryRef: ArtifactRef;
  sourceDigest: string;
  diffDigest: string;
  createdAt: string;
};

export type FinalCandidateItem = FinalCandidateItemBase & (
  | { operation: 'agent'; producingOpId: string }
  | { operation: 'delivery'; producingOpId?: never }
);

export type VerifierPlan = {
  schemaVersion: 1;
  runId: string;
  candidateItemId: string;
  resultSourceRef: ArtifactRef;
  verifierSpecRef: ArtifactRef;
  verifierSpecDigest: string;
  dependencyPlanRef?: ArtifactRef;
  entries: Array<{
    index: number;
    verifierId: string;
    verifierSpecDigest: string;
    verifierEntryDigest: string;
    commandRef: ArtifactRef;
    commandDigest: string;
    environmentRef: ArtifactRef;
    environmentDigest: string;
    required: boolean;
    maxAttempts: number;
  }>;
  planDigest: string;
};

export type InheritedVerificationProvenanceV1 = {
  schemaVersion: 1;
  format: 'cliq-inherited-verification-provenance-v1';
  deliveryRunId: string;
  sourceRunId: string;
  sourceRunResultRef: ArtifactRef;
  sourceRunResultDigest: string;
  sourceVerificationClosureRef: ArtifactRef;
  sourceVerificationClosureDigest: string;
  resultSourceRef: ArtifactRef;
  verifierSpecRef: ArtifactRef;
  verifierSpecDigest: string;
  verificationReceiptRefs: ArtifactRef[];
  verificationReceiptDigests: string[];
  createdAt: string;
  provenanceDigest: string;
};

export type VerificationClosureV1 = {
  schemaVersion: 1;
  format: 'cliq-verification-closure-v1';
  runId: string;
  candidateItemId: string;
  resultSourceRef: ArtifactRef;
  verifierPlanRef: ArtifactRef;
  dependency: { kind: 'none' } | {
    kind: 'inherited_verification'; dependencyPolicyRef: ArtifactRef; dependencyPlanRef: ArtifactRef;
    sourceRunId: string; sourceRunResultRef: ArtifactRef; sourceVerificationClosureRef: ArtifactRef; inheritedProvenanceRef: ArtifactRef;
  } | ({
    kind: 'ready'; dependencyPolicyRef: ArtifactRef; dependencyPlanRef: ArtifactRef;
    dependencyReadyItemId: string; readyCheckpointId: string;
  } & (
    | { origin: 'acquired'; acquisitionOpId: string; acquisitionAttempt: number; completedJournalSeq: number }
    | { origin: 'inherited_parent_ready'; parentRunId: string; parentReadyItemRef: ArtifactRef; childAdmissionRequestRef: ArtifactRef }
  ));
  verification: {
    kind: 'local'; outcome: 'verified' | 'unverified'; unverifiedConsentRef?: ArtifactRef;
    entries: Array<{
      verifierIndex: number; verifierId: string; verifierSpecDigest: string; verifierEntryDigest: string; required: boolean;
      disposition: {
        kind: 'passed'; verifierResultItemId: string; opId: string; attempt: number; completedJournalSeq: number; receiptRef: ArtifactRef;
      } | {
        kind: 'advisory_nonpassing'; outcome: 'assertion_failed' | 'infra_failed'; verifierResultItemId: string;
        opId: string; attempt: number; terminalJournalSeq: number; receiptRef: ArtifactRef;
      } | { kind: 'advisory_skipped'; verifierSkipItemId: string; decisionRef: ArtifactRef };
    }>;
  } | {
    kind: 'inherited_verified'; sourceRunId: string; sourceRunResultRef: ArtifactRef;
    sourceVerificationClosureRef: ArtifactRef; inheritedProvenanceRef: ArtifactRef;
  };
  closureDigest: string;
  createdAt: string;
};

export type RunResult = {
  schemaVersion: 1;
  runId: string;
  baseSourceRef: ArtifactRef;
  resultSourceRef: ArtifactRef;
  diffRef: ArtifactRef;
  dependencyPlanRef?: ArtifactRef;
  verificationClosureRef: ArtifactRef;
  deliveryTerminalProjectionEvidenceRef?: ArtifactRef;
  verificationReceiptRefs: ArtifactRef[];
  verificationProvenanceRef?: ArtifactRef;
  summaryRef: ArtifactRef;
  createdAt: string;
};
