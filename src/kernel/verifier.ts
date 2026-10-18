import type { ArtifactRef } from './types.js';

export type VerifierExecutableIdentityV1 =
  | { kind: 'guest_toolchain'; guestToolchainManifestRef: ArtifactRef; guestToolchainManifestDigest: string;
      toolId: string; executionPath: string; executableDigest: string; abiFingerprint: string }
  | { kind: 'workspace_script'; workspaceIdentityDigest: string; canonicalRootRelativePath: string; scriptDigest: string;
      interpreterIdentityRef: ArtifactRef; interpreterIdentityDigest: string };

export type VerifierCommandV1 = {
  schemaVersion: 1; format: 'cliq-verifier-command-v1'; verifierId: string; verifierVersion: string;
  executable: VerifierExecutableIdentityV1; argv: Array<{ kind: 'non_secret_literal'; value: string }>;
  cwd: string; commandDigest: string;
};

export type VerifierEnvironmentV1 = {
  schemaVersion: 1; format: 'cliq-verifier-environment-v1'; verifierId: string; verifierVersion: string;
  commandRef: ArtifactRef; commandDigest: string; variables: Array<{ name: string; value: { kind: 'non_secret_literal'; value: string } }>;
  writableEphemeralPaths: string[]; sourceProjectionRef: ArtifactRef; sourceAccess: 'read_only'; networkAccess: 'denied';
  sandboxProfile: 'cliq-verifier-readonly-v1'; runtimeBundleRef: ArtifactRef; runtimeBundleManifestDigest: string;
  guestToolchainManifestRef?: ArtifactRef; guestToolchainManifestDigest?: string; environmentDigest: string;
};

export type VerificationReceipt = {
  schemaVersion: 1; format: 'cliq-verification-receipt-v1'; runId: string; verifierId: string; verifierVersion: string; attempt: number;
  outcome: 'passed' | 'assertion_failed' | 'infra_failed' | 'source_mutation'; reasonCode?: string;
  resultSourceRef: ArtifactRef; sourceDigestBefore: string; sourceDigestAfter: string;
  commandRef: ArtifactRef; commandDigest: string; environmentRef: ArtifactRef; environmentDigest: string;
  startedAt: string; endedAt: string; durationMs: number;
  /** controller_stop is fatal-source-integrity or typed Stop evidence only,
   * never an ordinary pass/assertion/infrastructure receipt. */
  terminationReason: 'exit' | 'timeout' | 'signal' | 'spawn_error' | 'sandbox_denial' | 'resource_failure' | 'controller_stop';
  exitCode?: number; signal?: string; stdoutRef: ArtifactRef; stderrRef: ArtifactRef; stdoutTruncated: boolean; stderrTruncated: boolean;
  leaseEpoch: number; containmentEvidenceRef: ArtifactRef; violationEvidenceRef?: ArtifactRef; violationEvidenceDigest?: string; receiptDigest: string;
};

export type VerifierResultItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'verifier_result'; candidateItemId: string; verifierPlanRef: ArtifactRef;
  verifierIndex: number; verifierId: string; opId: string; attempt: number; outcome: VerificationReceipt['outcome']; receiptRef: ArtifactRef; createdAt: string;
};

/** A Run cancellation/deadline retains the real measurement and retirement,
 * not an infrastructure receipt or permission to retry the claimed attempt. */
export type VerifierStopEvidence = Omit<VerificationReceipt,
  'format' | 'outcome' | 'receiptDigest' | 'containmentEvidenceRef' | 'violationEvidenceRef' | 'violationEvidenceDigest'> & {
  format: 'cliq-verifier-stop-evidence-v1'; stopIntentRef: ArtifactRef; retirementRef: ArtifactRef; evidenceDigest: string;
};
export type VerifierStopItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'verifier_stop'; candidateItemId: string; verifierPlanRef: ArtifactRef;
  verifierIndex: number; verifierId: string; opId: string; attempt: number;
  stopIntent: 'cancelled_by_user' | 'parent_cancelled' | 'budget_exhausted'; stopIntentRef: ArtifactRef;
  containmentEvidenceRef: ArtifactRef; createdAt: string;
};

export type VerifierRepairModelContentV1 = {
  schemaVersion: 1; format: 'cliq-verifier-repair-model-content-v1'; verifierId: string; outcome: 'assertion_failed'; message: string; contentDigest: string;
};

export type VerifierRepairDiagnosticV1 = {
  schemaVersion: 1; format: 'cliq-verifier-repair-diagnostic-v1'; runId: string; candidateItemId: string; verifierPlanRef: ArtifactRef;
  verifierId: string; receiptRef: ArtifactRef; receiptDigest: string; stdoutRef: ArtifactRef; stderrRef: ArtifactRef;
  redactionAlgorithm: 'cliq-verifier-repair-redaction-v1'; modelContentRef: ArtifactRef; modelContentDigest: string; diagnosticDigest: string;
};

export type RepairDiagnosticEntryV1 = {
  verifierId: string; diagnosticRef: ArtifactRef; diagnosticDigest: string; modelContentRef: ArtifactRef; modelContentDigest: string;
};

export type RepairDiagnosticItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'repair_diagnostic'; candidateItemId: string; verifierPlanRef: ArtifactRef;
  failedVerifierResultItemIds: string[]; diagnostics: RepairDiagnosticEntryV1[]; repairOrdinal: number; createdAt: string;
};
