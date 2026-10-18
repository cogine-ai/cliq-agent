import type { ArtifactRef } from './types.js';
import type { PolicyDisposition, ToolOperationGrantV1 } from './tool-authorization.js';

/** Closed internal projections of the frozen verifier graph. Attempt identity
 * belongs to its Journal/claim, so retries retain this same request and opId. */
export type VerifierTargetV1 = {
  schemaVersion: 1; format: 'cliq-verifier-target-v1'; runId: string; candidateItemId: string;
  resultSourceRef: ArtifactRef; sourceDigest: string; verifierPlanRef: ArtifactRef; verifierPlanDigest: string;
  verifierSpecRef: ArtifactRef; verifierSpecDigest: string; verifierIndex: number; verifierId: string; verifierVersion: string;
  verifierEntryDigest: string; commandRef: ArtifactRef; commandDigest: string; environmentRef: ArtifactRef; environmentDigest: string;
  required: boolean; maxAttempts: number; targetDigest: string;
};
export type VerifierRequestV1 = {
  schemaVersion: 1; format: 'cliq-verifier-request-v1'; runId: string; opId: string; frontierRef: ArtifactRef; assemblyRef: ArtifactRef;
  candidateItemId: string; verifierPlanRef: ArtifactRef; verifierIndex: number;
  targetRef: ArtifactRef; targetDigest: string; requestDigest: string;
};
export type VerifierPolicyChannelEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-policy-channel-evidence-v1'; principalId: string; runId: string;
  policyRef: ArtifactRef; policyDigest: string; frontierRef: ArtifactRef; opId: string;
  requestRef: ArtifactRef; requestDigest: string; targetRef: ArtifactRef; targetDigest: string; actionClass: 'verifier';
  decisionSource: 'rule' | 'mode_fallthrough'; matchedRuleIds: string[]; effectiveDisposition: PolicyDisposition;
  evaluatedAt: string; evidenceDigest: string; channel: 'named-action';
  namedAction: { kind: 'verifier'; candidateItemId: string; verifierPlanRef: ArtifactRef; verifierId: string }; identityKey: string;
};
export type VerifierOperationGrantV1 = Omit<ToolOperationGrantV1, 'subject' | 'provenance'> & {
  subject: { kind: 'verifier_launch'; candidateItemId: string; resultSourceRef: ArtifactRef; verifierPlanRef: ArtifactRef;
    verifierIndex: number; verifierId: string; verifierSpecDigest: string; required: boolean };
  provenance: Extract<ToolOperationGrantV1['provenance'], { kind: 'policy_snapshot' }> & { actionClass: 'verifier' };
};

export type VerifierPolicyDecisionItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'policy_decision'; subjectKind: 'verifier_launch';
  opId: string; principalId: string; decisionRef: ArtifactRef; policyChannelEvidenceRef: ArtifactRef;
  policyChannelEvidenceDigest: string; createdAt: string; decisionSource: 'direct_policy';
} & (
  | { decision: 'allow'; grantRef: ArtifactRef; denialOutcome?: never }
  | { decision: 'deny'; grantRef?: never; denialOutcome: { kind: 'stop_intent'; subjectKind: 'verifier_launch'; stopIntentRef: ArtifactRef } }
);
