import type { ToolOperationGrantV1, PolicyDisposition, ToolApprovalDecisionV1 } from './tool-authorization.js';

/** Fixed named-action projections. These are retained data, never native
 * publication handles or permission inferred from a verified result. */
export type DeliveryTargetV1 = {
  schemaVersion: 1; format: 'cliq-delivery-target-v1'; runId: string;
  workspaceIdentityRef: string; workspaceIdentityDigest: string;
  deliveryPlanRef: string; deliveryPlanDigest: string; operationSetDigest: string; targetDigest: string;
};
export type DeliveryRequestV1 = {
  schemaVersion: 1; format: 'cliq-delivery-request-v1'; runId: string; opId: string;
  assemblyRef: string; frontierRef: string; targetRef: string; targetDigest: string; requestDigest: string;
};
export type DeliveryPolicyChannelEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-policy-channel-evidence-v1'; principalId: string; runId: string;
  policyRef: string; policyDigest: string; frontierRef: string; opId: string;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string;
  actionClass: 'delivery'; decisionSource: 'rule' | 'mode_fallthrough'; matchedRuleIds: string[];
  effectiveDisposition: PolicyDisposition; evaluatedAt: string; evidenceDigest: string;
  channel: 'named-action'; namedAction: { kind: 'delivery'; deliveryPlanRef: string; operationSetDigest: string }; identityKey: string;
};
export type DeliveryPlanGrantV1 = Omit<ToolOperationGrantV1, 'subject'> & {
  subject: { kind: 'delivery_plan'; deliveryPlanRef: string; deliveryPlanDigest: string; operationSetDigest: string };
};
export type PublicationPathGrantV1 = Omit<ToolOperationGrantV1, 'subject' | 'provenance'> & {
  subject: { kind: 'publication_path'; deliveryPlanRef: string; sequence: 'forward';
    operationIndex: number; operationId: string; operationDigest: string };
  provenance: { kind: 'delivery_plan_derivation'; planAuthorizationGrantRef: string; deliveryDecisionItemId: string };
};
/** Post-stop maintenance is not a renewable productive grant. The actual
 * owner must prove the original Stop, creator, prefix and empty directory;
 * these immutable fields alone authorize no native operation. */
export type PublicationMaintenanceAuthorityV1 = {
  schemaVersion: 1; format: 'cliq-publication-maintenance-authority-v1'; authorityId: string;
  principalId: string; runId: string; policyRef: string; frontierRef: string; opId: string;
  requestRef: string; requestDigest: string; targetRef: string; targetDigest: string;
  subject: { kind: 'publication_abort_maintenance'; deliveryPlanRef: string; operationIndex: number;
    operationId: string; operationDigest: string; createdByOperationId: string;
    creatorReceiptRef: string; stopIntentRef: string };
  provenance: { kind: 'delivery_plan_maintenance'; planAuthorizationGrantRef: string; deliveryDecisionItemId: string };
  maxDispatchedAttempts: 1; issuedAt: string; authorityDigest: string;
};
export type PublicationPathRequestV1 = {
  schemaVersion: 1; format: 'cliq-publication-path-request-v1'; runId: string; opId: string;
  assemblyRef: string; frontierRef: string; deliveryPlanRef: string; sequence: 'forward' | 'abort';
  operationIndex: number; operationId: string; operationDigest: string;
  targetRef: string; targetDigest: string; requestDigest: string;
};
export type DeliveryApprovalSubject = DeliveryPlanGrantV1['subject'] & {
  opId: string; policyChannelEvidenceRef: string; policyChannelEvidenceDigest: string;
};
export type DeliveryApprovalWait = {
  schemaVersion: 1; kind: 'approval'; runId: string; createdFromRevision: number; createdAt: string;
  frontierRef: string; subject: DeliveryApprovalSubject;
};
export type DeliveryApprovalDecisionV1 = Omit<ToolApprovalDecisionV1, 'subject'> & { subject: DeliveryApprovalSubject };

export type DeliveryPolicyDecisionItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'policy_decision'; subjectKind: 'delivery_plan';
  opId: string; principalId: string; decisionRef: string; policyChannelEvidenceRef: string;
  policyChannelEvidenceDigest: string; createdAt: string;
} & (
  | { decisionSource: 'direct_policy'; waitingSubjectRef?: never }
  | { decisionSource: 'interactive_approval'; waitingSubjectRef: string }
) & (
  | { decision: 'allow'; grantRef: string; denialOutcome?: never }
  | { decision: 'deny'; grantRef?: never; denialOutcome: { kind: 'delivery_stopped'; subjectKind: 'delivery_plan'; stopIntentRef: string } }
);
