import type { ArtifactRef, ReplayClass } from './types.js';
import type { ToolContractManifestV1 } from './continuation.js';

export type PolicyDisposition = 'allow' | 'ask' | 'deny';
export type PolicyActionClass = 'read' | 'plan' | 'write' | 'exec' | 'mcp' | 'verifier'
  | 'dependency_install_scripts' | 'delivery' | 'child_read_only' | 'child_mutating';

export type PolicyEngineProfileV1 = {
  schemaVersion: 1;
  format: 'cliq-policy-engine-profile-v1';
  evaluator: 'cliq-policy-evaluator-v1';
  permissionGrammar: 'cliq-permission-grammar-v0';
  bashParser: 'cliq-bash-head-parser-v1';
  profileDigest: string;
};

export type RunPolicySnapshotV1 = {
  schemaVersion: 1;
  format: 'cliq-run-policy-v1';
  principalId: string;
  workspaceIdentityDigest: string;
  mode: 'default' | 'accept-edits' | 'plan' | 'yolo';
  engine: { id: 'cliq-policy-v1'; version: string; runtimeBundleRef: ArtifactRef;
    profileEntryId: string; profileRef: ArtifactRef; profileDigest: string };
  toolManifestRef: ArtifactRef;
  toolManifestDigest: string;
  decisions: Record<PolicyActionClass, PolicyDisposition>;
  decisionRules: Array<{
    ruleId: string; order: number;
    source: 'builtin' | 'cli' | 'user_config' | 'session' | 'repository_request';
    sourceRef?: ArtifactRef;
    channel: 'fs-read' | 'fs-write' | 'bash' | 'mcp' | 'plan' | 'plan-progress' | 'named-action';
    pattern: string; disposition: PolicyDisposition;
  }>;
  repositoryRequestRefs: ArtifactRef[];
  policyDigest: string;
  createdAt: string;
};

/** Stable across attempts; physical generation/lease identity is bound by the dispatch claim. */
export type ToolRequestV1 = {
  schemaVersion: 1; format: 'cliq-tool-request-v1';
  runId: string; opId: string; frontierRef: ArtifactRef; assemblyRef: ArtifactRef;
  batchItemId: string; callId: string; callIndex: number; toolName: string;
  inputRef: ArtifactRef; inputDigest: string;
  targetRef: ArtifactRef; targetDigest: string;
  idempotencyKey?: string;
  requestDigest: string;
};

export type ToolTargetV1 = {
  schemaVersion: 1; format: 'cliq-tool-target-v1';
  runId: string; workspaceIdentityRef: ArtifactRef; workspaceIdentityDigest: string;
  toolManifestRef: ArtifactRef; toolManifestDigest: string;
  toolName: string; toolContractDigest: string;
  execution: ToolContractManifestV1['entries'][number]['execution'];
  targetDigest: string;
};

export type ToolPolicyChannel =
  | { channel: 'fs-read' | 'fs-write'; canonicalRootRelativePaths: string[] }
  | { channel: 'bash'; command: { encoding: 'shell_text'; shellText: string } | { encoding: 'argv'; argv: string[] };
      parser: 'cliq-bash-head-parser-v1'; outerCommandHead?: string; nestedBuiltinDenyHeads: string[]; unsafeForAllow: boolean }
  | { channel: 'mcp'; registrationId: string; serverToolName: string }
  | { channel: 'plan' | 'plan-progress'; normalizedPlanIdentity: string };

/** Ordinary-tool branch of the RFC evidence union; named effects have separate owning reducers. */
export type ToolPolicyChannelEvidenceV1 = ToolPolicyChannel & {
  schemaVersion: 1; format: 'cliq-policy-channel-evidence-v1';
  principalId: string; runId: string; policyRef: ArtifactRef; policyDigest: string;
  frontierRef: ArtifactRef; opId: string; requestRef: ArtifactRef; requestDigest: string;
  targetRef: ArtifactRef; targetDigest: string; actionClass: PolicyActionClass;
  decisionSource: 'rule' | 'mode_fallthrough'; matchedRuleIds: string[];
  effectiveDisposition: PolicyDisposition; evaluatedAt: string; evidenceDigest: string;
};

/** Ordinary-tool grants only; interactive provenance is committed by the authenticated control reducer. */
export type ToolOperationGrantV1 = {
  schemaVersion: 1; format: 'cliq-operation-grant-v1'; grantId: string;
  principalId: string; runId: string; policyRef: ArtifactRef; frontierRef: ArtifactRef;
  opId: string; requestRef: ArtifactRef; requestDigest: string; targetRef: ArtifactRef; targetDigest: string;
  subject: { kind: 'tool_call'; batchItemId: string; callId: string; callIndex: number; toolName: string;
    toolContractDigest: string; replayClass: ReplayClass; policySubjectKind: 'ordinary_tool' };
  provenance:
    | { kind: 'policy_snapshot'; actionClass: PolicyActionClass; channelEvidenceRef: ArtifactRef;
        channelEvidenceDigest: string; matchedRuleIds: string[]; effectiveDisposition: 'allow'; decisionDigest: string }
    | { kind: 'user_approval'; waitingSubjectRef: ArtifactRef; decisionRef: ArtifactRef; requestId: string;
        channelEvidenceRef: ArtifactRef; channelEvidenceDigest: string };
  maxDispatchedAttempts: number; issuedAt: string; expiresAt: string; grantDigest: string;
};

export type ToolPolicyDecisionItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'policy_decision'; subjectKind: 'tool_call';
  opId: string; principalId: string; decisionRef: ArtifactRef;
  policyChannelEvidenceRef: ArtifactRef; policyChannelEvidenceDigest: string;
  createdAt: string;
} & (
  | { decisionSource: 'direct_policy'; waitingSubjectRef?: never }
  | { decisionSource: 'interactive_approval'; waitingSubjectRef: ArtifactRef }
) & (
  | { decision: 'allow'; grantRef: ArtifactRef; denialOutcome?: never }
  | { decision: 'deny'; grantRef?: never; denialOutcome: { kind: 'tool_result_denied'; subjectKind: 'tool_call'; outcomeItemRef: ArtifactRef } }
);

/** Other approval subjects belong to their own reducers, never a generic tool-shaped fallback. */
export type ToolApprovalSubject = ToolOperationGrantV1['subject'] & {
  opId: string; target: string; policyChannelEvidenceRef: ArtifactRef; policyChannelEvidenceDigest: string;
};

export type ToolApprovalWait = {
  schemaVersion: 1; kind: 'approval'; runId: string; createdFromRevision: number; createdAt: string;
  frontierRef: ArtifactRef; subject: ToolApprovalSubject;
};

export type ToolApprovalDecisionV1 = {
  schemaVersion: 1; format: 'cliq-approval-decision-v1'; decisionId: string;
  principalId: string; channelIdentityRef: ArtifactRef; channelIdentityDigest: string;
  runId: string; waitingSubjectRef: ArtifactRef; waitingSubjectDigest: string; frontierRef: ArtifactRef;
  subject: ToolApprovalSubject; subjectDigest: string; requestId: string; requestDigest: string;
  expectedRunRevision: number; decision: 'allow' | 'deny'; requestedTtlMs?: number; grantExpiresAt?: string;
  createdAt: string; decisionDigest: string;
};

export type ToolCheckpointProof = {
  workspaceStateRef: ArtifactRef; snapshotEvidenceRef: ArtifactRef; retirementEvidenceRef: ArtifactRef;
};

/** Positive State-owned no-dispatch closure, committed with the replacement wait and reservation refund. */
export type ToolGrantExpiryV1 = {
  schemaVersion: 1; format: 'cliq-tool-grant-expiry-v1'; code: 'TOOL_GRANT_EXPIRED_BEFORE_DISPATCH';
  runId: string; opId: string; attempt: number; preparedJournalSeq: number; grantRef: ArtifactRef;
  waitingSubjectRef: ArtifactRef; observedAt: string;
};

/** Retained adapter observation. State derives model content and settlement; this is never an execution permit. */
export type ToolObservationV1 = {
  schemaVersion: 1; format: 'cliq-tool-observation-v1'; runId: string; opId: string; attempt: number;
  requestRef: ArtifactRef; targetRef: ArtifactRef; grantRef: ArtifactRef; dispatchId: string;
  observedAt: string; observationDigest: string;
  postEffect?: ToolCheckpointProof;
} & (
  | { outcome: 'executed'; content: unknown }
  | { outcome: 'error'; code: 'TOOL_EXECUTION_FAILED' | 'TOOL_PROTOCOL_ERROR' | 'TOOL_RESOURCE_EXHAUSTED';
      diagnosticRef: ArtifactRef; diagnosticDigest: string }
);
