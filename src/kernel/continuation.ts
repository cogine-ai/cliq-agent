import type { ChildHandleItem, ChildResultItem, ChildMergeBatchItem, ChildMergeResultItem } from './children.js';
import type { AgentToolCall } from '../protocol/agent-ir.js';
import type { ArtifactRef, ReplayClass } from './types.js';
import type { ToolPolicyDecisionItem } from './tool-authorization.js';
import type { InputRequestItem, UserInputItem } from './user-input.js';
import type { FinalCandidateItem } from './result.js';
import type { DeliveryMergeItem, DeliveryMergeConflictItem, DeliveryDecisionItem } from './delivery.js';
import type { PublicationPathProgressItem, PublicationPathResultItem, PublicationLateObservationItem } from './publication.js';
import type { VerifierPolicyDecisionItem } from './verifier-invocation.js';
import type { DeliveryPolicyDecisionItem } from './delivery-invocation.js';
import type { VerifierResultItem, RepairDiagnosticItem, VerifierStopItem } from './verifier.js';

export type BuiltinScriptExecutionV1 = {
  kind: 'builtin_script'; adapterId: 'builtin_tools'; adapterVersion: '1'; adapterCodeDigest: string;
  guestToolchainManifestRef: ArtifactRef; guestToolchainManifestDigest: string;
  toolId: 'node'; executionPath: '/usr/bin/node'; executableDigest: string;
};
export type SupervisorControlExecutionV1 = {
  kind: 'supervisor_control'; handlerId: 'request_input' | 'await_children'; supervisorEntryId: string;
  supervisorEntryVersion: string; supervisorExecutableDigest: string;
};

export type SupervisorOperationExecutionV1 = {
  kind: 'supervisor_operation'; handlerId: 'delegate' | 'child_merge' | 'skill_resource'; supervisorEntryId: string;
  supervisorEntryVersion: string; supervisorExecutableDigest: string;
};

export type ToolContractManifestV1 = {
  schemaVersion: 1;
  format: 'cliq-tool-contracts-v1';
  entries: Array<{
    name: string;
    version: string;
    description: string;
    access: 'read' | 'write' | 'exec' | 'plan' | 'control';
    inputSchemaRef: ArtifactRef;
    inputSchemaDigest: string;
    outputSchemaRef?: ArtifactRef;
    outputSchemaDigest?: string;
  } & (
    | { replayClass: 'manual' | 'retry'; execution: {
        kind: 'builtin'; adapterId: string; adapterVersion: string; adapterCodeDigest: string;
      } | BuiltinScriptExecutionV1 }
    | { replayClass: 'manual'; execution: SupervisorControlExecutionV1 }
    | { replayClass: 'retry'; execution: SupervisorOperationExecutionV1 }
    | { replayClass: ReplayClass; execution: {
        kind: 'mcp'; registrationId: string; registryRevisionRef: ArtifactRef;
        registryManifestDigest: string; serverToolName: string; toolContractDigest: string;
      } }
  )>;
  manifestDigest: string;
};

type ItemIdentity = { schemaVersion: 1; itemId: string; runId: string; createdAt: string };

export type ModelTurnItem = ItemIdentity & {
  kind: 'model_turn';
  modelOpId: string;
  modelAttempt: number;
  modelTurnRef: ArtifactRef;
  stopReason: 'end' | 'tool_calls' | 'cancelled';
  textRef: ArtifactRef;
  abortStopIntentRef?: ArtifactRef;
};

export type ToolBatchItem = ItemIdentity & {
  kind: 'assistant_tool_batch';
  modelOpId: string;
  modelAttempt: number;
  modelTurnRef: ArtifactRef;
  textRef: ArtifactRef;
  calls: AgentToolCall[];
};

export type ToolResultItem = ItemIdentity & {
  kind: 'tool_result';
  batchItemId: string;
  callId: string;
  index: number;
  opId?: string;
  outcome: 'executed' | 'denied' | 'error' | 'batch_not_executed' | 'cancelled';
  resultRef: ArtifactRef;
};

export type ToolResultModelContentV1 = {
  schemaVersion: 1;
  format: 'cliq-tool-result-model-content-v1';
  callId: string;
  index: number;
  toolName: string;
  outcome: ToolResultItem['outcome'];
  content: unknown;
  contentDigest: string;
};

export type ToolResultPayloadV1 = {
  schemaVersion: 1;
  format: 'cliq-tool-result-payload-v1';
  runId: string;
  batchItemId: string;
  callId: string;
  index: number;
  toolName: string;
  modelContentRef: ArtifactRef;
  modelContentDigest: string;
  payloadDigest: string;
} & (
  | { outcome: 'executed'; source: 'invocation'; opId: string; attempt: number; journalResultRef: ArtifactRef;
      journalResultDigest: string; outputSchemaRef?: ArtifactRef; outputSchemaDigest?: string }
  | { outcome: 'executed'; source: 'user_input'; inputItemRef: ArtifactRef; inputRef: ArtifactRef; inputDigest: string }
  | { outcome: 'executed'; source: 'child_admission'; opId: string; journalResultRef: ArtifactRef; journalResultDigest: string; childHandleItemRef: ArtifactRef }
  | { outcome: 'executed'; source: 'child_admission_refusal'; opId: string; journalResultRef: ArtifactRef; journalResultDigest: string }
  | { outcome: 'executed'; source: 'skill_resource'; opId: string; journalResultRef: ArtifactRef; journalResultDigest: string }
  | { outcome: 'executed'; source: 'child_results'; waitSetRef: ArtifactRef; childResultItemRefs: ArtifactRef[]; mergeResultItemRefs?: ArtifactRef[] }
  | { outcome: 'denied'; code: 'TOOL_CALL_DENIED'; denial:
      | { source: 'policy'; policyRef: ArtifactRef; decisionDigest: string }
      | { source: 'user'; approvalDecisionRef: ArtifactRef; approvalDecisionDigest: string } }
  | { outcome: 'error'; code: 'TOOL_NOT_FOUND' | 'TOOL_INPUT_INVALID' | 'TOOL_AUTHORITY_UNAVAILABLE'
      | 'TOOL_EXECUTION_FAILED' | 'TOOL_PROTOCOL_ERROR' | 'TOOL_RESOURCE_EXHAUSTED';
      diagnosticRef: ArtifactRef; diagnosticDigest: string;
      opId?: string; attempt?: number; journalErrorRef?: ArtifactRef; journalErrorDigest?: string }
  | { outcome: 'batch_not_executed'; code: 'BATCH_REJECTED_BEFORE_DISPATCH'; invalidCallIds: string[] }
  | { outcome: 'cancelled'; cancellationKind: 'undispatched_stop' | 'await_children_stop';
      stopIntentRef: ArtifactRef; noticeRef: ArtifactRef; noticeDigest: string }
);

export type RunContextCompactionPlan = {
  schemaVersion: 1;
  runId: string;
  sourceContextManifestRef: ArtifactRef;
  compactFromItemSeq: number;
  compactThroughItemSeq: number;
  preservedItemIds: string[];
  sourceItemsDigest: string;
  summaryFormat: 'cliq-context-summary-markdown-v1';
  maxSummaryBytes: number;
  contextLimitTokens: number;
  reservedNormalOutputTokens: number;
  triggerThresholdTokens: number;
  protectedRecentTokens: number;
  summaryTokenCap: number;
  promptEnvelopeRef: ArtifactRef;
  promptEnvelopeDigest: string;
  promptOverheadTokens: number;
  sourceInputTokenCap: number;
  sourceProjectedTokens: number;
  createdAt: string;
};

export type RunContextCompactionItem = ItemIdentity & {
  kind: 'context_compaction';
  planRef: ArtifactRef;
  modelOpId: string;
  modelAttempt: number;
  summaryRef: ArtifactRef;
  summaryDigest: string;
  coveredFromItemSeq: number;
  coveredThroughItemSeq: number;
  sourceItemsDigest: string;
};

export type ContinuationItem = import('./dependency.js').DependencyReadyItem | import('./dependency.js').DependencyFailureItem | import('./dependency-script-approval.js').DependencyScriptDecisionItem | import('./child-merge.js').ChildMergePolicyDecisionItem | ChildHandleItem | ChildResultItem | ChildMergeBatchItem | ChildMergeResultItem | ModelTurnItem | ToolBatchItem | ToolResultItem | RunContextCompactionItem | ToolPolicyDecisionItem | InputRequestItem | UserInputItem | FinalCandidateItem |
  VerifierPolicyDecisionItem | VerifierResultItem | RepairDiagnosticItem | VerifierStopItem |
  DeliveryMergeItem | DeliveryMergeConflictItem | DeliveryDecisionItem | DeliveryPolicyDecisionItem | PublicationPathProgressItem | PublicationPathResultItem | PublicationLateObservationItem;
