import type { AgentToolCall } from '../protocol/agent-ir.js';
import type { ArtifactRef, ReplayClass } from './types.js';

export type ToolContractManifestV1 = {
  schemaVersion: 1;
  format: 'cliq-tool-contracts-v1';
  entries: Array<{
    name: string;
    version: string;
    description: string;
    access: 'read' | 'write' | 'exec' | 'plan';
    inputSchemaRef: ArtifactRef;
    inputSchemaDigest: string;
    outputSchemaRef?: ArtifactRef;
    outputSchemaDigest?: string;
  } & (
    | { replayClass: 'manual' | 'retry'; execution: {
        kind: 'builtin'; adapterId: string; adapterVersion: string; adapterCodeDigest: string;
      } }
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
  | { outcome: 'executed'; opId: string; attempt: number; journalResultRef: ArtifactRef;
      journalResultDigest: string; outputSchemaRef?: ArtifactRef; outputSchemaDigest?: string }
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

export type ContinuationItem = ModelTurnItem | ToolBatchItem | ToolResultItem | RunContextCompactionItem;
