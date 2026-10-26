import type { ArtifactRef, ToolContractManifestV1 } from './types.js';
type SupervisorControlExecutionIdentity = Extract<ToolContractManifestV1['entries'][number]['execution'], { kind: 'supervisor_control' }>;

export type ChildAwaitTargetV1 = { schemaVersion: 1; format: 'cliq-child-await-target-v1'; runId: string; assemblyRef: ArtifactRef;
  execution: SupervisorControlExecutionIdentity; targetDigest: string };
export type ChildAwaitRequestV1 = { schemaVersion: 1; format: 'cliq-child-await-request-v1'; runId: string; opId: string;
  sourceCheckpointId: string; parentRunSnapshotRef: ArtifactRef; assemblyRef: ArtifactRef; batchItemId: string; callId: string; callIndex: number;
  inputRef: ArtifactRef; inputDigest: string; waitSetRef: ArtifactRef; targetRef: ArtifactRef; preparedAt: string; requestDigest: string };
export type ChildAwaitReceiptV1 = { schemaVersion: 1; format: 'cliq-child-await-receipt-v1'; runId: string; opId: string; requestRef: ArtifactRef;
  waitSetRef: ArtifactRef; checkpointId: string; inspectorIdentityRef: ArtifactRef; inspectorIdentityDigest: string; preparedAt: string; receiptDigest: string };
