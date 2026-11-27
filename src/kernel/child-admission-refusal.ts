import type { ArtifactRef, BudgetUsage } from './types.js';
export type ChildAdmissionRefusalReason = 'deadline' | 'depth' | 'concurrency' | 'modelTokens' | 'costMicros' | 'toolCalls' | 'repairAttempts';
export type ChildAdmissionRefusalRequestV1 = { schemaVersion: 1; format: 'cliq-child-admission-refusal-request-v1'; runId: string; opId: string;
  parentRunSnapshotRef: ArtifactRef; parentChildAllocationsRef: ArtifactRef; sourceCheckpointId: string; toolRequestRef: ArtifactRef;
  delegateOperationGrantRef: ArtifactRef; continuationFloor: BudgetUsage; reason: ChildAdmissionRefusalReason; preparedAt: string; requestDigest: string };
export type ChildAdmissionRefusalReceiptV1 = { schemaVersion: 1; format: 'cliq-child-admission-refusal-v1'; runId: string; opId: string;
  requestRef: ArtifactRef; reason: ChildAdmissionRefusalReason; inspectorIdentityRef: ArtifactRef; inspectorIdentityDigest: string;
  preparedAt: string; receiptDigest: string };
