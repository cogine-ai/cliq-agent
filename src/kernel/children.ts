import type { ArtifactRef, BudgetUsage, ChildAllocationTerminal, RunSpec, RunTerminalReason } from './types.js';

export type ChildCapabilityGrantV1 = {
  schemaVersion: 1; format: 'cliq-child-capability-grant-v1'; parentRunId: string;
  delegateBatchItemId: string; delegateCallId: string; delegateCallIndex: number; delegateOpId: string;
  mode: 'read_only' | 'mutating'; parentAssemblyRef: ArtifactRef; parentPolicyRef: ArtifactRef;
  granted: { builtinToolNames: string[]; registeredMcpServerIds: string[]; allowShell: boolean; allowSourceWrite: boolean };
  childToolManifestRef: ArtifactRef; childToolManifestDigest: string; childAssemblyRef: ArtifactRef; childPolicyRef: ArtifactRef;
  verifierMode: 'inherit_parent' | 'none'; childVerifierSpecRef: ArtifactRef; childDependencyPolicyRef?: ArtifactRef;
  childCredentialGrantRefs: ArtifactRef[]; derivedUnverifiedConsentRef?: ArtifactRef;
  grantedBudgets: RunSpec['budgets']; childDeadlineAt: string; grantCoreDigest: string; grantDigest: string;
};
export type DelegateRequest = {
  objective: string; mode: 'read_only' | 'mutating';
  context: { source: 'parent_current' | 'parent_summary'; additionalArtifactRefs: ArtifactRef[] };
  requestedBudgets: RunSpec['budgets']; capabilities: ChildCapabilityGrantV1['granted'];
  verifierMode: 'inherit_parent' | 'none'; allowUnverifiedHelper: boolean;
};
export type AwaitChildrenRequest = { childRunIds: string[] };
export type ChildHandleItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'child_handle'; delegateBatchItemId: string;
  delegateCallId: string; delegateCallIndex: number; delegateOpId: string; childRunId: string;
  admittedSpecRef: ArtifactRef; mode: 'read_only' | 'mutating'; createdAt: string;
};
export type DelegateResult = { schemaVersion: 1; childHandleItemId: string; childRunId: string; admittedSpecRef: ArtifactRef };
export type ChildMergeModelDiagnostic = {
  outcome: 'merged' | 'conflict' | 'resource_limit' | 'denied'; processedCalls: number; chargedCalls: number; appliedCalls: number; unattemptedCalls: number;
  conflicts?: { total: number; truncated: boolean; paths: Array<{ path?: string; reason: string }> };
  limit?: { kind: string; observed: number; limit: number };
};
export type AwaitChildrenResult = { schemaVersion: 1; results: Array<{ childRunId: string; mode: 'read_only' | 'mutating' } & ChildResultModelContentV1['content']>;
  merge?: ChildMergeModelDiagnostic };
export type ChildPatchManifest = {
  schemaVersion: 1; childRunId: string; admittedForkBaseRef: ArtifactRef; resultSourceRef: ArtifactRef; diffRef: ArtifactRef;
  operations: Array<
    | { kind: 'add'; path: string; resultEntryDigest: string }
    | { kind: 'modify' | 'mode'; path: string; expectedEntryDigest: string; resultEntryDigest: string }
    | { kind: 'delete'; path: string; expectedEntryDigest: string }
    | { kind: 'symlink'; path: string; expectedEntryDigest?: string; resultEntryDigest: string }>;
  patchDigest: string;
};
export type ChildResultModelContentV1 = {
  schemaVersion: 1; format: 'cliq-child-result-model-content-v1'; childRunId: string; mode: 'read_only' | 'mutating';
  content: { status: 'succeeded' | 'completed_unverified'; summary: string }
    | { status: 'failed' | 'cancelled'; terminalReason: RunTerminalReason }; contentDigest: string;
};
export type ChildWaitSet = {
  schemaVersion: 1; parentRunId: string;
  purpose: { kind: 'await_tool'; awaitBatchItemId: string; awaitCallId: string; awaitCallIndex: number }
    | { kind: 'finalize_settlement'; modelTurnItemId: string }
    | { kind: 'stop_settlement'; stopIntentRef: ArtifactRef; interruptedWaitRef?: ArtifactRef; awaitOrigin?: { batchItemId: string; callId: string; callIndex: number } };
  childRunIds: string[];
};
export type ChildResultItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'child_result';
  delivery: { kind: 'await_tool'; waitSetRef: ArtifactRef; awaitBatchItemId: string; awaitCallId: string; awaitCallIndex: number }
    | { kind: 'finalize_settlement'; waitSetRef: ArtifactRef; modelTurnItemId: string }
    | { kind: 'stop_settlement'; waitSetRef: ArtifactRef; stopIntentRef: ArtifactRef };
  childRunId: string; inclusiveBudgetUsage: BudgetUsage; modelContentRef: ArtifactRef; modelContentDigest: string; createdAt: string;
} & ChildAllocationTerminal;
export type ChildMergeResultItem = {
  schemaVersion: 1; kind: 'child_merge_result'; itemId: string; runId: string; createdAt: string;
  mergeBatchItemId: string; callId: string; callIndex: number; opId: string; requestRef: ArtifactRef; policyDecisionItemRef: ArtifactRef; resultRef: ArtifactRef;
  outcome: 'merged' | 'conflict' | 'resource_limit' | 'denied'; modelContentRef?: ArtifactRef; modelContentDigest?: string;
};
export type ChildMergeBatchItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'child_merge_batch';
  resume: { kind: 'await_tool'; batchItemId: string; callId: string; callIndex: number }
    | { kind: 'finalize_settlement'; modelTurnItemId: string };
  childResultItemIds: string[];
  calls: Array<{ index: number; callId: string; childRunId: string; patchManifestRef: ArtifactRef; admittedForkBaseRef: ArtifactRef }>;
  createdAt: string;
};

/** Original local Journal request. Its full immutable inputs are the child
 * admission provenance; it is not another mutable admission ledger. */
export type ChildAdmissionRequestV1 = {
  schemaVersion: 1; format: 'cliq-child-admission-request-v1'; parentRunId: string; childRunId: string;
  parentRunSnapshotRef: ArtifactRef; parentChildAllocationsRef: ArtifactRef; parentCheckpointId: string; toolRequestRef: ArtifactRef;
  delegateOperationGrantRef: ArtifactRef; capabilityGrantRef: ArtifactRef; admissionKey: string;
  childSpecRef: ArtifactRef; childWorkspaceStateRef: ArtifactRef; childContextManifestRef: ArtifactRef;
  childFrontierRef: ArtifactRef; preparedAt: string; requestDigest: string;
};
export type ChildAdmissionReceiptV1 = {
  schemaVersion: 1; format: 'cliq-child-admission-receipt-v1'; parentRunId: string; childRunId: string;
  requestRef: ArtifactRef; childSpecRef: ArtifactRef; childHandleItemRef: ArtifactRef;
  inspectorIdentityRef: ArtifactRef; inspectorIdentityDigest: string; preparedAt: string; receiptDigest: string;
};
export type ChildWaitingSubject = {
  schemaVersion: 1; kind: 'child'; runId: string; createdFromRevision: number; createdAt: string; frontierRef: ArtifactRef;
  subject: { kind: 'await_tool'; waitSetRef: ArtifactRef; awaitBatchItemId: string; awaitCallId: string; awaitCallIndex: number }
    | { kind: 'finalize_settlement'; waitSetRef: ArtifactRef; modelTurnItemId: string; observedStopIntentRef?: ArtifactRef }
    | { kind: 'stop_settlement'; waitSetRef: ArtifactRef; stopIntentRef: ArtifactRef; interruptedWaitRef?: ArtifactRef; awaitOrigin?: { batchItemId: string; callId: string; callIndex: number } };
};
