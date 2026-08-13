export type ArtifactRef = string;

export type RunObjectiveV1 = {
  schemaVersion: 1;
  format: 'cliq-run-objective-v1';
  utf8: string;
  byteCount: number;
  objectiveDigest: string;
};

export type RunSpec = {
  schemaVersion: 1;
  operation: 'agent' | 'delivery';
  objectiveRef: ArtifactRef;
  admittedContextRef: ArtifactRef;
  baseWorkspaceManifestRef: ArtifactRef;
  sourceProjectionRef: ArtifactRef;
  assemblyRef: ArtifactRef;
  policyRef: ArtifactRef;
  sandboxProfileRef: ArtifactRef;
  verifierSpecRef: ArtifactRef;
  dependencyPolicyRef?: ArtifactRef;
  unverifiedConsentRef?: ArtifactRef;
  credentialGrantRefs: ArtifactRef[];
  budgets: {
    wallTimeMs: number;
    modelTokens: number;
    costMicros: number;
    toolCalls: number;
    repairAttempts: number;
    childDepth: number;
    childConcurrency: number;
  };
};

export type RunStatus =
  | 'queued'
  | 'running'
  | 'waiting'
  | 'succeeded'
  | 'completed_unverified'
  | 'failed'
  | 'cancelled';

export type RunNextStep = 'agent' | 'tool' | 'verify' | 'finalize' | 'delivery' | null;

export type WaitingReason = 'approval' | 'input' | 'child' | 'reconciliation';

export type BudgetUsage = {
  modelTokens: number;
  costMicros: number;
  toolCalls: number;
  repairAttempts: number;
};

export type RunFrontier =
  | {
      schemaVersion: 1;
      kind: 'agent';
      phase: 'model_turn' | 'context_compaction';
      turnId: string;
      contextItemSeq: number;
      cause: 'initial' | 'tool_batch_complete' | 'repair' | 'child_results' | 'input';
      compactionPlanRef?: ArtifactRef;
    }
  | {
      schemaVersion: 1;
      kind: 'tool';
      batchItemId: string;
      orderedCallIds: string[];
      nextCallIndex: number;
    }
  | {
      schemaVersion: 1;
      kind: 'verify';
      phase: 'dependencies' | 'verifiers';
      candidateItemId: string;
      resultSourceRef: ArtifactRef;
      verifierPlanRef: ArtifactRef;
      dependencyPlanRef?: ArtifactRef;
      nextVerifierIndex: number;
      afterPass: 'finalize' | 'delivery_approval';
    }
  | {
      schemaVersion: 1;
      kind: 'finalize';
      operation: 'agent';
      candidateItemId: string;
      resultSourceRef: ArtifactRef;
      verificationClosureRef: ArtifactRef;
      deliveryTerminalProjectionEvidenceRef?: never;
    }
  | {
      schemaVersion: 1;
      kind: 'finalize';
      operation: 'delivery';
      candidateItemId: string;
      resultSourceRef: ArtifactRef;
      verificationClosureRef: ArtifactRef;
      deliveryTerminalProjectionEvidenceRef: ArtifactRef;
    }
  | {
      schemaVersion: 1;
      kind: 'delivery';
      sourceRunResultRef: ArtifactRef;
      phase: 'merge';
      capturedWorkspaceRef: ArtifactRef;
    }
  | {
      schemaVersion: 1;
      kind: 'delivery';
      sourceRunResultRef: ArtifactRef;
      phase: 'approval';
      candidateItemId: string;
      resultSourceRef: ArtifactRef;
      verifierPlanRef: ArtifactRef;
      verificationClosureRef: ArtifactRef;
      deliveryPlanRef: ArtifactRef;
    }
  | {
      schemaVersion: 1;
      kind: 'delivery';
      sourceRunResultRef: ArtifactRef;
      phase: 'publish' | 'abort_cleanup';
      candidateItemId: string;
      resultSourceRef: ArtifactRef;
      verifierPlanRef: ArtifactRef;
      verificationClosureRef: ArtifactRef;
      deliveryPlanRef: ArtifactRef;
      nextPathOperationIndex: number;
    };

export type RunTerminalReason =
  | 'verified'
  | 'no_required_verifier'
  | 'verification_failed'
  | 'verifier_infrastructure_failed'
  | 'verifier_mutated_source'
  | 'budget_exhausted'
  | 'runtime_failed'
  | 'cancelled_by_user'
  | 'parent_cancelled';

export type Run = {
  id: string;
  sessionId: string;
  parentRunId?: string;
  specRef: ArtifactRef;
  status: RunStatus;
  nextStep: RunNextStep;
  frontierRef?: ArtifactRef;
  waitingReason?: WaitingReason;
  waitingOnRef?: ArtifactRef;
  revision: number;
  leaseEpoch: number;
  activeWorkerLaunchId?: string;
  latestCheckpointId: string;
  budgetReserved: BudgetUsage;
  budgetConsumed: BudgetUsage;
  repairCount: number;
  resultRef?: ArtifactRef;
  terminalReason?: RunTerminalReason;
  terminalDetailRef?: ArtifactRef;
  stopIntentRef?: ArtifactRef;
  cancelRequested: boolean;
  createdAt: string;
  deadlineAt: string;
  updatedAt: string;
};

export type Checkpoint = {
  id: string;
  schemaVersion: 1;
  runId: string;
  basedOnRunRevision: number;
  runItemSeq: number;
  contextManifestRef: ArtifactRef;
  journalSeq: number;
  workspaceStateRef: ArtifactRef;
  createdAt: string;
  reason: 'initial' | 'auto' | 'manual' | 'pre-effect' | 'handoff';
};

export type RunEvent =
  | {
      schemaVersion: 1;
      kind: 'state_changed';
      runId: string;
      eventSeq: number;
      runRevision: number;
      status: RunStatus;
      nextStep: RunNextStep;
      waitingReason?: WaitingReason;
      waitingOnRef?: ArtifactRef;
      frontierRef?: ArtifactRef;
      latestRunItemSeq: number;
      resultRef?: ArtifactRef;
      terminalReason?: RunTerminalReason;
      terminalDetailRef?: ArtifactRef;
      occurredAt: string;
    }
  | {
      schemaVersion: 1;
      kind: 'progress';
      runId: string;
      eventSeq: number;
      observedRunRevision: number;
      phase: 'agent' | 'tool' | 'verify' | 'recovery' | 'delivery';
      opId?: string;
      messageRef?: ArtifactRef;
      completedUnits?: number;
      totalUnits?: number;
      occurredAt: string;
    };

export type RunSnapshotV1 = {
  schemaVersion: 1;
  operation: 'agent' | 'delivery';
  run: Run;
  latestRunItemSeq: number;
};
