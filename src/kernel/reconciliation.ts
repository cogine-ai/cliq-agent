import type { ArtifactRef } from './types.js';

// Canonical RFC recovery artifacts. Their retained shape is not a native observation.
type WorkerRecoveryEvidenceBaseV1 = {
  schemaVersion: 1;
  format: 'cliq-worker-recovery-evidence-v1';
  runId: string;
  waitingSubjectRef: ArtifactRef;
  oldWorkerLaunchId: string;
  oldLeaseEpoch: number;
  oldWorkerIdentityDigest: string;
  processContainmentRef: ArtifactRef;
  containmentDeathEvidenceRef: ArtifactRef;
  containmentDeathEvidenceDigest: string;
  workspaceGenerationRef: ArtifactRef;
  generationTreeDigest: string;
  inspectorIdentityRef: ArtifactRef;
  inspectorIdentityDigest: string;
  observedAt: string;
  evidenceDigest: string;
};
export type WorkerRecoveryEvidenceV1 = WorkerRecoveryEvidenceBaseV1 & (
  | { generationDisposition: 'quarantined'; restoredCheckpointId?: never; restoredWorkspaceStateRef?: never; replacementWorkspaceGenerationRef?: never }
  | { generationDisposition: 'restored_from_checkpoint'; restoredCheckpointId: string; restoredWorkspaceStateRef: ArtifactRef; replacementWorkspaceGenerationRef: ArtifactRef }
);

export type ReconciliationProbeDispatchV1 = {
  schemaVersion: 1;
  format: 'cliq-reconciliation-probe-dispatch-v1';
  runId: string;
  reconciliationSubjectDigest: string;
  probeKind: 'automatic' | 'user_requested';
  probeOrdinal: number;
  probeNonceDigest: string;
  probeStartedAt: string;
  probeDeadlineAt: string;
  owningSupervisorInstanceId: string;
  dispatchDigest: string;
} & (
  | { subjectKind: 'mcp_recovery'; brokerDispatchId: string; brokerRequestDigest: string; brokerTargetDigest: string; brokerFenceTokenDigest: string }
  | { subjectKind: 'publication'; inspectorTaskId: string; inspectionTargetDigest: string }
  | { subjectKind: 'worker_recovery'; inspectorTaskId: string; inspectionTargetDigest: string }
);

export type ReconciliationInspectorTaskClosureV1 =
  | { closureKind: 'cancelled_and_joined'; inspectorTaskCancelledAndJoined: true; ownerDeathAcquisitionEvidenceRef?: never; ownerDeathAcquisitionEvidenceDigest?: never }
  | { closureKind: 'owner_process_dead'; ownerDeathAcquisitionEvidenceRef: ArtifactRef; ownerDeathAcquisitionEvidenceDigest: string; inspectorTaskCancelledAndJoined?: never };

export type ReconciliationProbeTimeoutClosureV1 = {
  schemaVersion: 1;
  format: 'cliq-reconciliation-probe-timeout-closure-v1';
  runId: string;
  waitingSubjectRef: ArtifactRef;
  probeKind: 'automatic' | 'user_requested';
  probeOrdinal: number;
  probeNonceDigest: string;
  probeDispatchDigest: string;
  probeDeadlineAt: string;
  inspectorIdentityRef: ArtifactRef;
  inspectorIdentityDigest: string;
  closedAt: string;
  closureDigest: string;
} & (
  | { subjectKind: 'mcp_recovery'; brokerDispatchId: string; brokerTargetDigest: string; brokerFenceTokenDigest: string; noActiveReleaseForNonce: true }
  | { subjectKind: 'publication'; deliveryPlanRef: ArtifactRef; pathOperationId: string; attempt: number; inspectorTaskId: string; taskClosure: ReconciliationInspectorTaskClosureV1 }
  | { subjectKind: 'worker_recovery'; oldWorkerLaunchId: string; processContainmentRef: ArtifactRef; inspectorTaskId: string; taskClosure: ReconciliationInspectorTaskClosureV1 }
);

export type ReconciliationProbeEvidenceV1 = {
  schemaVersion: 1;
  format: 'cliq-reconciliation-probe-evidence-v1';
  runId: string;
  waitingSubjectRef: ArtifactRef;
  waitingSubjectDigest: string;
  probeKind: 'automatic' | 'user_requested';
  probeOrdinal: number;
  probeNonceDigest: string;
  probeDispatchDigest: string;
  probeStartedAt: string;
  probeDeadlineAt: string;
  inspectorIdentityRef: ArtifactRef;
  inspectorIdentityDigest: string;
  observedAt: string;
  evidenceDigest: string;
} & (
  | { outcome: 'subject_observation'; subjectEvidenceKind: 'mcp_recovery' | 'publication' | 'worker_recovery'; subjectEvidenceRef: ArtifactRef; subjectEvidenceDigest: string; timeoutClosureRef?: never; timeoutClosureDigest?: never }
  | { outcome: 'probe_timeout'; timeoutReason: 'no_authoritative_observation_before_deadline'; timeoutClosureRef: ArtifactRef; timeoutClosureDigest: string; subjectEvidenceKind?: never; subjectEvidenceRef?: never; subjectEvidenceDigest?: never }
);

export type ReconciliationLastProbeEvidenceV1 =
  | { lastProbeEvidenceRef?: never; lastProbeEvidenceDigest?: never }
  | { lastProbeEvidenceRef: ArtifactRef; lastProbeEvidenceDigest: string };

export type ReconciliationProbeStateV1 =
  | { phase: 'manual_only'; automaticProbeCount: 0; userProbeCount: 0 }
  | { phase: 'automatic_pending'; automaticProbeCount: 0; userProbeCount: 0; nextProbeAt: string; lastProbeEvidenceRef?: never; lastProbeEvidenceDigest?: never }
  | { phase: 'automatic_pending'; automaticProbeCount: 1 | 2 | 3 | 4 | 5 | 6 | 7; userProbeCount: 0; nextProbeAt: string; lastProbeEvidenceRef: ArtifactRef; lastProbeEvidenceDigest: string }
  | { phase: 'automatic_in_flight'; automaticProbeCount: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8; userProbeCount: 0;
      dispatch: ReconciliationProbeDispatchV1 & { probeKind: 'automatic'; probeOrdinal: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 } }
  | { phase: 'automatic_exhausted'; automaticProbeCount: 8; userProbeCount: number; lastProbeEvidenceRef: ArtifactRef; lastProbeEvidenceDigest: string }
  | { phase: 'user_in_flight'; automaticProbeCount: 8; userProbeCount: number;
      dispatch: ReconciliationProbeDispatchV1 & { probeKind: 'user_requested'; probeOrdinal: number; controlRequestId: string; controlRequestDigest: string } };
