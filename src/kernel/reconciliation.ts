import type { ArtifactRef } from './types.js';

/** The RFC publication subject names the original permanently claimed path,
 * not a request to run the publication operation again. */
export type PublicationReconciliationSubject = {
  kind: 'publication_path'; deliveryPlanRef: ArtifactRef; pathOperationId: string; attempt: number;
};
export type PublicationPathWait = {
  schemaVersion: 1; kind: 'reconciliation'; runId: string; createdFromRevision: number; createdAt: string;
  frontierRef: ArtifactRef; subject: PublicationReconciliationSubject; probeState: ReconciliationProbeStateV1;
};

/** Fixed first inspection target. All fields come from the original fully
 * validated Journal/prefix; no probe can substitute a later claim or target. */
export type PublicationInspectionTargetV1 = {
  schemaVersion: 1; format: 'cliq-publication-inspection-target-v1'; runId: string;
  subject: PublicationReconciliationSubject; preparedJournalSeq: number; claimJournalSeq: number; unknownJournalSeq: number;
  unknownEvidenceRef: ArtifactRef; unknownBudgetSettlementRef: ArtifactRef;
  progress?: { itemRef: ArtifactRef; checkpointId: string };
};

/** Retained current-inspector provenance only. It cannot recreate an old
 * native owner, prove a path outcome, or authorize another semantic release.
 * This record never refers to a wait, probe, or the proof that names it, so a
 * wrapper -> proof -> origin graph is acyclic. */
export type PublicationRecoveryOriginV1 = {
  schemaVersion: 1; format: 'cliq-publication-recovery-origin-v1'; deliveryRunId: string; deliveryPlanRef: ArtifactRef;
  opId: string; attempt: number; dispatchId: string; claimJournalSeq: number;
  arenaBirthRef: ArtifactRef; arenaBirthDigest: string; inspectorIdentityRef: ArtifactRef; inspectorIdentityDigest: string;
  observedAt: string; originDigest: string;
} & ({ ownerDeathAcquisitionEvidenceRef: ArtifactRef; ownerDeathAcquisitionEvidenceDigest: string; gracefulOwnerDeath?: never } |
  { ownerDeathAcquisitionEvidenceRef?: never; ownerDeathAcquisitionEvidenceDigest?: never;
    gracefulOwnerDeath: { kind: 'observed_after_graceful_release'; priorOwnerRowDigest: string;
      priorProcessIdentityRef: ArtifactRef; priorProcessIdentityDigest: string;
      gracefulTransitionEvidenceRef: ArtifactRef; gracefulTransitionEvidenceDigest: string;
      processObservation: 'absent_or_start_token_mismatch' } });

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
  | { subjectKind: 'publication'; inspectorTaskId: string; inspectionTargetDigest: string; previousWaitingSubjectRef: ArtifactRef }
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

/** A real owning process joined its descriptor-only publication probe during
 * shutdown. This is neither a deadline timeout nor a path outcome. */
export type ReconciliationProbeCancellationClosureV1 = {
  schemaVersion: 1; format: 'cliq-reconciliation-probe-cancellation-closure-v1'; runId: string;
  waitingSubjectRef: ArtifactRef; probeKind: 'automatic' | 'user_requested'; probeOrdinal: number;
  probeNonceDigest: string; probeDispatchDigest: string; probeDeadlineAt: string;
  inspectorIdentityRef: ArtifactRef; inspectorIdentityDigest: string; closedAt: string; closureDigest: string;
  reason: 'owning_supervisor_shutdown'; subjectKind: 'publication'; deliveryPlanRef: ArtifactRef;
  pathOperationId: string; attempt: number; inspectorTaskId: string;
  taskClosure: Extract<ReconciliationInspectorTaskClosureV1, { closureKind: 'cancelled_and_joined' }>;
};

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
  | { outcome: 'probe_cancelled'; cancellationReason: 'owning_supervisor_shutdown'; cancellationClosureRef: ArtifactRef;
      cancellationClosureDigest: string; subjectEvidenceKind?: never; subjectEvidenceRef?: never; subjectEvidenceDigest?: never;
      timeoutClosureRef?: never; timeoutClosureDigest?: never }
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
