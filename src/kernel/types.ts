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

export type CanonicalTimeFenceV1 = {
  schemaVersion: 1;
  format: 'cliq-canonical-time-fence-v1';
  stateOwnerEpoch: number;
  lastAcceptedAt: string;
  observedWallClockAt: string;
  state: 'healthy' | 'clock_regressed';
  updatedAt: string;
  fenceDigest: string;
};

export type LocalPrincipalIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-local-principal-identity-v1';
  stateRootIdentityRef: ArtifactRef;
  stateRootIdentityDigest: string;
  platform: 'macos' | 'linux';
  effectiveUid: number;
  principalId: string;
  identityDigest: string;
};

export type LocalControlChannelIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-local-control-channel-identity-v1';
  principalIdentityRef: ArtifactRef;
  principalIdentityDigest: string;
  principalId: string;
  client: 'cli' | 'tui' | 'jsonl' | 'rpc';
  transport:
    | {
        kind: 'in_process';
        processIdentityRef: ArtifactRef;
        processIdentityDigest: string;
      }
    | {
        kind: 'uds_peer';
        peerObservationRef: ArtifactRef;
        peerObservationDigest: string;
      };
  openedAt: string;
  channelNonceDigest: string;
  channelIdentityDigest: string;
};

export type RepositoryIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-repository-identity-v1';
  platform: 'macos' | 'linux';
  gitDirectoryRelativePath: '.git';
  gitDirectoryIdentity: {
    deviceId: string;
    fileId: string;
    ownerUid: number;
  };
  objectFormat: 'sha1' | 'sha256';
  repositoryIdentityDigest: string;
};

export type WorkspaceIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-workspace-identity-v1';
  ownerPrincipalId: string;
  platform: 'macos' | 'linux';
} & (
  | {
      kind: 'live';
      canonicalRootPath: string;
      rootIdentity: {
        deviceId: string;
        fileId: string;
        ownerUid: number;
      };
      repositoryIdentityRef?: ArtifactRef;
      repositoryIdentityDigest?: string;
      identityDigest: string;
    }
  | {
      kind: 'legacy_unavailable';
      legacyCanonicalRootPath: string;
      unavailableReason: 'missing' | 'moved' | 'unsupported_platform' | 'identity_unverifiable';
      observedAt: string;
      identityDigest: string;
    }
);

export type Session = {
  schemaVersion: 1;
  id: string;
  workspaceIdentityRef: ArtifactRef;
  name?: string;
  parentSessionId?: string;
  forkedThroughItemSeq?: number;
  contextRevision: number;
  latestItemSeq: number;
  contextProjectionRef: ArtifactRef;
  createdAt: string;
  updatedAt: string;
};

export type SessionItemKind =
  | 'compaction'
  | 'run_terminal'
  | 'legacy_record'
  | 'legacy_compaction'
  | 'legacy_plan'
  | 'legacy_handoff'
  | 'legacy_bookmark';

export type SessionContextSegment =
  | {
      kind: 'raw';
      fromItemSeq: number;
      throughItemSeq: number;
      items: Array<{
        sourceSessionId: string;
        itemSeq: number;
        itemId: string;
        kind: SessionItemKind;
        payloadRef: ArtifactRef;
      }>;
    }
  | {
      kind: 'summary';
      fromItemSeq: number;
      throughItemSeq: number;
      compactionItemId: string;
      summaryRef: ArtifactRef;
      summaryDigest: string;
      sourceItemsDigest: string;
      retainedItemIds: string[];
    }
  | {
      kind: 'excluded_control';
      fromItemSeq: number;
      throughItemSeq: number;
      sourceItemsDigest: string;
    };

export type SessionContextProjection = {
  schemaVersion: 1;
  format: 'cliq-session-context-v1';
  sessionId: string;
  contextRevision: number;
  throughItemSeq: number;
  segments: SessionContextSegment[];
  projectionDigest: string;
};

export type SessionSnapshotV1 = {
  schemaVersion: 1;
  session: Session;
};

export type AdmittedContextManifest = {
  schemaVersion: 1;
  format: 'cliq-admitted-context-v1';
  sessionId: string;
  sessionContextRevision: number;
  throughSessionItemSeq: number;
  sessionProjectionRef: ArtifactRef;
  parentContextRefs: ArtifactRef[];
  additionalArtifactRefs: ArtifactRef[];
  contextDigest: string;
};

export type ContextSegment =
  | {
      kind: 'raw';
      fromItemSeq: number;
      throughItemSeq: number;
      items: Array<{ itemSeq: number; itemRef: ArtifactRef }>;
    }
  | {
      kind: 'summary';
      fromItemSeq: number;
      throughItemSeq: number;
      compactionItemId: string;
      summaryRef: ArtifactRef;
      summaryDigest: string;
      sourceItemsDigest: string;
      preservedItemRefs: ArtifactRef[];
    }
  | {
      kind: 'excluded_control';
      fromItemSeq: number;
      throughItemSeq: number;
      sourceItemsDigest: string;
    };

export type ContextManifest = {
  schemaVersion: 1;
  format: 'cliq-context-manifest-v1';
  runId: string;
  throughItemSeq: number;
  admittedContextRef: ArtifactRef;
  segments: ContextSegment[];
  assemblyRef: ArtifactRef;
  projectionDigest: string;
};

export type FrozenIgnoreRuleV1 = {
  order: number;
  sourceIndex: number;
  sourceLine: number;
  baseDirectory: string;
  negated: boolean;
  directoryOnly: boolean;
  anchored: boolean;
  pattern: string;
};

export type FrozenIgnoreRulesV1 = {
  schemaVersion: 1;
  format: 'cliq-frozen-ignore-rules-v1';
  matcherVersion: 'cliq-git-wildmatch-v1';
  repositoryIdentityDigest?: string;
  sources: Array<{
    index: number;
    kind: 'git_info_exclude' | 'gitignore';
    canonicalRootRelativePath: string;
    baseDirectory: string;
    contentRef: ArtifactRef;
    contentDigest: string;
  }>;
  rules: FrozenIgnoreRuleV1[];
  rulesDigest: string;
};

export type SourceProjectionSpec = {
  schemaVersion: 1;
  matcherVersion: 'cliq-exact-path-v1';
  frozenIgnoreRulesRef: ArtifactRef;
  frozenIgnoreRulesDigest: string;
  explicitIncludes: Array<{
    path: string;
    scope: 'entry' | 'subtree';
    authorizationRef: ArtifactRef;
  }>;
  explicitExcludes: Array<{
    path: string;
    scope: 'entry' | 'subtree';
  }>;
  maxChangedPaths: number;
  maxChangedBytes: number;
  projectionDigest: string;
};

export type WorkspaceEntry =
  | { path: string; kind: 'directory'; mode: number }
  | { path: string; kind: 'file'; mode: number; size: number; blobRef: ArtifactRef }
  | { path: string; kind: 'symlink'; mode: number; target: string; targetDigest: string };

export type WorkspaceEntryManifest = {
  schemaVersion: 1;
  format: 'cliq-workspace-entries-v1';
  entries: WorkspaceEntry[];
  entryCount: number;
  byteCount: number;
  treeDigest: string;
};

export type SourceManifest = {
  schemaVersion: 1;
  format: 'cliq-source-manifest-v1';
  role: 'base' | 'result';
  workspaceIdentityDigest: string;
  entriesRef: ArtifactRef;
  sourceProjectionRef: ArtifactRef;
  sourceProjectionDigest: string;
  frozenIgnoreRulesRef: ArtifactRef;
  frozenIgnoreRulesDigest: string;
  git?: {
    repositoryIdentityDigest: string;
    head:
      | { kind: 'unborn'; branch: string }
      | { kind: 'symbolic'; ref: string; objectId: string }
      | { kind: 'detached'; objectId: string };
    indexRef: ArtifactRef;
    indexTreeObjectId: string;
  };
  treeDigest: string;
  manifestDigest: string;
};

export type WorkspaceStateManifest = {
  schemaVersion: 1;
  format: 'cliq-workspace-state-v1';
  runId: string;
  baseWorkspaceManifestRef: ArtifactRef;
  entriesRef: ArtifactRef;
  privateGitStateRef?: ArtifactRef;
  invalidatedEphemeralPaths: string[];
  sourceProjectionDigest: string;
  stateDigest: string;
};

export type DirectUnverifiedConsentV1 = {
  schemaVersion: 1;
  kind: 'direct_unverified_consent';
  principalId: string;
  client: 'cli' | 'tui' | 'jsonl' | 'rpc';
  channelIdentityRef: ArtifactRef;
  channelIdentityDigest: string;
  admissionIntentDigest: string;
  runSpecCoreDigest: string;
  allowUnverified: true;
  createdAt: string;
  consentDigest: string;
};

export type VerifierSpec = {
  schemaVersion: 1;
  format: 'cliq-verifier-spec-v1';
  verifiers: Array<{
    index: number;
    id: string;
    version: string;
    gate: 'required' | 'advisory';
    commandRef: ArtifactRef;
    commandDigest: string;
    environmentRef: ArtifactRef;
    environmentDigest: string;
    timeoutMs: number;
    retries: number;
    outputLimitBytes: number;
    entryDigest: string;
  }>;
  specDigest: string;
};

export type StateRootIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-state-root-identity-v1';
  platform: 'linux' | 'macos';
  canonicalAbsolutePath: string;
  ownerUid: number;
  deviceId: string;
  directoryFileId: string;
  mode: 448;
  openedNoFollow: true;
  layoutVersion: 1;
  identityDigest: string;
};

export type PlatformProcessIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-platform-process-identity-v1';
  platform: 'linux' | 'macos';
  pid: number;
  processStartToken: string;
  ownerUid: number;
  executableImageDigest: string;
  observedAt: string;
  identityDigest: string;
};

export type StateLockIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-state-lock-identity-v1';
  stateRootIdentityRef: ArtifactRef;
  stateRootIdentityDigest: string;
  canonicalRootRelativePath: 'runtime/state-owner.lock';
  deviceId: string;
  fileId: string;
  ownerUid: number;
  mode: 384;
  linkCount: 1;
  identityDigest: string;
};

export type StateOwnerAcquisitionEvidenceV1 = {
  schemaVersion: 1;
  format: 'cliq-state-owner-acquisition-evidence-v1';
  ownerEpoch: number;
  supervisorInstanceId: string;
  runtimeBundleRef: ArtifactRef;
  runtimeBundleManifestDigest: string;
  processIdentityRef: ArtifactRef;
  processIdentityDigest: string;
  stateLockIdentityRef: ArtifactRef;
  stateLockIdentityDigest: string;
  instanceNonceDigest: string;
  acquiredAt: string;
  evidenceDigest: string;
} & (
  | {
      kind: 'genesis';
      kernelGenerationIdentityRef: ArtifactRef;
      kernelGenerationIdentityDigest: string;
      ownerTableObservation: 'empty';
    }
  | {
      kind: 'acquire_after_graceful_release';
      priorOwnerEpoch: number;
      priorTerminalRowDigest: string;
      priorTransitionEvidenceRef: ArtifactRef;
      priorTransitionEvidenceDigest: string;
      priorTerminalReason: 'graceful_release';
    }
  | {
      kind: 'takeover_after_owner_death';
      priorOwnerEpoch: number;
      priorTerminalRowDigest: string;
      priorTransitionEvidenceRef: ArtifactRef;
      priorTransitionEvidenceDigest: string;
      priorTerminalReason: 'superseded_after_owner_death';
    }
);

export type StateOwnerRecordV1 = {
  schemaVersion: 1;
  ownerEpoch: number;
  supervisorInstanceId: string;
  runtimeBundleRef: ArtifactRef;
  runtimeBundleManifestDigest: string;
  supervisorEntryId: string;
  supervisorEntryVersion: string;
  supervisorExecutableDigest: string;
  processIdentityRef: ArtifactRef;
  processIdentityDigest: string;
  stateLockIdentityRef: ArtifactRef;
  stateLockIdentityDigest: string;
  acquisitionEvidenceRef: ArtifactRef;
  acquisitionEvidenceDigest: string;
  instanceNonceDigest: string;
  acquiredAt: string;
  rowDigest: string;
} & (
  | {
      state: 'active';
      rowVersion: 1;
    }
  | {
      state: 'terminal';
      rowVersion: 2;
      releasedAt: string;
      terminalReason: 'graceful_release' | 'superseded_after_owner_death';
      transitionEvidenceRef: ArtifactRef;
      transitionEvidenceDigest: string;
    }
);

export type KernelGenerationIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-kernel-generation-identity-v1';
  generationId: string;
  stateRootIdentityRef: ArtifactRef;
  stateRootIdentityDigest: string;
  databaseImageRef: ArtifactRef;
  databaseImageDigest: string;
  databaseIdentityDigest: string;
  databaseContentDigest: string;
  casNamespaceManifestRef: ArtifactRef;
  casNamespaceManifestDigest: string;
  casNamespaceId: string;
  casRootDigest: string;
  stateSchemaVersion: 1;
  generationDigest: string;
} & (
  | {
      origin: 'fresh_empty';
      pristineSchemaManifestRef: ArtifactRef;
      pristineSchemaManifestDigest: string;
      pristineSchemaDigest: string;
    }
  | {
      origin: 'migrated_candidate';
      candidateRef: ArtifactRef;
      candidateDigest: string;
      migrationId: string;
    }
);

export type RecoveryClosureV1 = {
  runSpec: RunSpec;
  run: Run;
  latestCheckpoint: Checkpoint;
  items: [];
  journal: [];
  workerLaunches: [];
  childAllocations: [];
};

export type ControlResultV1 =
  | { method: 'session.create'; snapshot: SessionSnapshotV1 }
  | { method: 'run.submit'; snapshot: RunSnapshotV1 };

export type ControlApplicationResponseV1 =
  | { protocolVersion: 1; ok: true; result: ControlResultV1 }
  | {
      protocolVersion: 1;
      ok: false;
      method: 'session.create' | 'run.submit';
      error: {
        code:
          | 'ADMISSION_KEY_CONFLICT'
          | 'REQUEST_ID_CONFLICT'
          | 'ARTIFACT_MISMATCH'
          | 'INVALID_REQUEST'
          | 'NOT_FOUND'
          | 'RECOVERY_REQUIRED'
          | 'UNSUPPORTED_PLATFORM';
        retryable: false;
      };
    };
