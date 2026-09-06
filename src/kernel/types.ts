export type ArtifactRef = string;

export type {
  ToolContractManifestV1, ModelTurnItem, ToolBatchItem, ToolResultItem,
  ToolResultPayloadV1, ToolResultModelContentV1, RunContextCompactionPlan,
  RunContextCompactionItem, ContinuationItem
} from './continuation.js';

export type ProviderName =
  | 'openrouter'
  | 'anthropic'
  | 'openai'
  | 'openai-compatible'
  | 'zhipu'
  | 'ollama';

export type ModelPricingBound =
  | {
      kind: 'zero_cost';
      maxRunCostMicros: 0;
      provenanceRef: ArtifactRef;
    }
  | {
      kind: 'trusted_price_table';
      priceTableRef: ArtifactRef;
      priceTableDigest: string;
      calculationAlgorithm: 'cliq-price-ceil-v1';
      maxRunCostMicros: number;
      validThrough: string;
      provenanceRef: ArtifactRef;
    };

export type RunAssemblyV1 = {
  schemaVersion: 1;
  format: 'cliq-run-assembly-v1';
  provider: {
    name: ProviderName;
    model: string;
    endpoint:
      | {
          kind: 'local_zero_cost';
          identityDigest: string;
          localProvenanceRef: ArtifactRef;
        }
      | {
          kind: 'registered';
          registrationKind: 'bundled_default' | 'user';
          endpointRegistrationRef: ArtifactRef;
          endpointIdentityDigest: string;
          tlsPolicyDigest: string;
        };
    credentialGrantRefs: ArtifactRef[];
    adapter: { adapterId: string; version: string; codeDigest: string };
    negotiation: {
      mode: 'native-tools' | 'text-only';
      capabilityEvidenceRef: ArtifactRef;
      capabilityDigest: string;
      nativeToolCalling: boolean;
      streaming: boolean;
      trustedUsageEvidence: boolean;
      contextLimitTokens: number;
      maxOutputTokens: number;
      exposedToolNames: string[];
    };
    pricing: ModelPricingBound;
  };
  mcpServers: Array<{
    registrationId: string;
    registryRevisionRef: ArtifactRef;
    registryRevision: number;
    manifestDigest: string;
  }>;
  tools: {
    manifestRef: ArtifactRef;
    manifestDigest: string;
  };
  instructions: {
    systemPromptRef: ArtifactRef;
    systemPromptDigest: string;
    workspaceInstructionsRef: ArtifactRef;
    workspaceInstructionsDigest: string;
    skills: Array<{ skillId: string; manifestRef: ArtifactRef; manifestDigest: string }>;
  };
  runtime: {
    runtimeBundleRef: ArtifactRef;
    runtimeBundleManifestDigest: string;
    workerExecutableId: string;
    workerExecutableDigest: string;
    sandboxBackend: 'macos_vm' | 'linux_namespace';
    guestToolchainManifestRef?: ArtifactRef;
    guestToolchainManifestDigest?: string;
  };
  retry: {
    model: {
      maxDispatchedAttempts: 3;
      maxZeroByteTransportRetriesPerAttempt: 0;
      postAttemptDelaysMs: [500, 2000];
    };
    tools: Array<
      | {
          toolName: string;
          replayClass: 'retry';
          maxDispatchedAttempts: 3;
          postAttemptDelaysMs: [500, 2000];
        }
      | {
          toolName: string;
          replayClass: 'workspace-rollback-retry';
          maxDispatchedAttempts: 2;
          postAttemptDelaysMs: [500];
        }
      | {
          toolName: string;
          replayClass: 'reconcile' | 'manual';
          maxDispatchedAttempts: 1;
          postAttemptDelaysMs: [];
        }
    >;
  };
  context: {
    compactionPromptEnvelopeRef: ArtifactRef;
    compactionPromptEnvelopeDigest: string;
    contextLimitTokens: number;
    reservedOutputTokens: number;
    hardPromptTokens: number;
    triggerThresholdTokens: number;
    protectedRecentTokens: number;
    summaryTokenCap: number;
    compactionEnvelopeTokens: number;
    sourceInputTokenCap: number;
    maxSummaryBytes: 262144;
  };
  assemblyDigest: string;
  createdAt: string;
};

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

export type RunItemReferenceV1 = {
  schemaVersion: 1;
  itemId: string;
  itemSeq: number;
  payloadRef: ArtifactRef;
  payloadDigest: string;
  createdAt: string;
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

export type SessionItem = {
  schemaVersion: 1;
  itemId: string;
  sessionId: string;
  itemSeq: number;
  kind:
    | 'compaction'
    | 'run_terminal'
    | 'legacy_record'
    | 'legacy_compaction'
    | 'legacy_plan'
    | 'legacy_handoff'
    | 'legacy_bookmark';
  payloadRef: ArtifactRef;
  createdAt: string;
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

export type WorkspaceGenerationIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-workspace-generation-identity-v1';
  generationId: string;
  runId: string;
  workspaceIdentityDigest: string;
  sourceCheckpointId: string;
  sourceWorkspaceStateRef: ArtifactRef;
  sourceWorkspaceStateDigest: string;
  sourceTreeDigest: string;
  creationNonceDigest: string;
  locator:
    | {
        kind: 'linux_directory';
        stateRootIdentityRef: ArtifactRef;
        stateRootIdentityDigest: string;
        canonicalRootRelativePath: string;
        deviceId: string;
        directoryFileId: string;
        ownerUid: number;
        mode: 448;
        linkCount: 1;
      }
    | {
        kind: 'macos_vm_volume';
        stateRootIdentityRef: ArtifactRef;
        stateRootIdentityDigest: string;
        backingStoreCanonicalRootRelativePath: string;
        backingStoreDeviceId: string;
        backingStoreFileId: string;
        backingStoreOwnerUid: number;
        backingStoreMode: 384;
        backingStoreLinkCount: 1;
        vmVolumeReservationId: string;
        guestVolumeId: string;
      };
  createdAt: string;
  identityDigest: string;
};

export type WorkspaceGenerationSnapshotEvidenceV1 = {
  schemaVersion: 1;
  format: 'cliq-workspace-generation-snapshot-evidence-v1';
  purpose: 'materialized_from_checkpoint' | 'sealed_to_checkpoint';
  runId: string;
  generationRef: ArtifactRef;
  generationIdentityDigest: string;
  checkpointId: string;
  workspaceStateRef: ArtifactRef;
  workspaceStateDigest: string;
  entriesRef: ArtifactRef;
  treeDigest: string;
  privateGitStateRef?: ArtifactRef;
  descriptorRewalkComplete: true;
  fileFsyncComplete: true;
  directoryFsyncComplete: true;
  observedAt: string;
  evidenceDigest: string;
};

export type WorkspaceGenerationQuarantineEvidenceBaseV1 = {
  schemaVersion: 1;
  format: 'cliq-workspace-generation-quarantine-evidence-v1';
  runId: string;
  generationRef: ArtifactRef;
  generationIdentityDigest: string;
  sourceRowVersion: number;
  observedState:
    | { kind: 'complete_tree'; treeDigest: string }
    | {
        kind: 'unreadable_partial';
        failureCode:
          | 'descriptor_io_failed'
          | 'artifact_missing_or_corrupt'
          | 'path_or_entry_invalid'
          | 'git_closure_invalid';
      };
  inspectorIdentityRef: ArtifactRef;
  inspectorIdentityDigest: string;
  quarantineCanonicalRootRelativePath: string;
  quarantineDeviceId: string;
  quarantineFileId: string;
  originalLocatorAbsent: true;
  renameNoReplace: true;
  directoryFsyncComplete: true;
  observedAt: string;
  evidenceDigest: string;
};

export type WorkspaceGenerationQuarantineEvidenceV1 =
  WorkspaceGenerationQuarantineEvidenceBaseV1 &
    (
      | {
          reason: 'materialization_failed';
          fromPhase: 'materializing';
          failureDetailRef: ArtifactRef;
          failureDetailDigest: string;
          workerRecoveryEvidenceRef?: never;
          workerRecoveryEvidenceDigest?: never;
          workerLaunchId?: never;
          quiesceId?: never;
          containmentNoSpawnEvidenceRef?: never;
          containmentNoSpawnEvidenceDigest?: never;
          containmentDeathEvidenceRef?: never;
          containmentDeathEvidenceDigest?: never;
        }
      | {
          reason: 'preactivation_failed';
          fromPhase: 'preactivated_readonly';
          failureDetailRef: ArtifactRef;
          failureDetailDigest: string;
          workerRecoveryEvidenceRef?: never;
          workerRecoveryEvidenceDigest?: never;
          workerLaunchId?: never;
          quiesceId?: never;
          containmentNoSpawnEvidenceRef?: never;
          containmentNoSpawnEvidenceDigest?: never;
          containmentDeathEvidenceRef?: never;
          containmentDeathEvidenceDigest?: never;
        }
      | {
          reason: 'launch_aborted';
          fromPhase: 'preactivated_readonly';
          workerLaunchId: string;
          containmentNoSpawnEvidenceRef: ArtifactRef;
          containmentNoSpawnEvidenceDigest: string;
          failureDetailRef?: never;
          failureDetailDigest?: never;
          workerRecoveryEvidenceRef?: never;
          workerRecoveryEvidenceDigest?: never;
          quiesceId?: never;
          containmentDeathEvidenceRef?: never;
          containmentDeathEvidenceDigest?: never;
        }
      | {
          reason: 'launch_died_before_activation';
          fromPhase: 'preactivated_readonly';
          workerLaunchId: string;
          containmentDeathEvidenceRef: ArtifactRef;
          containmentDeathEvidenceDigest: string;
          failureDetailRef?: never;
          failureDetailDigest?: never;
          workerRecoveryEvidenceRef?: never;
          workerRecoveryEvidenceDigest?: never;
          quiesceId?: never;
          containmentNoSpawnEvidenceRef?: never;
          containmentNoSpawnEvidenceDigest?: never;
        }
      | {
          reason: 'worker_recovery';
          fromPhase: 'fenced_reconciling';
          workerRecoveryEvidenceRef: ArtifactRef;
          workerRecoveryEvidenceDigest: string;
          failureDetailRef?: never;
          failureDetailDigest?: never;
          workerLaunchId?: never;
          quiesceId?: never;
          containmentNoSpawnEvidenceRef?: never;
          containmentNoSpawnEvidenceDigest?: never;
          containmentDeathEvidenceRef?: never;
          containmentDeathEvidenceDigest?: never;
        }
      | {
          reason: 'checkpoint_failed';
          fromPhase: 'revoking' | 'checkpointing';
          workerLaunchId: string;
          quiesceId: string;
          containmentDeathEvidenceRef: ArtifactRef;
          containmentDeathEvidenceDigest: string;
          failureDetailRef?: never;
          failureDetailDigest?: never;
          workerRecoveryEvidenceRef?: never;
          workerRecoveryEvidenceDigest?: never;
          containmentNoSpawnEvidenceRef?: never;
          containmentNoSpawnEvidenceDigest?: never;
        }
    );

export type WorkspaceGenerationStateBaseV1 = {
  schemaVersion: 1;
  generationId: string;
  runId: string;
  generationRef: ArtifactRef;
  generationIdentityDigest: string;
  rowVersion: number;
  sourceCheckpointId: string;
  sourceWorkspaceStateRef: ArtifactRef;
  sourceWorkspaceStateDigest: string;
  lastVerifiedTreeDigest: string;
  updatedAt: string;
};

export type WorkspaceGenerationStateV1 = WorkspaceGenerationStateBaseV1 &
  (
    | {
        phase: 'materializing';
        snapshotEvidenceRef?: never;
        snapshotEvidenceDigest?: never;
        activeWorkerLaunchId?: never;
        leaseEpoch?: never;
        quiesceId?: never;
        waitingSubjectRef?: never;
        waitingSubjectDigest?: never;
        fencedFromPhase?: never;
        quarantineEvidenceRef?: never;
        quarantineEvidenceDigest?: never;
        observedState?: never;
        retirementEvidenceRef?: never;
        retirementEvidenceDigest?: never;
      }
    | {
        phase: 'preactivated_readonly';
        snapshotEvidenceRef: ArtifactRef;
        snapshotEvidenceDigest: string;
        activeWorkerLaunchId?: never;
        leaseEpoch?: never;
        quiesceId?: never;
        waitingSubjectRef?: never;
        waitingSubjectDigest?: never;
        fencedFromPhase?: never;
        quarantineEvidenceRef?: never;
        quarantineEvidenceDigest?: never;
        observedState?: never;
        retirementEvidenceRef?: never;
        retirementEvidenceDigest?: never;
      }
    | {
        phase: 'active';
        snapshotEvidenceRef: ArtifactRef;
        snapshotEvidenceDigest: string;
        activeWorkerLaunchId: string;
        leaseEpoch: number;
        quiesceId?: never;
        waitingSubjectRef?: never;
        waitingSubjectDigest?: never;
        fencedFromPhase?: never;
        quarantineEvidenceRef?: never;
        quarantineEvidenceDigest?: never;
        observedState?: never;
        retirementEvidenceRef?: never;
        retirementEvidenceDigest?: never;
      }
    | {
        phase: 'revoking' | 'checkpointing';
        snapshotEvidenceRef: ArtifactRef;
        snapshotEvidenceDigest: string;
        activeWorkerLaunchId: string;
        leaseEpoch: number;
        quiesceId: string;
        waitingSubjectRef?: never;
        waitingSubjectDigest?: never;
        fencedFromPhase?: never;
        quarantineEvidenceRef?: never;
        quarantineEvidenceDigest?: never;
        observedState?: never;
        retirementEvidenceRef?: never;
        retirementEvidenceDigest?: never;
      }
    | ({
        phase: 'fenced_reconciling';
        snapshotEvidenceRef: ArtifactRef;
        snapshotEvidenceDigest: string;
        activeWorkerLaunchId: string;
        leaseEpoch: number;
        waitingSubjectRef: ArtifactRef;
        waitingSubjectDigest: string;
        quarantineEvidenceRef?: never;
        quarantineEvidenceDigest?: never;
        observedState?: never;
        retirementEvidenceRef?: never;
        retirementEvidenceDigest?: never;
      } &
        (
          | { fencedFromPhase: 'active'; quiesceId?: never }
          | { fencedFromPhase: 'revoking' | 'checkpointing'; quiesceId: string }
        ))
    | {
        phase: 'sealed';
        snapshotEvidenceRef: ArtifactRef;
        snapshotEvidenceDigest: string;
        activeWorkerLaunchId?: never;
        leaseEpoch?: never;
        quiesceId?: never;
        waitingSubjectRef?: never;
        waitingSubjectDigest?: never;
        fencedFromPhase?: never;
        quarantineEvidenceRef?: never;
        quarantineEvidenceDigest?: never;
        observedState?: never;
        retirementEvidenceRef?: never;
        retirementEvidenceDigest?: never;
      }
    | {
        phase: 'quarantined';
        quarantineEvidenceRef: ArtifactRef;
        quarantineEvidenceDigest: string;
        observedState: WorkspaceGenerationQuarantineEvidenceV1['observedState'];
        snapshotEvidenceRef?: never;
        snapshotEvidenceDigest?: never;
        activeWorkerLaunchId?: never;
        leaseEpoch?: never;
        quiesceId?: never;
        waitingSubjectRef?: never;
        waitingSubjectDigest?: never;
        fencedFromPhase?: never;
        retirementEvidenceRef?: never;
        retirementEvidenceDigest?: never;
      }
    | {
        phase: 'retired';
        retirementEvidenceRef: ArtifactRef;
        retirementEvidenceDigest: string;
        snapshotEvidenceRef?: never;
        snapshotEvidenceDigest?: never;
        activeWorkerLaunchId?: never;
        leaseEpoch?: never;
        quiesceId?: never;
        waitingSubjectRef?: never;
        waitingSubjectDigest?: never;
        fencedFromPhase?: never;
        quarantineEvidenceRef?: never;
        quarantineEvidenceDigest?: never;
        observedState?: never;
      }
  );

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

export type StateOwnerTransitionEvidenceV1 = {
  schemaVersion: 1;
  format: 'cliq-state-owner-transition-evidence-v1';
  priorOwnerEpoch: number;
  priorSupervisorInstanceId: string;
  priorProcessIdentityRef: ArtifactRef;
  priorProcessIdentityDigest: string;
  stateLockIdentityRef: ArtifactRef;
  stateLockIdentityDigest: string;
  observedAt: string;
  evidenceDigest: string;
} & (
  | {
      kind: 'graceful_release';
      releasingProcessIdentityRef: ArtifactRef;
      releasingProcessIdentityDigest: string;
    }
  | {
      kind: 'superseded_after_owner_death';
      priorProcessObservation: 'absent_or_start_token_mismatch';
      successorOwnerEpoch: number;
      successorSupervisorInstanceId: string;
      successorRuntimeBundleRef: ArtifactRef;
      successorRuntimeBundleManifestDigest: string;
      successorProcessIdentityRef: ArtifactRef;
      successorProcessIdentityDigest: string;
      successorInstanceNonceDigest: string;
    }
);

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
      priorOwnerEpoch?: never;
      priorTerminalRowDigest?: never;
      priorTransitionEvidenceRef?: never;
      priorTransitionEvidenceDigest?: never;
      priorTerminalReason?: never;
    }
  | {
      kind: 'acquire_after_graceful_release';
      priorOwnerEpoch: number;
      priorTerminalRowDigest: string;
      priorTransitionEvidenceRef: ArtifactRef;
      priorTransitionEvidenceDigest: string;
      priorTerminalReason: 'graceful_release';
      kernelGenerationIdentityRef?: never;
      kernelGenerationIdentityDigest?: never;
      ownerTableObservation?: never;
    }
  | {
      kind: 'takeover_after_owner_death';
      priorOwnerEpoch: number;
      priorTerminalRowDigest: string;
      priorTransitionEvidenceRef: ArtifactRef;
      priorTransitionEvidenceDigest: string;
      priorTerminalReason: 'superseded_after_owner_death';
      kernelGenerationIdentityRef?: never;
      kernelGenerationIdentityDigest?: never;
      ownerTableObservation?: never;
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
      releasedAt?: never;
      terminalReason?: never;
      transitionEvidenceRef?: never;
      transitionEvidenceDigest?: never;
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

export type SupervisorInspectorIdentityV1 = {
  schemaVersion: 1;
  format: 'cliq-supervisor-inspector-identity-v1';
  supervisorInstanceId: string;
  stateOwnerEpoch: number;
  runtimeBundleRef: ArtifactRef;
  runtimeBundleManifestDigest: string;
  supervisorEntryId: string;
  supervisorEntryVersion: string;
  supervisorExecutableDigest: string;
  processIdentityRef: ArtifactRef;
  processIdentityDigest: string;
  stateLockIdentityRef: ArtifactRef;
  stateLockIdentityDigest: string;
  instanceNonceDigest: string;
  activatedAt: string;
  identityDigest: string;
};

export type ReplayClass =
  | 'retry'
  | 'workspace-rollback-retry'
  | 'reconcile'
  | 'manual';

export type InvocationPhase =
  | 'prepared'
  | 'dispatch_claimed'
  | 'completed'
  | 'failed'
  | 'unknown'
  | 'abandoned';

export type InvocationJournalEntry = {
  seq: number;
  runId: string;
  opId: string;
  opKind: 'model' | 'tool' | 'mcp-server' | 'mcp' | 'verifier' | 'publish';
  attempt: number;
  leaseEpoch: number;
  phase: InvocationPhase;
  target: string;
  requestRef: ArtifactRef;
  sandboxLaunchSpecRef?: ArtifactRef;
  replayClass: ReplayClass;
  idempotencyKey?: string;
  grantRef?: ArtifactRef;
  dispatchId?: string;
  supervisorInstanceId?: string;
  stateOwnerEpoch?: number;
  brokerFenceTokenDigest?: string;
  resultRef?: ArtifactRef;
  receiptRef?: ArtifactRef;
  errorRef?: ArtifactRef;
  evidenceRef?: ArtifactRef;
  evidenceDigest?: string;
  attestationRef?: ArtifactRef;
  budgetDelta: BudgetUsage;
  budgetSettlementRef?: ArtifactRef;
  timestamp: string;
};

export type BudgetSettlementV1 = {
  schemaVersion: 1;
  format: 'cliq-budget-settlement-v1';
  runId: string;
  opId: string;
  attempt: number;
  preparedJournalSeq: number;
  terminalJournalSeq: number;
  terminalPhase: 'completed' | 'failed' | 'unknown';
  reserved: BudgetUsage;
  consumed: BudgetUsage;
  released: BudgetUsage;
  budgetConsumedBefore: BudgetUsage;
  budgetConsumedAfter: BudgetUsage;
  budgetReservedBefore: BudgetUsage;
  budgetReservedAfter: BudgetUsage;
  settledAt: string;
  settlementDigest: string;
};

export type WorkerIdentity = {
  schemaVersion: 1;
  executableRealpath: string;
  executableDigest: string;
  pid: number;
  processStartToken: string;
  spawnNonceDigest: string;
  activationNonceDigest: string;
  intendedLeaseEpoch: number;
  launchId: string;
  supervisorInstanceId: string;
  processContainmentRef: ArtifactRef;
};

export type WorkerLaunch = {
  schemaVersion: 1;
  launchId: string;
  runId: string;
  plannedRunRevision: number;
  supervisorInstanceId: string;
  spawnNonceDigest: string;
  activationNonceDigest: string;
  phase: 'reserved' | 'preactivated' | 'activated' | 'reconciling' | 'retired';
  workspaceGenerationRef: ArtifactRef;
  containmentPlanRef: ArtifactRef;
  sandboxLaunchSpecRef: ArtifactRef;
  workerIdentityDigest?: string;
  processContainmentRef?: ArtifactRef;
  leaseEpoch?: number;
  leaseVersion: number;
  leaseExpiresAt?: string;
  generationWriteState:
    | 'preactivated_readonly'
    | 'active'
    | 'revoking'
    | 'checkpointing'
    | 'fenced_reconciling'
    | 'sealed';
  quiesceId?: string;
  createdAt: string;
  activationDeadlineAt: string;
  activatedAt?: string;
  retiredAt?: string;
  retirementEvidenceRef?: ArtifactRef;
};

export type ChildAllocationTerminal =
  | {
      mode: 'read_only';
      status: 'succeeded' | 'completed_unverified';
      resultRef: ArtifactRef;
      patchManifestRef?: never;
      modelContentRef: ArtifactRef;
      modelContentDigest: string;
    }
  | {
      mode: 'mutating';
      status: 'succeeded' | 'completed_unverified';
      resultRef: ArtifactRef;
      patchManifestRef: ArtifactRef;
      modelContentRef: ArtifactRef;
      modelContentDigest: string;
    }
  | {
      mode: 'read_only' | 'mutating';
      status: 'failed' | 'cancelled';
      resultRef?: never;
      patchManifestRef?: never;
      terminalDetailRef: ArtifactRef;
      modelContentRef: ArtifactRef;
      modelContentDigest: string;
    };

export type ChildAllocationBase = {
  schemaVersion: 1;
  parentRunId: string;
  childRunId: string;
  admissionKey: string;
  delegateBatchItemId: string;
  delegateCallId: string;
  delegateCallIndex: number;
  delegateOpId: string;
  delegateOperationGrantRef: ArtifactRef;
  capabilityGrantRef: ArtifactRef;
  mode: 'read_only' | 'mutating';
  grantedAdditiveCeilings: BudgetUsage;
  grantedChildDepth: number;
  grantedChildConcurrency: number;
  childDeadlineAt: string;
  createdAt: string;
};

export type ChildAllocationV1 = ChildAllocationBase &
  (
    | {
        state: 'reserved';
        terminal?: never;
        inclusiveBudgetUsage?: never;
        terminalAt?: never;
        childResultItemId?: never;
        parentSettlementRevision?: never;
        releasedUnusedBudget?: never;
        settledAt?: never;
      }
    | {
        state: 'child_terminal';
        terminal: ChildAllocationTerminal;
        inclusiveBudgetUsage: BudgetUsage;
        terminalAt: string;
        childResultItemId?: never;
        parentSettlementRevision?: never;
        releasedUnusedBudget?: never;
        settledAt?: never;
      }
    | {
        state: 'settled';
        terminal: ChildAllocationTerminal;
        inclusiveBudgetUsage: BudgetUsage;
        terminalAt: string;
        childResultItemId: string;
        parentSettlementRevision: number;
        releasedUnusedBudget: BudgetUsage;
        settledAt: string;
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
  items: RunItemReferenceV1[];
  journal: InvocationJournalEntry[];
  workerLaunches: WorkerLaunch[];
  workspaceGenerations: WorkspaceGenerationStateV1[];
  childAllocations: ChildAllocationV1[];
};

export type ControlResultV1 =
  | { method: 'session.create'; snapshot: SessionSnapshotV1 }
  | { method: 'run.submit'; snapshot: RunSnapshotV1 }
  | { method: 'run.approve'; snapshot: RunSnapshotV1; decisionRef: ArtifactRef };

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
