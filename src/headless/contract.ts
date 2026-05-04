import type { PartialModelConfig } from '../model/config.js';
import type { ProviderName } from '../model/types.js';
import type { PolicyMode } from '../policy/types.js';
import type { AutoCompactConfig } from '../session/auto-compact-config.js';
import type { SessionModelRef } from '../session/types.js';

export const HEADLESS_SCHEMA_VERSION = 1;
export const HEADLESS_EXIT_SUCCESS = 0;
export const HEADLESS_EXIT_FAILURE = 1;
export const HEADLESS_EXIT_CANCELLED = 130;

export type HeadlessRunRequest = {
  prompt: string;
  cwd: string;
  policy?: PolicyMode;
  model?: PartialModelConfig;
  skills?: string[];
  autoCompact?: AutoCompactConfig;
  session?: {
    mode?: 'active' | 'new';
  };
  metadata?: Record<string, string | number | boolean | null>;
};

export type HeadlessRunOptions = {
  signal?: AbortSignal;
  onEvent?: (event: RuntimeEventEnvelope) => void | Promise<void>;
};

export type HeadlessRunStatus = 'completed' | 'failed' | 'cancelled';

export type HeadlessErrorCode =
  | 'invalid-input'
  | 'config-error'
  | 'model-auth-error'
  | 'model-error'
  | 'context-overflow'
  | 'protocol-error'
  | 'policy-denied'
  | 'tool-error'
  | 'compact-error'
  | 'session-store-error'
  | 'artifact-not-found'
  | 'cancelled'
  | 'internal-error';

export type HeadlessErrorStage =
  | 'input'
  | 'assembly'
  | 'checkpoint'
  | 'model'
  | 'protocol'
  | 'policy'
  | 'tool'
  | 'compact'
  | 'session'
  | 'cancel';

export type HeadlessRunError = {
  code: HeadlessErrorCode;
  stage: HeadlessErrorStage;
  message: string;
  recoverable: boolean;
};

export type HeadlessArtifacts = {
  checkpoints: string[];
  workspaceCheckpoints: string[];
  compactions: string[];
  handoffs: string[];
};

export function emptyHeadlessArtifacts(): HeadlessArtifacts {
  return {
    checkpoints: [],
    workspaceCheckpoints: [],
    compactions: [],
    handoffs: []
  };
}

export type HeadlessRunOutput = {
  runId: string;
  sessionId?: string;
  turn?: number;
  status: HeadlessRunStatus;
  exitCode: number;
  finalMessage?: string;
  checkpointId?: string;
  artifacts: HeadlessArtifacts;
  error?: HeadlessRunError;
};

export type HeadlessRuntimeEventType =
  | 'run-start'
  | 'checkpoint-created'
  | 'model-start'
  | 'model-progress'
  | 'model-end'
  | 'tool-start'
  | 'tool-end'
  | 'compact-start'
  | 'compact-end'
  | 'compact-skip'
  | 'compact-error'
  | 'final'
  | 'error'
  | 'run-end';

export type RunStartPayload = {
  cwd: string;
  policy: PolicyMode;
  model: SessionModelRef;
};

export type CheckpointCreatedPayload = {
  checkpointId: string;
  kind: 'auto' | 'manual' | 'restore-safety' | 'handoff';
  workspaceCheckpointId?: string;
  workspaceSnapshotStatus: 'available' | 'unavailable' | 'expired';
  warning?: string;
};

export type ModelStartPayload = {
  provider: ProviderName;
  model: string;
  streaming: boolean;
};

export type ModelProgressPayload = {
  chunks: number;
  chars: number;
};

export type ModelEndPayload = {
  provider: ProviderName;
  model: string;
};

export type ToolStartPayload = {
  tool: string;
  preview?: string;
};

export type ToolEndPayload = {
  tool: string;
  status: 'ok' | 'error';
};

export type CompactStartPayload = {
  trigger: 'threshold' | 'overflow';
  phase: 'pre-model' | 'mid-loop';
};

export type CompactEndPayload = {
  artifactId: string;
  estimatedTokensBefore: number;
  estimatedTokensAfter: number;
};

export type CompactSkipPayload = {
  reason: string;
};

export type CompactErrorPayload = {
  trigger: 'threshold' | 'overflow';
  message: string;
};

export type FinalPayload = {
  message: string;
};

export type RunEndPayload = {
  status: HeadlessRunStatus;
  exitCode: number;
  output: HeadlessRunOutput;
};

export type HeadlessEventPayloadByType = {
  'run-start': RunStartPayload;
  'checkpoint-created': CheckpointCreatedPayload;
  'model-start': ModelStartPayload;
  'model-progress': ModelProgressPayload;
  'model-end': ModelEndPayload;
  'tool-start': ToolStartPayload;
  'tool-end': ToolEndPayload;
  'compact-start': CompactStartPayload;
  'compact-end': CompactEndPayload;
  'compact-skip': CompactSkipPayload;
  'compact-error': CompactErrorPayload;
  final: FinalPayload;
  error: HeadlessRunError;
  'run-end': RunEndPayload;
};

export type RuntimeEventEnvelopeFor<TType extends HeadlessRuntimeEventType> = TType extends HeadlessRuntimeEventType
  ? {
      schemaVersion: typeof HEADLESS_SCHEMA_VERSION;
      eventId: string;
      runId: string;
      sessionId?: string;
      turn?: number;
      timestamp: string;
      type: TType;
      payload: HeadlessEventPayloadByType[TType];
    }
  : never;

export type RuntimeEventEnvelope = {
  [TType in HeadlessRuntimeEventType]: RuntimeEventEnvelopeFor<TType>;
}[HeadlessRuntimeEventType];

export type SessionRecordView =
  | {
      id: string;
      ts: string;
      kind: 'system';
      role: 'system';
      text: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'user';
      role: 'user';
      text: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'assistant';
      role: 'assistant';
      actionType: 'message' | 'tool-call' | 'invalid' | 'none';
      message?: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'tool';
      role: 'user';
      tool: string;
      status: 'ok' | 'error';
      contentPreview: string;
      meta?: Record<string, string | number | boolean | null>;
    };

export type CheckpointView = {
  id: string;
  name?: string;
  kind: 'auto' | 'manual' | 'restore-safety' | 'handoff';
  createdAt: string;
  recordIndex: number;
  turn: number;
  workspaceCheckpointId?: string;
};

export type WorkspaceCheckpointView = {
  id: string;
  kind: 'git-ghost' | 'unavailable';
  status: 'available' | 'expired' | 'unavailable';
  createdAt: string;
  workspaceRealPath: string;
  gitRootRealPath?: string;
  commitId?: string;
  reason?: 'not-git' | 'snapshot-failed';
  warnings?: string[];
};

export type CompactionView = {
  id: string;
  status: 'active' | 'superseded';
  createdAt: string;
  coveredRange: {
    startIndexInclusive: number;
    endIndexExclusive: number;
  };
  firstKeptRecordId: string;
  anchorCheckpointId?: string;
  createdBy: {
    provider: ProviderName;
    model: string;
  };
  summaryMarkdown: string;
  auto?: {
    trigger: 'threshold' | 'overflow';
    phase: 'pre-model' | 'mid-loop';
    estimatedTokensBefore: number;
    estimatedTokensAfter?: number;
  };
};

export type HandoffView = {
  id: string;
  createdAt: string;
  sessionId: string;
  parentSessionId?: string;
  checkpointId: string;
  activeCompactionId?: string;
  summarySource: 'active-compaction' | 'handoff-only';
  provider: ProviderName;
  model: string;
  workspaceCheckpointId?: string;
  summaryMarkdown: string;
  markdown: string;
};

export type SessionView = {
  id: string;
  cwd: string;
  model: SessionModelRef;
  lifecycle: {
    status: 'idle' | 'running';
    turn: number;
    lastUserInputAt?: string;
    lastAssistantOutputAt?: string;
  };
  parentSessionId?: string;
  forkedFromCheckpointId?: string;
  records: SessionRecordView[];
  checkpoints: CheckpointView[];
  compactions: CompactionView[];
};

export type ArtifactView =
  | { kind: 'checkpoint'; checkpoint: CheckpointView; workspaceCheckpoint?: WorkspaceCheckpointView }
  | { kind: 'workspace-checkpoint'; workspaceCheckpoint: WorkspaceCheckpointView }
  | { kind: 'compaction'; compaction: CompactionView }
  | { kind: 'handoff'; handoff: HandoffView };
