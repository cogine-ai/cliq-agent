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

export type RuntimeEventEnvelope<TPayload = unknown> = {
  schemaVersion: 1;
  eventId: string;
  runId: string;
  sessionId?: string;
  turn?: number;
  timestamp: string;
  type: HeadlessRuntimeEventType;
  payload: TPayload;
};

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

export type FinalPayload = {
  message: string;
};

export type RunEndPayload = {
  status: HeadlessRunStatus;
  exitCode: number;
  output: HeadlessRunOutput;
};
