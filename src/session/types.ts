import type { ProviderName } from '../model/types.js';
import type { ModelAction } from '../protocol/actions.js';
import type { AutoCompactContextWindowSource } from './auto-compact-config.js';

export type SessionModelRef = {
  provider: ProviderName;
  model: string;
  baseUrl?: string;
};

export type SessionRecord =
  | {
      id: string;
      ts: string;
      kind: 'system' | 'user';
      role: 'system' | 'user';
      content: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'assistant';
      role: 'assistant';
      content: string;
      action: ModelAction | null;
    }
  | {
      id: string;
      ts: string;
      kind: 'tool';
      role: 'user';
      tool: string;
      status: 'ok' | 'error';
      content: string;
      meta?: Record<string, string | number | boolean | null>;
    };

export type SessionCheckpoint = {
  id: string;
  name?: string;
  kind: 'auto' | 'manual' | 'restore-safety' | 'handoff';
  createdAt: string;
  recordIndex: number;
  turn: number;
  workspaceCheckpointId?: string;
};

export type WorkspaceCheckpoint =
  | {
      id: string;
      kind: 'git-ghost';
      status: 'available' | 'expired';
      createdAt: string;
      workspaceRealPath: string;
      gitRootRealPath: string;
      repoRelativeScope: string;
      commitId: string;
      parentCommitId?: string;
      preexistingUntrackedFiles: string[];
      warnings: string[];
    }
  | {
      id: string;
      kind: 'unavailable';
      status: 'unavailable';
      createdAt: string;
      workspaceRealPath: string;
      reason: 'not-git' | 'snapshot-failed';
      error?: string;
    };

export type CompactionArtifact = {
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
  details?: {
    filesRead?: string[];
    filesModified?: string[];
    tests?: string[];
    risks?: string[];
  };
  auto?: AutoCompactionMetadata;
};

export type AutoCompactionMetadata = {
  trigger: 'threshold' | 'overflow';
  phase: 'pre-model' | 'mid-loop';
  estimatedTokensBefore: number;
  estimatedTokensAfter?: number;
  usableLimitTokens?: number;
  contextWindowTokens?: number;
  contextWindowSource?: AutoCompactContextWindowSource;
  keepRecentTokens: number;
  summaryInputBudgetTokens?: number;
  overflowRetryAttempt?: number;
  previousCompactionId?: string;
};

export type Session = {
  version: number;
  app: 'cliq';
  id: string;
  name?: string;
  parentSessionId?: string;
  forkedFromCheckpointId?: string;
  model: SessionModelRef;
  cwd: string;
  createdAt: string;
  updatedAt: string;
  lifecycle: {
    status: 'idle' | 'running';
    turn: number;
    lastUserInputAt?: string;
    lastAssistantOutputAt?: string;
  };
  records: SessionRecord[];
  checkpoints: SessionCheckpoint[];
  compactions: CompactionArtifact[];
};
