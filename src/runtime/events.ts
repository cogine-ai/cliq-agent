import type { ProviderName } from '../model/types.js';
import type { AutoCompactSkipReason } from '../session/auto-compaction.js';
import type { SessionCheckpoint } from '../session/types.js';

export type RuntimeEvent =
  | { type: 'model-start'; provider: ProviderName; model: string; streaming: boolean }
  | { type: 'model-progress'; chunks: number; chars: number }
  | { type: 'model-end'; provider: ProviderName; model: string }
  | {
      type: 'checkpoint-created';
      checkpointId: string;
      kind: SessionCheckpoint['kind'];
      workspaceCheckpointId?: string;
      workspaceSnapshotStatus: 'available' | 'unavailable' | 'expired';
      warning?: string;
    }
  | { type: 'compact-start'; trigger: 'threshold' | 'overflow'; phase: 'pre-model' | 'mid-loop' }
  | { type: 'compact-end'; artifactId: string; estimatedTokensBefore: number; estimatedTokensAfter: number }
  | { type: 'compact-skip'; reason: AutoCompactSkipReason }
  | { type: 'compact-error'; trigger: 'threshold' | 'overflow'; message: string }
  | { type: 'tool-start'; tool: string; preview?: string }
  | { type: 'tool-end'; tool: string; status: 'ok' | 'error' }
  | { type: 'final'; message: string }
  | { type: 'error'; stage: 'model' | 'protocol' | 'policy' | 'tool' | 'cancel'; message: string };

export type RuntimeEventSink = (event: RuntimeEvent) => void | Promise<void>;
