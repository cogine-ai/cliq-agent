import type { ProviderName } from '../model/types.js';

export type RuntimeEvent =
  | { type: 'model-start'; provider: ProviderName; model: string; streaming: boolean }
  | { type: 'model-progress'; chunks: number; chars: number }
  | { type: 'model-end'; provider: ProviderName; model: string }
  | { type: 'tool-start'; tool: string; preview?: string }
  | { type: 'tool-end'; tool: string; status: 'ok' | 'error' }
  | { type: 'final'; message: string }
  | { type: 'error'; stage: 'model' | 'protocol' | 'policy' | 'tool'; message: string };

export type RuntimeEventSink = (event: RuntimeEvent) => void | Promise<void>;
