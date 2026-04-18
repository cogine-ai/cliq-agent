import type { ModelAction } from '../protocol/actions.js';

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

export type Session = {
  version: number;
  app: 'cliq';
  model: string;
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
};
