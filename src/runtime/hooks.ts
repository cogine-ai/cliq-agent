import type { ModelAction } from '../protocol/actions.js';
import type { Session } from '../session/types.js';
import type { ToolResult } from '../tools/types.js';

export type RuntimeHook = {
  beforeTurn?(session: Session, userInput: string): Promise<void> | void;
  afterAssistantAction?(session: Session, action: ModelAction, rawContent: string): Promise<void> | void;
  beforeTool?(session: Session, action: ModelAction): Promise<void> | void;
  afterTool?(session: Session, result: ToolResult): Promise<void> | void;
  afterTurn?(session: Session, finalMessage: string): Promise<void> | void;
};

export async function runHooks<K extends keyof RuntimeHook>(
  hooks: RuntimeHook[],
  name: K,
  ...args: Parameters<NonNullable<RuntimeHook[K]>>
) {
  for (const hook of hooks) {
    const fn = hook[name];
    if (fn) {
      await fn(...args);
    }
  }
}
