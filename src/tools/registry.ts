import type { ModelAction } from '../protocol/actions.js';
import { bashTool } from './bash.js';
import { editTool } from './edit.js';
import type { ToolDefinition } from './types.js';

export function createToolRegistry(definitions: ToolDefinition[] = [bashTool, editTool]) {
  return {
    definitions,
    resolve(action: ModelAction) {
      const definition = definitions.find((candidate) => candidate.supports(action));
      if (!definition) {
        throw new Error(`No tool registered for action: ${JSON.stringify(action)}`);
      }

      return { definition };
    }
  };
}
