import type { ModelAction } from '../protocol/actions.js';
import { bashTool } from './bash.js';
import { editTool } from './edit.js';
import { lsTool } from './ls.js';
import { readTool } from './read.js';
import type { ToolDefinition } from './types.js';

export function createToolRegistry(definitions: ToolDefinition[] = [bashTool, editTool, readTool, lsTool]) {
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
