import type { ModelAction } from '../protocol/model/actions.js';
import { bashTool } from './bash.js';
import { editTool } from './edit.js';
import { findTool } from './find.js';
import { grepTool } from './grep.js';
import { lsTool } from './ls.js';
import { readTool } from './read.js';
import { skillTool } from './skill.js';
import { skillResourceTool } from './skill-resource.js';
import type { ToolDefinition } from './types.js';

export function createToolRegistry(
  definitions: ToolDefinition[] = [bashTool, editTool, readTool, lsTool, findTool, grepTool, skillTool, skillResourceTool]
) {
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
