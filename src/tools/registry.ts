import type { ModelAction } from '../protocol/model/actions.js';
import type { ModelToolCall } from '../model/types.js';
import { bashTool } from './bash.js';
import { editTool } from './edit.js';
import { findTool } from './find.js';
import { grepTool } from './grep.js';
import { lsTool } from './ls.js';
import { planTool } from './plan.js';
import { readTool } from './read.js';
import { skillTool } from './skill.js';
import { skillResourceTool } from './skill-resource.js';
import { todoTool } from './todo.js';
import type { ToolDefinition } from './types.js';

export function createToolRegistry(
  definitions: ToolDefinition[] = [
    bashTool,
    editTool,
    readTool,
    lsTool,
    findTool,
    grepTool,
    skillTool,
    skillResourceTool,
    planTool,
    todoTool
  ]
) {
  return {
    definitions,
    modelVisibleToolSpecs() {
      return definitions
        .filter((definition) => definition.modelSpec !== undefined)
        .map((definition) => {
          const modelSpec = definition.modelSpec!;
          return {
            name: modelSpec.name,
            description: modelSpec.description,
            inputSchema: modelSpec.inputSchema
          };
        });
    },
    resolveToolCall(call: ModelToolCall) {
      const definition = definitions.find((candidate) => candidate.modelSpec?.name === call.name);
      if (!definition?.modelSpec) {
        throw new Error(`No tool registered for structured tool call: ${call.name}`);
      }
      const action = definition.modelSpec.actionFromInput(call.arguments);
      if (!definition.supports(action)) {
        throw new Error(`Structured tool call did not produce a supported action: ${JSON.stringify(call)}`);
      }
      return { definition, action };
    },
    resolve(action: ModelAction) {
      const definition = definitions.find((candidate) => candidate.supports(action));
      if (!definition) {
        throw new Error(`No tool registered for action: ${JSON.stringify(action)}`);
      }

      return { definition };
    }
  };
}
