import type { SkillAction } from '../protocol/model/actions.js';
import { activateSkill } from '../skills/loader.js';
import type { ToolDefinition, ToolResult } from './types.js';

function requireNonEmptyString(input: Record<string, unknown>, field: string) {
  const value = input[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid skill tool arguments: ${field} must be a non-empty string`);
  }
  return value;
}

export const skillTool: ToolDefinition<{ skill: SkillAction }> = {
  name: 'skill',
  access: 'read',
  modelSpec: {
    name: 'skill',
    description: 'Activate a discovered Cliq skill for specialized instructions.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', minLength: 1, description: 'Skill name to activate.' }
      },
      required: ['name'],
      additionalProperties: false
    },
    actionFromInput(input) {
      return {
        skill: {
          name: requireNonEmptyString(input, 'name')
        }
      };
    }
  },
  supports(action): action is { skill: SkillAction } {
    return typeof (action as { skill?: unknown }).skill === 'object' && !!(action as { skill?: unknown }).skill;
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const activation = await activateSkill(context.cwd, context.session, action.skill.name, {
        activatedBy: 'model'
      });
      return {
        tool: 'skill',
        status: 'ok',
        meta: {
          skill: activation.skill.name,
          status: activation.status,
          scope: activation.skill.scope,
          source: activation.skill.skillFile
        },
        content:
          `TOOL_RESULT skill OK\n` +
          `skill=${activation.skill.name}\n` +
          `status=${activation.status}\n` +
          `source=${activation.skill.skillFile}`
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'skill',
        status: 'error',
        meta: { skill: action.skill.name, error: message },
        content: `TOOL_RESULT skill ERROR\nskill=${action.skill.name}\n${message}`
      };
    }
  }
};
