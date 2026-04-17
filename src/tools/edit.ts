import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { ToolDefinition } from './types.js';

export const editTool: ToolDefinition<{ edit: { path: string; old_text: string; new_text: string } }> = {
  name: 'edit',
  supports(action): action is { edit: { path: string; old_text: string; new_text: string } } {
    return typeof (action as { edit?: unknown }).edit === 'object' && !!(action as { edit?: unknown }).edit;
  },
  async execute(action, context) {
    const target = path.isAbsolute(action.edit.path) ? action.edit.path : path.join(context.cwd, action.edit.path);

    try {
      const current = await fs.readFile(target, 'utf8');
      const matches = current.split(action.edit.old_text).length - 1;
      if (matches !== 1) {
        return {
          tool: 'edit',
          status: 'error',
          meta: { path: path.relative(context.cwd, target) || action.edit.path, matches },
          content: `TOOL_RESULT edit ERROR\npath=${path.relative(context.cwd, target) || action.edit.path}\nexpected old_text to match exactly once, but matched ${matches} times`
        };
      }

      await fs.writeFile(target, current.replace(action.edit.old_text, action.edit.new_text), 'utf8');
      return {
        tool: 'edit',
        status: 'ok',
        meta: { path: path.relative(context.cwd, target) || action.edit.path },
        content: `TOOL_RESULT edit OK\npath=${path.relative(context.cwd, target) || action.edit.path}\nreplaced exact text span successfully`
      };
    } catch (error) {
      return {
        tool: 'edit',
        status: 'error',
        meta: { path: path.relative(context.cwd, target) || action.edit.path },
        content: `TOOL_RESULT edit ERROR\npath=${path.relative(context.cwd, target) || action.edit.path}\n${error instanceof Error ? error.message : String(error)}`
      };
    }
  }
};
