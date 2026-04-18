import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { EditModelAction, ToolDefinition, ToolResult } from './types.js';

export const editTool: ToolDefinition<EditModelAction> = {
  name: 'edit',
  supports(action): action is EditModelAction {
    return typeof (action as { edit?: unknown }).edit === 'object' && !!(action as { edit?: unknown }).edit;
  },
  async execute(action, context): Promise<ToolResult> {
    const target = path.resolve(context.cwd, action.edit.path);
    const relativePath = path.relative(context.cwd, target) || action.edit.path;

    if (path.isAbsolute(action.edit.path) || relativePath.startsWith('..')) {
      const meta: ToolResult['meta'] = { path: action.edit.path };
      return {
        tool: 'edit',
        status: 'error',
        meta,
        content: `TOOL_RESULT edit ERROR\npath=${action.edit.path}\nedit.path must be a workspace-relative path inside the workspace`
      };
    }

    try {
      const current = await fs.readFile(target, 'utf8');
      const matches = current.split(action.edit.old_text).length - 1;
      if (matches !== 1) {
        const meta: ToolResult['meta'] = { path: relativePath, matches };
        return {
          tool: 'edit',
          status: 'error',
          meta,
          content: `TOOL_RESULT edit ERROR\npath=${relativePath}\nexpected old_text to match exactly once, but matched ${matches} times`
        };
      }

      const meta: ToolResult['meta'] = { path: relativePath };
      await fs.writeFile(target, current.replace(action.edit.old_text, action.edit.new_text), 'utf8');
      return {
        tool: 'edit',
        status: 'ok',
        meta,
        content: `TOOL_RESULT edit OK\npath=${relativePath}\nreplaced exact text span successfully`
      };
    } catch (error) {
      const meta: ToolResult['meta'] = { path: relativePath };
      return {
        tool: 'edit',
        status: 'error',
        meta,
        content: `TOOL_RESULT edit ERROR\npath=${relativePath}\n${error instanceof Error ? error.message : String(error)}`
      };
    }
  }
};
