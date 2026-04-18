import { promises as fs } from 'node:fs';

import type { EditModelAction, ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspacePath } from './path.js';

export const editTool: ToolDefinition<EditModelAction> = {
  name: 'edit',
  access: 'write',
  supports(action): action is EditModelAction {
    return typeof (action as { edit?: unknown }).edit === 'object' && !!(action as { edit?: unknown }).edit;
  },
  async execute(action, context): Promise<ToolResult> {
    let targetRealPath: string;
    let relativePath: string;
    try {
      ({ targetRealPath, relativePath } = await resolveWorkspacePath(context.cwd, action.edit.path));
    } catch {
      const meta: ToolResult['meta'] = { path: action.edit.path };
      return {
        tool: 'edit',
        status: 'error',
        meta,
        content: `TOOL_RESULT edit ERROR\npath=${action.edit.path}\nedit.path must be a workspace-relative path inside the workspace`
      };
    }

    try {
      const current = await fs.readFile(targetRealPath, 'utf8');
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
      await fs.writeFile(targetRealPath, current.replace(action.edit.old_text, action.edit.new_text), 'utf8');
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
