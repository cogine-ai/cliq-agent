import { createPassthroughWriter, type WorkspaceWriter } from '../runtime/workspace-writer.js';
import type { EditModelAction, ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspacePath, WORKSPACE_PATH_ERROR } from './path.js';

export const editTool: ToolDefinition<EditModelAction> = {
  name: 'edit',
  access: 'write',
  supports(action): action is EditModelAction {
    return typeof (action as { edit?: unknown }).edit === 'object' && !!(action as { edit?: unknown }).edit;
  },
  async execute(action, context): Promise<ToolResult> {
    let relativePath: string;
    try {
      ({ relativePath } = await resolveWorkspacePath(context.cwd, action.edit.path));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const displayError =
        message === WORKSPACE_PATH_ERROR
          ? 'edit.path must be a workspace-relative path inside the workspace'
          : message;
      const meta: ToolResult['meta'] = { path: action.edit.path, error: displayError };
      return {
        tool: 'edit',
        status: 'error',
        meta,
        content: `TOOL_RESULT edit ERROR\npath=${action.edit.path}\n${displayError}`
      };
    }

    const writer: WorkspaceWriter = context.writer ?? createPassthroughWriter(context.cwd);
    try {
      await writer.replaceText(relativePath, action.edit.old_text, action.edit.new_text);
      const meta: ToolResult['meta'] = { path: relativePath };
      return {
        tool: 'edit',
        status: 'ok',
        meta,
        content: `TOOL_RESULT edit OK\npath=${relativePath}\nreplaced exact text span successfully`
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const matchesMatch = /matched (\d+) times/.exec(message);
      const meta: ToolResult['meta'] = matchesMatch
        ? { path: relativePath, matches: Number(matchesMatch[1]), error: message }
        : { path: relativePath, error: message };
      return {
        tool: 'edit',
        status: 'error',
        meta,
        content: `TOOL_RESULT edit ERROR\npath=${relativePath}\n${message}`
      };
    }
  }
};
