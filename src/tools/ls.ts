import { promises as fs } from 'node:fs';

import { LIST_MAX_ENTRIES } from '../config.js';
import type { LsAction } from '../protocol/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspacePath } from './path.js';

export const lsTool: ToolDefinition<{ ls: LsAction }> = {
  name: 'ls',
  access: 'read',
  supports(action): action is { ls: LsAction } {
    return typeof (action as { ls?: unknown }).ls === 'object' && !!(action as { ls?: unknown }).ls;
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const { relativePath, targetRealPath } = await resolveWorkspacePath(context.cwd, action.ls.path ?? '.');
      const allEntries = (await fs.readdir(targetRealPath, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
      const truncated = allEntries.length > LIST_MAX_ENTRIES;
      const entries = allEntries
        .slice(0, LIST_MAX_ENTRIES)
        .map((entry) => `${entry.isDirectory() ? 'dir' : 'file'} ${entry.name}${entry.isDirectory() ? '/' : ''}`)
        .join('\n');
      const truncationNotice = truncated ? `\n... (truncated, showing ${Math.min(allEntries.length, LIST_MAX_ENTRIES)} of ${allEntries.length} entries)` : '';

      return {
        tool: 'ls',
        status: 'ok',
        meta: { path: relativePath },
        content: `TOOL_RESULT ls OK\npath=${relativePath}\n${entries}${truncationNotice}`.trim()
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'ls',
        status: 'error',
        meta: { path: action.ls.path ?? '.' },
        content: `TOOL_RESULT ls ERROR\npath=${action.ls.path ?? '.'}\n${message}`
      };
    }
  }
};
