import { promises as fs } from 'node:fs';

import { READ_MAX_BYTES } from '../config.js';
import type { ReadAction } from '../protocol/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspacePath } from './path.js';

export const readTool: ToolDefinition<{ read: ReadAction }> = {
  name: 'read',
  access: 'read',
  supports(action): action is { read: ReadAction } {
    return typeof (action as { read?: unknown }).read === 'object' && !!(action as { read?: unknown }).read;
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const { target, relativePath } = resolveWorkspacePath(context.cwd, action.read.path);
      const raw = await fs.readFile(target, 'utf8');
      const lines = raw.split('\n');
      const start = Math.max(1, action.read.start_line ?? 1);
      const end = Math.min(lines.length, action.read.end_line ?? Math.min(lines.length, start + 199));
      const snippet = lines
        .slice(start - 1, end)
        .map((line, index) => `${start + index}| ${line}`)
        .join('\n')
        .slice(0, READ_MAX_BYTES);

      return {
        tool: 'read',
        status: 'ok',
        meta: { path: relativePath, start_line: start, end_line: end },
        content: `TOOL_RESULT read OK\npath=${relativePath}\n${snippet}`.trim()
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'read',
        status: 'error',
        meta: { path: action.read.path },
        content: `TOOL_RESULT read ERROR\npath=${action.read.path}\n${message}`
      };
    }
  }
};
