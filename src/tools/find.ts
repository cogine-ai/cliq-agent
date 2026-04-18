import { promises as fs } from 'node:fs';
import path from 'node:path';

import { FIND_MAX_RESULTS } from '../config.js';
import type { FindAction } from '../protocol/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspacePath } from './path.js';

async function collectMatches(root: string, query: string, cwd: string, out: string[]) {
  const entries = await fs.readdir(root, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (out.length >= FIND_MAX_RESULTS) {
      break;
    }

    const target = path.join(root, entry.name);
    const relativePath = path.relative(cwd, target);
    if (entry.name.includes(query)) {
      out.push(relativePath);
    }
    if (entry.isDirectory()) {
      await collectMatches(target, query, cwd, out);
    }
  }
}

export const findTool: ToolDefinition<{ find: FindAction }> = {
  name: 'find',
  access: 'read',
  supports(action): action is { find: FindAction } {
    return typeof (action as { find?: unknown }).find === 'object' && !!(action as { find?: unknown }).find;
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const { target, relativePath } = resolveWorkspacePath(context.cwd, action.find.path ?? '.');
      const matches: string[] = [];
      await collectMatches(target, action.find.name, context.cwd, matches);
      return {
        tool: 'find',
        status: 'ok',
        meta: { path: relativePath, matches: matches.length },
        content: `TOOL_RESULT find OK\npath=${relativePath}\n${matches.join('\n')}`.trim()
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'find',
        status: 'error',
        meta: { path: action.find.path ?? '.' },
        content: `TOOL_RESULT find ERROR\npath=${action.find.path ?? '.'}\n${message}`
      };
    }
  }
};
