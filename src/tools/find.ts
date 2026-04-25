import { promises as fs } from 'node:fs';
import path from 'node:path';

import { FIND_MAX_DEPTH, FIND_MAX_RESULTS } from '../config.js';
import type { FindAction } from '../protocol/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspaceEntry, resolveWorkspacePath } from './path.js';

async function collectMatches(
  root: string,
  query: string,
  workspaceRealPath: string,
  out: string[],
  depth: number,
  seenRealPaths: Set<string>,
  maxDepth: number
) {
  if (out.length >= FIND_MAX_RESULTS || depth > maxDepth) {
    return;
  }

  const rootRealPath = await fs.realpath(root);
  if (seenRealPaths.has(rootRealPath)) {
    return;
  }
  seenRealPaths.add(rootRealPath);

  const entries = await fs.readdir(rootRealPath, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (out.length >= FIND_MAX_RESULTS) {
      break;
    }

    const target = path.join(rootRealPath, entry.name);
    const resolved = await resolveWorkspaceEntry(workspaceRealPath, target).catch(() => null);
    if (!resolved) {
      continue;
    }

    if (entry.name.includes(query)) {
      if (out.length >= FIND_MAX_RESULTS) {
        break;
      }
      out.push(resolved.relativePath);
    }

    if (out.length >= FIND_MAX_RESULTS || depth >= maxDepth || !resolved.stat.isDirectory()) {
      continue;
    }

    if (seenRealPaths.has(resolved.targetRealPath)) {
      continue;
    }

    await collectMatches(resolved.targetRealPath, query, workspaceRealPath, out, depth + 1, seenRealPaths, maxDepth);
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
      const { relativePath, targetRealPath, workspaceRealPath } = await resolveWorkspacePath(context.cwd, action.find.path ?? '.');
      const matches: string[] = [];
      await collectMatches(targetRealPath, action.find.name, workspaceRealPath, matches, 0, new Set<string>(), FIND_MAX_DEPTH);
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
        meta: { path: action.find.path ?? '.', error: message },
        content: `TOOL_RESULT find ERROR\npath=${action.find.path ?? '.'}\n${message}`
      };
    }
  }
};
