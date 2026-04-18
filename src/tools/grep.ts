import { promises as fs } from 'node:fs';
import path from 'node:path';

import { GREP_MAX_FILE_BYTES, GREP_MAX_MATCHES } from '../config.js';
import type { GrepAction } from '../protocol/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspacePath } from './path.js';

async function collectGrepMatches(root: string, pattern: string, cwd: string, out: string[]) {
  const entries = await fs.readdir(root, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (out.length >= GREP_MAX_MATCHES) {
      break;
    }

    const target = path.join(root, entry.name);
    if (entry.isDirectory()) {
      await collectGrepMatches(target, pattern, cwd, out);
      continue;
    }

    const raw = await fs.readFile(target, 'utf8');
    if (raw.length > GREP_MAX_FILE_BYTES) {
      continue;
    }

    for (const [index, line] of raw.split('\n').entries()) {
      if (out.length >= GREP_MAX_MATCHES) {
        break;
      }
      if (line.includes(pattern)) {
        out.push(`${path.relative(cwd, target)}:${index + 1}: ${line}`);
      }
    }
  }
}

export const grepTool: ToolDefinition<{ grep: GrepAction }> = {
  name: 'grep',
  access: 'read',
  supports(action): action is { grep: GrepAction } {
    return typeof (action as { grep?: unknown }).grep === 'object' && !!(action as { grep?: unknown }).grep;
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const { target, relativePath } = resolveWorkspacePath(context.cwd, action.grep.path ?? '.');
      const matches: string[] = [];
      await collectGrepMatches(target, action.grep.pattern, context.cwd, matches);
      return {
        tool: 'grep',
        status: 'ok',
        meta: { path: relativePath, matches: matches.length },
        content: `TOOL_RESULT grep OK\npath=${relativePath}\n${matches.join('\n')}`.trim()
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tool: 'grep',
        status: 'error',
        meta: { path: action.grep.path ?? '.' },
        content: `TOOL_RESULT grep ERROR\npath=${action.grep.path ?? '.'}\n${message}`
      };
    }
  }
};
