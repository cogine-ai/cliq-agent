import { promises as fs } from 'node:fs';
import path from 'node:path';

import { GREP_MAX_FILE_BYTES, GREP_MAX_MATCHES } from '../config.js';
import type { GrepAction } from '../protocol/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspaceEntry, resolveWorkspacePath } from './path.js';

async function collectFileMatches(filePath: string, pattern: string, workspaceRealPath: string, out: string[]) {
  if (out.length >= GREP_MAX_MATCHES) {
    return;
  }

  const resolved = await resolveWorkspaceEntry(workspaceRealPath, filePath).catch(() => null);
  if (!resolved || !resolved.stat.isFile()) {
    return;
  }

  const fileStats = await fs.stat(resolved.targetRealPath).catch(() => null);
  if (!fileStats || fileStats.size > GREP_MAX_FILE_BYTES) {
    return;
  }

  const raw = await fs.readFile(resolved.targetRealPath, 'utf8').catch(() => null);
  if (raw === null) {
    return;
  }

  for (const [index, line] of raw.split('\n').entries()) {
    if (out.length >= GREP_MAX_MATCHES) {
      break;
    }
    if (line.includes(pattern)) {
      out.push(`${resolved.relativePath}:${index + 1}: ${line}`);
    }
  }
}

async function collectGrepMatches(
  root: string,
  pattern: string,
  workspaceRealPath: string,
  out: string[],
  seenRealPaths: Set<string>
) {
  if (out.length >= GREP_MAX_MATCHES) {
    return;
  }

  const rootRealPath = await fs.realpath(root);
  if (seenRealPaths.has(rootRealPath)) {
    return;
  }
  seenRealPaths.add(rootRealPath);

  const entries = await fs.readdir(rootRealPath, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (out.length >= GREP_MAX_MATCHES) {
      break;
    }

    const target = path.join(rootRealPath, entry.name);
    const resolved = await resolveWorkspaceEntry(workspaceRealPath, target).catch(() => null);
    if (!resolved) {
      continue;
    }

    if (resolved.stat.isDirectory()) {
      await collectGrepMatches(resolved.targetRealPath, pattern, workspaceRealPath, out, seenRealPaths);
      continue;
    }

    await collectFileMatches(resolved.targetRealPath, pattern, workspaceRealPath, out);
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
      const { relativePath, targetRealPath, workspaceRealPath } = await resolveWorkspacePath(context.cwd, action.grep.path ?? '.');
      const matches: string[] = [];
      const targetStats = await fs.stat(targetRealPath);

      if (targetStats.isDirectory()) {
        await collectGrepMatches(targetRealPath, action.grep.pattern, workspaceRealPath, matches, new Set<string>());
      } else if (targetStats.isFile()) {
        await collectFileMatches(targetRealPath, action.grep.pattern, workspaceRealPath, matches);
      }

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
