import { promises as fs } from 'node:fs';

import { READ_MAX_BYTES } from '../config.js';
import type { ReadAction } from '../protocol/model/actions.js';
import type { ToolDefinition, ToolResult } from './types.js';
import { resolveWorkspacePath } from './path.js';

function requireString(input: Record<string, unknown>, field: string) {
  const value = input[field];
  if (typeof value !== 'string') {
    throw new Error(`Invalid read tool arguments: ${field} must be a string`);
  }
  return value;
}

function optionalPositiveInteger(input: Record<string, unknown>, field: string) {
  const value = input[field];
  if (value === undefined) {
    return undefined;
  }
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`Invalid read tool arguments: ${field} must be an integer >= 1`);
  }
  return value as number;
}

export const readTool: ToolDefinition<{ read: ReadAction }> = {
  name: 'read',
  access: 'read',
  modelSpec: {
    name: 'read',
    description: 'Read a line range from a workspace file.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative file path.' },
        start_line: { type: 'integer', minimum: 1, description: '1-based first line to include.' },
        end_line: { type: 'integer', minimum: 1, description: '1-based final line to include.' }
      },
      required: ['path'],
      additionalProperties: false
    },
    actionFromInput(input) {
      return {
        read: {
          path: requireString(input, 'path'),
          ...(() => {
            const startLine = optionalPositiveInteger(input, 'start_line');
            return startLine === undefined ? {} : { start_line: startLine };
          })(),
          ...(() => {
            const endLine = optionalPositiveInteger(input, 'end_line');
            return endLine === undefined ? {} : { end_line: endLine };
          })()
        }
      };
    }
  },
  supports(action): action is { read: ReadAction } {
    return typeof (action as { read?: unknown }).read === 'object' && !!(action as { read?: unknown }).read;
  },
  async execute(action, context): Promise<ToolResult> {
    try {
      const { relativePath, targetRealPath } = await resolveWorkspacePath(context.cwd, action.read.path);
      const raw = await fs.readFile(targetRealPath, 'utf8');
      const lines = raw.split('\n');
      const start = Math.min(Math.max(1, action.read.start_line ?? 1), lines.length);
      const requestedEnd = action.read.end_line ?? Math.min(lines.length, start + 199);
      const end = Math.max(start, Math.min(lines.length, requestedEnd));
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
        meta: { path: action.read.path, error: message },
        content: `TOOL_RESULT read ERROR\npath=${action.read.path}\n${message}`
      };
    }
  }
};
