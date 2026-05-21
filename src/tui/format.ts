import type { ModelAction } from '../protocol/model/actions.js';
import type { ToolResult } from '../tools/types.js';

// Mirrors src/cli.ts:formatToolResultLine for the TUI surface so the TUI can
// evolve its rendering without churning the readline REPL.

// Tool result content has a small plain-text envelope before the raw output.
// Most file tools use two lines (TOOL_RESULT + `path=...`); bash can include a
// third `(exit=... signal=...)` line that belongs in the summary, not the body.
const TOOL_HEADER_LINES = 2;

export function toolNameFromAction(action: ModelAction): string {
  if ('bash' in action) return 'bash';
  if ('edit' in action) return 'edit';
  if ('read' in action) return 'read';
  if ('ls' in action) return 'ls';
  if ('find' in action) return 'find';
  if ('grep' in action) return 'grep';
  if ('message' in action) return 'message';
  const _exhaustive: never = action;
  return _exhaustive;
}

export function previewFromAction(action: ModelAction): string {
  if ('bash' in action) return action.bash;
  if ('edit' in action) return action.edit.path;
  if ('read' in action) {
    const r = action.read;
    if (r.start_line !== undefined || r.end_line !== undefined) {
      const start = r.start_line ?? 1;
      const end = r.end_line ?? '';
      return `${r.path}:${start}-${end}`;
    }
    return r.path;
  }
  if ('ls' in action) return action.ls.path ?? '.';
  if ('find' in action) {
    const f = action.find;
    return `${f.name}${f.path ? ` in ${f.path}` : ''}`;
  }
  if ('grep' in action) {
    const g = action.grep;
    return `${g.pattern}${g.path ? ` in ${g.path}` : ''}`;
  }
  if ('message' in action) {
    // 'message' is not a tool action; if it slipped past the runner's
    // dispatch into a preview, render empty rather than crash. The
    // exhaustiveness check below still catches new variants at compile time.
    return '';
  }
  const _exhaustive: never = action;
  return _exhaustive;
}

export function formatToolResultSummary(result: ToolResult): string {
  const bashSummary = result.tool === 'bash' ? formatBashSummary(result) : null;
  if (bashSummary) return bashSummary;

  const path = formatPathSummary(result);
  const policy = firstLine(result.meta.policy);
  const reason = firstLine(result.meta.reason);
  const error = firstLine(result.meta.error);
  const errorDetail = reason ?? error;
  let detail = path;

  if (detail && result.status === 'error' && errorDetail) {
    detail = `${detail} — ${errorDetail}`;
  }
  if (!detail && policy && reason) {
    detail = `policy=${policy} ${reason}`;
  }
  if (!detail && policy && error) {
    detail = `policy=${policy} ${error}`;
  }
  if (!detail) {
    detail = error ?? '(no details)';
  }
  return detail;
}

export function extractToolBody(result: ToolResult): string | undefined {
  // 'message' isn't a tool but be defensive — model can in principle emit one
  // and we still get a ToolResult for unknown shapes.
  const parts = result.content.split('\n');
  const headerLines = result.tool === 'bash' && isBashExitEnvelope(parts[2])
    ? TOOL_HEADER_LINES + 1
    : TOOL_HEADER_LINES;
  if (parts.length <= headerLines) return undefined;
  const body = parts.slice(headerLines).join('\n');
  return body.trim().length > 0 ? body : undefined;
}

function firstLine(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  return value.trim().split('\n')[0] ?? null;
}

function metaNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function metaBoolean(value: unknown): boolean {
  return value === true || value === 'true';
}

function formatPathSummary(result: ToolResult): string | null {
  const path = firstLine(result.meta.path);
  if (!path) return null;

  if (result.tool === 'read') {
    const start = metaNumber(result.meta.start_line);
    const end = metaNumber(result.meta.end_line);
    if (start !== null || end !== null) {
      return `${path}:${start ?? 1}-${end ?? ''}`;
    }
  }

  if (result.tool === 'find' || result.tool === 'grep') {
    const matches = metaNumber(result.meta.matches);
    if (matches !== null) {
      return `${path} — ${matches} match${matches === 1 ? '' : 'es'}`;
    }
  }

  return path;
}

function formatBashSummary(result: ToolResult): string | null {
  const command = extractBashCommand(result.content);
  if (!command) return null;

  const status = formatBashStatus(result);
  return status ? `${command} — ${status}` : command;
}

function extractBashCommand(content: string): string | null {
  const commandLine = content.split('\n').find((line) => line.startsWith('$ '));
  const command = commandLine?.slice(2).trim();
  return command ? command : null;
}

function formatBashStatus(result: ToolResult): string | null {
  const parts: string[] = [];
  if (Object.hasOwn(result.meta, 'exit')) {
    parts.push(`exit=${result.meta.exit === null ? 'null' : String(result.meta.exit)}`);
  }

  const signal = firstLine(result.meta.signal);
  if (signal && signal !== 'none') {
    parts.push(`signal=${signal}`);
  }

  if (metaBoolean(result.meta.timed_out)) {
    parts.push('timed out');
  }

  return parts.length ? parts.join(' ') : null;
}

function isBashExitEnvelope(line: string | undefined): boolean {
  return typeof line === 'string' && /^\(exit=.*\)$/.test(line.trim());
}
