import type { ModelAction } from '../protocol/model/actions.js';
import type { ToolResult } from '../tools/types.js';

// Mirrors src/cli.ts:formatToolResultLine for the TUI surface so the TUI can
// evolve its rendering without churning the readline REPL.

// Tool result content has a 2-line header for bash (TOOL_RESULT line + the
// `$ <cmd>` echo) and a similar 2-line header for the file tools
// (TOOL_RESULT line + `path=<...>` line). Both shapes happen to share the
// same offset so a single constant works for all current tools; revisit if a
// tool ships a different envelope.
const TOOL_HEADER_LINES = 2;

export function toolNameFromAction(action: ModelAction): string {
  if ('bash' in action) return 'bash';
  if ('edit' in action) return 'edit';
  if ('read' in action) return 'read';
  if ('ls' in action) return 'ls';
  if ('find' in action) return 'find';
  if ('grep' in action) return 'grep';
  if ('skill' in action) return 'skill';
  if ('skillResource' in action) return 'skillResource';
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
  if ('skill' in action) return action.skill.name;
  if ('skillResource' in action) {
    const r = action.skillResource;
    return `${r.skill}:${r.path ?? '.'}`;
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
  const path = firstLine(result.meta.path);
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
  if (parts.length <= TOOL_HEADER_LINES) return undefined;
  const body = parts.slice(TOOL_HEADER_LINES).join('\n');
  return body.trim().length > 0 ? body : undefined;
}

function firstLine(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  return value.trim().split('\n')[0] ?? null;
}
