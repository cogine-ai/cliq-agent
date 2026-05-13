import type { PolicyMode } from '../policy/types.js';

export type SlashCommandSpec = {
  name: string;
  args?: string;
  description: string;
};

export const SLASH_COMMANDS: readonly SlashCommandSpec[] = [
  { name: '/exit', description: 'Exit the TUI and save the session' },
  { name: '/quit', description: 'Same as /exit' },
  { name: '/reset', description: 'Reset the current session (drops transcript and records)' },
  { name: '/help', description: 'Show available commands' },
  { name: '/policy', args: '<mode>', description: 'Live-swap the policy mode' }
];

const POLICY_MODES_LIST: readonly PolicyMode[] = [
  'auto',
  'confirm-write',
  'read-only',
  'confirm-bash',
  'confirm-all'
];

function isPolicyMode(value: string): value is PolicyMode {
  return (POLICY_MODES_LIST as readonly string[]).includes(value);
}

export type ParsedSlashCommand =
  | { kind: 'exit' }
  | { kind: 'reset' }
  | { kind: 'help' }
  | { kind: 'policy'; mode: PolicyMode }
  | { kind: 'unknown'; head: string }
  | { kind: 'invalid'; head: string; reason: string };

export function parseSlash(input: string): ParsedSlashCommand {
  const trimmed = input.trim();
  // Caller should have checked startsWith('/'); guard anyway.
  if (!trimmed.startsWith('/')) {
    return { kind: 'invalid', head: '', reason: 'not a slash command' };
  }
  const parts = trimmed.split(/\s+/);
  const head = parts[0]!;
  const rest = parts.slice(1);

  switch (head) {
    case '/exit':
    case '/quit':
      return { kind: 'exit' };
    case '/reset':
      return { kind: 'reset' };
    case '/help':
      return { kind: 'help' };
    case '/policy': {
      const mode = rest.join(' ').trim();
      if (!mode) {
        return {
          kind: 'invalid',
          head,
          reason: `/policy requires a mode argument: ${POLICY_MODES_LIST.join(', ')}`
        };
      }
      if (!isPolicyMode(mode)) {
        return {
          kind: 'invalid',
          head,
          reason: `unknown policy mode "${mode}"; expected one of: ${POLICY_MODES_LIST.join(', ')}`
        };
      }
      return { kind: 'policy', mode };
    }
    default:
      return { kind: 'unknown', head };
  }
}

export function matchSlash(query: string): SlashCommandSpec[] {
  if (!query.startsWith('/')) return [];
  const head = query.split(/\s+/)[0]!;
  return SLASH_COMMANDS.filter((c) => c.name.startsWith(head));
}

export function completeSlash(query: string): string | null {
  if (!query.startsWith('/')) return null;
  const head = query.split(/\s+/)[0]!;
  // Only complete the head; arg values are out of scope.
  if (query.length > head.length) return null;
  const matches = SLASH_COMMANDS.filter((c) => c.name.startsWith(head));
  if (matches.length !== 1) return null;
  const only = matches[0]!;
  return only.args ? `${only.name} ` : only.name;
}

export function buildHelpText(): string {
  const lines = ['Available slash commands:'];
  for (const cmd of SLASH_COMMANDS) {
    const display = cmd.args ? `${cmd.name} ${cmd.args}` : cmd.name;
    lines.push(`  ${display.padEnd(22)} ${cmd.description}`);
  }
  lines.push('', 'Keys:');
  lines.push('  Shift+Tab              Rotate policy mode (read-only → confirm-write → confirm-bash → auto)');
  lines.push('  Ctrl+O                 Toggle the most recent tool body');
  lines.push('  Ctrl+C                 Cancel an active turn (or clear input)');
  lines.push('  Ctrl+D                 Exit on empty input');
  return lines.join('\n');
}
