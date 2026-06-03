import os from 'node:os';
import path from 'node:path';

import { readCurrentPackageVersion } from '../updates.js';
import type { UiState } from './store.js';

export type LocalReportKind = 'bug' | 'feedback';

export type LocalReportOptions = {
  kind: LocalReportKind;
  cliqVersion?: string | null;
  cliqCommit?: string | null;
  env?: Record<string, string | undefined>;
  platform?: string | null;
  arch?: string | null;
  release?: string | null;
  nodeVersion?: string | null;
  isTTY?: boolean | null;
  colorDepth?: number | null;
};

const UNKNOWN = 'unknown';
const RECENT_ERROR_LIMIT = 5;

export async function buildLocalReportMarkdown(
  state: UiState,
  options: LocalReportOptions
): Promise<string> {
  const env = options.env ?? process.env;
  const title = options.kind === 'bug' ? 'Cliq Bug Report Draft' : 'Cliq Feedback Draft';
  const promptSections =
    options.kind === 'bug'
      ? [
          ['Summary', UNKNOWN],
          ['Steps to Reproduce', UNKNOWN],
          ['Expected Behavior', UNKNOWN],
          ['Actual Behavior', UNKNOWN]
        ]
      : [
          ['Feedback', UNKNOWN],
          ['Context', UNKNOWN]
        ];

  const lines = [
    `# ${title}`,
    '',
    '> Local draft only. Cliq has not submitted or uploaded this report.',
    ''
  ];

  for (const [heading, body] of promptSections) {
    lines.push(`## ${heading}`, body, '');
  }

  lines.push(
    '## Diagnostics',
    `- Cliq version: ${await resolveCliqVersion(options)}`,
    `- Cliq commit: ${formatCommit(resolveCliqCommit(options, env))}`,
    `- OS/platform: ${formatOs(options)}`,
    `- Terminal: ${formatTerminal(env)}`,
    `- Shell: ${formatShell(env.SHELL)}`,
    `- Node.js: ${valueOrUnknown(options.nodeVersion !== undefined ? options.nodeVersion : process.version)}`,
    `- TTY: ${formatBoolean(resolveIsTTY(options))}`,
    `- Color depth: ${formatNumber(resolveColorDepth(options))}`,
    `- Provider/model: ${formatProviderModel(state)}`,
    `- Policy/mode: ${valueOrUnknown(state.policy)}`,
    `- Short session id: ${shortSessionId(state.session.id)}`,
    `- Workspace: ${workspaceLabel(state.session.cwd)}`,
    '- Recent structured errors:',
    ...formatRecentErrors(state)
  );

  return redactReportText(lines.join('\n'));
}

export function redactReportText(input: string): string {
  return input
    .replace(
      /\b(Authorization\s*[:=]\s*)(?:Bearer|Basic)?\s*[^\s,;]+/gi,
      '$1[REDACTED]'
    )
    .replace(
      /\b([A-Z][A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)[A-Z0-9_]*\s*[:=]\s*)(["']?)[^\s"'`]+(["']?)/gi,
      '$1[REDACTED]'
    )
    .replace(
      /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})\b/g,
      '[REDACTED]'
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g,
      '[REDACTED]'
    )
    .replace(
      /\b(?=[A-Za-z0-9+/]{32,}={0,2}\b)(?=[A-Za-z0-9+/=]*[A-Z])(?=[A-Za-z0-9+/=]*[a-z])(?=[A-Za-z0-9+/=]*[0-9])[A-Za-z0-9+/]{32,}={0,2}\b/g,
      '[REDACTED]'
    );
}

async function resolveCliqVersion(options: LocalReportOptions): Promise<string> {
  if (options.cliqVersion !== undefined) return valueOrUnknown(options.cliqVersion);
  return valueOrUnknown(await readCurrentPackageVersion());
}

function resolveCliqCommit(
  options: LocalReportOptions,
  env: Record<string, string | undefined>
): string {
  if (options.cliqCommit !== undefined) return valueOrUnknown(options.cliqCommit);
  return valueOrUnknown(
    env.CLIQ_COMMIT_SHA ??
      env.CLIQ_GIT_COMMIT ??
      env.GIT_COMMIT ??
      env.SOURCE_VERSION ??
      env.VERCEL_GIT_COMMIT_SHA
  );
}

function formatOs(options: LocalReportOptions): string {
  const parts = [
    valueOrNull(options.platform !== undefined ? options.platform : process.platform),
    valueOrNull(options.arch !== undefined ? options.arch : process.arch),
    valueOrNull(options.release !== undefined ? options.release : os.release())
  ];
  return parts.every((part) => part === null) ? UNKNOWN : parts.map((part) => part ?? UNKNOWN).join(' ');
}

function formatTerminal(env: Record<string, string | undefined>): string {
  const termProgram = valueOrNull(env.TERM_PROGRAM);
  const term = valueOrNull(env.TERM);
  if (termProgram && term) return `${termProgram} (${term})`;
  return termProgram ?? term ?? UNKNOWN;
}

function formatShell(shell: string | undefined): string {
  const normalized = valueOrNull(shell);
  if (!normalized) return UNKNOWN;
  return basename(normalized);
}

function resolveIsTTY(options: LocalReportOptions): boolean | null {
  if (options.isTTY !== undefined) return options.isTTY;
  return typeof process.stdout.isTTY === 'boolean' ? process.stdout.isTTY : null;
}

function resolveColorDepth(options: LocalReportOptions): number | null {
  if (options.colorDepth !== undefined) return options.colorDepth;
  try {
    return typeof process.stdout.getColorDepth === 'function' ? process.stdout.getColorDepth() : null;
  } catch {
    return null;
  }
}

function formatProviderModel(state: UiState): string {
  const provider = valueOrNull(state.model.provider);
  const model = valueOrNull(state.model.model);
  return provider && model ? `${provider}/${model}` : UNKNOWN;
}

function formatRecentErrors(state: UiState): string[] {
  const errors = state.errors.slice(-RECENT_ERROR_LIMIT);
  if (errors.length === 0) return [`- ${UNKNOWN}`];
  return errors.map((error) => {
    const code = valueOrNull(error.code);
    const label = code ? `${error.stage}:${code}` : error.stage;
    return `- [${label}] ${valueOrUnknown(error.message)}`;
  });
}

function formatCommit(value: string): string {
  if (value === UNKNOWN) return UNKNOWN;
  return /^[0-9a-f]{7,40}$/i.test(value) ? value.slice(0, 12) : value;
}

function shortSessionId(value: string): string {
  const sessionId = valueOrNull(value);
  return sessionId ? sessionId.slice(0, 12) : UNKNOWN;
}

function workspaceLabel(cwd: string): string {
  const normalized = valueOrNull(cwd)?.replace(/[\\/]+$/, '');
  if (!normalized) return UNKNOWN;
  return valueOrUnknown(basename(normalized));
}

function basename(value: string): string {
  return value.includes('\\') ? path.win32.basename(value) : path.basename(value);
}

function formatBoolean(value: boolean | null): string {
  return value === null ? UNKNOWN : String(value);
}

function formatNumber(value: number | null): string {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : UNKNOWN;
}

function valueOrUnknown(value: unknown): string {
  return valueOrNull(value) ?? UNKNOWN;
}

function valueOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}
