import { spawn } from 'node:child_process';

import type {
  HookCommandConfig,
  HookInput,
  HookMatcherConfig,
  HookOutput,
  HookRunResult,
  HooksConfig
} from './types.js';

export const DEFAULT_HOOK_TIMEOUT_MS = 30_000;
export const MAX_HOOK_STDIN_BYTES = 1 * 1024 * 1024;
export const MAX_HOOK_STDOUT_BYTES = 256 * 1024;
export const MAX_HOOK_STDERR_BYTES = 64 * 1024;

const TRUNCATION_MARKER = '... (truncated)';
const FIELD_PREVIEW_BYTES = 4096;

type MutableHookInput = Omit<HookInput, 'action' | 'approvalSubject'> & {
  action?: unknown;
  approvalSubject?: unknown;
  _truncated?: true;
};

export function parseMatcher(matcher: string | undefined): string[] {
  if (!matcher) return [];
  return matcher
    .split('|')
    .map((term) => term.trim())
    .filter((term) => term.length > 0);
}

export function selectHookCommands(hooks: HooksConfig, input: HookInput): HookCommandConfig[] {
  const entries = hooks[input.hookEventName] ?? [];
  return entries.flatMap((entry) => (matchesHookMatcher(entry, input) ? entry.hooks : []));
}

export type CommandHookRunResult = {
  hook: HookCommandConfig;
  result: HookRunResult;
};

export function formatHookFailureReason(result: HookRunResult) {
  if (result.status === 'denied') {
    return result.decision.reason ?? 'hook denied';
  }
  if (result.status === 'error') {
    const stderr = result.stderr.trim();
    return stderr ? `${result.error}: ${stderr}` : result.error;
  }
  return 'hook failed';
}

export async function runCommandHooks(
  hooks: HooksConfig,
  input: HookInput,
  opts: { cwd: string }
): Promise<CommandHookRunResult[]> {
  const selected = selectHookCommands(hooks, input);
  const results: CommandHookRunResult[] = [];
  for (const hook of selected) {
    results.push({ hook, result: await runHookCommand(hook, input, opts) });
  }
  return results;
}

export async function runHookCommand(
  config: HookCommandConfig,
  input: HookInput,
  opts: { cwd: string }
): Promise<HookRunResult> {
  const stdin = serializeHookInput(input);
  const stdout = createCappedCollector(MAX_HOOK_STDOUT_BYTES);
  const stderr = createCappedCollector(MAX_HOOK_STDERR_BYTES);
  const timeoutMs = config.timeoutMs ?? DEFAULT_HOOK_TIMEOUT_MS;

  return await new Promise<HookRunResult>((resolve) => {
    let settled = false;
    let timedOut = false;
    const child = spawn(config.command, { cwd: opts.cwd, shell: true });

    const resolveOnce = (result: HookRunResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(result);
    };

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => {
        if (!settled) child.kill('SIGKILL');
      }, 250).unref();
    }, timeoutMs);
    timeout.unref();

    child.stdout.on('data', (chunk: Buffer | string) => stdout.add(chunk));
    child.stderr.on('data', (chunk: Buffer | string) => stderr.add(chunk));
    child.stdin.on('error', () => undefined);
    child.on('error', (error) => {
      resolveOnce({
        status: 'error',
        command: config.command,
        error: error.message,
        stdout: stdout.text(),
        stderr: stderr.text(),
        exitCode: null,
        timedOut
      });
    });
    child.on('close', (exitCode) => {
      const out = stdout.text();
      const err = stderr.text();
      if (timedOut) {
        resolveOnce({
          status: 'error',
          command: config.command,
          error: `hook command timed out after ${timeoutMs}ms`,
          stdout: out,
          stderr: err,
          exitCode,
          timedOut: true
        });
        return;
      }

      resolveOnce(resultFromExit(config.command, exitCode, out, err));
    });

    child.stdin.end(stdin);
  });
}

function matchesHookMatcher(config: HookMatcherConfig, input: HookInput): boolean {
  const matcherTerms = parseMatcher(config.matcher);
  if (matcherTerms.length === 0) return true;
  if (
    input.hookEventName !== 'PreToolUse' &&
    input.hookEventName !== 'PostToolUse' &&
    input.hookEventName !== 'PermissionRequest'
  ) {
    return true;
  }
  if (!input.toolName) return false;
  return matcherTerms.includes(input.toolName);
}

function resultFromExit(
  command: string,
  exitCode: number | null,
  stdout: string,
  stderr: string
): HookRunResult {
  if (exitCode === 0) {
    const trimmed = stdout.trim();
    if (trimmed.length === 0) {
      return {
        status: 'ok',
        command,
        output: null,
        stdout,
        stderr,
        exitCode: 0,
        timedOut: false
      };
    }

    try {
      const output = JSON.parse(trimmed) as unknown;
      if (!isHookOutput(output)) {
        return {
          status: 'denied',
          command,
          decision: { behavior: 'deny', reason: 'invalid hook output: non-object JSON' },
          output: null,
          stdout,
          stderr,
          exitCode: 0,
          timedOut: false
        };
      }
      if (output.decision === 'deny') {
        return {
          status: 'denied',
          command,
          decision: { behavior: 'deny', reason: output.reason ?? 'hook denied' },
          output,
          stdout,
          stderr,
          exitCode: 0,
          timedOut: false
        };
      }
      return {
        status: 'ok',
        command,
        output,
        stdout,
        stderr,
        exitCode: 0,
        timedOut: false
      };
    } catch (error) {
      return {
        status: 'error',
        command,
        error: `hook command returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
        stdout,
        stderr,
        exitCode,
        timedOut: false
      };
    }
  }

  if (exitCode === 2) {
    return {
      status: 'denied',
      command,
      decision: { behavior: 'deny', reason: stderr.trim() || 'hook denied' },
      stdout,
      stderr,
      exitCode,
      timedOut: false
    };
  }

  return {
    status: 'error',
    command,
    error: `hook command exited with code ${exitCode ?? 'unknown'}`,
    stdout,
    stderr,
    exitCode,
    timedOut: false
  };
}

function isHookOutput(output: unknown): output is HookOutput {
  return typeof output === 'object' && output !== null && !Array.isArray(output);
}

function serializeHookInput(input: HookInput): string {
  let cloned = cloneJson(input) as MutableHookInput;
  let serialized = JSON.stringify(cloned);
  if (Buffer.byteLength(serialized, 'utf8') <= MAX_HOOK_STDIN_BYTES) {
    return serialized;
  }

  for (const truncate of [
    truncateToolResultContent,
    truncateAction,
    truncateApprovalSubject,
    truncateTxDiffSummary,
    truncateTxValidators
  ]) {
    truncate(cloned);
    serialized = JSON.stringify(cloned);
    if (Buffer.byteLength(serialized, 'utf8') <= MAX_HOOK_STDIN_BYTES) {
      return serialized;
    }
  }

  cloned = {
    schemaVersion: input.schemaVersion,
    hookEventName: input.hookEventName,
    sessionId: input.sessionId,
    cwd: input.cwd,
    _truncated: true
  };
  return JSON.stringify(cloned);
}

function truncateToolResultContent(input: MutableHookInput) {
  if (typeof input.toolResult?.content !== 'string') return;
  input.toolResult.content = truncateString(input.toolResult.content, FIELD_PREVIEW_BYTES);
  input.toolResult._truncated = true;
}

function truncateAction(input: MutableHookInput) {
  if (input.action === undefined) return;
  input.action = {
    _truncated: true,
    preview: truncateString(JSON.stringify(input.action), FIELD_PREVIEW_BYTES)
  };
}

function truncateApprovalSubject(input: MutableHookInput) {
  if (input.approvalSubject === undefined) return;
  input.approvalSubject = {
    _truncated: true,
    preview: truncateString(JSON.stringify(input.approvalSubject), FIELD_PREVIEW_BYTES)
  };
}

function truncateTxDiffSummary(input: MutableHookInput) {
  if (input.tx?.diffSummary === undefined) return;
  input.tx.diffSummary = {
    _truncated: true,
    preview: truncateString(JSON.stringify(input.tx.diffSummary), FIELD_PREVIEW_BYTES)
  };
}

function truncateTxValidators(input: MutableHookInput) {
  if (input.tx?.validators === undefined) return;
  input.tx.validators = {
    _truncated: true,
    preview: truncateString(JSON.stringify(input.tx.validators), FIELD_PREVIEW_BYTES)
  };
}

function truncateString(value: string, maxBytes: number): string {
  const markerBytes = Buffer.byteLength(TRUNCATION_MARKER, 'utf8');
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) return value;
  return `${Buffer.from(value, 'utf8').subarray(0, Math.max(0, maxBytes - markerBytes)).toString('utf8')}${TRUNCATION_MARKER}`;
}

function createCappedCollector(maxBytes: number) {
  const markerBytes = Buffer.byteLength(TRUNCATION_MARKER, 'utf8');
  const contentLimit = Math.max(0, maxBytes - markerBytes);
  const chunks: Buffer[] = [];
  let bytes = 0;
  let truncated = false;
  return {
    add(chunk: Buffer | string) {
      if (truncated) return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = contentLimit - bytes;
      if (buffer.length <= remaining) {
        chunks.push(buffer);
        bytes += buffer.length;
        return;
      }
      if (remaining > 0) {
        chunks.push(buffer.subarray(0, remaining));
        bytes += remaining;
      }
      truncated = true;
    },
    text() {
      const content = Buffer.concat(chunks).toString('utf8');
      return truncated ? `${content}${TRUNCATION_MARKER}` : content;
    }
  };
}

function cloneJson(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value));
}
