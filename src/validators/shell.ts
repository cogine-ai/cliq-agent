import { spawn } from 'node:child_process';

import type { Validator } from './types.js';
import type { Severity } from '../workspace/transactions/types.js';
import { diffJsonPath, resolveTxRoot } from '../workspace/transactions/store.js';
import { resolveCliqHome } from '../session/store.js';

const STDOUT_LIMIT = 256 * 1024;
const MESSAGE_LIMIT = 2048;
const DEFAULT_TIMEOUT_MS = 60_000;

export type ShellValidatorOptions = {
  name: string;
  command: string;
  severity: Severity;
  timeoutMs?: number;
};

export function createShellValidator(opts: ShellValidatorOptions): Validator {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return {
    name: opts.name,
    defaultSeverity: opts.severity,
    async run(ctx) {
      const start = Date.now();
      const env = {
        ...process.env,
        CLIQ_TX_ID: ctx.txId,
        CLIQ_TX_DIFF_PATH: diffJsonPath(resolveTxRoot(resolveCliqHome()), ctx.txId),
        CLIQ_WORKSPACE_REAL_PATH: ctx.realCwd
      };

      const child = spawn(opts.command, {
        cwd: ctx.workspaceView,
        env,
        shell: true,
        signal: ctx.signal
      });

      let stdout = '';
      let stderr = '';
      let stdoutBytes = 0;
      let stderrBytes = 0;

      const appendCapped = (which: 'stdout' | 'stderr', chunk: Buffer) => {
        if (which === 'stdout') {
          if (stdoutBytes >= STDOUT_LIMIT) return;
          const remaining = STDOUT_LIMIT - stdoutBytes;
          const slice = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
          stdout += slice.toString('utf8');
          stdoutBytes += slice.length;
        } else {
          if (stderrBytes >= STDOUT_LIMIT) return;
          const remaining = STDOUT_LIMIT - stderrBytes;
          const slice = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
          stderr += slice.toString('utf8');
          stderrBytes += slice.length;
        }
      };

      child.stdout?.on('data', (chunk: Buffer) => appendCapped('stdout', chunk));
      child.stderr?.on('data', (chunk: Buffer) => appendCapped('stderr', chunk));

      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // best-effort: child may have already exited
        }
      }, timeoutMs);

      const exitCode: number | null = await new Promise((resolve) => {
        child.on('close', (code) => resolve(code));
        child.on('error', () => resolve(null));
      });
      clearTimeout(timer);

      const durationMs = Date.now() - start;

      if (timedOut) {
        return {
          name: opts.name,
          severity: opts.severity,
          status: 'error',
          durationMs,
          message: `timed out after ${timeoutMs}ms`
        };
      }

      if (exitCode === 0) {
        return {
          name: opts.name,
          severity: opts.severity,
          status: 'pass',
          durationMs,
          message: stdout.length > 0 ? stdout.slice(0, MESSAGE_LIMIT) : undefined
        };
      }

      const failMessage = (stderr || stdout).slice(0, MESSAGE_LIMIT);
      return {
        name: opts.name,
        severity: opts.severity,
        status: 'fail',
        durationMs,
        message: failMessage.length > 0 ? failMessage : undefined
      };
    }
  };
}
