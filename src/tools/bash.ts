import { spawn } from 'node:child_process';

import { BASH_TIMEOUT_MS, MAX_OUTPUT } from '../config.js';
import {
  enforceBashPolicy,
  snapshotMtimes,
  diffMtimes,
  recordBashEffect as buildBashEffect
} from '../runtime/bash-policy.js';
import type { ToolContext, ToolDefinition, ToolResult } from './types.js';

function clip(text: string) {
  return text.length <= MAX_OUTPUT ? text : text.slice(-MAX_OUTPUT);
}

function runBashChild(action: { bash: string }, context: ToolContext): Promise<ToolResult> {
  return new Promise((resolve) => {
    const child = spawn('bash', ['-lc', action.bash], { cwd: context.cwd, env: process.env });
    let out = '';
    let timedOut = false;
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;

    const finish = (result: ToolResult) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timer);
      if (killTimer) {
        clearTimeout(killTimer);
      }
      resolve(result);
    };

    const onData = (chunk: Buffer) => {
      out += chunk.toString();
      out = clip(out);
    };

    child.stdout?.on('data', onData);
    child.stderr?.on('data', onData);

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => {
        if (!settled) {
          child.kill('SIGKILL');
        }
      }, 250);
      out = clip(`${out}\n[process timed out after ${BASH_TIMEOUT_MS}ms]`);
    }, BASH_TIMEOUT_MS);

    child.on('error', (error) => {
      finish({
        tool: 'bash',
        status: 'error',
        meta: { exit: null, signal: (error as NodeJS.ErrnoException).code ?? 'error', timed_out: false },
        content: [`TOOL_RESULT bash ERROR`, `$ ${action.bash}`, `(exit=null signal=${(error as NodeJS.ErrnoException).code ?? 'error'})`, error.message]
          .filter(Boolean)
          .join('\n')
          .trim()
      });
    });

    child.on('close', (code, signal) => {
      const status = code === 0 && !timedOut ? 'ok' : 'error';
      finish({
        tool: 'bash',
        status,
        meta: { exit: code ?? null, signal: signal ?? 'none', timed_out: timedOut },
        content: [`TOOL_RESULT bash ${status.toUpperCase()}`, `$ ${action.bash}`, `(exit=${code ?? 'null'} signal=${signal ?? 'none'})`, out]
          .filter(Boolean)
          .join('\n')
          .trim()
      });
    });
  });
}

export const bashTool: ToolDefinition<{ bash: string }> = {
  name: 'bash',
  access: 'exec',
  supports(action): action is { bash: string } {
    return typeof (action as { bash?: unknown }).bash === 'string';
  },
  async execute(action, context): Promise<ToolResult> {
    if (context.tx) {
      // The runner only invokes execute() after the PolicyEngine path has
      // already approved (preset / decision table / user confirm / hook).
      // Pass policyAlreadyApproved so the tx overlay collapses passthrough
      // and confirm to allow (no double prompt). `deny` still wins so the
      // tx-specific hard limit is preserved. See bash-policy.ts and the
      // #62-A "merge bash dual-track" commit message for the rationale.
      const decision = await enforceBashPolicy({
        policy: context.tx.bashPolicy,
        txMode: context.tx.mode,
        headless: context.tx.headless,
        policyAlreadyApproved: true
      });
      if (decision.decision === 'deny') {
        return {
          tool: 'bash',
          status: 'error',
          meta: { code: decision.code, error: decision.message },
          content: `TOOL_RESULT bash ERROR\n${decision.message}`
        };
      }

      const before = await snapshotMtimes(context.cwd);
      const result = await runBashChild(action, context);
      const after = await snapshotMtimes(context.cwd);
      const pathsChanged = diffMtimes(before, after);
      const exitCode = typeof result.meta.exit === 'number' ? result.meta.exit : (result.status === 'ok' ? 0 : 1);
      const eff = buildBashEffect({
        command: action.bash,
        exitCode,
        pathsChanged
      });
      await context.tx.recordBashEffect(eff);
      return result;
    }

    return runBashChild(action, context);
  }
};
