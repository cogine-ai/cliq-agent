import { spawn } from 'node:child_process';

import { BASH_TIMEOUT_MS, MAX_OUTPUT } from '../config.js';
import type { ToolDefinition, ToolResult } from './types.js';

function clip(text: string) {
  return text.length <= MAX_OUTPUT ? text : text.slice(-MAX_OUTPUT);
}

export const bashTool: ToolDefinition<{ bash: string }> = {
  name: 'bash',
  supports(action): action is { bash: string } {
    return typeof (action as { bash?: unknown }).bash === 'string';
  },
  async execute(action, context): Promise<ToolResult> {
    return await new Promise((resolve) => {
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
};
