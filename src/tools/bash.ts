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

      const onData = (chunk: Buffer) => {
        out += chunk.toString();
        out = clip(out);
      };

      child.stdout.on('data', onData);
      child.stderr.on('data', onData);

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        out = clip(`${out}\n[process timed out after ${BASH_TIMEOUT_MS}ms]`);
      }, BASH_TIMEOUT_MS);

      child.on('close', (code, signal) => {
        clearTimeout(timer);
        const status = code === 0 && !timedOut ? 'ok' : 'error';
        resolve({
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
