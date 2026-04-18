import path from 'node:path';
import readline from 'node:readline';

import { APP_DIR } from './config.js';
import { createOpenRouterClient } from './model/openrouter.js';
import { createRunner } from './runtime/runner.js';
import type { RuntimeHook } from './runtime/hooks.js';
import { ensureFresh, ensureSession, saveSession } from './session/store.js';

export function parseArgs(argv: string[]) {
  const args = argv.slice(2);
  const cmd = args[0];
  if (!cmd || cmd === 'chat') return { cmd: 'chat', prompt: args.slice(1).join(' ') };
  if (cmd === 'run' || cmd === 'ask') return { cmd: 'chat', prompt: args.slice(1).join(' ') };
  if (cmd === 'reset') return { cmd };
  if (cmd === 'history') return { cmd };
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return { cmd: 'help' };
  return { cmd: 'chat', prompt: args.join(' ') };
}

export function printHelp() {
  console.log(`cliq - tiny local coding agent harness

Usage:
  cliq "task"        Run a task in the current directory
  cliq chat          Start interactive chat in the current directory
  cliq reset         Clear persisted conversation for this directory
  cliq history       Print persisted session for this directory

Env:
  OPENROUTER_API_KEY Required
`);
}

function createCliHooks(): RuntimeHook[] {
  return [
    {
      beforeTool(_session, action) {
        if ('bash' in action) {
          process.stdout.write(`\n$ ${action.bash}\n`);
        }
      },
      afterTool(_session, result) {
        if (result.tool === 'bash') {
          const output = result.content.split('\n').slice(2).join('\n');
          process.stdout.write(`${output}\n`);
          return;
        }

        process.stdout.write(`\n[${result.tool ?? 'unknown'} ${result.status}] ${result.meta.path ?? '(unknown path)'}\n`);
      }
    }
  ];
}

export async function runCli(argv: string[]) {
  const { cmd, prompt } = parseArgs(argv) as { cmd: string; prompt?: string };
  const cwd = process.cwd();

  if (cmd === 'help') {
    printHelp();
    return;
  }

  if (cmd === 'reset') {
    await ensureFresh(cwd);
    console.log(`reset session in ${path.join(cwd, APP_DIR)}`);
    return;
  }

  if (cmd === 'history') {
    console.log(JSON.stringify(await ensureSession(cwd), null, 2));
    return;
  }

  const session = await ensureSession(cwd);
  const runner = createRunner({
    model: createOpenRouterClient(),
    hooks: createCliHooks()
  });

  if (prompt && prompt.trim()) {
    const finalMessage = await runner.runTurn(session, prompt.trim());
    console.log(`\n${finalMessage}`);
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'cliq> ' });
  console.log(`cliq chat in ${session.cwd}`);
  rl.prompt();

  for await (const line of rl) {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      continue;
    }

    if (input === '/exit' || input === '/quit') {
      break;
    }

    if (input === '/reset') {
      const fresh = await ensureFresh(session.cwd);
      Object.assign(session, fresh);
      console.log('session reset');
      rl.prompt();
      continue;
    }

    try {
      const finalMessage = await runner.runTurn(session, input);
      console.log(`\n${finalMessage}\n`);
    } catch (error) {
      console.error(String(error));
    }

    rl.prompt();
  }

  rl.close();
  await saveSession(cwd, session);
}
