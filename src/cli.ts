import path from 'node:path';
import { stdin as input, stdout as output } from 'node:process';
import readline from 'node:readline';
import { createInterface as createPromptInterface } from 'node:readline/promises';

import { APP_DIR, DEFAULT_POLICY_MODE } from './config.js';
import { createOpenRouterClient } from './model/openrouter.js';
import { createPolicyEngine } from './policy/engine.js';
import type { PolicyMode } from './policy/types.js';
import { createRunner } from './runtime/runner.js';
import type { RuntimeHook } from './runtime/hooks.js';
import { ensureFresh, ensureSession, saveSession } from './session/store.js';

function isPolicyMode(value: string): value is PolicyMode {
  return ['auto', 'confirm-write', 'read-only', 'confirm-bash', 'confirm-all'].includes(value);
}

export function parseArgs(argv: string[]) {
  const raw = argv.slice(2);
  let policy: PolicyMode = DEFAULT_POLICY_MODE;
  const envPolicy = process.env.CLIQ_POLICY_MODE;
  if (envPolicy && isPolicyMode(envPolicy)) {
    policy = envPolicy;
  }

  const args: string[] = [];

  for (let i = 0; i < raw.length; i += 1) {
    const token = raw[i];
    if (token.startsWith('--policy=')) {
      const value = token.slice('--policy='.length);
      if (!isPolicyMode(value)) {
        throw new Error(`Unknown policy mode: ${value}`);
      }
      policy = value;
      continue;
    }

    if (token === '--policy') {
      const value = raw[i + 1] ?? '';
      if (!isPolicyMode(value)) {
        throw new Error(`Unknown policy mode: ${value}`);
      }
      policy = value;
      i += 1;
      continue;
    }

    args.push(token);
  }

  const cmd = args[0];
  if (!cmd || cmd === 'chat') return { cmd: 'chat', prompt: args.slice(1).join(' '), policy };
  if (cmd === 'run' || cmd === 'ask') return { cmd: 'chat', prompt: args.slice(1).join(' '), policy };
  if (cmd === 'reset') return { cmd, policy };
  if (cmd === 'history') return { cmd, policy };
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return { cmd: 'help', policy };
  return { cmd: 'chat', prompt: args.join(' '), policy };
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
  CLIQ_POLICY_MODE   Optional (auto | confirm-write | read-only | confirm-bash | confirm-all)
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

async function askYesNo(question: string, rl?: readline.Interface) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return false;
  }

  if (rl) {
    const answer = await new Promise<string>((resolve) => {
      rl.question(`${question} [y/N] `, resolve);
    });
    return answer.trim().toLowerCase() === 'y';
  }

  const promptRl = createPromptInterface({ input, output });
  try {
    const answer = await promptRl.question(`${question} [y/N] `);
    return answer.trim().toLowerCase() === 'y';
  } finally {
    promptRl.close();
  }
}

function createConfirmTool(rl?: readline.Interface) {
  return async (prompt: string) => await askYesNo(prompt, rl);
}

export async function runCli(argv: string[]) {
  const { cmd, prompt, policy } = parseArgs(argv) as { cmd: string; prompt?: string; policy: PolicyMode };
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

  if (prompt && prompt.trim()) {
    const runner = createRunner({
      model: createOpenRouterClient(),
      hooks: createCliHooks(),
      policy: createPolicyEngine({ mode: policy, confirm: createConfirmTool() })
    });
    const finalMessage = await runner.runTurn(session, prompt.trim());
    console.log(`\n${finalMessage}`);
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'cliq> ' });
  const runner = createRunner({
    model: createOpenRouterClient(),
    hooks: createCliHooks(),
    policy: createPolicyEngine({ mode: policy, confirm: createConfirmTool(rl) })
  });
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
