import { stdin as input, stdout as output } from 'node:process';
import readline from 'node:readline';
import { createInterface as createPromptInterface } from 'node:readline/promises';

import { DEFAULT_POLICY_MODE } from './config.js';
import { resolveModelConfig, type PartialModelConfig } from './model/config.js';
import { createModelClient } from './model/index.js';
import { isProviderName } from './model/registry.js';
import { createPolicyEngine } from './policy/engine.js';
import type { PolicyMode } from './policy/types.js';
import { createRuntimeAssembly } from './runtime/assembly.js';
import type { RuntimeEvent } from './runtime/events.js';
import { createRunner } from './runtime/runner.js';
import type { RuntimeHook } from './runtime/hooks.js';
import { ensureFresh, ensureSession, saveSession } from './session/store.js';
import type { ToolResult } from './tools/types.js';

const POLICY_MODES = ['auto', 'confirm-write', 'read-only', 'confirm-bash', 'confirm-all'] as const satisfies readonly PolicyMode[];
const POLICY_MODE_LIST = POLICY_MODES.join(', ');
const STREAMING_MODES = ['auto', 'on', 'off'] as const;

type ParsedArgsBase = {
  policy: PolicyMode;
  skills: string[];
  model: PartialModelConfig;
};

export type ParsedArgs = ParsedArgsBase & (
  | { cmd: 'chat'; prompt: string }
  | { cmd: 'reset' | 'history' | 'help'; prompt?: undefined }
);

function isPolicyMode(value: string): value is PolicyMode {
  return (POLICY_MODES as readonly string[]).includes(value);
}

function isStreamingMode(value: string) {
  return (STREAMING_MODES as readonly string[]).includes(value);
}

export class ReportedCliError extends Error {
  constructor(error: unknown) {
    super(error instanceof Error ? error.message : String(error), { cause: error });
    this.name = 'ReportedCliError';
  }
}

export function isReportedCliError(error: unknown): error is ReportedCliError {
  return error instanceof ReportedCliError;
}

export function renderUnhandledError(error: unknown) {
  if (isReportedCliError(error)) {
    return null;
  }

  return error instanceof Error ? error.message : String(error);
}

function readFlagValue(raw: string[], index: number, flag: string) {
  const value = raw[index + 1];
  if (value === undefined || value === '' || value.startsWith('--')) {
    throw new Error(`Missing value for ${flag}`);
  }

  return value;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const raw = argv.slice(2);
  let policy: PolicyMode = DEFAULT_POLICY_MODE;
  const skills: string[] = [];
  const model: PartialModelConfig = {};
  const envPolicy = process.env.CLIQ_POLICY_MODE;
  if (envPolicy !== undefined) {
    if (!isPolicyMode(envPolicy)) {
      throw new Error(`Invalid CLIQ_POLICY_MODE: ${envPolicy}; expected one of: ${POLICY_MODE_LIST}`);
    }
    policy = envPolicy;
  }

  const args: string[] = [];

  for (let i = 0; i < raw.length; i += 1) {
    const token = raw[i];
    if (token.startsWith('--policy=')) {
      const value = token.slice('--policy='.length);
      if (!value) {
        throw new Error(`Missing value for --policy; expected one of: ${POLICY_MODE_LIST}`);
      }
      if (!isPolicyMode(value)) {
        throw new Error(`Unknown policy mode: ${value}`);
      }
      policy = value;
      continue;
    }

    if (token === '--policy') {
      const value = readFlagValue(raw, i, '--policy');
      if (!isPolicyMode(value)) {
        throw new Error(`Unknown policy mode: ${value}`);
      }
      policy = value;
      i += 1;
      continue;
    }

    if (token.startsWith('--skill=')) {
      const value = token.slice('--skill='.length);
      if (!value) {
        throw new Error('Missing value for --skill');
      }
      skills.push(value);
      continue;
    }

    if (token === '--skill') {
      const value = readFlagValue(raw, i, '--skill');
      skills.push(value);
      i += 1;
      continue;
    }

    if (token.startsWith('--provider=')) {
      const value = token.slice('--provider='.length);
      if (!value) {
        throw new Error('Missing value for --provider');
      }
      if (!isProviderName(value)) {
        throw new Error(`Unknown model provider: ${value}`);
      }
      model.provider = value;
      continue;
    }

    if (token === '--provider') {
      const value = readFlagValue(raw, i, '--provider');
      if (!isProviderName(value)) {
        throw new Error(`Unknown model provider: ${value}`);
      }
      model.provider = value;
      i += 1;
      continue;
    }

    if (token.startsWith('--model=')) {
      const value = token.slice('--model='.length);
      if (!value) {
        throw new Error('Missing value for --model');
      }
      model.model = value;
      continue;
    }

    if (token === '--model') {
      model.model = readFlagValue(raw, i, '--model');
      i += 1;
      continue;
    }

    if (token.startsWith('--base-url=')) {
      const value = token.slice('--base-url='.length);
      if (!value) {
        throw new Error('Missing value for --base-url');
      }
      model.baseUrl = value;
      continue;
    }

    if (token === '--base-url') {
      model.baseUrl = readFlagValue(raw, i, '--base-url');
      i += 1;
      continue;
    }

    if (token.startsWith('--streaming=')) {
      const value = token.slice('--streaming='.length);
      if (!value) {
        throw new Error('Missing value for --streaming');
      }
      if (!isStreamingMode(value)) {
        throw new Error(`Unknown streaming mode: ${value}`);
      }
      model.streaming = value;
      continue;
    }

    if (token === '--streaming') {
      const value = readFlagValue(raw, i, '--streaming');
      if (!isStreamingMode(value)) {
        throw new Error(`Unknown streaming mode: ${value}`);
      }
      model.streaming = value;
      i += 1;
      continue;
    }

    args.push(token);
  }

  const cmd = args[0];
  if (!cmd || cmd === 'chat') return { cmd: 'chat', prompt: args.slice(1).join(' '), policy, skills, model };
  if (cmd === 'run' || cmd === 'ask') return { cmd: 'chat', prompt: args.slice(1).join(' '), policy, skills, model };
  if (cmd === 'reset') return { cmd, policy, skills, model };
  if (cmd === 'history') return { cmd, policy, skills, model };
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return { cmd: 'help', policy, skills, model };
  return { cmd: 'chat', prompt: args.join(' '), policy, skills, model };
}

export function printHelp() {
  console.log(`cliq - tiny local coding agent harness

Usage:
  cliq "task"              Run a task in the current directory
  cliq run "task"          Alias for one-shot task execution
  cliq ask "task"          Alias for one-shot task execution
  cliq chat                Start interactive chat in the current directory
  cliq reset               Clear persisted conversation for this directory
  cliq history             Print persisted session for this directory
  cliq help                Print this help
  -h, --help               Print this help

Options:
  --policy MODE            auto | confirm-write | read-only | confirm-bash | confirm-all
  --skill NAME             Activate a local skill; repeat to load multiple skills
  --provider NAME          openrouter | anthropic | openai | openai-compatible | ollama
  --model ID               Provider model id; required for openai-compatible; auto-discovered for ollama
  --base-url URL           Required for openai-compatible; optional provider override
  --streaming MODE         auto | on | off

Policy modes:
  auto                     Execute registered tools without confirmation
  confirm-write            Ask before write tools
  read-only                Allow read, ls, find, and grep only
  confirm-bash             Ask before exec tools
  confirm-all              Ask before every tool

Streaming modes:
  auto                     Use provider default; compatible endpoints may fall back
  on                       Request streaming when supported
  off                      Force non-streaming responses

Examples:
  cliq --policy read-only "inspect this repo"
  cliq --provider ollama --model qwen3:4b "inspect this repo"

Env:
  OPENROUTER_API_KEY        Required for OpenRouter
  ANTHROPIC_API_KEY         Required for Anthropic
  OPENAI_API_KEY            Required for OpenAI
  CLIQ_MODEL_API_KEY        Optional for openai-compatible
  OPENAI_COMPATIBLE_API_KEY Optional for openai-compatible
  CLIQ_MODEL_*              Optional provider/model/base URL/streaming defaults
  CLIQ_POLICY_MODE          Optional default policy mode
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

        process.stdout.write(`\n${formatToolResultLine(result)}\n`);
      }
    }
  ];
}

function firstLine(value: unknown) {
  if (typeof value !== 'string' || !value.trim()) {
    return null;
  }

  return value.trim().split('\n')[0];
}

export function formatToolResultLine(result: ToolResult) {
  const pathValue = firstLine(result.meta.path);
  const policy = firstLine(result.meta.policy);
  const reason = firstLine(result.meta.reason);
  const error = firstLine(result.meta.error);
  const errorDetail = reason ?? error;
  let detail = pathValue;

  if (detail && result.status === 'error' && errorDetail) {
    detail = `${detail} - ${errorDetail}`;
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

  return `[${result.tool ?? 'unknown'} ${result.status}] ${detail}`;
}

async function askYesNo(question: string, rl?: readline.Interface) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.warn("Confirmation skipped: non-interactive TTY, defaulting to 'no'");
    return false;
  }

  if (rl) {
    try {
      const answer = await new Promise<string>((resolve) => {
        rl.question(`${question} [y/N] `, resolve);
      });
      return answer.trim().toLowerCase() === 'y';
    } catch (error) {
      console.warn(`Confirmation prompt failed: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  let promptRl: ReturnType<typeof createPromptInterface> | undefined;
  try {
    promptRl = createPromptInterface({ input, output });
    const answer = await promptRl.question(`${question} [y/N] `);
    return answer.trim().toLowerCase() === 'y';
  } catch (error) {
    console.warn(`Confirmation prompt failed: ${error instanceof Error ? error.message : String(error)}`);
    throw error;
  } finally {
    promptRl?.close();
  }
}

function createConfirmTool(rl?: readline.Interface) {
  return async (prompt: string) => await askYesNo(prompt, rl);
}

function createCliEventSink() {
  return async (event: RuntimeEvent) => {
    if (event.type === 'model-start') {
      process.stdout.write(`\n[model ${event.provider}/${event.model}]\n`);
    } else if (event.type === 'model-progress' && event.chunks % 20 === 0) {
      process.stdout.write('.');
    } else if (event.type === 'model-end') {
      process.stdout.write('\n');
    } else if (event.type === 'error') {
      process.stderr.write(`[${event.stage} error] ${event.message}\n`);
    }
  };
}

export async function runCli(argv: string[]) {
  const { cmd, prompt, policy, skills, model: cliModel } = parseArgs(argv);
  const cwd = process.cwd();

  if (cmd === 'help') {
    printHelp();
    return;
  }

  if (cmd === 'reset') {
    await ensureFresh(cwd);
    console.log(`reset active session for ${cwd}`);
    return;
  }

  if (cmd === 'history') {
    console.log(JSON.stringify(await ensureSession(cwd), null, 2));
    return;
  }

  const session = await ensureSession(cwd);
  const assembly = await createRuntimeAssembly({
    cwd,
    session,
    policyMode: policy,
    cliSkillNames: skills
  });
  const modelConfig = await resolveModelConfig({ workspace: assembly.workspaceConfig, cli: cliModel });
  const modelClient = createModelClient(modelConfig);
  session.model = {
    provider: modelConfig.provider,
    model: modelConfig.model,
    baseUrl: modelConfig.baseUrl
  };

  if (prompt && prompt.trim()) {
    const eventSink = createCliEventSink();
    let turnSawRuntimeError = false;
    const runner = createRunner({
      model: modelClient,
      hooks: [...assembly.hooks, ...createCliHooks()],
      policy: createPolicyEngine({ mode: policy, confirm: createConfirmTool() }),
      instructions: assembly.instructions,
      async onEvent(event) {
        if (event.type === 'error') {
          turnSawRuntimeError = true;
        }
        await eventSink(event);
      }
    });

    let finalMessage: string;
    try {
      finalMessage = await runner.runTurn(session, prompt.trim());
    } catch (error) {
      if (turnSawRuntimeError) {
        throw new ReportedCliError(error);
      }
      throw error;
    }

    console.log(`\n${finalMessage}`);
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'cliq> ' });
  const eventSink = createCliEventSink();
  let turnSawRuntimeError = false;
  const runner = createRunner({
    model: modelClient,
    hooks: [...assembly.hooks, ...createCliHooks()],
    policy: createPolicyEngine({ mode: policy, confirm: createConfirmTool(rl) }),
    instructions: assembly.instructions,
    async onEvent(event) {
      if (event.type === 'error') {
        turnSawRuntimeError = true;
      }
      await eventSink(event);
    }
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
      session.model = {
        provider: modelConfig.provider,
        model: modelConfig.model,
        baseUrl: modelConfig.baseUrl
      };
      console.log('session reset');
      rl.prompt();
      continue;
    }

    try {
      turnSawRuntimeError = false;
      const finalMessage = await runner.runTurn(session, input);
      console.log(`\n${finalMessage}\n`);
    } catch (error) {
      if (!turnSawRuntimeError) {
        process.stderr.write(
          `[interactive fallback error] ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`
        );
      }
    }

    rl.prompt();
  }

  rl.close();
  await saveSession(cwd, session);
}
