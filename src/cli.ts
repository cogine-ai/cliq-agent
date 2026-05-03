import { stdin as input, stdout as output } from 'node:process';
import readline from 'node:readline';
import { createInterface as createPromptInterface } from 'node:readline/promises';

import { DEFAULT_POLICY_MODE } from './config.js';
import { exportHandoff } from './handoff/export.js';
import type { HeadlessRunStatus, RuntimeEventEnvelope } from './headless/contract.js';
import { writeJsonlEvent } from './headless/jsonl.js';
import { runHeadless } from './headless/run.js';
import { resolveModelConfig, type PartialModelConfig } from './model/config.js';
import { createModelClient } from './model/index.js';
import { isProviderName } from './model/registry.js';
import type { ProviderName } from './model/types.js';
import { createPolicyEngine } from './policy/engine.js';
import type { PolicyMode } from './policy/types.js';
import { createRuntimeAssembly } from './runtime/assembly.js';
import type { RuntimeEvent } from './runtime/events.js';
import { createRunner } from './runtime/runner.js';
import type { RuntimeHook } from './runtime/hooks.js';
import {
  assertWorkspaceCheckpointRestorable,
  createCheckpoint,
  restoreWorkspaceCheckpoint,
  type CreatedSessionCheckpoint
} from './session/checkpoints.js';
import { createCompaction } from './session/compaction.js';
import { forkSessionFromCheckpoint } from './session/fork.js';
import { ensureFresh, ensureSession, saveSession } from './session/store.js';
import type { ToolResult } from './tools/types.js';

const POLICY_MODES = ['auto', 'confirm-write', 'read-only', 'confirm-bash', 'confirm-all'] as const satisfies readonly PolicyMode[];
const POLICY_MODE_LIST = POLICY_MODES.join(', ');
const STREAMING_MODES = ['auto', 'on', 'off'] as const;
const RESTORE_SCOPES = ['session', 'files', 'both'] as const;
const HELP_TOPICS = ['checkpoint', 'compact', 'handoff'] as const;

type RestoreScope = (typeof RESTORE_SCOPES)[number];
type HelpTopic = (typeof HELP_TOPICS)[number];

type ParsedArgsBase = {
  policy: PolicyMode;
  skills: string[];
  model: PartialModelConfig;
};

export type ParsedArgs = ParsedArgsBase & (
  | { cmd: 'chat'; prompt: string; jsonl?: boolean }
  | { cmd: 'checkpoint-create'; name?: string; prompt?: undefined }
  | { cmd: 'checkpoint-list'; prompt?: undefined }
  | {
      cmd: 'checkpoint-fork';
      checkpointId: string;
      name?: string;
      restoreFiles?: true;
      yes?: boolean;
      allowStagedChanges?: boolean;
      prompt?: undefined;
    }
  | {
      cmd: 'checkpoint-restore';
      checkpointId: string;
      scope: RestoreScope;
      yes: boolean;
      allowStagedChanges: boolean;
      prompt?: undefined;
    }
  | { cmd: 'compact-create'; summaryMarkdown: string; beforeCheckpointId?: string; prompt?: undefined }
  | { cmd: 'compact-list'; prompt?: undefined }
  | { cmd: 'handoff-create'; checkpointId?: string; prompt?: undefined }
  | { cmd: 'reset' | 'history'; prompt?: undefined }
  | { cmd: 'help'; topic?: HelpTopic; prompt?: undefined }
);

function isPolicyMode(value: string): value is PolicyMode {
  return (POLICY_MODES as readonly string[]).includes(value);
}

function isStreamingMode(value: string) {
  return (STREAMING_MODES as readonly string[]).includes(value);
}

function isRestoreScope(value: string): value is RestoreScope {
  return (RESTORE_SCOPES as readonly string[]).includes(value);
}

function isHelpTopic(value: string): value is HelpTopic {
  return (HELP_TOPICS as readonly string[]).includes(value);
}

function isHelpToken(value: string | undefined) {
  return value === undefined || value === 'help' || value === '--help' || value === '-h';
}

function hasHelpFlag(values: string[]) {
  return values.some((value) => value === '--help' || value === '-h');
}

export class ReportedCliError extends Error {
  readonly exitCode?: number;
  readonly status?: HeadlessRunStatus;

  constructor(error: unknown, options: { exitCode?: number; status?: HeadlessRunStatus } = {}) {
    super(error instanceof Error ? error.message : String(error), { cause: error });
    this.name = 'ReportedCliError';
    this.exitCode = options.exitCode;
    this.status = options.status;
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

export function cliExitCode(error: unknown) {
  return isReportedCliError(error) && error.exitCode !== undefined ? error.exitCode : 1;
}

function readFlagValue(raw: string[], index: number, flag: string) {
  const value = raw[index + 1];
  if (value === undefined || value === '' || value.startsWith('--')) {
    throw new Error(`Missing value for ${flag}`);
  }

  return value;
}

function parseCompactCreateArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  if (hasHelpFlag(args.slice(2))) {
    return { ...base, cmd: 'help', topic: 'compact' };
  }

  let summaryMarkdown: string | undefined;
  let beforeCheckpointId: string | undefined;

  for (let i = 2; i < args.length; i += 1) {
    const token = args[i];
    if (token.startsWith('--summary=')) {
      summaryMarkdown = token.slice('--summary='.length);
      continue;
    }

    if (token === '--summary') {
      summaryMarkdown = readFlagValue(args, i, '--summary');
      i += 1;
      continue;
    }

    if (token.startsWith('--before=')) {
      beforeCheckpointId = token.slice('--before='.length);
      continue;
    }

    if (token === '--before') {
      beforeCheckpointId = readFlagValue(args, i, '--before');
      i += 1;
      continue;
    }

    throw new Error(`Unknown compact argument: ${token}`);
  }

  if (!summaryMarkdown) {
    throw new Error('Missing value for --summary');
  }

  return {
    ...base,
    cmd: 'compact-create',
    summaryMarkdown,
    beforeCheckpointId
  };
}

function parseHandoffCreateArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  if (hasHelpFlag(args.slice(2))) {
    return { ...base, cmd: 'help', topic: 'handoff' };
  }

  let checkpointId: string | undefined;

  for (let i = 2; i < args.length; i += 1) {
    const token = args[i];
    if (token.startsWith('--checkpoint=')) {
      checkpointId = token.slice('--checkpoint='.length);
      continue;
    }

    if (token === '--checkpoint') {
      checkpointId = readFlagValue(args, i, '--checkpoint');
      i += 1;
      continue;
    }

    throw new Error(`Unknown handoff argument: ${token}`);
  }

  return {
    ...base,
    cmd: 'handoff-create',
    checkpointId
  };
}

function parseCheckpointRestoreArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  if (hasHelpFlag(args.slice(2))) {
    return { ...base, cmd: 'help', topic: 'checkpoint' };
  }

  const checkpointId = args[2];
  if (!checkpointId) {
    throw new Error('Missing checkpoint id for checkpoint restore');
  }

  let scope: RestoreScope = 'session';
  let yes = false;
  let allowStagedChanges = false;

  for (let i = 3; i < args.length; i += 1) {
    const token = args[i];
    if (token.startsWith('--scope=')) {
      const value = token.slice('--scope='.length);
      if (!isRestoreScope(value)) {
        throw new Error(`Unknown restore scope: ${value}`);
      }
      scope = value;
      continue;
    }

    if (token === '--scope') {
      const value = readFlagValue(args, i, '--scope');
      if (!isRestoreScope(value)) {
        throw new Error(`Unknown restore scope: ${value}`);
      }
      scope = value;
      i += 1;
      continue;
    }

    if (token === '--yes') {
      yes = true;
      continue;
    }

    if (token === '--allow-staged') {
      allowStagedChanges = true;
      continue;
    }

    throw new Error(`Unknown restore argument: ${token}`);
  }

  return {
    ...base,
    cmd: 'checkpoint-restore',
    checkpointId,
    scope,
    yes,
    allowStagedChanges
  };
}

function ensureNoExtraArgs(args: string[], startIndex: number, command: string) {
  const extra = args[startIndex];
  if (extra !== undefined) {
    throw new Error(`Unknown ${command} argument: ${extra}`);
  }
}

function parseCheckpointArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  const action = args[1];
  if (isHelpToken(action)) {
    return { ...base, cmd: 'help', topic: 'checkpoint' };
  }

  if (action === 'create') {
    if (hasHelpFlag(args.slice(2))) {
      return { ...base, cmd: 'help', topic: 'checkpoint' };
    }
    const name = args.slice(2).join(' ').trim();
    return { ...base, cmd: 'checkpoint-create', name: name || undefined };
  }

  if (action === 'list') {
    if (hasHelpFlag(args.slice(2))) {
      return { ...base, cmd: 'help', topic: 'checkpoint' };
    }
    ensureNoExtraArgs(args, 2, 'checkpoint list');
    return { ...base, cmd: 'checkpoint-list' };
  }

  if (action === 'fork') {
    if (hasHelpFlag(args.slice(2))) {
      return { ...base, cmd: 'help', topic: 'checkpoint' };
    }
    const checkpointId = args[2];
    if (!checkpointId) {
      throw new Error('Missing checkpoint id for checkpoint fork');
    }
    const nameParts: string[] = [];
    let restoreFiles = false;
    let yes = false;
    let allowStagedChanges = false;

    for (let i = 3; i < args.length; i += 1) {
      const token = args[i];
      if (token === '--restore-files') {
        restoreFiles = true;
        continue;
      }

      if (token === '--yes') {
        yes = true;
        continue;
      }

      if (token === '--allow-staged') {
        allowStagedChanges = true;
        continue;
      }

      if (token.startsWith('--')) {
        throw new Error(`Unknown checkpoint fork argument: ${token}`);
      }

      nameParts.push(token);
    }

    if (yes && !restoreFiles) {
      throw new Error('checkpoint fork --yes requires --restore-files');
    }
    if (allowStagedChanges && !restoreFiles) {
      throw new Error('checkpoint fork --allow-staged requires --restore-files');
    }

    const name = nameParts.join(' ').trim();
    return {
      ...base,
      cmd: 'checkpoint-fork',
      checkpointId,
      ...(restoreFiles
        ? { restoreFiles: true as const, yes, ...(allowStagedChanges ? { allowStagedChanges } : {}) }
        : {}),
      name: name || undefined
    };
  }

  if (action === 'restore') {
    return parseCheckpointRestoreArgs(args, base);
  }

  throw new Error(`Unknown checkpoint action: ${action}. Run "cliq checkpoint help".`);
}

function parseCompactGroupArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  const action = args[1];
  if (isHelpToken(action)) {
    return { ...base, cmd: 'help', topic: 'compact' };
  }

  if (action === 'create') {
    return parseCompactCreateArgs(args, base);
  }

  if (action === 'list') {
    if (hasHelpFlag(args.slice(2))) {
      return { ...base, cmd: 'help', topic: 'compact' };
    }
    ensureNoExtraArgs(args, 2, 'compact list');
    return { ...base, cmd: 'compact-list' };
  }

  throw new Error(`Unknown compact action: ${action}. Run "cliq compact help".`);
}

function parseHandoffGroupArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  const action = args[1];
  if (isHelpToken(action)) {
    return { ...base, cmd: 'help', topic: 'handoff' };
  }

  if (action === 'create') {
    return parseHandoffCreateArgs(args, base);
  }

  throw new Error(`Unknown handoff action: ${action}. Run "cliq handoff help".`);
}

function parseRunArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  const promptParts: string[] = [];
  let jsonl = false;
  let parsingFlags = true;

  for (let i = 1; i < args.length; i += 1) {
    const token = args[i]!;
    if (parsingFlags && token === '--jsonl') {
      jsonl = true;
      continue;
    }
    if (parsingFlags && token.startsWith('--jsonl=')) {
      throw new Error('--jsonl does not accept a value');
    }
    parsingFlags = false;
    promptParts.push(token);
  }

  const prompt = promptParts.join(' ').trim();
  if (!prompt) {
    throw new Error('Missing prompt for cliq run/ask');
  }

  return { ...base, cmd: 'chat', prompt, ...(jsonl ? { jsonl } : {}) };
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
  const base: ParsedArgsBase = { policy, skills, model };
  const hasJsonlArg = args.includes('--jsonl') || args.some((arg) => arg.startsWith('--jsonl='));
  if (hasJsonlArg && cmd !== 'run' && cmd !== 'ask') {
    throw new Error('--jsonl is only supported with cliq run --jsonl "task"');
  }
  if (!cmd || cmd === 'chat') {
    return { cmd: 'chat', prompt: args.slice(1).join(' '), policy, skills, model };
  }
  if (cmd === 'run' || cmd === 'ask') return parseRunArgs(args, base);
  if (cmd === 'checkpoint') return parseCheckpointArgs(args, base);
  if (cmd === 'compact') return parseCompactGroupArgs(args, base);
  if (cmd === 'handoff') return parseHandoffGroupArgs(args, base);
  if (cmd === 'checkpoints') {
    throw new Error('Command changed. Use "cliq checkpoint list".');
  }
  if (cmd === 'compactions') {
    throw new Error('Command changed. Use "cliq compact list".');
  }
  if (cmd === 'fork') {
    throw new Error('Command changed. Use "cliq checkpoint fork <checkpoint-id> [name]".');
  }
  if (cmd === 'restore') {
    throw new Error('Command changed. Use "cliq checkpoint restore <checkpoint-id> --scope session|files|both".');
  }
  if (cmd === 'reset') return { cmd, policy, skills, model };
  if (cmd === 'history') return { cmd, policy, skills, model };
  if (cmd === 'help') {
    const topic = args[1];
    if (topic === undefined) {
      return { cmd: 'help', policy, skills, model };
    }
    if (!isHelpTopic(topic)) {
      throw new Error(`Unknown help topic: ${topic}. Expected one of: ${HELP_TOPICS.join(', ')}`);
    }
    ensureNoExtraArgs(args, 2, 'help');
    return { cmd: 'help', topic, policy, skills, model };
  }
  if (cmd === '--help' || cmd === '-h') return { cmd: 'help', policy, skills, model };
  return { cmd: 'chat', prompt: args.join(' '), policy, skills, model };
}

function printCheckpointHelp() {
  console.log(`cliq checkpoint - manage session and workspace checkpoints

Usage:
  cliq checkpoint create [name]              Create a manual checkpoint
  cliq checkpoint list                       Print session checkpoints
  cliq checkpoint restore CHECKPOINT         Restore session history from a checkpoint
  cliq checkpoint restore CHECKPOINT --scope session|files|both [--yes] [--allow-staged]
  cliq checkpoint fork CHECKPOINT [name]     Fork the active session from a checkpoint
  cliq checkpoint fork CHECKPOINT [name] --restore-files --yes [--allow-staged]
  cliq checkpoint help                       Print this help

Notes:
  restore --scope session                    Creates a new active session from the checkpoint prefix
  restore --scope files --yes                Restores workspace files without changing the Git index
  restore --scope both --yes                 Restores files and creates a new active session
  --allow-staged                             Allows file restore when staged changes are present
`);
}

function printCompactHelp() {
  console.log(`cliq compact - manage manual context compaction

Usage:
  cliq compact create --summary MARKDOWN     Create a manual compaction summary
  cliq compact create --summary MARKDOWN --before CHECKPOINT
  cliq compact list                          Print session compactions
  cliq compact help                          Print this help

Notes:
  create                                    Supersedes the previous active compaction only after writing the new artifact
  list                                      Shows active and superseded compaction artifacts
`);
}

function printHandoffHelp() {
  console.log(`cliq handoff - export handoff artifacts

Usage:
  cliq handoff create                        Export a handoff for the current session
  cliq handoff create --checkpoint CHECKPOINT
  cliq handoff help                          Print this help

Notes:
  create                                    Writes JSON and Markdown handoff artifacts under CLIQ_HOME
  --checkpoint                              Uses an existing checkpoint instead of creating a handoff checkpoint
`);
}

export function printHelp(topic?: HelpTopic) {
  if (topic === 'checkpoint') {
    printCheckpointHelp();
    return;
  }

  if (topic === 'compact') {
    printCompactHelp();
    return;
  }

  if (topic === 'handoff') {
    printHandoffHelp();
    return;
  }

  console.log(`cliq - tiny local coding agent harness

Usage:
  cliq "task"              Run a task in the current directory
  cliq run "task"          Alias for one-shot task execution
  cliq run --jsonl "task"  Emit machine-readable JSONL runtime events
  cliq ask "task"          Alias for one-shot task execution
  cliq chat                Start interactive chat in the current directory
  cliq reset               Clear persisted conversation for this directory
  cliq history             Print persisted session for this directory
  cliq checkpoint create   Create a manual checkpoint
  cliq checkpoint list     Print session checkpoints
  cliq checkpoint restore  Restore session or files from a checkpoint
  cliq checkpoint fork     Fork the current session from a checkpoint
  cliq compact create      Create a manual compaction summary
  cliq compact list        Print session compactions
  cliq handoff create      Export a handoff artifact
  cliq checkpoint help     Print checkpoint command help
  cliq compact help        Print compact command help
  cliq handoff help        Print handoff command help
  cliq help                Print this help
  cliq help TOPIC          Print help for checkpoint, compact, or handoff
  -h, --help               Print this help

Options:
  --policy MODE            auto | confirm-write | read-only | confirm-bash | confirm-all
  --skill NAME             Activate a local skill; repeat to load multiple skills
  --provider NAME          openrouter | anthropic | openai | openai-compatible | ollama
  --model ID               Provider model id; required for openai-compatible; auto-discovered for ollama
  --base-url URL           Required for openai-compatible; optional provider override
  --streaming MODE         auto | on | off
  --jsonl                  With cliq run only, write structured JSONL events to stdout

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
    } else if (event.type === 'compact-end') {
      process.stderr.write(`[compact] created ${event.artifactId}\n`);
    } else if (event.type === 'compact-error') {
      process.stderr.write(`[compact ${event.trigger} error] ${event.message}\n`);
    } else if (event.type === 'error') {
      process.stderr.write(`[${event.stage} error] ${event.message}\n`);
    }
  };
}

async function renderHeadlessEventToCli(
  event: RuntimeEventEnvelope,
  eventSink: ReturnType<typeof createCliEventSink>
) {
  if (event.type === 'run-start' || event.type === 'run-end') {
    return;
  }

  if (event.type === 'model-start') {
    const payload = event.payload as { provider: ProviderName; model: string; streaming: boolean };
    await eventSink({
      type: 'model-start',
      provider: payload.provider,
      model: payload.model,
      streaming: payload.streaming
    });
    return;
  }

  if (event.type === 'model-progress') {
    const payload = event.payload as { chunks: number; chars: number };
    await eventSink({ type: 'model-progress', chunks: payload.chunks, chars: payload.chars });
    return;
  }

  if (event.type === 'model-end') {
    const payload = event.payload as { provider: ProviderName; model: string };
    await eventSink({ type: 'model-end', provider: payload.provider, model: payload.model });
    return;
  }

  if (event.type === 'compact-end') {
    const payload = event.payload as {
      artifactId: string;
      estimatedTokensBefore: number;
      estimatedTokensAfter: number;
    };
    await eventSink({ type: 'compact-end', ...payload });
    return;
  }

  if (event.type === 'compact-error') {
    const payload = event.payload as { trigger: 'threshold' | 'overflow'; message: string };
    await eventSink({ type: 'compact-error', trigger: payload.trigger, message: payload.message });
    return;
  }

  if (event.type === 'error') {
    const payload = event.payload as { stage: string; message: string };
    process.stderr.write(`[${payload.stage} error] ${payload.message}\n`);
  }
}

function workspaceSnapshotUnavailableMessage(checkpoint: CreatedSessionCheckpoint) {
  const workspaceCheckpoint = checkpoint.workspaceCheckpoint;
  if (workspaceCheckpoint.kind !== 'unavailable') {
    return null;
  }

  return `workspace snapshot unavailable: ${workspaceCheckpoint.reason}${
    workspaceCheckpoint.error ? ` (${workspaceCheckpoint.error})` : ''
  }`;
}

function renderCreatedCheckpointMessage(checkpoint: CreatedSessionCheckpoint) {
  const unavailable = workspaceSnapshotUnavailableMessage(checkpoint);
  if (unavailable) {
    process.stderr.write(`[checkpoint warning] ${unavailable}\n`);
  }
  return [
    `created checkpoint ${checkpoint.id}${checkpoint.name ? ` (${checkpoint.name})` : ''}`,
    unavailable ? ` (${unavailable})` : ''
  ].join('');
}

function defaultCompactEndIndex(recordCount: number) {
  if (recordCount < 2) {
    throw new Error('compact requires at least two session records so one raw tail record can remain');
  }
  return recordCount - 1;
}

function compactEndIndexForSession(recordCount: number, checkpoint?: { id: string; recordIndex: number }) {
  const endIndexExclusive = checkpoint?.recordIndex ?? defaultCompactEndIndex(recordCount);
  if (checkpoint && (endIndexExclusive <= 0 || endIndexExclusive >= recordCount)) {
    throw new Error(`checkpoint ${checkpoint.id} does not leave a compactable range`);
  }
  return endIndexExclusive;
}

async function createRestoreSafetyCheckpoint(cwd: string, session: Awaited<ReturnType<typeof ensureSession>>, checkpointId: string) {
  await createCheckpoint(cwd, session, {
    kind: 'restore-safety',
    name: `before restore ${checkpointId}`
  });
}

async function prepareWorkspaceRestore(
  cwd: string,
  session: Awaited<ReturnType<typeof ensureSession>>,
  checkpointId: string,
  workspaceCheckpointId: string,
  allowStagedChanges?: boolean
) {
  await assertWorkspaceCheckpointRestorable(cwd, workspaceCheckpointId, { allowStagedChanges });
  await createRestoreSafetyCheckpoint(cwd, session, checkpointId);
}

export async function runCli(argv: string[]) {
  const parsed = parseArgs(argv);
  const { cmd, prompt, policy, skills, model: cliModel } = parsed;
  const cwd = process.cwd();

  if (cmd === 'help') {
    printHelp(parsed.topic);
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

  if (parsed.cmd === 'checkpoint-create') {
    const session = await ensureSession(cwd);
    const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual', name: parsed.name });
    console.log(renderCreatedCheckpointMessage(checkpoint));
    return;
  }

  if (parsed.cmd === 'checkpoint-list') {
    const session = await ensureSession(cwd);
    console.log(JSON.stringify(session.checkpoints, null, 2));
    return;
  }

  if (parsed.cmd === 'compact-create') {
    const session = await ensureSession(cwd);
    const checkpoint = parsed.beforeCheckpointId
      ? session.checkpoints.find((candidate) => candidate.id === parsed.beforeCheckpointId)
      : undefined;
    if (parsed.beforeCheckpointId && !checkpoint) {
      throw new Error(`checkpoint not found: ${parsed.beforeCheckpointId}`);
    }
    const artifact = await createCompaction(cwd, session, {
      endIndexExclusive: compactEndIndexForSession(session.records.length, checkpoint),
      anchorCheckpointId: checkpoint?.id,
      summaryMarkdown: parsed.summaryMarkdown
    });
    console.log(`created compaction ${artifact.id}`);
    return;
  }

  if (parsed.cmd === 'compact-list') {
    const session = await ensureSession(cwd);
    console.log(JSON.stringify(session.compactions, null, 2));
    return;
  }

  if (parsed.cmd === 'checkpoint-fork') {
    const session = await ensureSession(cwd);
    if (parsed.restoreFiles) {
      const checkpoint = session.checkpoints.find((candidate) => candidate.id === parsed.checkpointId);
      if (!checkpoint) {
        throw new Error(`checkpoint not found: ${parsed.checkpointId}`);
      }
      if (!parsed.yes) {
        throw new Error('checkpoint fork --restore-files requires --yes in non-interactive CLI mode');
      }
      if (!checkpoint.workspaceCheckpointId) {
        throw new Error(`checkpoint has no workspace snapshot: ${parsed.checkpointId}`);
      }
      await prepareWorkspaceRestore(
        cwd,
        session,
        parsed.checkpointId,
        checkpoint.workspaceCheckpointId,
        parsed.allowStagedChanges
      );
      await restoreWorkspaceCheckpoint(cwd, checkpoint.workspaceCheckpointId, {
        allowStagedChanges: parsed.allowStagedChanges
      });
    }

    const child = await forkSessionFromCheckpoint(cwd, session, parsed.checkpointId, { name: parsed.name });
    console.log(`forked session ${child.id} from ${parsed.checkpointId}`);
    return;
  }

  if (parsed.cmd === 'checkpoint-restore') {
    const session = await ensureSession(cwd);
    const checkpoint = session.checkpoints.find((candidate) => candidate.id === parsed.checkpointId);
    if (!checkpoint) {
      throw new Error(`checkpoint not found: ${parsed.checkpointId}`);
    }

    if (parsed.scope === 'files' || parsed.scope === 'both') {
      if (!parsed.yes) {
        throw new Error('restore files requires --yes in non-interactive CLI mode');
      }
      if (!checkpoint.workspaceCheckpointId) {
        throw new Error(`checkpoint has no workspace snapshot: ${parsed.checkpointId}`);
      }
      await prepareWorkspaceRestore(
        cwd,
        session,
        parsed.checkpointId,
        checkpoint.workspaceCheckpointId,
        parsed.allowStagedChanges
      );
      await restoreWorkspaceCheckpoint(cwd, checkpoint.workspaceCheckpointId, {
        allowStagedChanges: parsed.allowStagedChanges
      });
    }

    if (parsed.scope === 'session' || parsed.scope === 'both') {
      const child = await forkSessionFromCheckpoint(cwd, session, parsed.checkpointId, {
        name: `restore ${parsed.checkpointId}`
      });
      console.log(`restored session ${child.id} from ${parsed.checkpointId}`);
      return;
    }

    console.log(`restored files from ${parsed.checkpointId}`);
    return;
  }

  if (parsed.cmd === 'handoff-create') {
    const session = await ensureSession(cwd);
    const artifact = await exportHandoff(cwd, session, { checkpointId: parsed.checkpointId });
    console.log(`created handoff ${artifact.id} at ${artifact.paths.markdown}`);
    return;
  }

  if (prompt && prompt.trim()) {
    if (parsed.jsonl) {
      const output = await runHeadless(
        {
          cwd,
          prompt: prompt.trim(),
          policy,
          skills,
          model: cliModel
        },
        {
          onEvent(event) {
            writeJsonlEvent(event);
          }
        }
      );
      if (output.exitCode !== 0) {
        throw new ReportedCliError(output.error?.message ?? `headless run failed with exit code ${output.exitCode}`, {
          exitCode: output.exitCode,
          status: output.status
        });
      }
      return;
    }

    const eventSink = createCliEventSink();
    let finalMessage = '';
    const output = await runHeadless(
      {
        cwd,
        prompt: prompt.trim(),
        policy,
        skills,
        model: cliModel
      },
      {
        hooks: createCliHooks(),
        confirm: createConfirmTool(),
        async onEvent(event) {
          if (event.type === 'final') {
            finalMessage = (event.payload as { message: string }).message;
            return;
          }
          await renderHeadlessEventToCli(event, eventSink);
        }
      }
    );

    if (output.status !== 'completed') {
      throw new ReportedCliError(output.error?.message ?? 'headless run failed', {
        exitCode: output.exitCode,
        status: output.status
      });
    }
    console.log(`\n${finalMessage || output.finalMessage || '(no content)'}`);
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

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'cliq> ' });
  const eventSink = createCliEventSink();
  let turnSawRuntimeError = false;
  const runner = createRunner({
    model: modelClient,
    hooks: [...assembly.hooks, ...createCliHooks()],
    policy: createPolicyEngine({ mode: policy, confirm: createConfirmTool(rl) }),
    instructions: assembly.instructions,
    autoCompact: {
      config: assembly.workspaceConfig.autoCompact,
      modelConfig
    },
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
