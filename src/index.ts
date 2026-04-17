#!/usr/bin/env node
import { promises as fs } from 'fs';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import crypto from 'crypto';

const MODEL = 'anthropic/claude-sonnet-4.6';
const APP_DIR = '.cliq';
const SESSION_FILE = 'session.json';
const MAX_LOOPS = 24;
const MAX_OUTPUT = 12000;
const BASH_TIMEOUT_MS = 60_000;
const SESSION_VERSION = 2;

const SYSTEM = `You are a tiny coding agent inside a local CLI harness.
Return exactly one JSON object and nothing else.

Allowed response shapes:
- {"bash":"<shell command>"}
- {"edit":{"path":"<relative-or-absolute-path>","old_text":"<exact old text>","new_text":"<replacement text>"}}
- {"message":"<final user-facing response>"}

Rules:
- The workspace root is the current working directory. Commands run there.
- Prefer {"edit":...} for precise single-file text replacements when it is simpler and safer than shell editing.
- Use {"bash":...} for inspection, tests, formatting, file creation, multi-step shell work, or anything not covered by exact replacement.
- Paths should normally be relative to the workspace root.
- old_text must match exactly once. If it does not, inspect first and recover.
- Keep going until the task is complete or you are blocked.
- When finished, respond with {"message":"..."} summarizing what changed and any verification.
- Do not wrap JSON in markdown fences.
- Do not emit explanatory text before or after the JSON.`;

type ChatMessage = {
  role: 'system' | 'user' | 'assistant';
  content: string;
};

type SessionRecord =
  | {
      id: string;
      ts: string;
      kind: 'system' | 'user';
      role: 'system' | 'user';
      content: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'assistant';
      role: 'assistant';
      content: string;
      action: ModelAction | null;
    }
  | {
      id: string;
      ts: string;
      kind: 'tool';
      role: 'user';
      tool: 'bash' | 'edit';
      status: 'ok' | 'error';
      content: string;
      meta?: Record<string, string | number | boolean | null>;
    };

type Session = {
  version: number;
  app: 'cliq';
  model: string;
  cwd: string;
  createdAt: string;
  updatedAt: string;
  lifecycle: {
    status: 'idle' | 'running';
    turn: number;
    lastUserInputAt?: string;
    lastAssistantOutputAt?: string;
  };
  records: SessionRecord[];
};

type ModelAction =
  | { bash: string }
  | { edit: { path: string; old_text: string; new_text: string } }
  | { message: string };

type OpenRouterResp = {
  choices: Array<{
    message: {
      role: 'assistant';
      content?: string;
    };
  }>;
};

function sessionPath(cwd: string) {
  return path.join(cwd, APP_DIR, SESSION_FILE);
}

function makeId(prefix: string) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function nowIso() {
  return new Date().toISOString();
}

function createSession(cwd: string): Session {
  const now = nowIso();
  return {
    version: SESSION_VERSION,
    app: 'cliq',
    model: MODEL,
    cwd,
    createdAt: now,
    updatedAt: now,
    lifecycle: { status: 'idle', turn: 0 },
    records: [
      {
        id: makeId('sys'),
        ts: now,
        kind: 'system',
        role: 'system',
        content: SYSTEM
      }
    ]
  };
}

function isSession(value: unknown): value is Session {
  return !!value && typeof value === 'object' && Array.isArray((value as Session).records);
}

async function saveSession(cwd: string, session: Session) {
  session.updatedAt = nowIso();
  const p = sessionPath(cwd);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify(session, null, 2));
}

function migrateLegacySession(cwd: string, legacy: { createdAt?: string; updatedAt?: string; messages?: Array<{ role?: string; content?: string | null; name?: string }> }): Session {
  const session = createSession(cwd);
  session.createdAt = legacy.createdAt ?? session.createdAt;
  session.updatedAt = legacy.updatedAt ?? session.updatedAt;
  session.records = [];

  for (const message of legacy.messages ?? []) {
    const ts = nowIso();
    if (message.role === 'system' && typeof message.content === 'string') {
      session.records.push({ id: makeId('sys'), ts, kind: 'system', role: 'system', content: message.content });
    } else if (message.role === 'user' && typeof message.content === 'string') {
      session.records.push({ id: makeId('usr'), ts, kind: 'user', role: 'user', content: message.content });
    } else if (message.role === 'assistant') {
      session.records.push({
        id: makeId('ast'),
        ts,
        kind: 'assistant',
        role: 'assistant',
        content: message.content ?? '',
        action: null
      });
    } else if (message.role === 'tool') {
      session.records.push({
        id: makeId('tool'),
        ts,
        kind: 'tool',
        role: 'user',
        tool: message.name === 'edit' ? 'edit' : 'bash',
        status: 'ok',
        content: message.content ?? ''
      });
    }
  }

  if (session.records.length === 0 || session.records[0]?.kind !== 'system') {
    session.records.unshift({
      id: makeId('sys'),
      ts: nowIso(),
      kind: 'system',
      role: 'system',
      content: SYSTEM
    });
  }

  return session;
}

async function ensureSession(cwd: string): Promise<Session> {
  const p = sessionPath(cwd);
  await fs.mkdir(path.dirname(p), { recursive: true });
  try {
    const raw = JSON.parse(await fs.readFile(p, 'utf8')) as unknown;
    if (isSession(raw)) return raw;
    const migrated = migrateLegacySession(cwd, raw as any);
    await saveSession(cwd, migrated);
    return migrated;
  } catch {
    const session = createSession(cwd);
    await saveSession(cwd, session);
    return session;
  }
}

async function appendRecord(cwd: string, session: Session, record: SessionRecord) {
  session.records.push(record);
  await saveSession(cwd, session);
}

function parseArgs(argv: string[]) {
  const args = argv.slice(2);
  const cmd = args[0];
  if (!cmd || cmd === 'chat') return { cmd: 'chat', prompt: args.slice(1).join(' ') };
  if (cmd === 'run' || cmd === 'ask') return { cmd: 'chat', prompt: args.slice(1).join(' ') };
  if (cmd === 'reset') return { cmd };
  if (cmd === 'history') return { cmd };
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return { cmd: 'help' };
  return { cmd: 'chat', prompt: args.join(' ') };
}

function printHelp() {
  console.log(`cliq - tiny local coding agent harness\n\nUsage:\n  cliq "task"        Run a task in the current directory\n  cliq chat          Start interactive chat in the current directory\n  cliq reset         Clear persisted conversation for this directory\n  cliq history       Print persisted session for this directory\n\nEnv:\n  OPENROUTER_API_KEY Required\n`);
}

function buildChatMessages(session: Session): ChatMessage[] {
  return session.records.map((record) => {
    if (record.kind === 'tool') {
      return {
        role: 'user',
        content: record.content
      };
    }
    return {
      role: record.role,
      content: record.content
    };
  });
}

async function callOpenRouter(messages: ChatMessage[]): Promise<string> {
  const key = process.env.OPENROUTER_API_KEY;
  if (!key) throw new Error('OPENROUTER_API_KEY is required');
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${key}`,
      'HTTP-Referer': 'https://local.cliq',
      'X-Title': 'cliq-agent'
    },
    body: JSON.stringify({
      model: MODEL,
      messages
    })
  });
  if (!res.ok) throw new Error(`OpenRouter error ${res.status}: ${await res.text()}`);
  const json = (await res.json()) as OpenRouterResp;
  return json.choices[0]?.message?.content?.trim() ?? '';
}

function parseModelAction(content: string): ModelAction {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(`Model returned non-JSON content:\n${content}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Model returned invalid action object:\n${content}`);
  }

  const keys = Object.keys(parsed as Record<string, unknown>);
  if (keys.length !== 1) throw new Error(`Model action must contain exactly one top-level key:\n${content}`);

  if (typeof (parsed as { bash?: unknown }).bash === 'string') {
    return { bash: (parsed as { bash: string }).bash };
  }

  if (typeof (parsed as { message?: unknown }).message === 'string') {
    return { message: (parsed as { message: string }).message };
  }

  const edit = (parsed as { edit?: unknown }).edit;
  if (edit && typeof edit === 'object' && !Array.isArray(edit)) {
    const e = edit as Record<string, unknown>;
    if (typeof e.path === 'string' && typeof e.old_text === 'string' && typeof e.new_text === 'string') {
      return { edit: { path: e.path, old_text: e.old_text, new_text: e.new_text } };
    }
  }

  throw new Error(`Model returned unsupported action:\n${content}`);
}

function clip(text: string) {
  return text.length <= MAX_OUTPUT ? text : text.slice(-MAX_OUTPUT);
}

async function runBash(command: string, cwd: string): Promise<{ status: 'ok' | 'error'; content: string; meta: Record<string, string | number | boolean | null> }> {
  return await new Promise((resolve) => {
    const child = spawn('bash', ['-lc', command], { cwd, env: process.env });
    let out = '';
    let timedOut = false;
    const onData = (d: Buffer) => {
      out += d.toString();
      out = clip(out);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      out += `\n[process timed out after ${BASH_TIMEOUT_MS}ms]`;
      out = clip(out);
    }, BASH_TIMEOUT_MS);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const status = code === 0 && !timedOut ? 'ok' : 'error';
      resolve({
        status,
        meta: { exit: code ?? null, signal: signal ?? 'none', timed_out: timedOut },
        content: [`TOOL_RESULT bash ${status.toUpperCase()}`, `$ ${command}`, `(exit=${code ?? 'null'} signal=${signal ?? 'none'})`, out].filter(Boolean).join('\n').trim()
      });
    });
  });
}

async function runEdit(edit: { path: string; old_text: string; new_text: string }, cwd: string): Promise<{ status: 'ok' | 'error'; content: string; meta: Record<string, string | number | boolean | null> }> {
  const target = path.isAbsolute(edit.path) ? edit.path : path.join(cwd, edit.path);
  try {
    const current = await fs.readFile(target, 'utf8');
    const matches = current.split(edit.old_text).length - 1;
    if (matches !== 1) {
      return {
        status: 'error',
        meta: { path: path.relative(cwd, target) || edit.path, matches },
        content: `TOOL_RESULT edit ERROR\npath=${path.relative(cwd, target) || edit.path}\nexpected old_text to match exactly once, but matched ${matches} times`
      };
    }
    const next = current.replace(edit.old_text, edit.new_text);
    await fs.writeFile(target, next, 'utf8');
    return {
      status: 'ok',
      meta: { path: path.relative(cwd, target) || edit.path },
      content: `TOOL_RESULT edit OK\npath=${path.relative(cwd, target) || edit.path}\nreplaced exact text span successfully`
    };
  } catch (error) {
    return {
      status: 'error',
      meta: { path: path.relative(cwd, target) || edit.path },
      content: `TOOL_RESULT edit ERROR\npath=${path.relative(cwd, target) || edit.path}\n${error instanceof Error ? error.message : String(error)}`
    };
  }
}

async function runTurn(session: Session, userInput: string): Promise<string> {
  const cwd = session.cwd;
  session.lifecycle.status = 'running';
  session.lifecycle.turn += 1;
  session.lifecycle.lastUserInputAt = nowIso();
  await appendRecord(cwd, session, {
    id: makeId('usr'),
    ts: nowIso(),
    kind: 'user',
    role: 'user',
    content: userInput
  });

  try {
    for (let i = 0; i < MAX_LOOPS; i++) {
      const content = await callOpenRouter(buildChatMessages(session));
      const action = parseModelAction(content);
      session.lifecycle.lastAssistantOutputAt = nowIso();
      await appendRecord(cwd, session, {
        id: makeId('ast'),
        ts: nowIso(),
        kind: 'assistant',
        role: 'assistant',
        content,
        action
      });

      if ('message' in action) {
        session.lifecycle.status = 'idle';
        await saveSession(cwd, session);
        return action.message.trim() || '(no content)';
      }

      if ('bash' in action) {
        process.stdout.write(`\n$ ${action.bash}\n`);
        const result = await runBash(action.bash, cwd);
        process.stdout.write(result.content.split('\n').slice(2).join('\n') + '\n');
        await appendRecord(cwd, session, {
          id: makeId('tool'),
          ts: nowIso(),
          kind: 'tool',
          role: 'user',
          tool: 'bash',
          status: result.status,
          content: result.content,
          meta: result.meta
        });
        continue;
      }

      const result = await runEdit(action.edit, cwd);
      process.stdout.write(`\n[edit ${result.status}] ${result.meta?.path ?? action.edit.path}\n`);
      await appendRecord(cwd, session, {
        id: makeId('tool'),
        ts: nowIso(),
        kind: 'tool',
        role: 'user',
        tool: 'edit',
        status: result.status,
        content: result.content,
        meta: result.meta
      });
    }
    throw new Error('Exceeded action loop limit');
  } finally {
    session.lifecycle.status = 'idle';
    await saveSession(cwd, session);
  }
}

async function interactive(session: Session) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'cliq> ' });
  console.log(`cliq chat in ${session.cwd}`);
  rl.prompt();
  for await (const line of rl) {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      continue;
    }
    if (input === '/exit' || input === '/quit') break;
    if (input === '/reset') {
      const fresh = await ensureFresh(session.cwd);
      Object.assign(session, fresh);
      console.log('session reset');
      rl.prompt();
      continue;
    }
    try {
      const final = await runTurn(session, input);
      console.log(`\n${final}\n`);
    } catch (e) {
      console.error(String(e));
    }
    rl.prompt();
  }
  rl.close();
}

async function ensureFresh(cwd: string): Promise<Session> {
  await fs.rm(path.join(cwd, APP_DIR), { recursive: true, force: true });
  return ensureSession(cwd);
}

async function main() {
  const { cmd, prompt } = parseArgs(process.argv) as { cmd: string; prompt?: string };
  const cwd = process.cwd();
  if (cmd === 'help') return printHelp();
  if (cmd === 'reset') {
    await ensureFresh(cwd);
    console.log(`reset session in ${path.join(cwd, APP_DIR)}`);
    return;
  }
  if (cmd === 'history') {
    const session = await ensureSession(cwd);
    console.log(JSON.stringify(session, null, 2));
    return;
  }
  const session = await ensureSession(cwd);
  if (prompt && prompt.trim()) {
    const final = await runTurn(session, prompt.trim());
    console.log(`\n${final}`);
    return;
  }
  await interactive(session);
  await saveSession(cwd, session);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
