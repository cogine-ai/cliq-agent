# Phase 0: Cliq Runtime Kernel Foundation Implementation Plan

> This document is the execution plan for [RFC: Cliq Agent Runtime Architecture](/Users/kiedis/Coding/AI/cliq-agent/docs/rfcs/2026-04-17-agent-runtime-architecture.md).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute Phase 0 of the runtime architecture RFC by refactoring Cliq from a single-file harness into a small modular runtime kernel with explicit session, protocol, model, tool, runner, and CLI boundaries while preserving the current external behavior.

**Architecture:** Extract the current behavior in [src/index.ts](/Users/kiedis/Coding/AI/cliq-agent/src/index.ts) into focused modules behind typed interfaces. Keep the public protocol unchanged for this phase (`bash`, `edit`, `message` only), but introduce a tool registry plus lifecycle hooks so later work can add read-only tools, policy gates, and alternate frontends without rewriting the turn loop again.

**Tech Stack:** TypeScript, Node.js built-ins (`node:test`, `assert/strict`, `fs`, `child_process`, `readline`), existing `tsc` build, `tsx` for local test execution if needed.

---

## Scope Check

The architecture RFC spans at least five later subsystems:

1. runtime decomposition
2. tool/protocol expansion
3. policy and approval modes
4. session branching/compaction
5. headless/RPC plus observability/TUI

Do **not** implement all of that in one pass. This plan only covers subsystem 1 plus the minimal hook surface needed to support the later plans cleanly. Follow-up plans should handle:

- Plan 2: structured read-only tools plus policy modes
- Plan 3: session checkpoints/fork/compaction
- Plan 4: JSONL/RPC event stream plus metrics/export
- Plan 5: richer interactive UX/TUI

## Target File Structure

These files define the new kernel boundary:

- Create: `src/config.ts`
- Create: `src/prompt/system.ts`
- Create: `src/protocol/actions.ts`
- Create: `src/session/types.ts`
- Create: `src/session/store.ts`
- Create: `src/model/types.ts`
- Create: `src/model/openrouter.ts`
- Create: `src/tools/types.ts`
- Create: `src/tools/bash.ts`
- Create: `src/tools/edit.ts`
- Create: `src/tools/registry.ts`
- Create: `src/runtime/hooks.ts`
- Create: `src/runtime/runner.ts`
- Create: `src/cli.ts`
- Create: `src/protocol/actions.test.ts`
- Create: `src/session/store.test.ts`
- Create: `src/runtime/runner.test.ts`
- Modify: `src/index.ts`
- Modify: `package.json`
- Modify: `README.md`

### Responsibility Map

- `src/config.ts`: central constants now scattered at the top of `src/index.ts`
- `src/prompt/system.ts`: system prompt text and prompt construction helpers
- `src/protocol/actions.ts`: typed action model plus JSON parsing/validation
- `src/session/types.ts`: `Session`, `SessionRecord`, and related runtime types
- `src/session/store.ts`: create/load/save/migrate session data
- `src/model/types.ts`: model client interface for real and fake clients
- `src/model/openrouter.ts`: current OpenRouter HTTP implementation
- `src/tools/types.ts`: tool request/result contracts and runtime context
- `src/tools/bash.ts`: current bash execution primitive
- `src/tools/edit.ts`: current exact-replace edit primitive
- `src/tools/registry.ts`: map protocol actions to tools without hard-coded `if/else`
- `src/runtime/hooks.ts`: lifecycle hook interface and runner helper
- `src/runtime/runner.ts`: turn loop, tool dispatch, and session mutation
- `src/cli.ts`: argument parsing, REPL wiring, and user-facing console behavior
- `src/index.ts`: thin bootstrap only

### Guardrails

- Preserve existing CLI commands: `chat`, `run`, `ask`, `reset`, `history`, `help`
- Preserve existing session file path: `./.cliq/session.json`
- Preserve existing model action protocol for this phase
- Preserve tool-result replay model where tool output is appended as a user-visible record
- Do not add approval prompts, new tools, or RPC in this plan

### Task 1: Extract The Protocol Layer First

**Files:**
- Create: `src/protocol/actions.ts`
- Create: `src/protocol/actions.test.ts`
- Modify: `package.json`

- [ ] **Step 1: Write the failing protocol tests**

```ts
// src/protocol/actions.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseModelAction } from './actions.js';

test('parses bash action', () => {
  assert.deepEqual(parseModelAction('{"bash":"npm test"}'), { bash: 'npm test' });
});

test('parses edit action', () => {
  assert.deepEqual(parseModelAction('{"edit":{"path":"src/index.ts","old_text":"foo","new_text":"bar"}}'), {
    edit: { path: 'src/index.ts', old_text: 'foo', new_text: 'bar' }
  });
});

test('parses final message action', () => {
  assert.deepEqual(parseModelAction('{"message":"done"}'), { message: 'done' });
});

test('rejects multiple top-level keys', () => {
  assert.throws(() => parseModelAction('{"bash":"pwd","message":"done"}'), /exactly one top-level key/i);
});
```

- [ ] **Step 2: Run the protocol test to verify it fails**

Run: `node --test --import tsx src/protocol/actions.test.ts`
Expected: FAIL with `Cannot find module './actions.js'` or equivalent import error.

- [ ] **Step 3: Implement the protocol module**

```ts
// src/protocol/actions.ts
export type EditAction = {
  path: string;
  old_text: string;
  new_text: string;
};

export type ModelAction =
  | { bash: string }
  | { edit: EditAction }
  | { message: string };

export function parseModelAction(content: string): ModelAction {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(`Model returned non-JSON content:\n${content}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Model returned invalid action object:\n${content}`);
  }

  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 1) {
    throw new Error(`Model action must contain exactly one top-level key:\n${content}`);
  }

  if (typeof record.bash === 'string') {
    return { bash: record.bash };
  }

  if (typeof record.message === 'string') {
    return { message: record.message };
  }

  if (record.edit && typeof record.edit === 'object' && !Array.isArray(record.edit)) {
    const edit = record.edit as Record<string, unknown>;
    if (typeof edit.path === 'string' && typeof edit.old_text === 'string' && typeof edit.new_text === 'string') {
      return {
        edit: {
          path: edit.path,
          old_text: edit.old_text,
          new_text: edit.new_text
        }
      };
    }
  }

  throw new Error(`Model returned unsupported action:\n${content}`);
}
```

- [ ] **Step 4: Add a reusable test command and run the tests**

```json
// package.json
{
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "start": "node dist/index.js",
    "dev": "tsx src/index.ts",
    "test": "node --test --import tsx \"src/**/*.test.ts\""
  }
}
```

Run: `npm test -- --test-name-pattern="parses"`
Expected: PASS for the four protocol tests.

- [ ] **Step 5: Commit**

```bash
git add package.json src/protocol/actions.ts src/protocol/actions.test.ts
git commit -m "refactor: extract protocol parsing"
```

### Task 2: Move Session State Into Its Own Module

**Files:**
- Create: `src/config.ts`
- Create: `src/prompt/system.ts`
- Create: `src/session/types.ts`
- Create: `src/session/store.ts`
- Create: `src/session/store.test.ts`

- [ ] **Step 1: Write failing session tests**

```ts
// src/session/store.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createSession, ensureSession, sessionPath } from './store.js';

test('createSession seeds a system record', () => {
  const session = createSession('/tmp/workspace');
  assert.equal(session.records[0]?.kind, 'system');
  assert.equal(session.cwd, '/tmp/workspace');
});

test('ensureSession creates the persisted file when missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-'));
  const session = await ensureSession(cwd);
  const raw = JSON.parse(await readFile(sessionPath(cwd), 'utf8')) as { records: Array<{ kind: string }> };
  assert.equal(session.records.length > 0, true);
  assert.equal(raw.records[0]?.kind, 'system');
});
```

- [ ] **Step 2: Run the session test to verify it fails**

Run: `npm test -- src/session/store.test.ts`
Expected: FAIL because `./store.js` and the exported session helpers do not exist yet.

- [ ] **Step 3: Implement config, prompt, and session modules**

```ts
// src/config.ts
export const MODEL = 'anthropic/claude-sonnet-4.6';
export const APP_DIR = '.cliq';
export const SESSION_FILE = 'session.json';
export const MAX_LOOPS = 24;
export const MAX_OUTPUT = 12_000;
export const BASH_TIMEOUT_MS = 60_000;
export const SESSION_VERSION = 2;
```

```ts
// src/prompt/system.ts
export const SYSTEM_PROMPT = `You are a tiny coding agent inside a local CLI harness.
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
```

```ts
// src/session/types.ts
import type { ModelAction } from '../protocol/actions.js';

export type SessionRecord =
  | { id: string; ts: string; kind: 'system' | 'user'; role: 'system' | 'user'; content: string }
  | { id: string; ts: string; kind: 'assistant'; role: 'assistant'; content: string; action: ModelAction | null }
  | {
      id: string;
      ts: string;
      kind: 'tool';
      role: 'user';
      tool: string;
      status: 'ok' | 'error';
      content: string;
      meta?: Record<string, string | number | boolean | null>;
    };

export type Session = {
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
```

```ts
// src/session/store.ts
import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { APP_DIR, MODEL, SESSION_FILE, SESSION_VERSION } from '../config.js';
import { SYSTEM_PROMPT } from '../prompt/system.js';
import type { Session, SessionRecord } from './types.js';

export function sessionPath(cwd: string) {
  return path.join(cwd, APP_DIR, SESSION_FILE);
}

export function nowIso() {
  return new Date().toISOString();
}

export function makeId(prefix: string) {
  return `${prefix}_${crypto.randomUUID()}`;
}

export function createSession(cwd: string): Session {
  const now = nowIso();
  return {
    version: SESSION_VERSION,
    app: 'cliq',
    model: MODEL,
    cwd,
    createdAt: now,
    updatedAt: now,
    lifecycle: { status: 'idle', turn: 0 },
    records: [{ id: makeId('sys'), ts: now, kind: 'system', role: 'system', content: SYSTEM_PROMPT }]
  };
}

export async function saveSession(cwd: string, session: Session) {
  session.updatedAt = nowIso();
  await fs.mkdir(path.dirname(sessionPath(cwd)), { recursive: true });
  await fs.writeFile(sessionPath(cwd), JSON.stringify(session, null, 2));
}

export async function appendRecord(cwd: string, session: Session, record: SessionRecord) {
  session.records.push(record);
  await saveSession(cwd, session);
}

export async function ensureSession(cwd: string): Promise<Session> {
  await fs.mkdir(path.dirname(sessionPath(cwd)), { recursive: true });
  try {
    return JSON.parse(await fs.readFile(sessionPath(cwd), 'utf8')) as Session;
  } catch {
    const session = createSession(cwd);
    await saveSession(cwd, session);
    return session;
  }
}
```

- [ ] **Step 4: Extend `ensureSession` with the current legacy migration behavior and rerun tests**

Add the existing `migrateLegacySession` logic from [src/index.ts](/Users/kiedis/Coding/AI/cliq-agent/src/index.ts) lines 142-203 to `src/session/store.ts`, then run:

Run: `npm test -- src/session/store.test.ts`
Expected: PASS for the new session tests, plus no regression in `npm test`.

- [ ] **Step 5: Commit**

```bash
git add src/config.ts src/prompt/system.ts src/session/types.ts src/session/store.ts src/session/store.test.ts
git commit -m "refactor: extract session storage"
```

### Task 3: Introduce A Tool Registry For Existing Tools

**Files:**
- Create: `src/tools/types.ts`
- Create: `src/tools/bash.ts`
- Create: `src/tools/edit.ts`
- Create: `src/tools/registry.ts`
- Modify: `src/protocol/actions.ts`

- [ ] **Step 1: Write failing registry and tool tests**

```ts
// append to src/runtime/runner.test.ts later or start a focused tool test
import test from 'node:test';
import assert from 'node:assert/strict';
import { createToolRegistry } from '../tools/registry.js';

test('registry resolves bash and edit tools', () => {
  const registry = createToolRegistry();
  assert.equal(typeof registry.resolve({ bash: 'pwd' }).definition.name, 'string');
  assert.equal(typeof registry.resolve({ edit: { path: 'a', old_text: 'b', new_text: 'c' } }).definition.name, 'string');
});
```

- [ ] **Step 2: Run the tool test to verify it fails**

Run: `npm test -- --test-name-pattern="registry resolves"`
Expected: FAIL because `createToolRegistry` and tool contracts do not exist.

- [ ] **Step 3: Implement tool contracts and current tool definitions**

```ts
// src/tools/types.ts
import type { EditAction, ModelAction } from '../protocol/actions.js';
import type { Session } from '../session/types.js';

export type ToolStatus = 'ok' | 'error';

export type ToolResult = {
  tool: string;
  status: ToolStatus;
  content: string;
  meta: Record<string, string | number | boolean | null>;
};

export type ToolContext = {
  cwd: string;
  session: Session;
};

export type ToolDefinition<TAction extends ModelAction = ModelAction> = {
  name: string;
  supports(action: ModelAction): action is TAction;
  execute(action: TAction, context: ToolContext): Promise<ToolResult>;
};

export type EditModelAction = { edit: EditAction };
```

```ts
// src/tools/bash.ts
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
```

```ts
// src/tools/edit.ts
import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { ToolDefinition } from './types.js';

export const editTool: ToolDefinition<{ edit: { path: string; old_text: string; new_text: string } }> = {
  name: 'edit',
  supports(action): action is { edit: { path: string; old_text: string; new_text: string } } {
    return typeof (action as { edit?: unknown }).edit === 'object' && !!(action as { edit?: unknown }).edit;
  },
  async execute(action, context) {
    const target = path.isAbsolute(action.edit.path) ? action.edit.path : path.join(context.cwd, action.edit.path);
    try {
      const current = await fs.readFile(target, 'utf8');
      const matches = current.split(action.edit.old_text).length - 1;
      if (matches !== 1) {
        return {
          tool: 'edit',
          status: 'error',
          meta: { path: path.relative(context.cwd, target) || action.edit.path, matches },
          content: `TOOL_RESULT edit ERROR\npath=${path.relative(context.cwd, target) || action.edit.path}\nexpected old_text to match exactly once, but matched ${matches} times`
        };
      }
      await fs.writeFile(target, current.replace(action.edit.old_text, action.edit.new_text), 'utf8');
      return {
        tool: 'edit',
        status: 'ok',
        meta: { path: path.relative(context.cwd, target) || action.edit.path },
        content: `TOOL_RESULT edit OK\npath=${path.relative(context.cwd, target) || action.edit.path}\nreplaced exact text span successfully`
      };
    } catch (error) {
      return {
        tool: 'edit',
        status: 'error',
        meta: { path: path.relative(context.cwd, target) || action.edit.path },
        content: `TOOL_RESULT edit ERROR\npath=${path.relative(context.cwd, target) || action.edit.path}\n${error instanceof Error ? error.message : String(error)}`
      };
    }
  }
};
```

```ts
// src/tools/registry.ts
import type { ModelAction } from '../protocol/actions.js';
import { bashTool } from './bash.js';
import { editTool } from './edit.js';
import type { ToolDefinition } from './types.js';

export function createToolRegistry(definitions: ToolDefinition[] = [bashTool, editTool]) {
  return {
    definitions,
    resolve(action: ModelAction) {
      const definition = definitions.find((candidate) => candidate.supports(action));
      if (!definition) {
        throw new Error(`No tool registered for action: ${JSON.stringify(action)}`);
      }
      return { definition };
    }
  };
}
```

- [ ] **Step 4: Replace direct tool branching in the future runner entry point with registry dispatch**

This step is preparatory. Update imports in any module still using `runBash`/`runEdit` directly so new runtime code only depends on `createToolRegistry()`, then run:

Run: `npm test`
Expected: PASS with protocol and session tests still green.

- [ ] **Step 5: Commit**

```bash
git add src/tools/types.ts src/tools/bash.ts src/tools/edit.ts src/tools/registry.ts
git commit -m "refactor: add tool registry for core tools"
```

### Task 4: Build The Runner And Hook Pipeline

**Files:**
- Create: `src/model/types.ts`
- Create: `src/model/openrouter.ts`
- Create: `src/runtime/hooks.ts`
- Create: `src/runtime/runner.ts`
- Create: `src/runtime/runner.test.ts`

- [ ] **Step 1: Write failing runner tests around hook order and tool replay**

```ts
// src/runtime/runner.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { createSession } from '../session/store.js';
import { createRunner } from './runner.js';

test('runner invokes hooks around assistant and tool execution', async () => {
  const session = createSession('/tmp/workspace');
  const events: string[] = [];

  const runner = createRunner({
    model: {
      async complete() {
        return '{"message":"done"}';
      }
    },
    registry: {
      resolve() {
        throw new Error('tool dispatch should not run for final message');
      }
    },
    hooks: [
      {
        async beforeTurn() {
          events.push('beforeTurn');
        },
        async afterAssistantAction() {
          events.push('afterAssistantAction');
        },
        async afterTurn() {
          events.push('afterTurn');
        }
      }
    ]
  });

  const finalMessage = await runner.runTurn(session, 'say done');
  assert.equal(finalMessage, 'done');
  assert.deepEqual(events, ['beforeTurn', 'afterAssistantAction', 'afterTurn']);
});
```

- [ ] **Step 2: Run the runner tests to verify they fail**

Run: `npm test -- src/runtime/runner.test.ts`
Expected: FAIL because `createRunner` and the hook interface do not exist.

- [ ] **Step 3: Implement model client, hooks, and runner**

```ts
// src/model/types.ts
export type ChatMessage = {
  role: 'system' | 'user' | 'assistant';
  content: string;
};

export type ModelClient = {
  complete(messages: ChatMessage[]): Promise<string>;
};
```

```ts
// src/model/openrouter.ts
import { MODEL } from '../config.js';
import type { ChatMessage, ModelClient } from './types.js';

type OpenRouterResp = {
  choices: Array<{
    message: {
      role: 'assistant';
      content?: string;
    };
  }>;
};

export function createOpenRouterClient(): ModelClient {
  return {
    async complete(messages: ChatMessage[]) {
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
        body: JSON.stringify({ model: MODEL, messages })
      });

      if (!res.ok) {
        throw new Error(`OpenRouter error ${res.status}: ${await res.text()}`);
      }

      const json = (await res.json()) as OpenRouterResp;
      return json.choices[0]?.message?.content?.trim() ?? '';
    }
  };
}
```

```ts
// src/runtime/hooks.ts
import type { ModelAction } from '../protocol/actions.js';
import type { Session } from '../session/types.js';
import type { ToolResult } from '../tools/types.js';

export type RuntimeHook = {
  beforeTurn?(session: Session, userInput: string): Promise<void> | void;
  afterAssistantAction?(session: Session, action: ModelAction, rawContent: string): Promise<void> | void;
  beforeTool?(session: Session, action: ModelAction): Promise<void> | void;
  afterTool?(session: Session, result: ToolResult): Promise<void> | void;
  afterTurn?(session: Session, finalMessage: string): Promise<void> | void;
};

export async function runHooks<K extends keyof RuntimeHook>(
  hooks: RuntimeHook[],
  name: K,
  ...args: Parameters<NonNullable<RuntimeHook[K]>>
) {
  for (const hook of hooks) {
    const fn = hook[name];
    if (fn) {
      await fn(...args);
    }
  }
}
```

```ts
// src/runtime/runner.ts
import { MAX_LOOPS } from '../config.js';
import { parseModelAction } from '../protocol/actions.js';
import { appendRecord, makeId, nowIso, saveSession } from '../session/store.js';
import type { Session } from '../session/types.js';
import type { ModelClient, ChatMessage } from '../model/types.js';
import { runHooks, type RuntimeHook } from './hooks.js';
import { createToolRegistry } from '../tools/registry.js';

function buildChatMessages(session: Session): ChatMessage[] {
  return session.records.map((record) =>
    record.kind === 'tool'
      ? { role: 'user', content: record.content }
      : { role: record.role, content: record.content }
  );
}

export function createRunner({
  model,
  registry = createToolRegistry(),
  hooks = []
}: {
  model: ModelClient;
  registry?: ReturnType<typeof createToolRegistry>;
  hooks?: RuntimeHook[];
}) {
  return {
    async runTurn(session: Session, userInput: string): Promise<string> {
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

      await runHooks(hooks, 'beforeTurn', session, userInput);

      try {
        for (let i = 0; i < MAX_LOOPS; i += 1) {
          const rawContent = await model.complete(buildChatMessages(session));
          const action = parseModelAction(rawContent);

          session.lifecycle.lastAssistantOutputAt = nowIso();
          await appendRecord(cwd, session, {
            id: makeId('ast'),
            ts: nowIso(),
            kind: 'assistant',
            role: 'assistant',
            content: rawContent,
            action
          });

          await runHooks(hooks, 'afterAssistantAction', session, action, rawContent);

          if ('message' in action) {
            session.lifecycle.status = 'idle';
            await saveSession(cwd, session);
            await runHooks(hooks, 'afterTurn', session, action.message.trim() || '(no content)');
            return action.message.trim() || '(no content)';
          }

          await runHooks(hooks, 'beforeTool', session, action);
          const { definition } = registry.resolve(action);
          const result = await definition.execute(action as never, { cwd, session });
          await appendRecord(cwd, session, {
            id: makeId('tool'),
            ts: nowIso(),
            kind: 'tool',
            role: 'user',
            tool: result.tool,
            status: result.status,
            content: result.content,
            meta: result.meta
          });
          await runHooks(hooks, 'afterTool', session, result);
        }

        throw new Error('Exceeded action loop limit');
      } finally {
        session.lifecycle.status = 'idle';
        await saveSession(cwd, session);
      }
    }
  };
}
```

- [ ] **Step 4: Add one more test that exercises tool dispatch and replay, then rerun the suite**

Add a second runner test where the fake model first returns `{"bash":"pwd"}` and then `{"message":"done"}` while the fake registry returns a canned tool result. Then run:

Run: `npm test`
Expected: PASS, including verification that a tool result record is appended and replayed back as a user message.

- [ ] **Step 5: Commit**

```bash
git add src/model/types.ts src/model/openrouter.ts src/runtime/hooks.ts src/runtime/runner.ts src/runtime/runner.test.ts
git commit -m "refactor: add modular runner and lifecycle hooks"
```

### Task 5: Reduce The CLI To A Thin Bootstrap

**Files:**
- Create: `src/cli.ts`
- Modify: `src/index.ts`
- Modify: `README.md`

- [ ] **Step 1: Write a failing smoke test for CLI argument parsing if needed, otherwise capture current command behavior manually**

If you do not want a separate CLI test file in this phase, record the manual smoke matrix in the commit message and verify all five commands by hand:

Run:
- `npm run dev -- help`
- `npm run dev -- history`
- `npm run dev -- reset`
- `npm run dev -- "say hello"`
- `printf '/quit\n' | npm run dev -- chat`

Expected:
- `help` prints usage
- `history` prints JSON
- `reset` recreates `.cliq`
- one-shot prompt runs through `runTurn`
- `chat` opens REPL and exits cleanly

- [ ] **Step 2: Implement the CLI module**

```ts
// src/cli.ts
import readline from 'node:readline';
import path from 'node:path';
import { ensureFresh, ensureSession, saveSession } from './session/store.js';
import { createOpenRouterClient } from './model/openrouter.js';
import { createRunner } from './runtime/runner.js';

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
  console.log(`cliq - tiny local coding agent harness\n\nUsage:\n  cliq "task"        Run a task in the current directory\n  cliq chat          Start interactive chat in the current directory\n  cliq reset         Clear persisted conversation for this directory\n  cliq history       Print persisted session for this directory\n\nEnv:\n  OPENROUTER_API_KEY Required\n`);
}

export async function runCli(argv: string[]) {
  const { cmd, prompt } = parseArgs(argv) as { cmd: string; prompt?: string };
  const cwd = process.cwd();
  if (cmd === 'help') return printHelp();
  if (cmd === 'reset') {
    await ensureFresh(cwd);
    console.log(`reset session in ${path.join(cwd, '.cliq')}`);
    return;
  }
  if (cmd === 'history') {
    console.log(JSON.stringify(await ensureSession(cwd), null, 2));
    return;
  }

  const session = await ensureSession(cwd);
  const runner = createRunner({ model: createOpenRouterClient() });

  if (prompt && prompt.trim()) {
    console.log(`\n${await runner.runTurn(session, prompt.trim())}`);
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
    if (input === '/exit' || input === '/quit') break;
    const finalMessage = await runner.runTurn(session, input);
    console.log(`\n${finalMessage}\n`);
    rl.prompt();
  }
  rl.close();
  await saveSession(cwd, session);
}
```

- [ ] **Step 3: Replace `src/index.ts` with a bootstrap only**

```ts
#!/usr/bin/env node
import { runCli } from './cli.js';

runCli(process.argv).catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
```

- [ ] **Step 4: Update the README so the internal architecture matches reality, then run all verification**

Add a short `Internal architecture` section to `README.md` listing:

- `session`
- `protocol`
- `model`
- `tools`
- `runtime`
- `cli`

Run:
- `npm test`
- `npm run build`

Expected:
- all tests PASS
- TypeScript build PASS

- [ ] **Step 5: Commit**

```bash
git add README.md src/cli.ts src/index.ts
git commit -m "refactor: split cli bootstrap from runtime kernel"
```

## Self-Review

### Spec coverage

- Monolith split: covered by Tasks 1-5
- Hook/extension surface: covered by Task 4
- Preserve current session model while improving structure: covered by Task 2
- Preserve provider-agnostic JSON action loop: covered by Tasks 1 and 4
- Avoid prematurely adding new protocol/actions: enforced in Guardrails

### Explicit gaps left for later plans

- Structured `read`/`ls`/`grep` tools
- approval and permission strategies
- session checkpoints/fork/compaction/handoff
- headless JSONL/RPC interface
- rich TUI/UX and metrics/event stream

### Placeholder scan

- No `TODO`, `TBD`, or “appropriate error handling” placeholders remain.
- All tasks name exact files and verification commands.

### Type consistency

- `ModelAction` is defined once in `src/protocol/actions.ts`
- `Session`/`SessionRecord` are defined once in `src/session/types.ts`
- runtime depends on `ModelClient`, `ToolDefinition`, and `RuntimeHook` interfaces instead of re-declaring shapes inline

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-17-runtime-kernel-foundation.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
