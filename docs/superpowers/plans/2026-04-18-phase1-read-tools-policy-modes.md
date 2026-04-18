# Phase 1: Structured Read Tools And Policy Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add structured read-only tools (`read`, `ls`, `find`, `grep`) plus minimal configurable policy modes so Cliq can inspect repositories without overusing `bash`, and can gate writes/command execution without rewriting the runtime again.

**Architecture:** Keep the Phase 0 runtime boundaries intact. Add a small `policy` module that evaluates tool access against a mode and optional confirmation callback, extend the protocol with four read actions, and register four focused file tools that all share one workspace-bound path helper and output limits. The runner stays responsible for the turn loop, but policy decides whether a tool may run before execution.

**Tech Stack:** TypeScript, Node.js built-ins (`node:test`, `assert/strict`, `fs`, `path`, `readline/promises`), existing `tsx`-based tests, current CLI/runtime/session modules.

Reference RFC: [RFC: Cliq Agent Runtime Architecture](../../rfcs/2026-04-17-agent-runtime-architecture.md)

---

## Scope Check

This plan only covers the two Phase 1 deliverables from the RFC:

1. structured read tools: `read`, `ls`, `find`, `grep`
2. policy modes: `auto`, `confirm-write`, `read-only`, `confirm-bash`, `confirm-all`

Do **not** mix in later-phase work:

- no extension discovery
- no skill loading
- no session checkpoint/fork/compact
- no RPC/JSONL transport
- no rich TUI or structured approval UI beyond a minimal CLI yes/no prompt

## Target File Structure

- Create: `src/policy/types.ts`
- Create: `src/policy/engine.ts`
- Create: `src/policy/engine.test.ts`
- Create: `src/cli.test.ts`
- Create: `src/tools/path.ts`
- Create: `src/tools/read.ts`
- Create: `src/tools/read.test.ts`
- Create: `src/tools/ls.ts`
- Create: `src/tools/ls.test.ts`
- Create: `src/tools/find.ts`
- Create: `src/tools/find.test.ts`
- Create: `src/tools/grep.ts`
- Create: `src/tools/grep.test.ts`
- Modify: `src/config.ts`
- Modify: `src/prompt/system.ts`
- Modify: `src/protocol/actions.ts`
- Modify: `src/protocol/actions.test.ts`
- Modify: `src/tools/types.ts`
- Modify: `src/tools/registry.ts`
- Modify: `src/tools/bash.ts`
- Modify: `src/tools/edit.ts`
- Modify: `src/runtime/runner.ts`
- Modify: `src/runtime/runner.test.ts`
- Modify: `src/cli.ts`
- Modify: `README.md`

### Responsibility Map

- `src/policy/types.ts`: policy mode names, tool access kinds, authorization result shape
- `src/policy/engine.ts`: mode evaluation plus optional confirmation callback
- `src/policy/engine.test.ts`: policy matrix and confirmation behavior
- `src/cli.test.ts`: CLI flag parsing for `--policy`
- `src/tools/path.ts`: workspace-relative path resolution plus output-bound traversal helpers
- `src/tools/read.ts`: bounded file reads with optional line ranges
- `src/tools/ls.ts`: bounded directory listing
- `src/tools/find.ts`: bounded filename search
- `src/tools/grep.ts`: bounded substring search across files
- `src/runtime/runner.ts`: invoke policy before tool execution and synthesize denial results
- `src/prompt/system.ts`: teach the model the new read tools and policy-sensitive behavior
- `README.md`: document the new tools and policy flags

### Guardrails

- Keep `bash`, `edit`, `message` behavior backward compatible
- Reject absolute paths and any path escaping `context.cwd`
- Keep tool results textual so existing replay/session model still works
- Bound file size, directory entries, search results, and grep matches in `src/config.ts`
- In non-interactive contexts, confirmation-required modes must deny by default with a clear error
- `beforeTool` hooks should run only for tools that will actually execute
- Denied tools must still append a tool record and run `afterTool` hooks

### Task 1: Add Policy Modes And CLI Plumbing

**Files:**
- Create: `src/policy/types.ts`
- Create: `src/policy/engine.ts`
- Create: `src/policy/engine.test.ts`
- Create: `src/cli.test.ts`
- Modify: `src/cli.ts`
- Modify: `src/config.ts`

- [ ] **Step 1: Write the failing policy and CLI tests**

```ts
// src/policy/engine.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPolicyEngine } from './engine.js';
import type { ToolAccess } from './types.js';

function definition(name: string, access: ToolAccess) {
  return { name, access };
}

test('read-only denies write and exec access', async () => {
  const policy = createPolicyEngine({ mode: 'read-only' });

  assert.deepEqual(await policy.authorize(definition('read', 'read')), { allowed: true });
  assert.deepEqual(await policy.authorize(definition('edit', 'write')), {
    allowed: false,
    reason: 'policy mode read-only blocks write tools'
  });
  assert.deepEqual(await policy.authorize(definition('bash', 'exec')), {
    allowed: false,
    reason: 'policy mode read-only blocks exec tools'
  });
});

test('confirm-write only prompts for write tools', async () => {
  const prompts: string[] = [];
  const policy = createPolicyEngine({
    mode: 'confirm-write',
    confirm: async (prompt) => {
      prompts.push(prompt);
      return false;
    }
  });

  assert.deepEqual(await policy.authorize(definition('read', 'read')), { allowed: true });
  assert.deepEqual(await policy.authorize(definition('edit', 'write')), {
    allowed: false,
    reason: 'user declined confirmation'
  });
  assert.equal(prompts.length, 1);
  assert.match(prompts[0] ?? '', /edit/i);
});
```

```ts
// src/cli.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from './cli.js';

test('parseArgs accepts --policy=read-only', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy=read-only', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'read-only'
  });
});

test('parseArgs accepts --policy confirm-all for one-shot prompt', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--policy', 'confirm-all', 'fix', 'tests']), {
    cmd: 'chat',
    prompt: 'fix tests',
    policy: 'confirm-all'
  });
});
```

- [ ] **Step 2: Run the new tests to verify the expected failures**

Run: `node --test --import tsx src/policy/engine.test.ts src/cli.test.ts`
Expected: FAIL with missing module errors for `./engine.js` and missing `policy` support in `parseArgs`.

- [ ] **Step 3: Implement policy types, engine, and CLI policy parsing**

```ts
// src/policy/types.ts
export type PolicyMode = 'auto' | 'confirm-write' | 'read-only' | 'confirm-bash' | 'confirm-all';

export type ToolAccess = 'read' | 'write' | 'exec';

export type PolicyAuthorization =
  | { allowed: true }
  | { allowed: false; reason: string };

export type PolicyConfirm = (prompt: string) => Promise<boolean>;
```

```ts
// src/policy/engine.ts
import type { PolicyAuthorization, PolicyConfirm, PolicyMode, ToolAccess } from './types.js';

type PolicyEngineOptions = {
  mode: PolicyMode;
  confirm?: PolicyConfirm;
};

type ToolShape = {
  name: string;
  access: ToolAccess;
};

export function createPolicyEngine({ mode, confirm }: PolicyEngineOptions) {
  async function authorize(definition: ToolShape): Promise<PolicyAuthorization> {
    if (mode === 'auto') return { allowed: true };

    if (mode === 'read-only' && definition.access !== 'read') {
      return {
        allowed: false,
        reason: `policy mode read-only blocks ${definition.access} tools`
      };
    }

    const requiresConfirmation =
      mode === 'confirm-all' ||
      (mode === 'confirm-write' && definition.access === 'write') ||
      (mode === 'confirm-bash' && definition.name === 'bash');

    if (!requiresConfirmation) {
      return { allowed: true };
    }

    if (!confirm) {
      return {
        allowed: false,
        reason: 'confirmation required but no confirmer is available'
      };
    }

    const approved = await confirm(`Allow ${definition.name} (${definition.access})?`);
    return approved ? { allowed: true } : { allowed: false, reason: 'user declined confirmation' };
  }

  return { mode, authorize };
}
```

```ts
// src/config.ts
export const DEFAULT_POLICY_MODE = 'auto';
```

```ts
// src/cli.ts
import type { PolicyMode } from './policy/types.js';

function isPolicyMode(value: string): value is PolicyMode {
  return ['auto', 'confirm-write', 'read-only', 'confirm-bash', 'confirm-all'].includes(value);
}

export function parseArgs(argv: string[]) {
  const raw = argv.slice(2);
  let policy: PolicyMode = (process.env.CLIQ_POLICY_MODE as PolicyMode | undefined) ?? 'auto';
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
  if (cmd === 'reset' || cmd === 'history') return { cmd, policy };
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return { cmd: 'help', policy };
  return { cmd: 'chat', prompt: args.join(' '), policy };
}
```

- [ ] **Step 4: Run the policy and CLI tests**

Run: `node --test --import tsx src/policy/engine.test.ts src/cli.test.ts`
Expected: PASS with four passing tests and no missing-module errors.

- [ ] **Step 5: Commit**

```bash
git add src/policy/types.ts src/policy/engine.ts src/policy/engine.test.ts src/cli.test.ts src/cli.ts src/config.ts
git commit -m "feat: add policy mode engine"
```

### Task 2: Extend The Protocol And Add `read` / `ls`

**Files:**
- Create: `src/tools/path.ts`
- Create: `src/tools/read.ts`
- Create: `src/tools/read.test.ts`
- Create: `src/tools/ls.ts`
- Create: `src/tools/ls.test.ts`
- Modify: `src/protocol/actions.ts`
- Modify: `src/protocol/actions.test.ts`
- Modify: `src/tools/registry.ts`
- Modify: `src/tools/types.ts`
- Modify: `src/prompt/system.ts`
- Modify: `src/config.ts`

- [ ] **Step 1: Write the failing protocol, read, and ls tests**

```ts
// src/protocol/actions.test.ts
test('parses read action', () => {
  assert.deepEqual(
    parseModelAction('{"read":{"path":"src/index.ts","start_line":1,"end_line":20}}'),
    { read: { path: 'src/index.ts', start_line: 1, end_line: 20 } }
  );
});

test('parses ls action', () => {
  assert.deepEqual(parseModelAction('{"ls":{"path":"src"}}'), { ls: { path: 'src' } });
});
```

```ts
// src/tools/read.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createSession } from '../session/store.js';
import { readTool } from './read.js';

test('readTool returns numbered lines for a workspace file', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-read-'));
  await writeFile(path.join(cwd, 'notes.txt'), 'alpha\\nbeta\\ngamma\\n', 'utf8');

  const result = await readTool.execute(
    { read: { path: 'notes.txt', start_line: 2, end_line: 3 } },
    { cwd, session: createSession(cwd) }
  );

  assert.equal(result.status, 'ok');
  assert.match(result.content, /2\\| beta/);
  assert.match(result.content, /3\\| gamma/);
});
```

```ts
// src/tools/ls.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createSession } from '../session/store.js';
import { lsTool } from './ls.js';

test('lsTool lists directory entries in sorted order', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-ls-'));
  await mkdir(path.join(cwd, 'src'));
  await writeFile(path.join(cwd, 'README.md'), '# demo\\n', 'utf8');

  const result = await lsTool.execute({ ls: { path: '.' } }, { cwd, session: createSession(cwd) });

  assert.equal(result.status, 'ok');
  assert.match(result.content, /dir\\s+src\\//);
  assert.match(result.content, /file\\s+README\\.md/);
});
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `node --test --import tsx src/protocol/actions.test.ts src/tools/read.test.ts src/tools/ls.test.ts`
Expected: FAIL because `read`/`ls` are not yet valid actions and the new tool modules do not exist.

- [ ] **Step 3: Implement bounded path resolution, protocol parsing, and the two tools**

```ts
// src/tools/path.ts
import path from 'node:path';

export function resolveWorkspacePath(cwd: string, inputPath: string) {
  const target = path.resolve(cwd, inputPath);
  const relativePath = path.relative(cwd, target) || '.';

  if (path.isAbsolute(inputPath) || relativePath.startsWith('..')) {
    throw new Error('path must stay inside the workspace and be workspace-relative');
  }

  return { target, relativePath };
}
```

```ts
// src/protocol/actions.ts
export type ReadAction = {
  path: string;
  start_line?: number;
  end_line?: number;
};

export type LsAction = {
  path?: string;
};

export type ModelAction =
  | { bash: string }
  | { edit: EditAction }
  | { read: ReadAction }
  | { ls: LsAction }
  | { message: string };
```

```ts
// src/tools/types.ts
import type { ToolAccess } from '../policy/types.js';

export type ToolDefinition<TAction extends ModelAction = ModelAction> = {
  name: string;
  access: ToolAccess;
  supports(action: ModelAction): action is TAction;
  execute(action: TAction, context: ToolContext): Promise<ToolResult>;
};
```

```ts
// src/tools/read.ts
import { promises as fs } from 'node:fs';
import { READ_MAX_BYTES } from '../config.js';
import { resolveWorkspacePath } from './path.js';

export const readTool: ToolDefinition<{ read: ReadAction }> = {
  name: 'read',
  access: 'read',
  supports(action): action is { read: ReadAction } {
    return typeof (action as { read?: unknown }).read === 'object' && !!(action as { read?: unknown }).read;
  },
  async execute(action, context) {
    const { target, relativePath } = resolveWorkspacePath(context.cwd, action.read.path);
    const raw = await fs.readFile(target, 'utf8');
    const lines = raw.split('\n');
    const start = Math.max(1, action.read.start_line ?? 1);
    const end = Math.min(lines.length, action.read.end_line ?? Math.min(lines.length, start + 199));
    const snippet = lines
      .slice(start - 1, end)
      .map((line, index) => `${start + index}| ${line}`)
      .join('\n')
      .slice(0, READ_MAX_BYTES);

    return {
      tool: 'read',
      status: 'ok',
      meta: { path: relativePath, start_line: start, end_line: end },
      content: `TOOL_RESULT read OK\npath=${relativePath}\n${snippet}`.trim()
    };
  }
};
```

```ts
// src/tools/ls.ts
import { promises as fs } from 'node:fs';
import { LIST_MAX_ENTRIES } from '../config.js';
import { resolveWorkspacePath } from './path.js';

export const lsTool: ToolDefinition<{ ls: LsAction }> = {
  name: 'ls',
  access: 'read',
  supports(action): action is { ls: LsAction } {
    return typeof (action as { ls?: unknown }).ls === 'object' && !!(action as { ls?: unknown }).ls;
  },
  async execute(action, context) {
    const { target, relativePath } = resolveWorkspacePath(context.cwd, action.ls.path ?? '.');
    const entries = (await fs.readdir(target, { withFileTypes: true }))
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, LIST_MAX_ENTRIES)
      .map((entry) => `${entry.isDirectory() ? 'dir' : 'file'} ${entry.name}${entry.isDirectory() ? '/' : ''}`)
      .join('\n');

    return {
      tool: 'ls',
      status: 'ok',
      meta: { path: relativePath },
      content: `TOOL_RESULT ls OK\npath=${relativePath}\n${entries}`.trim()
    };
  }
};
```

```ts
// src/tools/registry.ts
import { readTool } from './read.js';
import { lsTool } from './ls.js';
import { bashTool } from './bash.js';
import { editTool } from './edit.js';
import type { ModelAction } from '../protocol/actions.js';
import type { ToolDefinition } from './types.js';

const coreTools: ToolDefinition[] = [bashTool, editTool, readTool, lsTool];

export function createToolRegistry(definitions: ToolDefinition[] = coreTools) {
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

```ts
// src/prompt/system.ts
Examples:
{"read":{"path":"src/runtime/runner.ts","start_line":1,"end_line":80}}
{"ls":{"path":"src"}}
```

- [ ] **Step 4: Add output-limit constants and rerun the focused tests**

```ts
// src/config.ts
export const READ_MAX_BYTES = 8_000;
export const LIST_MAX_ENTRIES = 200;
```

Run: `node --test --import tsx src/protocol/actions.test.ts src/tools/read.test.ts src/tools/ls.test.ts`
Expected: PASS for the new parser cases and both read-only tool tests.

- [ ] **Step 5: Commit**

```bash
git add src/config.ts src/protocol/actions.ts src/protocol/actions.test.ts src/tools/path.ts src/tools/read.ts src/tools/read.test.ts src/tools/ls.ts src/tools/ls.test.ts src/tools/types.ts src/tools/registry.ts src/prompt/system.ts
git commit -m "feat: add structured read and ls tools"
```

### Task 3: Add `find` / `grep` Without Falling Back To Shell

**Files:**
- Create: `src/tools/find.ts`
- Create: `src/tools/find.test.ts`
- Create: `src/tools/grep.ts`
- Create: `src/tools/grep.test.ts`
- Modify: `src/protocol/actions.ts`
- Modify: `src/protocol/actions.test.ts`
- Modify: `src/tools/registry.ts`
- Modify: `src/config.ts`
- Modify: `src/prompt/system.ts`

- [ ] **Step 1: Write the failing parser and tool tests**

```ts
// src/protocol/actions.test.ts
test('parses find action', () => {
  assert.deepEqual(parseModelAction('{"find":{"path":"src","name":"runner"}}'), {
    find: { path: 'src', name: 'runner' }
  });
});

test('parses grep action', () => {
  assert.deepEqual(parseModelAction('{"grep":{"path":"src","pattern":"runTurn"}}'), {
    grep: { path: 'src', pattern: 'runTurn' }
  });
});
```

```ts
// src/tools/find.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createSession } from '../session/store.js';
import { findTool } from './find.js';

test('findTool returns matching relative paths', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-find-'));
  await mkdir(path.join(cwd, 'src'));
  await writeFile(path.join(cwd, 'src', 'runner.ts'), 'export {};\n', 'utf8');
  await writeFile(path.join(cwd, 'src', 'other.ts'), 'export {};\n', 'utf8');

  const result = await findTool.execute({ find: { path: 'src', name: 'runner' } }, { cwd, session: createSession(cwd) });

  assert.equal(result.status, 'ok');
  assert.match(result.content, /src\/runner\.ts/);
  assert.doesNotMatch(result.content, /other\.ts/);
});
```

```ts
// src/tools/grep.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createSession } from '../session/store.js';
import { grepTool } from './grep.js';

test('grepTool returns line matches with file and line numbers', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-grep-'));
  await mkdir(path.join(cwd, 'src'));
  await writeFile(path.join(cwd, 'src', 'runner.ts'), 'export function runTurn() {}\n', 'utf8');

  const result = await grepTool.execute(
    { grep: { path: 'src', pattern: 'runTurn' } },
    { cwd, session: createSession(cwd) }
  );

  assert.equal(result.status, 'ok');
  assert.match(result.content, /src\/runner\.ts:1:/);
  assert.match(result.content, /runTurn/);
});
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `node --test --import tsx src/protocol/actions.test.ts src/tools/find.test.ts src/tools/grep.test.ts`
Expected: FAIL because `find`/`grep` are not valid parser branches and the two tools do not exist.

- [ ] **Step 3: Implement recursive search with explicit limits**

```ts
// src/config.ts
export const FIND_MAX_RESULTS = 200;
export const GREP_MAX_MATCHES = 200;
export const GREP_MAX_FILE_BYTES = 64_000;
```

```ts
// src/protocol/actions.ts
export type FindAction = {
  path?: string;
  name: string;
};

export type GrepAction = {
  path?: string;
  pattern: string;
};

export type ModelAction =
  | { bash: string }
  | { edit: EditAction }
  | { read: ReadAction }
  | { ls: LsAction }
  | { find: FindAction }
  | { grep: GrepAction }
  | { message: string };
```

```ts
// src/tools/find.ts
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { FIND_MAX_RESULTS } from '../config.js';
import { resolveWorkspacePath } from './path.js';

async function collectMatches(root: string, query: string, cwd: string, out: string[]) {
  const entries = await fs.readdir(root, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (out.length >= FIND_MAX_RESULTS) break;
    const target = path.join(root, entry.name);
    const relativePath = path.relative(cwd, target);
    if (entry.name.includes(query)) out.push(relativePath);
    if (entry.isDirectory()) await collectMatches(target, query, cwd, out);
  }
}

export const findTool: ToolDefinition<{ find: FindAction }> = {
  name: 'find',
  access: 'read',
  supports(action): action is { find: FindAction } {
    return typeof (action as { find?: unknown }).find === 'object' && !!(action as { find?: unknown }).find;
  },
  async execute(action, context) {
    const { target, relativePath } = resolveWorkspacePath(context.cwd, action.find.path ?? '.');
    const matches: string[] = [];
    await collectMatches(target, action.find.name, context.cwd, matches);
    return {
      tool: 'find',
      status: 'ok',
      meta: { path: relativePath, matches: matches.length },
      content: `TOOL_RESULT find OK\npath=${relativePath}\n${matches.join('\n')}`.trim()
    };
  }
};
```

```ts
// src/tools/grep.ts
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { GREP_MAX_FILE_BYTES, GREP_MAX_MATCHES } from '../config.js';
import { resolveWorkspacePath } from './path.js';

async function collectGrepMatches(root: string, pattern: string, cwd: string, out: string[]) {
  const entries = await fs.readdir(root, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (out.length >= GREP_MAX_MATCHES) break;
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) {
      await collectGrepMatches(target, pattern, cwd, out);
      continue;
    }

    const raw = await fs.readFile(target, 'utf8');
    if (raw.length > GREP_MAX_FILE_BYTES) continue;
    for (const [index, line] of raw.split('\n').entries()) {
      if (out.length >= GREP_MAX_MATCHES) break;
      if (line.includes(pattern)) {
        out.push(`${path.relative(cwd, target)}:${index + 1}: ${line}`);
      }
    }
  }
}

export const grepTool: ToolDefinition<{ grep: GrepAction }> = {
  name: 'grep',
  access: 'read',
  supports(action): action is { grep: GrepAction } {
    return typeof (action as { grep?: unknown }).grep === 'object' && !!(action as { grep?: unknown }).grep;
  },
  async execute(action, context) {
    const { target, relativePath } = resolveWorkspacePath(context.cwd, action.grep.path ?? '.');
    const matches: string[] = [];
    await collectGrepMatches(target, action.grep.pattern, context.cwd, matches);
    return {
      tool: 'grep',
      status: 'ok',
      meta: { path: relativePath, matches: matches.length },
      content: `TOOL_RESULT grep OK\npath=${relativePath}\n${matches.join('\n')}`.trim()
    };
  }
};
```

```ts
// src/tools/registry.ts
import { findTool } from './find.js';
import { grepTool } from './grep.js';
import { bashTool } from './bash.js';
import { editTool } from './edit.js';
import { readTool } from './read.js';
import { lsTool } from './ls.js';
import type { ModelAction } from '../protocol/actions.js';
import type { ToolDefinition } from './types.js';

const coreTools: ToolDefinition[] = [bashTool, editTool, readTool, lsTool, findTool, grepTool];

export function createToolRegistry(definitions: ToolDefinition[] = coreTools) {
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

```ts
// src/prompt/system.ts
{"find":{"path":"src","name":"runner"}}
{"grep":{"path":"src","pattern":"runTurn"}}
Use read/ls/find/grep before reaching for bash when you only need inspection.
```

- [ ] **Step 4: Run the focused tests**

Run: `node --test --import tsx src/protocol/actions.test.ts src/tools/find.test.ts src/tools/grep.test.ts`
Expected: PASS for the new parser branches and both recursive search tools.

- [ ] **Step 5: Commit**

```bash
git add src/config.ts src/protocol/actions.ts src/protocol/actions.test.ts src/tools/find.ts src/tools/find.test.ts src/tools/grep.ts src/tools/grep.test.ts src/tools/registry.ts src/prompt/system.ts
git commit -m "feat: add find and grep tools"
```

### Task 4: Enforce Policy Modes In The Runner And Document The Surface

**Files:**
- Modify: `src/runtime/runner.ts`
- Modify: `src/runtime/runner.test.ts`
- Modify: `src/tools/bash.ts`
- Modify: `src/tools/edit.ts`
- Modify: `src/cli.ts`
- Modify: `src/prompt/system.ts`
- Modify: `README.md`

- [ ] **Step 1: Write failing runner tests for policy denial and confirmation**

```ts
// src/runtime/runner.test.ts
import { createPolicyEngine } from '../policy/engine.js';

test('runner records a denied bash action when mode is read-only', async () => {
  const outputs: string[] = [];
  const model = createFakeModel([
    '{"bash":"pwd"}',
    '{"message":"done"}'
  ]);

  const runner = createRunner({
    model,
    policy: createPolicyEngine({ mode: 'read-only' }),
    hooks: [
      {
        afterTool(_session, result) {
          outputs.push(result.content);
        }
      }
    ]
  });

  const finalMessage = await runner.runTurn(createSession('/tmp/workspace'), 'inspect repo');

  assert.equal(finalMessage, 'done');
  assert.match(outputs[0] ?? '', /policy mode read-only blocks exec tools/);
});

test('runner executes edit only after confirmation in confirm-write mode', async () => {
  let prompted = 0;
  const policy = createPolicyEngine({
    mode: 'confirm-write',
    confirm: async () => {
      prompted += 1;
      return true;
    }
  });

  const model = createFakeModel([
    '{"edit":{"path":"file.txt","old_text":"before","new_text":"after"}}',
    '{"message":"done"}'
  ]);
  const editExecutions: string[] = [];

  const runner = createRunner({
    model,
    policy,
    registry: createToolRegistry([
      {
        name: 'edit',
        access: 'write',
        supports(action): action is { edit: { path: string; old_text: string; new_text: string } } {
          return 'edit' in action;
        },
        async execute(action) {
          editExecutions.push(action.edit.path);
          return {
            tool: 'edit',
            status: 'ok',
            meta: { path: action.edit.path },
            content: `TOOL_RESULT edit OK\npath=${action.edit.path}`
          };
        }
      }
    ])
  });

  await runner.runTurn(createSession('/tmp/workspace'), 'apply edit');
  assert.equal(prompted, 1);
  assert.deepEqual(editExecutions, ['file.txt']);
});
```

- [ ] **Step 2: Run the runner tests to verify they fail**

Run: `node --test --import tsx src/runtime/runner.test.ts`
Expected: FAIL because `createRunner` does not accept a policy engine and denial results are not synthesized yet.

- [ ] **Step 3: Mark tool access levels and enforce policy before execution**

```ts
// src/tools/bash.ts
export const bashTool: ToolDefinition<{ bash: string }> = {
  name: 'bash',
  access: 'exec'
};
```

```ts
// src/tools/edit.ts
export const editTool: ToolDefinition<EditModelAction> = {
  name: 'edit',
  access: 'write'
};
```

Keep the current `supports(...)` and `execute(...)` implementations for both tools unchanged in this task; only the new `access` field is added here.

```ts
// src/runtime/runner.ts
import { createPolicyEngine } from '../policy/engine.js';
import type { ToolResult } from '../tools/types.js';

export function createRunner({
  model,
  registry = createToolRegistry(),
  hooks = [],
  policy = createPolicyEngine({ mode: 'auto' })
}: {
  model: ModelClient;
  registry?: ReturnType<typeof createToolRegistry>;
  hooks?: RuntimeHook[];
  policy?: ReturnType<typeof createPolicyEngine>;
}) {
  return {
    async runTurn(session: Session, userInput: string): Promise<string> {
      const cwd = session.cwd;
      await appendRecord(cwd, session, {
        id: makeId('usr'),
        ts: nowIso(),
        kind: 'user',
        role: 'user',
        content: userInput
      });

      await runHooks(hooks, 'beforeTurn', session, userInput);

      for (let i = 0; i < MAX_LOOPS; i += 1) {
        const rawContent = await model.complete(buildChatMessages(session));
        const action = parseModelAction(rawContent);
        const { definition } = registry.resolve(action);
        const authorization = await policy.authorize(definition);

        let result: ToolResult;
        if (!authorization.allowed) {
          result = {
            tool: definition.name,
            status: 'error',
            meta: { policy: policy.mode },
            content: `TOOL_RESULT ${definition.name} ERROR\npolicy=${policy.mode}\n${authorization.reason}`
          };
        } else {
          await runHooks(hooks, 'beforeTool', session, action);
          result = await definition.execute(action as never, { cwd, session });
        }

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
    }
  };
}
```

```ts
// src/cli.ts
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { createPolicyEngine } from './policy/engine.js';

async function confirmTool(prompt: string) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return false;
  }
  const rl = createInterface({ input, output });
  const answer = await rl.question(`${prompt} [y/N] `);
  rl.close();
  return answer.trim().toLowerCase() === 'y';
}

const runner = createRunner({
  model: createOpenRouterClient(),
  hooks: createCliHooks(),
  policy: createPolicyEngine({ mode: policyMode, confirm: confirmTool })
});
```

````md
<!-- README.md -->
## Policy Modes

- `auto`: execute all registered tools
- `confirm-write`: ask before `edit`
- `read-only`: allow only `read`, `ls`, `find`, `grep`
- `confirm-bash`: ask before `bash`
- `confirm-all`: ask before every tool

Example:

```bash
cliq --policy read-only "inspect the repo and explain the runner"
```
````

- [ ] **Step 4: Update the system prompt and help output**

```ts
// src/prompt/system.ts
If you only need to inspect files or search the repo, prefer:
- {"ls":{"path":"src"}}
- {"find":{"path":"src","name":"runner"}}
- {"grep":{"path":"src","pattern":"runTurn"}}
- {"read":{"path":"src/runtime/runner.ts","start_line":1,"end_line":120}}

Only use {"bash":"..."} when structured inspection tools are insufficient.
```

```ts
// src/cli.ts
Env:
  OPENROUTER_API_KEY Required
  CLIQ_POLICY_MODE   Optional (auto | confirm-write | read-only | confirm-bash | confirm-all)
```

- [ ] **Step 5: Run the full verification suite and CLI smoke checks**

Run: `npm test`
Expected: PASS with all prior tests plus the new policy/read-only tests.

Run: `npm run build`
Expected: PASS with no TypeScript errors.

Run: `npm run dev -- --help`
Expected: help output lists the policy env var and still shows `chat`, `reset`, and `history`.

- [ ] **Step 6: Commit**

```bash
git add src/runtime/runner.ts src/runtime/runner.test.ts src/tools/bash.ts src/tools/edit.ts src/cli.ts src/prompt/system.ts README.md
git commit -m "feat: enforce policy modes in runner"
```

## Done Criteria

Phase 1 is complete only when all of the following are true:

- the model can emit `read`, `ls`, `find`, and `grep` actions and the parser accepts them
- all four read-only tools stay inside the workspace and obey output limits
- `bash` is no longer required for ordinary repository inspection
- policy mode can be selected through CLI flag or `CLIQ_POLICY_MODE`
- `read-only` blocks `bash` and `edit`
- confirmation modes degrade safely in non-interactive execution by denying instead of hanging
- runner records denied tools as tool results instead of throwing away the turn
- `npm test`, `npm run build`, and `npm run dev -- --help` all pass
