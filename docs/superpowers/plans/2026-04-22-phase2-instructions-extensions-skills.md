# Phase 2: Instruction Composition, Extensions, And Skills Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `v0.3.0` as the first configurable Cliq runtime where prompt/context growth happens through composed instructions, locally loaded skills, and typed extension contributions instead of hardcoded edits to the CLI and runner.

**Architecture:** Keep the Phase 1 action protocol, tool surface, and session replay model stable where possible, but stop baking the base prompt into session creation. Add a runtime assembly layer that reads workspace config, resolves extensions and skills, builds ordered instruction records for each turn, and wires those contributions into the existing runner. Extensions in this release contribute hooks and instruction sources only; they do **not** add new top-level model actions, which would require a separate protocol redesign.

**Tech Stack:** TypeScript, Node.js built-ins (`fs/promises`, `path`, `url`), existing `node:test` + `tsx` test setup, current CLI/runtime/session modules, ESM `import()` for extension loading.

Reference RFC: [RFC: Cliq Agent Runtime Architecture](../../rfcs/2026-04-17-agent-runtime-architecture.md)

---

## Scope Check

This plan intentionally treats Phase 2 as one release because the three deliverables are tightly coupled around one new boundary: **runtime assembly**.

`v0.3.0` includes:

1. instruction composition
2. extension loading and typed hook/instruction contributions
3. local skill loading and CLI skill activation
4. explicit workspace config for these inputs
5. documentation and tests proving the composed runtime works

`v0.3.0` does **not** include:

- new top-level protocol actions for third-party tools
- session checkpoint / fork / compact
- RPC / JSONL / daemon mode
- streaming output or rich TUI workbench
- sandboxing or richer approval UX than Phase 1
- package-manager-driven install commands such as `cliq install`
- remote marketplace discovery for skills or extensions

## NOT In Scope

This release intentionally does **not** promise:

- npm/package distribution UX for skills or extensions
- extension-contributed model tools or protocol action keys
- runtime inspection UI such as `cliq doctor` or `cliq runtime`
- branchable sessions, compaction, handoff, or queued steering
- RPC/daemon/service embedding
- rich TUI status/footer/tool-collapse UX

These are deferred because they require either a protocol redesign, a broader packaging story, or a separate interaction surface beyond the Phase 2 runtime kernel.

## What Already Exists

Phase 2 should reuse these existing foundations instead of rebuilding them:

- `src/cli.ts`: CLI parsing, one-shot execution, and interactive REPL loop
- `src/runtime/runner.ts`: turn loop, model call, policy gate, tool execution, and result replay
- `src/runtime/hooks.ts`: lifecycle hook fan-out with non-fatal hook isolation
- `src/session/store.ts`: persisted session lifecycle, migration, and replay model
- `src/policy/engine.ts`: policy mode selection and authorization decisions
- `src/tools/path.ts`: canonical workspace-boundary enforcement for filesystem access

The new runtime assembly layer should sit **in front of** these modules and compose them; it should not duplicate their responsibilities.

## v0.3.0 Product Bar

`v0.3.0` only counts as shipped if a real user can do all of the following **without editing Cliq source code**:

1. add `.cliq/config.json` to a repo and change agent behavior for that repo
2. add `.cliq/skills/<name>/SKILL.md` and activate it via `--skill <name>` or `defaultSkills`
3. enable at least one extension from config and see its effect on runtime behavior
4. get a clear, immediate startup error when config, skill, or extension loading is broken
5. keep using Cliq normally in repos that have no Phase 2 config at all

### Why Extensions Do Not Add New Tools In Phase 2

Current protocol parsing in `src/protocol/actions.ts` accepts a closed set of top-level keys (`bash`, `edit`, `read`, `ls`, `find`, `grep`, `message`). Letting external extensions add arbitrary tools in this release would force a protocol redesign at the same time as instruction composition and loader work. That is scope creep and should be deferred to a later protocol-focused release.

Phase 2 extensions may contribute:

- `RuntimeHook[]`
- `InstructionSource[]`

Phase 2 extensions may **not** contribute:

- new protocol action keys
- new `ToolDefinition`s reachable by the model

---

## Release Definition

`v0.3.0` is complete when all of the following are true:

- Cliq loads `.cliq/config.json` if present and behaves the same as `v0.2.0` when it is absent
- Cliq accepts repeated `--skill <name>` flags
- one-shot and interactive CLI flows both use the same runtime assembly path
- new sessions no longer persist a seeded base system prompt record
- legacy sessions migrate by removing only the seeded prompt record while preserving all other records
- runner prepends composed instructions on every turn before replaying session history
- composed instruction messages are **not** persisted as session records
- instruction order is deterministic and tested across repeated turns
- local skills load from `.cliq/skills/<name>/SKILL.md`
- local skills reject malformed frontmatter, mismatched names, and blank prompt bodies
- extensions load from either `builtin:<name>` or a workspace-relative module reference declared in `.cliq/config.json`
- config / skill / extension failures are named, fatal, and include the failing path or specifier in the error message
- at least one built-in extension proves instruction contribution works (`builtin:policy-instructions`)
- README documents the new config, skill, and extension flow
- full manual smoke proves:
  - a repo with no `.cliq/config.json` still works
  - a repo-local skill changes behavior
  - a broken extension path fails fast with a clear error

---

## Target File Structure

- Create: `src/workspace/config.ts`
- Create: `src/workspace/config.test.ts`
- Create: `src/instructions/types.ts`
- Create: `src/instructions/builder.ts`
- Create: `src/instructions/builder.test.ts`
- Create: `src/extensions/types.ts`
- Create: `src/extensions/loader.ts`
- Create: `src/extensions/loader.test.ts`
- Create: `src/extensions/builtin/policy-instructions.ts`
- Create: `src/skills/types.ts`
- Create: `src/skills/loader.ts`
- Create: `src/skills/loader.test.ts`
- Create: `src/runtime/assembly.ts`
- Create: `src/runtime/assembly.test.ts`
- Modify: `src/config.ts`
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`
- Modify: `src/prompt/system.ts`
- Modify: `src/runtime/runner.ts`
- Modify: `src/runtime/runner.test.ts`
- Modify: `src/session/store.ts`
- Modify: `src/session/store.test.ts`
- Modify: `README.md`

### Responsibility Map

- `src/workspace/config.ts`: read and validate `.cliq/config.json`
- `src/instructions/types.ts`: instruction record/source/build context types
- `src/instructions/builder.ts`: deterministic instruction layering and workspace instruction file loading
- `src/extensions/types.ts`: typed extension contract for hooks and instruction sources
- `src/extensions/loader.ts`: resolve `builtin:` aliases plus workspace-relative extension refs
- `src/extensions/builtin/policy-instructions.ts`: inject policy-aware system guidance without hardcoding it into the base prompt
- `src/skills/loader.ts`: load markdown-based skills from `.cliq/skills/<name>/SKILL.md`
- `src/runtime/assembly.ts`: central place that loads config/skills/extensions and returns runner inputs
- `src/runtime/runner.ts`: prepend composed instruction messages before replayed session records
- `src/session/store.ts`: stop seeding the base prompt into new sessions and migrate legacy sessions cleanly
- `src/cli.ts`: expose `--skill`, call the runtime assembly layer, and keep CLI-specific output hooks local

### Runtime Assembly Diagram

```text
user CLI input
     |
     v
 parseArgs (--policy, --skill)
     |
     v
 ensureSession(cwd)
     |
     v
 createRuntimeAssembly(cwd, session, policyMode, cliSkillNames)
     |
     +--> loadWorkspaceConfig(.cliq/config.json)
     |        |
     |        +--> instructionFiles[]
     |        +--> extensions[]
     |        `--> defaultSkills[]
     |
     +--> loadSkills(.cliq/skills/<name>/SKILL.md)
     |
     +--> loadExtensions(builtin:* or workspace-relative module)
     |
     `--> buildInstructionMessages(core -> workspace -> skill -> extension)
                |
                v
         createRunner(..., instructions, hooks, policy)
                |
                v
        runTurn() -> model.complete() -> existing tool loop
```

### Guardrails

- Keep the Phase 1 protocol JSON unchanged
- Do not change the tool registry contract in this release
- Keep session replay text-based and provider-agnostic
- Hard-fail startup on invalid config, missing skills, or extension load failures
- Keep hook execution non-fatal once the runtime is assembled; existing `runHooks` error logging remains the isolation boundary
- Keep all local file references inside the workspace root
- Deduplicate repeated skill names from config and CLI flags while preserving order
- Keep instruction ordering explicit and tested:
  1. `core`
  2. `workspace`
  3. `skill`
  4. `extension`

### Decisions Resolved Now

These decisions should be treated as settled before implementation starts:

- Phase 2 extensions do not register model-callable tools
- runtime assembly is the only new integration boundary; existing runner, policy engine, and session store remain the core loop
- composed instructions are rebuilt per turn but never persisted into session records
- workspace-relative extension refs are supported in this release; package install/discovery is deferred
- loader failures fail fast before the agent starts acting, while hook failures remain non-fatal once runtime assembly succeeds

### Instruction Sources In This Release

Phase 2 uses two instruction channels:

1. **reserved layers owned by runtime assembly**
   - `core`
   - `workspace`
   - `skill`
2. **extension-provided messages**
   - always emitted as `layer: 'extension'`

This keeps ordering deterministic without asking third-party extensions to compete for reserved layers. Policy-aware prompt guidance in this release comes from the built-in extension `builtin:policy-instructions`, not from a separate hardcoded policy layer.

### Workspace Config Shape

Phase 2 uses one explicit config file:

```json
{
  "instructionFiles": [".cliq/instructions.md"],
  "extensions": ["builtin:policy-instructions", "./.cliq/extensions/log-turns.js"],
  "defaultSkills": ["reviewer"]
}
```

All fields are optional. Missing config must behave the same as:

```json
{
  "instructionFiles": [],
  "extensions": [],
  "defaultSkills": []
}
```

### Skill File Shape

Each local skill lives at `.cliq/skills/<name>/SKILL.md` and uses a small frontmatter header:

```md
---
name: reviewer
description: Focus on repo inspection and explanation before edits
---

Prefer read-only inspection first. Summarize structure before proposing mutations.
```

The frontmatter fields are:

- `name` (required)
- `description` (optional)

The markdown body becomes the injected skill prompt.

---

## Task 1: Add Workspace Config And CLI Skill Flags

**Files:**
- Create: `src/workspace/config.ts`
- Create: `src/workspace/config.test.ts`
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`

- [ ] **Step 1: Write the failing config and CLI tests**

```ts
// src/workspace/config.test.ts
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadWorkspaceConfig } from './config.js';

test('loadWorkspaceConfig returns empty defaults when config is missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-config-'));
  try {
    assert.deepEqual(await loadWorkspaceConfig(cwd), {
      instructionFiles: [],
      extensions: [],
      defaultSkills: []
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadWorkspaceConfig validates array fields', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-config-invalid-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({ instructionFiles: 'bad', extensions: [], defaultSkills: [] }),
      'utf8'
    );

    await assert.rejects(() => loadWorkspaceConfig(cwd), /instructionFiles must be an array of strings/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
```

```ts
// src/cli.test.ts
test('parseArgs collects repeated --skill flags', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--skill', 'reviewer', '--skill=safe-edit', 'chat']), {
    cmd: 'chat',
    prompt: '',
    policy: 'auto',
    skills: ['reviewer', 'safe-edit']
  });
});

test('parseArgs rejects missing --skill values', () => {
  assert.throws(
    () => parseArgs(['node', 'src/index.ts', '--skill']),
    /Missing value for --skill/i
  );
});
```

- [ ] **Step 2: Run the new tests to verify the expected failures**

Run: `node --test --import tsx src/workspace/config.test.ts src/cli.test.ts`
Expected: FAIL with missing module errors for `src/workspace/config.ts` and missing `skills` handling in `parseArgs`.

- [ ] **Step 3: Implement workspace config loading and CLI skill parsing**

```ts
// src/workspace/config.ts
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';

export type WorkspaceConfig = {
  instructionFiles: string[];
  extensions: string[];
  defaultSkills: string[];
};

const EMPTY_WORKSPACE_CONFIG: WorkspaceConfig = {
  instructionFiles: [],
  extensions: [],
  defaultSkills: []
};

function readStringArray(record: Record<string, unknown>, key: keyof WorkspaceConfig) {
  const value = record[key];
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`${key} must be an array of strings`);
  }
  return value;
}

export async function loadWorkspaceConfig(cwd: string): Promise<WorkspaceConfig> {
  const target = path.join(cwd, APP_DIR, 'config.json');
  try {
    const parsed = JSON.parse(await fs.readFile(target, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('workspace config must be a JSON object');
    }

    const record = parsed as Record<string, unknown>;
    return {
      instructionFiles: readStringArray(record, 'instructionFiles'),
      extensions: readStringArray(record, 'extensions'),
      defaultSkills: readStringArray(record, 'defaultSkills')
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return EMPTY_WORKSPACE_CONFIG;
    }
    throw error;
  }
}
```

```ts
// src/cli.ts
export function parseArgs(argv: string[]) {
  const raw = argv.slice(2);
  let policy: PolicyMode = DEFAULT_POLICY_MODE;
  const skills: string[] = [];
  // existing env policy handling stays the same

  for (let i = 0; i < raw.length; i += 1) {
    const token = raw[i];

    if (token.startsWith('--skill=')) {
      const value = token.slice('--skill='.length);
      if (!value) {
        throw new Error('Missing value for --skill');
      }
      skills.push(value);
      continue;
    }

    if (token === '--skill') {
      const value = raw[i + 1];
      if (value === undefined || value === '') {
        throw new Error('Missing value for --skill');
      }
      skills.push(value);
      i += 1;
      continue;
    }

    // existing --policy handling and arg collection remain
  }

  const cmd = args[0];
  if (!cmd || cmd === 'chat') return { cmd: 'chat', prompt: args.slice(1).join(' '), policy, skills };
  if (cmd === 'run' || cmd === 'ask') return { cmd: 'chat', prompt: args.slice(1).join(' '), policy, skills };
  if (cmd === 'reset') return { cmd, policy, skills };
  if (cmd === 'history') return { cmd, policy, skills };
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return { cmd: 'help', policy, skills };
  return { cmd: 'chat', prompt: args.join(' '), policy, skills };
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `node --test --import tsx src/workspace/config.test.ts src/cli.test.ts`
Expected: PASS with all config-loader and CLI skill parsing tests green.

- [ ] **Step 5: Commit the config and flag plumbing**

```bash
git add src/workspace/config.ts src/workspace/config.test.ts src/cli.ts src/cli.test.ts
git commit -m "feat: add workspace config and skill flags"
```

---

## Task 2: Introduce Instruction Composition And Remove The Seeded System Prompt

**Files:**
- Create: `src/instructions/types.ts`
- Create: `src/instructions/builder.ts`
- Create: `src/instructions/builder.test.ts`
- Modify: `src/prompt/system.ts`
- Modify: `src/runtime/runner.ts`
- Modify: `src/runtime/runner.test.ts`
- Modify: `src/session/store.ts`
- Modify: `src/session/store.test.ts`
- Modify: `src/config.ts`

- [ ] **Step 1: Write the failing instruction and session migration tests**

```ts
// src/instructions/builder.test.ts
import assert from 'node:assert/strict';
import test from 'node:test';

import { buildInstructionMessages } from './builder.js';

test('buildInstructionMessages preserves deterministic layer order', async () => {
  const messages = await buildInstructionMessages({
    cwd: '/tmp/workspace',
    basePrompt: 'BASE',
    workspaceInstructions: ['WORKSPACE'],
    skills: [{ name: 'reviewer', prompt: 'SKILL' }],
    extensionMessages: [{ role: 'system', layer: 'extension', source: 'logger', content: 'EXTENSION' }]
  });

  assert.deepEqual(
    messages.map((message) => `${message.layer}:${message.source}:${message.content}`),
    [
      'core:base:BASE',
      'workspace:workspace:WORKSPACE',
      'skill:skill:reviewer:SKILL',
      'extension:logger:EXTENSION'
    ]
  );
});
```

```ts
// src/runtime/runner.test.ts
test('runner prepends composed instruction messages before replayed session records', async () => {
  const session = createSession('/tmp/workspace');
  let seenMessages: Array<{ role: string; content: string }> = [];

  const runner = createRunner({
    model: {
      async complete(messages) {
        seenMessages = messages;
        return '{"message":"done"}';
      }
    },
    instructions: async () => [
      { role: 'system', layer: 'core', source: 'base', content: 'BASE' },
      { role: 'system', layer: 'skill', source: 'reviewer', content: 'SKILL' }
    ]
  });

  await runner.runTurn(session, 'say done');

  assert.equal(seenMessages[0]?.content, 'BASE');
  assert.equal(seenMessages[1]?.content, 'SKILL');
  assert.equal(seenMessages[2]?.content, 'say done');
});

test('runner does not persist composed instruction messages into the session record log', async () => {
  const session = createSession('/tmp/workspace');

  const runner = createRunner({
    model: {
      async complete() {
        return '{"message":"done"}';
      }
    },
    instructions: async () => [
      { role: 'system', layer: 'core', source: 'base', content: 'BASE' },
      { role: 'system', layer: 'skill', source: 'reviewer', content: 'SKILL' }
    ]
  });

  await runner.runTurn(session, 'say done');

  assert.equal(session.records.some((record) => record.kind === 'system'), false);
});
```

```ts
// src/session/store.test.ts
test('createSession starts without a seeded system record', () => {
  const session = createSession('/tmp/workspace');
  assert.deepEqual(session.records, []);
});

test('ensureSession strips the legacy seeded system prompt during migration', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-migrate-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 2,
        app: 'cliq',
        model: 'anthropic/claude-sonnet-4.6',
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 0 },
        records: [
          {
            id: 'sys_1',
            ts: '2026-04-01T00:00:00.000Z',
            kind: 'system',
            role: 'system',
            content: SYSTEM_PROMPT
          }
        ]
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.deepEqual(session.records, []);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('ensureSession preserves non-system records when stripping the legacy seeded prompt', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-session-migrate-preserve-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'session.json'),
      JSON.stringify({
        version: 2,
        app: 'cliq',
        model: 'anthropic/claude-sonnet-4.6',
        cwd,
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:00:00.000Z',
        lifecycle: { status: 'idle', turn: 2 },
        records: [
          {
            id: 'sys_1',
            ts: '2026-04-01T00:00:00.000Z',
            kind: 'system',
            role: 'system',
            content: SYSTEM_PROMPT
          },
          {
            id: 'usr_1',
            ts: '2026-04-01T00:00:01.000Z',
            kind: 'user',
            role: 'user',
            content: 'inspect the repo'
          },
          {
            id: 'ast_1',
            ts: '2026-04-01T00:00:02.000Z',
            kind: 'assistant',
            role: 'assistant',
            content: '{"message":"done"}',
            action: { message: 'done' }
          }
        ]
      }),
      'utf8'
    );

    const session = await ensureSession(cwd);
    assert.deepEqual(
      session.records.map((record) => record.kind),
      ['user', 'assistant']
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run the focused tests to verify the expected failures**

Run: `node --test --import tsx src/instructions/builder.test.ts src/runtime/runner.test.ts src/session/store.test.ts`
Expected: FAIL because the instruction builder does not exist, `createRunner` cannot accept composed instructions yet, and sessions still seed `SYSTEM_PROMPT`.

- [ ] **Step 3: Implement instruction types, builder, runner wiring, and session migration**

```ts
// src/instructions/types.ts
import type { ChatMessage } from '../model/types.js';
import type { Session } from '../session/types.js';

export type InstructionLayer = 'core' | 'workspace' | 'skill' | 'extension';

export type InstructionMessage = ChatMessage & {
  role: 'system';
  layer: InstructionLayer;
  source: string;
};

export type LoadedSkillPrompt = {
  name: string;
  prompt: string;
};

export type BuildInstructionMessagesOptions = {
  cwd: string;
  basePrompt: string;
  workspaceInstructions: string[];
  skills: LoadedSkillPrompt[];
  extensionMessages: InstructionMessage[];
  session?: Session;
};
```

```ts
// src/instructions/builder.ts
import { promises as fs } from 'node:fs';
import { resolveWorkspacePath } from '../tools/path.js';

import type { BuildInstructionMessagesOptions, InstructionMessage } from './types.js';

export async function loadWorkspaceInstructionFiles(cwd: string, files: string[]) {
  const loaded: string[] = [];
  for (const file of files) {
    const { targetRealPath } = await resolveWorkspacePath(cwd, file);
    loaded.push((await fs.readFile(targetRealPath, 'utf8')).trim());
  }
  return loaded.filter(Boolean);
}

export async function buildInstructionMessages(options: BuildInstructionMessagesOptions): Promise<InstructionMessage[]> {
  const messages: InstructionMessage[] = [
    { role: 'system', layer: 'core', source: 'base', content: options.basePrompt }
  ];

  for (const instruction of options.workspaceInstructions) {
    messages.push({
      role: 'system',
      layer: 'workspace',
      source: 'workspace',
      content: instruction
    });
  }

  for (const skill of options.skills) {
    messages.push({
      role: 'system',
      layer: 'skill',
      source: `skill:${skill.name}`,
      content: skill.prompt
    });
  }

  messages.push(...options.extensionMessages);
  return messages;
}
```

```ts
// src/runtime/runner.ts
import type { InstructionMessage } from '../instructions/types.js';

function buildChatMessages(session: Session, instructions: InstructionMessage[]): ChatMessage[] {
  return [
    ...instructions.map(({ role, content }) => ({ role, content })),
    ...session.records.map((record) =>
      record.kind === 'tool'
        ? { role: 'user', content: record.content }
        : { role: record.role, content: record.content }
    )
  ];
}

export function createRunner({
  model,
  registry = createToolRegistry(),
  hooks = [],
  policy = createPolicyEngine({ mode: DEFAULT_POLICY_MODE }),
  instructions = async () => []
}: {
  model: ModelClient;
  registry?: ReturnType<typeof createToolRegistry>;
  hooks?: RuntimeHook[];
  policy?: ReturnType<typeof createPolicyEngine>;
  instructions?: (session: Session) => Promise<InstructionMessage[]>;
}) {
  return {
    async runTurn(session: Session, userInput: string): Promise<string> {
      const cwd = session.cwd;
      try {
        // existing turn setup remains
        for (let i = 0; i < MAX_LOOPS; i += 1) {
          const rawContent = await model.complete(buildChatMessages(session, await instructions(session)));
          // existing loop body remains
        }
      } finally {
        session.lifecycle.status = 'idle';
        await saveSession(cwd, session);
      }
    }
  };
}
```

```ts
// src/session/store.ts
import { BASE_SYSTEM_PROMPT } from '../prompt/system.js';

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
    records: []
  };
}

function stripSeededSystemPrompt(records: SessionRecord[]) {
  return records.filter((record, index) => {
    return !(
      index === 0 &&
      record.kind === 'system' &&
      record.role === 'system' &&
      (record.content === BASE_SYSTEM_PROMPT || record.content === SYSTEM_PROMPT)
    );
  });
}

function migrateLegacySession(cwd: string, legacy: LegacySession): Session {
  const session = createSession(cwd);
  // existing migration loop stays the same
  session.records = stripSeededSystemPrompt(session.records);
  return session;
}
```

```ts
// src/config.ts
export const SESSION_VERSION = 3;
```

```ts
// src/prompt/system.ts
export const BASE_SYSTEM_PROMPT = `You are a tiny coding agent inside a local CLI runtime.
Return exactly one JSON object and nothing else.

Allowed response shapes:
- {"bash":"<shell command>"}
- {"edit":{"path":"<workspace-relative-path>","old_text":"<exact old text>","new_text":"<replacement text>"}}
- {"read":{"path":"<workspace-relative-path>","start_line":1,"end_line":120}}
- {"ls":{"path":"<workspace-relative-path>"}}
- {"find":{"path":"<workspace-relative-path>","name":"<substring>"}}
- {"grep":{"path":"<workspace-relative-path>","pattern":"<substring>"}}
- {"message":"<final user-facing response>"}
`;

export const SYSTEM_PROMPT = BASE_SYSTEM_PROMPT;
```

- [ ] **Step 4: Run the focused tests to verify the migration and builder pass**

Run: `node --test --import tsx src/instructions/builder.test.ts src/runtime/runner.test.ts src/session/store.test.ts`
Expected: PASS with deterministic instruction ordering and migrated sessions no longer containing a seeded base prompt record.

- [ ] **Step 5: Commit the instruction and session foundation**

```bash
git add src/instructions src/prompt/system.ts src/runtime/runner.ts src/runtime/runner.test.ts src/session/store.ts src/session/store.test.ts src/config.ts
git commit -m "feat: compose runtime instructions per turn"
```

---

## Task 3: Add The Extension Contract And Loader

**Files:**
- Create: `src/extensions/types.ts`
- Create: `src/extensions/loader.ts`
- Create: `src/extensions/loader.test.ts`
- Create: `src/extensions/builtin/policy-instructions.ts`

- [ ] **Step 1: Write the failing extension loader tests**

```ts
// src/extensions/loader.test.ts
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadExtensions } from './loader.js';

test('loadExtensions resolves built-in extension aliases', async () => {
  const loaded = await loadExtensions('/tmp/workspace', ['builtin:policy-instructions']);
  assert.equal(loaded[0]?.name, 'policy-instructions');
});

test('loadExtensions resolves workspace-relative extension modules', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-extension-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'echo.js'),
      `export default {
        name: 'echo',
        instructionSources: [
          async () => [{ role: 'system', layer: 'extension', source: 'echo', content: 'EXTENSION ECHO' }]
        ],
        hooks: []
      };`,
      'utf8'
    );

    const loaded = await loadExtensions(cwd, ['./.cliq/extensions/echo.js']);
    assert.equal(loaded[0]?.name, 'echo');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadExtensions rejects duplicate extension names', async () => {
  await assert.rejects(
    () => loadExtensions('/tmp/workspace', ['builtin:policy-instructions', 'builtin:policy-instructions']),
    /duplicate extension name/i
  );
});

test('loadExtensions reports the failing specifier on import failure', async () => {
  await assert.rejects(
    () => loadExtensions('/tmp/workspace', ['./.cliq/extensions/missing.js']),
    /missing\.js/i
  );
});
```

- [ ] **Step 2: Run the extension tests to verify the expected failures**

Run: `node --test --import tsx src/extensions/loader.test.ts`
Expected: FAIL with missing module errors for the extension loader and built-in extension.

- [ ] **Step 3: Implement the extension contract, built-in policy extension, and loader**

```ts
// src/extensions/types.ts
import type { InstructionMessage } from '../instructions/types.js';
import type { PolicyMode } from '../policy/types.js';
import type { RuntimeHook } from '../runtime/hooks.js';
import type { Session } from '../session/types.js';

export type ExtensionInstructionSource = (context: {
  cwd: string;
  session: Session;
  policyMode: PolicyMode;
}) => Promise<InstructionMessage[]> | InstructionMessage[];

export type CliqExtension = {
  name: string;
  instructionSources?: ExtensionInstructionSource[];
  hooks?: RuntimeHook[];
};
```

```ts
// src/extensions/builtin/policy-instructions.ts
import type { CliqExtension } from '../types.js';

export const policyInstructionsExtension: CliqExtension = {
  name: 'policy-instructions',
  instructionSources: [
    async ({ policyMode }) => {
      if (policyMode === 'auto') return [];
      return [
        {
          role: 'system',
          layer: 'extension',
          source: 'policy-instructions',
          content: `Current policy mode is ${policyMode}. Plan actions that can succeed under this mode and explain when a write or exec step would be blocked.`
        }
      ];
    }
  ],
  hooks: []
};
```

```ts
// src/extensions/loader.ts
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { resolveWorkspacePath } from '../tools/path.js';
import type { CliqExtension } from './types.js';
import { policyInstructionsExtension } from './builtin/policy-instructions.js';

const BUILTIN_EXTENSIONS: Record<string, CliqExtension> = {
  'policy-instructions': policyInstructionsExtension
};

async function importExtension(specifier: string, cwd: string): Promise<CliqExtension> {
  if (specifier.startsWith('builtin:')) {
    const builtin = BUILTIN_EXTENSIONS[specifier.slice('builtin:'.length)];
    if (!builtin) throw new Error(`Unknown built-in extension: ${specifier}`);
    return builtin;
  }

  if (specifier.startsWith('.')) {
    const { targetRealPath } = await resolveWorkspacePath(cwd, specifier);
    try {
      const mod = await import(pathToFileURL(targetRealPath).href);
      return (mod.default ?? mod.extension) as CliqExtension;
    } catch (error) {
      throw new Error(
        `Failed to load extension ${specifier}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  throw new Error(`Unsupported extension specifier in Phase 2: ${specifier}`);
}

export async function loadExtensions(cwd: string, specifiers: string[]) {
  const loaded: CliqExtension[] = [];
  const names = new Set<string>();

  for (const specifier of specifiers) {
    const extension = await importExtension(specifier, cwd);
    if (!extension || typeof extension.name !== 'string') {
      throw new Error(`Extension ${specifier} must export a named CliqExtension`);
    }
    if (names.has(extension.name)) {
      throw new Error(`duplicate extension name: ${extension.name}`);
    }
    names.add(extension.name);
    loaded.push({
      name: extension.name,
      instructionSources: extension.instructionSources ?? [],
      hooks: extension.hooks ?? []
    });
  }

  return loaded;
}
```

- [ ] **Step 4: Run the focused extension tests to verify they pass**

Run: `node --test --import tsx src/extensions/loader.test.ts`
Expected: PASS with built-in alias resolution, workspace-relative module loading, and duplicate-name protection.

- [ ] **Step 5: Commit the extension loader**

```bash
git add src/extensions
git commit -m "feat: add extension loader and built-in policy overlay"
```

---

## Task 4: Add The Local Skill Loader

**Files:**
- Create: `src/skills/types.ts`
- Create: `src/skills/loader.ts`
- Create: `src/skills/loader.test.ts`

- [ ] **Step 1: Write the failing skill loader tests**

```ts
// src/skills/loader.test.ts
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadSkills, mergeSkillNames } from './loader.js';

test('mergeSkillNames preserves order and removes duplicates', () => {
  assert.deepEqual(mergeSkillNames(['reviewer', 'safe-edit'], ['safe-edit', 'planner']), [
    'reviewer',
    'safe-edit',
    'planner'
  ]);
});

test('loadSkills reads SKILL.md from the workspace skill directory', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
      `---
name: reviewer
description: inspection-first review mode
---

Prefer read-only inspection before edits.`,
      'utf8'
    );

    const loaded = await loadSkills(cwd, ['reviewer']);
    assert.equal(loaded[0]?.name, 'reviewer');
    assert.match(loaded[0]?.prompt ?? '', /Prefer read-only inspection/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with missing name frontmatter', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-invalid-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'broken'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'broken', 'SKILL.md'),
      `---
description: missing name
---

Prompt body.`,
      'utf8'
    );

    await assert.rejects(() => loadSkills(cwd, ['broken']), /must declare a name/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadSkills rejects a skill file with a blank prompt body', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-skill-empty-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'empty'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'empty', 'SKILL.md'),
      `---
name: empty
---
`,
      'utf8'
    );

    await assert.rejects(() => loadSkills(cwd, ['empty']), /prompt body must not be empty/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run the new skill tests to verify the expected failures**

Run: `node --test --import tsx src/skills/loader.test.ts`
Expected: FAIL because the skill loader does not exist yet.

- [ ] **Step 3: Implement local skill parsing and name merging**

```ts
// src/skills/types.ts
export type LoadedSkill = {
  name: string;
  description: string | null;
  prompt: string;
};
```

```ts
// src/skills/loader.ts
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { APP_DIR } from '../config.js';
import type { LoadedSkill } from './types.js';

export function mergeSkillNames(defaultSkills: string[], cliSkills: string[]) {
  return [...new Set([...defaultSkills, ...cliSkills])];
}

function parseSkillMarkdown(raw: string): LoadedSkill {
  const match = raw.match(/^---\n([\s\S]*?)\n---\n+([\s\S]*)$/);
  if (!match) {
    throw new Error('Skill file must begin with frontmatter');
  }

  const headers = Object.fromEntries(
    match[1]
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const [key, ...rest] = line.split(':');
        return [key.trim(), rest.join(':').trim()];
      })
  );

  if (!headers.name) {
    throw new Error('Skill file must declare a name');
  }

  const prompt = match[2].trim();
  if (!prompt) {
    throw new Error('Skill prompt body must not be empty');
  }

  return {
    name: headers.name,
    description: headers.description ?? null,
    prompt
  };
}

export async function loadSkills(cwd: string, names: string[]): Promise<LoadedSkill[]> {
  const loaded: LoadedSkill[] = [];
  for (const name of names) {
    const target = path.join(cwd, APP_DIR, 'skills', name, 'SKILL.md');
    const raw = await fs.readFile(target, 'utf8');
    const skill = parseSkillMarkdown(raw);
    if (skill.name !== name) {
      throw new Error(`Skill ${name} must declare matching frontmatter name`);
    }
    loaded.push(skill);
  }
  return loaded;
}
```

- [ ] **Step 4: Run the skill loader tests to verify they pass**

Run: `node --test --import tsx src/skills/loader.test.ts`
Expected: PASS with deterministic name merging and markdown skill loading.

- [ ] **Step 5: Commit the skill loader**

```bash
git add src/skills
git commit -m "feat: add local skill loader"
```

---

## Task 5: Add Runtime Assembly And Wire It Into The CLI

**Files:**
- Create: `src/runtime/assembly.ts`
- Create: `src/runtime/assembly.test.ts`
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`

- [ ] **Step 1: Write the failing runtime assembly tests**

```ts
// src/runtime/assembly.test.ts
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createRuntimeAssembly } from './assembly.js';
import { createSession } from '../session/store.js';

test('createRuntimeAssembly merges config skills, CLI skills, and extension instructions', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-assembly-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
    await mkdir(path.join(cwd, '.cliq', 'skills', 'safe-edit'), { recursive: true });
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        instructionFiles: ['.cliq/instructions.md'],
        extensions: ['builtin:policy-instructions', './.cliq/extensions/echo.js'],
        defaultSkills: ['reviewer']
      }),
      'utf8'
    );
    await writeFile(path.join(cwd, '.cliq', 'instructions.md'), 'Workspace instruction file.', 'utf8');
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
      `---
name: reviewer
---

Review before editing.`,
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'safe-edit', 'SKILL.md'),
      `---
name: safe-edit
---

Prefer exact edits over shell mutation when possible.`,
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'echo.js'),
      `export default {
        name: 'echo',
        instructionSources: [
          async () => [{ role: 'system', layer: 'extension', source: 'echo', content: 'EXTENSION ECHO' }]
        ],
        hooks: []
      };`,
      'utf8'
    );

    const assembly = await createRuntimeAssembly({
      cwd,
      session: createSession(cwd),
      policyMode: 'read-only',
      cliSkillNames: ['safe-edit']
    });

    const messages = await assembly.instructions(assembly.session);

    assert.deepEqual(assembly.skillNames, ['reviewer', 'safe-edit']);
    assert.equal(assembly.extensionNames.includes('policy-instructions'), true);
    assert.equal(messages.some((message) => message.layer === 'workspace'), true);
    assert.equal(messages.some((message) => message.source === 'echo'), true);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createRuntimeAssembly surfaces extension instruction source failures clearly', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-assembly-fail-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        extensions: ['./.cliq/extensions/broken.js']
      }),
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'broken.js'),
      `export default {
        name: 'broken',
        instructionSources: [async () => { throw new Error('instruction source exploded'); }],
        hooks: []
      };`,
      'utf8'
    );

    const assembly = await createRuntimeAssembly({
      cwd,
      session: createSession(cwd),
      policyMode: 'auto',
      cliSkillNames: []
    });

    await assert.rejects(
      () => assembly.instructions(assembly.session),
      /Extension broken instruction source failed: instruction source exploded/i
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
```

```ts
// src/cli.test.ts
test('parseArgs keeps skills on non-chat commands for downstream assembly parity', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', '--skill', 'reviewer', 'history']), {
    cmd: 'history',
    policy: 'auto',
    skills: ['reviewer']
  });
});
```

- [ ] **Step 2: Run the assembly tests to verify the expected failures**

Run: `node --test --import tsx src/runtime/assembly.test.ts src/cli.test.ts`
Expected: FAIL with missing `src/runtime/assembly.ts` and CLI/runtime not yet assembled through one helper.

- [ ] **Step 3: Implement the runtime assembly layer and switch the CLI to use it**

```ts
// src/runtime/assembly.ts
import { BASE_SYSTEM_PROMPT } from '../prompt/system.js';
import { loadExtensions } from '../extensions/loader.js';
import { buildInstructionMessages, loadWorkspaceInstructionFiles } from '../instructions/builder.js';
import { mergeSkillNames, loadSkills } from '../skills/loader.js';
import { loadWorkspaceConfig } from '../workspace/config.js';
import type { PolicyMode } from '../policy/types.js';
import type { Session } from '../session/types.js';

export async function createRuntimeAssembly({
  cwd,
  session,
  policyMode,
  cliSkillNames
}: {
  cwd: string;
  session: Session;
  policyMode: PolicyMode;
  cliSkillNames: string[];
}) {
  const workspaceConfig = await loadWorkspaceConfig(cwd);
  const skillNames = mergeSkillNames(workspaceConfig.defaultSkills, cliSkillNames);
  const extensions = await loadExtensions(cwd, workspaceConfig.extensions);
  const skills = await loadSkills(cwd, skillNames);
  const workspaceInstructions = await loadWorkspaceInstructionFiles(cwd, workspaceConfig.instructionFiles);

  return {
    skillNames,
    extensionNames: extensions.map((extension) => extension.name),
    hooks: extensions.flatMap((extension) => extension.hooks ?? []),
    session,
    async instructions(currentSession: Session) {
      const extensionMessages = (
        await Promise.all(
          extensions.flatMap((extension) =>
            (extension.instructionSources ?? []).map(async (source) => {
              try {
                return await source({ cwd, session: currentSession, policyMode });
              } catch (error) {
                throw new Error(
                  `Extension ${extension.name} instruction source failed: ${
                    error instanceof Error ? error.message : String(error)
                  }`
                );
              }
            })
          )
        )
      ).flat();

      return buildInstructionMessages({
        cwd,
        basePrompt: BASE_SYSTEM_PROMPT,
        workspaceInstructions,
        skills: skills.map((skill) => ({ name: skill.name, prompt: skill.prompt })),
        extensionMessages
      });
    }
  };
}
```

```ts
// src/cli.ts
import { createRuntimeAssembly } from './runtime/assembly.js';

export async function runCli(argv: string[]) {
  const { cmd, prompt, policy, skills } = parseArgs(argv) as {
    cmd: string;
    prompt?: string;
    policy: PolicyMode;
    skills: string[];
  };
  const cwd = process.cwd();
  const session = await ensureSession(cwd);

  const assembly = await createRuntimeAssembly({
    cwd,
    session,
    policyMode: policy,
    cliSkillNames: skills
  });

  if (prompt && prompt.trim()) {
    const runner = createRunner({
      model: createOpenRouterClient(),
      hooks: [...assembly.hooks, ...createCliHooks()],
      policy: createPolicyEngine({ mode: policy, confirm: createConfirmTool() }),
      instructions: assembly.instructions
    });
    const finalMessage = await runner.runTurn(session, prompt.trim());
    console.log(`\n${finalMessage}`);
    return;
  }

  // interactive path uses the same assembly but passes the readline confirmer
}
```

- [ ] **Step 4: Run the assembly tests to verify the new wiring passes**

Run: `node --test --import tsx src/runtime/assembly.test.ts src/cli.test.ts`
Expected: PASS with assembled hooks/instructions and CLI `--skill` data flowing into runtime assembly.

- [ ] **Step 5: Commit the runtime assembly integration**

```bash
git add src/runtime/assembly.ts src/runtime/assembly.test.ts src/cli.ts src/cli.test.ts
git commit -m "feat: assemble runtime from config skills and extensions"
```

---

## Task 6: Document The New Runtime Surface And Verify The Full Release

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the failing documentation checklist to the task notes**

```md
- README must explain `.cliq/config.json`
- README must explain `.cliq/skills/<name>/SKILL.md`
- README must explain `--skill <name>`
- README must explain `builtin:policy-instructions` and local extension module refs
```

- [ ] **Step 2: Update README with the Phase 2 runtime model**

```md
## Workspace Config

Cliq now reads optional runtime config from `./.cliq/config.json`:

{
  "instructionFiles": [".cliq/instructions.md"],
  "extensions": ["builtin:policy-instructions", "./.cliq/extensions/log-turns.js"],
  "defaultSkills": ["reviewer"]
}
```

```md
## Local Skills

Local skills live at `./.cliq/skills/<name>/SKILL.md`:

---
name: reviewer
description: inspection-first review mode
---

Prefer read-only inspection before edits.

Activate one for a run with:

cliq --skill reviewer "inspect the runtime and explain extension loading"
```

```md
## Extensions

Phase 2 extensions add instruction overlays and runtime hooks. Enable a built-in extension:

{
  "extensions": ["builtin:policy-instructions"]
}

Enable a local extension module:

{
  "extensions": ["./.cliq/extensions/log-turns.js"]
}
```

- [ ] **Step 3: Run the full release verification**

Run: `npm test && npm run build`
Expected: PASS with all existing tests plus the new Phase 2 tests green.

- [ ] **Step 4: Commit the docs and final release wiring**

```bash
git add README.md
git commit -m "docs: describe phase2 runtime composition"
```

---

## Final Verification Checklist

Before calling Phase 2 complete:

- [ ] `node --test --import tsx src/workspace/config.test.ts src/instructions/builder.test.ts src/extensions/loader.test.ts src/skills/loader.test.ts src/runtime/assembly.test.ts`
- [ ] `node --test --import tsx src/runtime/runner.test.ts src/session/store.test.ts src/cli.test.ts`
- [ ] `npm test`
- [ ] `npm run build`
- [ ] start Cliq in a repo with no `.cliq/config.json` and confirm behavior still matches `v0.2.0`
- [ ] manual smoke:
  - [ ] run `cliq --skill reviewer "explain the runtime architecture"` in a repo that has `.cliq/skills/reviewer/SKILL.md`
  - [ ] run `cliq --policy read-only "inspect this repo"` with `builtin:policy-instructions` enabled
  - [ ] run Cliq with a missing extension path and verify it exits non-zero with a path-specific error
  - [ ] start `cliq chat --skill reviewer` and verify the session still resumes after `/quit`

## Test Diagram

```text
NEW USER-FACING FLOWS

1. Repo with no Phase 2 config
   cli -> ensureSession -> createRuntimeAssembly(default empty config) -> runner
   tests: workspace/config.test.ts + manual smoke

2. Repo-local skill activation
   cli --skill reviewer -> loadSkills -> buildInstructionMessages -> runner
   tests: cli.test.ts + skills/loader.test.ts + runtime/assembly.test.ts

3. Repo-local extension activation
   .cliq/config.json -> loadExtensions -> extension instructions/hooks -> runner
   tests: extensions/loader.test.ts + runtime/assembly.test.ts

4. Legacy session migration
   old session.json -> ensureSession -> strip only seeded prompt -> preserve other records
   tests: session/store.test.ts

5. Broken config / skill / extension
   startup -> named fatal error -> no agent turn begins
   tests: workspace/config.test.ts + skills/loader.test.ts + extensions/loader.test.ts
```

## Failure Modes And Error Visibility

| Codepath | Failure mode | Expected handling | User-visible outcome | Test |
| --- | --- | --- | --- | --- |
| `loadWorkspaceConfig` | invalid JSON or wrong field type | fail startup immediately | clear config parse/validation error | `src/workspace/config.test.ts` |
| `loadWorkspaceInstructionFiles` | missing or escaped file path | fail startup immediately | clear path-specific error | `src/instructions/builder.test.ts` |
| `loadSkills` | missing file, bad frontmatter, blank prompt, mismatched name | fail startup immediately | clear skill-specific error | `src/skills/loader.test.ts` |
| `loadExtensions` | missing file, unknown builtin alias, duplicate name | fail startup immediately | clear specifier-specific error | `src/extensions/loader.test.ts` |
| `assembly.instructions()` | extension instruction source throws | fail the turn before tool execution | clear turn error, no silent fallback | `src/runtime/assembly.test.ts` or `src/runtime/runner.test.ts` |
| `ensureSession` migration | seeded prompt removed too aggressively | preserve all non-seeded records | existing conversation still resumes | `src/session/store.test.ts` |

Any new codepath that can fail silently is a release blocker for `v0.3.0`.

## Deferred Follow-Ups

Because this repo does not currently maintain `TODOS.md`, Phase 2 defers are captured here explicitly:

- package-installed extension loading and discovery
  Rationale: real package/install UX is a separate capability from local runtime assembly
- extension-contributed tools and protocol versioning
  Rationale: requires redesign of `src/protocol/actions.ts` and tool registration semantics
- runtime inspection commands (`cliq doctor`, loaded skill/extension introspection)
  Rationale: useful, but not required to prove the kernel boundary in `v0.3.0`
- session fork/compact/handoff
  Rationale: important workflow asset work, but orthogonal to instruction/extension composition
- RPC/JSONL/SDK surface
  Rationale: next platform step after local runtime composition is proven stable

## v0.3.0 Changelog Shape

When this plan is fully implemented, `v0.3.0` release notes should be able to claim:

- composable instruction layering instead of a single hardcoded runtime prompt
- explicit workspace runtime config at `.cliq/config.json`
- local skill loading through `.cliq/skills/<name>/SKILL.md`
- extension loading for hook/instruction contributions
- policy-aware prompt layering through runtime assembly instead of a single hardcoded session seed

## Self-Review

Spec coverage check against the RFC:

- instruction composition: covered by Tasks 1, 2, and 5
- hook lifecycle through extensions: covered by Tasks 3 and 5
- skill loading: covered by Task 4
- extension discovery/loading: covered by Tasks 1 and 3
- CLI/runtime surface integration: covered by Task 5
- docs and release verification: covered by Task 6

Placeholder scan result:

- no `TODO`, `TBD`, or “similar to above” shortcuts remain
- all implementation tasks include exact file paths, code targets, commands, and commit messages

Type consistency check:

- config fields stay `instructionFiles`, `extensions`, `defaultSkills`
- runtime assembly returns `skillNames`, `extensionNames`, `hooks`, and `instructions`
- instruction composition uses the fixed layer names `core`, `workspace`, `skill`, `extension`
