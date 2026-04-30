# Auto Compact Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement v1 Auto Compact so Cliq can automatically summarize long sessions before model calls exceed the usable context window.

**Architecture:** Auto Compact stays outside replay assembly as a session service. The runner asks the service before model calls and once after recognized overflow errors; the service owns policy resolution, token estimation, range selection, summarization, and artifact creation. Raw records remain durable, context replay remains `HEAD + active summary + raw tail`, and the runner remains orchestration-only.

**Tech Stack:** TypeScript, Node.js `node:test`, existing `ModelClient`, existing global session store and `mutateSession`, no new runtime dependencies.

---

## File Structure

Create:

- `src/session/auto-compact-config.ts` - Auto Compact config types, defaults, validation, and context-window resolution.
- `src/session/auto-compact-config.test.ts` - config and context-window resolution tests.
- `src/session/auto-compaction.ts` - token estimator, range selection, safe split checks, summarizer prompt/chunking, and `maybeAutoCompact`.
- `src/session/auto-compaction.test.ts` - service-level tests for estimates, ranges, summarization budget, artifact mutation, and skip/error semantics.
- `src/model/errors.ts` - provider error classification for context overflow.
- `src/model/errors.test.ts` - overflow classifier tests.

Modify:

- `src/config.ts` - add `MAX_STORED_TOOL_RESULT_CHARS`.
- `src/model/registry.ts` and `src/model/registry.test.ts` - add static context-window metadata for built-in default models and a descriptor lookup helper.
- `src/workspace/config.ts` and `src/workspace/config.test.ts` - parse `autoCompact`.
- `src/session/types.ts` and `src/session/store.ts` - extend and validate `CompactionArtifact.auto`.
- `src/session/compaction.ts` and `src/session/compaction.test.ts` - allow optional auto metadata when creating a compaction.
- `src/runtime/events.ts` - add compact runtime events.
- `src/runtime/runner.ts` and `src/runtime/runner.test.ts` - enforce stored tool-result cap, call Auto Compact before model calls, and retry once on context overflow.
- `src/cli.ts` and `src/cli.test.ts` - pass Auto Compact config to the runner and render warning/error compact events.

Data flow:

```text
CLI
  load workspace config
  resolve model config
  create runner(autoCompact config + model metadata)

Runner turn loop
  append user
  before model call
    maybeAutoCompact(threshold)
    build HEAD + active summary + tail
    model.complete
      if context overflow:
        maybeAutoCompact(overflow)
        rebuild context
        retry once
  append assistant
  execute tool
  cap stored tool result
  append tool
```

## Task 1: Static Model Context Windows

**Files:**
- Modify: `src/model/registry.ts`
- Modify: `src/model/registry.test.ts`

- [ ] **Step 1: Write failing registry tests**

Add these tests to `src/model/registry.test.ts`:

```ts
import { findKnownModelDescriptor } from './registry.js';

test('known default model descriptors expose context windows', () => {
  const openrouter = findKnownModelDescriptor('openrouter', 'anthropic/claude-sonnet-4.6');
  const anthropic = findKnownModelDescriptor('anthropic', 'claude-sonnet-4-20250514');
  const openai = findKnownModelDescriptor('openai', 'gpt-5.2');

  assert.equal(openrouter?.capabilities.contextWindow, 200_000);
  assert.equal(anthropic?.capabilities.contextWindow, 200_000);
  assert.equal(openai?.capabilities.contextWindow, 128_000);
});

test('findKnownModelDescriptor returns null for unknown models', () => {
  assert.equal(findKnownModelDescriptor('ollama', 'qwen3:4b'), null);
  assert.equal(findKnownModelDescriptor('openai-compatible', 'local-model'), null);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
node --test --import tsx src/model/registry.test.ts
```

Expected: FAIL because `findKnownModelDescriptor` is not exported and descriptors do not yet contain `contextWindow`.

- [ ] **Step 3: Add descriptor metadata and lookup**

Modify `src/model/registry.ts`:

```ts
const CLAUDE_CONTEXT_WINDOW = 200_000;
const OPENAI_DEFAULT_CONTEXT_WINDOW = 128_000;

const TEXT_TO_TEXT = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: false
} satisfies ModelDescriptor['capabilities'];

function withContextWindow(
  capabilities: ModelDescriptor['capabilities'],
  contextWindow: number
): ModelDescriptor['capabilities'] {
  return {
    ...capabilities,
    contextWindow
  };
}
```

Set built-in descriptors:

```ts
{
  provider: 'openrouter',
  model: MODEL,
  displayName: 'Claude Sonnet 4.6 via OpenRouter',
  capabilities: withContextWindow(TEXT_TO_TEXT_REASONING, CLAUDE_CONTEXT_WINDOW)
}
```

```ts
{
  provider: 'anthropic',
  model: 'claude-sonnet-4-20250514',
  displayName: 'Claude Sonnet 4',
  capabilities: withContextWindow(TEXT_TO_TEXT_REASONING, CLAUDE_CONTEXT_WINDOW)
}
```

```ts
{
  provider: 'openai',
  model: 'gpt-5.2',
  displayName: 'GPT-5.2',
  capabilities: withContextWindow(TEXT_TO_TEXT_REASONING, OPENAI_DEFAULT_CONTEXT_WINDOW)
}
```

Export lookup:

```ts
export function findKnownModelDescriptor(provider: ProviderName, model: string): ModelDescriptor | null {
  return getModelProvider(provider).getKnownModels().find((descriptor) => descriptor.model === model) ?? null;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
node --test --import tsx src/model/registry.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/model/registry.ts src/model/registry.test.ts
git commit -m "feat: add static model context windows"
```

## Task 2: Auto Compact Workspace Config

**Files:**
- Create: `src/session/auto-compact-config.ts`
- Create: `src/session/auto-compact-config.test.ts`
- Modify: `src/workspace/config.ts`
- Modify: `src/workspace/config.test.ts`

- [ ] **Step 1: Write failing config tests**

Create `src/session/auto-compact-config.test.ts`:

```ts
import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveAutoCompactConfig } from './auto-compact-config.js';

test('resolveAutoCompactConfig defaults to auto mode with known model context window', () => {
  const resolved = resolveAutoCompactConfig({
    config: {},
    modelContextWindowTokens: 200_000
  });

  assert.equal(resolved.enabled, 'auto');
  assert.equal(resolved.contextWindowTokens, 200_000);
  assert.equal(resolved.contextWindowSource, 'model-descriptor');
  assert.equal(resolved.usableLimitTokens, 160_000);
});

test('resolveAutoCompactConfig prefers workspace context window over model descriptor', () => {
  const resolved = resolveAutoCompactConfig({
    config: { contextWindowTokens: 128_000 },
    modelContextWindowTokens: 200_000
  });

  assert.equal(resolved.contextWindowTokens, 128_000);
  assert.equal(resolved.contextWindowSource, 'config');
});

test('resolveAutoCompactConfig rejects invalid numeric relationships', () => {
  assert.throws(
    () =>
      resolveAutoCompactConfig({
        config: { contextWindowTokens: 10_000, reserveTokens: 10_000 }
      }),
    /reserveTokens must be less than contextWindowTokens/i
  );

  assert.throws(
    () =>
      resolveAutoCompactConfig({
        config: { contextWindowTokens: 100_000, thresholdRatio: 1 }
      }),
    /thresholdRatio must be greater than 0 and less than 1/i
  );

  assert.throws(
    () =>
      resolveAutoCompactConfig({
        config: { contextWindowTokens: 100_000, keepRecentTokens: 90_000 }
      }),
    /keepRecentTokens must be less than usableLimit/i
  );
});

test('resolveAutoCompactConfig leaves unknown auto context unresolved', () => {
  const resolved = resolveAutoCompactConfig({ config: {} });

  assert.equal(resolved.enabled, 'auto');
  assert.equal(resolved.contextWindowTokens, null);
  assert.equal(resolved.contextWindowSource, null);
  assert.equal(resolved.usableLimitTokens, null);
});

test('resolveAutoCompactConfig rejects on mode without a context window', () => {
  assert.throws(
    () => resolveAutoCompactConfig({ config: { enabled: 'on' } }),
    /autoCompact.enabled on requires a context window/i
  );
});
```

Add to `src/workspace/config.test.ts`:

```ts
test('loadWorkspaceConfig reads autoCompact config', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-auto-compact-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        autoCompact: {
          enabled: 'on',
          contextWindowTokens: 128000,
          thresholdRatio: 0.75,
          reserveTokens: 12000,
          keepRecentTokens: 16000,
          minNewTokens: 3000,
          maxThresholdCompactionsPerTurn: 2,
          maxOverflowRetriesPerModelCall: 1
        }
      }),
      'utf8'
    );

    assert.deepEqual((await loadWorkspaceConfig(cwd)).autoCompact, {
      enabled: 'on',
      contextWindowTokens: 128000,
      thresholdRatio: 0.75,
      reserveTokens: 12000,
      keepRecentTokens: 16000,
      minNewTokens: 3000,
      maxThresholdCompactionsPerTurn: 2,
      maxOverflowRetriesPerModelCall: 1
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --test --import tsx src/session/auto-compact-config.test.ts src/workspace/config.test.ts
```

Expected: FAIL because the new module and parser do not exist.

- [ ] **Step 3: Implement config types and resolver**

Create `src/session/auto-compact-config.ts`:

```ts
export type AutoCompactEnabled = 'auto' | 'on' | 'off';
export type AutoCompactContextWindowSource = 'config' | 'model-descriptor' | 'overflow-error';

export type AutoCompactConfig = {
  enabled?: AutoCompactEnabled;
  contextWindowTokens?: number;
  thresholdRatio?: number;
  reserveTokens?: number;
  keepRecentTokens?: number;
  minNewTokens?: number;
  maxThresholdCompactionsPerTurn?: number;
  maxOverflowRetriesPerModelCall?: number;
};

export type ResolvedAutoCompactConfig = {
  enabled: AutoCompactEnabled;
  contextWindowTokens: number | null;
  contextWindowSource: AutoCompactContextWindowSource | null;
  thresholdRatio: number;
  reserveTokens: number;
  keepRecentTokens: number;
  minNewTokens: number;
  maxThresholdCompactionsPerTurn: number;
  maxOverflowRetriesPerModelCall: number;
  usableLimitTokens: number | null;
};

const DEFAULTS = {
  enabled: 'auto' as const,
  thresholdRatio: 0.8,
  reserveTokens: 16_000,
  keepRecentTokens: 20_000,
  minNewTokens: 4_000,
  maxThresholdCompactionsPerTurn: 1,
  maxOverflowRetriesPerModelCall: 1
};

function assertInteger(name: string, value: number, minimum: number) {
  if (!Number.isInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer greater than or equal to ${minimum}`);
  }
}

export function resolveAutoCompactConfig({
  config,
  modelContextWindowTokens,
  overflowContextWindowTokens
}: {
  config: AutoCompactConfig;
  modelContextWindowTokens?: number;
  overflowContextWindowTokens?: number;
}): ResolvedAutoCompactConfig {
  const resolved = {
    ...DEFAULTS,
    ...config
  };

  if (resolved.enabled !== 'auto' && resolved.enabled !== 'on' && resolved.enabled !== 'off') {
    throw new Error('autoCompact.enabled must be one of: auto, on, off');
  }
  if (resolved.thresholdRatio <= 0 || resolved.thresholdRatio >= 1) {
    throw new Error('autoCompact.thresholdRatio must be greater than 0 and less than 1');
  }

  assertInteger('autoCompact.reserveTokens', resolved.reserveTokens, 0);
  assertInteger('autoCompact.keepRecentTokens', resolved.keepRecentTokens, 0);
  assertInteger('autoCompact.minNewTokens', resolved.minNewTokens, 0);
  assertInteger('autoCompact.maxThresholdCompactionsPerTurn', resolved.maxThresholdCompactionsPerTurn, 1);
  assertInteger('autoCompact.maxOverflowRetriesPerModelCall', resolved.maxOverflowRetriesPerModelCall, 1);

  let contextWindowTokens = config.contextWindowTokens ?? modelContextWindowTokens ?? overflowContextWindowTokens ?? null;
  let contextWindowSource: AutoCompactContextWindowSource | null = null;
  if (config.contextWindowTokens !== undefined) contextWindowSource = 'config';
  else if (modelContextWindowTokens !== undefined) contextWindowSource = 'model-descriptor';
  else if (overflowContextWindowTokens !== undefined) contextWindowSource = 'overflow-error';

  if (contextWindowTokens !== null) {
    assertInteger('autoCompact.contextWindowTokens', contextWindowTokens, 1);
    if (resolved.reserveTokens >= contextWindowTokens) {
      throw new Error('autoCompact.reserveTokens must be less than contextWindowTokens');
    }
  }
  if (resolved.enabled === 'on' && contextWindowTokens === null) {
    throw new Error('autoCompact.enabled on requires a context window');
  }

  const usableLimitTokens =
    contextWindowTokens === null
      ? null
      : Math.floor(Math.min(contextWindowTokens * resolved.thresholdRatio, contextWindowTokens - resolved.reserveTokens));

  if (usableLimitTokens !== null && usableLimitTokens <= 0) {
    throw new Error('autoCompact usableLimit must be positive');
  }
  if (usableLimitTokens !== null && resolved.keepRecentTokens >= usableLimitTokens) {
    throw new Error('autoCompact.keepRecentTokens must be less than usableLimit');
  }

  return {
    enabled: resolved.enabled,
    contextWindowTokens,
    contextWindowSource,
    thresholdRatio: resolved.thresholdRatio,
    reserveTokens: resolved.reserveTokens,
    keepRecentTokens: resolved.keepRecentTokens,
    minNewTokens: resolved.minNewTokens,
    maxThresholdCompactionsPerTurn: resolved.maxThresholdCompactionsPerTurn,
    maxOverflowRetriesPerModelCall: resolved.maxOverflowRetriesPerModelCall,
    usableLimitTokens
  };
}
```

- [ ] **Step 4: Parse autoCompact from workspace config**

Modify `src/workspace/config.ts`:

```ts
import type { AutoCompactConfig } from '../session/auto-compact-config.js';
```

Extend `WorkspaceConfig`:

```ts
export type WorkspaceConfig = {
  instructionFiles: string[];
  extensions: string[];
  defaultSkills: string[];
  model?: PartialModelConfig;
  autoCompact: AutoCompactConfig;
};
```

Add default:

```ts
const EMPTY_WORKSPACE_CONFIG: WorkspaceConfig = {
  instructionFiles: [],
  extensions: [],
  defaultSkills: [],
  autoCompact: {}
};
```

Add parser:

```ts
function readNumberField(record: Record<string, unknown>, key: keyof AutoCompactConfig) {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'number') {
    throw new Error(`autoCompact.${String(key)} must be a number`);
  }
  return value;
}

function readAutoCompactConfig(record: Record<string, unknown>): AutoCompactConfig {
  const value = record.autoCompact;
  if (value === undefined) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('autoCompact must be an object');
  }

  const autoCompact = value as Record<string, unknown>;
  const enabled = autoCompact.enabled;
  if (enabled !== undefined && enabled !== 'auto' && enabled !== 'on' && enabled !== 'off') {
    throw new Error('autoCompact.enabled must be one of: auto, on, off');
  }

  return {
    ...(enabled ? { enabled } : {}),
    ...(readNumberField(autoCompact, 'contextWindowTokens') !== undefined
      ? { contextWindowTokens: readNumberField(autoCompact, 'contextWindowTokens') }
      : {}),
    ...(readNumberField(autoCompact, 'thresholdRatio') !== undefined
      ? { thresholdRatio: readNumberField(autoCompact, 'thresholdRatio') }
      : {}),
    ...(readNumberField(autoCompact, 'reserveTokens') !== undefined
      ? { reserveTokens: readNumberField(autoCompact, 'reserveTokens') }
      : {}),
    ...(readNumberField(autoCompact, 'keepRecentTokens') !== undefined
      ? { keepRecentTokens: readNumberField(autoCompact, 'keepRecentTokens') }
      : {}),
    ...(readNumberField(autoCompact, 'minNewTokens') !== undefined
      ? { minNewTokens: readNumberField(autoCompact, 'minNewTokens') }
      : {}),
    ...(readNumberField(autoCompact, 'maxThresholdCompactionsPerTurn') !== undefined
      ? { maxThresholdCompactionsPerTurn: readNumberField(autoCompact, 'maxThresholdCompactionsPerTurn') }
      : {}),
    ...(readNumberField(autoCompact, 'maxOverflowRetriesPerModelCall') !== undefined
      ? { maxOverflowRetriesPerModelCall: readNumberField(autoCompact, 'maxOverflowRetriesPerModelCall') }
      : {})
  };
}
```

Include it in `loadWorkspaceConfig` return:

```ts
const autoCompact = readAutoCompactConfig(record);
return {
  instructionFiles: readStringArray(record, 'instructionFiles'),
  extensions: readStringArray(record, 'extensions'),
  defaultSkills: readStringArray(record, 'defaultSkills'),
  autoCompact,
  ...(model ? { model } : {})
};
```

Update existing `src/workspace/config.test.ts` deep equality assertions so empty workspace config includes `autoCompact: {}`. For example:

```ts
assert.deepEqual(await loadWorkspaceConfig(cwd), {
  instructionFiles: [],
  extensions: [],
  defaultSkills: [],
  autoCompact: {}
});
```

- [ ] **Step 5: Run tests to verify pass**

Run:

```bash
node --test --import tsx src/session/auto-compact-config.test.ts src/workspace/config.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/session/auto-compact-config.ts src/session/auto-compact-config.test.ts src/workspace/config.ts src/workspace/config.test.ts
git commit -m "feat: parse auto compact config"
```

## Task 3: Compaction Artifact Auto Metadata

**Files:**
- Modify: `src/session/types.ts`
- Modify: `src/session/store.ts`
- Modify: `src/session/compaction.ts`
- Modify: `src/session/compaction.test.ts`

- [ ] **Step 1: Write failing compaction metadata test**

Add to `src/session/compaction.test.ts`:

```ts
test('createCompaction persists optional auto metadata', async () => {
  await withCliqHome(async () => {
    const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-compaction-auto-'));
    try {
      const session = createSession(cwd);
      addUserRecords(session, 3);

      const artifact = await createCompaction(cwd, session, {
        endIndexExclusive: 1,
        summaryMarkdown: 'auto summary',
        auto: {
          trigger: 'threshold',
          phase: 'pre-model',
          estimatedTokensBefore: 100_000,
          estimatedTokensAfter: 40_000,
          usableLimitTokens: 80_000,
          contextWindowTokens: 128_000,
          contextWindowSource: 'config',
          keepRecentTokens: 20_000,
          summaryInputBudgetTokens: 100_000
        }
      });

      assert.equal(artifact.auto?.trigger, 'threshold');
      assert.equal(session.compactions[0]?.auto?.contextWindowSource, 'config');
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
node --test --import tsx src/session/compaction.test.ts
```

Expected: FAIL because `CreateCompactionOptions` does not accept `auto`.

- [ ] **Step 3: Extend types**

Modify `src/session/types.ts`:

```ts
export type AutoCompactionMetadata = {
  trigger: 'threshold' | 'overflow';
  phase: 'pre-model' | 'mid-loop';
  estimatedTokensBefore: number;
  estimatedTokensAfter?: number;
  usableLimitTokens?: number;
  contextWindowTokens?: number;
  contextWindowSource?: 'config' | 'model-descriptor' | 'overflow-error';
  keepRecentTokens: number;
  summaryInputBudgetTokens?: number;
  overflowRetryAttempt?: number;
  previousCompactionId?: string;
};
```

Then add to `CompactionArtifact`:

```ts
auto?: AutoCompactionMetadata;
```

- [ ] **Step 4: Validate auto metadata on session load**

Modify `src/session/store.ts`:

```ts
function isAutoCompactionMetadata(value: unknown): value is NonNullable<CompactionArtifact['auto']> {
  if (!value || typeof value !== 'object') return false;
  const auto = value as NonNullable<CompactionArtifact['auto']>;
  return (
    (auto.trigger === 'threshold' || auto.trigger === 'overflow') &&
    (auto.phase === 'pre-model' || auto.phase === 'mid-loop') &&
    typeof auto.estimatedTokensBefore === 'number' &&
    (auto.estimatedTokensAfter === undefined || typeof auto.estimatedTokensAfter === 'number') &&
    (auto.usableLimitTokens === undefined || typeof auto.usableLimitTokens === 'number') &&
    (auto.contextWindowTokens === undefined || typeof auto.contextWindowTokens === 'number') &&
    (auto.contextWindowSource === undefined ||
      auto.contextWindowSource === 'config' ||
      auto.contextWindowSource === 'model-descriptor' ||
      auto.contextWindowSource === 'overflow-error') &&
    typeof auto.keepRecentTokens === 'number' &&
    (auto.summaryInputBudgetTokens === undefined || typeof auto.summaryInputBudgetTokens === 'number') &&
    (auto.overflowRetryAttempt === undefined || typeof auto.overflowRetryAttempt === 'number') &&
    (auto.previousCompactionId === undefined || typeof auto.previousCompactionId === 'string')
  );
}
```

Add to `isCompactionArtifact`:

```ts
&& (artifact.auto === undefined || isAutoCompactionMetadata(artifact.auto))
```

- [ ] **Step 5: Pass auto metadata through createCompaction**

Modify `src/session/compaction.ts`:

```ts
export type CreateCompactionOptions = {
  endIndexExclusive: number;
  summaryMarkdown: string;
  anchorCheckpointId?: string;
  createdBy?: CompactionArtifact['createdBy'];
  details?: CompactionArtifact['details'];
  auto?: CompactionArtifact['auto'];
};
```

Add to artifact construction:

```ts
auto: options.auto
```

- [ ] **Step 6: Run tests to verify pass**

Run:

```bash
node --test --import tsx src/session/compaction.test.ts src/session/store.test.ts
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/session/types.ts src/session/store.ts src/session/compaction.ts src/session/compaction.test.ts
git commit -m "feat: persist auto compaction metadata"
```

## Task 4: Stored Tool Result Admission Cap

**Files:**
- Modify: `src/config.ts`
- Create: `src/tools/results.ts`
- Create: `src/tools/results.test.ts`
- Modify: `src/runtime/runner.ts`
- Modify: `src/runtime/runner.test.ts`

- [ ] **Step 1: Write failing tool result cap tests**

Create `src/tools/results.test.ts`:

```ts
import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeToolResultForStorage } from './results.js';

test('normalizeToolResultForStorage keeps short results unchanged', () => {
  const result = normalizeToolResultForStorage({
    tool: 'bash',
    status: 'ok',
    content: 'TOOL_RESULT bash OK\nshort',
    meta: { exit: 0 }
  }, 100);

  assert.equal(result.content, 'TOOL_RESULT bash OK\nshort');
  assert.deepEqual(result.meta, { exit: 0 });
});

test('normalizeToolResultForStorage caps long results and records truncation metadata', () => {
  const result = normalizeToolResultForStorage({
    tool: 'bash',
    status: 'ok',
    content: `TOOL_RESULT bash OK\n${'x'.repeat(200)}`,
    meta: { exit: 0 }
  }, 80);

  assert.equal(result.content.length <= 80, true);
  assert.match(result.content, /cliq truncated tool result/i);
  assert.equal(result.meta.truncated, true);
  assert.equal(result.meta.originalChars, 220);
  assert.equal(typeof result.meta.storedChars, 'number');
});
```

Add to `src/runtime/runner.test.ts`:

```ts
test('runner caps stored tool result content before appending tool record', async () => {
  const session = await createTempSession();
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"huge"}' : '{"message":"done"}');
      }
    },
    registry: {
      definitions: [],
      resolve() {
        return {
          definition: {
            name: 'bash',
            access: 'exec',
            supports(action: unknown): action is { bash: string } {
              return typeof (action as { bash?: unknown }).bash === 'string';
            },
            async execute() {
              return {
                tool: 'bash',
                status: 'ok' as const,
                content: `TOOL_RESULT bash OK\n${'x'.repeat(20_000)}`,
                meta: { exit: 0 }
              };
            }
          }
        };
      }
    }
  });

  await runner.runTurn(session, 'run huge output');
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(toolRecord?.kind, 'tool');
  assert.match(toolRecord?.content ?? '', /cliq truncated tool result/i);
  assert.equal(toolRecord?.meta?.truncated, true);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --test --import tsx src/tools/results.test.ts src/runtime/runner.test.ts
```

Expected: FAIL because `src/tools/results.ts` does not exist.

- [ ] **Step 3: Implement central cap**

Modify `src/config.ts`:

```ts
export const MAX_STORED_TOOL_RESULT_CHARS = 12_000;
```

Create `src/tools/results.ts`:

```ts
import { MAX_STORED_TOOL_RESULT_CHARS } from '../config.js';
import type { ToolResult } from './types.js';

export function normalizeToolResultForStorage(
  result: ToolResult,
  maxChars = MAX_STORED_TOOL_RESULT_CHARS
): ToolResult {
  if (result.content.length <= maxChars) {
    return result;
  }

  const marker = `\n\n[cliq truncated tool result: originalChars=${result.content.length}]`;
  const contentBudget = Math.max(0, maxChars - marker.length);
  const prefixBudget = Math.ceil(contentBudget * 0.4);
  const suffixBudget = Math.max(0, contentBudget - prefixBudget);
  const prefix = result.content.slice(0, prefixBudget);
  const suffix = suffixBudget > 0 ? result.content.slice(-suffixBudget) : '';
  const content = `${prefix}${marker}${suffix}`.slice(0, maxChars);

  return {
    ...result,
    content,
    meta: {
      ...result.meta,
      truncated: true,
      originalChars: result.content.length,
      storedChars: content.length
    }
  };
}
```

- [ ] **Step 4: Use cap in runner**

Modify `src/runtime/runner.ts`:

```ts
import { normalizeToolResultForStorage } from '../tools/results.js';
```

Before `appendRecord` for a tool record:

```ts
const storedResult = normalizeToolResultForStorage(result);
await appendRecord(cwd, session, {
  id: makeId('tool'),
  ts: nowIso(),
  kind: 'tool',
  role: 'user',
  tool: storedResult.tool,
  status: storedResult.status,
  content: storedResult.content,
  meta: storedResult.meta
});
await runHooks(hooks, 'afterTool', session, storedResult);
await onEvent({ type: 'tool-end', tool: storedResult.tool, status: storedResult.status });
```

- [ ] **Step 5: Run tests to verify pass**

Run:

```bash
node --test --import tsx src/tools/results.test.ts src/runtime/runner.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/config.ts src/tools/results.ts src/tools/results.test.ts src/runtime/runner.ts src/runtime/runner.test.ts
git commit -m "feat: cap stored tool results"
```

## Task 5: Token Estimator And Range Selection

**Files:**
- Create: `src/session/auto-compaction.ts`
- Create: `src/session/auto-compaction.test.ts`

- [ ] **Step 1: Write failing estimator and range tests**

Create the first version of `src/session/auto-compaction.test.ts`:

```ts
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createSession } from './store.js';
import {
  estimateMessagesTokens,
  estimateRecordTokens,
  selectAutoCompactRange,
  serializeRecordForSummary
} from './auto-compaction.js';

async function withTempSession(callback: (input: { cwd: string; session: ReturnType<typeof createSession> }) => Promise<void>) {
  const originalCliqHome = process.env.CLIQ_HOME;
  const cliqHome = await mkdtemp(path.join(os.tmpdir(), 'cliq-auto-compact-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-auto-compact-workspace-'));
  try {
    process.env.CLIQ_HOME = cliqHome;
    await callback({ cwd, session: createSession(cwd) });
  } finally {
    if (originalCliqHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = originalCliqHome;
    }
    await rm(cwd, { recursive: true, force: true });
    await rm(cliqHome, { recursive: true, force: true });
  }
}

function user(id: string, content: string) {
  return { id, ts: '2026-04-30T00:00:00.000Z', kind: 'user' as const, role: 'user' as const, content };
}

function assistant(id: string, content: string, action: any = { message: content }) {
  return { id, ts: '2026-04-30T00:00:01.000Z', kind: 'assistant' as const, role: 'assistant' as const, content, action };
}

function tool(id: string, content: string) {
  return {
    id,
    ts: '2026-04-30T00:00:02.000Z',
    kind: 'tool' as const,
    role: 'user' as const,
    tool: 'bash',
    status: 'ok' as const,
    content,
    meta: { exit: 0 }
  };
}

test('estimateRecordTokens is deterministic', () => {
  assert.equal(estimateRecordTokens(user('u1', 'abcd')).tokens, 5);
  assert.equal(estimateMessagesTokens([{ role: 'user', content: 'abcd' }]).tokens, 5);
});

test('selectAutoCompactRange prefers a user-turn boundary and leaves a raw tail', () => {
  const session = createSession('/tmp/workspace');
  session.records.push(
    user('u1', 'old '.repeat(100)),
    assistant('a1', '{"message":"old answer"}'),
    user('u2', 'tail '.repeat(100)),
    assistant('a2', '{"message":"tail answer"}')
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 60,
    minNewTokens: 1
  });

  assert.equal(range?.endIndexExclusive, 2);
  assert.equal(range?.firstKeptRecordId, 'u2');
});

test('selectAutoCompactRange never keeps a tool record as the first tail record', () => {
  const session = createSession('/tmp/workspace');
  session.records.push(
    user('u1', 'run command'),
    assistant('a1', '{"bash":"printf ok"}', { bash: 'printf ok' }),
    tool('t1', 'TOOL_RESULT bash OK\nok'),
    assistant('a2', '{"message":"done"}')
  );

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: 1,
    minNewTokens: 1
  });

  assert.notEqual(session.records[range?.endIndexExclusive ?? -1]?.kind, 'tool');
});

test('serializeRecordForSummary includes tool metadata', () => {
  const serialized = serializeRecordForSummary(tool('t1', 'TOOL_RESULT bash OK\nok'), 10_000);

  assert.match(serialized, /tool=bash/);
  assert.match(serialized, /status=ok/);
  assert.match(serialized, /TOOL_RESULT bash OK/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
node --test --import tsx src/session/auto-compaction.test.ts
```

Expected: FAIL because `src/session/auto-compaction.ts` does not exist.

- [ ] **Step 3: Implement estimator, serialization, and range selection**

Create `src/session/auto-compaction.ts` with these exports first:

```ts
import type { ChatMessage, ModelClient, ResolvedModelConfig } from '../model/types.js';
import { createCompaction } from './compaction.js';
import type { ResolvedAutoCompactConfig } from './auto-compact-config.js';
import type { CompactionArtifact, Session, SessionRecord } from './types.js';

const TOKEN_MESSAGE_OVERHEAD = 4;

export type TokenEstimate = {
  tokens: number;
  messages: number;
  source: 'approx';
};

export type AutoCompactRange = {
  endIndexExclusive: number;
  firstKeptRecordId: string;
  previousCompactionId?: string;
  compactableNewTokens: number;
  splitTurnPrefix: boolean;
};

export function estimateTextTokens(text: string) {
  return Math.ceil(text.length / 4);
}

export function estimateRecordTokens(record: SessionRecord): TokenEstimate {
  return {
    tokens: estimateTextTokens(record.content) + TOKEN_MESSAGE_OVERHEAD,
    messages: 1,
    source: 'approx'
  };
}

export function estimateMessagesTokens(messages: ChatMessage[]): TokenEstimate {
  return {
    tokens: messages.reduce((total, message) => total + estimateTextTokens(message.content) + TOKEN_MESSAGE_OVERHEAD, 0),
    messages: messages.length,
    source: 'approx'
  };
}

function estimateRecordsTokens(records: SessionRecord[]) {
  return records.reduce((total, record) => total + estimateRecordTokens(record).tokens, 0);
}

function isAssistantToolAction(record: SessionRecord) {
  return record.kind === 'assistant' && record.action !== null && !('message' in record.action);
}

function hasValidImmediateToolResult(records: SessionRecord[], index: number) {
  return isAssistantToolAction(records[index]!) && records[index + 1]?.kind === 'tool';
}

function isSafeSplitPoint(records: SessionRecord[], index: number) {
  const firstKept = records[index];
  if (!firstKept || firstKept.kind === 'tool') return false;
  const previous = records[index - 1];
  if (!previous) return false;
  if (isAssistantToolAction(previous)) return false;
  if (previous.kind === 'tool') return true;
  if (firstKept.kind === 'user') return true;
  if (firstKept.kind === 'assistant') return true;
  return false;
}

function activeCompaction(session: Session) {
  return session.compactions.find((artifact) => artifact.status === 'active') ?? null;
}

function userBoundaryCandidates(records: SessionRecord[]) {
  const candidates: number[] = [];
  for (let index = 1; index < records.length; index += 1) {
    if (records[index]?.kind === 'user') {
      candidates.push(index);
    }
  }
  return candidates;
}

function safeBoundaryCandidates(records: SessionRecord[]) {
  const candidates = userBoundaryCandidates(records);
  for (let index = 1; index < records.length; index += 1) {
    if (isSafeSplitPoint(records, index) && !candidates.includes(index)) {
      candidates.push(index);
    }
  }
  return candidates.sort((a, b) => a - b);
}

export function selectAutoCompactRange({
  session,
  keepRecentTokens,
  minNewTokens
}: {
  session: Session;
  keepRecentTokens: number;
  minNewTokens: number;
}): AutoCompactRange | null {
  if (session.records.length < 2) return null;

  const active = activeCompaction(session);
  const previousEnd = active?.coveredRange.endIndexExclusive ?? 0;
  const candidates = safeBoundaryCandidates(session.records).filter((index) => index > previousEnd && index < session.records.length);

  let selected: number | null = null;
  for (const index of candidates) {
    const tailTokens = estimateRecordsTokens(session.records.slice(index));
    if (tailTokens >= keepRecentTokens) {
      selected = index;
    }
  }

  selected ??= candidates[0] ?? null;
  if (selected === null) return null;

  const compactableNewTokens = estimateRecordsTokens(session.records.slice(previousEnd, selected));
  if (compactableNewTokens < minNewTokens) return null;

  return {
    endIndexExclusive: selected,
    firstKeptRecordId: session.records[selected]!.id,
    previousCompactionId: active?.id,
    compactableNewTokens,
    splitTurnPrefix: !userBoundaryCandidates(session.records).includes(selected)
  };
}

export function serializeRecordForSummary(record: SessionRecord, maxToolPayloadChars: number) {
  if (record.kind === 'tool') {
    const original = record.content;
    const clipped =
      original.length <= maxToolPayloadChars
        ? original
        : `${original.slice(0, maxToolPayloadChars)}\n[cliq truncated summarizer tool payload: originalChars=${original.length}]`;
    return [
      `<record id="${record.id}" kind="tool" tool="${record.tool}" status="${record.status}">`,
      `tool=${record.tool}`,
      `status=${record.status}`,
      clipped,
      '</record>'
    ].join('\n');
  }

  return [`<record id="${record.id}" kind="${record.kind}" role="${record.role}">`, record.content, '</record>'].join('\n');
}
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
node --test --import tsx src/session/auto-compaction.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/session/auto-compaction.ts src/session/auto-compaction.test.ts
git commit -m "feat: select auto compact ranges"
```

## Task 6: Summary Budget, Chunking, And Artifact Creation

**Files:**
- Modify: `src/session/auto-compaction.ts`
- Modify: `src/session/auto-compaction.test.ts`

- [ ] **Step 1: Add failing summarizer tests**

Append to `src/session/auto-compaction.test.ts`:

```ts
function fakeModel(outputs: string[]) {
  const calls: Array<{ role: string; content: string }[]> = [];
  return {
    calls,
    client: {
      async complete(messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>) {
        calls.push(messages);
        return {
          content: outputs.shift() ?? '## Objective\nGenerated summary',
          provider: 'openrouter' as const,
          model: 'test-model'
        };
      }
    }
  };
}

test('maybeAutoCompact writes an active artifact when threshold is exceeded', async () => {
  await withTempSession(async ({ cwd, session }) => {
    session.records.push(
      user('u1', 'old '.repeat(100)),
      assistant('a1', '{"message":"old"}'),
      user('u2', 'tail')
    );
    const model = fakeModel(['## Objective\nSummarized old context']);

    const result = await maybeAutoCompact({
      cwd,
      session,
      model: model.client,
      modelConfig: { provider: 'openrouter', model: 'test-model', baseUrl: 'https://example.test', streaming: 'off' },
      config: {
        enabled: 'on',
        contextWindowTokens: 400,
        thresholdRatio: 0.8,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1,
        maxThresholdCompactionsPerTurn: 1,
        maxOverflowRetriesPerModelCall: 1,
        usableLimitTokens: 300,
        contextWindowSource: 'config'
      },
      instructions: [],
      phase: 'pre-model',
      trigger: 'threshold',
      state: { thresholdCompactionsThisTurn: 0, thresholdSuppressed: false },
      estimateOverrideTokens: 350
    });

    assert.equal(result.status, 'compacted');
    assert.equal(session.compactions[0]?.status, 'active');
    assert.match(session.compactions[0]?.summaryMarkdown ?? '', /Summarized old context/);
  });
});

test('maybeAutoCompact chunks summarizer input when selected records exceed summary budget', async () => {
  await withTempSession(async ({ cwd, session }) => {
    session.records.push(
      user('u1', 'old '.repeat(400)),
      user('u2', 'older '.repeat(400)),
      user('u3', 'tail')
    );
    const model = fakeModel([
      '## Objective\nChunk 1 summary',
      '## Objective\nChunk 2 summary'
    ]);

    const result = await maybeAutoCompact({
      cwd,
      session,
      model: model.client,
      modelConfig: { provider: 'openrouter', model: 'test-model', baseUrl: 'https://example.test', streaming: 'off' },
      config: {
        enabled: 'on',
        contextWindowTokens: 900,
        thresholdRatio: 0.8,
        reserveTokens: 300,
        keepRecentTokens: 20,
        minNewTokens: 1,
        maxThresholdCompactionsPerTurn: 1,
        maxOverflowRetriesPerModelCall: 1,
        usableLimitTokens: 600,
        contextWindowSource: 'config'
      },
      instructions: [],
      phase: 'pre-model',
      trigger: 'threshold',
      state: { thresholdCompactionsThisTurn: 0, thresholdSuppressed: false },
      estimateOverrideTokens: 800
    });

    assert.equal(result.status, 'compacted');
    assert.equal(model.calls.length > 1, true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
node --test --import tsx src/session/auto-compaction.test.ts
```

Expected: FAIL because `maybeAutoCompact` and summarizer logic do not exist.

- [ ] **Step 3: Implement summarizer prompt and chunking**

Extend `src/session/auto-compaction.ts`:

```ts
import { resolveAutoCompactConfig } from './auto-compact-config.js';

export type AutoCompactState = {
  thresholdCompactionsThisTurn: number;
  thresholdSuppressed: boolean;
};

export type AutoCompactResult =
  | { status: 'disabled' | 'skipped'; reason: string }
  | { status: 'compacted'; artifact: CompactionArtifact; estimatedTokensBefore: number; estimatedTokensAfter: number }
  | { status: 'error'; error: Error };

const SUMMARY_PROMPT = `You are compacting a local agent session.

Write a durable markdown summary with these headings:
## Objective
## Current State
## Decisions And Constraints
## Relevant Artifacts
## Validation
## Open Questions And Risks
## Next Steps

Preserve exact paths, commands, identifiers, constraints, and errors. Mark absent sections as (none).`;

function buildSummaryMessages(input: string): ChatMessage[] {
  return [
    { role: 'system', content: SUMMARY_PROMPT },
    { role: 'user', content: input }
  ];
}

function summaryInputBudget(config: ResolvedAutoCompactConfig) {
  if (config.contextWindowTokens === null) return null;
  const promptOverheadTokens = estimateMessagesTokens(buildSummaryMessages('')).tokens;
  return config.contextWindowTokens - config.reserveTokens - promptOverheadTokens;
}

function chunkSerializedRecords(serialized: string[], budgetTokens: number) {
  const chunks: string[] = [];
  let current = '';
  for (const item of serialized) {
    const candidate = current ? `${current}\n\n${item}` : item;
    if (estimateTextTokens(candidate) <= budgetTokens) {
      current = candidate;
      continue;
    }
    if (!current) {
      throw new Error('single compact summary input record exceeds summarizer budget');
    }
    chunks.push(current);
    current = item;
  }
  if (current) chunks.push(current);
  return chunks;
}

async function summarizeChunks({
  model,
  previousSummary,
  serializedRecords,
  summaryInputBudgetTokens
}: {
  model: ModelClient;
  previousSummary?: string;
  serializedRecords: string[];
  summaryInputBudgetTokens: number;
}) {
  let rollingSummary = previousSummary ?? '';
  const chunks = chunkSerializedRecords(serializedRecords, summaryInputBudgetTokens);
  for (const chunk of chunks) {
    const input = [
      rollingSummary ? `Previous summary:\n${rollingSummary}` : '',
      `Records to summarize:\n${chunk}`
    ]
      .filter(Boolean)
      .join('\n\n');
    if (estimateMessagesTokens(buildSummaryMessages(input)).tokens > summaryInputBudgetTokens) {
      throw new Error('compact summarizer chunk exceeds input budget');
    }
    const completion = await model.complete(buildSummaryMessages(input));
    rollingSummary = completion.content.trim();
    if (!rollingSummary) {
      throw new Error('compact summarizer returned an empty summary');
    }
  }
  return rollingSummary;
}
```

- [ ] **Step 4: Implement maybeAutoCompact**

Add to `src/session/auto-compaction.ts`:

```ts
export async function maybeAutoCompact({
  cwd,
  session,
  model,
  modelConfig,
  config,
  instructions,
  phase,
  trigger,
  state,
  estimateOverrideTokens
}: {
  cwd: string;
  session: Session;
  model: ModelClient;
  modelConfig: ResolvedModelConfig;
  config: ResolvedAutoCompactConfig;
  instructions: ChatMessage[];
  phase: 'pre-model' | 'mid-loop';
  trigger: 'threshold' | 'overflow';
  state: AutoCompactState;
  estimateOverrideTokens?: number;
}): Promise<AutoCompactResult> {
  if (config.enabled === 'off') return { status: 'disabled', reason: 'disabled' };
  if (config.contextWindowTokens === null || config.usableLimitTokens === null) {
    return { status: 'skipped', reason: 'unknown-context-window' };
  }
  if (trigger === 'threshold' && state.thresholdSuppressed) {
    return { status: 'skipped', reason: 'threshold-suppressed' };
  }
  if (trigger === 'threshold' && state.thresholdCompactionsThisTurn >= config.maxThresholdCompactionsPerTurn) {
    return { status: 'skipped', reason: 'max-threshold-per-turn' };
  }

  const estimatedTokensBefore =
    estimateOverrideTokens ??
    estimateMessagesTokens([
      ...instructions,
      ...session.records.map((record) => ({ role: record.kind === 'assistant' ? 'assistant' : 'user', content: record.content }) as ChatMessage)
    ]).tokens;

  if (trigger === 'threshold' && estimatedTokensBefore < config.usableLimitTokens) {
    return { status: 'skipped', reason: 'too-small' };
  }

  const range = selectAutoCompactRange({
    session,
    keepRecentTokens: config.keepRecentTokens,
    minNewTokens: config.minNewTokens
  });
  if (!range) return { status: 'skipped', reason: 'no-safe-range' };

  const budget = summaryInputBudget(config);
  if (budget === null || budget <= 0) {
    return { status: 'error', error: new Error('compact summarizer input budget is not positive') };
  }

  try {
    const previous = range.previousCompactionId
      ? session.compactions.find((artifact) => artifact.id === range.previousCompactionId)
      : undefined;
    const records = session.records.slice(previous?.coveredRange.endIndexExclusive ?? 0, range.endIndexExclusive);
    const serializedRecords = records.map((record) => serializeRecordForSummary(record, Math.floor(budget * 4)));
    const summaryMarkdown = await summarizeChunks({
      model,
      previousSummary: previous?.summaryMarkdown,
      serializedRecords,
      summaryInputBudgetTokens: budget
    });
    const estimatedTokensAfter = estimateRecordsTokens(session.records.slice(range.endIndexExclusive)) + estimateTextTokens(summaryMarkdown);
    const artifact = await createCompaction(cwd, session, {
      endIndexExclusive: range.endIndexExclusive,
      summaryMarkdown,
      auto: {
        trigger,
        phase,
        estimatedTokensBefore,
        estimatedTokensAfter,
        usableLimitTokens: config.usableLimitTokens,
        contextWindowTokens: config.contextWindowTokens,
        contextWindowSource: config.contextWindowSource ?? undefined,
        keepRecentTokens: config.keepRecentTokens,
        summaryInputBudgetTokens: budget,
        previousCompactionId: range.previousCompactionId
      }
    });

    if (trigger === 'threshold') state.thresholdCompactionsThisTurn += 1;
    return { status: 'compacted', artifact, estimatedTokensBefore, estimatedTokensAfter };
  } catch (error) {
    return { status: 'error', error: error instanceof Error ? error : new Error(String(error)) };
  }
}
```

- [ ] **Step 5: Run tests to verify pass**

Run:

```bash
node --test --import tsx src/session/auto-compaction.test.ts src/session/compaction.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/session/auto-compaction.ts src/session/auto-compaction.test.ts
git commit -m "feat: summarize auto compact ranges"
```

## Task 7: Overflow Classification And Runner Integration

**Files:**
- Create: `src/model/errors.ts`
- Create: `src/model/errors.test.ts`
- Modify: `src/runtime/events.ts`
- Modify: `src/runtime/runner.ts`
- Modify: `src/runtime/runner.test.ts`
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`

- [ ] **Step 1: Write failing overflow classifier tests**

Create `src/model/errors.test.ts`:

```ts
import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyContextOverflow } from './errors.js';

test('classifyContextOverflow recognizes common provider overflow messages', () => {
  assert.equal(classifyContextOverflow(new Error('context length exceeded'))?.isOverflow, true);
  assert.equal(classifyContextOverflow(new Error('maximum context window is 128000 tokens'))?.contextWindowTokens, 128000);
  assert.equal(classifyContextOverflow(new Error('input is too long: too many tokens'))?.isOverflow, true);
});

test('classifyContextOverflow ignores unrelated errors', () => {
  assert.equal(classifyContextOverflow(new Error('network unavailable')), null);
});
```

- [ ] **Step 2: Implement overflow classifier**

Create `src/model/errors.ts`:

```ts
export type ContextOverflowInfo = {
  isOverflow: true;
  contextWindowTokens?: number;
  message: string;
};

const OVERFLOW_PATTERNS = [
  /context length exceeded/i,
  /context window/i,
  /maximum context/i,
  /too many tokens/i,
  /input is too long/i,
  /tokens.*exceed/i
];

export function classifyContextOverflow(error: unknown): ContextOverflowInfo | null {
  const message = error instanceof Error ? error.message : String(error);
  if (!OVERFLOW_PATTERNS.some((pattern) => pattern.test(message))) return null;
  const tokenMatch = message.match(/(?:context window|maximum context|limit)[^\d]{0,32}(\d{4,})/i);
  return {
    isOverflow: true,
    message,
    ...(tokenMatch ? { contextWindowTokens: Number(tokenMatch[1]) } : {})
  };
}
```

- [ ] **Step 3: Add compact runtime events**

Modify `src/runtime/events.ts`:

```ts
  | { type: 'compact-start'; trigger: 'threshold' | 'overflow'; phase: 'pre-model' | 'mid-loop' }
  | { type: 'compact-end'; artifactId: string; estimatedTokensBefore: number; estimatedTokensAfter: number }
  | {
      type: 'compact-skip';
      reason:
        | 'disabled'
        | 'unknown-context-window'
        | 'too-small'
        | 'min-new-tokens'
        | 'max-threshold-per-turn'
        | 'max-overflow-retries'
        | 'threshold-suppressed'
        | 'no-safe-range';
    }
  | { type: 'compact-error'; trigger: 'threshold' | 'overflow'; message: string }
```

- [ ] **Step 4: Integrate Auto Compact in runner**

Modify `createRunner` options in `src/runtime/runner.ts`:

```ts
import { classifyContextOverflow } from '../model/errors.js';
import type { ResolvedModelConfig } from '../model/types.js';
import { findKnownModelDescriptor } from '../model/registry.js';
import { resolveAutoCompactConfig, type AutoCompactConfig } from '../session/auto-compact-config.js';
import { maybeAutoCompact, type AutoCompactState } from '../session/auto-compaction.js';

autoCompact?: {
  config: AutoCompactConfig;
  modelConfig: ResolvedModelConfig;
};
```

Inside `runTurn`, initialize per-turn state:

```ts
const autoCompactState: AutoCompactState = {
  thresholdCompactionsThisTurn: 0,
  thresholdSuppressed: false
};
```

Before each model call:

```ts
let currentInstructions = await instructions(session);
if (autoCompact) {
  const descriptor = findKnownModelDescriptor(autoCompact.modelConfig.provider, autoCompact.modelConfig.model);
  const resolvedAutoCompact = resolveAutoCompactConfig({
    config: autoCompact.config,
    modelContextWindowTokens: descriptor?.capabilities.contextWindow
  });
  const phase = i === 0 ? 'pre-model' : 'mid-loop';
  const compactResult = await maybeAutoCompact({
    cwd,
    session,
    model,
    modelConfig: autoCompact.modelConfig,
    config: resolvedAutoCompact,
    instructions: currentInstructions,
    phase,
    trigger: 'threshold',
    state: autoCompactState
  });
  if (compactResult.status === 'compacted') {
    await onEvent({ type: 'compact-end', artifactId: compactResult.artifact.id, estimatedTokensBefore: compactResult.estimatedTokensBefore, estimatedTokensAfter: compactResult.estimatedTokensAfter });
    currentInstructions = await instructions(session);
  } else if (compactResult.status === 'error') {
    autoCompactState.thresholdSuppressed = true;
    await onEvent({ type: 'compact-error', trigger: 'threshold', message: compactResult.error.message });
  }
}
completion = await model.complete(buildContextMessages(session, currentInstructions), { onEvent: ... });
```

On model error, before rethrow:

```ts
const overflow = classifyContextOverflow(error);
if (overflow && autoCompact) {
  const descriptor = findKnownModelDescriptor(autoCompact.modelConfig.provider, autoCompact.modelConfig.model);
  const resolvedAutoCompact = resolveAutoCompactConfig({
    config: autoCompact.config,
    modelContextWindowTokens: descriptor?.capabilities.contextWindow,
    overflowContextWindowTokens: overflow.contextWindowTokens
  });
  const phase = i === 0 ? 'pre-model' : 'mid-loop';
  const overflowResult = await maybeAutoCompact({
    cwd,
    session,
    model,
    modelConfig: autoCompact.modelConfig,
    config: resolvedAutoCompact,
    instructions: await instructions(session),
    phase,
    trigger: 'overflow',
    state: autoCompactState
  });
  if (overflowResult.status === 'compacted') {
    completion = await model.complete(buildContextMessages(session, await instructions(session)), { onEvent: ... });
  } else {
    throw error;
  }
} else {
  throw error;
}
```

Keep retry count local to the current model call with a boolean such as `let overflowRetried = false;` inside the loop body.

- [ ] **Step 5: Pass autoCompact config from CLI**

Modify both `createRunner` calls in `src/cli.ts`:

```ts
autoCompact: {
  config: assembly.workspaceConfig.autoCompact,
  modelConfig
}
```

Update `createCliEventSink`:

```ts
} else if (event.type === 'compact-error') {
  process.stderr.write(`[compact ${event.trigger} error] ${event.message}\n`);
} else if (event.type === 'compact-end') {
  process.stderr.write(`[compact] created ${event.artifactId}\n`);
}
```

- [ ] **Step 6: Write runner integration tests**

Add tests to `src/runtime/runner.test.ts`:

```ts
test('runner auto compacts before model call when threshold is exceeded', async () => {
  const session = await createTempSession();
  session.records.push(
    { id: 'u_old', ts: '2026-04-30T00:00:00.000Z', kind: 'user', role: 'user', content: 'old '.repeat(1000) },
    { id: 'u_tail', ts: '2026-04-30T00:00:01.000Z', kind: 'user', role: 'user', content: 'tail' }
  );
  let firstCallMessages: Array<{ role: string; content: string }> = [];

  const runner = createRunner({
    model: {
      async complete(messages) {
        firstCallMessages = messages;
        if (messages.some((message) => message.content.includes('Records to summarize'))) {
          return completion('## Objective\nSummarized');
        }
        return completion('{"message":"done"}');
      }
    },
    autoCompact: {
      config: { enabled: 'on', contextWindowTokens: 1000, keepRecentTokens: 20, reserveTokens: 200 },
      modelConfig: { provider: 'openrouter', model: 'anthropic/claude-sonnet-4.6', baseUrl: 'https://example.test', streaming: 'off' }
    }
  });

  await runner.runTurn(session, 'new request');

  assert.equal(session.compactions.length, 1);
  assert.equal(firstCallMessages.some((message) => message.content.includes('COMPACTED SESSION SUMMARY')), true);
});
```

Add a second test for overflow retry:

```ts
test('runner retries once after recognized context overflow and successful compaction', async () => {
  const session = await createTempSession();
  session.records.push(
    { id: 'u_old', ts: '2026-04-30T00:00:00.000Z', kind: 'user', role: 'user', content: 'old '.repeat(1000) },
    { id: 'u_tail', ts: '2026-04-30T00:00:01.000Z', kind: 'user', role: 'user', content: 'tail' }
  );
  let normalCalls = 0;

  const runner = createRunner({
    model: {
      async complete(messages) {
        if (messages.some((message) => message.content.includes('Records to summarize'))) {
          return completion('## Objective\nSummarized');
        }
        normalCalls += 1;
        if (normalCalls === 1) throw new Error('context length exceeded, maximum context window is 1000 tokens');
        return completion('{"message":"done"}');
      }
    },
    autoCompact: {
      config: { enabled: 'on', contextWindowTokens: 1000, keepRecentTokens: 20, reserveTokens: 200 },
      modelConfig: { provider: 'openrouter', model: 'anthropic/claude-sonnet-4.6', baseUrl: 'https://example.test', streaming: 'off' }
    }
  });

  const final = await runner.runTurn(session, 'new request');

  assert.equal(final, 'done');
  assert.equal(normalCalls, 2);
  assert.equal(session.compactions.length, 1);
});
```

- [ ] **Step 7: Run focused tests**

Run:

```bash
node --test --import tsx src/model/errors.test.ts src/runtime/runner.test.ts src/cli.test.ts
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/model/errors.ts src/model/errors.test.ts src/runtime/events.ts src/runtime/runner.ts src/runtime/runner.test.ts src/cli.ts src/cli.test.ts
git commit -m "feat: auto compact during runner turns"
```

## Task 8: Full Regression And Final Hardening

**Files:**
- Modify only files touched by failing tests.

- [ ] **Step 1: Run full suite and build**

Run:

```bash
npm test
npm run build
```

Expected: both commands PASS.

- [ ] **Step 2: Inspect edge-case coverage**

Run:

```bash
rg -n "autoCompact|maybeAutoCompact|MAX_STORED_TOOL_RESULT_CHARS|contextWindowSource|compact-error|compact-end" src
```

Expected: references exist only in the modules named in this plan, plus tests.

- [ ] **Step 3: Verify no spec drift**

Run:

```bash
rg -n "maxPerTurn|tool-output pruning|unknown context window|summaryInputBudgetTokens|safe record boundary" docs/superpowers/specs/2026-04-30-auto-compact-design.md src
```

Expected:

- `maxPerTurn` has no matches.
- `summaryInputBudgetTokens` appears in spec, type, service, and tests.
- `safe record boundary` appears in the spec or comments only.

- [ ] **Step 4: Commit final hardening**

If Step 1 changed no files, skip this commit. If fixes were needed:

```bash
git add <changed-files>
git commit -m "fix: harden auto compact implementation"
```

- [ ] **Step 5: Prepare PR summary**

Use this summary:

```md
## Summary
- add autoCompact config parsing and static model context-window metadata
- cap stored tool results before session admission
- implement auto compaction policy, range selection, summary budgeting, and artifact creation
- wire threshold auto compact and overflow compact-and-retry into runner

## Tests
- npm test
- npm run build
```

## Self-Review Checklist

- [ ] Spec coverage: every section in `docs/superpowers/specs/2026-04-30-auto-compact-design.md` maps to at least one task above.
- [ ] Placeholder scan: this plan contains concrete file paths, concrete commands, and named modules introduced before use.
- [ ] Type consistency: `AutoCompactConfig`, `ResolvedAutoCompactConfig`, `AutoCompactionMetadata`, `summaryInputBudgetTokens`, `maxThresholdCompactionsPerTurn`, and `maxOverflowRetriesPerModelCall` use the same names throughout.
- [ ] Scope control: `compactModel`, public hooks, provider-native tokenizers, replay pruning, and UI controls remain outside this implementation.
