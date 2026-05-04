# Phase 4 Headless Runtime Interfaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v0.7.0 Phase 4 headless runtime foundation: serializable run contract, versioned JSONL event stream, stable artifact views, and cooperative cancellation.

**Architecture:** Add a focused `src/headless/` layer above the existing runtime runner. The runner continues to own the agent loop and emits internal `RuntimeEvent`s; the headless layer validates public requests, wraps events in stable envelopes, tracks run artifacts, and powers both human one-shot CLI execution and `cliq run --jsonl`.

**Tech Stack:** TypeScript, Node.js built-in `node:test`, existing Cliq runtime/session/model modules, JSONL over stdout.

---

## Scope

Implement in `v0.7.0`:

- `HeadlessRunRequest` and local `HeadlessRunOptions`
- `RuntimeEventEnvelope`
- pre-session structured errors
- `checkpoint-created` runtime event
- `cliq run --jsonl "task"`
- stable session/artifact view functions
- cooperative cancellation through `AbortSignal`

Do not implement in `v0.7.0`:

- stdio JSON-RPC adapter
- daemon or HTTP server
- rich TUI/GUI
- cost/token accounting
- debug/replay
- public extension hooks

## File Structure

- Create `src/headless/contract.ts`
  - Public request/output/event/error/view types.
  - Runtime-independent helper constants such as exit codes.

- Create `src/headless/events.ts`
  - Event id generation.
  - Envelope creation.
  - Runtime event to headless event mapping.
  - Created artifact tracking.

- Create `src/headless/artifacts.ts`
  - Convert internal session/checkpoint/compaction/handoff state into external view types.
  - Read handoff artifacts and workspace checkpoint artifacts without exposing storage paths as the contract.

- Create `src/headless/run.ts`
  - Validate `HeadlessRunRequest`.
  - Resolve session, runtime assembly, model config, policy, and model client.
  - Execute one run through `createRunner`.
  - Emit `run-start`, mapped runtime events, structured `error`, and `run-end`.

- Create `src/headless/jsonl.ts`
  - Serialize `RuntimeEventEnvelope` objects as newline-delimited JSON.

- Create tests:
  - `src/headless/events.test.ts`
  - `src/headless/artifacts.test.ts`
  - `src/headless/run.test.ts`

- Modify `src/runtime/events.ts`
  - Add `checkpoint-created`.
  - Add `cancel` error stage.

- Modify `src/runtime/runner.ts`
  - Accept an optional `AbortSignal`.
  - Emit `checkpoint-created`.
  - Check cancellation at defined mutation and loop boundaries.

- Modify `src/model/types.ts`
  - Pass `signal?: AbortSignal` through model completion options.

- Modify provider files that call `fetch`
  - `src/model/providers/anthropic.ts`
  - `src/model/providers/ollama.ts`
  - `src/model/providers/openai-compatible.ts`
  - `src/model/providers/openai.ts`
  - `src/model/providers/openrouter.ts`
  - Forward `signal` into request options where supported by existing provider implementation.

- Modify `src/tools/types.ts`
  - Add `signal?: AbortSignal` to `ToolContext`.

- Modify `src/cli.ts`
  - Parse command-scoped `run --jsonl`.
  - Route one-shot human runs and JSONL runs through `runHeadless`.
  - Preserve interactive chat path for this release.

- Modify `src/cli.test.ts`
  - Add parse and JSONL behavior coverage.
  - Preserve existing human CLI assertions.

## Task 1: Contract And Event Envelope

**Files:**
- Create: `src/headless/contract.ts`
- Create: `src/headless/events.ts`
- Test: `src/headless/events.test.ts`
- Modify: `src/runtime/events.ts`

- [ ] **Step 1: Write failing event envelope tests**

Create `src/headless/events.test.ts`:

```ts
import test from 'node:test';
import assert from 'node:assert/strict';

import type { RuntimeEvent } from '../runtime/events.js';
import { createHeadlessEventFactory, runtimeEventToHeadless } from './events.js';

test('createHeadlessEventFactory emits versioned envelopes with optional session fields', () => {
  const factory = createHeadlessEventFactory({
    runId: 'run_test',
    now: () => '2026-05-03T00:00:00.000Z'
  });

  const preSession = factory('error', {
    code: 'invalid-input',
    stage: 'input',
    message: 'prompt is required',
    recoverable: false
  });

  assert.equal(preSession.schemaVersion, 1);
  assert.equal(preSession.runId, 'run_test');
  assert.equal(preSession.sessionId, undefined);
  assert.equal(preSession.turn, undefined);
  assert.equal(preSession.type, 'error');
  assert.equal(preSession.timestamp, '2026-05-03T00:00:00.000Z');

  const scoped = factory(
    'run-start',
    {
      cwd: '/workspace',
      policy: 'auto',
      model: { provider: 'ollama', model: 'qwen3:4b', baseUrl: 'http://localhost:11434' }
    },
    { sessionId: 'sess_test', turn: 3 }
  );

  assert.equal(scoped.sessionId, 'sess_test');
  assert.equal(scoped.turn, 3);
  assert.notEqual(scoped.eventId, preSession.eventId);
});

test('runtimeEventToHeadless maps existing runtime events without raw deltas', () => {
  const runtimeEvent: RuntimeEvent = { type: 'model-progress', chunks: 2, chars: 50 };
  const mapped = runtimeEventToHeadless(runtimeEvent);

  assert.deepEqual(mapped, {
    type: 'model-progress',
    payload: { chunks: 2, chars: 50 }
  });
});

test('runtimeEventToHeadless maps checkpoint-created artifacts', () => {
  const runtimeEvent: RuntimeEvent = {
    type: 'checkpoint-created',
    checkpointId: 'chk_test',
    kind: 'auto',
    workspaceCheckpointId: 'wchk_test',
    workspaceSnapshotStatus: 'available'
  };

  const mapped = runtimeEventToHeadless(runtimeEvent);

  assert.deepEqual(mapped, {
    type: 'checkpoint-created',
    payload: {
      checkpointId: 'chk_test',
      kind: 'auto',
      workspaceCheckpointId: 'wchk_test',
      workspaceSnapshotStatus: 'available'
    },
    artifacts: {
      checkpoints: ['chk_test'],
      workspaceCheckpoints: ['wchk_test'],
      compactions: [],
      handoffs: []
    }
  });
});
```

- [ ] **Step 2: Run event tests and verify they fail**

Run:

```bash
node --test --import tsx src/headless/events.test.ts
```

Expected: FAIL because `src/headless/events.ts` does not exist.

- [ ] **Step 3: Add public contract types**

Create `src/headless/contract.ts`:

```ts
import type { PartialModelConfig } from '../model/config.js';
import type { ProviderName } from '../model/types.js';
import type { PolicyMode } from '../policy/types.js';
import type { AutoCompactConfig } from '../session/auto-compact-config.js';
import type { SessionModelRef } from '../session/types.js';

export const HEADLESS_SCHEMA_VERSION = 1;
export const HEADLESS_EXIT_SUCCESS = 0;
export const HEADLESS_EXIT_FAILURE = 1;
export const HEADLESS_EXIT_CANCELLED = 130;

export type HeadlessRunRequest = {
  prompt: string;
  cwd: string;
  policy?: PolicyMode;
  model?: PartialModelConfig;
  skills?: string[];
  autoCompact?: AutoCompactConfig;
  session?: {
    mode?: 'active' | 'new';
  };
  metadata?: Record<string, string | number | boolean | null>;
};

export type HeadlessRunOptions = {
  signal?: AbortSignal;
  onEvent?: (event: RuntimeEventEnvelope) => void | Promise<void>;
};

export type HeadlessRunStatus = 'completed' | 'failed' | 'cancelled';

export type HeadlessErrorCode =
  | 'invalid-input'
  | 'config-error'
  | 'model-auth-error'
  | 'model-error'
  | 'context-overflow'
  | 'protocol-error'
  | 'policy-denied'
  | 'tool-error'
  | 'compact-error'
  | 'session-store-error'
  | 'artifact-not-found'
  | 'cancelled'
  | 'internal-error';

export type HeadlessErrorStage =
  | 'input'
  | 'assembly'
  | 'checkpoint'
  | 'model'
  | 'protocol'
  | 'policy'
  | 'tool'
  | 'compact'
  | 'session'
  | 'cancel';

export type HeadlessRunError = {
  code: HeadlessErrorCode;
  stage: HeadlessErrorStage;
  message: string;
  recoverable: boolean;
};

export type HeadlessArtifacts = {
  checkpoints: string[];
  workspaceCheckpoints: string[];
  compactions: string[];
  handoffs: string[];
};

export function emptyHeadlessArtifacts(): HeadlessArtifacts {
  return {
    checkpoints: [],
    workspaceCheckpoints: [],
    compactions: [],
    handoffs: []
  };
}

export type HeadlessRunOutput = {
  runId: string;
  sessionId?: string;
  turn?: number;
  status: HeadlessRunStatus;
  exitCode: number;
  finalMessage?: string;
  checkpointId?: string;
  artifacts: HeadlessArtifacts;
  error?: HeadlessRunError;
};

export type HeadlessRuntimeEventType =
  | 'run-start'
  | 'checkpoint-created'
  | 'model-start'
  | 'model-progress'
  | 'model-end'
  | 'tool-start'
  | 'tool-end'
  | 'compact-start'
  | 'compact-end'
  | 'compact-skip'
  | 'compact-error'
  | 'final'
  | 'error'
  | 'run-end';

export type RunStartPayload = {
  cwd: string;
  policy: PolicyMode;
  model: SessionModelRef;
};

export type CheckpointCreatedPayload = {
  checkpointId: string;
  kind: 'auto' | 'manual' | 'restore-safety' | 'handoff';
  workspaceCheckpointId?: string;
  workspaceSnapshotStatus: 'available' | 'unavailable' | 'expired';
  warning?: string;
};

export type ModelStartPayload = {
  provider: ProviderName;
  model: string;
  streaming: boolean;
};

export type ModelProgressPayload = {
  chunks: number;
  chars: number;
};

export type ModelEndPayload = {
  provider: ProviderName;
  model: string;
};

export type ToolStartPayload = {
  tool: string;
  preview?: string;
};

export type ToolEndPayload = {
  tool: string;
  status: 'ok' | 'error';
};

export type CompactStartPayload = {
  trigger: 'threshold' | 'overflow';
  phase: 'pre-model' | 'mid-loop';
};

export type CompactEndPayload = {
  artifactId: string;
  estimatedTokensBefore: number;
  estimatedTokensAfter: number;
};

export type CompactSkipPayload = {
  reason: string;
};

export type CompactErrorPayload = {
  trigger: 'threshold' | 'overflow';
  message: string;
};

export type FinalPayload = {
  message: string;
};

export type RunEndPayload = {
  status: HeadlessRunStatus;
  exitCode: number;
  output: HeadlessRunOutput;
};

export type HeadlessEventPayloadByType = {
  'run-start': RunStartPayload;
  'checkpoint-created': CheckpointCreatedPayload;
  'model-start': ModelStartPayload;
  'model-progress': ModelProgressPayload;
  'model-end': ModelEndPayload;
  'tool-start': ToolStartPayload;
  'tool-end': ToolEndPayload;
  'compact-start': CompactStartPayload;
  'compact-end': CompactEndPayload;
  'compact-skip': CompactSkipPayload;
  'compact-error': CompactErrorPayload;
  final: FinalPayload;
  error: HeadlessRunError;
  'run-end': RunEndPayload;
};

export type RuntimeEventEnvelopeFor<TType extends HeadlessRuntimeEventType> =
  TType extends HeadlessRuntimeEventType
    ? {
        schemaVersion: 1;
        eventId: string;
        runId: string;
        sessionId?: string;
        turn?: number;
        timestamp: string;
        type: TType;
        payload: HeadlessEventPayloadByType[TType];
      }
    : never;

export type RuntimeEventEnvelope = {
  [TType in HeadlessRuntimeEventType]: RuntimeEventEnvelopeFor<TType>;
}[HeadlessRuntimeEventType];
```

- [ ] **Step 4: Extend runtime event types**

Modify `src/runtime/events.ts` so the union includes checkpoint and cancel-stage errors:

```ts
import type { ProviderName } from '../model/types.js';
import type { AutoCompactSkipReason } from '../session/auto-compaction.js';
import type { SessionCheckpoint } from '../session/types.js';

export type RuntimeEvent =
  | { type: 'model-start'; provider: ProviderName; model: string; streaming: boolean }
  | { type: 'model-progress'; chunks: number; chars: number }
  | { type: 'model-end'; provider: ProviderName; model: string }
  | { type: 'checkpoint-created'; checkpointId: string; kind: SessionCheckpoint['kind']; workspaceCheckpointId?: string; workspaceSnapshotStatus: 'available' | 'unavailable' | 'expired'; warning?: string }
  | { type: 'compact-start'; trigger: 'threshold' | 'overflow'; phase: 'pre-model' | 'mid-loop' }
  | { type: 'compact-end'; artifactId: string; estimatedTokensBefore: number; estimatedTokensAfter: number }
  | { type: 'compact-skip'; reason: AutoCompactSkipReason }
  | { type: 'compact-error'; trigger: 'threshold' | 'overflow'; message: string }
  | { type: 'tool-start'; tool: string; preview?: string }
  | { type: 'tool-end'; tool: string; status: 'ok' | 'error' }
  | { type: 'final'; message: string }
  | { type: 'error'; stage: 'model' | 'protocol' | 'policy' | 'tool' | 'cancel'; message: string };

export type RuntimeEventSink = (event: RuntimeEvent) => void | Promise<void>;
```

Keep this as a type-only change in this task. Later tasks will update runner behavior.

- [ ] **Step 5: Implement event envelope helpers**

Create `src/headless/events.ts`:

```ts
import { makeId, nowIso } from '../session/store.js';
import type { RuntimeEvent } from '../runtime/events.js';
import {
  emptyHeadlessArtifacts,
  HEADLESS_SCHEMA_VERSION,
  type CheckpointCreatedPayload,
  type HeadlessEventPayloadByType,
  type HeadlessArtifacts,
  type HeadlessRuntimeEventType,
  type RuntimeEventEnvelopeFor
} from './contract.js';

type EnvelopeScope = {
  sessionId?: string;
  turn?: number;
};

type EventFactoryOptions = {
  runId: string;
  now?: () => string;
};

export type RuntimeEventMapping = {
  [TType in HeadlessRuntimeEventType]: {
    type: TType;
    payload: HeadlessEventPayloadByType[TType];
    artifacts?: HeadlessArtifacts;
  };
}[HeadlessRuntimeEventType];

function artifactsWith(values: Partial<HeadlessArtifacts>): HeadlessArtifacts {
  return {
    ...emptyHeadlessArtifacts(),
    ...values
  };
}

function checkpointArtifacts(payload: CheckpointCreatedPayload): HeadlessArtifacts {
  return artifactsWith({
    checkpoints: [payload.checkpointId],
    workspaceCheckpoints: payload.workspaceCheckpointId ? [payload.workspaceCheckpointId] : []
  });
}

export function mergeArtifacts(target: HeadlessArtifacts, source: HeadlessArtifacts) {
  for (const key of Object.keys(target) as Array<keyof HeadlessArtifacts>) {
    for (const id of source[key]) {
      if (!target[key].includes(id)) {
        target[key].push(id);
      }
    }
  }
}

export function createHeadlessEventFactory({ runId, now = nowIso }: EventFactoryOptions) {
  return function createEvent<TType extends HeadlessRuntimeEventType>(
    type: TType,
    payload: HeadlessEventPayloadByType[TType],
    scope: EnvelopeScope = {}
  ): RuntimeEventEnvelopeFor<TType> {
    return {
      schemaVersion: HEADLESS_SCHEMA_VERSION,
      eventId: makeId('evt'),
      runId,
      sessionId: scope.sessionId,
      turn: scope.turn,
      timestamp: now(),
      type,
      payload
    } as RuntimeEventEnvelopeFor<TType>;
  };
}

const codeByRuntimeErrorStage = {
  model: 'model-error',
  protocol: 'protocol-error',
  policy: 'policy-denied',
  tool: 'tool-error',
  cancel: 'cancelled'
} as const;

function assertNever(value: never): never {
  throw new Error(`unhandled runtime event: ${JSON.stringify(value)}`);
}

export function runtimeEventToHeadless(event: RuntimeEvent): RuntimeEventMapping {
  if (event.type === 'checkpoint-created') {
    const payload: CheckpointCreatedPayload = {
      checkpointId: event.checkpointId,
      kind: event.kind,
      workspaceCheckpointId: event.workspaceCheckpointId,
      workspaceSnapshotStatus: event.workspaceSnapshotStatus,
      warning: event.warning
    };
    return {
      type: 'checkpoint-created',
      payload,
      artifacts: checkpointArtifacts(payload)
    };
  }

  if (event.type === 'compact-end') {
    return {
      type: 'compact-end',
      payload: {
        artifactId: event.artifactId,
        estimatedTokensBefore: event.estimatedTokensBefore,
        estimatedTokensAfter: event.estimatedTokensAfter
      },
      artifacts: artifactsWith({ compactions: [event.artifactId] })
    };
  }

  if (event.type === 'error') {
    return {
      type: 'error',
      payload: {
        code: codeByRuntimeErrorStage[event.stage],
        stage: event.stage,
        message: event.message,
        recoverable: false
      }
    };
  }

  if (event.type === 'model-start') {
    return {
      type: 'model-start',
      payload: { provider: event.provider, model: event.model, streaming: event.streaming }
    };
  }

  if (event.type === 'model-progress') {
    return {
      type: 'model-progress',
      payload: { chunks: event.chunks, chars: event.chars }
    };
  }

  if (event.type === 'model-end') {
    return {
      type: 'model-end',
      payload: { provider: event.provider, model: event.model }
    };
  }

  if (event.type === 'tool-start') {
    return {
      type: 'tool-start',
      payload: { tool: event.tool, preview: event.preview }
    };
  }

  if (event.type === 'tool-end') {
    return {
      type: 'tool-end',
      payload: { tool: event.tool, status: event.status }
    };
  }

  if (event.type === 'compact-start') {
    return {
      type: 'compact-start',
      payload: { trigger: event.trigger, phase: event.phase }
    };
  }

  if (event.type === 'compact-skip') {
    return {
      type: 'compact-skip',
      payload: { reason: event.reason }
    };
  }

  if (event.type === 'compact-error') {
    return {
      type: 'compact-error',
      payload: { trigger: event.trigger, message: event.message }
    };
  }

  if (event.type === 'final') {
    return {
      type: 'final',
      payload: { message: event.message }
    };
  }

  return assertNever(event);
}
```

- [ ] **Step 6: Run event tests and build**

Run:

```bash
node --test --import tsx src/headless/events.test.ts
npm run build
```

Expected: PASS for `events.test.ts`; PASS for `npm run build`.

- [ ] **Step 7: Commit Task 1**

```bash
git add src/headless/contract.ts src/headless/events.ts src/headless/events.test.ts src/runtime/events.ts
git commit -m "feat: add headless event contract"
```

## Task 2: Artifact View Surface

**Files:**
- Modify: `src/headless/contract.ts`
- Create: `src/headless/artifacts.ts`
- Test: `src/headless/artifacts.test.ts`
- Modify: `src/session/checkpoints.ts`
- Modify: `src/handoff/export.ts`

- [ ] **Step 1: Write failing artifact view tests**

Create `src/headless/artifacts.test.ts`:

```ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { exportHandoff } from '../handoff/export.js';
import { createCheckpoint } from '../session/checkpoints.js';
import { createSession } from '../session/store.js';
import { createCompaction } from '../session/compaction.js';
import { getArtifactView, toSessionView } from './artifacts.js';

const previousHome = process.env.CLIQ_HOME;
const cleanupDirs: string[] = [];

test.after(async () => {
  if (previousHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = previousHome;
  }
  await Promise.all(cleanupDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function setupWorkspace() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-artifacts-workspace-'));
  cleanupDirs.push(home, cwd);
  process.env.CLIQ_HOME = home;
  return { home, cwd };
}

test('toSessionView exposes stable records without raw assistant JSON', async () => {
  const { cwd } = await setupWorkspace();
  const session = createSession(cwd);
  session.records.push(
    { id: 'usr_1', ts: '2026-05-03T00:00:00.000Z', kind: 'user', role: 'user', content: 'hello' },
    {
      id: 'ast_1',
      ts: '2026-05-03T00:00:01.000Z',
      kind: 'assistant',
      role: 'assistant',
      content: '{"message":"done"}',
      action: { message: 'done' }
    },
    {
      id: 'tool_1',
      ts: '2026-05-03T00:00:02.000Z',
      kind: 'tool',
      role: 'user',
      tool: 'bash',
      status: 'ok',
      content: `TOOL_RESULT bash OK\n${'x'.repeat(500)}`,
      meta: { exit: 0 }
    }
  );

  const view = toSessionView(session);

  assert.equal(view.records[0]?.kind, 'user');
  assert.equal(view.records[1]?.kind, 'assistant');
  assert.deepEqual(view.records[1], {
    id: 'ast_1',
    ts: '2026-05-03T00:00:01.000Z',
    kind: 'assistant',
    role: 'assistant',
    actionType: 'message',
    message: 'done'
  });
  assert.equal(view.records[2]?.kind, 'tool');
  assert.equal('content' in view.records[2]!, false);
  assert.equal((view.records[2] as { contentPreview: string }).contentPreview.length <= 240, true);
});

test('getArtifactView resolves checkpoint, workspace checkpoint, compaction, and handoff views', async () => {
  const { cwd } = await setupWorkspace();
  const session = createSession(cwd);
  session.records.push(
    { id: 'usr_1', ts: '2026-05-03T00:00:00.000Z', kind: 'user', role: 'user', content: 'summarize' },
    {
      id: 'ast_1',
      ts: '2026-05-03T00:00:01.000Z',
      kind: 'assistant',
      role: 'assistant',
      content: '{"message":"ok"}',
      action: { message: 'ok' }
    }
  );

  const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual', name: 'manual' });
  const compaction = await createCompaction(cwd, session, {
    endIndexExclusive: 1,
    summaryMarkdown: 'summary'
  });
  const handoff = await exportHandoff(cwd, session, { checkpointId: checkpoint.id });

  assert.equal((await getArtifactView(session, checkpoint.id)).kind, 'checkpoint');
  assert.equal((await getArtifactView(session, checkpoint.workspaceCheckpointId!)).kind, 'workspace-checkpoint');
  assert.equal((await getArtifactView(session, compaction.id)).kind, 'compaction');
  assert.equal((await getArtifactView(session, handoff.id)).kind, 'handoff');
  await assert.rejects(() => getArtifactView(session, 'missing'), /artifact not found/i);
});
```

- [ ] **Step 2: Run artifact tests and verify they fail**

Run:

```bash
node --test --import tsx src/headless/artifacts.test.ts
```

Expected: FAIL because `src/headless/artifacts.ts` does not exist.

- [ ] **Step 3: Export workspace checkpoint and handoff readers**

Modify `src/session/checkpoints.ts`:

```ts
export async function getWorkspaceCheckpoint(workspaceCheckpointId: string): Promise<WorkspaceCheckpoint> {
  return await readWorkspaceCheckpoint(workspaceCheckpointId);
}
```

Place it below `readWorkspaceCheckpoint`.

Modify `src/handoff/export.ts`:

```ts
export async function readHandoffArtifact(handoffId: string): Promise<{ json: HandoffArtifact; markdown: string }> {
  const dir = handoffDirPath(handoffId);
  const jsonPath = path.join(dir, 'handoff.json');
  const markdownPath = path.join(dir, 'HANDOFF.md');
  const json = JSON.parse(await fs.readFile(jsonPath, 'utf8')) as HandoffArtifact;
  const markdown = await fs.readFile(markdownPath, 'utf8');
  return { json, markdown };
}
```

- [ ] **Step 4: Add view types to contract**

Append these types to `src/headless/contract.ts`:

```ts
export type SessionRecordView =
  | {
      id: string;
      ts: string;
      kind: 'system';
      role: 'system';
      text: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'user';
      role: 'user';
      text: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'assistant';
      role: 'assistant';
      actionType: 'message' | 'tool-call' | 'invalid' | 'none';
      message?: string;
    }
  | {
      id: string;
      ts: string;
      kind: 'tool';
      role: 'user';
      tool: string;
      status: 'ok' | 'error';
      contentPreview: string;
      meta?: Record<string, string | number | boolean | null>;
    };

export type CheckpointView = {
  id: string;
  name?: string;
  kind: 'auto' | 'manual' | 'restore-safety' | 'handoff';
  createdAt: string;
  recordIndex: number;
  turn: number;
  workspaceCheckpointId?: string;
};

export type WorkspaceCheckpointView = {
  id: string;
  kind: 'git-ghost' | 'unavailable';
  status: 'available' | 'expired' | 'unavailable';
  createdAt: string;
  workspaceRealPath: string;
  gitRootRealPath?: string;
  commitId?: string;
  reason?: 'not-git' | 'snapshot-failed';
  warnings?: string[];
};

export type CompactionView = {
  id: string;
  status: 'active' | 'superseded';
  createdAt: string;
  coveredRange: {
    startIndexInclusive: number;
    endIndexExclusive: number;
  };
  firstKeptRecordId: string;
  anchorCheckpointId?: string;
  createdBy: {
    provider: ProviderName;
    model: string;
  };
  summaryMarkdown: string;
  auto?: {
    trigger: 'threshold' | 'overflow';
    phase: 'pre-model' | 'mid-loop';
    estimatedTokensBefore: number;
    estimatedTokensAfter?: number;
  };
};

export type HandoffView = {
  id: string;
  createdAt: string;
  sessionId: string;
  parentSessionId?: string;
  checkpointId: string;
  activeCompactionId?: string;
  summarySource: 'active-compaction' | 'handoff-only';
  provider: ProviderName;
  model: string;
  workspaceCheckpointId?: string;
  summaryMarkdown: string;
  markdown: string;
};

export type SessionView = {
  id: string;
  cwd: string;
  model: SessionModelRef;
  lifecycle: {
    status: 'idle' | 'running';
    turn: number;
    lastUserInputAt?: string;
    lastAssistantOutputAt?: string;
  };
  parentSessionId?: string;
  forkedFromCheckpointId?: string;
  records: SessionRecordView[];
  checkpoints: CheckpointView[];
  compactions: CompactionView[];
};

export type ArtifactView =
  | { kind: 'checkpoint'; checkpoint: CheckpointView; workspaceCheckpoint?: WorkspaceCheckpointView }
  | { kind: 'workspace-checkpoint'; workspaceCheckpoint: WorkspaceCheckpointView }
  | { kind: 'compaction'; compaction: CompactionView }
  | { kind: 'handoff'; handoff: HandoffView };
```

- [ ] **Step 5: Implement artifact view functions**

Create `src/headless/artifacts.ts`:

```ts
import { readHandoffArtifact } from '../handoff/export.js';
import { getWorkspaceCheckpoint } from '../session/checkpoints.js';
import type { CompactionArtifact, Session, SessionCheckpoint, SessionRecord, WorkspaceCheckpoint } from '../session/types.js';
import type {
  ArtifactView,
  CheckpointView,
  CompactionView,
  HandoffView,
  SessionRecordView,
  SessionView,
  WorkspaceCheckpointView
} from './contract.js';

const TOOL_PREVIEW_CHARS = 240;
const TRUNCATION_MARKER = '\n[cliq preview truncated]';

function preview(value: string, limit = TOOL_PREVIEW_CHARS) {
  if (value.length <= limit) {
    return value;
  }
  return `${value.slice(0, Math.max(0, limit - TRUNCATION_MARKER.length))}${TRUNCATION_MARKER}`;
}

export function toSessionRecordView(record: SessionRecord): SessionRecordView {
  if (record.kind === 'system' || record.kind === 'user') {
    return {
      id: record.id,
      ts: record.ts,
      kind: record.kind,
      role: record.role,
      text: record.content
    };
  }

  if (record.kind === 'tool') {
    return {
      id: record.id,
      ts: record.ts,
      kind: 'tool',
      role: 'user',
      tool: record.tool,
      status: record.status,
      contentPreview: preview(record.content),
      meta: record.meta
    };
  }

  if (record.action && 'message' in record.action) {
    return {
      id: record.id,
      ts: record.ts,
      kind: 'assistant',
      role: 'assistant',
      actionType: 'message',
      message: record.action.message
    };
  }

  if (record.action) {
    return {
      id: record.id,
      ts: record.ts,
      kind: 'assistant',
      role: 'assistant',
      actionType: 'tool-call'
    };
  }

  return {
    id: record.id,
    ts: record.ts,
    kind: 'assistant',
    role: 'assistant',
    actionType: 'none'
  };
}

export function toCheckpointView(checkpoint: SessionCheckpoint): CheckpointView {
  return {
    id: checkpoint.id,
    name: checkpoint.name,
    kind: checkpoint.kind,
    createdAt: checkpoint.createdAt,
    recordIndex: checkpoint.recordIndex,
    turn: checkpoint.turn,
    workspaceCheckpointId: checkpoint.workspaceCheckpointId
  };
}

export function toWorkspaceCheckpointView(checkpoint: WorkspaceCheckpoint): WorkspaceCheckpointView {
  if (checkpoint.kind === 'unavailable') {
    return {
      id: checkpoint.id,
      kind: checkpoint.kind,
      status: checkpoint.status,
      createdAt: checkpoint.createdAt,
      workspaceRealPath: checkpoint.workspaceRealPath,
      reason: checkpoint.reason
    };
  }

  return {
    id: checkpoint.id,
    kind: checkpoint.kind,
    status: checkpoint.status,
    createdAt: checkpoint.createdAt,
    workspaceRealPath: checkpoint.workspaceRealPath,
    gitRootRealPath: checkpoint.gitRootRealPath,
    commitId: checkpoint.commitId,
    warnings: checkpoint.warnings
  };
}

export function toCompactionView(compaction: CompactionArtifact): CompactionView {
  return {
    id: compaction.id,
    status: compaction.status,
    createdAt: compaction.createdAt,
    coveredRange: compaction.coveredRange,
    firstKeptRecordId: compaction.firstKeptRecordId,
    anchorCheckpointId: compaction.anchorCheckpointId,
    createdBy: compaction.createdBy,
    summaryMarkdown: compaction.summaryMarkdown,
    auto: compaction.auto
      ? {
          trigger: compaction.auto.trigger,
          phase: compaction.auto.phase,
          estimatedTokensBefore: compaction.auto.estimatedTokensBefore,
          estimatedTokensAfter: compaction.auto.estimatedTokensAfter
        }
      : undefined
  };
}

export function toSessionView(session: Session): SessionView {
  return {
    id: session.id,
    cwd: session.cwd,
    model: session.model,
    lifecycle: session.lifecycle,
    parentSessionId: session.parentSessionId,
    forkedFromCheckpointId: session.forkedFromCheckpointId,
    records: session.records.map(toSessionRecordView),
    checkpoints: session.checkpoints.map(toCheckpointView),
    compactions: session.compactions.map(toCompactionView)
  };
}

async function toHandoffView(handoffId: string): Promise<HandoffView> {
  const handoff = await readHandoffArtifact(handoffId);
  const artifact = handoff.json;
  return {
    id: artifact.id,
    createdAt: artifact.createdAt,
    sessionId: artifact.sessionId,
    parentSessionId: artifact.parentSessionId,
    checkpointId: artifact.checkpointId,
    activeCompactionId: artifact.activeCompactionId,
    summarySource: artifact.summarySource,
    provider: artifact.provider,
    model: artifact.model,
    workspaceCheckpointId: artifact.workspaceCheckpointId,
    summaryMarkdown: artifact.summaryMarkdown,
    markdown: handoff.markdown
  };
}

export async function getArtifactView(session: Session, artifactId: string): Promise<ArtifactView> {
  const checkpoint = session.checkpoints.find((candidate) => candidate.id === artifactId);
  if (checkpoint) {
    const workspaceCheckpoint = checkpoint.workspaceCheckpointId
      ? toWorkspaceCheckpointView(await getWorkspaceCheckpoint(checkpoint.workspaceCheckpointId))
      : undefined;
    return {
      kind: 'checkpoint',
      checkpoint: toCheckpointView(checkpoint),
      workspaceCheckpoint
    };
  }

  if (artifactId.startsWith('wchk_')) {
    return {
      kind: 'workspace-checkpoint',
      workspaceCheckpoint: toWorkspaceCheckpointView(await getWorkspaceCheckpoint(artifactId))
    };
  }

  const compaction = session.compactions.find((candidate) => candidate.id === artifactId);
  if (compaction) {
    return {
      kind: 'compaction',
      compaction: toCompactionView(compaction)
    };
  }

  if (artifactId.startsWith('handoff_')) {
    return {
      kind: 'handoff',
      handoff: await toHandoffView(artifactId)
    };
  }

  throw new Error(`artifact not found: ${artifactId}`);
}
```

- [ ] **Step 6: Run artifact tests and build**

Run:

```bash
node --test --import tsx src/headless/artifacts.test.ts
npm run build
```

Expected: PASS for artifact tests; PASS for build.

- [ ] **Step 7: Commit Task 2**

```bash
git add src/headless/contract.ts src/headless/artifacts.ts src/headless/artifacts.test.ts src/session/checkpoints.ts src/handoff/export.ts
git commit -m "feat: add headless artifact views"
```

## Task 3: Runner Checkpoint Event And Cancellation Boundaries

**Files:**
- Modify: `src/runtime/runner.ts`
- Modify: `src/runtime/runner.test.ts`
- Modify: `src/model/types.ts`
- Modify: `src/model/providers/anthropic.ts`
- Modify: `src/model/providers/ollama.ts`
- Modify: `src/model/providers/openai-compatible.ts`
- Modify: `src/model/providers/openai.ts`
- Modify: `src/model/providers/openrouter.ts`
- Modify: `src/tools/types.ts`

- [ ] **Step 1: Write failing runner tests**

Append these tests to `src/runtime/runner.test.ts`:

```ts
test('runner emits checkpoint-created after automatic checkpoint creation', async () => {
  const session = await createTempSession();
  const events: string[] = [];

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    },
    onEvent(event) {
      events.push(event.type);
    }
  });

  await runner.runTurn(session, 'say done');

  assert.equal(events[0], 'checkpoint-created');
  assert.equal(session.checkpoints.length, 1);
});

test('runner cancellation before checkpoint leaves session records unchanged', async () => {
  const session = await createTempSession();
  const controller = new AbortController();
  controller.abort();

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    },
    signal: controller.signal
  });

  await assert.rejects(() => runner.runTurn(session, 'say done'), /cancelled/i);
  assert.equal(session.records.length, 0);
  assert.equal(session.checkpoints.length, 0);
  assert.equal(session.lifecycle.status, 'idle');
});

test('runner cancellation after checkpoint keeps checkpoint and skips user append', async () => {
  const session = await createTempSession();
  const controller = new AbortController();
  const events: string[] = [];

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    },
    signal: controller.signal,
    onEvent(event) {
      events.push(event.type);
      if (event.type === 'checkpoint-created') {
        controller.abort();
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'say done'), /cancelled/i);
  assert.deepEqual(events, ['checkpoint-created', 'error']);
  assert.equal(session.checkpoints.length, 1);
  assert.equal(session.records.length, 0);
  assert.equal(session.lifecycle.status, 'idle');
});
```

- [ ] **Step 2: Run runner tests and verify they fail**

Run:

```bash
node --test --import tsx src/runtime/runner.test.ts --test-name-pattern "checkpoint-created|cancellation"
```

Expected: FAIL because `createRunner` does not accept `signal` and does not emit `checkpoint-created`.

- [ ] **Step 3: Pass signal through model and tool types**

Modify `src/model/types.ts`:

```ts
export type ModelClient = {
  complete(
    messages: ChatMessage[],
    options?: {
      onEvent?: (event: ModelStreamEvent) => void | Promise<void>;
      signal?: AbortSignal;
    }
  ): Promise<ModelCompletion>;
};
```

Modify `src/tools/types.ts`:

```ts
export type ToolContext = {
  cwd: string;
  session: Session;
  signal?: AbortSignal;
};
```

Modify `src/model/providers/anthropic.ts`, `src/model/providers/ollama.ts`, `src/model/providers/openai-compatible.ts`, `src/model/providers/openai.ts`, and `src/model/providers/openrouter.ts` so each `fetch` request options object includes:

```ts
signal: options?.signal
```

When a provider uses multiple `fetch` calls, pass the same signal to each call.

- [ ] **Step 4: Add cancellation helpers and checkpoint event in runner**

In `src/runtime/runner.ts`, update `createRunner` options:

```ts
export function createRunner({
  model,
  registry = createToolRegistry(),
  hooks = [],
  policy = createPolicyEngine({ mode: DEFAULT_POLICY_MODE }),
  instructions = async () => [],
  onEvent = async () => undefined,
  autoCompact,
  signal
}: {
  model: ModelClient;
  registry?: ReturnType<typeof createToolRegistry>;
  hooks?: RuntimeHook[];
  policy?: ReturnType<typeof createPolicyEngine>;
  instructions?: (session: Session) => Promise<InstructionMessage[]>;
  onEvent?: RuntimeEventSink;
  autoCompact?: AutoCompactRunnerOptions;
  signal?: AbortSignal;
}) {
```

Inside `runTurn`, add this helper near `const cwd = session.cwd;`:

```ts
const throwIfCancelled = async () => {
  if (signal?.aborted) {
    await onEvent({ type: 'error', stage: 'cancel', message: 'run cancelled' });
    throw new Error('run cancelled');
  }
};
```

Change the setup sequence to:

```ts
const previousLifecycle = {
  status: session.lifecycle.status,
  turn: session.lifecycle.turn,
  lastUserInputAt: session.lifecycle.lastUserInputAt,
  lastAssistantOutputAt: session.lifecycle.lastAssistantOutputAt
};
let checkpointCreated = false;

await throwIfCancelled();
session.lifecycle.status = 'running';
session.lifecycle.turn += 1;
await throwIfCancelled();
const checkpoint = await createCheckpoint(cwd, session, { kind: 'auto' });
checkpointCreated = true;
await onEvent({
  type: 'checkpoint-created',
  checkpointId: checkpoint.id,
  kind: checkpoint.kind,
  workspaceCheckpointId: checkpoint.workspaceCheckpointId,
  workspaceSnapshotStatus: checkpoint.workspaceCheckpoint.status,
  warning:
    checkpoint.workspaceCheckpoint.kind === 'unavailable'
      ? checkpoint.workspaceCheckpoint.error ?? checkpoint.workspaceCheckpoint.reason
      : undefined
});
await throwIfCancelled();
const ts = nowIso();
await appendRecord(cwd, session, {
  id: makeId('usr'),
  ts,
  kind: 'user',
  role: 'user',
  content: userInput
});
session.lifecycle.lastUserInputAt = ts;
await saveSession(cwd, session);
await throwIfCancelled();
```

Change the `finally` block to preserve pre-checkpoint cancellation semantics:

```ts
if (!checkpointCreated) {
  session.lifecycle.status = previousLifecycle.status;
  session.lifecycle.turn = previousLifecycle.turn;
  session.lifecycle.lastUserInputAt = previousLifecycle.lastUserInputAt;
  session.lifecycle.lastAssistantOutputAt = previousLifecycle.lastAssistantOutputAt;
} else {
  session.lifecycle.status = 'idle';
}
await saveSession(cwd, session);
```

Pass `signal` to model completion:

```ts
const completion = await model.complete(buildContextMessages(session, currentInstructions), {
  signal,
  async onEvent(event) {
    if (event.type === 'start') {
      activeProvider = event.provider;
      activeModel = event.model;
      sawModelStart = true;
      await onEvent({
        type: 'model-start',
        provider: event.provider,
        model: event.model,
        streaming: event.streaming
      });
    } else if (event.type === 'text-delta') {
      chunks += 1;
      chars += event.text.length;
      await onEvent({ type: 'model-progress', chunks, chars });
    } else if (event.type === 'end') {
      if (activeProvider && activeModel) {
        sawModelEnd = true;
        await onEvent({ type: 'model-end', provider: activeProvider, model: activeModel });
      }
    } else if (event.type === 'error') {
      sawModelError = true;
      await onEvent({ type: 'error', stage: 'model', message: event.message });
    }
  }
});
```

Add `await throwIfCancelled();` before each loop model request, before policy authorization, before tool execution, before auto compact, and after appending tool results before the next loop.

Pass `signal` into tool execution:

```ts
result = await definition.execute(action as never, { cwd, session, signal });
```

- [ ] **Step 5: Run focused runner tests**

Run:

```bash
node --test --import tsx src/runtime/runner.test.ts --test-name-pattern "checkpoint-created|cancellation"
```

Expected: PASS.

- [ ] **Step 6: Run full runner and provider tests**

Run:

```bash
node --test --import tsx src/runtime/runner.test.ts src/model/providers/*.test.ts
npm run build
```

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```bash
git add src/runtime/runner.ts src/runtime/runner.test.ts src/model/types.ts src/model/providers src/tools/types.ts
git commit -m "feat: add runner checkpoint events and cancellation"
```

## Task 4: Headless Run Orchestration

**Files:**
- Create: `src/headless/run.ts`
- Test: `src/headless/run.test.ts`

- [ ] **Step 1: Write failing headless run tests**

Create `src/headless/run.test.ts`:

```ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import type { ModelClient } from '../model/types.js';
import { runHeadless } from './run.js';

const previousHome = process.env.CLIQ_HOME;
const cleanupDirs: string[] = [];

test.after(async () => {
  if (previousHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = previousHome;
  }
  await Promise.all(cleanupDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function setupWorkspace() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-run-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-run-workspace-'));
  cleanupDirs.push(home, cwd);
  process.env.CLIQ_HOME = home;
  return { home, cwd };
}

function finalModel(message = 'done'): ModelClient {
  return {
    async complete(_messages, options) {
      await options?.onEvent?.({ type: 'start', provider: 'ollama', model: 'test-model', streaming: false });
      await options?.onEvent?.({ type: 'end' });
      return { provider: 'ollama', model: 'test-model', content: JSON.stringify({ message }) };
    }
  };
}

test('runHeadless emits run-start through run-end for a completed run', async () => {
  const { cwd } = await setupWorkspace();
  const events: string[] = [];

  const output = await runHeadless(
    { cwd, prompt: 'say done', model: { provider: 'ollama', model: 'test-model' } },
    {
      modelClient: finalModel('done'),
      onEvent(event) {
        events.push(event.type);
      }
    }
  );

  assert.equal(output.status, 'completed');
  assert.equal(output.exitCode, 0);
  assert.equal(output.finalMessage, 'done');
  assert.equal(typeof output.sessionId, 'string');
  assert.equal(typeof output.turn, 'number');
  assert.deepEqual(events, ['run-start', 'checkpoint-created', 'model-start', 'model-end', 'final', 'run-end']);
});

test('runHeadless returns structured pre-session errors without session fields', async () => {
  const events: Array<{ type: string; sessionId?: string; turn?: number }> = [];

  const output = await runHeadless(
    { cwd: '/path/that/does/not/exist', prompt: 'say done' },
    {
      modelClient: finalModel('done'),
      onEvent(event) {
        events.push({ type: event.type, sessionId: event.sessionId, turn: event.turn });
      }
    }
  );

  assert.equal(output.status, 'failed');
  assert.equal(output.error?.code, 'invalid-input');
  assert.equal(output.sessionId, undefined);
  assert.equal(output.turn, undefined);
  assert.deepEqual(events.map((event) => event.type), ['error', 'run-end']);
  assert.equal(events[0]?.sessionId, undefined);
  assert.equal(events[0]?.turn, undefined);
});

test('runHeadless rejects unknown session request fields', async () => {
  const { cwd } = await setupWorkspace();

  const output = await runHeadless(
    { cwd, prompt: 'say done', session: { mode: 'active', id: 'sess_1' } as never },
    { modelClient: finalModel('done') }
  );

  assert.equal(output.status, 'failed');
  assert.equal(output.error?.code, 'invalid-input');
  assert.match(output.error?.message ?? '', /unknown session field/i);
});
```

- [ ] **Step 2: Run headless run tests and verify they fail**

Run:

```bash
node --test --import tsx src/headless/run.test.ts
```

Expected: FAIL because `src/headless/run.ts` does not exist.

- [ ] **Step 3: Implement request validation and dependency injection**

Create `src/headless/run.ts` with this structure:

```ts
import { stat } from 'node:fs/promises';

import { DEFAULT_POLICY_MODE } from '../config.js';
import { resolveModelConfig, type PartialModelConfig } from '../model/config.js';
import { createModelClient } from '../model/index.js';
import type { ModelClient, ResolvedModelConfig } from '../model/types.js';
import { createPolicyEngine } from '../policy/engine.js';
import type { PolicyConfirm, PolicyMode } from '../policy/types.js';
import { createRuntimeAssembly } from '../runtime/assembly.js';
import type { RuntimeHook } from '../runtime/hooks.js';
import { createRunner } from '../runtime/runner.js';
import { ensureFresh, ensureSession, makeId } from '../session/store.js';
import type { Session } from '../session/types.js';
import type {
  HeadlessErrorCode,
  HeadlessErrorStage,
  HeadlessRunError,
  HeadlessRunOptions,
  HeadlessRunOutput,
  HeadlessRunRequest,
  RuntimeEventEnvelope
} from './contract.js';
import {
  emptyHeadlessArtifacts,
  HEADLESS_EXIT_CANCELLED,
  HEADLESS_EXIT_FAILURE,
  HEADLESS_EXIT_SUCCESS
} from './contract.js';
import { createHeadlessEventFactory, mergeArtifacts, runtimeEventToHeadless } from './events.js';

export type RunHeadlessDependencies = {
  modelClient?: ModelClient;
  createModelClient?: (config: ResolvedModelConfig) => ModelClient;
  confirm?: PolicyConfirm;
  hooks?: RuntimeHook[];
};

type RunScope = {
  session: Session;
  modelConfig: ResolvedModelConfig;
  policy: PolicyMode;
};

function errorFrom(code: HeadlessErrorCode, stage: HeadlessErrorStage, message: string, recoverable = false): HeadlessRunError {
  return { code, stage, message, recoverable };
}

async function validateRequest(request: HeadlessRunRequest) {
  if (!request.prompt?.trim()) {
    throw errorFrom('invalid-input', 'input', 'prompt is required');
  }
  if (!request.cwd?.trim()) {
    throw errorFrom('invalid-input', 'input', 'cwd is required');
  }
  const cwdStat = await stat(request.cwd).catch(() => null);
  if (!cwdStat?.isDirectory()) {
    throw errorFrom('invalid-input', 'input', `cwd must be an existing directory: ${request.cwd}`);
  }
  const sessionKeys = request.session ? Object.keys(request.session) : [];
  for (const key of sessionKeys) {
    if (key !== 'mode') {
      throw errorFrom('invalid-input', 'input', `unknown session field: ${key}`);
    }
  }
  if (request.session?.mode && request.session.mode !== 'active' && request.session.mode !== 'new') {
    throw errorFrom('invalid-input', 'input', `unknown session mode: ${request.session.mode}`);
  }
}
```

- [ ] **Step 4: Implement `runHeadless`**

Continue `src/headless/run.ts`:

```ts
export async function runHeadless(
  request: HeadlessRunRequest,
  options: HeadlessRunOptions & RunHeadlessDependencies = {}
): Promise<HeadlessRunOutput> {
  const runId = makeId('run');
  const artifacts = emptyHeadlessArtifacts();
  const createEvent = createHeadlessEventFactory({ runId });
  let scope: RunScope | undefined;

  const emit = async (event: RuntimeEventEnvelope) => {
    await options.onEvent?.(event);
  };

  const emitErrorAndEnd = async (error: HeadlessRunError, status: 'failed' | 'cancelled') => {
    const exitCode = status === 'cancelled' ? HEADLESS_EXIT_CANCELLED : HEADLESS_EXIT_FAILURE;
    const output: HeadlessRunOutput = {
      runId,
      sessionId: scope?.session.id,
      turn: scope?.session.lifecycle.turn,
      status,
      exitCode,
      artifacts,
      error
    };
    await emit(createEvent('error', error, scope ? { sessionId: scope.session.id, turn: scope.session.lifecycle.turn } : {}));
    await emit(createEvent('run-end', { status, exitCode, output }, scope ? { sessionId: scope.session.id, turn: scope.session.lifecycle.turn } : {}));
    return output;
  };

  try {
    await validateRequest(request);

    const session =
      request.session?.mode === 'new' ? await ensureFresh(request.cwd) : await ensureSession(request.cwd);
    const assembly = await createRuntimeAssembly({
      cwd: request.cwd,
      session,
      policyMode: request.policy ?? DEFAULT_POLICY_MODE,
      cliSkillNames: request.skills ?? []
    });
    const workspaceConfig = {
      ...assembly.workspaceConfig,
      autoCompact: request.autoCompact ?? assembly.workspaceConfig.autoCompact
    };
    const modelConfig = await resolveModelConfig({
      workspace: workspaceConfig,
      cli: request.model as PartialModelConfig | undefined
    });
    session.model = {
      provider: modelConfig.provider,
      model: modelConfig.model,
      baseUrl: modelConfig.baseUrl
    };
    scope = {
      session,
      modelConfig,
      policy: request.policy ?? DEFAULT_POLICY_MODE
    };

    await emit(
      createEvent(
        'run-start',
        {
          cwd: request.cwd,
          policy: scope.policy,
          model: session.model
        },
        { sessionId: session.id, turn: session.lifecycle.turn + 1 }
      )
    );

    const modelClient = options.modelClient ?? options.createModelClient?.(modelConfig) ?? createModelClient(modelConfig);
    const runner = createRunner({
      model: modelClient,
      hooks: [...assembly.hooks, ...(options.hooks ?? [])],
      policy: createPolicyEngine({ mode: scope.policy, confirm: options.confirm }),
      instructions: assembly.instructions,
      signal: options.signal,
      autoCompact: {
        config: workspaceConfig.autoCompact,
        modelConfig
      },
      async onEvent(runtimeEvent) {
        const mapped = runtimeEventToHeadless(runtimeEvent);
        if (mapped.artifacts) {
          mergeArtifacts(artifacts, mapped.artifacts);
        }
        await emit(
          createEvent(mapped.type, mapped.payload, {
            sessionId: session.id,
            turn: session.lifecycle.turn
          })
        );
      }
    });

    const finalMessage = await runner.runTurn(session, request.prompt.trim());
    const output: HeadlessRunOutput = {
      runId,
      sessionId: session.id,
      turn: session.lifecycle.turn,
      status: 'completed',
      exitCode: HEADLESS_EXIT_SUCCESS,
      finalMessage,
      checkpointId: artifacts.checkpoints[0],
      artifacts
    };
    await emit(createEvent('run-end', { status: 'completed', exitCode: HEADLESS_EXIT_SUCCESS, output }, { sessionId: session.id, turn: session.lifecycle.turn }));
    return output;
  } catch (error) {
    if (typeof error === 'object' && error && 'code' in error && 'stage' in error) {
      const headlessError = error as HeadlessRunError;
      const status = headlessError.code === 'cancelled' ? 'cancelled' : 'failed';
      return await emitErrorAndEnd(headlessError, status);
    }
    const message = error instanceof Error ? error.message : String(error);
    const headlessError = errorFrom(
      message.toLowerCase().includes('cancelled') ? 'cancelled' : 'internal-error',
      message.toLowerCase().includes('cancelled') ? 'cancel' : 'assembly',
      message
    );
    return await emitErrorAndEnd(headlessError, headlessError.code === 'cancelled' ? 'cancelled' : 'failed');
  }
}
```

- [ ] **Step 5: Run headless run tests**

Run:

```bash
node --test --import tsx src/headless/run.test.ts
npm run build
```

Expected: PASS.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/headless/run.ts src/headless/run.test.ts
git commit -m "feat: add headless run orchestration"
```

## Task 5: JSONL Adapter And CLI Integration

**Files:**
- Create: `src/headless/jsonl.ts`
- Modify: `src/cli.ts`
- Modify: `src/cli.test.ts`

- [ ] **Step 1: Write failing CLI parse tests**

Add to `src/cli.test.ts` near the other `parseArgs` tests:

```ts
test('parseArgs accepts command-scoped run --jsonl', () => {
  assert.deepEqual(parseArgs(['node', 'src/index.ts', 'run', '--jsonl', 'inspect', 'repo']), {
    cmd: 'chat',
    prompt: 'inspect repo',
    jsonl: true,
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('parseArgs rejects --jsonl outside one-shot run aliases', () => {
  assert.throws(() => parseArgs(['node', 'src/index.ts', '--jsonl', 'inspect']), /--jsonl is only supported with cliq run/i);
  assert.throws(() => parseArgs(['node', 'src/index.ts', 'chat', '--jsonl']), /--jsonl is only supported with cliq run/i);
});
```

- [ ] **Step 2: Add JSONL writer unit test**

Create `src/headless/jsonl.test.ts`:

```ts
import test from 'node:test';
import assert from 'node:assert/strict';

import type { RuntimeEventEnvelope } from './contract.js';
import { writeJsonlEvent } from './jsonl.js';

test('writeJsonlEvent writes one parseable JSON object per line', () => {
  const chunks: string[] = [];
  const event: RuntimeEventEnvelope = {
    schemaVersion: 1,
    eventId: 'evt_1',
    runId: 'run_1',
    timestamp: '2026-05-03T00:00:00.000Z',
    type: 'error',
    payload: {
      code: 'invalid-input',
      stage: 'input',
      message: 'prompt is required',
      recoverable: false
    }
  };

  writeJsonlEvent(event, (chunk) => {
    chunks.push(chunk);
  });

  assert.equal(chunks.length, 1);
  assert.equal(chunks[0]?.endsWith('\n'), true);
  assert.deepEqual(JSON.parse(chunks[0]!), event);
});
```

- [ ] **Step 3: Run tests and verify they fail**

Run:

```bash
node --test --import tsx src/headless/jsonl.test.ts src/cli.test.ts --test-name-pattern "jsonl|JSONL"
```

Expected: FAIL because JSONL parsing and writer do not exist.

- [ ] **Step 4: Implement JSONL writer**

Create `src/headless/jsonl.ts`:

```ts
import type { RuntimeEventEnvelope } from './contract.js';

export function writeJsonlEvent(
  event: RuntimeEventEnvelope,
  write: (chunk: string) => void = (chunk) => {
    process.stdout.write(chunk);
  }
) {
  write(`${JSON.stringify(event)}\n`);
}
```

- [ ] **Step 5: Update parsed args for JSONL**

In `src/cli.ts`, update the `ParsedArgs` chat shape:

```ts
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
```

Add helper:

```ts
function parseRunArgs(args: string[], base: ParsedArgsBase): ParsedArgs {
  const promptParts: string[] = [];
  let jsonl = false;

  for (let i = 1; i < args.length; i += 1) {
    const token = args[i];
    if (token === '--jsonl') {
      jsonl = true;
      continue;
    }
    if (token.startsWith('--jsonl=')) {
      throw new Error('--jsonl does not accept a value');
    }
    promptParts.push(token);
  }

  return { ...base, cmd: 'chat', prompt: promptParts.join(' '), ...(jsonl ? { jsonl } : {}) };
}
```

Update the command dispatch:

```ts
if (cmd === '--jsonl' || cmd?.startsWith('--jsonl=')) {
  throw new Error('--jsonl is only supported with cliq run --jsonl "task"');
}
const hasJsonlArg = args.includes('--jsonl') || args.some((arg) => arg.startsWith('--jsonl='));
if (!cmd || cmd === 'chat') {
  if (hasJsonlArg) {
    throw new Error('--jsonl is only supported with cliq run --jsonl "task"');
  }
  return { cmd: 'chat', prompt: args.slice(1).join(' '), policy, skills, model };
}
if (cmd === 'run') return parseRunArgs(args, base);
if (cmd === 'ask') {
  if (hasJsonlArg) {
    throw new Error('--jsonl is only supported with cliq run --jsonl "task"');
  }
  return parseAskArgs(args, base);
}
```

- [ ] **Step 6: Route one-shot runs through headless**

In `src/cli.ts`, import:

```ts
import { runHeadless } from './headless/run.js';
import { writeJsonlEvent } from './headless/jsonl.js';
import type { RuntimeEventEnvelope } from './headless/contract.js';
import type { ProviderName } from './model/types.js';
```

Add this adapter near `createCliEventSink`:

```ts
async function renderHeadlessEventToCli(event: RuntimeEventEnvelope, eventSink: ReturnType<typeof createCliEventSink>) {
  if (event.type === 'run-start' || event.type === 'run-end') {
    return;
  }

  if (event.type === 'model-start') {
    const payload = event.payload as { provider: ProviderName; model: string; streaming: boolean };
    await eventSink({ type: 'model-start', provider: payload.provider, model: payload.model, streaming: payload.streaming });
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
```

Replace the one-shot `if (prompt && prompt.trim())` branch with:

```ts
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
```

- [ ] **Step 7: Add JSONL CLI behavior test**

Add to `src/cli.test.ts`:

```ts
test('runCli run --jsonl writes only JSONL events to stdout for model errors', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'cliq-jsonl-cwd-'));
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-jsonl-home-'));
  const previousCwd = process.cwd();
  const previousHome = process.env.CLIQ_HOME;
  const previousWrite = process.stdout.write;
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw new Error('fetch failed');
  });
  const chunks: string[] = [];

  process.chdir(cwd);
  process.env.CLIQ_HOME = home;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;

  try {
    await assert.rejects(
      () =>
        runCli([
          'node',
          'src/index.ts',
          '--provider',
          'openai-compatible',
          '--model',
          'fake',
          '--base-url',
          'http://127.0.0.1:59999/v1',
          '--streaming',
          'off',
          'run',
          '--jsonl',
          'hello'
        ]),
      isReportedCliError
    );
  } finally {
    process.stdout.write = previousWrite;
    fetchMock.mock.restore();
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    process.chdir(previousCwd);
    await rm(cwd, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }

  const lines = chunks.join('').trim().split('\n').filter(Boolean);
  assert.equal(lines.length >= 2, true);
  for (const line of lines) {
    assert.doesNotThrow(() => JSON.parse(line));
  }
  assert.equal(lines.some((line) => JSON.parse(line).type === 'run-start'), true);
  assert.equal(lines.some((line) => JSON.parse(line).type === 'error'), true);
  assert.equal(JSON.parse(lines.at(-1)!).type, 'run-end');
});
```

- [ ] **Step 8: Run CLI and JSONL tests**

Run:

```bash
node --test --import tsx src/headless/jsonl.test.ts src/cli.test.ts --test-name-pattern "jsonl|JSONL|one-shot|reported"
npm run build
```

Expected: PASS.

- [ ] **Step 9: Commit Task 5**

```bash
git add src/headless/jsonl.ts src/headless/jsonl.test.ts src/cli.ts src/cli.test.ts
git commit -m "feat: add headless jsonl cli"
```

## Task 6: Full Verification And Regression Tightening

**Files:**
- Modify only files needed to fix failures found by the commands in this task.

- [ ] **Step 1: Run full test suite**

Run:

```bash
npm test
```

Expected: PASS.

- [ ] **Step 2: Run TypeScript build**

Run:

```bash
npm run build
```

Expected: PASS.

- [ ] **Step 3: Manually verify JSONL parseability**

Run:

```bash
npm run build
node --input-type=module -e "import { runHeadless } from './dist/headless/run.js'; import { writeJsonlEvent } from './dist/headless/jsonl.js'; const output = await runHeadless({ cwd: '/path/that/does/not/exist', prompt: 'hello' }, { onEvent: writeJsonlEvent }); process.exitCode = output.exitCode;"
```

Expected:

- Command exits non-zero because `cwd` is invalid.
- stdout contains only JSONL.
- Each line parses with `JSON.parse`.
- The final event has `"type":"run-end"`.

Verify the captured stdout:

```bash
node --input-type=module -e "import { runHeadless } from './dist/headless/run.js'; import { writeJsonlEvent } from './dist/headless/jsonl.js'; const output = await runHeadless({ cwd: '/path/that/does/not/exist', prompt: 'hello' }, { onEvent: writeJsonlEvent }); process.exitCode = output.exitCode;" 1>/tmp/cliq-jsonl.out 2>/tmp/cliq-jsonl.err || true
node -e "for (const line of require('node:fs').readFileSync('/tmp/cliq-jsonl.out','utf8').trim().split('\\n').filter(Boolean)) JSON.parse(line); console.log('jsonl ok')"
```

Expected: `jsonl ok`.

- [ ] **Step 4: Review git diff for scope**

Run:

```bash
git diff --stat origin/main...HEAD
git status --short
```

Expected:

- Changes are limited to `src/headless`, `src/runtime`, `src/model`, `src/tools`, `src/cli`, tests, and provider signal pass-through.
- No JSON-RPC implementation files are present except future references in docs.
- Working tree is clean after the final commit.

- [ ] **Step 5: Commit any regression fixes**

If Step 1 or Step 2 required fixes, inspect the exact changed files:

```bash
git status --short
```

Stage only the source and test files shown by `git status --short`, then commit:

```bash
git add src/headless src/runtime src/model src/tools src/cli.ts src/cli.test.ts
git commit -m "fix: stabilize headless runtime regressions"
```

If no fixes were required, do not create an empty commit.

## Spec Coverage Checklist

- `HeadlessRunRequest` / `HeadlessRunOptions`: Task 1 and Task 4.
- Pre-session event envelope semantics: Task 1 and Task 4.
- JSONL CLI adapter: Task 5.
- Artifact query views: Task 2.
- Cooperative cancellation: Task 3 and Task 4.
- Checkpoint-created event: Task 1 and Task 3.
- Runtime/CLI separation: Task 4 and Task 5.
- RPC follow-up excluded from v0.7.0: Scope section and Task 6 scope review.

## Final Verification Commands

Run these before declaring the implementation complete:

```bash
npm test
npm run build
node --input-type=module -e "import { runHeadless } from './dist/headless/run.js'; import { writeJsonlEvent } from './dist/headless/jsonl.js'; const output = await runHeadless({ cwd: '/path/that/does/not/exist', prompt: 'hello' }, { onEvent: writeJsonlEvent }); process.exitCode = output.exitCode;" 1>/tmp/cliq-jsonl.out 2>/tmp/cliq-jsonl.err || true
node -e "for (const line of require('node:fs').readFileSync('/tmp/cliq-jsonl.out','utf8').trim().split('\\n').filter(Boolean)) JSON.parse(line); console.log('jsonl ok')"
```

Expected:

- `npm test` passes.
- `npm run build` passes.
- JSONL parse check prints `jsonl ok`.
