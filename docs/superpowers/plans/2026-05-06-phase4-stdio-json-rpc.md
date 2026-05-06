# Phase 4 Stdio JSON-RPC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal stdio JSON-RPC adapter on top of the existing headless run contract so GUI, gateway, automation, and future subagent orchestrators can start runs, receive events, cancel work, and query stable session/artifact views.

**Architecture:** Keep `src/runtime/runner.ts` unchanged and keep `runHeadless` as the single run orchestration API. Add a thin `src/headless/rpc.ts` transport/controller layer that speaks newline-delimited JSON-RPC 2.0 over stdio, injects caller-visible `runId` values into `runHeadless`, forwards runtime envelopes as `run.event` notifications, and enforces one active run per RPC process while keeping `runId` in every public payload for future multi-run/subagent expansion.

**Tech Stack:** TypeScript, Node.js streams/readline, JSON-RPC 2.0 over stdio, existing `node:test` tests, existing headless/session/artifact modules.

---

## Design Review

No P1/P2 blockers were found in the proposed design. It matches the Phase 4 spec: stdio JSON-RPC is the next `v0.7.x` follow-up after JSONL, not a daemon, HTTP service, or subagent runtime.

One implementation detail must be fixed before the RPC adapter: `runHeadless` currently creates its own `runId`. RPC `run.start` must return a `runId` immediately, and all later `run.event` notifications must use the same `runId`. Therefore the first task adds `HeadlessRunOptions.runId?: string` and uses it in `runHeadless`.

## File Structure

- Modify `src/headless/contract.ts`: add optional local-only `runId` to `HeadlessRunOptions`.
- Modify `src/headless/run.ts`: use `options.runId ?? makeId('run')`.
- Modify `src/headless/run.test.ts`: prove injected `runId` appears in output and emitted events.
- Modify `src/session/store.ts`: export a read-only `loadSessionById(cwd, sessionId)` helper backed by the workspace recent-session index.
- Modify `src/headless/artifacts.ts`: add `getSessionView(cwd, sessionId?)` and `getArtifactViewForRequest(cwd, artifactId, sessionId?)` wrappers so RPC does not know session-store internals.
- Modify `src/headless/artifacts.test.ts`: cover active session view, session-id lookup, missing session, and artifact lookup wrappers.
- Create `src/headless/rpc.ts`: JSON-RPC types, line framing, dispatcher, run controller, JSON-RPC error mapping, and stdio server entrypoint.
- Create `src/headless/rpc.test.ts`: unit tests for parse errors, method errors, run start/events, cancellation, single-active-run rejection, and session/artifact query methods.
- Modify `src/cli.ts`: add `rpc` command parsing/help and start the stdio RPC server.
- Modify `src/cli.test.ts`: cover `parseArgs` and help text for `rpc`.
- Modify `README.md`: document the minimal RPC protocol and its one-active-run constraint.
- Modify `docs/superpowers/specs/2026-05-03-phase4-headless-runtime-interfaces-design.md`: update the RPC section with the exact v1 request shapes and subagent-readiness note.

---

### Task 1: Caller-Supplied Run IDs

**Files:**
- Modify: `src/headless/contract.ts`
- Modify: `src/headless/run.ts`
- Test: `src/headless/run.test.ts`

- [ ] **Step 1: Add the failing run-id test**

Update the imports in `src/headless/run.test.ts`:

```ts
import type { RuntimeEventEnvelope } from './contract.js';
```

Append this test to the same file:

```ts
test('runHeadless uses a caller-supplied run id for output and events', async () => {
  const { cwd } = await setupWorkspace();
  const events: RuntimeEventEnvelope[] = [];

  const output = await runHeadless(
    {
      cwd,
      prompt: 'hello',
      model: { provider: 'openai-compatible', model: 'fake', baseUrl: 'http://localhost.test/v1' },
      autoCompact: { enabled: 'off' }
    },
    {
      runId: 'run_rpc_known',
      modelClient: finalModel('hello from rpc'),
      onEvent(event) {
        events.push(event);
      }
    }
  );

  assert.equal(output.runId, 'run_rpc_known');
  assert.ok(events.length > 0);
  assert.ok(events.every((event) => event.runId === 'run_rpc_known'));
});
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
node --test --import tsx src/headless/run.test.ts --test-name-pattern "caller-supplied run id"
```

Expected: FAIL with a TypeScript/runtime assertion because `HeadlessRunOptions` has no `runId` and `runHeadless` generates a different id.

- [ ] **Step 3: Add `runId` to local-only headless options**

In `src/headless/contract.ts`, update `HeadlessRunOptions`:

```ts
export type HeadlessRunOptions = {
  runId?: string;
  signal?: AbortSignal;
  onEvent?: (event: RuntimeEventEnvelope) => void | Promise<void>;
};
```

- [ ] **Step 4: Use the supplied run id in `runHeadless`**

In `src/headless/run.ts`, replace:

```ts
const runId = makeId('run');
```

with:

```ts
const runId = options.runId ?? makeId('run');
```

- [ ] **Step 5: Verify the focused test passes**

Run:

```bash
node --test --import tsx src/headless/run.test.ts --test-name-pattern "caller-supplied run id"
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/headless/contract.ts src/headless/run.ts src/headless/run.test.ts
git commit -m "feat: allow headless run id injection"
```

---

### Task 2: Stable Session And Artifact Query Wrappers

**Files:**
- Modify: `src/session/store.ts`
- Modify: `src/headless/artifacts.ts`
- Test: `src/headless/artifacts.test.ts`

- [ ] **Step 1: Add failing tests for RPC-ready query wrappers**

Update the imports in `src/headless/artifacts.test.ts`:

```ts
import { createSession, ensureSession, saveSession } from '../session/store.js';
import {
  getArtifactView,
  getArtifactViewForRequest,
  getSessionView,
  toSessionView
} from './artifacts.js';
```

Append these tests to the same file:

```ts
test('getSessionView returns active and explicit session views for a workspace', async () => {
  const { cwd } = await setupWorkspace();
  const active = await ensureSession(cwd);
  active.records.push({
    id: 'usr_rpc_1',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'hello'
  });
  await saveSession(cwd, active);

  const activeView = await getSessionView(cwd);
  const explicitView = await getSessionView(cwd, active.id);

  assert.equal(activeView.id, active.id);
  assert.equal(explicitView.id, active.id);
  assert.equal(explicitView.records[0]?.kind, 'user');
});

test('getSessionView rejects unknown session ids without creating raw file contracts', async () => {
  const { cwd } = await setupWorkspace();
  await ensureSession(cwd);

  await assert.rejects(
    async () => await getSessionView(cwd, 'sess_missing'),
    /session not found: sess_missing/
  );
});

test('getArtifactViewForRequest resolves artifacts through stable session lookup', async () => {
  const { cwd } = await setupWorkspace();
  const session = await ensureSession(cwd);
  session.records.push({
    id: 'usr_rpc_1',
    ts: '2026-05-06T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'checkpoint me'
  });
  await saveSession(cwd, session);
  const checkpoint = await createCheckpoint(cwd, session, { kind: 'manual', name: 'rpc-checkpoint' });

  const artifact = await getArtifactViewForRequest(cwd, checkpoint.id, session.id);

  assert.equal(artifact.kind, 'checkpoint');
  assert.equal(artifact.checkpoint.id, checkpoint.id);
});
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
node --test --import tsx src/headless/artifacts.test.ts --test-name-pattern "getSessionView| getArtifactViewForRequest"
```

Expected: FAIL because `getSessionView`, `getArtifactViewForRequest`, and `loadSessionById` do not exist.

- [ ] **Step 3: Export a read-only session lookup helper**

In `src/session/store.ts`, add this function after `ensureSession`:

```ts
export async function loadSessionById(cwd: string, sessionId: string): Promise<Session | null> {
  const state = await loadWorkspaceState(cwd);
  const match = state.recentSessions.find((entry) => entry.id === sessionId);
  if (!match) {
    return null;
  }

  const session = await loadSessionFromPath(match.path);
  return session?.id === sessionId ? session : null;
}
```

- [ ] **Step 4: Add headless query wrappers**

In `src/headless/artifacts.ts`, update the imports:

```ts
import { ensureSession, loadSessionById } from '../session/store.js';
```

Then add these exported helpers before the existing `getArtifactView` export:

```ts
function sessionNotFound(sessionId: string): never {
  throw new Error(`session not found: ${sessionId}`);
}

async function sessionForView(cwd: string, sessionId?: string): Promise<Session> {
  if (!sessionId) {
    return await ensureSession(cwd);
  }

  return (await loadSessionById(cwd, sessionId)) ?? sessionNotFound(sessionId);
}

export async function getSessionView(cwd: string, sessionId?: string): Promise<SessionView> {
  return toSessionView(await sessionForView(cwd, sessionId));
}

export async function getArtifactViewForRequest(
  cwd: string,
  artifactId: string,
  sessionId?: string
): Promise<ArtifactView> {
  return await getArtifactView(await sessionForView(cwd, sessionId), artifactId);
}
```

- [ ] **Step 5: Verify the focused tests pass**

Run:

```bash
node --test --import tsx src/headless/artifacts.test.ts --test-name-pattern "getSessionView| getArtifactViewForRequest"
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/session/store.ts src/headless/artifacts.ts src/headless/artifacts.test.ts
git commit -m "feat: expose headless session artifact queries"
```

---

### Task 3: JSON-RPC Dispatcher And Run Controller

**Files:**
- Create: `src/headless/rpc.ts`
- Test: `src/headless/rpc.test.ts`

- [ ] **Step 1: Create failing RPC dispatcher tests**

Create `src/headless/rpc.test.ts`:

```ts
import assert from 'node:assert/strict';
import test from 'node:test';

import type { HeadlessRunOutput, HeadlessRunRequest, RuntimeEventEnvelope } from './contract.js';
import { HEADLESS_EXIT_CANCELLED, HEADLESS_EXIT_SUCCESS, emptyHeadlessArtifacts } from './contract.js';
import { createRpcServer } from './rpc.js';

function parseLines(lines: string[]) {
  return lines.map((line) => JSON.parse(line));
}

function completedOutput(runId: string): HeadlessRunOutput {
  return {
    runId,
    status: 'completed',
    exitCode: HEADLESS_EXIT_SUCCESS,
    finalMessage: 'done',
    artifacts: emptyHeadlessArtifacts()
  };
}

test('rpc returns parse errors for invalid JSON lines', async () => {
  const writes: string[] = [];
  const server = createRpcServer({ writeLine: (line) => writes.push(line) });

  await server.handleLine('{bad json');

  const [response] = parseLines(writes);
  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, null);
  assert.equal(response.error.code, -32700);
});

test('rpc run.start returns a run id and emits run events with the same id', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => writes.push(line),
    makeRunId: () => 'run_rpc_1',
    async runHeadless(request: HeadlessRunRequest, options) {
      const event: RuntimeEventEnvelope = {
        schemaVersion: 1,
        eventId: 'evt_rpc_1',
        runId: options.runId!,
        timestamp: '2026-05-06T00:00:00.000Z',
        type: 'run-start',
        payload: {
          cwd: request.cwd,
          policy: request.policy ?? 'auto',
          model: { provider: 'ollama', model: 'fake' }
        }
      };
      await options.onEvent?.(event);
      return completedOutput(options.runId!);
    }
  });

  await server.handleLine(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'run.start',
      params: { cwd: process.cwd(), prompt: 'hello' }
    })
  );
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.deepEqual(messages[0], { jsonrpc: '2.0', id: 1, result: { runId: 'run_rpc_1' } });
  assert.equal(messages[1].method, 'run.event');
  assert.equal(messages[1].params.runId, 'run_rpc_1');
});

test('rpc rejects a second active run in the same process', async () => {
  const writes: string[] = [];
  let release!: () => void;
  const blocking = new Promise<void>((resolve) => {
    release = resolve;
  });
  const server = createRpcServer({
    writeLine: (line) => writes.push(line),
    makeRunId: () => `run_rpc_${writes.length}`,
    async runHeadless(_request, options) {
      await blocking;
      return completedOutput(options.runId!);
    }
  });

  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'run.start', params: { cwd: process.cwd(), prompt: 'one' } }));
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'run.start', params: { cwd: process.cwd(), prompt: 'two' } }));
  release();
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.equal(messages[1].id, 2);
  assert.equal(messages[1].error.code, -32001);
  assert.match(messages[1].error.message, /active run/i);
});

test('rpc run.cancel aborts the active run controller', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => writes.push(line),
    makeRunId: () => 'run_rpc_cancel',
    async runHeadless(_request, options) {
      await new Promise<void>((resolve) => {
        options.signal?.addEventListener('abort', () => resolve(), { once: true });
      });
      return {
        runId: options.runId!,
        status: 'cancelled',
        exitCode: HEADLESS_EXIT_CANCELLED,
        artifacts: emptyHeadlessArtifacts(),
        error: { code: 'cancelled', stage: 'cancel', message: 'run cancelled', recoverable: false }
      };
    }
  });

  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'run.start', params: { cwd: process.cwd(), prompt: 'cancel me' } }));
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'run.cancel', params: { runId: 'run_rpc_cancel' } }));
  await server.waitForIdle();

  const messages = parseLines(writes);
  assert.deepEqual(messages[1], { jsonrpc: '2.0', id: 2, result: { status: 'cancelled' } });
});
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```bash
node --test --import tsx src/headless/rpc.test.ts
```

Expected: FAIL because `src/headless/rpc.ts` does not exist.

- [ ] **Step 3: Implement the minimal RPC dispatcher**

Create `src/headless/rpc.ts` with these public exports:

```ts
import readline from 'node:readline';
import { stdin, stdout } from 'node:process';

import { makeId } from '../session/store.js';
import type { HeadlessRunOptions, HeadlessRunOutput, HeadlessRunRequest, RuntimeEventEnvelope } from './contract.js';
import { runHeadless as defaultRunHeadless } from './run.js';

type JsonRpcId = string | number | null;
type JsonRpcRequest = {
  jsonrpc: '2.0';
  id?: JsonRpcId;
  method: string;
  params?: unknown;
};

type RpcRunHeadless = (
  request: HeadlessRunRequest,
  options: HeadlessRunOptions
) => Promise<HeadlessRunOutput>;

export type RpcServerOptions = {
  writeLine: (line: string) => void | Promise<void>;
  runHeadless?: RpcRunHeadless;
  makeRunId?: () => string;
};

type ActiveRun = {
  runId: string;
  controller: AbortController;
  promise: Promise<HeadlessRunOutput>;
};

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;
const ACTIVE_RUN_ERROR = -32001;
const NOT_FOUND_ERROR = -32004;

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isRequest(value: unknown): value is JsonRpcRequest {
  return (
    isObject(value) &&
    value.jsonrpc === '2.0' &&
    typeof value.method === 'string' &&
    (value.id === undefined || typeof value.id === 'string' || typeof value.id === 'number' || value.id === null)
  );
}

function requestId(value: unknown): JsonRpcId {
  return isObject(value) && (typeof value.id === 'string' || typeof value.id === 'number' || value.id === null)
    ? value.id
    : null;
}

function errorResponse(id: JsonRpcId, code: number, message: string, data?: unknown) {
  return JSON.stringify({
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      ...(data === undefined ? {} : { data })
    }
  });
}

function resultResponse(id: JsonRpcId, result: unknown) {
  return JSON.stringify({ jsonrpc: '2.0', id, result });
}

function notification(method: string, params: unknown) {
  return JSON.stringify({ jsonrpc: '2.0', method, params });
}

function asRunRequest(params: unknown): HeadlessRunRequest | null {
  if (!isObject(params)) {
    return null;
  }
  return params as HeadlessRunRequest;
}

function asCancelParams(params: unknown): { runId: string } | null {
  return isObject(params) && typeof params.runId === 'string' ? { runId: params.runId } : null;
}

export function createRpcServer(options: RpcServerOptions) {
  const runHeadless = options.runHeadless ?? defaultRunHeadless;
  const makeRunId = options.makeRunId ?? (() => makeId('run'));
  let activeRun: ActiveRun | undefined;
  const finishedRuns = new Set<string>();

  async function write(value: string) {
    await options.writeLine(value);
  }

  async function emitEvent(event: RuntimeEventEnvelope) {
    await write(notification('run.event', event));
  }

  async function handleRunStart(id: JsonRpcId, params: unknown) {
    const request = asRunRequest(params);
    if (!request) {
      await write(errorResponse(id, INVALID_PARAMS, 'run.start params must be a HeadlessRunRequest object'));
      return;
    }
    if (activeRun) {
      await write(errorResponse(id, ACTIVE_RUN_ERROR, `active run already exists: ${activeRun.runId}`, { runId: activeRun.runId }));
      return;
    }

    const runId = makeRunId();
    const controller = new AbortController();
    const promise = Promise.resolve()
      .then(() =>
        runHeadless(request, {
          runId,
          signal: controller.signal,
          onEvent: emitEvent
        })
      )
      .finally(() => {
        finishedRuns.add(runId);
        if (activeRun?.runId === runId) {
          activeRun = undefined;
        }
      });

    activeRun = { runId, controller, promise };
    await write(resultResponse(id, { runId }));
  }

  async function handleRunCancel(id: JsonRpcId, params: unknown) {
    const parsed = asCancelParams(params);
    if (!parsed) {
      await write(errorResponse(id, INVALID_PARAMS, 'run.cancel params must include runId'));
      return;
    }
    if (activeRun?.runId === parsed.runId) {
      activeRun.controller.abort();
      await write(resultResponse(id, { status: 'cancelled' }));
      return;
    }
    if (finishedRuns.has(parsed.runId)) {
      await write(resultResponse(id, { status: 'already-finished' }));
      return;
    }
    await write(resultResponse(id, { status: 'not-found' }));
  }

  async function handleRequest(request: JsonRpcRequest) {
    const id = request.id ?? null;
    if (request.method === 'run.start') {
      await handleRunStart(id, request.params);
      return;
    }
    if (request.method === 'run.cancel') {
      await handleRunCancel(id, request.params);
      return;
    }
    await write(errorResponse(id, METHOD_NOT_FOUND, `method not found: ${request.method}`));
  }

  return {
    async handleLine(line: string) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        await write(errorResponse(null, PARSE_ERROR, 'parse error'));
        return;
      }

      if (!isRequest(parsed)) {
        await write(errorResponse(requestId(parsed), INVALID_REQUEST, 'invalid JSON-RPC request'));
        return;
      }

      try {
        await handleRequest(parsed);
      } catch (error) {
        await write(errorResponse(parsed.id ?? null, INTERNAL_ERROR, error instanceof Error ? error.message : String(error)));
      }
    },

    async waitForIdle() {
      await activeRun?.promise;
    }
  };
}

export async function runStdioJsonRpcServer() {
  const server = createRpcServer({
    writeLine(line) {
      stdout.write(`${line}\n`);
    }
  });
  const rl = readline.createInterface({ input: stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) {
      continue;
    }
    await server.handleLine(line);
  }
  await server.waitForIdle();
}
```

- [ ] **Step 4: Verify dispatcher tests pass**

Run:

```bash
node --test --import tsx src/headless/rpc.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/headless/rpc.ts src/headless/rpc.test.ts
git commit -m "feat: add stdio rpc run controller"
```

---

### Task 4: RPC Session And Artifact Methods

**Files:**
- Modify: `src/headless/rpc.ts`
- Test: `src/headless/rpc.test.ts`

- [ ] **Step 1: Add failing tests for `session.get` and `artifact.get`**

Append to `src/headless/rpc.test.ts`:

```ts
test('rpc session.get returns a stable session view', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => writes.push(line),
    async getSessionView(cwd, sessionId) {
      return {
        id: sessionId ?? 'sess_active',
        cwd,
        model: { provider: 'ollama', model: 'fake' },
        lifecycle: { status: 'idle', turn: 0 },
        records: [],
        checkpoints: [],
        compactions: []
      };
    }
  });

  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'session.get', params: { cwd: '/tmp/project', sessionId: 'sess_1' } }));

  const [response] = parseLines(writes);
  assert.equal(response.result.id, 'sess_1');
  assert.equal(response.result.cwd, '/tmp/project');
});

test('rpc artifact.get returns a stable artifact view', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => writes.push(line),
    async getArtifactView(cwd, artifactId, sessionId) {
      assert.equal(cwd, '/tmp/project');
      assert.equal(sessionId, 'sess_1');
      return {
        kind: 'compaction',
        compaction: {
          id: artifactId,
          status: 'active',
          createdAt: '2026-05-06T00:00:00.000Z',
          coveredRange: { startIndexInclusive: 0, endIndexExclusive: 1 },
          firstKeptRecordId: 'usr_1',
          createdBy: { provider: 'ollama', model: 'fake' },
          summaryMarkdown: 'summary'
        }
      };
    }
  });

  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'artifact.get', params: { cwd: '/tmp/project', sessionId: 'sess_1', artifactId: 'cmp_1' } }));

  const [response] = parseLines(writes);
  assert.equal(response.result.kind, 'compaction');
  assert.equal(response.result.compaction.id, 'cmp_1');
});

test('rpc query methods map missing artifacts to application errors', async () => {
  const writes: string[] = [];
  const server = createRpcServer({
    writeLine: (line) => writes.push(line),
    async getArtifactView() {
      throw new Error('artifact not found: cmp_missing');
    }
  });

  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'artifact.get', params: { cwd: '/tmp/project', artifactId: 'cmp_missing' } }));

  const [response] = parseLines(writes);
  assert.equal(response.error.code, -32004);
  assert.match(response.error.message, /artifact not found/);
});
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
node --test --import tsx src/headless/rpc.test.ts --test-name-pattern "session.get|artifact.get"
```

Expected: FAIL because the RPC server options and methods are not implemented.

- [ ] **Step 3: Add query dependencies to RPC options**

In `src/headless/rpc.ts`, add imports:

```ts
import type { ArtifactView, SessionView } from './contract.js';
import { getArtifactViewForRequest, getSessionView as defaultGetSessionView } from './artifacts.js';
```

Update `RpcServerOptions`:

```ts
export type RpcServerOptions = {
  writeLine: (line: string) => void | Promise<void>;
  runHeadless?: RpcRunHeadless;
  makeRunId?: () => string;
  getSessionView?: (cwd: string, sessionId?: string) => Promise<SessionView>;
  getArtifactView?: (cwd: string, artifactId: string, sessionId?: string) => Promise<ArtifactView>;
};
```

Inside `createRpcServer`, add:

```ts
const getSessionView = options.getSessionView ?? defaultGetSessionView;
const getArtifactView = options.getArtifactView ?? getArtifactViewForRequest;
```

- [ ] **Step 4: Add param validators and handlers**

In `src/headless/rpc.ts`, add:

```ts
function asSessionGetParams(params: unknown): { cwd: string; sessionId?: string } | null {
  if (!isObject(params) || typeof params.cwd !== 'string') {
    return null;
  }
  if (params.sessionId !== undefined && typeof params.sessionId !== 'string') {
    return null;
  }
  return { cwd: params.cwd, ...(params.sessionId ? { sessionId: params.sessionId } : {}) };
}

function asArtifactGetParams(params: unknown): { cwd: string; artifactId: string; sessionId?: string } | null {
  if (!isObject(params) || typeof params.cwd !== 'string' || typeof params.artifactId !== 'string') {
    return null;
  }
  if (params.sessionId !== undefined && typeof params.sessionId !== 'string') {
    return null;
  }
  return {
    cwd: params.cwd,
    artifactId: params.artifactId,
    ...(params.sessionId ? { sessionId: params.sessionId } : {})
  };
}

function isNotFoundError(error: unknown) {
  return error instanceof Error && /\b(session|artifact) not found\b/i.test(error.message);
}
```

Add handlers:

```ts
async function handleSessionGet(id: JsonRpcId, params: unknown) {
  const parsed = asSessionGetParams(params);
  if (!parsed) {
    await write(errorResponse(id, INVALID_PARAMS, 'session.get params must include cwd and optional sessionId'));
    return;
  }
  try {
    await write(resultResponse(id, await getSessionView(parsed.cwd, parsed.sessionId)));
  } catch (error) {
    if (isNotFoundError(error)) {
      await write(errorResponse(id, NOT_FOUND_ERROR, error instanceof Error ? error.message : String(error)));
      return;
    }
    throw error;
  }
}

async function handleArtifactGet(id: JsonRpcId, params: unknown) {
  const parsed = asArtifactGetParams(params);
  if (!parsed) {
    await write(errorResponse(id, INVALID_PARAMS, 'artifact.get params must include cwd, artifactId, and optional sessionId'));
    return;
  }
  try {
    await write(resultResponse(id, await getArtifactView(parsed.cwd, parsed.artifactId, parsed.sessionId)));
  } catch (error) {
    if (isNotFoundError(error)) {
      await write(errorResponse(id, NOT_FOUND_ERROR, error instanceof Error ? error.message : String(error)));
      return;
    }
    throw error;
  }
}
```

Then update `handleRequest`:

```ts
if (request.method === 'session.get') {
  await handleSessionGet(id, request.params);
  return;
}
if (request.method === 'artifact.get') {
  await handleArtifactGet(id, request.params);
  return;
}
```

- [ ] **Step 5: Verify focused tests pass**

Run:

```bash
node --test --import tsx src/headless/rpc.test.ts --test-name-pattern "session.get|artifact.get"
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/headless/rpc.ts src/headless/rpc.test.ts
git commit -m "feat: add rpc artifact query methods"
```

---

### Task 5: CLI Entry Point

**Files:**
- Modify: `src/cli.ts`
- Test: `src/cli.test.ts`

- [ ] **Step 1: Add failing CLI parse/help tests**

Append to `src/cli.test.ts` near the existing `printHelp documents aliases, policy modes, skills, and streaming` test:

```ts
test('parseArgs accepts rpc command', () => {
  assert.deepEqual(parseArgs(['node', 'cliq', 'rpc']), {
    cmd: 'rpc',
    policy: 'auto',
    skills: [],
    model: {}
  });
});

test('printHelp documents rpc command', () => {
  const previousLog = console.log;
  let output = '';
  console.log = (value?: unknown) => {
    output += String(value);
  };

  try {
    printHelp();
  } finally {
    console.log = previousLog;
  }

  assert.match(output, /cliq rpc\s+Start stdio JSON-RPC mode/);
});
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
node --test --import tsx src/cli.test.ts --test-name-pattern "rpc"
```

Expected: FAIL because `rpc` is not parsed or documented.

- [ ] **Step 3: Add `rpc` to CLI parsing**

In `src/cli.ts`, import:

```ts
import { runStdioJsonRpcServer } from './headless/rpc.js';
```

Update `ParsedArgs`:

```ts
| { cmd: 'reset' | 'history' | 'rpc'; prompt?: undefined }
```

Update `isKnownCommand`:

```ts
cmd === 'rpc' ||
```

Update `parseArgs`:

```ts
if (cmd === 'rpc') {
  ensureNoExtraArgs(args, 1, 'rpc');
  return { cmd, policy, skills, model };
}
```

- [ ] **Step 4: Add help and runtime branch**

In `printHelp`, add this usage line:

```text
  cliq rpc                 Start stdio JSON-RPC mode
```

In the options or notes area, add:

```text
RPC:
  cliq rpc                 Reads newline-delimited JSON-RPC 2.0 requests from stdin and writes protocol messages to stdout
```

In `runCli`, add after the `history` branch:

```ts
if (cmd === 'rpc') {
  await runStdioJsonRpcServer();
  return;
}
```

- [ ] **Step 5: Verify focused tests pass**

Run:

```bash
node --test --import tsx src/cli.test.ts --test-name-pattern "rpc"
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts src/cli.test.ts
git commit -m "feat: expose rpc cli command"
```

---

### Task 6: End-To-End RPC Smoke And Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-05-03-phase4-headless-runtime-interfaces-design.md`

- [ ] **Step 1: Run full test and build before docs**

Run:

```bash
npm run build
npm test
```

Expected: build succeeds and all tests pass.

- [ ] **Step 2: Run an RPC smoke test against the built CLI**

Run:

```bash
tmp_home=$(mktemp -d)
out=$(mktemp)
err=$(mktemp)
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"run.start","params":{"cwd":"'"$PWD"'","prompt":"hello","model":{"provider":"openai-compatible","model":"fake","baseUrl":"http://127.0.0.1:59999/v1"},"policy":"read-only"}}' \
  | CLIQ_HOME="$tmp_home" node dist/index.js rpc >"$out" 2>"$err" || true
node - "$out" "$err" <<'NODE'
const fs = require('fs');
const [outPath, errPath] = process.argv.slice(2);
const stderr = fs.readFileSync(errPath, 'utf8');
if (stderr.trim() !== '') throw new Error(`expected empty stderr, got ${JSON.stringify(stderr)}`);
const messages = fs.readFileSync(outPath, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
if (messages[0]?.result?.runId === undefined) throw new Error('first message must be run.start response with runId');
if (!messages.some((message) => message.method === 'run.event' && message.params.type === 'run-end')) throw new Error('missing run-end notification');
console.log(JSON.stringify({messageCount: messages.length, runId: messages[0].result.runId}, null, 2));
NODE
rm -rf "$tmp_home" "$out" "$err"
```

Expected: command prints a JSON object with `messageCount` and `runId`; stderr is empty.

- [ ] **Step 3: Update README**

Add a section near the JSONL headless run docs:

````md
### Stdio JSON-RPC

`cliq rpc` starts a newline-delimited JSON-RPC 2.0 server over stdio. It is intended for local GUI, gateway, automation, and future subagent orchestrators that need to start runs, subscribe to events, cancel work, and query stable artifacts without scraping terminal output.

Initial methods:

```text
run.start(params: HeadlessRunRequest) -> { runId }
run.cancel(params: { runId: string }) -> { status: 'cancelled' | 'not-found' | 'already-finished' }
session.get(params: { cwd: string; sessionId?: string }) -> SessionView
artifact.get(params: { cwd: string; artifactId: string; sessionId?: string }) -> ArtifactView
```

Runtime events are emitted as notifications:

```json
{"jsonrpc":"2.0","method":"run.event","params":{"schemaVersion":1,"eventId":"evt_...","runId":"run_...","timestamp":"...","type":"run-start","payload":{}}}
```

The first version allows one active run per `cliq rpc` process. The public protocol still carries `runId` on events so future orchestrators can run multiple Cliq workers or migrate to a multi-run process without changing event consumers.
````

- [ ] **Step 4: Update Phase 4 spec**

In `docs/superpowers/specs/2026-05-03-phase4-headless-runtime-interfaces-design.md`, update the RPC section so the method list exactly matches the implemented v1:

```text
run.start(params: HeadlessRunRequest) -> { runId }
run.cancel(params: { runId: string }) -> { status: 'cancelled' | 'not-found' | 'already-finished' }
session.get(params: { cwd: string; sessionId?: string }) -> SessionView
artifact.get(params: { cwd: string; artifactId: string; sessionId?: string }) -> ArtifactView
```

Add this paragraph after the concurrency rule:

```md
The one-active-run limit is a process-level v1 constraint, not a public event-contract constraint. Every event and terminal output keeps `runId` so a future subagent orchestrator can launch multiple `cliq rpc` workers or a later multi-run server without changing event consumers.
```

- [ ] **Step 5: Run final verification**

Run:

```bash
npm run build
npm test
git diff --check
```

Expected: build succeeds, all tests pass, and `git diff --check` prints no output.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/superpowers/specs/2026-05-03-phase4-headless-runtime-interfaces-design.md
git commit -m "docs: document stdio rpc protocol"
```

---

## Acceptance Checklist

- [ ] `runHeadless` can use an externally supplied `runId`.
- [ ] `cliq rpc` speaks newline-delimited JSON-RPC 2.0 over stdio.
- [ ] `run.start` responds immediately with `{ runId }`.
- [ ] Runtime events are emitted as `run.event` notifications.
- [ ] `run.cancel` aborts the active run through `AbortController`.
- [ ] One active run per process is enforced with a structured JSON-RPC error.
- [ ] `session.get` returns stable `SessionView` without exposing `CLIQ_HOME`.
- [ ] `artifact.get` returns stable `ArtifactView` without exposing internal storage paths.
- [ ] Human terminal text is not written to stdout during RPC mode.
- [ ] Future subagent orchestration can use `runId`, events, cancellation, and artifact queries without changing the RPC event contract.

## Out Of Scope

- No subagent scheduler.
- No multi-active-run process.
- No daemon lifecycle.
- No HTTP or socket server.
- No auth or remote access.
- No cost/token governance.
- No rich TUI or GUI implementation.

## Final Verification Commands

```bash
npm run build
npm test
npm pack --dry-run
```

Expected:

- TypeScript build succeeds.
- All `node:test` tests pass.
- Package dry-run includes `dist/headless/rpc.js` and does not include test files.
