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
    {
      cwd,
      prompt: 'say done',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
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

test('runHeadless uses the intended turn for post-session setup failures', async () => {
  const { cwd } = await setupWorkspace();
  const events: Array<{ type: string; turn?: number }> = [];
  let failedRunStart = false;

  const output = await runHeadless(
    {
      cwd,
      prompt: 'say done',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    {
      modelClient: finalModel('done'),
      onEvent(event) {
        events.push({ type: event.type, turn: event.turn });
        if (event.type === 'run-start' && !failedRunStart) {
          failedRunStart = true;
          throw new Error('event sink failed');
        }
      }
    }
  );

  assert.equal(output.status, 'failed');
  assert.equal(output.turn, 1);
  assert.deepEqual(events, [
    { type: 'run-start', turn: 1 },
    { type: 'error', turn: 1 },
    { type: 'run-end', turn: 1 }
  ]);
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

test('runHeadless maps invalid model config to config-error', async () => {
  const { cwd } = await setupWorkspace();

  const output = await runHeadless(
    { cwd, prompt: 'say done', model: { provider: 'missing-provider' } },
    { modelClient: finalModel('done') }
  );

  assert.equal(output.status, 'failed');
  assert.equal(output.error?.code, 'config-error');
  assert.equal(output.error?.stage, 'assembly');
  assert.equal(output.error?.recoverable, true);
});

test('runHeadless maps missing model credentials to model-auth-error', async () => {
  const { cwd } = await setupWorkspace();
  const previousOpenRouterKey = process.env.OPENROUTER_API_KEY;
  delete process.env.OPENROUTER_API_KEY;

  try {
    const output = await runHeadless(
      { cwd, prompt: 'say done', model: { provider: 'openrouter', model: 'test-model', streaming: 'off' } },
      { modelClient: finalModel('done') }
    );

    assert.equal(output.status, 'failed');
    assert.equal(output.error?.code, 'model-auth-error');
    assert.equal(output.error?.stage, 'assembly');
    assert.equal(output.error?.recoverable, true);
  } finally {
    if (previousOpenRouterKey === undefined) {
      delete process.env.OPENROUTER_API_KEY;
    } else {
      process.env.OPENROUTER_API_KEY = previousOpenRouterKey;
    }
  }
});

test('runHeadless maps explicit abort errors to cancellation', async () => {
  const { cwd } = await setupWorkspace();

  const output = await runHeadless(
    { cwd, prompt: 'say done', model: { provider: 'ollama', model: 'test-model' }, autoCompact: { enabled: 'off' } },
    {
      createModelClient() {
        const error = new Error('transport aborted');
        error.name = 'AbortError';
        throw error;
      }
    }
  );

  assert.equal(output.status, 'cancelled');
  assert.equal(output.exitCode, 130);
  assert.equal(output.error?.code, 'cancelled');
  assert.equal(output.error?.stage, 'cancel');
});

test('runHeadless does not classify arbitrary cancelled text as cancellation', async () => {
  const { cwd } = await setupWorkspace();
  let threw = false;

  const output = await runHeadless(
    {
      cwd,
      prompt: 'say done',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    {
      modelClient: finalModel('done'),
      onEvent() {
        if (!threw) {
          threw = true;
          throw new Error('logger cancelled write');
        }
      }
    }
  );

  assert.equal(output.status, 'failed');
  assert.equal(output.exitCode, 1);
  assert.equal(output.error?.code, 'internal-error');
  assert.equal(output.error?.stage, 'assembly');
});
