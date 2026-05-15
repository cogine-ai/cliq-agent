import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import type { ModelClient } from '../model/types.js';
import type { RuntimeEventEnvelope } from './contract.js';
import { runHeadless } from './run.js';

const previousHome = process.env.CLIQ_HOME;
const previousTrustWorkspace = process.env.CLIQ_TRUST_WORKSPACE;
const cleanupDirs: string[] = [];

test.after(async () => {
  if (previousHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = previousHome;
  }
  if (previousTrustWorkspace === undefined) {
    delete process.env.CLIQ_TRUST_WORKSPACE;
  } else {
    process.env.CLIQ_TRUST_WORKSPACE = previousTrustWorkspace;
  }
  await Promise.all(cleanupDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function setupWorkspace() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-run-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-run-workspace-'));
  cleanupDirs.push(home, cwd);
  process.env.CLIQ_HOME = home;
  process.env.CLIQ_TRUST_WORKSPACE = 'trust';
  return { home, cwd };
}

function commandFor(scriptPath: string): string {
  return `${JSON.stringify(process.execPath)} ${JSON.stringify(scriptPath)}`;
}

async function writeWorkspaceHook(cwd: string, name: string, source: string) {
  const hooksDir = path.join(cwd, '.cliq', 'hooks');
  await mkdir(hooksDir, { recursive: true });
  const scriptPath = path.join(hooksDir, name);
  await writeFile(scriptPath, source, 'utf8');
  return commandFor(scriptPath);
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

test('runHeadless refuses non-interactive runs without persisted workspace trust', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-no-trust-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-no-trust-ws-'));
  cleanupDirs.push(home, cwd);
  process.env.CLIQ_HOME = home;
  delete process.env.CLIQ_TRUST_WORKSPACE;

  const output = await runHeadless(
    {
      cwd,
      prompt: 'never runs',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('ignored') }
  );

  assert.equal(output.status, 'failed');
  assert.ok(output.error);
  assert.match(output.error!.message, /CLIQ_TRUST_WORKSPACE=/);
});

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

test('runHeadless runs workspace SessionStart command hooks before the model turn', async () => {
  const { cwd } = await setupWorkspace();
  const markerPath = path.join(cwd, 'session-start.json');
  const command = await writeWorkspaceHook(
    cwd,
    'session-start.js',
    `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  require('node:fs').writeFileSync(${JSON.stringify(markerPath)}, JSON.stringify({
    hookEventName: parsed.hookEventName,
    sessionId: parsed.sessionId,
    cwd: parsed.cwd
  }));
});
`
  );
  await writeFile(
    path.join(cwd, '.cliq', 'config.json'),
    JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command }] }] } }),
    'utf8'
  );
  let modelSawSessionStart = false;

  const output = await runHeadless(
    {
      cwd,
      prompt: 'say done',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    {
      modelClient: {
        async complete(_messages, options) {
          modelSawSessionStart = JSON.parse(await readFile(markerPath, 'utf8')).hookEventName === 'SessionStart';
          await options?.onEvent?.({ type: 'start', provider: 'ollama', model: 'test-model', streaming: false });
          await options?.onEvent?.({ type: 'end' });
          return { provider: 'ollama', model: 'test-model', content: JSON.stringify({ message: 'done' }) };
        }
      }
    }
  );
  const marker = JSON.parse(await readFile(markerPath, 'utf8')) as {
    hookEventName: string;
    sessionId: string;
    cwd: string;
  };

  assert.equal(output.status, 'completed');
  assert.equal(modelSawSessionStart, true);
  assert.equal(marker.hookEventName, 'SessionStart');
  assert.equal(typeof marker.sessionId, 'string');
  assert.equal(marker.cwd, cwd);
});

test('runHeadless fails closed for required SessionStart infrastructure errors before model execution', async () => {
  const { cwd } = await setupWorkspace();
  const command = await writeWorkspaceHook(
    cwd,
    'required-session-start.js',
    `process.stderr.write('session start hook crashed'); process.exit(9);`
  );
  await writeFile(
    path.join(cwd, '.cliq', 'config.json'),
    JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command, required: true }] }] } }),
    'utf8'
  );
  let modelCalls = 0;

  const output = await runHeadless(
    {
      cwd,
      prompt: 'say done',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    {
      modelClient: {
        async complete() {
          modelCalls += 1;
          return { provider: 'ollama', model: 'test-model', content: JSON.stringify({ message: 'done' }) };
        }
      }
    }
  );

  assert.equal(output.status, 'failed');
  assert.equal(modelCalls, 0);
  assert.match(output.error?.message ?? '', /required SessionStart hook failed/i);
  assert.match(output.error?.message ?? '', /session start hook crashed/i);
});

test('runHeadless passes workspace PreToolUse command hooks into the runner path', async () => {
  const { cwd } = await setupWorkspace();
  const hookInputPath = path.join(cwd, 'pre-tool-use.json');
  const command = await writeWorkspaceHook(
    cwd,
    'pre-tool-use.js',
    `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  require('node:fs').writeFileSync(${JSON.stringify(hookInputPath)}, JSON.stringify({
    hookEventName: parsed.hookEventName,
    toolName: parsed.toolName,
    action: parsed.action
  }));
});
`
  );
  await writeFile(
    path.join(cwd, '.cliq', 'config.json'),
    JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'bash', hooks: [{ type: 'command', command }] }] } }),
    'utf8'
  );
  let calls = 0;

  const output = await runHeadless(
    {
      cwd,
      prompt: 'show cwd',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    {
      modelClient: {
        async complete(_messages, options) {
          calls += 1;
          await options?.onEvent?.({ type: 'start', provider: 'ollama', model: 'test-model', streaming: false });
          await options?.onEvent?.({ type: 'end' });
          return {
            provider: 'ollama',
            model: 'test-model',
            content: calls === 1 ? JSON.stringify({ bash: 'pwd' }) : JSON.stringify({ message: 'done' })
          };
        }
      }
    }
  );
  const hookInput = JSON.parse(await readFile(hookInputPath, 'utf8')) as {
    hookEventName: string;
    toolName: string;
    action: { bash: string };
  };

  assert.equal(output.status, 'completed');
  assert.equal(hookInput.hookEventName, 'PreToolUse');
  assert.equal(hookInput.toolName, 'bash');
  assert.deepEqual(hookInput.action, { bash: 'pwd' });
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
