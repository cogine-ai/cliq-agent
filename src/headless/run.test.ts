import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
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

function bashLoopModel(): ModelClient {
  return {
    async complete() {
      return { provider: 'ollama', model: 'test-model', content: JSON.stringify({ bash: 'pwd' }) };
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

test('runHeadless rejects legacy policy tokens with migration guidance', async () => {
  const { cwd } = await setupWorkspace();
  const output = await runHeadless(
    {
      cwd,
      prompt: 'inspect',
      policy: 'read-only' as never,
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('ignored') }
  );

  assert.equal(output.status, 'failed');
  assert.equal(output.error?.stage, 'input');
  assert.match(output.error?.message ?? '', /read-only has been replaced by plan/i);
});

test('runHeadless checks workspace trust before loading skill configuration', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-skill-trust-home-'));
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-headless-skill-trust-ws-'));
  cleanupDirs.push(home, cwd);
  process.env.CLIQ_HOME = home;
  delete process.env.CLIQ_TRUST_WORKSPACE;
  await mkdir(path.join(cwd, '.cliq'), { recursive: true });
  await writeFile(path.join(cwd, '.cliq', 'config.json'), '{bad json', 'utf8');
  await mkdir(path.join(cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
  await writeFile(
    path.join(cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
    `---
name: reviewer
description: should not be read before trust
---

Do not load this before trust.`,
    'utf8'
  );

  const output = await runHeadless(
    {
      cwd,
      prompt: 'never runs',
      model: { provider: 'ollama', model: 'test-model' },
      skills: ['reviewer'],
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('ignored') }
  );

  assert.equal(output.status, 'failed');
  assert.ok(output.error);
  assert.match(output.error!.message, /CLIQ_TRUST_WORKSPACE=/);
  assert.doesNotMatch(output.error!.message, /bad json|reviewer/i);
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

test('runHeadless rejects invalid maxTurns before starting a session', async () => {
  const { cwd } = await setupWorkspace();

  for (const maxTurns of [0, -1, 1.5] as const) {
    const output = await runHeadless(
      {
        cwd,
        prompt: 'loop',
        model: { provider: 'ollama', model: 'test-model' },
        autoCompact: { enabled: 'off' },
        maxTurns
      },
      { modelClient: finalModel('ignored') }
    );

    assert.equal(output.status, 'failed');
    assert.equal(output.error?.code, 'invalid-input');
    assert.equal(output.error?.stage, 'input');
    assert.match(output.error?.message ?? '', /maxTurns must be a positive integer/);
    assert.equal(output.sessionId, undefined);
    assert.equal(output.turn, undefined);
  }
});

test('runHeadless passes request maxTurns into the runner', async () => {
  const { cwd } = await setupWorkspace();
  const events: RuntimeEventEnvelope[] = [];

  const output = await runHeadless(
    {
      cwd,
      prompt: 'loop',
      policy: 'yolo',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' },
      maxTurns: 2
    },
    {
      modelClient: bashLoopModel(),
      onEvent(event) {
        events.push(event);
      }
    }
  );

  assert.equal(output.status, 'failed');
  assert.equal(output.error?.stage, 'model');
  assert.match(output.error?.message ?? '', /Exceeded max turns \(2\)/);
  assert.equal(events.at(-1)?.type, 'run-end');
});

test('runHeadless creates a fresh session by default even when the workspace has an active session', async () => {
  const { cwd } = await setupWorkspace();

  const first = await runHeadless(
    {
      cwd,
      prompt: 'first',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('first done') }
  );
  const second = await runHeadless(
    {
      cwd,
      prompt: 'second',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('second done') }
  );

  assert.equal(first.status, 'completed');
  assert.equal(second.status, 'completed');
  assert.notEqual(second.sessionId, first.sessionId);
});

test('runHeadless resumes an existing session only when explicitly requested', async () => {
  const { cwd } = await setupWorkspace();

  const first = await runHeadless(
    {
      cwd,
      prompt: 'first',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('first done') }
  );
  assert.equal(first.status, 'completed');
  assert.ok(first.sessionId);

  const active = await runHeadless(
    {
      cwd,
      prompt: 'active',
      model: { provider: 'ollama', model: 'test-model' },
      session: { mode: 'active' },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('active done') }
  );
  const byId = await runHeadless(
    {
      cwd,
      prompt: 'by id',
      model: { provider: 'ollama', model: 'test-model' },
      session: { id: first.sessionId },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('id done') }
  );

  assert.equal(active.status, 'completed');
  assert.equal(byId.status, 'completed');
  assert.equal(active.sessionId, first.sessionId);
  assert.equal(byId.sessionId, first.sessionId);
});

test('runHeadless does not require local auth when request model config is explicit', async () => {
  const { home, cwd } = await setupWorkspace();
  await writeFile(path.join(home, 'auth.json'), '{bad json', 'utf8');

  const output = await runHeadless(
    {
      cwd,
      prompt: 'say done',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    { modelClient: finalModel('done') }
  );

  assert.equal(output.status, 'completed');
  assert.equal(output.exitCode, 0);
  assert.equal(output.finalMessage, 'done');
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

test('runHeadless falls back to workspace permissions.preset when request.policy is omitted (#62-B)', async () => {
  // Regression for PR #91 Codex finding "Honor workspace permissions.preset
  // at runtime". With request.policy undefined and workspace config setting
  // permissions.preset='plan', a model-issued edit must be denied by
  // the PolicyEngine. Without the fallback the run would happily execute
  // the edit under the global DEFAULT_POLICY_MODE.
  const { cwd } = await setupWorkspace();
  await mkdir(path.join(cwd, '.cliq'), { recursive: true });
  await writeFile(
    path.join(cwd, '.cliq', 'config.json'),
    JSON.stringify({ permissions: { preset: 'plan' } }),
    'utf8'
  );
  let calls = 0;
  const toolEndStatuses: string[] = [];
  const errorEvents: string[] = [];
  const output = await runHeadless(
    {
      cwd,
      prompt: 'edit README.md',
      // policy is intentionally omitted so workspace preset takes over.
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
            content:
              calls === 1
                ? JSON.stringify({ edit: { path: 'README.md', old_text: 'a', new_text: 'b' } })
                : JSON.stringify({ message: 'gave up' })
          };
        }
      },
      onEvent(event) {
        if (event.type === 'tool-end') {
          toolEndStatuses.push(event.payload.status);
        }
        if (event.type === 'error') {
          errorEvents.push(JSON.stringify(event.payload));
        }
      }
    }
  );

  assert.equal(output.status, 'failed', 'plan mode cannot complete with a final message after denying the edit');
  assert.match(output.error?.message ?? '', /Plan Mode requires a plan artifact/);
  // PolicyEngine deny under plan surfaces as a tool-end with status
  // 'error'. Without the workspace preset fallback the edit would run
  // cleanly and tool-end.status would be 'ok'.
  assert.ok(
    toolEndStatuses.includes('error'),
    'edit must be denied by PolicyEngine when workspace preset=plan; tool-end statuses=' +
      JSON.stringify(toolEndStatuses) +
      ' errors=' +
      JSON.stringify(errorEvents)
  );
});

test('runHeadless coerces hook scope to "once" and never persists permissions.json (#62-B headless safety)', async () => {
  // Even when a PermissionRequest hook tries to return scope='workspace',
  // the headless path must treat the decision as one-shot and must NOT
  // write to ~/.cliq/workspaces/<id>/permissions.json. Persisting from a
  // non-interactive run would let unattended CI quietly accumulate
  // "always allow" rules that survive forever — exactly the foot-gun
  // the TUI's deliberate Shift+W gating guards against.
  //
  // We exercise the SAME bash action twice in one run so that "one-shot"
  // (scope='once') has a chance to fail visibly: if headless mistakenly
  // honored the workspace scope, the hook would be skipped the second
  // time. The hook writes a counter to disk to record how many times it
  // ran; we assert it ran twice.
  const { home, cwd } = await setupWorkspace();
  const hookCounterPath = path.join(cwd, 'permission-hook-calls');
  const command = await writeWorkspaceHook(
    cwd,
    'workspace-scope-allow.js',
    `const fs = require('node:fs');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  // Bump a counter file so the test can confirm the hook participated
  // in BOTH decisions. If 'once' were silently upgraded to 'workspace'
  // the second turn would skip the hook and the counter would stay at 1.
  let prev = 0;
  try {
    prev = parseInt(fs.readFileSync(${JSON.stringify(hookCounterPath)}, 'utf8'), 10) || 0;
  } catch {}
  fs.writeFileSync(${JSON.stringify(hookCounterPath)}, String(prev + 1));
  process.stdout.write(JSON.stringify({
    permissionDecision: {
      behavior: 'allow',
      message: 'workspace-scope ask',
      scope: 'workspace'
    }
  }));
});
`
  );
  await writeFile(
    path.join(cwd, '.cliq', 'config.json'),
    JSON.stringify({
      hooks: {
        PermissionRequest: [{ matcher: 'bash', hooks: [{ type: 'command', command }] }]
      }
    }),
    'utf8'
  );
  let calls = 0;
  const output = await runHeadless(
    {
      cwd,
      prompt: 'show cwd',
      policy: 'accept-edits',
      model: { provider: 'ollama', model: 'test-model' },
      autoCompact: { enabled: 'off' }
    },
    {
      modelClient: {
        async complete(_messages, options) {
          calls += 1;
          await options?.onEvent?.({ type: 'start', provider: 'ollama', model: 'test-model', streaming: false });
          await options?.onEvent?.({ type: 'end' });
          // Emit `bash: pwd` on the first AND second turn so the
          // PermissionRequest hook is asked twice. Anything else would
          // let a "session was silently upgraded to workspace" regression
          // slip through.
          if (calls === 1 || calls === 2) {
            return {
              provider: 'ollama',
              model: 'test-model',
              content: JSON.stringify({ bash: 'pwd' })
            };
          }
          return {
            provider: 'ollama',
            model: 'test-model',
            content: JSON.stringify({ message: 'done' })
          };
        }
      }
    }
  );

  assert.equal(output.status, 'completed', 'turn must complete; hook allow was honored');

  const hookCalls = parseInt(await readFile(hookCounterPath, 'utf8'), 10);
  assert.equal(
    hookCalls,
    2,
    `PermissionRequest hook must run for each bash invocation under scope='once'; observed ${hookCalls}`
  );

  // Walk the cliqHome workspace dir; no permissions.json must have been
  // written. Iterate workspace ids because the headless path derives one
  // from realpath(cwd).
  const workspacesDir = path.join(home, 'workspaces');
  let leaked = false;
  try {
    const entries = await readdir(workspacesDir);
    for (const id of entries) {
      try {
        await access(path.join(workspacesDir, id, 'permissions.json'));
        leaked = true;
        break;
      } catch {
        // file not found → expected
      }
    }
  } catch {
    // workspacesDir missing → trivially compliant
  }
  assert.equal(leaked, false, 'headless must not persist permissions.json');
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
    { cwd, prompt: 'say done', session: { mode: 'active', unknown: 'sess_1' } as never },
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

test('runHeadless maps first-run missing model setup to config-error guidance', async () => {
  const { cwd } = await setupWorkspace();
  const previousProvider = process.env.CLIQ_MODEL_PROVIDER;
  const previousModel = process.env.CLIQ_MODEL;
  const previousBaseUrl = process.env.CLIQ_MODEL_BASE_URL;
  const previousStreaming = process.env.CLIQ_MODEL_STREAMING;
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ models: [] }));

  delete process.env.CLIQ_MODEL_PROVIDER;
  delete process.env.CLIQ_MODEL;
  delete process.env.CLIQ_MODEL_BASE_URL;
  delete process.env.CLIQ_MODEL_STREAMING;

  try {
    const output = await runHeadless(
      { cwd, prompt: 'say done', autoCompact: { enabled: 'off' } },
      { modelClient: finalModel('done') }
    );

    assert.equal(output.status, 'failed');
    assert.equal(output.error?.code, 'config-error');
    assert.equal(output.error?.stage, 'assembly');
    assert.equal(output.error?.recoverable, true);
    assert.match(output.error?.message ?? '', /Cliq needs a model provider before chat can start/i);
    assert.match(output.error?.message ?? '', /ollama pull qwen3\.5:4b/);
  } finally {
    fetchMock.mock.restore();
    if (previousProvider === undefined) delete process.env.CLIQ_MODEL_PROVIDER;
    else process.env.CLIQ_MODEL_PROVIDER = previousProvider;
    if (previousModel === undefined) delete process.env.CLIQ_MODEL;
    else process.env.CLIQ_MODEL = previousModel;
    if (previousBaseUrl === undefined) delete process.env.CLIQ_MODEL_BASE_URL;
    else process.env.CLIQ_MODEL_BASE_URL = previousBaseUrl;
    if (previousStreaming === undefined) delete process.env.CLIQ_MODEL_STREAMING;
    else process.env.CLIQ_MODEL_STREAMING = previousStreaming;
  }
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
