import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createPolicyEngine } from '../policy/engine.js';
import { createSession } from '../session/store.js';
import { createToolRegistry } from '../tools/registry.js';
import type { EditModelAction, ToolDefinition } from '../tools/types.js';
import { createRunner } from './runner.js';

function completion(content: string) {
  return {
    content,
    provider: 'openrouter' as const,
    model: 'test-model'
  };
}

const originalCliqHome = process.env.CLIQ_HOME;
const runnerCliqHome = await mkdtemp(path.join(os.tmpdir(), 'cliq-runner-home-'));
const cleanupDirs: string[] = [runnerCliqHome];
process.env.CLIQ_HOME = runnerCliqHome;

test.after(async () => {
  if (originalCliqHome === undefined) {
    delete process.env.CLIQ_HOME;
  } else {
    process.env.CLIQ_HOME = originalCliqHome;
  }

  await Promise.all(cleanupDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function createTempSession() {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-runner-workspace-'));
  cleanupDirs.push(cwd);
  return createSession(cwd);
}

test('registry resolves bash and edit tools', () => {
  const registry = createToolRegistry();

  assert.equal(typeof registry.resolve({ bash: 'pwd' }).definition.name, 'string');
  assert.equal(typeof registry.resolve({ edit: { path: 'a', old_text: 'b', new_text: 'c' } }).definition.name, 'string');
});

test('runner invokes hooks around assistant and tool execution', async () => {
  const session = await createTempSession();
  const events: string[] = [];

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    },
    registry: {
      definitions: [],
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

test('runner creates an automatic checkpoint before appending the user record', async () => {
  const session = await createTempSession();
  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    }
  });

  await runner.runTurn(session, 'say done');

  assert.equal(session.checkpoints.length, 1);
  assert.equal(session.checkpoints[0]?.kind, 'auto');
  assert.equal(session.checkpoints[0]?.recordIndex, 0);
  assert.equal(session.records[0]?.kind, 'user');
});

test('runner appends tool results and replays them back to the model', async () => {
  const session = await createTempSession();
  let callCount = 0;
  let secondCallMessages: Array<{ role: string; content: string }> = [];

  const runner = createRunner({
    model: {
      async complete(messages) {
        callCount += 1;
        if (callCount === 1) {
          return completion('{"bash":"pwd"}');
        }

        secondCallMessages = messages;
        return completion('{"message":"done"}');
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
                content: 'TOOL_RESULT bash OK\n$ pwd\n(exit=0 signal=none)\n/tmp/workspace',
                meta: { exit: 0, signal: 'none', timed_out: false }
              };
            }
          }
        };
      }
    }
  });

  const finalMessage = await runner.runTurn(session, 'show cwd');
  assert.equal(finalMessage, 'done');
  assert.equal(callCount, 2);
  assert.equal(session.records.at(-1)?.kind, 'assistant');
  assert.equal(session.records.at(-2)?.kind, 'tool');
  assert.equal(
    secondCallMessages.some((message) => message.role === 'user' && message.content.includes('TOOL_RESULT bash OK')),
    true
  );
});

test('runner prepends composed instruction messages before replayed session records', async () => {
  const session = await createTempSession();
  let seenMessages: Array<{ role: string; content: string }> = [];

  const runner = createRunner({
    model: {
      async complete(messages) {
        seenMessages = messages;
        return completion('{"message":"done"}');
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
  const session = await createTempSession();

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
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

test('runner resets lifecycle state when setup fails before the loop', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-runner-'));
  cleanupDirs.push(dir);
  const filePath = path.join(dir, 'workspace-file');
  await writeFile(filePath, 'not a directory');

  const session = createSession(filePath);
  let modelCalls = 0;
  const runner = createRunner({
    model: {
      async complete() {
        modelCalls += 1;
        return completion('{"message":"done"}');
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'say done'));
  assert.equal(session.lifecycle.status, 'idle');
  assert.equal(modelCalls, 0);
});

test('runner converts tool exceptions into tool error records and still calls afterTool hooks', async () => {
  const session = await createTempSession();
  const afterToolEvents: string[] = [];
  let callCount = 0;

  const runner = createRunner({
    model: {
      async complete() {
        callCount += 1;
        return completion(callCount === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
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
              throw new Error('spawn exploded');
            }
          }
        };
      }
    },
    hooks: [
      {
        async afterTool(_session, result) {
          afterToolEvents.push(`${result.tool}:${result.status}`);
        }
      }
    ]
  });

  const finalMessage = await runner.runTurn(session, 'show cwd');
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(finalMessage, 'done');
  assert.equal(toolRecord?.kind, 'tool');
  assert.equal(toolRecord?.status, 'error');
  assert.match(toolRecord?.content ?? '', /spawn exploded/);
  assert.deepEqual(afterToolEvents, ['bash:error']);
});

test('runner records a denied bash action when mode is read-only', async () => {
  const session = await createTempSession();
  const outputs: string[] = [];
  const runner = createRunner({
    model: {
      async complete() {
        return completion(outputs.length === 0 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'read-only' }),
    hooks: [
      {
        afterTool(_session, result) {
          outputs.push(result.content);
        }
      }
    ]
  });

  const finalMessage = await runner.runTurn(session, 'inspect repo');
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(finalMessage, 'done');
  assert.match(outputs[0] ?? '', /policy mode read-only blocks exec tools/);
  assert.equal(toolRecord?.status, 'error');
  assert.equal(toolRecord?.meta?.reason, 'policy mode read-only blocks exec tools');
});

test('runner records policy authorization failures as tool errors', async () => {
  const session = await createTempSession();
  const afterToolEvents: string[] = [];
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: {
      mode: 'confirm-all',
      async authorize() {
        throw new Error('confirmation backend unavailable');
      }
    },
    hooks: [
      {
        async afterTool(_session, result) {
          afterToolEvents.push(`${result.tool}:${result.status}`);
        }
      }
    ]
  });

  const finalMessage = await runner.runTurn(session, 'inspect repo');
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(finalMessage, 'done');
  assert.equal(toolRecord?.status, 'error');
  assert.match(toolRecord?.content ?? '', /policy=confirm-all/);
  assert.match(toolRecord?.content ?? '', /confirmation backend unavailable/);
  assert.deepEqual(afterToolEvents, ['bash:error']);
});

test('runner executes edit only after confirmation in confirm-write mode', async () => {
  const session = await createTempSession();
  let prompted = 0;
  const editExecutions: string[] = [];
  const editDefinition: ToolDefinition<EditModelAction> = {
    name: 'edit',
    access: 'write',
    supports(action): action is EditModelAction {
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
  };

  const runner = createRunner({
    model: {
      async complete() {
        return completion(
          editExecutions.length === 0
            ? '{"edit":{"path":"file.txt","old_text":"before","new_text":"after"}}'
            : '{"message":"done"}'
        );
      }
    },
    policy: createPolicyEngine({
      mode: 'confirm-write',
      confirm: async () => {
        prompted += 1;
        return true;
      }
    }),
    registry: createToolRegistry([editDefinition])
  });

  const finalMessage = await runner.runTurn(session, 'apply edit');

  assert.equal(finalMessage, 'done');
  assert.equal(prompted, 1);
  assert.deepEqual(editExecutions, ['file.txt']);
});

test('runner emits model lifecycle events without raw deltas', async () => {
  const session = await createTempSession();
  const events: Array<{ type: string; chars?: number; message?: string }> = [];

  const runner = createRunner({
    model: {
      async complete(_messages, options) {
        await options?.onEvent?.({ type: 'start', provider: 'openrouter', model: 'test-model', streaming: true });
        await options?.onEvent?.({ type: 'text-delta', text: '{"message":"' });
        await options?.onEvent?.({ type: 'text-delta', text: 'done"}' });
        await options?.onEvent?.({ type: 'end' });
        return completion('{"message":"done"}');
      }
    },
    onEvent(event) {
      events.push(event);
    }
  });

  const finalMessage = await runner.runTurn(session, 'say done');

  assert.equal(finalMessage, 'done');
  assert.deepEqual(events.map((event) => event.type), ['model-start', 'model-progress', 'model-progress', 'model-end', 'final']);
  assert.equal(events.some((event) => event.message?.includes('{"message"')), false);
});
