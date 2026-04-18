import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createSession } from '../session/store.js';
import { createToolRegistry } from '../tools/registry.js';
import { createRunner } from './runner.js';

test('registry resolves bash and edit tools', () => {
  const registry = createToolRegistry();

  assert.equal(typeof registry.resolve({ bash: 'pwd' }).definition.name, 'string');
  assert.equal(typeof registry.resolve({ edit: { path: 'a', old_text: 'b', new_text: 'c' } }).definition.name, 'string');
});

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

test('runner appends tool results and replays them back to the model', async () => {
  const session = createSession('/tmp/workspace');
  let callCount = 0;
  let secondCallMessages: Array<{ role: string; content: string }> = [];

  const runner = createRunner({
    model: {
      async complete(messages) {
        callCount += 1;
        if (callCount === 1) {
          return '{"bash":"pwd"}';
        }

        secondCallMessages = messages;
        return '{"message":"done"}';
      }
    },
    registry: {
      definitions: [],
      resolve() {
        return {
          definition: {
            name: 'bash',
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

test('runner resets lifecycle state when setup fails before the loop', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-runner-'));
  const filePath = path.join(dir, 'workspace-file');
  await writeFile(filePath, 'not a directory');

  const session = createSession(filePath);
  const runner = createRunner({
    model: {
      async complete() {
        return '{"message":"done"}';
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'say done'));
  assert.equal(session.lifecycle.status, 'idle');
});

test('runner converts tool exceptions into tool error records and still calls afterTool hooks', async () => {
  const session = createSession('/tmp/workspace');
  const afterToolEvents: string[] = [];
  let callCount = 0;

  const runner = createRunner({
    model: {
      async complete() {
        callCount += 1;
        return callCount === 1 ? '{"bash":"pwd"}' : '{"message":"done"}';
      }
    },
    registry: {
      definitions: [],
      resolve() {
        return {
          definition: {
            name: 'bash',
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
