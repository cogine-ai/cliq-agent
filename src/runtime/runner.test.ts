import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { resolveModelMetadata } from '../model/catalog/index.js';
import type { ModelClient, ModelRequestMode } from '../model/types.js';
import { approvePlan, createDraftPlan, finalizePlan, readPlanArtifact, readPlanProgress } from '../plans/store.js';
import { createPolicyEngine } from '../policy/engine.js';
import { createSession } from '../session/store.js';
import { createToolRegistry } from '../tools/registry.js';
import type { EditModelAction, ToolDefinition } from '../tools/types.js';
import type { RuntimeEvent } from '../protocol/runtime/events.js';
import { createRunner } from './runner.js';
import type { TxRunnerOptions } from './tx-runner.js';

function completion(
  content: string,
  overrides?: {
    mode?: ModelRequestMode;
    streaming?: boolean;
    toolNames?: string[];
  }
) {
  const mode = overrides?.mode ?? 'text-action';
  const streaming = overrides?.streaming ?? false;
  return {
    content,
    provider: 'openrouter' as const,
    model: 'test-model',
    effectiveRequest: {
      provider: 'openrouter' as const,
      model: 'test-model',
      mode,
      streaming,
      baseInstructionChars: 0,
      inputItemCount: 0,
      toolNames: overrides?.toolNames ?? []
    }
  };
}

function requestMessages(request: unknown): Array<{ role: string; content: string }> {
  if (Array.isArray(request)) {
    return request as Array<{ role: string; content: string }>;
  }
  const typed = request as {
    baseInstructions?: { messages?: Array<{ role: string; content: string }> };
    input?: Array<{ kind: string; role?: string; content: string }>;
  };
  return [
    ...(typed.baseInstructions?.messages ?? []),
    ...(typed.input ?? []).map((item) => ({
      role: item.kind === 'tool_result' ? 'user' : (item.role ?? 'user'),
      content: item.content
    }))
  ];
}

function requestHasContent(request: unknown, pattern: string | RegExp) {
  return requestMessages(request).some((message) =>
    typeof pattern === 'string' ? message.content.includes(pattern) : pattern.test(message.content)
  );
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

function commandFor(scriptPath: string): string {
  return `${JSON.stringify(process.execPath)} ${JSON.stringify(scriptPath)}`;
}

function bashOkRegistry() {
  return {
    definitions: [],
    resolve() {
      return {
        definition: {
          name: 'bash',
          access: 'exec' as const,
          supports(action: unknown): action is { bash: string } {
            return typeof (action as { bash?: unknown }).bash === 'string';
          },
          async execute(action: { bash: string }) {
            return {
              tool: 'bash',
              status: 'ok' as const,
              content: `TOOL_RESULT bash OK\n$ ${action.bash}\n(exit=0 signal=none)\nok`,
              meta: { exit: 0, signal: 'none', timed_out: false }
            };
          }
        }
      };
    }
  };
}

async function writeHookScript(cwd: string, name: string, source: string) {
  const hooksDir = path.join(cwd, '.cliq', 'hooks');
  await mkdir(hooksDir, { recursive: true });
  const scriptPath = path.join(hooksDir, name);
  await writeFile(scriptPath, source, 'utf8');
  return commandFor(scriptPath);
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
    policy: createPolicyEngine({ mode: 'yolo' }),
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
  assert.equal(session.lifecycle.lastUserInputAt, session.records[0]?.ts);
});

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

test('runner default max turns allows long local tasks up to 100 model iterations', async () => {
  const session = await createTempSession();
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        if (calls < 100) {
          return completion(JSON.stringify({ bash: `echo ${calls}` }));
        }
        return completion(JSON.stringify({ message: 'done' }));
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
    registry: bashOkRegistry()
  });

  const finalMessage = await runner.runTurn(session, 'do a long task');

  assert.equal(finalMessage, 'done');
  assert.equal(calls, 100);
  assert.equal(session.records.filter((record) => record.kind === 'tool').length, 99);
});

test('runner honors explicit maxTurns before the default max turns limit', async () => {
  const session = await createTempSession();
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(JSON.stringify({ bash: `echo ${calls}` }));
      }
    },
    maxTurns: 2,
    policy: createPolicyEngine({ mode: 'yolo' }),
    registry: bashOkRegistry()
  });

  await assert.rejects(() => runner.runTurn(session, 'stop after two tool loops'), /Exceeded max turns \(2\)/);
  assert.equal(calls, 2);
});

test('runner detects repeated identical tool action/result doom loops', async () => {
  const session = await createTempSession();
  const errors: Extract<RuntimeEvent, { type: 'error' }>[] = [];
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(JSON.stringify({ bash: 'pwd' }));
      }
    },
    maxTurns: 100,
    policy: createPolicyEngine({ mode: 'yolo' }),
    registry: bashOkRegistry(),
    onEvent(event) {
      if (event.type === 'error') {
        errors.push(event);
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'repeat a command'), /Doom loop detected/i);
  assert.equal(calls, 3);
  assert.match(errors.at(-1)?.message ?? '', /repeated identical bash action/i);
  assert.equal(errors.at(-1)?.stage, 'model');
});

test('createRunner rejects non-positive maxTurns and doomLoop.repeatedActionLimit', () => {
  const model = { async complete() { return completion('{"message":"done"}'); } };

  assert.throws(() => createRunner({ model, maxTurns: 0 }), /maxTurns must be a positive integer/);
  assert.throws(() => createRunner({ model, maxTurns: -2 }), /maxTurns must be a positive integer/);
  assert.throws(() => createRunner({ model, maxTurns: 1.5 }), /maxTurns must be a positive integer/);
  assert.throws(
    () => createRunner({ model, doomLoop: { repeatedActionLimit: 0 } }),
    /doomLoop\.repeatedActionLimit must be a positive integer/
  );
});

test('runner honors custom doomLoop.repeatedActionLimit before the default limit', async () => {
  const session = await createTempSession();
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(JSON.stringify({ bash: 'pwd' }));
      }
    },
    maxTurns: 100,
    doomLoop: { repeatedActionLimit: 2 },
    policy: createPolicyEngine({ mode: 'yolo' }),
    registry: bashOkRegistry()
  });

  await assert.rejects(() => runner.runTurn(session, 'repeat a command'), /Doom loop detected/i);
  assert.equal(calls, 2);
});

test('runner doom loop counter resets when the tool result changes', async () => {
  const session = await createTempSession();
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        if (calls <= 2) {
          return completion(JSON.stringify({ bash: 'pwd' }));
        }
        if (calls === 3) {
          return completion(JSON.stringify({ bash: 'pwd' }));
        }
        return completion(JSON.stringify({ message: 'done' }));
      }
    },
    maxTurns: 100,
    policy: createPolicyEngine({ mode: 'yolo' }),
    registry: {
      definitions: [],
      resolve() {
        return {
          definition: {
            name: 'bash',
            access: 'exec' as const,
            supports(action: unknown): action is { bash: string } {
              return typeof (action as { bash?: unknown }).bash === 'string';
            },
            async execute(action: { bash: string }) {
              return {
                tool: 'bash',
                status: 'ok' as const,
                content: calls === 3 ? '/tmp/other' : '/tmp/ws',
                meta: { exit: 0, signal: 'none', timed_out: false }
              };
            }
          }
        };
      }
    }
  });

  const finalMessage = await runner.runTurn(session, 'repeat with changing output');
  assert.equal(finalMessage, 'done');
  assert.equal(calls, 4);
});

test('per-turn signal in runTurn opts cancels the turn without poisoning the runner', async () => {
  const session = await createTempSession();
  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    }
  });

  // First turn: pre-aborted per-turn signal must reject without affecting
  // the runner's ability to run a fresh turn afterwards.
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(
    () => runner.runTurn(session, 'first turn', { signal: aborted.signal }),
    /cancelled/i
  );

  // Second turn: a fresh signal lets the runner make progress.
  const fresh = new AbortController();
  const finalMessage = await runner.runTurn(session, 'second turn', { signal: fresh.signal });
  assert.equal(finalMessage, 'done');
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
  assert.equal(session.lifecycle.turn, 0);
  assert.equal(session.lifecycle.lastUserInputAt, undefined);
});

test('runner cancellation after lifecycle mutation before checkpoint restores lifecycle', async () => {
  const session = await createTempSession();
  let reads = 0;
  const signal = {
    get aborted() {
      reads += 1;
      return reads >= 2;
    }
  } as AbortSignal;

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    },
    signal
  });

  await assert.rejects(() => runner.runTurn(session, 'say done'), /cancelled/i);
  assert.equal(session.records.length, 0);
  assert.equal(session.checkpoints.length, 0);
  assert.equal(session.lifecycle.status, 'idle');
  assert.equal(session.lifecycle.turn, 0);
  assert.equal(session.lifecycle.lastUserInputAt, undefined);
  assert.equal(session.lifecycle.lastAssistantOutputAt, undefined);
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
  assert.equal(session.lifecycle.turn, 1);
  assert.equal(session.lifecycle.lastUserInputAt, undefined);
});

test('runner cancellation after parsing assistant output skips assistant append', async () => {
  const session = await createTempSession();
  let reads = 0;
  const signal = {
    get aborted() {
      reads += 1;
      return reads >= 10;
    }
  } as AbortSignal;

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    },
    signal
  });

  await assert.rejects(() => runner.runTurn(session, 'say done'), /cancelled/i);
  assert.equal(session.records.length, 1);
  assert.equal(session.records[0]?.kind, 'user');
  assert.equal(session.lifecycle.lastAssistantOutputAt, undefined);
});

test('runner appends tool results and replays them back to the model', async () => {
  const session = await createTempSession();
  let callCount = 0;
  let secondCallRequest: unknown;

  const runner = createRunner({
    model: {
      async complete(request) {
        callCount += 1;
        if (callCount === 1) {
          return completion('{"bash":"pwd"}');
        }

        secondCallRequest = request;
        return completion('{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
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
    session.records.filter((record) => record.kind === 'assistant').at(-1)?.ts,
    session.lifecycle.lastAssistantOutputAt
  );
  assert.equal(
    requestHasContent(secondCallRequest, 'TOOL_RESULT bash OK'),
    true
  );
});

test('runner prioritizes structured tool calls and replays typed tool results before plain final text', async () => {
  const session = await createTempSession();
  session.model = {
    provider: 'openrouter',
    model: 'anthropic/claude-sonnet-4.6',
    baseUrl: 'https://openrouter.ai/api/v1'
  };
  const requests: unknown[] = [];
  let callCount = 0;

  const runner = createRunner({
    model: {
      async complete(request) {
        requests.push(request);
        callCount += 1;
        if (callCount === 1) {
          return {
            content: 'not-json',
            provider: 'openrouter' as const,
            model: 'test-model',
            toolCalls: [
              {
                id: 'call_1',
                name: 'bash',
                arguments: { command: 'pwd' }
              }
            ],
            effectiveRequest: {
              provider: 'openrouter' as const,
              model: 'test-model',
              mode: 'native-tools' as const,
              streaming: false,
              baseInstructionChars: 0,
              inputItemCount: 0,
              toolNames: ['bash']
            }
          };
        }

        return completion('done', { mode: 'native-tools' });
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' })
  });

  const finalMessage = await runner.runTurn(session, 'show cwd');
  assert.equal(finalMessage, 'done');
  assert.equal(callCount, 2);
  assert.equal(
    (requests[0] as { toolSpecs?: Array<{ name: string }> }).toolSpecs?.some((spec) => spec.name === 'bash'),
    true
  );
  assert.equal(
    (requests[1] as { input?: Array<{ kind: string; toolName?: string; callId?: string }> }).input?.some(
      (item) => item.kind === 'tool_result' && item.toolName === 'bash' && item.callId === 'call_1'
    ),
    true
  );
});

test('runner carries session streaming mode into typed prompt requests', async () => {
  const session = await createTempSession();
  session.model = {
    provider: 'openai-compatible',
    model: 'local-model',
    baseUrl: 'http://localhost:4000/v1',
    streaming: 'off'
  };
  let firstRequest: unknown;

  const runner = createRunner({
    model: {
      async complete(request) {
        firstRequest = request;
        return completion('{"message":"done"}');
      }
    }
  });

  const finalMessage = await runner.runTurn(session, 'say done');

  assert.equal(finalMessage, 'done');
  assert.equal((firstRequest as { streaming?: { mode?: string } }).streaming?.mode, 'off');
});

test('runner uses provider effectiveRequest streaming for model-start events', async () => {
  const session = await createTempSession();
  session.model = {
    provider: 'openai-compatible',
    model: 'local-model',
    baseUrl: 'http://localhost:4000/v1',
    streaming: 'auto'
  };
  let modelStart: Extract<RuntimeEvent, { type: 'model-start' }> | undefined;

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}', { streaming: true });
      }
    },
    onEvent(event) {
      if (event.type === 'model-start') {
        modelStart = event;
      }
    }
  });

  const finalMessage = await runner.runTurn(session, 'say done');

  assert.equal(finalMessage, 'done');
  assert.equal(modelStart?.streaming, true);
});

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
    policy: createPolicyEngine({ mode: 'yolo' }),
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

test('runner prepends composed instruction messages before replayed session records', async () => {
  const session = await createTempSession();
  let seenRequest: unknown;

  const runner = createRunner({
    model: {
      async complete(request) {
        seenRequest = request;
        return completion('{"message":"done"}');
      }
    },
    instructions: async () => [
      { role: 'system', layer: 'core', source: 'base', content: 'BASE' },
      { role: 'system', layer: 'skill', source: 'reviewer', content: 'SKILL' }
    ]
  });

  await runner.runTurn(session, 'say done');

  const seenMessages = requestMessages(seenRequest);
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
  assert.equal(session.lifecycle.lastUserInputAt, undefined);
  assert.equal(modelCalls, 0);
});

test('runner cancellation after beforeTool skips tool execution and tool record', async () => {
  const session = await createTempSession();
  const controller = new AbortController();
  let executed = false;

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"bash":"pwd"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
    signal: controller.signal,
    hooks: [
      {
        beforeTool() {
          controller.abort();
        }
      }
    ],
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
              executed = true;
              return {
                tool: 'bash',
                status: 'ok' as const,
                content: 'TOOL_RESULT bash OK\n$ pwd\n(exit=0 signal=none)\n/tmp/workspace',
                meta: { exit: 0 }
              };
            }
          }
        };
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'use tool'), /cancelled/i);
  assert.equal(executed, false);
  assert.equal(session.records.some((record) => record.kind === 'tool'), false);
});

test('runner cancellation during tool execution does not persist a tool error record', async () => {
  const session = await createTempSession();
  const controller = new AbortController();

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"bash":"pwd"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
    signal: controller.signal,
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
              controller.abort();
              const error = new Error('aborted');
              error.name = 'AbortError';
              throw error;
            }
          }
        };
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'use tool'), /cancelled/i);
  assert.equal(session.records.some((record) => record.kind === 'tool'), false);
});

test('runner treats tool AbortError as cancellation even when signal is not aborted', async () => {
  const session = await createTempSession();

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"bash":"pwd"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
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
              const error = new Error('aborted');
              error.name = 'AbortError';
              throw error;
            }
          }
        };
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'use tool'), /cancelled/i);
  assert.equal(session.records.some((record) => record.kind === 'tool'), false);
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
    policy: createPolicyEngine({ mode: 'yolo' }),
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

test('runner records a denied bash action when mode is plan', async () => {
  const session = await createTempSession();
  const outputs: string[] = [];
  let confirmCalls = 0;
  const runner = createRunner({
    model: {
      async complete() {
        return completion(outputs.length === 0 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'plan' }),
    confirm: async () => {
      confirmCalls += 1;
      return true;
    },
    hooks: [
      {
        afterTool(_session, result) {
          outputs.push(result.content);
        }
      }
    ]
  });

  await assert.rejects(
    () => runner.runTurn(session, 'inspect repo'),
    /Plan Mode requires a plan artifact before returning a final message/
  );
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.match(outputs[0] ?? '', /policy mode plan blocks exec tools/);
  assert.equal(toolRecord?.status, 'error');
  assert.equal(toolRecord?.meta?.reason, 'policy mode plan blocks exec tools');
  assert.equal(confirmCalls, 0);
});

test('runner rejects plan-mode final messages when no plan artifact was created', async () => {
  const session = await createTempSession();
  const events: RuntimeEvent[] = [];
  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"Here is the answer without a plan."}');
      }
    },
    policy: createPolicyEngine({ mode: 'plan' }),
    onEvent(event) {
      events.push(event);
    }
  });

  await assert.rejects(
    () => runner.runTurn(session, 'make a plan'),
    /Plan Mode requires a plan artifact before returning a final message/
  );

  assert.equal(session.activePlanId, undefined);
  assert.equal(events.some((event) => event.type === 'final'), false);
  assert.equal(
    events.some(
      (event) =>
        event.type === 'error' &&
        event.stage === 'policy' &&
        /Plan Mode requires a plan artifact/.test(event.message)
    ),
    true
  );
});

test('runner finalizes a plan-mode draft when the model tries to answer instead of requesting review', async () => {
  const session = await createTempSession();
  const events: RuntimeEvent[] = [];
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        if (calls === 1) {
          return completion('{"plan":{"op":"draft","title":"TUI plan","content":"## Steps\\n- Inspect\\n- Summarize"}}');
        }
        if (calls === 2) {
          return completion('{"ls":{"path":"."}}');
        }
        return completion('{"message":"I inspected the workspace and here is the answer."}');
      }
    },
    policy: createPolicyEngine({ mode: 'plan' }),
    onEvent(event) {
      events.push(event);
    }
  });

  const final = await runner.runTurn(session, 'make a plan');

  assert.equal(final, 'Plan ready for review: TUI plan');
  assert.equal(calls, 3);
  assert.equal(session.records.filter((record) => record.kind === 'tool' && record.tool === 'plan').length, 1);
  assert.equal(session.records.filter((record) => record.kind === 'tool' && record.tool === 'ls').length, 1);
  const finalizedEvent = events.find((event): event is Extract<RuntimeEvent, { type: 'plan-finalized' }> => event.type === 'plan-finalized');
  assert.ok(finalizedEvent);
  assert.equal(finalizedEvent.plan.title, 'TUI plan');
  const finalized = await readPlanArtifact(session.cwd, session, session.activePlanId!);
  assert.equal(finalized.status, 'finalized');
});

test('runner allows plan artifacts in plan mode and stops for TUI review after finalize', async () => {
  const session = await createTempSession();
  const events: RuntimeEvent[] = [];
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        if (calls === 1) {
          return completion('{"plan":{"op":"draft","title":"TUI plan","content":"## Steps\\n- One"}}');
        }
        return completion(`{"plan":{"op":"finalize","planId":"${session.activePlanId}"}}`);
      }
    },
    policy: createPolicyEngine({ mode: 'plan' }),
    onEvent(event) {
      events.push(event);
    }
  });

  const final = await runner.runTurn(session, 'make a plan');

  assert.equal(final, 'Plan ready for review: TUI plan');
  assert.equal(calls, 2);
  assert.equal(session.records.filter((record) => record.kind === 'tool' && record.tool === 'plan').length, 2);
  assert.equal(session.activePlanId?.startsWith('plan_'), true);
  const finalizedEvent = events.find((event): event is Extract<RuntimeEvent, { type: 'plan-finalized' }> => event.type === 'plan-finalized');
  assert.ok(finalizedEvent);
  assert.deepEqual(finalizedEvent.plan.items, [{ id: 'item_1', title: 'One', status: 'pending' }]);
  assert.match(finalizedEvent.plan.markdownPath, /plan\.md$/);
  const finalized = await readPlanArtifact(session.cwd, session, session.activePlanId!);
  assert.equal(finalized.status, 'finalized');
  assert.equal(finalized.contentMarkdown, '## Steps\n- One');
  assert.deepEqual(finalized.items, [{ id: 'item_1', title: 'One', status: 'pending' }]);
  assert.match(finalized.paths.markdown, /plan\.md$/);
});

test('runner emits plan-progress-updated after todo tool updates approved-plan progress', async () => {
  const session = await createTempSession();
  const draft = await createDraftPlan(session.cwd, session, {
    title: 'Execute tracked plan',
    contentMarkdown: '## Steps\n- Inspect\n- Implement'
  });
  await finalizePlan(session.cwd, session, { planId: draft.id });
  await approvePlan(session.cwd, session, { planId: draft.id, targetMode: 'default' });
  const events: RuntimeEvent[] = [];
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        if (calls === 1) {
          return completion(
            `{"todo":{"planId":"${draft.id}","items":[{"id":"item_1","title":"Inspect","status":"completed","activeForm":"Inspecting"},{"id":"item_2","title":"Implement","status":"in_progress","activeForm":"Implementing"}]}}`
          );
        }
        return completion('{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'default' }),
    onEvent(event) {
      events.push(event);
    }
  });

  const final = await runner.runTurn(session, 'execute plan');

  assert.equal(final, 'done');
  const progress = await readPlanProgress(session.cwd, session, draft.id);
  assert.deepEqual(progress.items.map((item) => [item.title, item.status]), [
    ['Inspect', 'completed'],
    ['Implement', 'in_progress']
  ]);
  const progressEvent = events.find(
    (event): event is Extract<RuntimeEvent, { type: 'plan-progress-updated' }> =>
      event.type === 'plan-progress-updated'
  );
  assert.ok(progressEvent);
  assert.equal(progressEvent.progress.planId, draft.id);
  assert.deepEqual(progressEvent.progress.items.map((item) => [item.title, item.status]), [
    ['Inspect', 'completed'],
    ['Implement', 'in_progress']
  ]);
});

test('runner makes model-activated skills available as next-call instructions', async () => {
  const session = await createTempSession();
  await mkdir(path.join(session.cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
  await writeFile(
    path.join(session.cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
    `---
name: reviewer
description: review workflow
---

Use reviewer workflow.`,
    'utf8'
  );

  let calls = 0;
  let sawSkillInstruction = false;
  const runner = createRunner({
    model: {
      async complete(request) {
        calls += 1;
        if (calls === 1) {
          return completion('{"skill":{"name":"reviewer"}}');
        }
        sawSkillInstruction = requestMessages(request).some(
          (message) => message.role === 'system' && /Use reviewer workflow/.test(message.content)
        );
        return completion('{"message":"done"}');
      }
    },
    instructions: async (currentSession) =>
      currentSession.activeSkills.map((skill) => ({
        role: 'system',
        layer: 'skill',
        source: `skill:${skill.name}`,
        content: skill.prompt
      }))
  });

  const finalMessage = await runner.runTurn(session, 'use reviewer');

  assert.equal(finalMessage, 'done');
  assert.equal(sawSkillInstruction, true);
  assert.equal(session.activeSkills[0]?.name, 'reviewer');
});

test('runner records policy decision failures as tool errors', async () => {
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
      mode: 'default',
      async decide() {
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
  assert.match(toolRecord?.content ?? '', /policy=default/);
  assert.match(toolRecord?.content ?? '', /confirmation backend unavailable/);
  assert.deepEqual(afterToolEvents, ['bash:error']);
});

test('runner executes edit only after confirmation in default mode', async () => {
  const session = await createTempSession();
  const prompts: string[] = [];
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
      mode: 'default'
    }),
    confirm: async (prompt) => {
      prompts.push(prompt);
      return true;
    },
    registry: createToolRegistry([editDefinition])
  });

  const finalMessage = await runner.runTurn(session, 'apply edit');

  assert.equal(finalMessage, 'done');
  assert.equal(prompts.length, 1);
  assert.match(prompts[0] ?? '', /Allow edit\?/);
  assert.match(prompts[0] ?? '', /file\.txt/);
  assert.match(prompts[0] ?? '', /policy: default/);
  assert.deepEqual(editExecutions, ['file.txt']);
});

test('runner confirmation prompt for bash includes the actual command', async () => {
  const session = await createTempSession();
  const prompts: string[] = [];
  let calls = 0;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"npm test"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'accept-edits' }),
    confirm: async (prompt) => {
      prompts.push(prompt);
      return true;
    }
  });

  const finalMessage = await runner.runTurn(session, 'run tests');

  assert.equal(finalMessage, 'done');
  assert.equal(prompts.length, 1);
  assert.match(prompts[0] ?? '', /Allow bash command\?/);
  assert.match(prompts[0] ?? '', /npm test/);
  assert.match(prompts[0] ?? '', /policy: accept-edits/);
});

test('runner runs PreToolUse and PostToolUse command hooks around tool execution', async () => {
  const session = await createTempSession();
  let calls = 0;
  const prePath = path.join(session.cwd, 'pre.json');
  const postPath = path.join(session.cwd, 'post.json');
  const preCommand = await writeHookScript(
    session.cwd,
    'pre-tool-use.js',
    `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  require('node:fs').writeFileSync(${JSON.stringify(prePath)}, JSON.stringify({
    hookEventName: parsed.hookEventName,
    sessionId: parsed.sessionId,
    cwd: parsed.cwd,
    toolName: parsed.toolName,
    action: parsed.action,
    approvalSubject: parsed.approvalSubject
  }));
});
`
  );
  const postCommand = await writeHookScript(
    session.cwd,
    'post-tool-use.js',
    `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  require('node:fs').writeFileSync(${JSON.stringify(postPath)}, JSON.stringify({
    hookEventName: parsed.hookEventName,
    toolName: parsed.toolName,
    toolResult: parsed.toolResult
  }));
});
`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
    commandHooks: {
      PreToolUse: [{ matcher: 'bash', hooks: [{ type: 'command', command: preCommand }] }],
      PostToolUse: [{ matcher: 'bash', hooks: [{ type: 'command', command: postCommand }] }]
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
                meta: { exit: 0 }
              };
            }
          }
        };
      }
    }
  });

  await runner.runTurn(session, 'show cwd');

  const pre = JSON.parse(await readFile(prePath, 'utf8')) as {
    hookEventName: string;
    sessionId: string;
    cwd: string;
    toolName: string;
    action: { bash: string };
    approvalSubject: { kind: string; toolName: string };
  };
  const post = JSON.parse(await readFile(postPath, 'utf8')) as {
    hookEventName: string;
    toolName: string;
    toolResult: { tool: string; status: string };
  };

  assert.equal(pre.hookEventName, 'PreToolUse');
  assert.equal(pre.sessionId, session.id);
  assert.equal(pre.cwd, session.cwd);
  assert.equal(pre.toolName, 'bash');
  assert.deepEqual(pre.action, { bash: 'pwd' });
  assert.equal(pre.approvalSubject.kind, 'tool');
  assert.equal(pre.approvalSubject.toolName, 'bash');
  assert.equal(post.hookEventName, 'PostToolUse');
  assert.equal(post.toolName, 'bash');
  assert.equal(post.toolResult.tool, 'bash');
  assert.equal(post.toolResult.status, 'ok');
});

test('runner blocks tool execution when PreToolUse command hook denies', async () => {
  const session = await createTempSession();
  let calls = 0;
  let executed = false;
  const denyCommand = await writeHookScript(
    session.cwd,
    'deny-pre-tool-use.js',
    `process.stderr.write('blocked by pre hook'); process.exit(2);`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
    commandHooks: {
      PreToolUse: [{ matcher: 'bash', hooks: [{ type: 'command', command: denyCommand }] }]
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
              executed = true;
              return { tool: 'bash', status: 'ok' as const, content: 'should not run', meta: {} };
            }
          }
        };
      }
    }
  });

  await runner.runTurn(session, 'show cwd');
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(executed, false);
  assert.equal(toolRecord?.kind, 'tool');
  assert.equal(toolRecord?.status, 'error');
  assert.equal(toolRecord?.meta?.hookEventName, 'PreToolUse');
  assert.equal(toolRecord?.meta?.reason, 'blocked by pre hook');
});

test('runner stops plan turns after repeated blocked exec requests', async () => {
  const session = await createTempSession();
  const events: Array<{ type: string; stage?: string; message?: string }> = [];
  let calls = 0;
  let executed = false;

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion('{"bash":"pwd"}');
      }
    },
    policy: createPolicyEngine({ mode: 'plan' }),
    onEvent(event) {
      if (event.type === 'error') events.push(event);
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
              executed = true;
              return { tool: 'bash', status: 'ok' as const, content: 'should not run', meta: {} };
            }
          }
        };
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'run pwd'), /plan mode repeatedly blocked exec tool bash/);

  assert.equal(calls, 2);
  assert.equal(executed, false);
  assert.equal(session.records.filter((record) => record.kind === 'tool').length, 2);
  assert.match(events.at(-1)?.message ?? '', /plan mode repeatedly blocked exec tool bash/);
});

test('runner warns and continues for non-required PreToolUse infrastructure errors', async () => {
  const session = await createTempSession();
  const events: Array<{ type: string; message?: string; recoverable?: boolean }> = [];
  let calls = 0;
  let executed = false;
  const failingCommand = await writeHookScript(
    session.cwd,
    'failing-pre-tool-use.js',
    `process.stderr.write('hook crashed'); process.exit(9);`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
    commandHooks: {
      PreToolUse: [{ matcher: 'bash', hooks: [{ type: 'command', command: failingCommand }] }]
    },
    onEvent(event) {
      if (event.type === 'error') events.push(event);
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
              executed = true;
              return { tool: 'bash', status: 'ok' as const, content: 'TOOL_RESULT bash OK', meta: {} };
            }
          }
        };
      }
    }
  });

  const finalMessage = await runner.runTurn(session, 'show cwd');

  assert.equal(finalMessage, 'done');
  assert.equal(executed, true);
  assert.equal(events.length, 1);
  assert.match(events[0]?.message ?? '', /PreToolUse hook failed/i);
  assert.equal(events[0]?.recoverable, true);
});

test('runner blocks tool execution for required PreToolUse infrastructure errors', async () => {
  const session = await createTempSession();
  let calls = 0;
  let executed = false;
  const failingCommand = await writeHookScript(
    session.cwd,
    'required-failing-pre-tool-use.js',
    `process.stderr.write('hook crashed'); process.exit(9);`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'yolo' }),
    commandHooks: {
      PreToolUse: [{ matcher: 'bash', hooks: [{ type: 'command', command: failingCommand, required: true }] }]
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
              executed = true;
              return { tool: 'bash', status: 'ok' as const, content: 'should not run', meta: {} };
            }
          }
        };
      }
    }
  });

  await runner.runTurn(session, 'show cwd');
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(executed, false);
  assert.equal(toolRecord?.status, 'error');
  assert.equal(toolRecord?.meta?.hookEventName, 'PreToolUse');
  assert.match(String(toolRecord?.meta?.reason ?? ''), /required PreToolUse hook failed/i);
});

test('runner lets PermissionRequest command hooks allow policy asks without user confirmation', async () => {
  const session = await createTempSession();
  let calls = 0;
  let executed = false;
  let confirmCalls = 0;
  const allowCommand = await writeHookScript(
    session.cwd,
    'allow-permission-request.js',
    `process.stdout.write(JSON.stringify({ permissionDecision: { behavior: 'allow', message: 'approved by hook' } }));`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'accept-edits' }),
    confirm: async () => {
      confirmCalls += 1;
      return false;
    },
    commandHooks: {
      PermissionRequest: [{ matcher: 'bash', hooks: [{ type: 'command', command: allowCommand }] }]
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
              executed = true;
              return { tool: 'bash', status: 'ok' as const, content: 'TOOL_RESULT bash OK', meta: {} };
            }
          }
        };
      }
    }
  });

  await runner.runTurn(session, 'show cwd');

  assert.equal(executed, true);
  assert.equal(confirmCalls, 0);
});

test('PermissionRequest hook allow with explicit scope is accepted (forward compat)', async () => {
  // v0 only acts on 'once'; 'session' and 'workspace' are accepted from the
  // hook so authors can start emitting them, but treated as 'once' by the
  // runner until #62-B lands. The hook must still complete the turn cleanly.
  // Non-string scope values are also exercised here (regression pin for
  // PR #71 nitpick) to lock in coerceHookPermissionScope's "unknown/non-string
  // → 'once'" guarantee.
  const session = await createTempSession();
  let calls = 0;
  let executed = false;
  const scopes: ReadonlyArray<string | number | undefined> = [
    'session',
    'workspace',
    'forever-unknown',
    undefined,
    123
  ];
  for (const scope of scopes) {
    calls = 0;
    executed = false;
    const payload = scope === undefined
      ? `{ permissionDecision: { behavior: 'allow', message: 'ok' } }`
      : `{ permissionDecision: { behavior: 'allow', message: 'ok', scope: ${JSON.stringify(scope)} } }`;
    const safeName = String(scope ?? 'missing').replace(/[^a-z0-9]/gi, '_');
    const cmd = await writeHookScript(
      session.cwd,
      `allow-scope-${safeName}.js`,
      `process.stdout.write(JSON.stringify(${payload}));`
    );

    const runner = createRunner({
      model: {
        async complete() {
          calls += 1;
          return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
        }
      },
      policy: createPolicyEngine({ mode: 'accept-edits' }),
      confirm: async () => false,
      commandHooks: {
        PermissionRequest: [{ matcher: 'bash', hooks: [{ type: 'command', command: cmd }] }]
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
                executed = true;
                return { tool: 'bash', status: 'ok' as const, content: 'TOOL_RESULT bash OK', meta: {} };
              }
            }
          };
        }
      }
    });

    await runner.runTurn(session, 'show cwd');
    assert.equal(executed, true, `executed for scope=${scope ?? 'missing'}`);
  }
});

test('runner lets PermissionRequest command hooks deny policy asks', async () => {
  const session = await createTempSession();
  let calls = 0;
  let executed = false;
  let confirmCalls = 0;
  const denyCommand = await writeHookScript(
    session.cwd,
    'deny-permission-request.js',
    `process.stdout.write(JSON.stringify({ permissionDecision: { behavior: 'deny', message: 'denied by hook' } }));`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'accept-edits' }),
    confirm: async () => {
      confirmCalls += 1;
      return true;
    },
    commandHooks: {
      PermissionRequest: [{ matcher: 'bash', hooks: [{ type: 'command', command: denyCommand }] }]
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
              executed = true;
              return { tool: 'bash', status: 'ok' as const, content: 'should not run', meta: {} };
            }
          }
        };
      }
    }
  });

  await runner.runTurn(session, 'show cwd');
  const toolRecord = session.records.find((record) => record.kind === 'tool');

  assert.equal(executed, false);
  assert.equal(confirmCalls, 0);
  assert.equal(toolRecord?.status, 'error');
  assert.equal(toolRecord?.meta?.reason, 'denied by hook');
});

test('runner falls back to user confirmation when PermissionRequest hooks make no decision', async () => {
  const session = await createTempSession();
  let calls = 0;
  let confirmCalls = 0;
  const noDecisionCommand = await writeHookScript(
    session.cwd,
    'no-decision-permission-request.js',
    `process.stdout.write(JSON.stringify({ additionalContext: 'not a decision' }));`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'accept-edits' }),
    confirm: async () => {
      confirmCalls += 1;
      return true;
    },
    commandHooks: {
      PermissionRequest: [{ matcher: 'bash', hooks: [{ type: 'command', command: noDecisionCommand }] }]
    }
  });

  await runner.runTurn(session, 'show cwd');

  assert.equal(confirmCalls, 1);
});

test('runner does not invoke PermissionRequest hooks for plan hard denies', async () => {
  const session = await createTempSession();
  let calls = 0;
  const markerPath = path.join(session.cwd, 'permission-hook-ran');
  const markerCommand = await writeHookScript(
    session.cwd,
    'marker-permission-request.js',
    `require('node:fs').writeFileSync(${JSON.stringify(markerPath)}, 'ran');`
  );

  const runner = createRunner({
    model: {
      async complete() {
        calls += 1;
        return completion(calls === 1 ? '{"bash":"pwd"}' : '{"message":"done"}');
      }
    },
    policy: createPolicyEngine({ mode: 'plan' }),
    commandHooks: {
      PermissionRequest: [{ matcher: 'bash', hooks: [{ type: 'command', command: markerCommand }] }]
    }
  });

  await assert.rejects(
    () => runner.runTurn(session, 'show cwd'),
    /Plan Mode requires a plan artifact before returning a final message/
  );

  await assert.rejects(() => readFile(markerPath, 'utf8'), /ENOENT/);
});

test('runner runs UserPromptSubmit and Stop command hooks at turn boundaries', async () => {
  const session = await createTempSession();
  const promptPath = path.join(session.cwd, 'prompt.json');
  const stopPath = path.join(session.cwd, 'stop.json');
  const observedFinalEvents: string[] = [];
  const promptCommand = await writeHookScript(
    session.cwd,
    'user-prompt-submit.js',
    `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  require('node:fs').writeFileSync(${JSON.stringify(promptPath)}, JSON.stringify({
    hookEventName: parsed.hookEventName,
    prompt: parsed.prompt,
    sessionId: parsed.sessionId
  }));
});
`
  );
  const stopCommand = await writeHookScript(
    session.cwd,
    'stop.js',
    `let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const parsed = JSON.parse(input);
  require('node:fs').writeFileSync(${JSON.stringify(stopPath)}, JSON.stringify({
    hookEventName: parsed.hookEventName,
    finalMessage: parsed.finalMessage
  }));
});
`
  );

  const runner = createRunner({
    model: {
      async complete() {
        return completion('{"message":"done"}');
      }
    },
    commandHooks: {
      UserPromptSubmit: [{ hooks: [{ type: 'command', command: promptCommand }] }],
      Stop: [{ hooks: [{ type: 'command', command: stopCommand }] }]
    },
    async onEvent(event) {
      if (event.type === 'final') {
        const stop = JSON.parse(await readFile(stopPath, 'utf8')) as { finalMessage: string };
        observedFinalEvents.push(stop.finalMessage);
      }
    }
  });

  await runner.runTurn(session, 'say done');

  const prompt = JSON.parse(await readFile(promptPath, 'utf8')) as {
    hookEventName: string;
    prompt: string;
    sessionId: string;
  };
  const stop = JSON.parse(await readFile(stopPath, 'utf8')) as { hookEventName: string; finalMessage: string };

  assert.equal(prompt.hookEventName, 'UserPromptSubmit');
  assert.equal(prompt.prompt, 'say done');
  assert.equal(prompt.sessionId, session.id);
  assert.equal(stop.hookEventName, 'Stop');
  assert.equal(stop.finalMessage, 'done');
  assert.deepEqual(observedFinalEvents, ['done']);
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
  assert.deepEqual(events.map((event) => event.type), [
    'checkpoint-created',
    'model-start',
    'model-progress',
    'model-progress',
    'model-end',
    'final'
  ]);
  assert.equal(events.some((event) => event.message?.includes('{"message"')), false);
});

test('runner auto compacts before model call when threshold is exceeded', async () => {
  const session = await createTempSession();
  const controller = new AbortController();
  session.records.push(
    { id: 'u_old', ts: '2026-04-30T00:00:00.000Z', kind: 'user', role: 'user', content: 'old '.repeat(300) },
    { id: 'u_tail', ts: '2026-04-30T00:00:01.000Z', kind: 'user', role: 'user', content: 'tail' }
  );
  let firstCallRequest: unknown;
  let summarizerSignal: AbortSignal | undefined;

  const runner = createRunner({
    model: {
      async complete(request, options) {
        if (requestHasContent(request, 'Records to summarize')) {
          summarizerSignal = options?.signal;
          return completion('## Objective\nSummarized');
        }
        firstCallRequest = request;
        return completion('{"message":"done"}');
      }
    },
    signal: controller.signal,
    autoCompact: {
      config: {
        enabled: 'on',
        contextWindowTokens: 700,
        thresholdRatio: 0.35,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1
      },
      modelConfig: {
        provider: 'openrouter',
        model: 'anthropic/claude-sonnet-4.6',
        baseUrl: 'https://example.test',
        streaming: 'off'
      }
    }
  });

  await runner.runTurn(session, 'new request');

  assert.equal(session.compactions.length, 1);
  assert.equal(summarizerSignal, controller.signal);
  assert.equal(requestHasContent(firstCallRequest, 'COMPACTED SESSION SUMMARY'), true);
});

test('runner auto compact can use catalog model metadata for context window', async () => {
  const session = await createTempSession();
  session.records.push(
    { id: 'u_old', ts: '2026-04-30T00:00:00.000Z', kind: 'user', role: 'user', content: 'old '.repeat(300) },
    { id: 'u_tail', ts: '2026-04-30T00:00:01.000Z', kind: 'user', role: 'user', content: 'tail' }
  );
  let firstCallRequest: unknown;

  const runner = createRunner({
    model: {
      async complete(request) {
        if (requestHasContent(request, 'Records to summarize')) {
          return completion('## Objective\nSummarized');
        }
        firstCallRequest = request;
        return completion('{"message":"done"}');
      }
    },
    autoCompact: {
      config: {
        enabled: 'on',
        thresholdRatio: 0.002,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1
      },
      modelConfig: {
        provider: 'openai',
        model: 'gpt-5.2',
        baseUrl: 'https://example.test',
        streaming: 'off'
      }
    }
  });

  await runner.runTurn(session, 'new request');

  assert.equal(session.compactions.length, 1);
  assert.equal(requestHasContent(firstCallRequest, 'COMPACTED SESSION SUMMARY'), true);
});

test('runner cancellation during auto compaction stops before the main model call', async () => {
  const session = await createTempSession();
  const controller = new AbortController();
  const events: string[] = [];
  session.records.push(
    { id: 'u_old', ts: '2026-04-30T00:00:00.000Z', kind: 'user', role: 'user', content: 'old '.repeat(300) },
    { id: 'u_tail', ts: '2026-04-30T00:00:01.000Z', kind: 'user', role: 'user', content: 'tail' }
  );
  let normalCalls = 0;

  const runner = createRunner({
    model: {
      async complete(request) {
        if (requestHasContent(request, 'Records to summarize')) {
          controller.abort();
          return completion('## Objective\nShould not persist');
        }
        normalCalls += 1;
        return completion('{"message":"done"}');
      }
    },
    signal: controller.signal,
    onEvent(event) {
      events.push(event.type);
    },
    autoCompact: {
      config: {
        enabled: 'on',
        contextWindowTokens: 700,
        thresholdRatio: 0.35,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1
      },
      modelConfig: {
        provider: 'openrouter',
        model: 'anthropic/claude-sonnet-4.6',
        baseUrl: 'https://example.test',
        streaming: 'off'
      }
    }
  });

  await assert.rejects(() => runner.runTurn(session, 'new request'), /cancelled/i);

  assert.equal(normalCalls, 0);
  assert.equal(events.includes('compact-error'), false);
  assert.equal(events.includes('error'), true);
});

test('runner treats auto compact off as a hard disable without compact events', async () => {
  const session = await createTempSession();
  session.records.push(
    { id: 'u_old', ts: '2026-04-30T00:00:00.000Z', kind: 'user', role: 'user', content: 'old '.repeat(300) },
    { id: 'u_tail', ts: '2026-04-30T00:00:01.000Z', kind: 'user', role: 'user', content: 'tail' }
  );
  const events: string[] = [];

  const runner = createRunner({
    model: {
      async complete(request) {
        assert.equal(requestHasContent(request, 'Records to summarize'), false);
        return completion('{"message":"done"}');
      }
    },
    onEvent(event) {
      events.push(event.type);
    },
    autoCompact: {
      config: {
        enabled: 'off',
        contextWindowTokens: 700,
        thresholdRatio: 0.35,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1
      },
      modelConfig: {
        provider: 'openrouter',
        model: 'anthropic/claude-sonnet-4.6',
        baseUrl: 'https://example.test',
        streaming: 'off'
      }
    }
  });

  const final = await runner.runTurn(session, 'new request');

  assert.equal(final, 'done');
  assert.equal(session.compactions.length, 0);
  assert.equal(events.includes('compact-start'), false);
  assert.equal(events.includes('compact-skip'), false);
});

test('runner retries once after recognized context overflow and successful compaction', async () => {
  const session = await createTempSession();
  session.records.push(
    { id: 'u_old', ts: '2026-04-30T00:00:00.000Z', kind: 'user', role: 'user', content: 'old '.repeat(300) },
    { id: 'u_tail', ts: '2026-04-30T00:00:01.000Z', kind: 'user', role: 'user', content: 'tail' }
  );
  let normalCalls = 0;

  const runner = createRunner({
    model: {
      async complete(request) {
        if (requestHasContent(request, 'Records to summarize')) {
          return completion('## Objective\nSummarized');
        }
        normalCalls += 1;
        if (normalCalls === 1) {
          throw new Error('context length exceeded, maximum context window is 700 tokens');
        }
        return completion('{"message":"done"}');
      }
    },
    autoCompact: {
      config: {
        enabled: 'on',
        contextWindowTokens: 700,
        thresholdRatio: 0.99,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1
      },
      modelConfig: {
        provider: 'openrouter',
        model: 'anthropic/claude-sonnet-4.6',
        baseUrl: 'https://example.test',
        streaming: 'off'
      }
    }
  });

  const final = await runner.runTurn(session, 'new request');

  assert.equal(final, 'done');
  assert.equal(normalCalls, 2);
  assert.equal(session.compactions.length, 1);
});

test('runner overflow retry can use catalog model metadata for context window', async () => {
  const session = await createTempSession();
  session.records.push({
    id: 'u_old',
    ts: '2026-04-30T00:00:00.000Z',
    kind: 'user',
    role: 'user',
    content: 'old '.repeat(300)
  });
  let normalCalls = 0;

  const catalogContextWindow = resolveModelMetadata('openai', 'gpt-5.2')?.capabilities.contextWindow;
  assert.equal(catalogContextWindow, 128_000);

  const runner = createRunner({
    model: {
      async complete(request) {
        if (requestHasContent(request, 'Records to summarize')) {
          return completion('## Objective\nSummarized');
        }
        normalCalls += 1;
        if (normalCalls === 1) {
          throw new Error('context length exceeded');
        }
        return completion('{"message":"done"}');
      }
    },
    autoCompact: {
      config: {
        enabled: 'on',
        thresholdRatio: 0.99,
        reserveTokens: 100,
        keepRecentTokens: 20,
        minNewTokens: 1
      },
      modelConfig: {
        provider: 'openai',
        model: 'gpt-5.2',
        baseUrl: 'https://example.test',
        streaming: 'off'
      }
    }
  });

  const final = await runner.runTurn(session, 'new request');

  assert.equal(final, 'done');
  assert.equal(normalCalls, 2);
  assert.equal(session.compactions.length, 1);
  assert.equal(session.compactions[0]?.auto?.trigger, 'overflow');
  assert.equal(session.compactions[0]?.auto?.contextWindowTokens, catalogContextWindow);
  assert.equal(session.compactions[0]?.auto?.contextWindowSource, 'model-descriptor');
});

test('createRunner refuses applyPolicy=interactive + headless at construction', () => {
  const stubModel = {} as ModelClient;
  const transactions: TxRunnerOptions = {
    mode: 'edit',
    auto: 'per-turn',
    applyPolicy: 'interactive',
    bashPolicy: 'passthrough',
    headless: true,
    validatorsConfig: {},
    stagedViewConfig: { copyMode: 'auto', bindPaths: [] },
    workspaceId: 'ws',
    workspaceRealPath: '/tmp/ws'
  };
  assert.throws(
    () => createRunner({ model: stubModel, transactions }),
    /interactive requires a TTY/
  );
});

test('createRunner with transactions: undefined still works (tx-off)', () => {
  const stubModel = {} as ModelClient;
  const runner = createRunner({ model: stubModel });
  assert.ok(runner);
  assert.equal(typeof runner.runTurn, 'function');
});
