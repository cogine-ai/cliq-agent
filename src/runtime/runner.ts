import { DEFAULT_POLICY_MODE, MAX_LOOPS } from '../config.js';
import type { InstructionMessage } from '../instructions/types.js';
import type { ModelClient, ModelCompletion } from '../model/types.js';
import { createPolicyEngine } from '../policy/engine.js';
import { parseModelAction } from '../protocol/actions.js';
import { createCheckpoint } from '../session/checkpoints.js';
import { appendRecord, makeId, nowIso, saveSession } from '../session/store.js';
import type { Session } from '../session/types.js';
import { createToolRegistry } from '../tools/registry.js';
import { normalizeToolResultForStorage } from '../tools/results.js';
import type { ToolResult } from '../tools/types.js';
import { buildContextMessages } from './context.js';
import type { RuntimeEventSink } from './events.js';
import { runHooks, type RuntimeHook } from './hooks.js';

export function createRunner({
  model,
  registry = createToolRegistry(),
  hooks = [],
  policy = createPolicyEngine({ mode: DEFAULT_POLICY_MODE }),
  instructions = async () => [],
  onEvent = async () => undefined
}: {
  model: ModelClient;
  registry?: ReturnType<typeof createToolRegistry>;
  hooks?: RuntimeHook[];
  policy?: ReturnType<typeof createPolicyEngine>;
  instructions?: (session: Session) => Promise<InstructionMessage[]>;
  onEvent?: RuntimeEventSink;
}) {
  return {
    async runTurn(session: Session, userInput: string): Promise<string> {
      const cwd = session.cwd;
      try {
        session.lifecycle.status = 'running';
        session.lifecycle.turn += 1;
        session.lifecycle.lastUserInputAt = nowIso();
        await createCheckpoint(cwd, session, { kind: 'auto' });
        await appendRecord(cwd, session, {
          id: makeId('usr'),
          ts: nowIso(),
          kind: 'user',
          role: 'user',
          content: userInput
        });

        await runHooks(hooks, 'beforeTurn', session, userInput);

        for (let i = 0; i < MAX_LOOPS; i += 1) {
          let chunks = 0;
          let chars = 0;
          let activeProvider: ModelCompletion['provider'] | null = null;
          let activeModel: string | null = null;
          let sawModelStart = false;
          let sawModelEnd = false;
          let sawModelError = false;
          let completion: ModelCompletion;

          try {
            completion = await model.complete(buildContextMessages(session, await instructions(session)), {
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
          } catch (error) {
            if (!sawModelError) {
              await onEvent({
                type: 'error',
                stage: 'model',
                message: error instanceof Error ? error.message : String(error)
              });
            }
            throw error;
          }

          if (!sawModelStart) {
            await onEvent({
              type: 'model-start',
              provider: completion.provider,
              model: completion.model,
              streaming: false
            });
          }

          if (!sawModelEnd) {
            await onEvent({ type: 'model-end', provider: completion.provider, model: completion.model });
          }

          const rawContent = completion.content;
          let action;
          try {
            action = parseModelAction(rawContent);
          } catch (error) {
            await onEvent({
              type: 'error',
              stage: 'protocol',
              message: error instanceof Error ? error.message : String(error)
            });
            throw error;
          }

          session.lifecycle.lastAssistantOutputAt = nowIso();
          await appendRecord(cwd, session, {
            id: makeId('ast'),
            ts: nowIso(),
            kind: 'assistant',
            role: 'assistant',
            content: rawContent,
            action
          });

          await runHooks(hooks, 'afterAssistantAction', session, action, rawContent);

          if ('message' in action) {
            const finalMessage = action.message.trim() || '(no content)';
            await runHooks(hooks, 'afterTurn', session, finalMessage);
            await onEvent({ type: 'final', message: finalMessage });
            return finalMessage;
          }

          const { definition } = registry.resolve(action);
          await onEvent({ type: 'tool-start', tool: definition.name, preview: rawContent.slice(0, 120) });
          let result: ToolResult | null = null;
          let authorization: Awaited<ReturnType<typeof policy.authorize>> | null = null;

          try {
            authorization = await policy.authorize(definition);
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            result = {
              tool: definition.name,
              status: 'error',
              content: `TOOL_RESULT ${definition.name} ERROR\npolicy=${policy.mode}\n${message}`,
              meta: {
                policy: policy.mode,
                error: error instanceof Error ? (error.stack ?? error.message) : message
              }
            };
          }

          if (result === null && authorization !== null && !authorization.allowed) {
            result = {
              tool: definition.name,
              status: 'error',
              content: `TOOL_RESULT ${definition.name} ERROR\npolicy=${policy.mode}\n${authorization.reason}`,
              meta: {
                policy: policy.mode,
                reason: authorization.reason
              }
            };
          } else if (result === null && authorization !== null) {
            await runHooks(hooks, 'beforeTool', session, action);
            try {
              result = await definition.execute(action as never, { cwd, session });
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              result = {
                tool: definition.name,
                status: 'error',
                content: `TOOL_RESULT ${definition.name} ERROR\n${message}`,
                meta: {
                  error: error instanceof Error ? (error.stack ?? error.message) : message
                }
              };
            }
          }

          if (result === null) {
            throw new Error(`No tool result produced for ${definition.name}`);
          }

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
        }

        throw new Error('Exceeded action loop limit');
      } finally {
        session.lifecycle.status = 'idle';
        await saveSession(cwd, session);
      }
    }
  };
}
