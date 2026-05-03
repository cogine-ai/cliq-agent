import { DEFAULT_POLICY_MODE, MAX_LOOPS } from '../config.js';
import type { InstructionMessage } from '../instructions/types.js';
import { classifyContextOverflow } from '../model/errors.js';
import { findKnownModelDescriptor } from '../model/registry.js';
import type { ChatMessage, ModelClient, ModelCompletion, ResolvedModelConfig } from '../model/types.js';
import { createPolicyEngine } from '../policy/engine.js';
import { parseModelAction } from '../protocol/actions.js';
import { resolveAutoCompactConfig, type AutoCompactConfig } from '../session/auto-compact-config.js';
import { maybeAutoCompact, type AutoCompactState } from '../session/auto-compaction.js';
import { createCheckpoint } from '../session/checkpoints.js';
import { appendRecord, makeId, nowIso, saveSession } from '../session/store.js';
import type { Session } from '../session/types.js';
import { createToolRegistry } from '../tools/registry.js';
import { normalizeToolResultForStorage } from '../tools/results.js';
import type { ToolResult } from '../tools/types.js';
import { buildContextMessages } from './context.js';
import type { RuntimeEventSink } from './events.js';
import { runHooks, type RuntimeHook } from './hooks.js';

type AutoCompactRunnerOptions = {
  config: AutoCompactConfig;
  modelConfig: ResolvedModelConfig;
};

type ModelAttemptResult =
  | { ok: true; completion: ModelCompletion }
  | { ok: false; error: unknown; sawModelError: boolean };

function isAbortError(error: unknown) {
  return error instanceof Error && error.name === 'AbortError';
}

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
  return {
    async runTurn(session: Session, userInput: string): Promise<string> {
      const cwd = session.cwd;
      const throwCancelled = async (): Promise<never> => {
        await onEvent({ type: 'error', stage: 'cancel', message: 'run cancelled' });
        throw new Error('run cancelled');
      };
      const throwIfCancelled = async () => {
        if (signal?.aborted) {
          await throwCancelled();
        }
      };

      try {
        if (signal?.aborted) {
          await throwCancelled();
        }
        session.lifecycle.status = 'running';
        session.lifecycle.turn += 1;
        await throwIfCancelled();
        const checkpoint = await createCheckpoint(cwd, session, { kind: 'auto' });
        const warning =
          checkpoint.workspaceCheckpoint.kind === 'unavailable'
            ? checkpoint.workspaceCheckpoint.error ?? checkpoint.workspaceCheckpoint.reason
            : undefined;
        await onEvent({
          type: 'checkpoint-created',
          checkpointId: checkpoint.id,
          kind: checkpoint.kind,
          ...(checkpoint.workspaceCheckpointId ? { workspaceCheckpointId: checkpoint.workspaceCheckpointId } : {}),
          workspaceSnapshotStatus: checkpoint.workspaceCheckpoint.status,
          ...(warning ? { warning } : {})
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

        await runHooks(hooks, 'beforeTurn', session, userInput);

        const autoCompactState: AutoCompactState = {
          thresholdCompactionsThisTurn: 0,
          thresholdSuppressed: false
        };

        const emitModelError = async (error: unknown) => {
          await onEvent({
            type: 'error',
            stage: 'model',
            message: error instanceof Error ? error.message : String(error)
          });
        };

        const completeModel = async (currentInstructions: InstructionMessage[]): Promise<ModelAttemptResult> => {
          let chunks = 0;
          let chars = 0;
          let activeProvider: ModelCompletion['provider'] | null = null;
          let activeModel: string | null = null;
          let sawModelStart = false;
          let sawModelEnd = false;
          let sawModelError = false;

          try {
            await throwIfCancelled();
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
            await throwIfCancelled();

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

            return { ok: true, completion };
          } catch (error) {
            if (signal?.aborted) {
              await throwIfCancelled();
            }
            return { ok: false, error, sawModelError };
          }
        };

        const runAutoCompact = async ({
          trigger,
          phase,
          currentInstructions,
          overflowContextWindowTokens
        }: {
          trigger: 'threshold' | 'overflow';
          phase: 'pre-model' | 'mid-loop';
          currentInstructions: ChatMessage[];
          overflowContextWindowTokens?: number;
        }) => {
          await throwIfCancelled();
          if (!autoCompact) {
            return null;
          }

          const descriptor = findKnownModelDescriptor(autoCompact.modelConfig.provider, autoCompact.modelConfig.model);
          const resolvedAutoCompact = resolveAutoCompactConfig({
            config: autoCompact.config,
            modelContextWindowTokens: descriptor?.capabilities.contextWindow,
            overflowContextWindowTokens
          });

          if (resolvedAutoCompact.enabled === 'off') {
            return null;
          }

          await onEvent({ type: 'compact-start', trigger, phase });
          await throwIfCancelled();
          const compactResult = await maybeAutoCompact({
            cwd,
            session,
            model,
            modelConfig: autoCompact.modelConfig,
            config: resolvedAutoCompact,
            instructions: currentInstructions,
            phase,
            trigger,
            state: autoCompactState,
            signal
          });
          await throwIfCancelled();

          if (compactResult.status === 'compacted') {
            await onEvent({
              type: 'compact-end',
              artifactId: compactResult.artifact.id,
              estimatedTokensBefore: compactResult.estimatedTokensBefore,
              estimatedTokensAfter: compactResult.estimatedTokensAfter
            });
          } else if (compactResult.status === 'error') {
            if (trigger === 'threshold') {
              autoCompactState.thresholdSuppressed = true;
            }
            await onEvent({ type: 'compact-error', trigger, message: compactResult.error.message });
          } else {
            await onEvent({ type: 'compact-skip', reason: compactResult.reason });
          }

          return compactResult;
        };

        for (let i = 0; i < MAX_LOOPS; i += 1) {
          await throwIfCancelled();
          let completion: ModelCompletion;
          let currentInstructions = await instructions(session);
          const phase = i === 0 ? 'pre-model' : 'mid-loop';

          const thresholdResult = await runAutoCompact({ trigger: 'threshold', phase, currentInstructions });
          if (thresholdResult?.status === 'compacted') {
            currentInstructions = await instructions(session);
          }

          let modelAttempt = await completeModel(currentInstructions);
          let overflowRetries = 0;
          while (!modelAttempt.ok) {
            const overflow = classifyContextOverflow(modelAttempt.error);
            const resolvedOverflowLimit =
              autoCompact && overflow
                ? resolveAutoCompactConfig({
                    config: autoCompact.config,
                    modelContextWindowTokens: findKnownModelDescriptor(
                      autoCompact.modelConfig.provider,
                      autoCompact.modelConfig.model
                    )?.capabilities.contextWindow,
                    overflowContextWindowTokens: overflow.contextWindowTokens
                  }).maxOverflowRetriesPerModelCall
                : 0;

            if (!overflow || !autoCompact || overflowRetries >= resolvedOverflowLimit) {
              if (overflow && autoCompact && overflowRetries >= resolvedOverflowLimit) {
                await onEvent({ type: 'compact-skip', reason: 'max-overflow-retries' });
              }
              if (!modelAttempt.sawModelError) {
                await emitModelError(modelAttempt.error);
              }
              throw modelAttempt.error;
            }

            const overflowInstructions = await instructions(session);
            await throwIfCancelled();
            const overflowResult = await runAutoCompact({
              trigger: 'overflow',
              phase,
              currentInstructions: overflowInstructions,
              overflowContextWindowTokens: overflow.contextWindowTokens
            });
            if (overflowResult?.status !== 'compacted') {
              if (!modelAttempt.sawModelError) {
                await emitModelError(modelAttempt.error);
              }
              throw modelAttempt.error;
            }

            overflowRetries += 1;
            const retryInstructions = await instructions(session);
            await throwIfCancelled();
            modelAttempt = await completeModel(retryInstructions);
          }
          completion = modelAttempt.completion;
          await throwIfCancelled();

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
          await throwIfCancelled();

          if ('message' in action) {
            const finalMessage = action.message.trim() || '(no content)';
            await runHooks(hooks, 'afterTurn', session, finalMessage);
            await onEvent({ type: 'final', message: finalMessage });
            return finalMessage;
          }

          const { definition } = registry.resolve(action);
          await onEvent({ type: 'tool-start', tool: definition.name, preview: rawContent.slice(0, 120) });
          await throwIfCancelled();
          let result: ToolResult | null = null;
          let authorization: Awaited<ReturnType<typeof policy.authorize>> | null = null;

          await throwIfCancelled();
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
            await throwIfCancelled();
            await runHooks(hooks, 'beforeTool', session, action);
            await throwIfCancelled();
            try {
              result = await definition.execute(action as never, { cwd, session, signal });
            } catch (error) {
              if (signal?.aborted || isAbortError(error)) {
                await throwIfCancelled();
                throw error;
              }
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
          await throwIfCancelled();
        }

        throw new Error('Exceeded action loop limit');
      } finally {
        session.lifecycle.status = 'idle';
        await saveSession(cwd, session);
      }
    }
  };
}
