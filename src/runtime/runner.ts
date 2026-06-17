import { DEFAULT_POLICY_MODE, MAX_LOOPS } from '../config.js';
import { formatHookFailureReason, runCommandHooks, type CommandHookRunResult } from '../hooks/runner.js';
import type { HookEventName, HookInput, HooksConfig } from '../hooks/types.js';
import type { InstructionMessage } from '../instructions/types.js';
import { classifyContextOverflow } from '../model/errors.js';
import { resolveModelMetadata } from '../model/catalog/index.js';
import { buildModelPromptRequest } from '../model/prompt.js';
import type {
  ChatMessage,
  ModelCapabilities,
  ModelClient,
  ModelCompletion,
  ModelPromptRequest,
  ModelStructuredOutput,
  ModelToolCall,
  ResolvedModelConfig
} from '../model/types.js';
import { finalizePlan, readPlanArtifact, readPlanProgress } from '../plans/store.js';
import { createPolicyEngine } from '../policy/engine.js';
import { buildToolApprovalSubject } from '../policy/subjects.js';
import type { ApprovalDecision, PolicyConfirm } from '../policy/types.js';
import { parseModelAction } from '../protocol/model/actions.js';
import { resolveAutoCompactConfig, type AutoCompactConfig } from '../session/auto-compact-config.js';
import { maybeAutoCompact, type AutoCompactState } from '../session/auto-compaction.js';
import { createCheckpoint } from '../session/checkpoints.js';
import { appendRecord, makeId, nowIso, resolveCliqHome, saveSession } from '../session/store.js';
import type { Session } from '../session/types.js';
import { createToolRegistry } from '../tools/registry.js';
import { normalizeToolResultForStorage } from '../tools/results.js';
import type { ToolContextTxFacade, ToolResult } from '../tools/types.js';
import { appendBashEffect } from '../workspace/transactions/bash-effects.js';
import { createOverlayWriter } from '../workspace/transactions/overlay.js';
import { overlayDir, resolveTxRoot } from '../workspace/transactions/store.js';
import { buildContextMessages, buildPromptInput } from './context.js';
import type { RuntimeEventSink } from '../protocol/runtime/events.js';
import { runHooks, type RuntimeHook } from './hooks.js';
import {
  assertHeadlessCompatible,
  finishTurnTx,
  openTurnTx,
  type CoordinatorCtx,
  type TxRunnerOptions
} from './tx-runner.js';
import type { WorkspaceWriter } from './workspace-writer.js';

type AutoCompactRunnerOptions = {
  config: AutoCompactConfig;
  modelConfig: ResolvedModelConfig;
};

type BuiltInToolRegistry = ReturnType<typeof createToolRegistry>;
type RuntimeToolRegistry = Pick<BuiltInToolRegistry, 'definitions' | 'resolve'> &
  Partial<Pick<BuiltInToolRegistry, 'modelVisibleToolSpecs' | 'resolveToolCall'>>;

type ModelAttemptResult =
  | { ok: true; completion: ModelCompletion }
  | { ok: false; error: unknown; sawModelError: boolean };

const FALLBACK_MODEL_CAPABILITIES: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: false
};

function isAbortError(error: unknown) {
  if (!error || typeof error !== 'object') {
    return false;
  }

  const candidate = error as { name?: unknown; code?: unknown; cancelled?: unknown };
  return (
    candidate.cancelled === true ||
    candidate.name === 'AbortError' ||
    candidate.code === 'ERR_ABORTED' ||
    candidate.code === 'ABORT_ERR'
  );
}

function runtimeModelConfig(session: Session): ResolvedModelConfig {
  return {
    provider: session.model.provider,
    model: session.model.model,
    baseUrl: session.model.baseUrl ?? '',
    streaming: session.model.streaming ?? 'auto'
  };
}

function runtimeModelCapabilities(session: Session): ModelCapabilities {
  return resolveModelMetadata(session.model.provider, session.model.model)?.capabilities ?? FALLBACK_MODEL_CAPABILITIES;
}

function toolCallFromStructuredOutput(output: Extract<ModelStructuredOutput, { type: 'tool' }>): ModelToolCall {
  return {
    id: output.callId ?? makeId('call'),
    name: output.tool,
    arguments: output.arguments
  };
}

function resolveStructuredToolCall(registry: RuntimeToolRegistry, call: ModelToolCall) {
  if (!registry.resolveToolCall) {
    throw new Error(`Runtime registry cannot resolve structured tool call: ${call.name}`);
  }
  return registry.resolveToolCall(call);
}

export function createRunner({
  model,
  registry = createToolRegistry(),
  hooks = [],
  commandHooks = {},
  policy = createPolicyEngine({ mode: DEFAULT_POLICY_MODE }),
  instructions = async () => [],
  onEvent = async () => undefined,
  autoCompact,
  signal: defaultSignal,
  transactions,
  confirm
}: {
  model: ModelClient;
  registry?: RuntimeToolRegistry;
  hooks?: RuntimeHook[];
  commandHooks?: HooksConfig;
  policy?: ReturnType<typeof createPolicyEngine>;
  confirm?: PolicyConfirm;
  instructions?: (session: Session) => Promise<InstructionMessage[]>;
  onEvent?: RuntimeEventSink;
  autoCompact?: AutoCompactRunnerOptions;
  signal?: AbortSignal;
  transactions?: TxRunnerOptions;
}) {
  if (transactions) {
    assertHeadlessCompatible(transactions);
  }

  async function emitCommandHookWarning(eventName: HookEventName, run: CommandHookRunResult) {
    await onEvent({
      type: 'error',
      stage: eventName === 'PermissionRequest' ? 'policy' : 'tool',
      message: `${eventName} hook failed (${run.hook.command}): ${formatHookFailureReason(run.result)}`,
      recoverable: true
    });
  }

  async function runNonBlockingCommandHookEvent(input: HookInput) {
    for (const run of await runCommandHooks(commandHooks, input, { cwd: input.cwd })) {
      if (run.result.status !== 'ok') {
        await emitCommandHookWarning(input.hookEventName, run);
      }
    }
  }

  async function runPreToolUseHooks(input: HookInput): Promise<ApprovalDecision | null> {
    for (const run of await runCommandHooks(commandHooks, input, { cwd: input.cwd })) {
      if (run.result.status === 'denied') {
        return {
          behavior: 'deny',
          reason: formatHookFailureReason(run.result),
          decidedBy: 'hook'
        };
      }
      if (run.result.status === 'error') {
        if (run.hook.required) {
          return {
            behavior: 'deny',
            reason: `required PreToolUse hook failed: ${formatHookFailureReason(run.result)}`,
            decidedBy: 'hook'
          };
        }
        await emitCommandHookWarning('PreToolUse', run);
      }
    }
    return null;
  }

  async function runPermissionRequestHooks(input: HookInput): Promise<ApprovalDecision | null> {
    for (const run of await runCommandHooks(commandHooks, input, { cwd: input.cwd })) {
      if (run.result.status === 'denied') {
        return {
          behavior: 'deny',
          reason: formatHookFailureReason(run.result),
          decidedBy: 'hook'
        };
      }
      if (run.result.status === 'error') {
        await emitCommandHookWarning('PermissionRequest', run);
        continue;
      }
      const permissionDecision = run.result.output?.permissionDecision;
      if (permissionDecision?.behavior === 'allow') {
        // Hook allows are always one-shot. Session/workspace persistence is
        // only available through the TUI approval modal (extendApprovalScope).
        return {
          behavior: 'allow',
          reason: permissionDecision.message,
          decidedBy: 'hook'
        };
      }
      if (permissionDecision?.behavior === 'deny') {
        return {
          behavior: 'deny',
          reason: permissionDecision.message ?? 'permission request denied by hook',
          decidedBy: 'hook'
        };
      }
    }
    return null;
  }

  return {
    async runTurn(
      session: Session,
      userInput: string,
      opts: { signal?: AbortSignal } = {}
    ): Promise<string> {
      // Per-turn signal takes precedence so the TUI can abort an active turn
      // without poisoning subsequent turns. Falls back to the construction-
      // time signal for callers that pre-date the per-turn channel.
      const signal = opts.signal ?? defaultSignal;
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
      const previousLifecycle = {
        status: session.lifecycle.status,
        turn: session.lifecycle.turn,
        lastUserInputAt: session.lifecycle.lastUserInputAt,
        lastAssistantOutputAt: session.lifecycle.lastAssistantOutputAt
      };
      let checkpointCreated = false;

      try {
        if (signal?.aborted) {
          await throwCancelled();
        }
        session.lifecycle.status = 'running';
        session.lifecycle.turn += 1;
        await throwIfCancelled();
        const checkpoint = await createCheckpoint(cwd, session, { kind: 'auto' });
        checkpointCreated = true;
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
        await runNonBlockingCommandHookEvent({
          schemaVersion: 1,
          hookEventName: 'UserPromptSubmit',
          sessionId: session.id,
          cwd,
          prompt: userInput,
          model: session.model?.model
        });
        await throwIfCancelled();

        // Tx open at turn start (if tx mode is on).
        let activeTxFromTxRunner: Awaited<ReturnType<typeof openTurnTx>>['tx'] = null;
        let txOpenedThisTurn = false;
        let coordinatorCtx: CoordinatorCtx | null = null;
        if (transactions) {
          coordinatorCtx = {
            cwd,
            session,
            cliqHome: transactions.cliqHome,
            workspaceId: transactions.workspaceId,
            sessionId: session.id,
            workspaceRealPath: transactions.workspaceRealPath
          };
          const opened = await openTurnTx(coordinatorCtx, transactions, async (e) => {
            await onEvent(e);
          });
          activeTxFromTxRunner = opened.tx;
          txOpenedThisTurn = opened.opened;
        }
        await throwIfCancelled();

        await runHooks(hooks, 'beforeTurn', session, userInput);

        const finishWithFinalMessage = async (finalMessage: string): Promise<string> => {
          await runHooks(hooks, 'afterTurn', session, finalMessage);
          // Only finalize/validate/apply when this turn auto-opened the tx. For
          // reused explicit tx (txOpenedThisTurn === false), the user drives
          // lifecycle via `cliq tx validate/approve/apply`.
          if (transactions && activeTxFromTxRunner && txOpenedThisTurn && coordinatorCtx) {
            await finishTurnTx(coordinatorCtx, transactions, activeTxFromTxRunner, async (e) => {
              await onEvent(e);
            });
          }
          await runNonBlockingCommandHookEvent({
            schemaVersion: 1,
            hookEventName: 'Stop',
            sessionId: session.id,
            cwd,
            finalMessage,
            model: session.model?.model
          });
          await onEvent({ type: 'final', message: finalMessage });
          return finalMessage;
        };

        const finishPlanForReview = async (planId: string): Promise<string> => {
          const plan = await readPlanArtifact(cwd, session, planId);
          await onEvent({
            type: 'plan-finalized',
            plan: {
              id: plan.id,
              title: plan.title,
              contentMarkdown: plan.contentMarkdown,
              items: plan.items,
              path: plan.paths.json,
              markdownPath: plan.paths.markdown
            }
          });
          return await finishWithFinalMessage(`Plan ready for review: ${plan.title}`);
        };

        const autoCompactState: AutoCompactState = {
          thresholdCompactionsThisTurn: 0,
          thresholdSuppressed: false
        };
        const repeatedReadOnlyDenials = new Map<string, number>();
        let lastPlanIdThisTurn: string | null = null;

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
            const promptRequest = buildModelPromptRequest({
              modelConfig: runtimeModelConfig(session),
              modelCapabilities: runtimeModelCapabilities(session),
              instructions: currentInstructions,
              input: buildPromptInput(session),
              registry
            });
            const completion = await model.complete(promptRequest, {
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
            const effectiveRequest = completion.effectiveRequest;
            if (!effectiveRequest) {
              throw new Error('ModelClient.complete must return effectiveRequest');
            }
            await throwIfCancelled();

            if (!sawModelStart) {
              await onEvent({
                type: 'model-start',
                provider: completion.provider,
                model: completion.model,
                streaming: effectiveRequest.streaming
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

          const metadata = resolveModelMetadata(autoCompact.modelConfig.provider, autoCompact.modelConfig.model);
          const resolvedAutoCompact = resolveAutoCompactConfig({
            config: autoCompact.config,
            modelContextWindowTokens: metadata?.capabilities.contextWindow,
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
            const metadata =
              autoCompact === undefined
                ? null
                : resolveModelMetadata(autoCompact.modelConfig.provider, autoCompact.modelConfig.model);
            const resolvedOverflowLimit =
              autoCompact && overflow
                ? resolveAutoCompactConfig({
                    config: autoCompact.config,
                    modelContextWindowTokens: metadata?.capabilities.contextWindow,
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
          let modelToolCall: ModelToolCall | undefined;
          let action;
          try {
            const firstToolCall = completion.toolCalls?.[0];
            if (firstToolCall) {
              modelToolCall = firstToolCall;
              action = resolveStructuredToolCall(registry, firstToolCall).action;
            } else if (completion.structuredOutput) {
              if (completion.structuredOutput.type === 'final') {
                action = { message: completion.structuredOutput.message };
              } else {
                modelToolCall = toolCallFromStructuredOutput(completion.structuredOutput);
                action = resolveStructuredToolCall(registry, modelToolCall).action;
              }
            } else if (completion.effectiveRequest!.mode === 'native-tools') {
              action = { message: rawContent };
            } else {
              action = parseModelAction(rawContent);
            }
          } catch (error) {
            await onEvent({
              type: 'error',
              stage: 'protocol',
              message: error instanceof Error ? error.message : String(error)
            });
            throw error;
          }
          await throwIfCancelled();

          const assistantTs = nowIso();
          await appendRecord(cwd, session, {
            id: makeId('ast'),
            ts: assistantTs,
            kind: 'assistant',
            role: 'assistant',
            content: rawContent,
            action,
            ...(modelToolCall ? { toolCalls: [modelToolCall] } : {})
          });
          session.lifecycle.lastAssistantOutputAt = assistantTs;

          await runHooks(hooks, 'afterAssistantAction', session, action, rawContent);
          await throwIfCancelled();

          if ('message' in action) {
            if (policy.mode === 'plan') {
              if (lastPlanIdThisTurn) {
                await finalizePlan(cwd, session, { planId: lastPlanIdThisTurn });
                return await finishPlanForReview(lastPlanIdThisTurn);
              }
              const message = 'Plan Mode requires a plan artifact before returning a final message.';
              await onEvent({ type: 'error', stage: 'policy', message });
              throw new Error(message);
            }
            const finalMessage = action.message.trim() || '(no content)';
            return await finishWithFinalMessage(finalMessage);
          }

          const { definition } = registry.resolve(action);
          const subject = buildToolApprovalSubject({
            definition,
            action,
            ...(transactions
              ? {
                  tx: {
                    enabled: true,
                    ...(activeTxFromTxRunner ? { txId: activeTxFromTxRunner.id } : {}),
                    mode: transactions.mode
                  }
                }
              : {})
          });
          await onEvent({ type: 'tool-start', tool: definition.name, preview: rawContent.slice(0, 120) });
          await throwIfCancelled();
          let result: ToolResult | null = null;
          let decision: ApprovalDecision | null = null;
          let hookDenyEventName: 'PreToolUse' | 'PermissionRequest' | null = null;

          await throwIfCancelled();
          try {
            decision = await runPreToolUseHooks({
              schemaVersion: 1,
              hookEventName: 'PreToolUse',
              sessionId: session.id,
              cwd,
              toolName: definition.name,
              action,
              approvalSubject: subject,
              model: session.model?.model
            });
            if (decision?.behavior === 'deny' && decision.decidedBy === 'hook') {
              hookDenyEventName = 'PreToolUse';
            }
            if (decision === null) {
              decision = await policy.decide(subject);
              if (decision.behavior === 'ask') {
                const hookDecision = await runPermissionRequestHooks({
                  schemaVersion: 1,
                  hookEventName: 'PermissionRequest',
                  sessionId: session.id,
                  cwd,
                  toolName: definition.name,
                  action,
                  approvalSubject: subject,
                  model: session.model?.model
                });
                if (hookDecision) {
                  decision = hookDecision;
                  if (decision.behavior === 'deny') {
                    hookDenyEventName = 'PermissionRequest';
                  }
                } else if (!confirm) {
                  decision = {
                    behavior: 'deny',
                    reason: 'confirmation required but no confirmer is available',
                    decidedBy: 'policy'
                  };
                } else {
                  const approved = await confirm(decision.prompt);
                  decision = approved
                    ? { behavior: 'allow', decidedBy: 'user' }
                    : { behavior: 'deny', reason: 'user declined confirmation', decidedBy: 'user' };
                }
              }
            }
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

          if (result === null && decision !== null && decision.behavior === 'deny') {
            result = {
              tool: definition.name,
              status: 'error',
              content: `TOOL_RESULT ${definition.name} ERROR\npolicy=${policy.mode}\n${decision.reason}`,
              meta: {
                policy: policy.mode,
                reason: decision.reason,
                ...(hookDenyEventName ? { hookEventName: hookDenyEventName } : {})
              }
            };
          } else if (result === null && decision !== null) {
            await throwIfCancelled();
            await runHooks(hooks, 'beforeTool', session, action);
            await throwIfCancelled();
            try {
              let writer: WorkspaceWriter | undefined;
              let txFacade: ToolContextTxFacade | undefined;
              if (transactions && activeTxFromTxRunner) {
                const root = resolveTxRoot(transactions.cliqHome ?? resolveCliqHome());
                const txId = activeTxFromTxRunner.id;
                writer = createOverlayWriter(cwd, overlayDir(root, txId));
                txFacade = {
                  mode: transactions.mode,
                  bashPolicy: transactions.bashPolicy,
                  txId,
                  headless: transactions.headless,
                  recordBashEffect: async (eff) => {
                    await appendBashEffect(root, txId, eff);
                  }
                };
              }
              result = await definition.execute(action as never, {
                cwd,
                session,
                signal,
                writer,
                tx: txFacade
              });
            } catch (error) {
              if (signal?.aborted || isAbortError(error)) {
                await throwCancelled();
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

          let storedResult = normalizeToolResultForStorage(result);
          if (modelToolCall) {
            storedResult = {
              ...storedResult,
              meta: {
                ...storedResult.meta,
                modelToolCallId: modelToolCall.id
              }
            };
          }
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
          await runNonBlockingCommandHookEvent({
            schemaVersion: 1,
            hookEventName: 'PostToolUse',
            sessionId: session.id,
            cwd,
            toolName: definition.name,
            action,
            approvalSubject: subject,
            toolResult: storedResult,
            model: session.model?.model
          });
          await runHooks(hooks, 'afterTool', session, storedResult);
          await onEvent({ type: 'tool-end', tool: storedResult.tool, status: storedResult.status });
          const completedPlanId =
            storedResult.tool === 'plan' &&
            storedResult.status === 'ok' &&
            typeof storedResult.meta.planId === 'string'
              ? storedResult.meta.planId
              : null;
          if (completedPlanId) {
            lastPlanIdThisTurn = completedPlanId;
          }
          const updatedProgressPlanId =
            storedResult.tool === 'todo' &&
            storedResult.status === 'ok' &&
            typeof storedResult.meta.planId === 'string'
              ? storedResult.meta.planId
              : null;
          if (updatedProgressPlanId) {
            const progress = await readPlanProgress(cwd, session, updatedProgressPlanId);
            await onEvent({
              type: 'plan-progress-updated',
              progress: {
                planId: progress.planId,
                title: progress.title,
                path: progress.paths.json,
                items: progress.items
              }
            });
          }
          const finalizedPlanId =
            storedResult.tool === 'plan' &&
            storedResult.status === 'ok' &&
            storedResult.meta.planStatus === 'finalized' &&
            typeof storedResult.meta.planId === 'string'
              ? storedResult.meta.planId
              : null;
          if (finalizedPlanId) {
            return await finishPlanForReview(finalizedPlanId);
          }
          if (
            decision?.behavior === 'deny' &&
            decision.decidedBy === 'policy' &&
            policy.mode === 'plan' &&
            subject.kind === 'tool' &&
            subject.access !== 'read' &&
            subject.access !== 'plan'
          ) {
            const blockedKey = `${subject.access}:${definition.name}`;
            const blockedCount = (repeatedReadOnlyDenials.get(blockedKey) ?? 0) + 1;
            repeatedReadOnlyDenials.set(blockedKey, blockedCount);
            if (blockedCount >= 2) {
              const message = `plan mode repeatedly blocked ${subject.access} tool ${definition.name}; switch policy mode or use inspection tools.`;
              await onEvent({ type: 'error', stage: 'policy', message });
              throw new Error(message);
            }
          }
          await throwIfCancelled();
        }

        throw new Error('Exceeded action loop limit');
      } finally {
        if (!checkpointCreated) {
          session.lifecycle.status = previousLifecycle.status;
          session.lifecycle.turn = previousLifecycle.turn;
          session.lifecycle.lastUserInputAt = previousLifecycle.lastUserInputAt;
          session.lifecycle.lastAssistantOutputAt = previousLifecycle.lastAssistantOutputAt;
        } else {
          session.lifecycle.status = 'idle';
        }
        await saveSession(cwd, session);
      }
    }
  };
}
