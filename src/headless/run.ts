import { stat, realpath } from 'node:fs/promises';

import { DEFAULT_POLICY_MODE } from '../config.js';
import { formatHookFailureReason, runCommandHooks } from '../hooks/runner.js';
import type { HooksConfig } from '../hooks/types.js';
import { resolveModelConfig } from '../model/config.js';
import type { PartialModelConfig } from '../model/config.js';
import { createModelClient } from '../model/index.js';
import type { ModelClient, ResolvedModelConfig } from '../model/types.js';
import { createPolicyEngine } from '../policy/engine.js';
import type { PolicyConfirm, PolicyMode } from '../policy/types.js';
import type { RuntimeErrorCode } from '../protocol/runtime/errors.js';
import { createRuntimeAssembly } from '../runtime/assembly.js';
import type { RuntimeHook } from '../runtime/hooks.js';
import { createRunner } from '../runtime/runner.js';
import type { TxRunnerOptions } from '../runtime/tx-runner.js';
import { ensureFresh, ensureSession, makeId, resolveCliqHome, workspaceIdFromRealPath } from '../session/store.js';
import type { Session } from '../session/types.js';
import {
  createWorkspaceTrustContext,
  evaluateWorkspaceTrustForNonInteractive
} from '../session/trust.js';
import { recoverAtStart, type CoordinatorContext } from '../workspace/transactions/coordinator.js';
import {
  emptyHeadlessArtifacts,
  HEADLESS_EXIT_CANCELLED,
  HEADLESS_EXIT_FAILURE,
  HEADLESS_EXIT_SUCCESS,
  type HeadlessErrorStage,
  type HeadlessRunError,
  type HeadlessRunOptions,
  type HeadlessRunOutput,
  type HeadlessRunRequest,
  type RuntimeEventEnvelope
} from './contract.js';
import { createHeadlessEventFactory, mergeArtifacts, runtimeEventToHeadless } from './events.js';

export type RunHeadlessDependencies = {
  modelClient?: ModelClient;
  createModelClient?: (config: ResolvedModelConfig) => ModelClient;
  confirm?: PolicyConfirm;
  hooks?: RuntimeHook[];
};

type RunScope = {
  session: Session;
  modelConfig: ResolvedModelConfig;
  policy: PolicyMode;
  intendedTurn: number;
};

const POLICY_MODES = new Set<PolicyMode>(['auto', 'confirm-write', 'read-only', 'confirm-bash', 'confirm-all']);

function errorFrom(
  code: RuntimeErrorCode,
  stage: HeadlessErrorStage,
  message: string,
  recoverable = false
): HeadlessRunError {
  return { code, stage, message, recoverable };
}

function isHeadlessRunError(error: unknown): error is HeadlessRunError {
  return (
    !!error &&
    typeof error === 'object' &&
    typeof (error as HeadlessRunError).code === 'string' &&
    typeof (error as HeadlessRunError).stage === 'string' &&
    typeof (error as HeadlessRunError).message === 'string' &&
    typeof (error as HeadlessRunError).recoverable === 'boolean'
  );
}

function isCancelledError(error: unknown) {
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

async function validateRequest(request: HeadlessRunRequest) {
  if (!request.prompt?.trim()) {
    throw errorFrom('invalid-input', 'input', 'prompt is required');
  }
  if (!request.cwd?.trim()) {
    throw errorFrom('invalid-input', 'input', 'cwd is required');
  }
  if (request.policy !== undefined && !POLICY_MODES.has(request.policy)) {
    throw errorFrom('invalid-input', 'input', `unknown policy mode: ${request.policy}`);
  }
  if (request.skills !== undefined && !Array.isArray(request.skills)) {
    throw errorFrom('invalid-input', 'input', 'skills must be an array of strings');
  }
  if (request.skills?.some((skill) => typeof skill !== 'string')) {
    throw errorFrom('invalid-input', 'input', 'skills must be an array of strings');
  }

  const cwdStat = await stat(request.cwd).catch(() => null);
  if (!cwdStat?.isDirectory()) {
    throw errorFrom('invalid-input', 'input', `cwd must be an existing directory: ${request.cwd}`);
  }

  const sessionKeys = request.session ? Object.keys(request.session) : [];
  for (const key of sessionKeys) {
    if (key !== 'mode') {
      throw errorFrom('invalid-input', 'input', `unknown session field: ${key}`);
    }
  }
  if (request.session?.mode && request.session.mode !== 'active' && request.session.mode !== 'new') {
    throw errorFrom('invalid-input', 'input', `unknown session mode: ${request.session.mode}`);
  }
}

function scopeEnvelope(scope: RunScope | undefined) {
  return scope
    ? {
        sessionId: scope.session.id,
        turn: scope.intendedTurn
      }
    : {};
}

function errorStatus(error: HeadlessRunError): 'failed' | 'cancelled' {
  return error.code === 'cancelled' ? 'cancelled' : 'failed';
}

function normalizeCaughtError(error: unknown): HeadlessRunError {
  if (isHeadlessRunError(error)) {
    return error;
  }

  const message = error instanceof Error ? error.message : String(error);
  if (isCancelledError(error)) {
    return errorFrom('cancelled', 'cancel', message);
  }

  if (/\bapi key is required\b/i.test(message) || /\b[A-Z0-9_]+_API_KEY\b/.test(message)) {
    return errorFrom('model-auth-error', 'assembly', message, true);
  }

  if (
    /unknown model provider/i.test(message) ||
    /invalid streaming mode/i.test(message) ||
    /model is required/i.test(message) ||
    /baseUrl is required/i.test(message) ||
    /no model provider or local ollama model configured/i.test(message)
  ) {
    return errorFrom('config-error', 'assembly', message, true);
  }

  return errorFrom('internal-error', 'assembly', message);
}

async function runHeadlessSessionStartHooks({
  commandHooks,
  cwd,
  session,
  modelConfig,
  emitWarning
}: {
  commandHooks: HooksConfig;
  cwd: string;
  session: Session;
  modelConfig: ResolvedModelConfig;
  emitWarning(message: string): Promise<void>;
}) {
  for (const run of await runCommandHooks(
    commandHooks,
    {
      schemaVersion: 1,
      hookEventName: 'SessionStart',
      sessionId: session.id,
      cwd,
      model: modelConfig.model
    },
    { cwd }
  )) {
    if (run.result.status === 'denied') {
      throw errorFrom('tool-error', 'tool', `SessionStart hook denied: ${formatHookFailureReason(run.result)}`, true);
    }
    if (run.result.status === 'error') {
      const message = `${run.hook.required ? 'required ' : ''}SessionStart hook failed: ${formatHookFailureReason(
        run.result
      )}`;
      if (run.hook.required) {
        throw errorFrom('tool-error', 'tool', message, true);
      }
      await emitWarning(message);
    }
  }
}

export async function runHeadless(
  request: HeadlessRunRequest,
  options: HeadlessRunOptions & RunHeadlessDependencies = {}
): Promise<HeadlessRunOutput> {
  const runId = options.runId ?? makeId('run');
  const artifacts = emptyHeadlessArtifacts();
  const createEvent = createHeadlessEventFactory({ runId });
  let scope: RunScope | undefined;
  let runtimeError: HeadlessRunError | undefined;

  const emit = async (event: RuntimeEventEnvelope) => {
    await options.onEvent?.(event);
  };

  const emitErrorAndEnd = async (error: HeadlessRunError, status: 'failed' | 'cancelled') => {
    const exitCode = status === 'cancelled' ? HEADLESS_EXIT_CANCELLED : HEADLESS_EXIT_FAILURE;
    const envelopeScope = scopeEnvelope(scope);
    const output: HeadlessRunOutput = {
      runId,
      ...(scope ? { sessionId: scope.session.id, turn: scope.intendedTurn } : {}),
      status,
      exitCode,
      artifacts,
      error
    };
    if (!runtimeError) {
      await emit(createEvent('error', error, envelopeScope));
    }
    await emit(createEvent('run-end', { status, exitCode, output }, envelopeScope));
    return output;
  };

  try {
    if (options.signal?.aborted) {
      throw errorFrom('cancelled', 'cancel', 'run cancelled');
    }
    await validateRequest(request);

    const trustCtx = await createWorkspaceTrustContext(request.cwd);
    const trustVerdict = await evaluateWorkspaceTrustForNonInteractive(trustCtx);
    if (!trustVerdict.ok) {
      throw errorFrom('invalid-input', 'session', trustVerdict.message);
    }

    const session = request.session?.mode === 'new' ? await ensureFresh(request.cwd) : await ensureSession(request.cwd);
    const policy = request.policy ?? DEFAULT_POLICY_MODE;
    const assembly = await createRuntimeAssembly({
      cwd: request.cwd,
      session,
      policyMode: policy,
      cliSkillNames: request.skills ?? []
    });
    const workspaceConfig = {
      ...assembly.workspaceConfig,
      autoCompact: request.autoCompact ?? assembly.workspaceConfig.autoCompact
    };
    const modelConfig = await resolveModelConfig({
      workspace: workspaceConfig,
      cli: (request.model ?? {}) as PartialModelConfig
    });
    session.model = {
      provider: modelConfig.provider,
      model: modelConfig.model,
      baseUrl: modelConfig.baseUrl
    };
    const runScope: RunScope = {
      session,
      modelConfig,
      policy,
      intendedTurn: session.lifecycle.turn + 1
    };
    scope = runScope;

    await emit(
      createEvent(
        'run-start',
        {
          cwd: request.cwd,
          policy,
          model: session.model
        },
        { sessionId: session.id, turn: runScope.intendedTurn }
      )
    );

    // §A.6: build CoordinatorContext, run crash recovery before constructing
    // the runner so cross-session orphans get filtered and own-session orphans
    // converge before the new turn starts.
    const cliqHome = resolveCliqHome();
    let workspaceRealPath = request.cwd;
    try {
      workspaceRealPath = await realpath(request.cwd);
    } catch {
      // fall back to cwd verbatim
    }
    const coordinatorCtx: CoordinatorContext = {
      cwd: request.cwd,
      session,
      cliqHome,
      workspaceId: workspaceIdFromRealPath(workspaceRealPath),
      sessionId: session.id,
      workspaceRealPath
    };

    const recoveryResult = await recoverAtStart(coordinatorCtx);
    for (const skippedTxId of recoveryResult.crossSessionSkipped) {
      await emit(
        createEvent(
          'error',
          {
            code: 'tx-overlay-error',
            stage: 'tool',
            message: `recovery skipped cross-session orphan ${skippedTxId}`,
            recoverable: true
          },
          { sessionId: session.id, turn: runScope.intendedTurn }
        )
      );
    }

    await runHeadlessSessionStartHooks({
      commandHooks: assembly.commandHooks ?? {},
      cwd: request.cwd,
      session,
      modelConfig,
      async emitWarning(message) {
        await emit(
          createEvent(
            'error',
            {
              code: 'tool-error',
              stage: 'tool',
              message,
              recoverable: true
            },
            { sessionId: session.id, turn: runScope.intendedTurn }
          )
        );
      }
    });

    // Build TxRunnerOptions when transactions mode is active.
    const txMode = request.txMode ?? workspaceConfig.transactions?.mode ?? 'off';
    let transactions: TxRunnerOptions | undefined;
    if (txMode === 'edit') {
      const applyPolicy = request.txApply ?? workspaceConfig.transactions?.applyPolicy ?? 'auto-on-pass';
      transactions = {
        mode: 'edit',
        auto: workspaceConfig.transactions?.auto ?? 'per-turn',
        applyPolicy,
        bashPolicy: workspaceConfig.transactions?.bashPolicy ?? 'passthrough',
        headless: true,
        validatorsConfig: workspaceConfig.transactions?.validators ?? {},
        stagedViewConfig: workspaceConfig.transactions?.stagedView ?? { copyMode: 'auto', bindPaths: ['node_modules'] },
        workspaceId: coordinatorCtx.workspaceId,
        workspaceRealPath: coordinatorCtx.workspaceRealPath,
        cliqHome
      };
    }

    const modelClient = options.modelClient ?? options.createModelClient?.(modelConfig) ?? createModelClient(modelConfig);
    const runner = createRunner({
      model: modelClient,
      hooks: [...assembly.hooks, ...(options.hooks ?? [])],
      commandHooks: assembly.commandHooks ?? {},
      policy: createPolicyEngine({ mode: policy }),
      confirm: options.confirm,
      instructions: assembly.instructions,
      signal: options.signal,
      autoCompact: {
        config: workspaceConfig.autoCompact,
        modelConfig
      },
      ...(transactions ? { transactions } : {}),
      async onEvent(runtimeEvent) {
        const mapped = runtimeEventToHeadless(runtimeEvent);
        if (mapped.type === 'error') {
          runtimeError = mapped.payload as HeadlessRunError;
        }
        if (mapped.artifacts) {
          mergeArtifacts(artifacts, mapped.artifacts);
        }
        await emit(
          createEvent(mapped.type, mapped.payload, {
            sessionId: session.id,
            turn: runScope.intendedTurn
          })
        );
      }
    });

    const finalMessage = await runner.runTurn(session, request.prompt.trim());
    const output: HeadlessRunOutput = {
      runId,
      sessionId: session.id,
      turn: runScope.intendedTurn,
      status: 'completed',
      exitCode: HEADLESS_EXIT_SUCCESS,
      finalMessage,
      checkpointId: artifacts.checkpoints[0],
      artifacts
    };
    await emit(
      createEvent(
        'run-end',
        { status: 'completed', exitCode: HEADLESS_EXIT_SUCCESS, output },
        { sessionId: session.id, turn: runScope.intendedTurn }
      )
    );
    return output;
  } catch (error) {
    const headlessError = runtimeError ?? normalizeCaughtError(error);
    return await emitErrorAndEnd(headlessError, errorStatus(headlessError));
  }
}
