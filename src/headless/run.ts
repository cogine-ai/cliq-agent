import { stat } from 'node:fs/promises';

import { DEFAULT_POLICY_MODE } from '../config.js';
import { resolveModelConfig } from '../model/config.js';
import type { PartialModelConfig } from '../model/config.js';
import { createModelClient } from '../model/index.js';
import type { ModelClient, ResolvedModelConfig } from '../model/types.js';
import { createPolicyEngine } from '../policy/engine.js';
import type { PolicyConfirm, PolicyMode } from '../policy/types.js';
import { createRuntimeAssembly } from '../runtime/assembly.js';
import type { RuntimeHook } from '../runtime/hooks.js';
import { createRunner } from '../runtime/runner.js';
import { ensureFresh, ensureSession, makeId } from '../session/store.js';
import type { Session } from '../session/types.js';
import {
  emptyHeadlessArtifacts,
  HEADLESS_EXIT_CANCELLED,
  HEADLESS_EXIT_FAILURE,
  HEADLESS_EXIT_SUCCESS,
  type HeadlessErrorCode,
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
};

const POLICY_MODES = new Set<PolicyMode>(['auto', 'confirm-write', 'read-only', 'confirm-bash', 'confirm-all']);

function errorFrom(
  code: HeadlessErrorCode,
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
        turn: scope.session.lifecycle.turn
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
  const cancelled = message.toLowerCase().includes('cancelled');
  return errorFrom(cancelled ? 'cancelled' : 'internal-error', cancelled ? 'cancel' : 'assembly', message);
}

export async function runHeadless(
  request: HeadlessRunRequest,
  options: HeadlessRunOptions & RunHeadlessDependencies = {}
): Promise<HeadlessRunOutput> {
  const runId = makeId('run');
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
      ...(scope ? { sessionId: scope.session.id, turn: scope.session.lifecycle.turn } : {}),
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
    scope = {
      session,
      modelConfig,
      policy
    };

    await emit(
      createEvent(
        'run-start',
        {
          cwd: request.cwd,
          policy,
          model: session.model
        },
        { sessionId: session.id, turn: session.lifecycle.turn + 1 }
      )
    );

    const modelClient = options.modelClient ?? options.createModelClient?.(modelConfig) ?? createModelClient(modelConfig);
    const runner = createRunner({
      model: modelClient,
      hooks: [...assembly.hooks, ...(options.hooks ?? [])],
      policy: createPolicyEngine({ mode: policy, confirm: options.confirm }),
      instructions: assembly.instructions,
      signal: options.signal,
      autoCompact: {
        config: workspaceConfig.autoCompact,
        modelConfig
      },
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
            turn: session.lifecycle.turn
          })
        );
      }
    });

    const finalMessage = await runner.runTurn(session, request.prompt.trim());
    const output: HeadlessRunOutput = {
      runId,
      sessionId: session.id,
      turn: session.lifecycle.turn,
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
        { sessionId: session.id, turn: session.lifecycle.turn }
      )
    );
    return output;
  } catch (error) {
    const headlessError = runtimeError ?? normalizeCaughtError(error);
    return await emitErrorAndEnd(headlessError, errorStatus(headlessError));
  }
}
