import { makeId, nowIso } from '../session/store.js';
import type { RuntimeEvent } from '../runtime/events.js';
import {
  emptyHeadlessArtifacts,
  HEADLESS_SCHEMA_VERSION,
  type CheckpointCreatedPayload,
  type HeadlessEventPayloadByType,
  type HeadlessArtifacts,
  type HeadlessErrorCode,
  type HeadlessRuntimeEventType,
  type RuntimeEventEnvelopeFor
} from './contract.js';

type EnvelopeScope = {
  sessionId?: string;
  turn?: number;
};

type EventFactoryOptions = {
  runId: string;
  now?: () => string;
};

export type RuntimeEventMapping = {
  [TType in HeadlessRuntimeEventType]: {
    type: TType;
    payload: HeadlessEventPayloadByType[TType];
    artifacts?: HeadlessArtifacts;
  };
}[HeadlessRuntimeEventType];

const codeByRuntimeErrorStage = {
  model: 'model-error',
  protocol: 'protocol-error',
  policy: 'policy-denied',
  tool: 'tool-error',
  cancel: 'cancelled'
} as const satisfies Record<Extract<RuntimeEvent, { type: 'error' }>['stage'], HeadlessErrorCode>;

function artifactsWith(values: Partial<HeadlessArtifacts>): HeadlessArtifacts {
  return {
    ...emptyHeadlessArtifacts(),
    ...values
  };
}

function checkpointArtifacts(payload: CheckpointCreatedPayload): HeadlessArtifacts {
  return artifactsWith({
    checkpoints: [payload.checkpointId],
    workspaceCheckpoints: payload.workspaceCheckpointId ? [payload.workspaceCheckpointId] : []
  });
}

function assertNever(value: never): never {
  throw new Error(`unhandled runtime event: ${JSON.stringify(value)}`);
}

export function mergeArtifacts(target: HeadlessArtifacts, source: HeadlessArtifacts) {
  for (const key of Object.keys(target) as Array<keyof HeadlessArtifacts>) {
    for (const id of source[key]) {
      if (!target[key].includes(id)) {
        target[key].push(id);
      }
    }
  }
}

export function createHeadlessEventFactory({ runId, now = nowIso }: EventFactoryOptions) {
  return function createEvent<TType extends HeadlessRuntimeEventType>(
    type: TType,
    payload: HeadlessEventPayloadByType[TType],
    scope: EnvelopeScope = {}
  ): RuntimeEventEnvelopeFor<TType> {
    return {
      schemaVersion: HEADLESS_SCHEMA_VERSION,
      eventId: makeId('evt'),
      runId,
      sessionId: scope.sessionId,
      turn: scope.turn,
      timestamp: now(),
      type,
      payload
    } as RuntimeEventEnvelopeFor<TType>;
  };
}

export function runtimeEventToHeadless(event: RuntimeEvent): RuntimeEventMapping {
  if (event.type === 'checkpoint-created') {
    const payload: CheckpointCreatedPayload = {
      checkpointId: event.checkpointId,
      kind: event.kind,
      workspaceSnapshotStatus: event.workspaceSnapshotStatus,
      ...(event.workspaceCheckpointId ? { workspaceCheckpointId: event.workspaceCheckpointId } : {}),
      ...(event.warning ? { warning: event.warning } : {})
    };
    return {
      type: 'checkpoint-created',
      payload,
      artifacts: checkpointArtifacts(payload)
    };
  }

  if (event.type === 'compact-end') {
    return {
      type: 'compact-end',
      payload: {
        artifactId: event.artifactId,
        estimatedTokensBefore: event.estimatedTokensBefore,
        estimatedTokensAfter: event.estimatedTokensAfter
      },
      artifacts: artifactsWith({ compactions: [event.artifactId] })
    };
  }

  if (event.type === 'error') {
    return {
      type: 'error',
      payload: {
        code: codeByRuntimeErrorStage[event.stage],
        stage: event.stage,
        message: event.message,
        recoverable: false
      }
    };
  }

  if (event.type === 'model-start') {
    return {
      type: 'model-start',
      payload: { provider: event.provider, model: event.model, streaming: event.streaming }
    };
  }

  if (event.type === 'model-progress') {
    return {
      type: 'model-progress',
      payload: { chunks: event.chunks, chars: event.chars }
    };
  }

  if (event.type === 'model-end') {
    return {
      type: 'model-end',
      payload: { provider: event.provider, model: event.model }
    };
  }

  if (event.type === 'tool-start') {
    return {
      type: 'tool-start',
      payload: { tool: event.tool, preview: event.preview }
    };
  }

  if (event.type === 'tool-end') {
    return {
      type: 'tool-end',
      payload: { tool: event.tool, status: event.status }
    };
  }

  if (event.type === 'compact-start') {
    return {
      type: 'compact-start',
      payload: { trigger: event.trigger, phase: event.phase }
    };
  }

  if (event.type === 'compact-skip') {
    return {
      type: 'compact-skip',
      payload: { reason: event.reason }
    };
  }

  if (event.type === 'compact-error') {
    return {
      type: 'compact-error',
      payload: { trigger: event.trigger, message: event.message }
    };
  }

  if (event.type === 'final') {
    return {
      type: 'final',
      payload: { message: event.message }
    };
  }

  if (event.type === 'tx-staging-start') {
    return {
      type: 'tx-staging-start',
      payload: {
        txId: event.txId,
        txKind: 'edit',
        trigger: event.trigger,
        ...(event.name ? { name: event.name } : {})
      },
      artifacts: artifactsWith({ transactions: [event.txId] })
    };
  }

  if (event.type === 'tx-finalized') {
    return {
      type: 'tx-finalized',
      payload: { txId: event.txId, txKind: 'edit', diffSummary: event.diffSummary },
      artifacts: artifactsWith({ transactions: [event.txId] })
    };
  }

  if (event.type === 'tx-validated') {
    return {
      type: 'tx-validated',
      payload: {
        txId: event.txId,
        txKind: 'edit',
        validators: event.validators,
        blockingFailures: event.blockingFailures
      },
      artifacts: artifactsWith({ transactions: [event.txId] })
    };
  }

  if (event.type === 'tx-applied') {
    return {
      type: 'tx-applied',
      payload: {
        txId: event.txId,
        txKind: 'edit',
        diffSummary: event.diffSummary,
        validators: event.validators,
        overrides: event.overrides,
        artifactRef: event.artifactRef,
        ...(event.ghostSnapshotId ? { ghostSnapshotId: event.ghostSnapshotId } : {})
      },
      artifacts: artifactsWith({ transactions: [event.txId] })
    };
  }

  if (event.type === 'tx-aborted') {
    return {
      type: 'tx-aborted',
      payload: {
        txId: event.txId,
        txKind: 'edit',
        reason: event.reason,
        ...(event.failedValidators ? { failedValidators: event.failedValidators } : {}),
        artifactRef: event.artifactRef,
        ...(event.appliedPartial ? { appliedPartial: event.appliedPartial } : {})
      },
      artifacts: artifactsWith({ transactions: [event.txId] })
    };
  }

  return assertNever(event);
}
