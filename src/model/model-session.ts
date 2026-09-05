import type { ArtifactRef } from '../kernel/types.js';
import { assertArtifactRef } from '../kernel/identity.js';
import type { AgentModelStreamEvent } from '../protocol/agent-ir.js';
import { compileModelObservation, type CompiledModelObservation, type ResolveToolInput } from './attempt.js';
import { immutableSnapshot } from './immutable.js';
import { calculateModelCostMicros } from './pricing.js';
import { createProviderResponseObserver, type ObservedProviderResponse } from './provider-observation.js';
import {
  prepareNormalModelAttempt,
  prepareCompactionModelAttempt,
  type ModelAttemptAuthority,
  type ModelRequestV1,
  type PreparedModelAttemptData,
  type PrepareNormalModelAttemptInput,
  type PrepareCompactionModelAttemptInput
} from './request.js';

type PrepareInput =
  | ({ kind: 'normal' } & Omit<PrepareNormalModelAttemptInput, 'authority'>)
  | ({ kind: 'context_compaction' } & Omit<PrepareCompactionModelAttemptInput, 'authority'>);

export type PreparedModelAttempt = Readonly<{
  request: Readonly<ModelRequestV1>;
  requestRef: ArtifactRef;
  artifacts: Readonly<PreparedModelAttemptData['artifacts']>;
  outbound: Readonly<PreparedModelAttemptData['outbound']>;
}>;

export type ModelAttemptResponse = {
  push(bytes: Uint8Array): AgentModelStreamEvent[];
  readonly overLimit: boolean;
  finish(observedAt: string, resolveToolInput: ResolveToolInput): ModelAttemptResult;
  /** The broker has already persisted this StopIntent and aborted transport. */
  abort(observedAt: string, stopIntentRef: ArtifactRef, resolveToolInput: ResolveToolInput): ModelAttemptResult;
};

export type ModelAttemptResult = CompiledModelObservation & { events: AgentModelStreamEvent[] };

export type ModelSession = {
  prepare(input: PrepareInput): PreparedModelAttempt;
  /** The broker must durably claim this exact request before releasing its bytes. No I/O or retries occur here. */
  start(prepared: PreparedModelAttempt, head: { status: number; mediaType?: string }): ModelAttemptResponse;
};

/** Internal factory. Admission/recovery enters through validateRunAssembly, never raw configuration. */
export function createModelSession(input: ModelAttemptAuthority): ModelSession {
  const authority = immutableSnapshot(input);
  const toolsByName = new Map(authority.exposedTools.map((tool) => [tool.name, tool]));
  const preparedRequests = new WeakMap<PreparedModelAttempt, PreparedModelAttemptData>();
  return Object.freeze({
    prepare(input: PrepareInput): PreparedModelAttempt {
      const snapshot = immutableSnapshot(input);
      if (snapshot.kind !== 'normal' && snapshot.kind !== 'context_compaction') {
        throw new TypeError('unsupported model attempt kind');
      }
      const data =
        snapshot.kind === 'normal'
          ? prepareNormalModelAttempt({ ...snapshot, authority })
          : prepareCompactionModelAttempt({ ...snapshot, authority });
      const request = immutableSnapshot(data.request);
      const bytes = data.outbound.bodyBytes.slice();
      const prepared = Object.freeze({
        request,
        requestRef: data.requestRef,
        artifacts: Object.freeze([...data.artifacts]),
        outbound: Object.freeze({
          requestPath: data.outbound.requestPath,
          mediaType: data.outbound.mediaType,
          bodyBytesRef: data.outbound.bodyBytesRef,
          get bodyBytes() {
            return bytes.slice();
          }
        })
      });
      preparedRequests.set(prepared, { ...data, request });
      return prepared;
    },
    start(prepared: PreparedModelAttempt, head: { status: number; mediaType?: string }): ModelAttemptResponse {
      const data = preparedRequests.get(prepared);
      if (!data) throw new TypeError('prepared attempt does not belong to this model session');
      const request = data.request;
      const observer = createProviderResponseObserver({
        ...head,
        mediaType: head.mediaType,
        provider: request.provider,
        model: request.model,
        negotiatedMode: request.negotiatedMode
      });
      const compile = (
        observed: ObservedProviderResponse,
        resolveToolInput: ResolveToolInput,
        abortStopIntentRef?: ArtifactRef
      ): ModelAttemptResult => {
        const binding = { requestRef: data.requestRef, requestDigest: request.requestDigest };
        const result = compileModelObservation({
          runId: request.runId,
          opId: request.opId,
          attempt: request.attempt,
          provider: request.provider,
          model: request.model,
          negotiatedMode: request.negotiatedMode,
          promptProjectionRef: request.promptProjectionRef,
          promptProjectionDigest: request.promptProjectionDigest,
          reservedModelTokens: request.reservation.modelTokens,
          observation: observed.observation,
          resolveToolInput: (call) => {
            const resolution = resolveToolInput(call);
            const tool = toolsByName.get(call.toolName);
            if (
              tool === undefined
                ? resolution.kind !== 'unknown_tool'
                : resolution.kind === 'unknown_tool' ||
                  resolution.inputSchemaRef !== tool.inputSchemaRef ||
                  resolution.inputSchemaDigest !== tool.inputSchemaDigest
            ) {
              throw new TypeError('input resolver does not match the frozen tool contract');
            }
            return resolution;
          },
          ...(abortStopIntentRef === undefined ? {} : { abortStopIntentRef }),
          calculateUsageCostMicros: (usage) => {
            for (const key of ['inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheWriteTokens'] as const) {
              if (usage[key] > request.reservation[key])
                throw new RangeError('usage exceeds the admitted request ceiling');
            }
            if (usage.outputTokens > request.maximumOutputTokens)
              throw new RangeError('usage exceeds the requested output cap');
            return authority.pricing.kind === 'zero_cost'
              ? 0
              : calculateModelCostMicros(usage, authority.pricing.table.prices);
          },
          ...(request.kind === 'normal'
            ? { request: { kind: 'normal' as const, ...binding } }
            : {
                request: { kind: 'context_compaction' as const, ...binding },
                compaction: { maximumOutputTokens: request.maximumOutputTokens }
              })
        });
        return { ...result, events: observed.events };
      };
      return Object.freeze({
        push: observer.push,
        get overLimit() {
          return observer.overLimit;
        },
        finish(observedAt: string, resolveToolInput: ResolveToolInput): ModelAttemptResult {
          return compile(observer.finish(observedAt), resolveToolInput);
        },
        abort(observedAt: string, stopIntentRef: ArtifactRef, resolveToolInput: ResolveToolInput): ModelAttemptResult {
          assertArtifactRef(stopIntentRef);
          return compile(observer.finish(observedAt, true), resolveToolInput, stopIntentRef);
        }
      });
    }
  });
}
