import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { ProviderName } from '../kernel/types.js';
import type { ObservedToolCallInputV1, ToolCallInputV1 } from '../protocol/agent-ir.js';
import {
  MODEL_RESPONSE_LIMIT_BYTES,
  compileModelObservation,
  type CompileModelObservationInput,
  type ObservedModelResponse,
  type ResolveToolInput
} from './attempt.js';

const REQUEST_REF = '1'.repeat(64);
const REQUEST_DIGEST = '2'.repeat(64);
const PROJECTION_REF = '3'.repeat(64);
const PROJECTION_DIGEST = '4'.repeat(64);
const SCHEMA_REF = '5'.repeat(64);
const SCHEMA_DIGEST = '6'.repeat(64);

function responseBytes(value: unknown): Uint8Array {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function diagnostic(code: 'TOOL_NOT_FOUND' | 'TOOL_INPUT_INVALID', callId: string) {
  const withoutDigest = {
    schemaVersion: 1,
    format: 'cliq-tool-input-diagnostic-v1',
    code,
    callId
  };
  const value = {
    ...withoutDigest,
    diagnosticDigest: canonicalSha256(withoutDigest)
  };
  return {
    artifact: planCanonicalArtifact(value, value.format),
    digest: value.diagnosticDigest
  };
}

const resolveToolInput: ResolveToolInput = ({ callId, toolName, observedInput }) => {
  if (toolName === 'missing') {
    const result = diagnostic('TOOL_NOT_FOUND', callId);
    return {
      kind: 'unknown_tool',
      diagnostic: result.artifact,
      diagnosticDigest: result.digest
    };
  }
  if (
    observedInput.encoding !== 'jcs_json' ||
    observedInput.value === null ||
    typeof observedInput.value !== 'object' ||
    Array.isArray(observedInput.value)
  ) {
    const result = diagnostic('TOOL_INPUT_INVALID', callId);
    return {
      kind: 'invalid_input',
      inputSchemaRef: SCHEMA_REF,
      inputSchemaDigest: SCHEMA_DIGEST,
      diagnostic: result.artifact,
      diagnosticDigest: result.digest
    };
  }
  return {
    kind: 'resolved',
    inputSchemaRef: SCHEMA_REF,
    inputSchemaDigest: SCHEMA_DIGEST,
    value: observedInput.value as Record<string, unknown>
  };
};

function decodedObservation(
  overrides: Partial<Extract<ObservedModelResponse, { kind: 'decoded' }>> = {}
): Extract<ObservedModelResponse, { kind: 'decoded' }> {
  return {
    kind: 'decoded',
    provider: 'openai',
    model: 'gpt-test',
    mediaType: 'application/json',
    bytes: responseBytes({ id: 'response-1', output: 'done' }),
    observedAt: '2026-09-05T00:00:00.000Z',
    responseId: 'response-1',
    stopReason: 'end',
    text: 'done',
    toolCalls: [],
    ...overrides
  };
}

function compileInput(
  observation: ObservedModelResponse,
  overrides: Partial<Extract<CompileModelObservationInput, { request: { kind: 'normal' } }>> = {}
): Extract<CompileModelObservationInput, { request: { kind: 'normal' } }> {
  return {
    runId: 'run-1',
    opId: 'model-op-1',
    attempt: 1,
    request: { kind: 'normal', requestRef: REQUEST_REF, requestDigest: REQUEST_DIGEST },
    provider: 'openai',
    model: 'gpt-test',
    negotiatedMode: 'native-tools',
    promptProjectionRef: PROJECTION_REF,
    promptProjectionDigest: PROJECTION_DIGEST,
    reservedModelTokens: 100,
    observation,
    resolveToolInput,
    calculateUsageCostMicros(usage) {
      return usage.inputTokens + usage.outputTokens + usage.cacheReadTokens + usage.cacheWriteTokens;
    },
    ...overrides
  };
}

function decodedArtifact<T>(artifacts: Array<{ ref: string; bytes: Uint8Array }>, ref: string): T {
  const artifact = artifacts.find((candidate) => candidate.ref === ref);
  assert.ok(artifact, `missing planned artifact ${ref}`);
  assert.equal(sha256Bytes(artifact.bytes), artifact.ref);
  return JSON.parse(Buffer.from(artifact.bytes).toString('utf8')) as T;
}

test('compileModelObservation creates one deterministic final AgentModelTurn', () => {
  const observation = decodedObservation({
    text: 'line one\r\nline two',
    usage: { inputTokens: 10, outputTokens: 4, cacheReadTokens: 2, cacheWriteTokens: 1 }
  });

  const first = compileModelObservation(compileInput(observation));
  const second = compileModelObservation(compileInput(observation));

  assert.equal(first.kind, 'usable');
  assert.equal(second.kind, 'usable');
  assert.equal(first.turnRef, second.turnRef);
  assert.deepEqual(first.artifacts, second.artifacts);
  assert.equal(first.turn.stopReason, 'end');
  assert.deepEqual(first.turn.toolCalls, []);
  assert.deepEqual(first.turn.usage, {
    inputTokens: 10,
    outputTokens: 4,
    cacheReadTokens: 2,
    cacheWriteTokens: 1,
    costMicros: 17
  });
  assert.equal(
    first.turn.responseDigest,
    canonicalSha256({
      format: 'cliq-agent-normalized-response-v1',
      provider: 'openai',
      model: 'gpt-test',
      responseId: 'response-1',
      usage: first.turn.usage,
      usageTrusted: false,
      negotiatedMode: 'native-tools',
      requestDigest: REQUEST_DIGEST,
      stopReason: 'end',
      textRef: first.turn.textRef,
      toolCalls: []
    })
  );

  const text = decodedArtifact<{ utf8: string; textDigest: string }>(first.artifacts, first.turn.textRef);
  assert.equal(text.utf8, 'line one\nline two');
  const persistedTurn = decodedArtifact<typeof first.turn>(first.artifacts, first.turnRef);
  assert.deepEqual(persistedTurn, first.turn);
});

test('compileModelObservation retains every call and its exact malformed argument fragment', () => {
  const seen: Array<{ callId: string; index: number; observed: ObservedToolCallInputV1 }> = [];
  const resolver: ResolveToolInput = (input) => {
    seen.push({ callId: input.callId, index: input.index, observed: input.observedInput });
    return resolveToolInput(input);
  };
  const observation = decodedObservation({
    stopReason: 'tool_calls',
    text: 'I will inspect both.',
    toolCalls: [
      {
        wireCallId: 'call-1',
        toolName: 'read',
        input: { encoding: 'jcs_json', value: { path: 'README.md' } }
      },
      {
        wireCallId: 'call-2',
        toolName: 'read',
        input: { encoding: 'utf8_json_fragment', utf8: '{"path":"broken"' }
      }
    ]
  });

  const result = compileModelObservation(compileInput(observation, { resolveToolInput: resolver }));

  assert.equal(result.kind, 'usable');
  assert.deepEqual(
    result.turn.toolCalls.map(({ callId, index, toolName }) => ({ callId, index, toolName })),
    [
      { callId: 'call-1', index: 0, toolName: 'read' },
      { callId: 'call-2', index: 1, toolName: 'read' }
    ]
  );
  assert.equal(seen.length, 2);
  assert.equal(seen[1]?.observed.encoding, 'utf8_json_fragment');
  assert.equal(seen[1]?.observed.encoding === 'utf8_json_fragment' ? seen[1].observed.utf8 : '', '{"path":"broken"');
  const secondInput = decodedArtifact<ToolCallInputV1>(result.artifacts, result.turn.toolCalls[1]!.inputRef);
  assert.equal(secondInput.disposition, 'rejected_invalid_input');
  const observed = decodedArtifact<ObservedToolCallInputV1>(result.artifacts, secondInput.observedInputRef);
  assert.equal(observed.encoding, 'utf8_json_fragment');
  assert.equal(observed.encoding === 'utf8_json_fragment' ? observed.utf8 : '', '{"path":"broken"');
});

test('compileModelObservation rejects the whole response before resolution when a later native id is missing', () => {
  let resolutions = 0;
  const observation = decodedObservation({
    stopReason: 'tool_calls',
    text: '',
    toolCalls: [
      { wireCallId: 'call-1', toolName: 'read', input: { encoding: 'jcs_json', value: { path: 'a' } } },
      { toolName: 'read', input: { encoding: 'jcs_json', value: { path: 'b' } } }
    ]
  });

  const result = compileModelObservation(
    compileInput(observation, {
      resolveToolInput(input) {
        resolutions += 1;
        return resolveToolInput(input);
      }
    })
  );

  assert.equal(result.kind, 'unusable');
  assert.equal(result.response.failureCode, 'missing_or_duplicate_call_id');
  assert.equal(resolutions, 0);
  assert.equal(result.artifacts.length, 2);
  assert.equal(result.response.unusableDigest, digestOmitting(result.response, 'unusableDigest'));
});

test('compileModelObservation rejects duplicate native ids and invalid stop/call pairs', () => {
  const duplicate = compileModelObservation(
    compileInput(
      decodedObservation({
        stopReason: 'tool_calls',
        toolCalls: [
          { wireCallId: 'same', toolName: 'read', input: { encoding: 'jcs_json', value: {} } },
          { wireCallId: 'same', toolName: 'read', input: { encoding: 'jcs_json', value: {} } }
        ]
      })
    )
  );
  assert.equal(duplicate.kind, 'unusable');
  assert.equal(duplicate.response.failureCode, 'missing_or_duplicate_call_id');

  const invalidPair = compileModelObservation(
    compileInput(
      decodedObservation({
        stopReason: 'end',
        toolCalls: [{ wireCallId: 'call-1', toolName: 'read', input: { encoding: 'jcs_json', value: {} } }]
      })
    )
  );
  assert.equal(invalidPair.kind, 'unusable');
  assert.equal(invalidPair.response.failureCode, 'invalid_stop_call_shape');
});

test('compileModelObservation fails closed for forbidden mode calls', () => {
  const textOnly = compileModelObservation(
    compileInput(
      decodedObservation({
        stopReason: 'tool_calls',
        toolCalls: [{ wireCallId: 'call-1', toolName: 'read', input: { encoding: 'jcs_json', value: {} } }]
      }),
      { negotiatedMode: 'text-only' }
    )
  );
  assert.equal(textOnly.kind, 'unusable');
  assert.equal(textOnly.response.failureCode, 'tool_calls_forbidden_by_mode');
});

test('compileModelObservation maps nonterminal stops and provider rejection to closed failures', () => {
  for (const [stopReason, expected] of [
    ['length', 'stop_reason_length'],
    ['content_filter', 'stop_reason_content_filter'],
    ['unknown', 'stop_reason_unknown']
  ] as const) {
    const result = compileModelObservation(compileInput(decodedObservation({ stopReason })));
    assert.equal(result.kind, 'unusable');
    assert.equal(result.response.failureCode, expected);
  }

  const rejectedObservation: ObservedModelResponse = {
    kind: 'provider_rejection',
    provider: 'openai',
    model: 'gpt-test',
    mediaType: 'application/json',
    bytes: responseBytes({ error: 'rejected' }),
    observedAt: '2026-09-05T00:00:00.000Z'
  };
  const rejected = compileModelObservation(compileInput(rejectedObservation));
  assert.equal(rejected.kind, 'unusable');
  assert.equal(rejected.response.failureCode, 'provider_rejected_response');
});

test('compileModelObservation retains exactly response-limit-plus-one bytes for oversize responses', () => {
  const bytes = new Uint8Array(MODEL_RESPONSE_LIMIT_BYTES + 17).fill(0x61);
  const result = compileModelObservation(compileInput(decodedObservation({ bytes })));

  assert.equal(result.kind, 'unusable');
  assert.equal(result.response.failureCode, 'response_too_large');
  assert.equal(result.response.observedResponse.kind, 'prefix_over_limit');
  assert.equal(result.response.observedResponse.byteCount, MODEL_RESPONSE_LIMIT_BYTES + 1);
  const raw = result.artifacts.find((artifact) => artifact.ref === result.response.observedResponse.bytesRef);
  assert.equal(raw?.bytes.byteLength, MODEL_RESPONSE_LIMIT_BYTES + 1);
});

test('compileModelObservation derives stable managed Ollama ids and isolates attempts', () => {
  const observation = decodedObservation({
    provider: 'ollama',
    model: 'qwen-test',
    stopReason: 'tool_calls',
    toolCalls: [{ wireCallId: 'ignored', toolName: 'read', input: { encoding: 'jcs_json', value: {} } }]
  });
  const first = compileModelObservation(compileInput(observation, { provider: 'ollama', model: 'qwen-test' }));
  const replay = compileModelObservation(compileInput(observation, { provider: 'ollama', model: 'qwen-test' }));
  const nextAttempt = compileModelObservation(
    compileInput(observation, { provider: 'ollama', model: 'qwen-test', attempt: 2 })
  );

  assert.equal(first.kind, 'usable');
  assert.equal(replay.kind, 'usable');
  assert.equal(nextAttempt.kind, 'usable');
  assert.equal(first.turn.stopReason, 'tool_calls');
  assert.equal(replay.turn.stopReason, 'tool_calls');
  assert.equal(nextAttempt.turn.stopReason, 'tool_calls');
  assert.equal(first.turn.toolCalls[0].callId, replay.turn.toolCalls[0].callId);
  assert.notEqual(first.turn.toolCalls[0].callId, nextAttempt.turn.toolCalls[0].callId);
  assert.notEqual(first.turn.toolCalls[0].callId, 'ignored');
});

test('compileModelObservation only accepts cancellation with the pre-existing StopIntent', () => {
  const observation = decodedObservation({ stopReason: 'cancelled', text: '', toolCalls: [] });
  const rejected = compileModelObservation(compileInput(observation));
  assert.equal(rejected.kind, 'unusable');
  assert.equal(rejected.response.failureCode, 'invalid_stop_call_shape');

  const stopIntentRef = '7'.repeat(64);
  const accepted = compileModelObservation(compileInput(observation, { abortStopIntentRef: stopIntentRef }));
  assert.equal(accepted.kind, 'usable');
  assert.equal(accepted.turn.stopReason, 'cancelled');
  assert.equal(accepted.turn.stopReason === 'cancelled' ? accepted.turn.abortStopIntentRef : undefined, stopIntentRef);
});

test('compileModelObservation rejects invalid usage rather than persisting partial telemetry', () => {
  const result = compileModelObservation(
    compileInput(
      decodedObservation({
        usage: { inputTokens: 99, outputTokens: 2, cacheReadTokens: 0, cacheWriteTokens: 0 }
      })
    )
  );
  assert.equal(result.kind, 'unusable');
  assert.equal(result.response.failureCode, 'malformed_transport_payload');

  const overflow = compileModelObservation(
    compileInput(
      decodedObservation({
        usage: { inputTokens: 1, outputTokens: 1, cacheReadTokens: 1, cacheWriteTokens: 1 }
      }),
      {
        calculateUsageCostMicros() {
          throw new RangeError('overflow');
        }
      }
    )
  );
  assert.equal(overflow.kind, 'unusable');
  assert.equal(overflow.response.failureCode, 'malformed_transport_payload');

  const invalidCost = compileModelObservation(
    compileInput(
      decodedObservation({
        usage: { inputTokens: 1, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0 }
      }),
      { calculateUsageCostMicros: () => Number.MAX_SAFE_INTEGER + 1 }
    )
  );
  assert.equal(invalidCost.kind, 'unusable');
  assert.equal(invalidCost.response.failureCode, 'malformed_transport_payload');
});

test('compileModelObservation maps an out-of-contract adapter stop to unknown', () => {
  const observation = decodedObservation() as unknown as { stopReason: string };
  observation.stopReason = 'future-provider-stop';
  const result = compileModelObservation(compileInput(observation as ObservedModelResponse));
  assert.equal(result.kind, 'unusable');
  assert.equal(result.response.failureCode, 'stop_reason_unknown');
});

test('compileModelObservation rejects provider identity substitution', () => {
  const providers: ProviderName[] = ['anthropic', 'openrouter', 'openai-compatible', 'zhipu', 'ollama'];
  for (const provider of providers) {
    const result = compileModelObservation(compileInput(decodedObservation({ provider })));
    assert.equal(result.kind, 'unusable');
    assert.equal(result.response.failureCode, 'capability_shape_mismatch');
  }

  const oversizedResponseId = compileModelObservation(
    compileInput(decodedObservation({ responseId: 'r'.repeat(513) }))
  );
  assert.equal(oversizedResponseId.kind, 'unusable');
  assert.equal(oversizedResponseId.response.failureCode, 'malformed_transport_payload');
});

test('compileModelObservation retains an identifiable call with a missing tool name for batch rejection', () => {
  let resolvedName: string | undefined;
  const result = compileModelObservation(
    compileInput(
      decodedObservation({
        stopReason: 'tool_calls',
        text: '',
        toolCalls: [
          {
            wireCallId: 'call-without-name',
            input: { encoding: 'jcs_json', value: { path: 'README.md' } }
          }
        ]
      }),
      {
        resolveToolInput(input) {
          resolvedName = input.toolName;
          const result = diagnostic('TOOL_NOT_FOUND', input.callId);
          return {
            kind: 'unknown_tool',
            diagnostic: result.artifact,
            diagnosticDigest: result.digest
          };
        }
      }
    )
  );
  assert.equal(result.kind, 'usable');
  assert.equal(resolvedName, '');
  assert.equal(result.turn.stopReason, 'tool_calls');
  assert.equal(result.turn.stopReason === 'tool_calls' ? result.turn.toolCalls[0].toolName : undefined, '');
  if (result.kind !== 'usable' || result.turn.stopReason !== 'tool_calls') return;
  const input = decodedArtifact<ToolCallInputV1>(result.artifacts, result.turn.toolCalls[0].inputRef);
  assert.equal(input.disposition, 'rejected_unknown_tool');
});

test('compileModelObservation rejects unsafe tool names before invoking resolution', () => {
  for (const toolName of ['bad\0name', 'x'.repeat(513), '\ud800']) {
    let resolutionCalls = 0;
    const result = compileModelObservation(
      compileInput(
        decodedObservation({
          stopReason: 'tool_calls',
          text: '',
          toolCalls: [{ wireCallId: 'call-1', toolName, input: { encoding: 'jcs_json', value: {} } }]
        }),
        {
          resolveToolInput(input) {
            resolutionCalls += 1;
            return resolveToolInput(input);
          }
        }
      )
    );
    assert.equal(result.kind, 'unusable');
    assert.equal(result.response.failureCode, 'malformed_transport_payload');
    assert.equal(resolutionCalls, 0);
  }
});

test('context compaction accepts only bounded text-only end turns with the requested output cap', () => {
  const compactionBase = {
    ...compileInput(decodedObservation({ text: '# Summary\n\nComplete.', stopReason: 'end' })),
    negotiatedMode: 'text-only' as const,
    request: {
      kind: 'context_compaction' as const,
      requestRef: REQUEST_REF,
      requestDigest: REQUEST_DIGEST
    },
    compaction: {
      maximumOutputTokens: 8
    }
  } satisfies CompileModelObservationInput;
  const accepted = compileModelObservation(compactionBase);
  assert.equal(accepted.kind, 'usable');
  assert.equal(accepted.kind === 'usable' ? accepted.turn.stopReason : undefined, 'end');

  const overTokenCap = compileModelObservation({
    ...compactionBase,
    compaction: { maximumOutputTokens: 1 },
    observation: decodedObservation({
      text: 'Summary',
      usage: { inputTokens: 1, outputTokens: 2, cacheReadTokens: 0, cacheWriteTokens: 0 }
    })
  });
  assert.equal(overTokenCap.kind, 'unusable');
  assert.equal(overTokenCap.response.failureCode, 'context_compaction_requires_end_markdown');

  const wrongMode = compileModelObservation({ ...compactionBase, negotiatedMode: 'native-tools' });
  assert.equal(wrongMode.kind, 'unusable');
  assert.equal(wrongMode.response.failureCode, 'context_compaction_requires_end_markdown');

  const toolBearing = compileModelObservation({
    ...compactionBase,
    observation: decodedObservation({
      stopReason: 'tool_calls',
      text: '',
      toolCalls: [{ wireCallId: 'call-1', toolName: 'read', input: { encoding: 'jcs_json', value: {} } }]
    })
  });
  assert.equal(toolBearing.kind, 'unusable');
  assert.equal(toolBearing.response.failureCode, 'context_compaction_requires_end_markdown');
});
