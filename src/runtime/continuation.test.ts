import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { sha256Bytes } from '../kernel/identity.js';
import type { ModelTextV1, ObservedToolCallInputV1, ToolCallInputV1 } from '../protocol/agent-ir.js';
import {
  compileModelObservation,
  modelResponseDigest,
  type CompileModelObservationInput,
  type CompiledModelObservation,
  type ObservedModelResponse,
  type ResolveToolInput
} from '../model/attempt.js';
import type { ModelRequestV1 } from '../model/request.js';
import {
  planModelContinuation,
  validateModelTurn,
  validateUnusableModelResponse,
  type ModelTurnMaterial
} from './continuation.js';

const REQUEST_REF = '1'.repeat(64);
const REQUEST_DIGEST = '2'.repeat(64);
const PROJECTION_REF = '3'.repeat(64);
const PROJECTION_DIGEST = '4'.repeat(64);
const SCHEMA_REF = '5'.repeat(64);
const SCHEMA_DIGEST = '6'.repeat(64);

function diagnostic(code: 'TOOL_NOT_FOUND' | 'TOOL_INPUT_INVALID', callId: string) {
  const withoutDigest = {
    schemaVersion: 1,
    format: 'cliq-tool-input-diagnostic-v1',
    code,
    callId
  };
  const value = { ...withoutDigest, diagnosticDigest: canonicalSha256(withoutDigest) };
  return { artifact: planCanonicalArtifact(value, value.format), digest: value.diagnosticDigest };
}

const resolveToolInput: ResolveToolInput = ({ callId, toolName, observedInput }) => {
  if (toolName === 'unknown') {
    const result = diagnostic('TOOL_NOT_FOUND', callId);
    return { kind: 'unknown_tool', diagnostic: result.artifact, diagnosticDigest: result.digest };
  }
  if (observedInput.encoding !== 'jcs_json' || typeof observedInput.value !== 'object' || observedInput.value === null ||
      Array.isArray(observedInput.value) ||
      typeof (observedInput.value as Record<string, unknown>).path !== 'string') {
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
    bytes: Buffer.from('{}'),
    observedAt: '2026-09-05T00:00:00.000Z',
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
      return usage.inputTokens + usage.outputTokens;
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

function materialFromCompile(result: Extract<CompiledModelObservation, { kind: 'usable' }>): ModelTurnMaterial {
  const text = decodedArtifact<ModelTextV1>(result.artifacts, result.turn.textRef);
  const inputs = result.turn.toolCalls.map((call) => {
    const value = decodedArtifact<ToolCallInputV1>(result.artifacts, call.inputRef);
    const observed = decodedArtifact<ObservedToolCallInputV1>(result.artifacts, value.observedInputRef);
    return { value, observed };
  });
  return { turn: result.turn, text, inputs };
}

function requestFromCompile(input: Extract<CompileModelObservationInput, { request: { kind: 'normal' } }>): ModelRequestV1 {
  const reservation = {
    inputTokens: 100,
    outputTokens: 100,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    costMicros: 1000,
    modelTokens: 100,
    toolCalls: 0,
    repairAttempts: 0
  };
  const withoutDigest = {
    schemaVersion: 1 as const,
    format: 'cliq-model-request-v1' as const,
    kind: 'normal' as const,
    runId: input.runId,
    opId: input.opId,
    attempt: input.attempt,
    assemblyRef: 'a'.repeat(64),
    assemblyDigest: 'b'.repeat(64),
    provider: input.provider,
    model: input.model,
    negotiatedMode: input.negotiatedMode,
    promptProjectionRef: input.promptProjectionRef,
    promptProjectionDigest: input.promptProjectionDigest,
    requestPath: '/responses',
    mediaType: 'application/json' as const,
    bodyBytesRef: 'c'.repeat(64),
    bodyByteCount: 0,
    streaming: true,
    maximumOutputTokens: 100,
    estimatedInputTokens: 10,
    reservation,
    requestDigest: input.request.requestDigest
  };
  return { ...withoutDigest, requestDigest: input.request.requestDigest };
}

test('validateUnusableModelResponse rejects a tampered unusable digest before charging semantics apply', () => {
  const compile = compileInput(decodedObservation({ stopReason: 'tool_calls', text: '', toolCalls: [
    { wireCallId: 'dup', toolName: 'read', input: { encoding: 'jcs_json', value: { path: 'a' } } },
    { wireCallId: 'dup', toolName: 'read', input: { encoding: 'jcs_json', value: { path: 'b' } } }
  ] }));
  const compiled = compileModelObservation(compile);
  assert.equal(compiled.kind, 'unusable');
  if (compiled.kind !== 'unusable') return;
  const request = requestFromCompile(compile);
  validateUnusableModelResponse(request, REQUEST_REF, compiled.response);
  const tampered = { ...compiled.response, unusableDigest: '0'.repeat(64) };
  assert.throws(
    () => validateUnusableModelResponse(request, REQUEST_REF, tampered),
    /does not match its prepared request/
  );
});

test('validateModelTurn rejects usage that exceeds the retained request ceiling', () => {
  const compile = compileInput(decodedObservation({
    usage: { inputTokens: 10, outputTokens: 4, cacheReadTokens: 0, cacheWriteTokens: 0 }
  }));
  const compiled = compileModelObservation(compile);
  assert.equal(compiled.kind, 'usable');
  if (compiled.kind !== 'usable') return;
  const material = materialFromCompile(compiled);
  const request = requestFromCompile(compile);
  validateModelTurn(request, material, resolveToolInput);
  const { responseDigest: _, ...withoutResponseDigest } = material.turn;
  const tamperedUsage = {
    inputTokens: 10,
    outputTokens: 4,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    costMicros: 2000
  };
  material.turn = {
    ...withoutResponseDigest,
    usage: tamperedUsage,
    responseDigest: modelResponseDigest({ ...withoutResponseDigest, usage: tamperedUsage })
  };
  assert.throws(
    () => validateModelTurn(request, material, resolveToolInput),
    /exceeds its retained request ceiling/
  );
});

test('planModelContinuation retains every rejected call and sorts invalid ids for batch rejection', () => {
  const compile = compileInput(decodedObservation({
    stopReason: 'tool_calls',
    text: '',
    toolCalls: [
      { wireCallId: 'z', toolName: 'read', input: { encoding: 'jcs_json', value: { path: 'ok.ts' } } },
      { wireCallId: 'a', toolName: 'read', input: { encoding: 'jcs_json', value: { path: 12 } } },
      { wireCallId: 'b', toolName: 'unknown', input: { encoding: 'jcs_json', value: {} } }
    ]
  }));
  const compiled = compileModelObservation(compile);
  assert.equal(compiled.kind, 'usable');
  if (compiled.kind !== 'usable') return;
  const material = materialFromCompile(compiled);
  const request = requestFromCompile(compile);
  const plan = planModelContinuation({
    request,
    turnRef: compiled.turnRef,
    material,
    throughItemSeq: 0,
    createdAt: '2026-09-05T00:00:00.000Z',
    resolveToolInput
  });
  assert.equal(plan.disposition, 'batch_rejected');
  assert.deepEqual(plan.items.map((item) => item.kind), [
    'model_turn', 'assistant_tool_batch', 'tool_result', 'tool_result', 'tool_result'
  ]);
  const results = plan.items.filter((item) => item.kind === 'tool_result');
  assert.deepEqual(results.map((item) => item.outcome), ['batch_not_executed', 'error', 'error']);
  const payloads = plan.artifacts
    .filter((artifact) => artifact.schemaKind === 'cliq-tool-result-payload-v1')
    .map((artifact) => JSON.parse(Buffer.from(artifact.bytes).toString('utf8')));
  const batchRejected = payloads.find((payload) => payload.outcome === 'batch_not_executed');
  assert.deepEqual(batchRejected?.invalidCallIds, ['a', 'b']);
  assert.equal(plan.frontier?.kind, 'agent');
});
