import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import type { ProviderName } from '../kernel/types.js';
import type { ModelTextV1, ToolCallInputV1 } from '../protocol/agent-ir.js';
import type { ObservedToolArguments } from '../protocol/agent-ir.js';
import { type ResolveToolInput, type CompiledModelObservation } from './attempt.js';
import { validateRunAssembly } from './run-assembly.js';
import { priceTableDigest } from './pricing.js';
import { MISSING_TOOL_NAME, type NormalPromptProjectionV1 } from './request.js';
import { normalInput, ref, reseal, testFixture } from './testing/fixtures.js';

const AT = '2026-09-05T00:00:02.000Z';
const SCHEMA_REF = normalInput(testFixture()).projection.tools[0]!.inputSchemaRef;
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
  const unknown = toolName !== 'read_file';
  const value = observedInput.encoding === 'jcs_json' ? observedInput.value : null;
  if (
    unknown ||
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    typeof (value as Record<string, unknown>).path !== 'string'
  ) {
    const failure = diagnostic(unknown ? 'TOOL_NOT_FOUND' : 'TOOL_INPUT_INVALID', callId);
    return unknown
      ? { kind: 'unknown_tool', diagnostic: failure.artifact, diagnosticDigest: failure.digest }
      : {
          kind: 'invalid_input',
          inputSchemaRef: SCHEMA_REF,
          inputSchemaDigest: SCHEMA_REF,
          diagnostic: failure.artifact,
          diagnosticDigest: failure.digest
        };
  }
  return {
    kind: 'resolved',
    inputSchemaRef: SCHEMA_REF,
    inputSchemaDigest: SCHEMA_REF,
    value: value as Record<string, unknown>
  };
};
function load(input = testFixture()) {
  const result = validateRunAssembly(input);
  assert.equal(result.ok, true, JSON.stringify(result));
  return result.model;
}
function encode(value: unknown) {
  return Buffer.from(JSON.stringify(value));
}
function body(prepared: ReturnType<ReturnType<typeof load>['prepare']>) {
  return JSON.parse(Buffer.from(prepared.outbound.bodyBytes).toString('utf8'));
}
function artifact<T>(result: CompiledModelObservation, reference: string): T {
  const found = result.artifacts.find((item) => item.ref === reference);
  assert.ok(found);
  return JSON.parse(Buffer.from(found.bytes).toString('utf8')) as T;
}
function resealProjection(input: ReturnType<typeof normalInput>) {
  const { projectionDigest: _, ...value } = input.projection;
  input.projection.projectionDigest = canonicalSha256(value);
  input.projectionRef = planCanonicalArtifact(input.projection, input.projection.format).ref;
}
function response(output: unknown[], status = 'completed') {
  return {
    id: 'resp-1',
    model: 'model-1',
    status,
    output,
    usage: { input_tokens: 20, output_tokens: 10, input_tokens_details: { cached_tokens: 0 } }
  };
}
const call = (id: string, name: string, args: string) => ({
  type: 'function_call',
  id: 'fc_' + id,
  call_id: id,
  name,
  arguments: args
});
const message = (text: string) => ({
  type: 'message',
  id: 'msg_1',
  role: 'assistant',
  content: [{ type: 'output_text', text }]
});
const sse = (value: unknown) => Buffer.from('data: ' + JSON.stringify(value) + '\n\n');

test('model session emits a fixed native Responses request with no intermediate prompt/profile artifacts', () => {
  const input = testFixture();
  const model = load(input);
  const prepared = model.prepare(normalInput(input));
  const expected = {
    model: 'model-1',
    input: [
      { role: 'system', content: 'Use tools carefully.' },
      { role: 'user', content: 'Read the file.' }
    ],
    stream: true,
    store: false,
    max_output_tokens: 4096,
    truncation: 'disabled',
    include: ['reasoning.encrypted_content'],
    tools: [
      {
        type: 'function',
        name: 'read_file',
        description: 'Read a file.',
        strict: false,
        parameters: {
          type: 'object',
          additionalProperties: false,
          required: ['path'],
          properties: { path: { type: 'string' } }
        }
      }
    ],
    tool_choice: 'auto'
  };
  assert.deepEqual(body(prepared), expected);
  assert.deepEqual(prepared.outbound.bodyBytes, Uint8Array.from(canonicalJsonBytes(expected)));
  assert.equal(prepared.outbound.requestPath, '/responses');
  assert.equal(prepared.artifacts.length, 2);
  assert.equal(prepared.request.reservation.inputTokens, 32768);
  assert.equal(prepared.request.reservation.outputTokens, 8192);
  assert.ok(prepared.request.estimatedInputTokens < 1000);
  for (const item of prepared.artifacts)
    assert.equal(canonicalSha256(JSON.parse(Buffer.from(item.bytes).toString())), item.ref);
});

test('all six providers match independent native/text-only and streaming/non-streaming wire fixtures', () => {
  const messages = [
    { role: 'system', content: 'Use tools carefully.' },
    { role: 'user', content: 'Read the file.' }
  ];
  const schema = {
    type: 'object',
    additionalProperties: false,
    required: ['path'],
    properties: { path: { type: 'string' } }
  };
  const fn = { name: 'read_file', description: 'Read a file.', parameters: schema };
  const chat = {
    model: 'model-1',
    messages,
    stream: true,
    stream_options: { include_usage: true },
    tools: [{ type: 'function', function: fn }],
    tool_choice: 'auto'
  };
  const cases: Record<ProviderName, { path: string; expected: Record<string, unknown> }> = {
    openai: {
      path: '/responses',
      expected: {
        model: 'model-1',
        input: messages,
        stream: true,
        store: false,
        max_output_tokens: 4096,
        truncation: 'disabled',
        include: ['reasoning.encrypted_content'],
        tools: [{ type: 'function', ...fn, strict: false }],
        tool_choice: 'auto'
      }
    },
    anthropic: {
      path: '/v1/messages',
      expected: {
        model: 'model-1',
        system: 'Use tools carefully.',
        stream: true,
        max_tokens: 4096,
        messages: [{ role: 'user', content: [{ type: 'text', text: 'Read the file.' }] }],
        tools: [{ name: 'read_file', description: 'Read a file.', input_schema: schema }]
      }
    },
    openrouter: { path: '/chat/completions', expected: { ...chat, max_completion_tokens: 4096 } },
    'openai-compatible': { path: '/chat/completions', expected: { ...chat, max_tokens: 4096 } },
    zhipu: { path: '/chat/completions', expected: { ...chat, max_tokens: 4096 } },
    ollama: {
      path: '/api/chat',
      expected: {
        model: 'model-1',
        messages,
        stream: true,
        options: { num_predict: 4096, num_ctx: 32768 },
        tools: [{ type: 'function', function: fn }]
      }
    }
  };
  for (const provider of Object.keys(cases) as ProviderName[]) {
    for (const native of [true, false]) {
      for (const streaming of [true, false]) {
        const input = testFixture(provider, native);
        input.assembly.provider.negotiation.streaming = streaming;
        reseal(input);
        const prepared = load(input).prepare(normalInput(input));
        const expected = structuredClone(cases[provider].expected);
        if (!native) {
          delete expected.tools;
          delete expected.tool_choice;
        }
        if (!streaming) {
          expected.stream = false;
          delete expected.stream_options;
        }
        assert.equal(prepared.outbound.requestPath, cases[provider].path);
        assert.deepEqual(body(prepared), expected);
        assert.deepEqual(prepared.outbound.bodyBytes, Uint8Array.from(canonicalJsonBytes(expected)));
        assert.equal(prepared.request.reservation.costMicros === 0, provider === 'ollama');
      }
    }
  }
});

test('loading snapshots every static authority and preparation never calls its verification callbacks again', () => {
  const input = testFixture();
  const prompt = normalInput(input);
  let checks = 0;
  input.material.verifyReference = () => {
    checks++;
    return true;
  };
  const model = load(input);
  const initialChecks = checks;
  const before = model.prepare(prompt);
  input.material.priceTable!.value.prices = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  input.assembly.provider.negotiation.exposedToolNames.length = 0;
  const after = model.prepare(prompt);
  assert.equal(before.requestRef, after.requestRef);
  assert.equal(after.request.reservation.costMicros, 114688);
  assert.equal(checks, initialChecks);
  assert.throws(() => {
    after.request.reservation.costMicros = 0;
  }, TypeError);
  const bytes = after.outbound.bodyBytes;
  bytes.fill(0);
  assert.deepEqual(after.outbound.bodyBytes, before.outbound.bodyBytes);
  assert.equal(validateRunAssembly(input).ok, false);
});

test('request handles cannot be forged, substituted, or used with a different loaded assembly', () => {
  const input = testFixture();
  const model = load(input);
  const prepared = model.prepare(normalInput(input));
  assert.throws(() => model.start({ ...prepared }, { status: 200 }), /does not belong/);
  assert.throws(() => load(input).start(prepared, { status: 200 }), /does not belong/);
  const wrong = normalInput(input);
  wrong.projection.assemblyRef = ref(999);
  resealProjection(wrong);
  assert.throws(() => model.prepare(wrong), /projection/);
  assert.throws(() => model.prepare({ ...normalInput(input), kind: 'unknown' } as never), /unsupported/);
  const extended = normalInput(input);
  Object.assign(extended.invocation, { kind: 'context_compaction' });
  assert.throws(() => model.prepare(extended), /invocation.*shape/);
});

test('object-native histories preserve typed arguments and malformed fragments without decoding them again', () => {
  const args: ObservedToolArguments[] = [
    { encoding: 'jcs_json', value: { path: 'one.ts' } },
    { encoding: 'utf8_json_fragment', utf8: '{"path":' },
    { encoding: 'jcs_json', value: [1, 2] }
  ];
  for (const provider of ['anthropic', 'ollama'] as const) {
    const input = testFixture(provider);
    const prepared = load(input).prepare(
      normalInput(input, [
        {
          index: 2,
          role: 'assistant',
          sourceItemId: 'batch-1',
          contentUtf8: '',
          toolCalls: args.map((value, index) => ({
            index,
            callId: 'call-' + index,
            toolName: 'read_file',
            inputRef: ref(100 + index),
            inputDigest: ref(200 + index),
            arguments: value
          }))
        },
        ...args.map((_, index) => ({
          index: index + 3,
          role: 'tool' as const,
          sourceItemId: 'result-' + index,
          toolCallId: 'call-' + index,
          contentUtf8: 'Batch rejected before dispatch.'
        }))
      ])
    );
    const assistant = body(prepared).messages.find((entry: { role: string }) => entry.role === 'assistant');
    const retained =
      provider === 'anthropic'
        ? assistant.content.map((entry: { input: unknown }) => entry.input)
        : assistant.tool_calls.map((entry: { function: { arguments: unknown } }) => entry.function.arguments);
    assert.deepEqual(retained, [
      args[0]!.value,
      { __cliqRetainedInput: { format: 'cliq-retained-provider-tool-input-v1', ...args[1] } },
      { __cliqRetainedInput: { format: 'cliq-retained-provider-tool-input-v1', ...args[2] } }
    ]);
  }
});

test('retained projections recreate exactly the same request after reloading authority', () => {
  const input = testFixture();
  const saved = JSON.stringify(normalInput(input));
  const before = load(input).prepare(JSON.parse(saved));
  const after = load(input).prepare(JSON.parse(saved));
  assert.equal(after.requestRef, before.requestRef);
  assert.deepEqual(after.outbound.bodyBytes, before.outbound.bodyBytes);
});

test('schema/description drift is rejected even when the exposed tool names and projection digest match', () => {
  const input = testFixture();
  const model = load(input);
  for (const change of [
    (p: NormalPromptProjectionV1) => {
      p.tools[0]!.description = 'Unapproved tool instructions';
    },
    (p: NormalPromptProjectionV1) => {
      p.tools[0]!.inputSchema = { type: 'object' };
    }
  ]) {
    const prompt = normalInput(input);
    change(prompt.projection);
    resealProjection(prompt);
    assert.throws(() => model.prepare(prompt), /frozen manifest/);
  }
});

test('compaction envelope and tool closure substitution are rejected at load, not trusted through unrelated root hashes', () => {
  const input = testFixture();
  input.assembly.context.compactionPromptEnvelopeRef = ref(999);
  reseal(input);
  assert.equal(validateRunAssembly(input).ok, false);
  const tools = testFixture();
  tools.material.resolveVerifiedTools = () => null;
  assert.equal(validateRunAssembly(tools).ok, false);
});

test('small normal output caps do not impose an unrelated smaller compaction output cap', () => {
  const input = testFixture();
  input.assembly.context.reservedOutputTokens = 2048;
  input.assembly.context.hardPromptTokens = 30720;
  input.assembly.context.triggerThresholdTokens = 22528;
  reseal(input);
  const model = load(input);
  assert.equal(model.prepare(normalInput(input)).request.maximumOutputTokens, 2048);
  const compact = model.prepare({
    kind: 'context_compaction',
    invocation: { runId: 'run-1', opId: 'compact-1', attempt: 1 },
    compactionPlanRef: ref(500),
    sourceContextUtf8: 'Previous work.'
  });
  assert.equal(compact.request.maximumOutputTokens, 4096);
  assert.equal(compact.request.negotiatedMode, 'text-only');
  assert.equal(body(compact).tools, undefined);
  assert.deepEqual(body(compact).input, [
    { role: 'system', content: 'Summarize faithfully.' },
    { role: 'user', content: 'Summarize this context:\n\nPrevious work.\n\nReturn Markdown only.' }
  ]);
});

test('Responses retains all calls including a missing name and malformed input, and closes a second request', () => {
  const input = testFixture();
  const model = load(input);
  const prepared = model.prepare(normalInput(input));
  const reader = model.start(prepared, { status: 200, mediaType: 'application/json' });
  reader.push(
    encode(
      response([
        { type: 'reasoning', id: 'rs_1', summary: [], encrypted_content: 'opaque-signature' },
        call('one', 'read_file', '{"path":"one.ts"}'),
        call('two', '', '{"path":'),
        call('three', 'read_file', '{"path":"three.ts"}')
      ])
    )
  );
  const result = reader.finish(AT, resolveToolInput);
  assert.equal(result.kind, 'usable');
  if (result.kind !== 'usable') return;
  assert.equal(result.turn.toolCalls.length, 3);
  assert.deepEqual(JSON.parse(JSON.stringify(result.turn.continuation?.items)), [
    { type: 'reasoning', id: 'rs_1', summary: [], encrypted_content: 'opaque-signature' }
  ]);
  const inputs = result.turn.toolCalls.map((item) => artifact<ToolCallInputV1>(result, item.inputRef));
  assert.deepEqual(
    inputs.map((item) => item.disposition),
    ['resolved', 'rejected_unknown_tool', 'resolved']
  );
  const extra: NormalPromptProjectionV1['messages'] = [
    {
      index: 2,
      role: 'assistant',
      sourceItemId: 'turn-1',
      contentUtf8: artifact<ModelTextV1>(result, result.turn.textRef).utf8,
      continuation: result.turn.continuation,
      toolCalls: result.turn.toolCalls.map((item, index) => ({
        ...item,
        arguments:
          index === 1
            ? { encoding: 'utf8_json_fragment' as const, utf8: '{"path":' }
            : { encoding: 'jcs_json' as const, value: { path: index === 0 ? 'one.ts' : 'three.ts' } }
      }))
    },
    ...result.turn.toolCalls.map((item, index) => ({
      index: index + 3,
      role: 'tool' as const,
      sourceItemId: 'result-' + index,
      toolCallId: item.callId,
      contentUtf8: index === 1 ? 'Rejected missing tool name and invalid input.' : 'Batch not executed.'
    }))
  ];
  const second = model.prepare(normalInput(input, extra));
  const outbound = body(second);
  assert.equal(outbound.input.filter((item: { type?: string }) => item.type === 'function_call').length, 3);
  assert.equal(
    outbound.input.find(
      (item: { call_id?: string; type?: string }) => item.type === 'function_call' && item.call_id === 'two'
    ).name,
    MISSING_TOOL_NAME
  );
  assert.deepEqual(canonicalJsonBytes(outbound.input[2]), canonicalJsonBytes(result.turn.continuation!.items[0]));
  assert.throws(() => model.prepare(normalInput(input, extra.slice(0, -1))), /unclosed/);
});

test('streaming delivers deltas before terminal bytes, preserves UTF-8 chunking, and compiles only after completion', () => {
  const input = testFixture();
  const model = load(input);
  const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType: 'text/event-stream' });
  reader.push(sse({ type: 'response.created', response: { id: 'resp-1', model: 'model-1' } }));
  reader.push(sse({ type: 'response.output_item.added', output_index: 0, item: message('') }));
  const events = [...sse({ type: 'response.output_text.delta', output_index: 0, delta: '你好' })].flatMap((byte) =>
    reader.push(Uint8Array.of(byte))
  );
  assert.deepEqual(events, [{ type: 'text_delta', text: '你好' }]);
  reader.push(sse({ type: 'response.completed', response: response([message('你好')]) }));
  const result = reader.finish(AT, resolveToolInput);
  assert.equal(result.kind, 'usable');
  assert.deepEqual(
    result.events.map((event) => event.type),
    ['usage', 'end']
  );
  assert.throws(() => reader.push(Buffer.from('later')), /closed/);
});

test('model sessions ignore a leading wire BOM without losing initial deltas or embedded BOM characters', () => {
  const cases: Array<{ provider: ProviderName; mediaType: string; payload: Buffer }> = [
    {
      provider: 'openai-compatible',
      mediaType: 'text/event-stream',
      payload: Buffer.concat([
        sse({ model: 'model-1', choices: [{ index: 0, delta: { content: 'first ' }, finish_reason: null }] }),
        sse({ model: 'model-1', choices: [{ index: 0, delta: { content: '\uFEFFsecond' }, finish_reason: 'stop' }] }),
        Buffer.from('data: [DONE]\n\n')
      ])
    },
    {
      provider: 'openai',
      mediaType: 'application/json',
      payload: encode(response([message('first \uFEFFsecond')]))
    },
    {
      provider: 'ollama',
      mediaType: 'application/x-ndjson',
      payload: Buffer.concat([
        encode({ model: 'model-1', message: { content: 'first ' }, done: false }),
        Buffer.from('\n'),
        encode({ model: 'model-1', message: { content: '\uFEFFsecond' }, done: true, done_reason: 'stop' }),
        Buffer.from('\n')
      ])
    }
  ];
  for (const { provider, mediaType, payload } of cases) {
    const input = testFixture(provider);
    const model = load(input);
    const bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), payload]);
    for (const chunked of [false, true]) {
      const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType });
      const events = chunked
        ? [...bytes].flatMap((byte) => reader.push(Uint8Array.of(byte)))
        : reader.push(bytes);
      const result = reader.finish(AT, resolveToolInput);
      const label = `${provider}, chunked=${chunked}`;
      assert.equal(result.kind, 'usable', label);
      assert.equal(result.turn.stopReason, 'end', label);
      assert.equal(artifact<ModelTextV1>(result, result.turn.textRef).utf8, 'first \uFEFFsecond', label);
      assert.equal(
        [...events, ...result.events].filter((event) => event.type === 'text_delta').map((event) => event.text).join(''),
        'first \uFEFFsecond',
        label
      );
    }
  }
});

test('truncated or contradictory streams cannot produce usable turns', () => {
  const input = testFixture();
  const model = load(input);
  for (const terminal of [undefined, 'different']) {
    const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType: 'text/event-stream' });
    reader.push(sse({ type: 'response.output_item.added', output_index: 0, item: message('') }));
    reader.push(sse({ type: 'response.output_text.delta', output_index: 0, delta: 'partial' }));
    if (terminal) reader.push(sse({ type: 'response.completed', response: response([message(terminal)]) }));
    const result = reader.finish(AT, resolveToolInput);
    assert.equal(result.kind, 'unusable');
  }
});

test('model sessions accept the zero-based attempt identity owned by the durable Journal', () => {
  const input = testFixture();
  const model = load(input);
  const normal = normalInput(input);
  normal.invocation.attempt = 0;
  const prepared = model.prepare(normal);
  assert.equal(prepared.request.attempt, 0);
  const reader = model.start(prepared, { status: 200, mediaType: 'application/json' });
  reader.push(encode(response([message('Done.')])));
  assert.equal(reader.finish(AT, resolveToolInput).kind, 'usable');
  normal.invocation.attempt = -1;
  assert.throws(() => model.prepare(normal), /attempt/);
});

test('signed request ceilings are mandatory and input estimates never reduce their reservations', () => {
  const input = testFixture();
  const material = input.material.priceTable!;
  const table = material.value;
  delete (table as Partial<typeof table>).requestTokenCeiling;
  table.tableDigest = priceTableDigest(table);
  material.ref = planCanonicalArtifact(table, table.format).ref;
  assert.equal(input.assembly.provider.pricing.kind, 'trusted_price_table');
  input.assembly.provider.pricing.priceTableRef = material.ref;
  input.assembly.provider.pricing.priceTableDigest = table.tableDigest;
  reseal(input);
  assert.deepEqual(validateRunAssembly(input), {
    ok: false,
    code: 'MODEL_COST_UNKNOWN',
    reason: 'pricing_authority_invalid'
  });
  const valid = testFixture();
  const model = load(valid);
  const short = model.prepare(normalInput(valid));
  const long = normalInput(valid);
  long.projection.messages[1]!.contentUtf8 += 'More context. '.repeat(100);
  resealProjection(long);
  const prepared = model.prepare(long);
  assert.ok(prepared.request.estimatedInputTokens > short.request.estimatedInputTokens);
  assert.deepEqual(prepared.request.reservation, short.request.reservation);
});

test('cancellation requires a StopIntent, cannot execute partial calls, and cannot overwrite a completed response', () => {
  const input = testFixture();
  const model = load(input);
  for (const [mediaType, partialUtf8] of [
    ['text/event-stream', false],
    ['text/event-stream', true],
    ['application/json', false],
    ['application/json', true]
  ] as const) {
    const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType });
    reader.push(
      Buffer.from(mediaType === 'application/json' ? '{"output":[' : 'data: {"type":"response.function_call')
    );
    if (partialUtf8) reader.push(Uint8Array.of(0xe4, 0xbd));
    assert.throws(() => reader.abort(AT, 'not-a-ref', resolveToolInput));
    const result = reader.abort(AT, ref(900), () => {
      throw new Error('partial calls must not be resolved');
    });
    assert.equal(result.kind, 'usable');
    if (result.kind !== 'usable') continue;
    assert.equal(result.turn.stopReason, 'cancelled');
    assert.deepEqual(result.turn.toolCalls, []);
    assert.deepEqual(result.events, [{ type: 'end', stopReason: 'cancelled' }]);
    assert.throws(() => reader.finish(AT, resolveToolInput), /closed/);
  }
  const complete = model.start(model.prepare(normalInput(input)), { status: 200, mediaType: 'text/event-stream' });
  complete.push(sse({ type: 'response.completed', response: response([message('Already finished.')]) }));
  const result = complete.abort(AT, ref(900), resolveToolInput);
  assert.equal(result.kind, 'usable');
  if (result.kind === 'usable') assert.equal(result.turn.stopReason, 'end');
  assert.deepEqual(
    result.events.map((event) => event.type),
    ['text_delta', 'usage', 'end']
  );
});

test('usage components and tool resolution remain bound to the prepared request', () => {
  const input = testFixture();
  const model = load(input);
  for (const usage of [
    { input_tokens: 32769, output_tokens: 1 },
    { input_tokens: 1, output_tokens: 4097 },
    { input_tokens: 1, output_tokens: 1, input_tokens_details: { cached_tokens: 32769 } }
  ]) {
    const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType: 'application/json' });
    reader.push(encode({ ...response([message('Done.')]), usage }));
    assert.equal(reader.finish(AT, resolveToolInput).kind, 'unusable');
  }
  const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType: 'application/json' });
  reader.push(encode(response([call('one', 'read_file', '{"path":"one.ts"}')])));
  assert.throws(
    () =>
      reader.finish(AT, () => ({
        kind: 'resolved',
        inputSchemaRef: ref(1),
        inputSchemaDigest: ref(1),
        value: { path: 'one.ts' }
      })),
    /frozen tool contract/
  );
});

test('Responses rejects streamed identity substitution and delivers complete tool events once', () => {
  const input = testFixture();
  const model = load(input);
  for (const changed of [false, true]) {
    const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType: 'text/event-stream' });
    const start = reader.push(
      sse({ type: 'response.output_item.added', output_index: 0, item: call('one', 'read_file', '') })
    );
    assert.deepEqual(
      start.map((event) => event.type),
      ['start', 'tool_call_start']
    );
    reader.push(sse({ type: 'response.function_call_arguments.delta', output_index: 0, delta: '{"path":"one.ts"}' }));
    reader.push(
      sse({
        type: 'response.completed',
        response: response([call(changed ? 'different' : 'one', 'read_file', '{"path":"one.ts"}')])
      })
    );
    const result = reader.finish(AT, resolveToolInput);
    assert.equal(result.kind, changed ? 'unusable' : 'usable');
    assert.deepEqual(
      result.events.map((event) => event.type),
      changed ? ['error'] : ['tool_call_complete', 'usage', 'end']
    );
  }
});

test('Anthropic thinking signatures and redacted blocks survive streamed observation and the next native request', () => {
  const input = testFixture('anthropic');
  const model = load(input);
  const reader = model.start(model.prepare(normalInput(input)), { status: 200, mediaType: 'text/event-stream' });
  const records = [
    {
      type: 'message_start',
      message: { id: 'msg-1', model: 'model-1', usage: { input_tokens: 10, output_tokens: 0 } }
    },
    { type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '', signature: '' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: 'Plan.' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'signature_delta', signature: 'opaque-' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'signature_delta', signature: 'signature' } },
    { type: 'content_block_stop', index: 0 },
    { type: 'content_block_start', index: 1, content_block: { type: 'redacted_thinking', data: 'ciphertext' } },
    { type: 'content_block_stop', index: 1 },
    { type: 'content_block_start', index: 2, content_block: { type: 'text', text: 'Done.' } },
    { type: 'content_block_stop', index: 2 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 10 } },
    { type: 'message_stop' }
  ];
  // CRLF split across chunks exercises the same framer as Responses.
  for (const record of records)
    for (const byte of Buffer.from('data: ' + JSON.stringify(record) + '\r\n\r\n')) reader.push(Uint8Array.of(byte));
  const result = reader.finish(AT, resolveToolInput);
  assert.equal(result.kind, 'usable');
  if (result.kind !== 'usable') return;
  const second = model.prepare(
    normalInput(input, [
      {
        index: 2,
        role: 'assistant',
        sourceItemId: 'turn-1',
        contentUtf8: 'Done.',
        toolCalls: [],
        continuation: result.turn.continuation
      },
      { index: 3, role: 'user', sourceKind: 'user_input', sourceId: 'input-2', contentUtf8: 'Continue.' }
    ])
  );
  assert.deepEqual(body(second).messages[1].content, [
    { type: 'thinking', thinking: 'Plan.', signature: 'opaque-signature' },
    { type: 'redacted_thinking', data: 'ciphertext' },
    { type: 'text', text: 'Done.' }
  ]);
});
