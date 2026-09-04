import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { ProviderName } from '../kernel/types.js';
import type { AgentNegotiatedMode } from '../protocol/agent-ir.js';
import { MODEL_RESPONSE_LIMIT_BYTES } from './attempt.js';
import {
  CONSTRAINED_MODEL_TURN_FORMAT,
  observeProviderResponse,
  type ObserveProviderResponseInput
} from './provider-observation.js';

const OBSERVED_AT = '2026-09-05T00:00:00.000Z';

function bytes(value: unknown): Uint8Array {
  return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value), 'utf8');
}

function observe(
  provider: ProviderName,
  body: unknown,
  overrides: Partial<ObserveProviderResponseInput> = {}
) {
  return observeProviderResponse({
    provider,
    model: 'model-1',
    negotiatedMode: 'native-tools',
    status: 200,
    mediaType: 'application/json',
    bytes: bytes(body),
    observedAt: OBSERVED_AT,
    ...overrides
  });
}

function plain(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value));
}

function openAiBody() {
  return {
    id: 'response-1',
    model: 'model-1',
    choices: [
      {
        index: 0,
        finish_reason: 'tool_calls',
        message: {
          content: 'working',
          reasoning_content: 'private',
          tool_calls: [
            { id: 'call-a', type: 'function', function: { name: 'alpha', arguments: '{"a":1}' } },
            { id: 'call-b', type: 'function', function: { name: 'beta', arguments: '{bad' } }
          ]
        }
      }
    ],
    usage: {
      prompt_tokens: 10,
      completion_tokens: 5,
      prompt_tokens_details: { cached_tokens: 3 }
    }
  };
}

function anthropicBody() {
  return {
    id: 'message-1',
    model: 'model-1',
    type: 'message',
    stop_reason: 'tool_use',
    content: [
      { type: 'thinking', thinking: 'private' },
      { type: 'text', text: 'working' },
      { type: 'tool_use', id: 'call-a', name: 'alpha', input: { a: 1 } },
      { type: 'tool_use', id: 'call-b', name: 'beta', input: { b: 2 } }
    ],
    usage: {
      input_tokens: 10,
      output_tokens: 5,
      cache_read_input_tokens: 3,
      cache_creation_input_tokens: 2
    }
  };
}

function ollamaBody() {
  return {
    model: 'model-1',
    done: true,
    done_reason: 'stop',
    message: {
      role: 'assistant',
      content: 'working',
      thinking: 'private',
      tool_calls: [
        { id: 'ignored-a', function: { name: 'alpha', arguments: { a: 1 } } },
        { id: 'ignored-b', function: { name: 'beta', arguments: { b: 2 } } }
      ]
    },
    prompt_eval_count: 10,
    eval_count: 5
  };
}

test('all six provider adapters preserve every native call in provider order', () => {
  const fixtures: Array<[ProviderName, unknown]> = [
    ['openai', openAiBody()],
    ['openrouter', openAiBody()],
    ['openai-compatible', openAiBody()],
    ['zhipu', openAiBody()],
    ['anthropic', anthropicBody()],
    ['ollama', ollamaBody()]
  ];
  for (const [provider, body] of fixtures) {
    const result = observe(provider, body);
    assert.equal(result.observation.kind, 'decoded', provider);
    if (result.observation.kind !== 'decoded') continue;
    assert.equal(result.observation.stopReason, 'tool_calls', provider);
    assert.equal(result.observation.toolCalls.length, 2, provider);
    assert.deepEqual(result.observation.toolCalls.map((call) => call.wireIndex), [0, 1], provider);
    assert.deepEqual(result.observation.toolCalls.map((call) => call.toolName), ['alpha', 'beta'], provider);
    assert.equal(result.events[0]?.type, 'start', provider);
    assert.equal(result.events.at(-1)?.type, 'end', provider);
  }
});

test('OpenAI-family JSON preserves valid values and exact malformed argument fragments', () => {
  const result = observe('openai', openAiBody());
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.equal(result.observation.responseId, 'response-1');
  assert.equal(result.observation.text, 'working');
  assert.equal(result.observation.reasoning, 'private');
  assert.deepEqual(result.observation.usage, {
    inputTokens: 10,
    outputTokens: 5,
    cacheReadTokens: 3,
    cacheWriteTokens: 0
  });
  assert.equal(result.observation.toolCalls[0]?.wireCallId, 'call-a');
  assert.deepEqual(plain(result.observation.toolCalls[0]?.input), {
    encoding: 'jcs_json',
    value: { a: 1 }
  });
  assert.deepEqual(result.observation.toolCalls[1]?.input, {
    encoding: 'utf8_json_fragment',
    utf8: '{bad'
  });
});

test('OpenAI streaming reconstructs three interleaved calls without reordering fragments', () => {
  const chunks = [
    {
      id: 'response-1',
      model: 'model-1',
      choices: [
        {
          index: 0,
          delta: {
            content: 'work',
            tool_calls: [
              { index: 0, id: 'call-a', function: { name: 'alpha', arguments: '{"a":' } },
              { index: 1, id: 'call-b', function: { name: 'beta', arguments: '{"b":' } }
            ]
          },
          finish_reason: null
        }
      ]
    },
    {
      id: 'response-1',
      model: 'model-1',
      choices: [
        {
          index: 0,
          delta: {
            reasoning_content: 'think',
            tool_calls: [
              { index: 1, function: { arguments: '2}' } },
              { index: 0, function: { arguments: '1}' } },
              { index: 2, id: 'call-c', function: { name: 'gamma', arguments: '{"c":3}' } }
            ]
          },
          finish_reason: null
        }
      ]
    },
    {
      id: 'response-1',
      model: 'model-1',
      choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }]
    },
    {
      id: 'response-1',
      model: 'model-1',
      choices: [],
      usage: { prompt_tokens: 12, completion_tokens: 7 }
    }
  ];
  const source = `${chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join('')}data: [DONE]\n\n`;
  const result = observe('openai', source, { mediaType: 'text/event-stream; charset=utf-8' });
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.equal(result.observation.text, 'work');
  assert.equal(result.observation.reasoning, 'think');
  assert.deepEqual(result.observation.toolCalls.map((call) => call.wireCallId), ['call-a', 'call-b', 'call-c']);
  assert.deepEqual(result.observation.toolCalls.map((call) => plain(call.input)), [
    { encoding: 'jcs_json', value: { a: 1 } },
    { encoding: 'jcs_json', value: { b: 2 } },
    { encoding: 'jcs_json', value: { c: 3 } }
  ]);
  assert.deepEqual(result.observation.usage, {
    inputTokens: 12,
    outputTokens: 7,
    cacheReadTokens: 0,
    cacheWriteTokens: 0
  });
  assert.equal(result.events.filter((event) => event.type === 'tool_call_complete').length, 3);
});

test('Anthropic streaming reconstructs interleaved tool input blocks', () => {
  const events = [
    {
      type: 'message_start',
      message: { id: 'message-1', model: 'model-1', usage: { input_tokens: 9, output_tokens: 0 } }
    },
    { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'call-a', name: 'alpha', input: {} } },
    { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 'call-b', name: 'beta', input: {} } },
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"a":' } },
    { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: '{"b":2}' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '1}' } },
    { type: 'content_block_stop', index: 1 },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 6 } },
    { type: 'message_stop' }
  ];
  const source = events.map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('');
  const result = observe('anthropic', source, { mediaType: 'text/event-stream' });
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.deepEqual(result.observation.toolCalls.map((call) => plain(call.input)), [
    { encoding: 'jcs_json', value: { a: 1 } },
    { encoding: 'jcs_json', value: { b: 2 } }
  ]);
  assert.deepEqual(result.observation.usage, {
    inputTokens: 9,
    outputTokens: 6,
    cacheReadTokens: 0,
    cacheWriteTokens: 0
  });
});

test('Ollama NDJSON retains ordered calls and complete usage', () => {
  const entries = [
    { model: 'model-1', done: false, message: { content: 'work', tool_calls: [] } },
    {
      model: 'model-1',
      done: false,
      message: { content: '', tool_calls: [{ function: { name: 'alpha', arguments: { a: 1 } } }] }
    },
    {
      model: 'model-1',
      done: true,
      done_reason: 'stop',
      message: { content: '', tool_calls: [{ function: { name: 'beta', arguments: { b: 2 } } }] },
      prompt_eval_count: 11,
      eval_count: 4
    }
  ];
  const result = observe('ollama', `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`, {
    mediaType: 'application/x-ndjson'
  });
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.equal(result.observation.stopReason, 'tool_calls');
  assert.equal(result.observation.text, 'work');
  assert.deepEqual(result.observation.toolCalls.map((call) => call.toolName), ['alpha', 'beta']);
  assert.deepEqual(result.observation.usage, {
    inputTokens: 11,
    outputTokens: 4,
    cacheReadTokens: 0,
    cacheWriteTokens: 0
  });
});

test('constrained IR accepts only the versioned completed-turn envelope and derives no wire ids', () => {
  const envelope = {
    schemaVersion: 1,
    format: CONSTRAINED_MODEL_TURN_FORMAT,
    turn: {
      stopReason: 'tool_calls',
      text: 'working',
      toolCalls: [
        { toolName: 'alpha', input: { a: 1 } },
        { toolName: 'beta', input: { b: 2 } }
      ]
    }
  };
  const result = observe('openai', {
    id: 'response-1',
    model: 'model-1',
    choices: [{ index: 0, finish_reason: 'stop', message: { content: JSON.stringify(envelope) } }]
  }, { negotiatedMode: 'constrained-ir' });
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.equal(result.observation.constrainedOutputAcknowledged, true);
  assert.equal(result.observation.stopReason, 'tool_calls');
  assert.deepEqual(result.observation.toolCalls.map((call) => call.wireCallId), [undefined, undefined]);
  assert.deepEqual(result.observation.toolCalls.map((call) => call.toolName), ['alpha', 'beta']);

  const extraField = { ...envelope, hidden: true };
  const rejected = observe('openai', {
    model: 'model-1',
    choices: [{ index: 0, finish_reason: 'stop', message: { content: JSON.stringify(extraField) } }]
  }, { negotiatedMode: 'constrained-ir' });
  assert.equal(rejected.observation.kind, 'capability_shape_mismatch');
});

test('constrained IR preserves terminal provider failures before envelope validation', () => {
  const truncated = observe('openai', {
    model: 'model-1',
    choices: [{ index: 0, finish_reason: 'length', message: { content: '{"schemaVersion":1' } }]
  }, { negotiatedMode: 'constrained-ir' });
  assert.equal(truncated.observation.kind, 'decoded');
  assert.equal(truncated.observation.kind === 'decoded' ? truncated.observation.stopReason : undefined, 'length');

  const refused = observe('openai', {
    model: 'model-1',
    choices: [{ index: 0, finish_reason: 'stop', message: { content: null, refusal: 'Cannot comply.' } }]
  }, { negotiatedMode: 'constrained-ir' });
  assert.equal(refused.observation.kind, 'decoded');
  assert.equal(refused.observation.kind === 'decoded' ? refused.observation.stopReason : undefined, 'content_filter');
});

test('OpenAI streaming refusal is classified as content filtering', () => {
  const chunks = [
    {
      id: 'response-1',
      model: 'model-1',
      choices: [{ index: 0, delta: { refusal: 'Cannot ' }, finish_reason: null }]
    },
    {
      id: 'response-1',
      model: 'model-1',
      choices: [{ index: 0, delta: { refusal: 'comply.' }, finish_reason: 'stop' }]
    }
  ];
  const source = `${chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join('')}data: [DONE]\n\n`;
  const result = observe('openai', source, { mediaType: 'text/event-stream' });
  assert.equal(result.observation.kind, 'decoded');
  assert.equal(result.observation.kind === 'decoded' ? result.observation.stopReason : undefined, 'content_filter');
});

test('text-only JSON-looking assistant content stays inert text', () => {
  const legacyAction = '{"bash":"rm -rf /tmp/should-not-run"}';
  const result = observe('zhipu', {
    model: 'model-1',
    choices: [{ index: 0, finish_reason: 'stop', message: { content: legacyAction } }]
  }, { negotiatedMode: 'text-only' });
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.equal(result.observation.text, legacyAction);
  assert.deepEqual(result.observation.toolCalls, []);
  assert.equal(result.observation.stopReason, 'end');
});

test('native malformed calls remain visible for central response-level or batch validation', () => {
  const body = openAiBody();
  body.choices[0]!.message.tool_calls = [
    { id: '', type: 'function', function: { name: 'alpha', arguments: '{}' } },
    { id: 'call-b', type: 'function', function: { name: '', arguments: '{bad' } }
  ];
  const result = observe('openai', body);
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.equal(result.observation.toolCalls.length, 2);
  assert.equal(result.observation.toolCalls[0]?.wireCallId, '');
  assert.equal(result.observation.toolCalls[1]?.toolName, '');
  assert.deepEqual(result.observation.toolCalls[1]?.input, {
    encoding: 'utf8_json_fragment',
    utf8: '{bad'
  });
});

test('strict wire parsing rejects duplicate keys, invalid UTF-8, and model substitution', () => {
  const duplicate = observe('openai', '{"model":"model-1","model":"model-1","choices":[]}');
  assert.equal(duplicate.observation.kind, 'malformed');

  const invalidUtf8 = observe('openai', null, { bytes: Uint8Array.of(0xc3, 0x28) });
  assert.equal(invalidUtf8.observation.kind, 'malformed');

  const substitution = observe('anthropic', { ...anthropicBody(), model: 'other-model' });
  assert.equal(substitution.observation.kind, 'capability_shape_mismatch');
});

test('positive HTTP and in-band provider rejections never enter decoded turns', () => {
  const redirect = observe('openrouter', { redirect: true }, { status: 307 });
  assert.equal(redirect.observation.kind, 'provider_rejection');
  const inBand = observe('openai', { error: { type: 'rate_limit_error' } });
  assert.equal(inBand.observation.kind, 'provider_rejection');
  assert.equal(inBand.events.at(-1)?.type, 'error');
});

test('oversized responses retain exactly the first limit plus one bytes', () => {
  const original = Buffer.alloc(MODEL_RESPONSE_LIMIT_BYTES + 50, 0x61);
  const result = observe('ollama', null, {
    mediaType: 'application/x-ndjson',
    bytes: original
  });
  assert.equal(result.observation.kind, 'prefix_over_limit');
  assert.equal(result.observation.bytes.byteLength, MODEL_RESPONSE_LIMIT_BYTES + 1);
  assert.deepEqual(result.observation.bytes, original.subarray(0, MODEL_RESPONSE_LIMIT_BYTES + 1));
});

test('nonterminal stop reasons retain calls for central unusable-response compilation', () => {
  const body = openAiBody();
  body.choices[0]!.finish_reason = 'length';
  const result = observe('openai', body);
  assert.equal(result.observation.kind, 'decoded');
  if (result.observation.kind !== 'decoded') return;
  assert.equal(result.observation.stopReason, 'length');
  assert.equal(result.observation.toolCalls.length, 2);
});

test('provider streams fail closed on partial usage and events after terminal boundaries', () => {
  const partialAnthropic = [
    {
      type: 'message_start',
      message: { id: 'message-1', model: 'model-1', usage: { input_tokens: 9 } }
    },
    { type: 'message_stop' }
  ]
    .map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
    .join('');
  assert.equal(
    observe('anthropic', partialAnthropic, { mediaType: 'text/event-stream' }).observation.kind,
    'malformed'
  );

  const afterOpenAiDone = [
    'data: [DONE]\n\n',
    `data: ${JSON.stringify({ model: 'model-1', choices: [] })}\n\n`
  ].join('');
  assert.equal(
    observe('openai', afterOpenAiDone, { mediaType: 'text/event-stream' }).observation.kind,
    'malformed'
  );

  const afterOpenAiFinish = [
    `data: ${JSON.stringify({
      model: 'model-1',
      choices: [{ index: 0, delta: {}, finish_reason: 'stop' }]
    })}\n\n`,
    `data: ${JSON.stringify({
      model: 'model-1',
      choices: [{ index: 0, delta: { content: 'late' }, finish_reason: null }]
    })}\n\n`,
    'data: [DONE]\n\n'
  ].join('');
  assert.equal(
    observe('openai', afterOpenAiFinish, { mediaType: 'text/event-stream' }).observation.kind,
    'malformed'
  );

  const ollamaAfterDone = [
    JSON.stringify({ model: 'model-1', done: true, done_reason: 'stop', message: { content: 'done' } }),
    JSON.stringify({ model: 'model-1', done: false, message: { content: 'late' } })
  ].join('\n');
  assert.equal(
    observe('ollama', ollamaAfterDone, { mediaType: 'application/x-ndjson' }).observation.kind,
    'malformed'
  );

  const incompleteOpenAi = `data: ${JSON.stringify({
    id: 'response-1',
    model: 'model-1',
    choices: [{ index: 0, delta: { content: 'partial' }, finish_reason: 'stop' }]
  })}\n\n`;
  assert.equal(
    observe('openai', incompleteOpenAi, { mediaType: 'text/event-stream' }).observation.kind,
    'malformed'
  );

  const invalidSignatureStream = [
    {
      type: 'message_start',
      message: { id: 'message-1', model: 'model-1', usage: { input_tokens: 1, output_tokens: 0 } }
    },
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'signature_delta', signature: 'not-thinking' } },
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 1 } },
    { type: 'message_stop' }
  ]
    .map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
    .join('');
  assert.equal(
    observe('anthropic', invalidSignatureStream, { mediaType: 'text/event-stream' }).observation.kind,
    'malformed'
  );

  const incompleteOllama = ollamaBody();
  incompleteOllama.done = false;
  assert.equal(observe('ollama', incompleteOllama).observation.kind, 'malformed');
});
