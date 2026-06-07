import assert from 'node:assert/strict';
import test from 'node:test';

import type { ModelPromptRequest } from '../types.js';
import {
  captureOpenAIToolCallDeltas,
  maybeParseStructuredOutput,
  openAIToolCallsFromDeltaParts,
  parseOllamaToolCalls,
  parseOpenAIToolCalls,
  selectTypedRequestMode
} from './prompt-mapping.js';

function promptRequest(overrides: {
  nativeToolCalling?: boolean;
  structuredOutput?: boolean;
  toolSpecs?: ModelPromptRequest['toolSpecs'];
}): ModelPromptRequest {
  return {
    kind: 'model-prompt-request',
    model: {
      provider: 'openai-compatible',
      model: 'local-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'auto'
    },
    baseInstructions: { messages: [], text: '' },
    input: [],
    toolSpecs: overrides.toolSpecs ?? [],
    outputSchema: {
      name: 'cliq_response',
      strict: true,
      schema: { type: 'object' }
    },
    providerCapabilities: {
      nativeToolCalling: overrides.nativeToolCalling ?? false,
      structuredOutput: overrides.structuredOutput ?? false,
      streaming: true
    },
    streaming: { mode: 'auto' },
    textActionFallback: { mode: 'disabled', maxAttempts: 1 }
  };
}

test('parseOpenAIToolCalls skips tool calls with non-object arguments', () => {
  assert.deepEqual(
    parseOpenAIToolCalls({
      tool_calls: [
        { id: 'call_array', function: { name: 'bash', arguments: '[]' } },
        { id: 'call_null', function: { name: 'bash', arguments: 'null' } },
        { id: 'call_object', function: { name: 'bash', arguments: '{"command":"pwd"}' } }
      ]
    }),
    [{ id: 'call_object', name: 'bash', arguments: { command: 'pwd' } }]
  );
});

test('parseOllamaToolCalls skips tool calls with non-object arguments', () => {
  assert.deepEqual(
    parseOllamaToolCalls({
      tool_calls: [
        { function: { name: 'bash', arguments: [] } },
        { function: { name: 'bash', arguments: null } },
        { function: { name: 'bash', arguments: { command: 'pwd' } } }
      ]
    }),
    [{ id: 'ollama_call_3', name: 'bash', arguments: { command: 'pwd' } }]
  );
});

test('selectTypedRequestMode prefers native tools, then structured output, then text action', () => {
  const bashSpec = {
    name: 'bash',
    description: 'Run shell',
    inputSchema: { type: 'object', properties: { command: { type: 'string' } } }
  };

  assert.equal(
    selectTypedRequestMode(
      promptRequest({
        nativeToolCalling: true,
        structuredOutput: true,
        toolSpecs: [bashSpec]
      })
    ),
    'native-tools'
  );
  assert.equal(
    selectTypedRequestMode(
      promptRequest({
        nativeToolCalling: true,
        structuredOutput: true,
        toolSpecs: []
      })
    ),
    'structured-output'
  );
  assert.equal(
    selectTypedRequestMode(
      promptRequest({
        nativeToolCalling: false,
        structuredOutput: false,
        toolSpecs: [bashSpec]
      })
    ),
    'text-action'
  );
});

test('captureOpenAIToolCallDeltas assembles fragmented streaming tool calls', () => {
  const accumulator = new Map<number, { id?: string; name?: string; arguments: string }>();

  assert.equal(
    captureOpenAIToolCallDeltas(
      {
        choices: [
          {
            delta: {
              tool_calls: [{ index: 0, id: 'call_1', function: { name: 'bash', arguments: '{"command":' } }]
            }
          }
        ]
      },
      accumulator
    ),
    null
  );
  assert.equal(
    captureOpenAIToolCallDeltas(
      {
        choices: [
          {
            delta: {
              content: 'thinking',
              tool_calls: [{ index: 0, function: { arguments: '"pwd"}' } }]
            }
          }
        ]
      },
      accumulator
    ),
    'thinking'
  );

  assert.deepEqual(openAIToolCallsFromDeltaParts(accumulator), [
    { id: 'call_1', name: 'bash', arguments: { command: 'pwd' } }
  ]);
});

test('maybeParseStructuredOutput only parses in structured-output and text-action modes', () => {
  const payload = '{"type":"final","message":"ok"}';

  assert.deepEqual(maybeParseStructuredOutput('structured-output', payload), {
    type: 'final',
    message: 'ok'
  });
  assert.deepEqual(maybeParseStructuredOutput('text-action', payload), {
    type: 'final',
    message: 'ok'
  });
  assert.equal(maybeParseStructuredOutput('native-tools', payload), undefined);
});
