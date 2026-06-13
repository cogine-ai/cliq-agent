import assert from 'node:assert/strict';
import test from 'node:test';

import { buildModelPromptRequest } from '../prompt.js';
import type { ModelCapabilities, ResolvedModelConfig } from '../types.js';
import { createToolRegistry } from '../../tools/registry.js';
import {
  captureOpenAIToolCallDeltas,
  effectiveTypedRequest,
  maybeParseStructuredOutput,
  openAIToolCallsFromDeltaParts,
  parseOllamaToolCalls,
  parseOpenAIToolCalls,
  selectTypedRequestMode,
  typedRequestShouldStream
} from './prompt-mapping.js';

const modelCapabilities: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: true
};

function promptRequest(provider: ResolvedModelConfig['provider'], toolCalling = true) {
  const modelConfig: ResolvedModelConfig = {
    provider,
    model: 'test-model',
    baseUrl: 'http://localhost:4000/v1',
    streaming: 'auto'
  };
  return buildModelPromptRequest({
    modelConfig,
    modelCapabilities: { ...modelCapabilities, toolCalling },
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry: createToolRegistry()
  });
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

test('selectTypedRequestMode prefers native tools when the provider supports them', () => {
  const request = promptRequest('openai-compatible');
  assert.equal(selectTypedRequestMode(request), 'native-tools');
});

test('selectTypedRequestMode falls back to structured output when native tools are unavailable', () => {
  const request = promptRequest('openai-compatible', false);
  assert.equal(selectTypedRequestMode(request), 'structured-output');
});

test('selectTypedRequestMode uses text-action when neither native tools nor structured output apply', () => {
  const request = promptRequest('anthropic', false);
  assert.equal(selectTypedRequestMode(request), 'text-action');
});

test('typedRequestShouldStream returns false when session streaming mode is off', () => {
  const request = buildModelPromptRequest({
    modelConfig: {
      provider: 'openai-compatible',
      model: 'test-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'off'
    },
    modelCapabilities,
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry: createToolRegistry()
  });

  assert.equal(typedRequestShouldStream(request), false);
});

test('typedRequestShouldStream returns false when the provider lacks streaming capability', () => {
  const request = buildModelPromptRequest({
    modelConfig: {
      provider: 'openai-compatible',
      model: 'test-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'auto'
    },
    modelCapabilities: { ...modelCapabilities, streaming: false },
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry: createToolRegistry()
  });

  assert.equal(typedRequestShouldStream(request), false);
});

test('typedRequestShouldStream returns true for on/auto when the provider supports streaming', () => {
  const autoRequest = promptRequest('openai-compatible');
  const onRequest = buildModelPromptRequest({
    modelConfig: {
      provider: 'openai-compatible',
      model: 'test-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'on'
    },
    modelCapabilities,
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry: createToolRegistry()
  });

  assert.equal(typedRequestShouldStream(autoRequest), true);
  assert.equal(typedRequestShouldStream(onRequest), true);
});

test('effectiveTypedRequest summarizes the resolved provider request shape', () => {
  const request = promptRequest('openai-compatible');
  const mode = selectTypedRequestMode(request);
  const effective = effectiveTypedRequest(request, mode, true);

  assert.equal(effective.provider, 'openai-compatible');
  assert.equal(effective.mode, 'native-tools');
  assert.equal(effective.streaming, true);
  assert.equal(effective.baseInstructionChars, request.baseInstructions.text.length);
  assert.equal(effective.inputItemCount, 1);
  assert.ok(effective.toolNames.includes('bash'));
  assert.equal(effective.outputSchema, undefined);
});

test('maybeParseStructuredOutput only parses in structured-output and text-action modes', () => {
  const payload = '{"type":"final","message":"done"}';

  assert.deepEqual(maybeParseStructuredOutput('structured-output', payload), {
    type: 'final',
    message: 'done'
  });
  assert.deepEqual(maybeParseStructuredOutput('text-action', payload), {
    type: 'final',
    message: 'done'
  });
  assert.equal(maybeParseStructuredOutput('native-tools', payload), undefined);
});

test('captureOpenAIToolCallDeltas assembles streaming tool call fragments', () => {
  const accumulator = new Map();

  assert.equal(
    captureOpenAIToolCallDeltas(
      {
        choices: [
          {
            delta: {
              content: 'thinking',
              tool_calls: [{ index: 0, id: 'call_1', function: { name: 'bash', arguments: '{"command":"' } }]
            }
          }
        ]
      },
      accumulator
    ),
    'thinking'
  );

  captureOpenAIToolCallDeltas(
    {
      choices: [
        {
          delta: {
            tool_calls: [{ index: 0, function: { arguments: 'pwd"}' } }]
          }
        }
      ]
    },
    accumulator
  );

  assert.deepEqual(openAIToolCallsFromDeltaParts(accumulator), [
    { id: 'call_1', name: 'bash', arguments: { command: 'pwd' } }
  ]);
});
