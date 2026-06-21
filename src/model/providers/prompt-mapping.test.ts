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
  typedPromptToAnthropicInput,
  typedPromptToOpenAIMessages,
  typedRequestShouldStream
} from './prompt-mapping.js';

const modelCapabilities: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: true
};

function promptRequest(
  provider: ResolvedModelConfig['provider'],
  toolCalling = true,
  streaming: ResolvedModelConfig['streaming'] = 'auto'
) {
  const modelConfig: ResolvedModelConfig = {
    provider,
    model: 'test-model',
    baseUrl: 'http://localhost:4000/v1',
    streaming
  };
  return buildModelPromptRequest({
    modelConfig,
    modelCapabilities: { ...modelCapabilities, toolCalling },
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry: createToolRegistry()
  });
}

function promptRequestWithToolHistory(provider: ResolvedModelConfig['provider']) {
  const modelConfig: ResolvedModelConfig = {
    provider,
    model: 'test-model',
    baseUrl: 'http://localhost:4000/v1',
    streaming: 'auto'
  };
  return buildModelPromptRequest({
    modelConfig,
    modelCapabilities,
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [
      { kind: 'message', role: 'user', content: 'run pwd' },
      {
        kind: 'message',
        role: 'assistant',
        content: '',
        toolCalls: [{ id: 'call_1', name: 'bash', arguments: { command: 'pwd' } }]
      },
      {
        kind: 'tool_result',
        toolName: 'bash',
        status: 'ok',
        content: '/workspace',
        callId: 'call_1'
      }
    ],
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

test('typedRequestShouldStream requires provider streaming and a non-off streaming mode', () => {
  const streamingRequest = promptRequest('openai-compatible');
  assert.equal(typedRequestShouldStream(streamingRequest), true);

  const offRequest = promptRequest('openai-compatible', true, 'off');
  assert.equal(typedRequestShouldStream(offRequest), false);

  const noProviderStreaming = buildModelPromptRequest({
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
  assert.equal(typedRequestShouldStream(noProviderStreaming), false);
});

test('typedPromptToOpenAIMessages maps native tool history into OpenAI chat roles', () => {
  const request = promptRequestWithToolHistory('openai-compatible');
  const messages = typedPromptToOpenAIMessages(request, 'native-tools');

  assert.deepEqual(messages[0], { role: 'system', content: 'BASE' });
  assert.deepEqual(messages[1], { role: 'user', content: 'run pwd' });
  assert.deepEqual(messages[2], {
    role: 'assistant',
    content: '',
    tool_calls: [
      {
        id: 'call_1',
        type: 'function',
        function: { name: 'bash', arguments: '{"command":"pwd"}' }
      }
    ]
  });
  assert.deepEqual(messages[3], {
    role: 'tool',
    tool_call_id: 'call_1',
    content: '/workspace'
  });
});

test('typedPromptToOpenAIMessages injects mode-specific fallback instructions', () => {
  const structuredRequest = promptRequest('openai-compatible', false);
  const structuredMessages = typedPromptToOpenAIMessages(structuredRequest, 'structured-output');
  assert.equal(structuredMessages[0]?.role, 'system');
  assert.match(structuredMessages[1]?.content ?? '', /STRUCTURED TOOL SCHEMA MODE/);

  const textActionRequest = promptRequest('anthropic', false);
  const textActionMessages = typedPromptToOpenAIMessages(textActionRequest, 'text-action');
  assert.equal(textActionMessages[0]?.role, 'system');
  assert.match(textActionMessages[1]?.content ?? '', /TEXT ACTION FALLBACK MODE/);
});

test('typedPromptToOpenAIMessages falls back to user content for tool results outside native-tools mode', () => {
  const request = promptRequestWithToolHistory('openai-compatible');
  const messages = typedPromptToOpenAIMessages(request, 'structured-output');

  const toolResult = messages.find((message) => message.content === '/workspace');
  assert.ok(toolResult);
  assert.equal(toolResult.role, 'user');
  assert.equal(toolResult.tool_call_id, undefined);
});

test('typedPromptToAnthropicInput serializes native tool history and mode instructions', () => {
  const request = promptRequestWithToolHistory('anthropic');
  const { system, messages } = typedPromptToAnthropicInput(request, 'native-tools');

  assert.equal(system, 'BASE');
  assert.deepEqual(messages[0], { role: 'user', content: 'run pwd' });
  assert.deepEqual(messages[1], {
    role: 'assistant',
    content: [
      {
        type: 'tool_use',
        id: 'call_1',
        name: 'bash',
        input: { command: 'pwd' }
      }
    ]
  });
  assert.deepEqual(messages[2], {
    role: 'user',
    content: [
      {
        type: 'tool_result',
        tool_use_id: 'call_1',
        content: '/workspace'
      }
    ]
  });
});

test('typedPromptToAnthropicInput marks error tool results and appends text-action guidance', () => {
  const request = buildModelPromptRequest({
    modelConfig: {
      provider: 'anthropic',
      model: 'test-model',
      baseUrl: 'http://localhost:4000/v1',
      streaming: 'auto'
    },
    modelCapabilities: { ...modelCapabilities, toolCalling: false },
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [
      {
        kind: 'tool_result',
        toolName: 'bash',
        status: 'error',
        content: 'command failed',
        callId: 'call_9'
      }
    ],
    registry: createToolRegistry()
  });

  const native = typedPromptToAnthropicInput(request, 'native-tools');
  assert.deepEqual(native.messages[0], {
    role: 'user',
    content: [
      {
        type: 'tool_result',
        tool_use_id: 'call_9',
        content: 'command failed',
        is_error: true
      }
    ]
  });

  const textAction = typedPromptToAnthropicInput(request, 'text-action');
  assert.match(textAction.system, /BASE/);
  assert.match(textAction.system, /TEXT ACTION FALLBACK MODE/);
});
