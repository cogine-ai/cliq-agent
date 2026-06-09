import assert from 'node:assert/strict';
import test from 'node:test';

import type { ModelCapabilities, ResolvedModelConfig } from './types.js';
import {
  buildModelPromptRequest,
  buildStructuredToolInstructions,
  buildTextActionFallbackInstructions,
  parseStructuredOutput
} from './prompt.js';
import { createToolRegistry } from '../tools/registry.js';

const modelConfig: ResolvedModelConfig = {
  provider: 'openai-compatible',
  model: 'local-model',
  baseUrl: 'http://localhost:4000/v1',
  streaming: 'auto'
};

const modelCapabilities: ModelCapabilities = {
  input: ['text'],
  output: ['text'],
  streaming: true,
  reasoning: false,
  toolCalling: true
};

test('buildModelPromptRequest separates base instructions, context, tools, output schema, capabilities, and fallback mode', () => {
  const registry = createToolRegistry();
  const request = buildModelPromptRequest({
    modelConfig,
    modelCapabilities,
    instructions: [
      {
        role: 'system',
        content: 'BASE INSTRUCTIONS',
        source: 'test',
        layer: 'core'
      }
    ],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry
  });

  assert.equal(request.baseInstructions.text, 'BASE INSTRUCTIONS');
  assert.equal(request.input[0]?.kind, 'message');
  assert.equal(request.input[0]?.content, 'hello');
  const bashSpec = request.toolSpecs.find((spec) => spec.name === 'bash');
  assert.equal(bashSpec?.inputSchema.properties?.command.type, 'string');
  assert.equal(request.outputSchema.name, 'cliq_response');
  assert.equal(request.providerCapabilities.nativeToolCalling, true);
  assert.equal(request.providerCapabilities.structuredOutput, true);
  assert.equal(request.streaming.mode, 'auto');
  assert.equal(request.textActionFallback.mode, 'disabled');
});

test('buildModelPromptRequest enables bounded text-action fallback when native tools are unavailable', () => {
  const registry = createToolRegistry();
  const request = buildModelPromptRequest({
    modelConfig: {
      provider: 'anthropic',
      model: 'claude-test',
      baseUrl: 'https://api.anthropic.com',
      streaming: 'auto'
    },
    modelCapabilities: { ...modelCapabilities, toolCalling: false },
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry
  });

  assert.equal(request.providerCapabilities.nativeToolCalling, false);
  assert.equal(request.providerCapabilities.structuredOutput, false);
  assert.equal(request.textActionFallback.mode, 'bounded');
  assert.equal(request.textActionFallback.maxAttempts, 1);
  assert.match(String(request.textActionFallback.reason), /no native tool-calling or structured-output/i);
});

test('buildModelPromptRequest gives ollama a higher text-action retry budget', () => {
  const registry = createToolRegistry();
  const request = buildModelPromptRequest({
    modelConfig: {
      provider: 'ollama',
      model: 'qwen-test',
      baseUrl: 'http://localhost:11434',
      streaming: 'auto'
    },
    modelCapabilities: { ...modelCapabilities, toolCalling: false },
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry,
    providerCapabilities: {
      nativeToolCalling: false,
      structuredOutput: false,
      streaming: true
    }
  });

  assert.equal(request.textActionFallback.mode, 'bounded');
  assert.equal(request.textActionFallback.maxAttempts, 2);
});

test('buildStructuredToolInstructions and buildTextActionFallbackInstructions include runtime tool schemas', () => {
  const registry = createToolRegistry();
  const request = buildModelPromptRequest({
    modelConfig,
    modelCapabilities,
    instructions: [{ role: 'system', content: 'BASE', source: 'test', layer: 'core' }],
    input: [{ kind: 'message', role: 'user', content: 'hello' }],
    registry
  });

  const structured = buildStructuredToolInstructions(request);
  const fallback = buildTextActionFallbackInstructions(request);

  assert.match(structured, /STRUCTURED TOOL SCHEMA MODE/);
  assert.match(structured, /bash/);
  assert.match(fallback, /TEXT ACTION FALLBACK MODE/);
  assert.match(fallback, /Available tools come from the runtime registry/);
  assert.match(fallback, /bash/);
});

test('parseStructuredOutput accepts only object tool arguments', () => {
  assert.deepEqual(parseStructuredOutput('{"type":"tool","tool":"bash","arguments":{}}'), {
    type: 'tool',
    tool: 'bash',
    arguments: {}
  });

  assert.throws(
    () => parseStructuredOutput('{"type":"tool","tool":"bash","arguments":[]}'),
    /structured output does not match Cliq response schema/
  );
  assert.throws(
    () => parseStructuredOutput('{"type":"tool","tool":"bash","arguments":null}'),
    /structured output does not match Cliq response schema/
  );
});
