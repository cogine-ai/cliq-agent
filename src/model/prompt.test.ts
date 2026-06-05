import assert from 'node:assert/strict';
import test from 'node:test';

import type { ModelCapabilities, ResolvedModelConfig } from './types.js';
import { buildModelPromptRequest } from './prompt.js';
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
