import assert from 'node:assert/strict';
import test from 'node:test';

import { DEFAULT_MODEL_CONFIG, findKnownModelDescriptor, getModelProvider, isProviderName } from './registry.js';

test('registry recognizes built-in providers', () => {
  assert.equal(isProviderName('openrouter'), true);
  assert.equal(isProviderName('anthropic'), true);
  assert.equal(isProviderName('openai'), true);
  assert.equal(isProviderName('openai-compatible'), true);
  assert.equal(isProviderName('ollama'), true);
  assert.equal(isProviderName('unknown'), false);
  assert.equal(isProviderName('toString'), false);
});

test('registry exposes safe defaults for the default provider', () => {
  assert.deepEqual(DEFAULT_MODEL_CONFIG, {
    provider: 'openrouter',
    model: 'anthropic/claude-sonnet-4.6',
    baseUrl: 'https://openrouter.ai/api/v1',
    streaming: 'auto'
  });
});

test('registry requires explicit model for ollama and openai-compatible', () => {
  assert.equal(getModelProvider('ollama').getDefaultModel(), null);
  assert.equal(getModelProvider('openai-compatible').getDefaultModel(), null);
});

test('known model descriptors are text-to-text compatible', () => {
  for (const provider of ['openrouter', 'anthropic', 'openai'] as const) {
    const descriptors = getModelProvider(provider).getKnownModels();
    assert.equal(descriptors.length > 0, true);
    assert.equal(descriptors.every((descriptor) => descriptor.capabilities.input.includes('text')), true);
    assert.equal(descriptors.every((descriptor) => descriptor.capabilities.output.includes('text')), true);
  }
});

test('known default model descriptors expose context windows', () => {
  const openrouter = findKnownModelDescriptor('openrouter', 'anthropic/claude-sonnet-4.6');
  const anthropic = findKnownModelDescriptor('anthropic', 'claude-sonnet-4-20250514');
  const openai = findKnownModelDescriptor('openai', 'gpt-5.2');

  assert.equal(openrouter?.capabilities.contextWindow, 200_000);
  assert.equal(anthropic?.capabilities.contextWindow, 200_000);
  assert.equal(openai?.capabilities.contextWindow, 128_000);
});

test('findKnownModelDescriptor returns null for unknown models', () => {
  assert.equal(findKnownModelDescriptor('ollama', 'qwen3:4b'), null);
  assert.equal(findKnownModelDescriptor('openai-compatible', 'local-model'), null);
});
