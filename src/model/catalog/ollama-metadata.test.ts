import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { inspectOllamaModelMetadata } from './ollama-metadata.js';

test('inspectOllamaModelMetadata distinguishes raw, configured, and loaded context sources', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    if (String(url) === 'http://localhost:11434/api/show') {
      assert.equal(init?.method, 'POST');
      assert.equal(init?.body, JSON.stringify({ model: 'qwen3:4b' }));
      return Response.json({
        model_info: {
          'qwen.context_length': 32_768
        },
        parameters: 'temperature 0.7\nnum_ctx 8192\n'
      });
    }

    if (String(url) === 'http://localhost:11434/api/ps') {
      return Response.json({
        models: [
          {
            name: 'qwen3:4b',
            context_length: 16_384
          }
        ]
      });
    }

    throw new Error(`unexpected URL ${String(url)}`);
  });

  try {
    const metadata = await inspectOllamaModelMetadata('http://localhost:11434', 'qwen3:4b');

    assert.equal(metadata.provider, 'ollama');
    assert.equal(metadata.model, 'qwen3:4b');
    assert.equal(metadata.capabilities.contextWindow, 16_384);
    assert.deepEqual(metadata.contextWindowSources, [
      { kind: 'ollama-show-model-info', contextWindow: 32_768, confidence: 'low' },
      { kind: 'ollama-show-parameters', contextWindow: 8192, confidence: 'high' },
      { kind: 'ollama-ps', contextWindow: 16_384, confidence: 'high' }
    ]);
  } finally {
    fetchMock.mock.restore();
  }
});

test('inspectOllamaModelMetadata still returns unknown metadata when Ollama is unavailable', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => {
    throw new Error('offline');
  });

  try {
    const metadata = await inspectOllamaModelMetadata('http://localhost:11434', 'qwen3:4b');

    assert.equal(metadata.provider, 'ollama');
    assert.equal(metadata.model, 'qwen3:4b');
    assert.equal(metadata.capabilities.contextWindow, undefined);
    assert.deepEqual(metadata.contextWindowSources, []);
    assert.equal(metadata.source.kind, 'ollama-unavailable');
  } finally {
    fetchMock.mock.restore();
  }
});
