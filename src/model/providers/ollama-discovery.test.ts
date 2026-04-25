import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { discoverOllamaModels, selectDefaultOllamaModel } from './ollama-discovery.js';

test('selectDefaultOllamaModel prefers qwen models', () => {
  assert.equal(
    selectDefaultOllamaModel([
      { name: 'llama3.2:latest' },
      { name: 'qwen3:4b' },
      { name: 'mistral:latest' }
    ]),
    'qwen3:4b'
  );
});

test('selectDefaultOllamaModel falls back to the first available model', () => {
  assert.equal(selectDefaultOllamaModel([{ name: 'llama3.2:latest' }, { name: 'mistral:latest' }]), 'llama3.2:latest');
});

test('discoverOllamaModels reads local tags', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:11434/api/tags');
    assert.equal(init?.method, 'GET');
    return Response.json({
      models: [
        { name: 'llama3.2:latest', modified_at: '2026-04-01T00:00:00Z', size: 1_000 },
        { name: 'qwen3:4b', digest: 'abc' }
      ]
    });
  });

  try {
    assert.deepEqual(await discoverOllamaModels('http://localhost:11434'), [
      { name: 'llama3.2:latest', modified_at: '2026-04-01T00:00:00Z', size: 1_000 },
      { name: 'qwen3:4b', digest: 'abc' }
    ]);
  } finally {
    fetchMock.mock.restore();
  }
});

test('discoverOllamaModels rejects malformed tags responses clearly', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json(null));

  try {
    await assert.rejects(
      () => discoverOllamaModels('http://localhost:11434'),
      /Ollama discovery response missing models array/i
    );
  } finally {
    fetchMock.mock.restore();
  }
});
