import assert from 'node:assert/strict';
import test, { mock } from 'node:test';

import { discoverOpenAICompatibleModels } from './openai-compatible-discovery.js';

test('discoverOpenAICompatibleModels reads OpenAI-compatible /models responses', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(String(_url), 'http://localhost:4000/v1/models');
    assert.equal(init?.method, 'GET');
    assert.equal((init?.headers as Record<string, string>).authorization, 'Bearer sk-local');
    return Response.json({
      data: [
        { id: 'local-coder:latest', owned_by: 'local' },
        { id: 'qwen3.5:4b' }
      ]
    });
  });

  try {
    assert.deepEqual(await discoverOpenAICompatibleModels('http://localhost:4000/v1', 'sk-local'), [
      { id: 'local-coder:latest', owned_by: 'local' },
      { id: 'qwen3.5:4b' }
    ]);
  } finally {
    fetchMock.mock.restore();
  }
});

test('discoverOpenAICompatibleModels rejects malformed model list responses clearly', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ data: null }));

  try {
    await assert.rejects(
      () => discoverOpenAICompatibleModels('http://localhost:4000/v1'),
      /OpenAI-compatible discovery response missing data array/i
    );
  } finally {
    fetchMock.mock.restore();
  }
});

test('discoverOpenAICompatibleModels filters invalid model entries and omits auth without a key', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async (_url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    assert.equal(init?.method, 'GET');
    assert.equal((init?.headers as Record<string, string> | undefined)?.authorization, undefined);
    return Response.json({
      data: [
        { id: 'valid-model' },
        { id: '' },
        { id: '   ' },
        { owned_by: 'local' },
        null,
        'not-an-object'
      ]
    });
  });

  try {
    assert.deepEqual(await discoverOpenAICompatibleModels('http://localhost:4000/v1'), [{ id: 'valid-model' }]);
  } finally {
    fetchMock.mock.restore();
  }
});

test('discoverOpenAICompatibleModels returns an empty list when the endpoint reports no models', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => Response.json({ data: [] }));

  try {
    assert.deepEqual(await discoverOpenAICompatibleModels('http://localhost:4000/v1', 'sk-local'), []);
  } finally {
    fetchMock.mock.restore();
  }
});
