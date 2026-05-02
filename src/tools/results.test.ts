import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeToolResultForStorage } from './results.js';

test('normalizeToolResultForStorage keeps short results unchanged', () => {
  const result = normalizeToolResultForStorage(
    {
      tool: 'bash',
      status: 'ok',
      content: 'TOOL_RESULT bash OK\nshort',
      meta: { exit: 0 }
    },
    100
  );

  assert.equal(result.content, 'TOOL_RESULT bash OK\nshort');
  assert.deepEqual(result.meta, { exit: 0 });
});

test('normalizeToolResultForStorage caps long results and records truncation metadata', () => {
  const result = normalizeToolResultForStorage(
    {
      tool: 'bash',
      status: 'ok',
      content: `TOOL_RESULT bash OK\n${'x'.repeat(200)}`,
      meta: { exit: 0 }
    },
    80
  );

  assert.equal(result.content.length <= 80, true);
  assert.match(result.content, /cliq truncated tool result/i);
  assert.equal(result.meta.truncated, true);
  assert.equal(result.meta.originalChars, 220);
  assert.equal(typeof result.meta.storedChars, 'number');
});
