import assert from 'node:assert/strict';
import test from 'node:test';

import { qualifyExecutionBackend } from './probe.js';

test('execution qualification fails closed until a real strong backend probe exists', async () => {
  const result = await qualifyExecutionBackend();

  assert.equal(result.ok, false);
  assert.equal(result.authorityReady, false);
  assert.equal('capability' in result, false);

  if (process.platform === 'darwin' || process.platform === 'linux') {
    assert.equal(result.error.code, 'UNSUPPORTED_EXECUTION_IDENTITY');
    assert.equal(result.observedPlatform, process.platform);
    assert.match(result.error.message, /real .* probe/i);
    return;
  }

  assert.equal(result.error.code, 'UNSUPPORTED_PLATFORM');
  assert.equal(result.observedPlatform, process.platform);
});
