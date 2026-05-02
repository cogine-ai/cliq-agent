import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyContextOverflow } from './errors.js';

test('classifyContextOverflow recognizes common provider overflow messages', () => {
  assert.equal(classifyContextOverflow(new Error('context length exceeded'))?.isOverflow, true);
  assert.equal(
    classifyContextOverflow(new Error('maximum context window is 128000 tokens'))?.contextWindowTokens,
    128000
  );
  assert.equal(classifyContextOverflow(new Error('input is too long: too many tokens'))?.isOverflow, true);
});

test('classifyContextOverflow ignores unrelated errors', () => {
  assert.equal(classifyContextOverflow(new Error('network unavailable')), null);
});
