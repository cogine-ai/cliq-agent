import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { estimateOutputTokensFromChars, formatApproxOutputTokens } from './token-estimate.js';

test('estimateOutputTokensFromChars returns 0 for non-positive and non-finite input', () => {
  assert.equal(estimateOutputTokensFromChars(-1), 0);
  assert.equal(estimateOutputTokensFromChars(0), 0);
  assert.equal(estimateOutputTokensFromChars(Number.NaN), 0);
  assert.equal(estimateOutputTokensFromChars(Number.POSITIVE_INFINITY), 0);
  assert.equal(estimateOutputTokensFromChars(Number.NEGATIVE_INFINITY), 0);
});

test('estimateOutputTokensFromChars rounds character counts up to approximate tokens', () => {
  assert.equal(estimateOutputTokensFromChars(1), 1);
  assert.equal(estimateOutputTokensFromChars(4), 1);
  assert.equal(estimateOutputTokensFromChars(5), 2);
  assert.equal(estimateOutputTokensFromChars(8), 2);
});

test('formatApproxOutputTokens returns null for non-positive and non-finite input', () => {
  assert.equal(formatApproxOutputTokens(-1), null);
  assert.equal(formatApproxOutputTokens(0), null);
  assert.equal(formatApproxOutputTokens(Number.NaN), null);
  assert.equal(formatApproxOutputTokens(Number.POSITIVE_INFINITY), null);
  assert.equal(formatApproxOutputTokens(Number.NEGATIVE_INFINITY), null);
});

test('formatApproxOutputTokens rounds up and formats small token counts', () => {
  assert.equal(formatApproxOutputTokens(1), '~ 1 tok');
  assert.equal(formatApproxOutputTokens(1.2), '~ 2 tok');
  assert.equal(formatApproxOutputTokens(999), '~ 999 tok');
});

test('formatApproxOutputTokens uses k format for large token counts', () => {
  assert.equal(formatApproxOutputTokens(1000), '~ 1.0k tok');
  assert.equal(formatApproxOutputTokens(1200), '~ 1.2k tok');
});
