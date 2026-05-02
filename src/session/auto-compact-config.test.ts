import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveAutoCompactConfig } from './auto-compact-config.js';

test('resolveAutoCompactConfig defaults to auto mode with known model context window', () => {
  const resolved = resolveAutoCompactConfig({
    config: {},
    modelContextWindowTokens: 200_000
  });

  assert.equal(resolved.enabled, 'auto');
  assert.equal(resolved.contextWindowTokens, 200_000);
  assert.equal(resolved.contextWindowSource, 'model-descriptor');
  assert.equal(resolved.usableLimitTokens, 160_000);
});

test('resolveAutoCompactConfig prefers workspace context window over model descriptor', () => {
  const resolved = resolveAutoCompactConfig({
    config: { contextWindowTokens: 128_000 },
    modelContextWindowTokens: 200_000
  });

  assert.equal(resolved.contextWindowTokens, 128_000);
  assert.equal(resolved.contextWindowSource, 'config');
});

test('resolveAutoCompactConfig rejects invalid numeric relationships', () => {
  assert.throws(
    () =>
      resolveAutoCompactConfig({
        config: { contextWindowTokens: 10_000, reserveTokens: 10_000 }
      }),
    /reserveTokens must be less than contextWindowTokens/i
  );

  assert.throws(
    () =>
      resolveAutoCompactConfig({
        config: { contextWindowTokens: 100_000, thresholdRatio: 1 }
      }),
    /thresholdRatio must be greater than 0 and less than 1/i
  );

  assert.throws(
    () =>
      resolveAutoCompactConfig({
        config: { contextWindowTokens: 100_000, keepRecentTokens: 90_000 }
      }),
    /keepRecentTokens must be less than usableLimit/i
  );
});

test('resolveAutoCompactConfig leaves unknown auto context unresolved', () => {
  const resolved = resolveAutoCompactConfig({ config: {} });

  assert.equal(resolved.enabled, 'auto');
  assert.equal(resolved.contextWindowTokens, null);
  assert.equal(resolved.contextWindowSource, null);
  assert.equal(resolved.usableLimitTokens, null);
});

test('resolveAutoCompactConfig rejects on mode without a context window', () => {
  assert.throws(
    () => resolveAutoCompactConfig({ config: { enabled: 'on' } }),
    /autoCompact.enabled on requires a context window/i
  );
});
