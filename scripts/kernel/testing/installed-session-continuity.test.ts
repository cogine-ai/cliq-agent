import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { assertInstalledSessionResumeBudget } from './installed-session-continuity.js';

test('genuine strict-parser budget records retain all four exact counters despite their null prototype', () => {
  const expected = { modelTokens: 36864, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const decoded = parseJsonStrict(canonicalJsonBytes(expected).toString('utf8'));
  assert.equal(Object.getPrototypeOf(decoded), null);
  assertInstalledSessionResumeBudget(decoded, expected);
  for (const invalid of [{ ...expected, modelTokens: 0 }, { ...expected, toolCalls: 1 }, { ...expected, costMicros: -1 },
    { ...expected, repairAttempts: 0.5 }, { ...expected, extra: 0 }, { ...expected, modelTokens: '36864' }])
    assert.throws(() => assertInstalledSessionResumeBudget(parseJsonStrict(canonicalJsonBytes(invalid).toString('utf8')), expected));
});
