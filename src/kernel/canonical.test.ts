import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from './canonical.js';

test('canonicalJsonBytes sorts object keys recursively and preserves array order', () => {
  const encoded = canonicalJsonBytes({
    z: 1,
    nested: { beta: true, alpha: 'x' },
    array: [{ y: 2, x: 1 }, null]
  });

  assert.equal(
    encoded.toString('utf8'),
    '{"array":[{"x":1,"y":2},null],"nested":{"alpha":"x","beta":true},"z":1}'
  );
});

test('canonicalSha256 matches an independently computed known vector', () => {
  assert.equal(canonicalSha256({ a: 1, b: 2 }), '43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777');
});

test('canonicalJsonBytes rejects values outside the RFC canonical JSON domain', () => {
  assert.throws(() => canonicalJsonBytes({ value: undefined }), /undefined/);
  assert.throws(() => canonicalJsonBytes({ value: Number.NaN }), /finite/);
  assert.throws(() => canonicalJsonBytes({ value: 1n }), /bigint/);
  assert.throws(() => canonicalJsonBytes({ value: new Date(0) }), /plain object/);
  assert.throws(() => canonicalJsonBytes({ value: '\ud800' }), /unpaired surrogate/);
});

test('canonicalJsonBytes rejects sparse arrays instead of colliding with dense arrays', () => {
  const oneHole = new Array<unknown>(1);
  const leadingHole = new Array<unknown>(2);
  leadingHole[1] = 'present';

  assert.throws(() => canonicalJsonBytes(oneHole), /sparse arrays/);
  assert.throws(() => canonicalJsonBytes(leadingHole), /sparse arrays/);
  assert.notEqual(canonicalJsonBytes([]).toString('utf8'), '[null]');
});

test('canonicalJsonBytes always emits syntactically valid JSON for accepted arrays', () => {
  const encoded = canonicalJsonBytes([null, false, 0, 'value', { nested: [1, 2] }]).toString('utf8');

  assert.deepEqual(JSON.parse(encoded), [null, false, 0, 'value', { nested: [1, 2] }]);
});

test('normalizeCanonicalText applies NFC and rejects NUL and unpaired surrogates', () => {
  assert.equal(normalizeCanonicalText('e\u0301'), '\u00e9');
  assert.throws(() => normalizeCanonicalText('a\0b'), /NUL/);
  assert.throws(() => normalizeCanonicalText('\udc00'), /unpaired surrogate/);
});
