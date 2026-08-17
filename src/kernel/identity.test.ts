import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalSha256 } from './canonical.js';
import {
  addCanonicalDuration,
  digestOmitting,
  encodeCanonicalTime,
  identityHash,
  normalizeAbsolutePath,
  parseCanonicalTime
} from './identity.js';

test('identityHash is unpadded base64url of SHA-256(JCS(arguments))', () => {
  const hex = canonicalSha256(['cliq-local-principal-v1', 'abc', 'macos', 501]);
  assert.equal(identityHash('cliq-local-principal-v1', 'abc', 'macos', 501), Buffer.from(hex, 'hex').toString('base64url'));
});

test('digestOmitting drops the digest field before hashing', () => {
  const value = { schemaVersion: 1, format: 'example', identityDigest: 'deadbeef' };
  assert.equal(digestOmitting(value, 'identityDigest'), canonicalSha256({ schemaVersion: 1, format: 'example' }));
});

test('canonical time round-trips a UTC millisecond and rejects alternate spellings', () => {
  assert.equal(encodeCanonicalTime(0), '1970-01-01T00:00:00.000Z');
  assert.equal(parseCanonicalTime('1970-01-01T00:00:00.000Z'), 0);
  assert.equal(addCanonicalDuration('1970-01-01T00:00:00.000Z', 1_000), '1970-01-01T00:00:01.000Z');
  assert.throws(() => parseCanonicalTime('1970-01-01T00:00:00Z'), /invalid canonical time/);
  assert.throws(() => parseCanonicalTime('1970-01-01T00:00:00.000+00:00'), /invalid canonical time/);
});

test('normalizeAbsolutePath rejects relative, dotted, and overlong paths', () => {
  assert.equal(normalizeAbsolutePath('/tmp/workspace'), '/tmp/workspace');
  assert.throws(() => normalizeAbsolutePath('tmp/workspace'), /absolute/);
  assert.throws(() => normalizeAbsolutePath('/tmp/../workspace'), /\.\./);
  assert.throws(() => normalizeAbsolutePath('/tmp/./workspace'), /"\."/);
});
