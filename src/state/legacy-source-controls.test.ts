import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { LegacySessionSourceStream } from './legacy-source-stream.js';

function source(change: Record<string, unknown> = {}) {
  const bytes = Buffer.from(JSON.stringify({ version: 5, app: 'cliq', id: 'old', cwd: '/old/path',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-02T00:00:00.000Z', model: {}, records: [],
    lifecycle: { status: 'running', turn: 12 }, activeTxId: 'old-tx', ...change }));
  return { bytes, expected: { byteCount: bytes.length, contentDigest: createHash('sha256').update(bytes).digest('hex') } };
}
test('nonportable controls require complete local EOF/hash and never enter portable metadata', () => {
  const value = source(), stream = new LegacySessionSourceStream(value.expected);
  assert.throws(() => stream.preflightControls(), /complete verified source/u);
  stream.feed(value.bytes); assert.throws(() => stream.preflightControls(), /complete verified source/u);
  const metadata = stream.finish();
  assert.equal(Object.hasOwn(metadata, 'activeTxId'), false); assert.equal(Object.hasOwn(metadata, 'lifecycle'), false);
  assert.deepEqual(stream.preflightControls(), { activeTxId: 'old-tx', lifecycle: { status: 'running', turn: 12 } });
});
test('failed complete-source verification can never open the controls getter', () => {
  const value = source(), stream = new LegacySessionSourceStream({ ...value.expected, contentDigest: 'a'.repeat(64) });
  stream.feed(value.bytes); assert.throws(() => stream.finish(), /hash was not observed/u);
  assert.throws(() => stream.preflightControls(), /complete verified source/u);
});
test('unknown or malformed control payloads fail preflight without changing historical context projection', () => {
  for (const change of [{ activeTxId: '../escape' }, { activeTxId: null }, { lifecycle: { status: 'unknown', turn: 0 } },
    { lifecycle: { status: 'idle', turn: -1 } }, { lifecycle: { status: 'idle', turn: 1, permission: 'allow' } }]) {
    const value = source(change), stream = new LegacySessionSourceStream(value.expected);
    stream.feed(value.bytes); stream.finish(); assert.throws(() => stream.preflightControls());
  }
});
