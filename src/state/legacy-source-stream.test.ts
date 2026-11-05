import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { LegacySessionSourceStream, LEGACY_SOURCE_BYTES, LEGACY_SOURCE_FRAGMENT_BYTES } from './legacy-source-stream.js';

const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const carrier = (records: unknown[] = [], extra: Record<string, unknown> = {}) => ({ version: 5, app: 'cliq',
  id: 'session_original', model: { provider: 'openai', model: 'historical' }, cwd: '/old/repository',
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:01.000Z',
  lifecycle: { status: 'running', turn: 9 }, activeSkills: [], records, compactions: [], checkpoints: [], ...extra });
function read(source: string, chunk = 65_536) {
  const bytes = Buffer.from(source), reader = new LegacySessionSourceStream({ byteCount: bytes.length, contentDigest: digest(bytes) });
  const events = [];
  for (let offset = 0; offset < bytes.length; offset += chunk) events.push(...reader.feed(bytes.subarray(offset, offset + chunk)));
  return { events, metadata: reader.finish(), reader };
}

test('a real byte stream preserves every original array ordinal without retaining its whole carrier', () => {
  const records = Array.from({ length: 2000 }, (_, index) => ({ id: `record_${index}`, ts: '2026-01-01T00:00:00.000Z',
    kind: 'user', role: 'user', content: `original ${index}` }));
  const source = JSON.stringify(carrier(records));
  const bytes = Buffer.from(source), reader = new LegacySessionSourceStream({ byteCount: bytes.length, contentDigest: digest(bytes) });
  let count = 0;
  for (let offset = 0; offset < bytes.length; offset += 4093) {
    for (const event of reader.feed(bytes.subarray(offset, offset + 4093))) {
      assert.equal(event.kind, 'legacy_record'); assert.equal(event.ordinal, count);
      assert.equal(JSON.stringify(event.value), JSON.stringify(records[count])); count++;
    }
  }
  assert.equal(count, records.length); assert.equal(reader.finish().id, 'session_original');
});

test('UTF-8 and escaped JSON strings may split at every byte boundary', () => {
  const value = { id: 'record_one', content: '雪🙂 \\ " end' };
  const result = read(JSON.stringify(carrier([value])), 1);
  assert.equal(JSON.stringify(result.events[0]?.value), JSON.stringify(value));
  assert.equal(result.metadata.cwd, '/old/repository');
  assert.equal(Object.hasOwn(result.metadata, 'model'), false);
  assert.equal(Object.hasOwn(result.metadata, 'activeSkills'), false);
  assert.equal(Object.hasOwn(result.metadata, 'lifecycle'), false);
});

test('three historical sequences retain independent ordinals and fixed nonexecution kinds', () => {
  const result = read(JSON.stringify(carrier([{ record: 1 }, { record: 2 }], { compactions: [{ summary: 1 }], checkpoints: [{ bookmark: 1 }] })), 7);
  assert.deepEqual(result.events.map(value => [value.kind, value.ordinal]), [
    ['legacy_record', 0], ['legacy_record', 1], ['legacy_compaction', 0], ['legacy_bookmark', 0]
  ]);
});

test('duplicate root and nested keys are refused by the original strict lexer', () => {
  const source = JSON.stringify(carrier());
  assert.throws(() => read(source.replace('"version":5', '"version":5,"version":5')), /duplicate/);
  assert.throws(() => read(source.replace('"records":[]', '"records":[{"same":1,"\\u0073ame":2}]')), /duplicate/);
});

test('trailing separators, wrong carriers and nonfinite values cannot become complete source', () => {
  const source = JSON.stringify(carrier());
  for (const bad of [source.slice(0, -1) + ',}', source.replace('"records":[]', '"records":[{},]'),
    source.replace('"records":[]', '"records":[1e999]'), source.replace('"records":[]', '"records":{}'),
    source.replace('"records":[]', '"records":[{"unterminated":true]'), '[]', source + '{}'])
    assert.throws(() => read(bad));
});

test('whole-source depth stays at its actual wrapper depth', () => {
  let nested: unknown = 0;
  for (let depth = 0; depth < 31; depth++) nested = [nested];
  assert.throws(() => read(JSON.stringify(carrier([nested]))), /depth|nesting/);
});

test('unknown fields and unsupported versions fail rather than restoring hidden configuration', () => {
  assert.throws(() => read(JSON.stringify(carrier([], { permissionGrant: 'not-authority' }))), /unknown/);
  assert.throws(() => read(JSON.stringify(carrier([], { version: 99 }))), /version/);
});

test('one bounded fragment and complete-file budget are independent and never reset per item', () => {
  assert.throws(() => new LegacySessionSourceStream({ byteCount: LEGACY_SOURCE_BYTES + 1, contentDigest: 'a'.repeat(64) }), /profile/);
  assert.throws(() => read(JSON.stringify(carrier([{ content: 'x'.repeat(LEGACY_SOURCE_FRAGMENT_BYTES) }]))), /fragment/);
  const bytes = Buffer.from(JSON.stringify(carrier()));
  const short = new LegacySessionSourceStream({ byteCount: bytes.length - 1, contentDigest: digest(bytes) });
  assert.throws(() => short.feed(bytes), /budget/);
  const largeChunk = new LegacySessionSourceStream({ byteCount: 65_537, contentDigest: 'a'.repeat(64) });
  assert.throws(() => largeChunk.feed(Buffer.alloc(65_537)), /chunk/);
});

test('EOF, exact length and complete digest are necessary independently', () => {
  const bytes = Buffer.from(JSON.stringify(carrier([{ original: true }])));
  const wrong = new LegacySessionSourceStream({ byteCount: bytes.length, contentDigest: 'a'.repeat(64) });
  wrong.feed(bytes); assert.throws(() => wrong.finish(), /hash/);
  const partial = new LegacySessionSourceStream({ byteCount: bytes.length, contentDigest: digest(bytes) });
  partial.feed(bytes.subarray(0, bytes.length - 1)); assert.throws(() => partial.finish(), /complete/);
  const complete = read(bytes.toString());
  assert.throws(() => complete.reader.feed(new Uint8Array()), /closed/);
  assert.throws(() => complete.reader.finish(), /closed/);
});

test('invalid UTF-8 cannot be repaired into a projected historical message', () => {
  const bytes = Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x30, 0x7d]);
  const reader = new LegacySessionSourceStream({ byteCount: bytes.length, contentDigest: digest(bytes) });
  assert.throws(() => reader.feed(bytes), /encoded|encoding|UTF/);
  assert.throws(() => reader.feed(new Uint8Array()), /failed/);
  assert.throws(() => reader.finish(), /failed/);
});
