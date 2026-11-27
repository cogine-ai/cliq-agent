import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeSessionContextHead, walkSessionContextSegments } from '../kernel/session-context-page-reader.js';
import type { SessionCompactionItem } from '../kernel/session-continuity.js';
import type { SessionContextSegment } from '../kernel/types.js';
import { publishSessionContextGraph } from './session-context-graph.js';
import { compactedSessionContextSegments, plannedSessionContextGraphRef, scanSessionCompactionRange,
  sessionContextPrefixSegments } from './session-context-revision.js';

// Ordinary graph/revision bytes only. These data objects supply no committed
// compaction index, StateOwner, Run or native proof to the real entry reader.
function fixture() {
  const objects = new Map<string, Buffer>();
  return { assertReadActive() {}, async readBoundedBytes(ref: string, maximum: number) {
    const bytes = objects.get(ref); assert(bytes); assert(bytes.length <= maximum); return Buffer.from(bytes);
  }, async publishCanonical(value: unknown, schemaKind: string) {
    const bytes = canonicalJsonBytes(value), ref = canonicalSha256(value); objects.set(ref, bytes);
    return { ref, mediaType: 'application/json', schemaKind, byteLength: bytes.length };
  } };
}
function* raw(count: number): IterableIterator<SessionContextSegment> {
  for (let index = 1; index <= count; index++) yield { kind: 'raw', fromItemSeq: index, throughItemSeq: index,
    items: [{ sourceSessionId: 'original', itemSeq: index, itemId: `item-${index}`, kind: 'legacy_record', payloadRef: canonicalSha256({ index }) }] };
}
async function collect<T>(source: AsyncIterable<T>): Promise<T[]> { const all: T[] = []; for await (const value of source) all.push(value); return all; }
test('whole raw compaction and its replay compute one deterministic paged replacement without losing the tail', async () => {
  const f = fixture(), original = await publishSessionContextGraph(f, { sessionId: 'original', contextRevision: 1,
    throughItemSeq: 2_000, segments: raw(2_000) });
  const selected = await scanSessionCompactionRange(f, original.head, { fromItemSeq: 1, throughItemSeq: 1_800,
    retainedItemIds: ['item-1500', 'item-100'] });
  assert.deepEqual(selected.retainedItemIds, ['item-100', 'item-1500']);
  const tuples = [...raw(1_800)].flatMap(segment => segment.kind === 'raw' ? segment.items.map(item =>
    ({ itemSeq: item.itemSeq, kind: item.kind, payloadRef: item.payloadRef })) : []);
  assert.equal(selected.sourceItemsDigest, canonicalSha256(tuples));
  const payload: SessionCompactionItem = { schemaVersion: 1, kind: 'compaction', fromItemSeq: 1, throughItemSeq: 1_800,
    sourceItemsDigest: selected.sourceItemsDigest, summaryRef: 'b'.repeat(64), summaryDigest: 'c'.repeat(64),
    retainedItemIds: selected.retainedItemIds, previousProjectionRef: original.artifact.ref, createdAt: '2026-01-04T00:00:00.000Z' };
  const payloadRef = canonicalSha256(payload);
  const input = () => ({ sessionId: 'original', contextRevision: 2, throughItemSeq: 2_001,
    segments: compactedSessionContextSegments(f, original.head, payload, 'compaction-item', payloadRef) });
  const published = await publishSessionContextGraph(f, input());
  assert.equal(await plannedSessionContextGraphRef(f, input()), published.artifact.ref);
  const result = await collect(walkSessionContextSegments(f, published.head));
  assert.equal(result[0]!.kind, 'summary'); assert.equal(result[0]!.throughItemSeq, 1_800);
  assert.equal(result.at(-1)!.kind, 'excluded_control'); assert.equal(result.at(-1)!.throughItemSeq, 2_001);
  assert.deepEqual(result.slice(1, -1), [...raw(2_000)].slice(1_800));
  await assert.rejects(scanSessionCompactionRange(f, published.head, { fromItemSeq: 1, throughItemSeq: 1_800, retainedItemIds: [] }), TypeError);
  await assert.rejects(collect(sessionContextPrefixSegments(f, published.head, 100)), TypeError);
});
test('fork keeps an exact frozen tuple prefix and never clones physical source ownership', async () => {
  const f = fixture(), original = await publishSessionContextGraph(f, { sessionId: 'original', contextRevision: 5,
    throughItemSeq: 2_000, segments: raw(2_000) });
  const forked = await publishSessionContextGraph(f, { sessionId: 'child', contextRevision: 1, throughItemSeq: 1_500,
    segments: sessionContextPrefixSegments(f, original.head, 1_500) });
  assert.deepEqual(await collect(walkSessionContextSegments(f, forked.head)), [...raw(1_500)]);
  assert.equal(forked.head.sessionId, 'child'); assert.equal(forked.head.contextRevision, 1);
  const last = await collect(walkSessionContextSegments(f, original.head)); assert.equal(last.at(-1)!.throughItemSeq, 2_000);
});
test('real v1 source normalization preserves every tuple while only the new revision becomes paged', async () => {
  const f = fixture(), items = [...raw(2_000)].flatMap(segment => segment.kind === 'raw' ? segment.items : []);
  const data = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId: 'original', contextRevision: 1,
    throughItemSeq: 2_000, segments: [{ kind: 'raw', fromItemSeq: 1, throughItemSeq: 2_000, items }], projectionDigest: '' };
  data.projectionDigest = digestOmitting(data, 'projectionDigest'); const original = decodeSessionContextHead(data);
  const before = canonicalJsonBytes(original);
  const fork = await publishSessionContextGraph(f, { sessionId: 'child', contextRevision: 1, throughItemSeq: 2_000,
    segments: sessionContextPrefixSegments(f, original, 2_000) });
  const copied = (await collect(walkSessionContextSegments(f, fork.head))).flatMap(segment => segment.kind === 'raw' ? segment.items : []);
  assert.deepEqual(copied, items); assert.deepEqual(canonicalJsonBytes(original), before);
  await assert.rejects(collect(sessionContextPrefixSegments(f, original, 1_000)), TypeError, 'the original whole v1 segment cannot be split by a fork request');
});
