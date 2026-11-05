import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { parseJsonStrict, measureBoundedJsonValue } from '../kernel/json.js';
import { decodeSessionContextHeadV2, decodeSessionContextPage, SESSION_CONTEXT_PAGE_BYTES,
  type SessionContextProjectionV2, type SessionContextBranchPage } from '../kernel/session-context-pages.js';
import type { SessionContextSegment } from '../kernel/types.js';
import type { PublishedArtifact } from './artifacts.js';
import { appendSessionContextGraph, publishSessionContextGraph, walkSessionContextSegments,
  walkSessionContextPageEdges } from './session-context-graph.js';

// Ordinary data only. No StateOwner/Run/native/credential/CAS factory or proof.
function fixture() {
  const objects = new Map<string, Buffer>();
  let reading = 0;
  return { objects, get reading() { return reading; }, assertReadActive() {},
    async publishCanonical(value: unknown, schemaKind: string): Promise<PublishedArtifact> {
      const bytes = canonicalJsonBytes(value), ref = canonicalSha256(value); objects.set(ref, bytes);
      return { ref, schemaKind, mediaType: 'application/json', byteLength: bytes.length };
    },
    async readBoundedBytes(ref: string, maximum: number): Promise<Buffer> {
      reading++;
      try {
        const bytes = objects.get(ref); assert(bytes, 'fixture has the requested complete data object');
        if (bytes.length > maximum) throw new TypeError('fixture object exceeds the exact consumer bound');
        return Buffer.from(bytes);
      } finally { reading--; }
    }
  };
}
function raw(seq: number): SessionContextSegment {
  return { kind: 'raw', fromItemSeq: seq, throughItemSeq: seq, items: [{ sourceSessionId: 'legacy-session',
    itemSeq: seq, itemId: `item-${seq}`, kind: 'legacy_record', payloadRef: canonicalSha256({ seq }) }] };
}
function* history(count: number): IterableIterator<SessionContextSegment> {
  for (let seq = 1; seq <= count; seq++) yield raw(seq);
}
async function collect<T>(source: AsyncIterable<T>): Promise<T[]> {
  const values: T[] = []; for await (const value of source) values.push(value); return values;
}
function replaceRoot(head: SessionContextProjectionV2, rootPageRef: string): SessionContextProjectionV2 {
  const changed = { ...head, rootPageRef, projectionDigest: '' };
  changed.projectionDigest = digestOmitting(changed, 'projectionDigest'); return decodeSessionContextHeadV2(changed);
}
test('large complete Session history is a bounded v2 graph and every tuple remains ordered', async () => {
  const f = fixture(), count = 2_000, publications: PublishedArtifact[] = [];
  const result = await publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 1,
    throughItemSeq: count, segments: history(count) }, { onPublished: value => { publications.push(value); } });
  assert(result.head.pageHeight >= 1);
  assert(canonicalJsonBytes(result.head).length < 1024);
  const rows = await collect(walkSessionContextSegments(f, result.head));
  assert.deepEqual(rows, [...history(count)]);
  for (const entry of publications.filter(entry => entry.schemaKind === 'cliq-session-context-page-v1')) {
    const bytes = f.objects.get(entry.ref)!;
    assert(bytes.length <= SESSION_CONTEXT_PAGE_BYTES);
    const data = parseJsonStrict(bytes.toString('utf8'));
    assert(measureBoundedJsonValue(data).containerEntries <= 10_000); decodeSessionContextPage(data);
  }
  const edges = await collect(walkSessionContextPageEdges(f, result.head));
  assert.deepEqual(new Set(edges.map(edge => edge.ref)), new Set(publications.filter(value =>
    value.schemaKind === 'cliq-session-context-page-v1').map(value => value.ref)));
  assert.equal(f.reading, 0);
});
test('tree crosses a complete fanout without an unbounded root or omitted leaf', async () => {
  const f = fixture(), count = 8_257;
  const result = await publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 4,
    throughItemSeq: count, segments: history(count) });
  assert.equal(result.head.pageHeight, 2);
  let expected = 1;
  for await (const segment of walkSessionContextSegments(f, result.head)) {
    assert.equal(segment.fromItemSeq, expected++);
  }
  assert.equal(expected, count + 1); assert.equal(f.reading, 0);
});
test('normal append preserves untouched immutable prefix pages and original head', async () => {
  const f = fixture();
  const previous = await publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 1,
    throughItemSeq: 128, segments: history(128) });
  const before = await collect(walkSessionContextPageEdges(f, previous.head));
  const next = await appendSessionContextGraph(f, previous.head, raw(129));
  assert.equal(next.head.contextRevision, 2); assert.equal(next.head.throughItemSeq, 129);
  const after = await collect(walkSessionContextPageEdges(f, next.head));
  assert(before.some(edge => after.some(current => current.ref === edge.ref)), 'the original complete prefix page is retained');
  assert.deepEqual(await collect(walkSessionContextSegments(f, previous.head)), [...history(128)]);
  assert.deepEqual(await collect(walkSessionContextSegments(f, next.head)), [...history(129)]);
});
test('empty graph and first append use the same fixed head contract', async () => {
  const f = fixture(), empty = await publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 1,
    throughItemSeq: 0, segments: [] });
  assert.equal(empty.head.rootPageRef, null);
  assert.deepEqual(await collect(walkSessionContextSegments(f, empty.head)), []);
  const next = await appendSessionContextGraph(f, empty.head, raw(1));
  assert.deepEqual(await collect(walkSessionContextSegments(f, next.head)), [raw(1)]);
});
test('full ranges/height/order are independently checked instead of trusting a CAS label', async () => {
  const f = fixture(), original = await publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 1,
    throughItemSeq: 128, segments: history(128) });
  const root = decodeSessionContextPage(parseJsonStrict(f.objects.get(original.head.rootPageRef!)!.toString('utf8')));
  assert.equal(root.kind, 'branch'); if (root.kind !== 'branch') return;
  const wrongChild = { ...root.children[0]!, ref: root.children[1]!.ref };
  const changed: SessionContextBranchPage = { ...root, children: [wrongChild, root.children[1]!] };
  const bad = await f.publishCanonical(changed, 'ordinary-user-file');
  await assert.rejects(collect(walkSessionContextSegments(f, replaceRoot(original.head, bad.ref))), /immutable graph/u);
  for (const data of [{ ...root, children: [...root.children].reverse() },
    { ...root, children: root.children.slice(0, 1) }]) {
    assert.throws(() => decodeSessionContextPage(data), TypeError);
  }
  const wrongHeight = await f.publishCanonical({ ...root, height: 2 }, 'ordinary-user-file');
  await assert.rejects(collect(walkSessionContextSegments(f, replaceRoot(original.head, wrongHeight.ref))), /immutable graph/u);
  assert.equal(f.reading, 0);
});
test('cancellation/early return stops page dispatch after already issued reads join', async () => {
  const f = fixture(), original = await publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 1,
    throughItemSeq: 1_000, segments: history(1_000) });
  const controller = new AbortController(); let count = 0;
  await assert.rejects(async () => {
    for await (const _segment of walkSessionContextSegments(f, original.head, { signal: controller.signal }))
      if (++count === 10) controller.abort(new Error('cancel this data read'));
  }, /cancel this data read/u);
  assert.equal(count, 10); assert.equal(f.reading, 0);
  for await (const _segment of walkSessionContextSegments(f, original.head)) break;
  assert.equal(f.reading, 0);
});
test('missing/extra input and page raw-item aggregate remain hard failures', async () => {
  const f = fixture();
  await assert.rejects(publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 1,
    throughItemSeq: 2, segments: [raw(1)] }), /complete declared prefix/u);
  await assert.rejects(publishSessionContextGraph(f, { sessionId: 'legacy-session', contextRevision: 1,
    throughItemSeq: 1, segments: [raw(2)] }), /immutable graph/u);
  const items = Array.from({ length: 257 }, (_, index) => {
    const source = raw(index + 1); assert.equal(source.kind, 'raw'); return source.kind === 'raw' ? source.items[0]! : assert.fail();
  });
  assert.throws(() => decodeSessionContextPage({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'leaf', height: 0,
    fromItemSeq: 1, throughItemSeq: 257, segments: [{ kind: 'raw', fromItemSeq: 1, throughItemSeq: 257, items }] }), TypeError);
});
