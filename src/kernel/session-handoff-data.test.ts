import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonBytes } from './canonical.js';
import { digestOmitting } from './identity.js';
import { parseJsonStrict } from './json.js';
import { inspectSessionHandoffBytes, verifySessionHandoffPair, encodeSessionHandoffMarkdown, type SessionHandoffHeader } from './session-handoff-data.js';
import { createHash } from 'node:crypto';
import type { SessionHandoffEntryV1 } from './session-continuity.js';
const ref = 'a'.repeat(64), expected = { sessionId: 'original-session', expectedContextRevision: 7 };
const header: SessionHandoffHeader = { sessionId: expected.sessionId, contextRevision: 7, throughItemSeq: 10,
  workspaceIdentityRef: ref, workspaceIdentityDigest: ref, contextProjectionRef: ref, contextProjectionDigest: ref };
const entry = (index: number, contentUtf8 = 'Historical prose only.'): SessionHandoffEntryV1 => ({ index, sourceKind: 'legacy_record',
  fromItemSeq: 1, throughItemSeq: 1, sourceRef: ref, sourceDigest: ref, contentUtf8 });
function document(entries: readonly unknown[] = [], ranges: readonly unknown[] = [], patch: Record<string, unknown> = {}) {
  const value = { schemaVersion: 1, format: 'cliq-session-handoff-v1', ...header, entries, excludedRanges: ranges, ...patch, handoffDigest: '' };
  value.handoffDigest = digestOmitting(value, 'handoffDigest'); return value;
}

test('portable handoff framing verifies all original source kinds, full omission digest and the captured cut', async () => {
  const kinds: SessionHandoffEntryV1['sourceKind'][] = ['run_terminal', 'summary', 'legacy_record', 'legacy_compaction', 'legacy_plan', 'legacy_handoff', 'legacy_bookmark'];
  const value = document(kinds.map((sourceKind, index) => ({ ...entry(index, 'Quoted " } ], \\ and LF\n汉字 / 🔥'), sourceKind })),
    [{ fromItemSeq: 2, throughItemSeq: 10, sourceItemsDigest: ref }]);
  const result = await inspectSessionHandoffBytes(canonicalJsonBytes(value), { ...expected, throughItemSeq: 10 });
  assert.deepEqual(result, { header, entryCount: 7, excludedRangeCount: 1, handoffDigest: value.handoffDigest });
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.header)); assert.equal('entries' in result, false);
  for (const changed of [{ ...expected, sessionId: 'foreign' }, { ...expected, expectedContextRevision: 8 }, { ...expected, throughItemSeq: 9 }])
    await assert.rejects(inspectSessionHandoffBytes(canonicalJsonBytes(value), changed), /original cut/u);
});

test('3,200 complete entries use the fixed export profile while the general aggregate JSON guard remains intact', async () => {
  const bytes = canonicalJsonBytes(document(Array.from({ length: 3200 }, (_, index) => entry(index))));
  assert.throws(() => parseJsonStrict(bytes.toString('utf8')), /container entries/u);
  const result = await inspectSessionHandoffBytes(bytes, expected); assert.equal(result.entryCount, 3200);
  assert.equal(result.excludedRangeCount, 0); assert.equal('entries' in result, false);
});

test('late malformed entries or excluded ranges fail without silently accepting a matching prefix', async () => {
  for (const bad of [{ ...entry(2), sourceKind: 'legacy_tool_permission' }, { ...entry(2), index: 1 },
    { ...entry(2), fromItemSeq: 11, throughItemSeq: 11 }, { ...entry(2), contentUtf8: 'bad\rline' }, { ...entry(2), authority: true }])
    await assert.rejects(inspectSessionHandoffBytes(canonicalJsonBytes(document([entry(0), entry(1), bad])), expected));
  for (const ranges of [[{ fromItemSeq: 1, throughItemSeq: 11, sourceItemsDigest: ref }],
    [{ fromItemSeq: 1, throughItemSeq: 3, sourceItemsDigest: ref }, { fromItemSeq: 3, throughItemSeq: 4, sourceItemsDigest: ref }]])
    await assert.rejects(inspectSessionHandoffBytes(canonicalJsonBytes(document([], ranges)), expected));
});

test('whole canonical envelope rejects duplicate/reordered fields, malformed UTF8, truncation, extra bytes and wrong digest', async () => {
  const value = document([entry(0, 'original')]), bytes = canonicalJsonBytes(value), text = bytes.toString('utf8');
  const wrongDigest = canonicalJsonBytes({ ...value, handoffDigest: 'b'.repeat(64) });
  const malformedUtf8 = Buffer.from(bytes); malformedUtf8[malformedUtf8.indexOf(Buffer.from('original'))] = 255;
  for (const bad of [wrongDigest, malformedUtf8, bytes.subarray(0, -1), Buffer.concat([bytes, Buffer.from('\n')]),
    Buffer.from(text.replace('"index":0', '"index":0,"index":0')), Buffer.from(text.replace('"entries":[', '"entries": [ ')),
    Buffer.from(text.replace('"schemaVersion":1', '"schemaVersion":1,"sessionId":"foreign"')), Buffer.from(JSON.stringify(value))])
    await assert.rejects(inspectSessionHandoffBytes(bad, expected));
});

test('a legal maximum quoted entry retains its full original string instead of imposing a new 1 MiB fragment ceiling', async () => {
  const bytes = canonicalJsonBytes(document([entry(0, '"'.repeat(1_048_576))]));
  assert.ok(bytes.length > 2 * 1024 * 1024);
  assert.equal((await inspectSessionHandoffBytes(bytes, expected)).entryCount, 1);
  await assert.rejects(inspectSessionHandoffBytes(canonicalJsonBytes(document([entry(0, 'x'.repeat(1_048_577))])), expected));
});

test('cancellation before parsing and during a real large fragment never returns a completed envelope', async () => {
  const bytes = canonicalJsonBytes(document([entry(0, 'x'.repeat(1_048_576))]));
  for (const when of ['before', 'during'] as const) {
    const controller = new AbortController();
    if (when === 'before') controller.abort(); else setImmediate(() => controller.abort());
    await assert.rejects(inspectSessionHandoffBytes(bytes, expected, controller.signal), { name: 'AbortError' });
  }
});

test('the exact complete portable JSON determines both the Markdown digest and its complete byte count', async () => {
  const entries = [entry(0, 'Actual "source"\nprose 🔥')], ranges = [{ fromItemSeq: 2, throughItemSeq: 10, sourceItemsDigest: ref }];
  async function* rows<T>(values: readonly T[]) { yield* values; }
  const chunks: Buffer[] = []; for await (const chunk of encodeSessionHandoffMarkdown(header, rows(entries), rows(ranges))) chunks.push(chunk);
  const markdown = Buffer.concat(chunks), digest = createHash('sha256').update(markdown).digest('hex');
  const bytes = canonicalJsonBytes(document(entries, ranges));
  await verifySessionHandoffPair(bytes, expected, { ref: digest, sizeBytes: markdown.length });
  for (const descriptor of [{ ref: 'b'.repeat(64), sizeBytes: markdown.length }, { ref: digest, sizeBytes: markdown.length + 1 }])
    await assert.rejects(verifySessionHandoffPair(bytes, expected, descriptor), /Markdown differs/u);
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(verifySessionHandoffPair(bytes, expected, { ref: digest, sizeBytes: markdown.length }, aborted.signal), { name: 'AbortError' });
});
