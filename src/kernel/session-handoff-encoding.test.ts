import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonBytes } from './canonical.js';
import { digestOmitting } from './identity.js';
import { encodeSessionHandoffJson, encodeSessionHandoffMarkdown, type SessionHandoffHeader } from './session-handoff-encoding.js';
import type { SessionHandoffEntryV1 } from './session-continuity.js';

// Pure output data; no authenticated source, Session index or native proof.
const ref = 'a'.repeat(64), digest = 'b'.repeat(64);
const header: SessionHandoffHeader = { sessionId: 'historical-session', workspaceIdentityRef: ref, workspaceIdentityDigest: digest,
  contextRevision: 3, throughItemSeq: 4, contextProjectionRef: ref, contextProjectionDigest: digest };
const entries: SessionHandoffEntryV1[] = [
  { index: 0, sourceKind: 'legacy_record', fromItemSeq: 1, throughItemSeq: 1, sourceRef: ref, sourceDigest: digest, contentUtf8: 'old\nitem' },
  { index: 1, sourceKind: 'summary', fromItemSeq: 2, throughItemSeq: 3, sourceRef: ref, sourceDigest: digest, contentUtf8: 'summary' },
  { index: 2, sourceKind: 'legacy_bookmark', fromItemSeq: 3, throughItemSeq: 3, sourceRef: ref, sourceDigest: digest, contentUtf8: 'retained' }
];
const ranges = [{ fromItemSeq: 4, throughItemSeq: 4, sourceItemsDigest: ref }];
async function* source<T>(values: readonly T[]): AsyncIterableIterator<T> { yield* values; }
async function bytes(values: AsyncIterable<Buffer>): Promise<Buffer> {
  const data: Buffer[] = []; for await (const chunk of values) { assert(chunk.length <= 65_536); data.push(chunk); } return Buffer.concat(data);
}
test('streamed handoff JSON is byte-identical to the original complete JCS/omission-digest contract', async () => {
  const data = { schemaVersion: 1, format: 'cliq-session-handoff-v1', ...header, entries, excludedRanges: ranges, handoffDigest: '' };
  data.handoffDigest = digestOmitting(data, 'handoffDigest');
  assert.deepEqual(await bytes(encodeSessionHandoffJson(header, source(entries), source(ranges))), canonicalJsonBytes(data));
  const expected = '# Cliq Session Handoff\n\nSession: "historical-session"\nContext revision: 3\nThrough item: 4\n' +
    '\n## Entry 1: legacy_record\n\n    old\n    item\n' + '\n## Entry 2: summary\n\n    summary\n' +
    '\n## Entry 3: legacy_bookmark\n\n    retained\n\nExcluded control ranges: 1\n';
  assert.equal((await bytes(encodeSessionHandoffMarkdown(header, source(entries), source(ranges)))).toString('utf8'), expected);
});
test('large human export retains every entry while every emitted chunk stays bounded', async () => {
  const count = 3_200;
  async function* many(): AsyncIterableIterator<SessionHandoffEntryV1> {
    for (let index = 0; index < count; index++) yield { ...entries[0]!, index, fromItemSeq: index + 1, throughItemSeq: index + 1,
      contentUtf8: `${index}: ${'prose '.repeat(150)}` };
  }
  const data = await bytes(encodeSessionHandoffJson({ ...header, throughItemSeq: count }, many(), source([])));
  // Parsing exported ordinary data in this test does not change any small
  // Kernel artifact/parser guard or claim a bounded authority JSON object.
  const decoded: { entries: SessionHandoffEntryV1[]; handoffDigest: string } = JSON.parse(data.toString('utf8'));
  assert.equal(decoded.entries.length, count); assert.equal(decoded.entries.at(-1)!.index, count - 1);
  assert.equal(decoded.handoffDigest, digestOmitting(decoded, 'handoffDigest'));
});
test('bad late entry/range data fails instead of authenticating a partial export', async () => {
  await assert.rejects(bytes(encodeSessionHandoffJson(header, source([entries[0]!, { ...entries[1]!, index: 9 }]), source(ranges))), /ordered visible data/u);
  await assert.rejects(bytes(encodeSessionHandoffJson(header, source(entries), source([...ranges, ...ranges]))), TypeError);
  await assert.rejects(bytes(encodeSessionHandoffMarkdown(header, source([{ ...entries[0]!, contentUtf8: 'noncanonical\rtext' }]), source([]))), /canonical LF/u);
});
test('data backpressure and cancellation close the actual input generator without reading the remainder', async () => {
  let read = 0, joined = false;
  async function* retained(): AsyncIterableIterator<SessionHandoffEntryV1> {
    try { for (const entry of entries) { read++; yield entry; } }
    finally { joined = true; }
  }
  const controller = new AbortController(), output = encodeSessionHandoffJson(header, retained(), source(ranges), controller.signal);
  await output.next(); assert.equal(read, 0, 'the header does not eagerly load source entries');
  const first = await output.next(); assert.equal(read, 1); assert(!first.done);
  controller.abort(new Error('cancel output data'));
  await assert.rejects(output.next(), /cancel output data/u);
  assert.equal(read, 1); assert.equal(joined, true);
});
