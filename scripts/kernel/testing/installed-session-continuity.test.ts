import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { assertInstalledSessionResumeBudget, readInstalledSessionFirstSegment } from './installed-session-continuity.js';

test('installed Session continuity reads the current paged head through complete bounded immutable bytes', async () => {
  const objects = new Map<string, Buffer>();
  const put = (value: unknown) => { const ref = canonicalSha256(value); objects.set(ref, canonicalJsonBytes(value)); return ref; };
  const raw = { kind: 'raw', fromItemSeq: 1, throughItemSeq: 1, items: [
    { sourceSessionId: 'session', itemSeq: 1, itemId: 'terminal', kind: 'run_terminal', payloadRef: 'a'.repeat(64) }] };
  const leafRef = put({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'leaf', height: 0,
    fromItemSeq: 1, throughItemSeq: 1, segments: [raw] });
  const rootRef = put({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'branch', height: 1,
    fromItemSeq: 1, throughItemSeq: 1, children: [{ ref: leafRef, fromItemSeq: 1, throughItemSeq: 1 }] });
  const core = { schemaVersion: 2, format: 'cliq-session-context-v2', sessionId: 'session', contextRevision: 2,
    throughItemSeq: 1, rootPageRef: rootRef, pageHeight: 1 };
  const ref = put({ ...core, projectionDigest: canonicalSha256(core) });
  const reads: string[] = [];
  const read = async (ref: string, maximum?: number) => {
    assert.equal(maximum, 256 * 1024); reads.push(ref); const bytes = objects.get(ref); assert(bytes); return bytes;
  };
  const result = await readInstalledSessionFirstSegment(ref, read);
  assert.equal(canonicalSha256(result.first), canonicalSha256(raw));
  assert.deepEqual(reads, [ref, rootRef, leafRef]);
  objects.set(leafRef, Buffer.from('{}'));
  await assert.rejects(readInstalledSessionFirstSegment(ref, read));
});

test('genuine strict-parser budget records retain all four exact counters despite their null prototype', () => {
  const expected = { modelTokens: 36864, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const decoded = parseJsonStrict(canonicalJsonBytes(expected).toString('utf8'));
  assert.equal(Object.getPrototypeOf(decoded), null);
  assertInstalledSessionResumeBudget(decoded, expected);
  for (const invalid of [{ ...expected, modelTokens: 0 }, { ...expected, toolCalls: 1 }, { ...expected, costMicros: -1 },
    { ...expected, repairAttempts: 0.5 }, { ...expected, extra: 0 }, { ...expected, modelTokens: '36864' }])
    assert.throws(() => assertInstalledSessionResumeBudget(parseJsonStrict(canonicalJsonBytes(invalid).toString('utf8')), expected));
});
