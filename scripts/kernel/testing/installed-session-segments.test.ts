import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { decodeSessionContextHead } from '../../../src/kernel/session-context-page-reader.js';
import type { SessionContextSegment } from '../../../src/kernel/types.js';
import { installedSessionSegmentsAt } from './installed-session-segments.js';

const segment = (seq: number): SessionContextSegment => ({ kind: 'raw', fromItemSeq: seq, throughItemSeq: seq,
  items: [{ sourceSessionId: 'data-session', itemSeq: seq, itemId: `item-${seq}`, kind: 'run_terminal',
    payloadRef: canonicalSha256({ seq }) }] });

test('installed result checks use complete v1 and paged v2 context, including pages after the selected terminal', async () => {
  const objects = new Map<string, Buffer>(), reads: string[] = [];
  const publish = (value: unknown) => { const bytes = canonicalJsonBytes(value), ref = sha256Bytes(bytes); objects.set(ref, bytes); return ref; };
  const pages = [1, 2, 3].map(seq => ({ fromItemSeq: seq, throughItemSeq: seq,
    ref: publish({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'leaf', height: 0,
      fromItemSeq: seq, throughItemSeq: seq, segments: [segment(seq)] }) }));
  const root = publish({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'branch', height: 1,
    fromItemSeq: 1, throughItemSeq: 3, children: pages });
  const core = { schemaVersion: 2, format: 'cliq-session-context-v2', sessionId: 'data-session', contextRevision: 2,
    throughItemSeq: 3, rootPageRef: root, pageHeight: 1 };
  const v2 = decodeSessionContextHead({ ...core, projectionDigest: canonicalSha256(core) });
  const read = async (ref: string, maximum: number) => {
    reads.push(ref); const bytes = objects.get(ref); assert(bytes); assert(bytes.length <= maximum); assert.equal(sha256Bytes(bytes), ref); return bytes;
  };
  assert.deepEqual(await installedSessionSegmentsAt(v2, 2, read), [segment(2)]);
  assert.deepEqual(reads, [root, ...pages.map(page => page.ref)]);
  const v1Core = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId: 'data-session', contextRevision: 1, throughItemSeq: 3,
    segments: [segment(1), segment(2), segment(3)], projectionDigest: '' };
  v1Core.projectionDigest = digestOmitting(v1Core, 'projectionDigest');
  reads.length = 0;
  assert.deepEqual(await installedSessionSegmentsAt(decodeSessionContextHead(v1Core), 2, read), [segment(2)]);
  assert.deepEqual(reads, []);
  const last = pages[2]!.ref; objects.set(last, Buffer.from('{}'));
  await assert.rejects(installedSessionSegmentsAt(v2, 2, read), 'a matching earlier terminal cannot hide corrupt later data');
  reads.length = 0;
  await assert.rejects(installedSessionSegmentsAt(v2, 4, read), TypeError);
  assert.deepEqual(reads, []);
});
