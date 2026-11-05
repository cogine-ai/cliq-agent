import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { encodeSessionHandoffMarkdown, type SessionHandoffHeader } from '../kernel/session-handoff-encoding.js';
import type { SessionHandoffEntryV1 } from '../kernel/session-continuity.js';
import { ContentAddressedStore } from './cas.js';
import { coalesceSessionHandoffPublication } from './session-handoff-publication.js';

// Ordinary export data/CAS bytes only; no Owner, Run or physical backup proof.
const header: SessionHandoffHeader = { sessionId: 'inert', contextRevision: 1, throughItemSeq: 1,
  workspaceIdentityRef: 'a'.repeat(64), workspaceIdentityDigest: 'b'.repeat(64),
  contextProjectionRef: 'c'.repeat(64), contextProjectionDigest: 'd'.repeat(64) };
async function* entries(): AsyncIterableIterator<SessionHandoffEntryV1> {
  yield { index: 0, sourceKind: 'summary', fromItemSeq: 1, throughItemSeq: 1, sourceRef: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
    contentUtf8: '\n'.repeat(131_071) };
}
async function* ranges() {}
test('real CAS receives fixed 64KiB chunks for many-line Markdown and roundtrips identical complete bytes', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-inert-export-coalescing-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cas = new ContentAddressedStore(root); let originalCount = 0, actualCount = 0;
  const original: Buffer[] = [];
  for await (const bytes of encodeSessionHandoffMarkdown(header, entries(), ranges())) { originalCount++; original.push(bytes); }
  async function* published() {
    for await (const bytes of coalesceSessionHandoffPublication(encodeSessionHandoffMarkdown(header, entries(), ranges()))) {
      assert(bytes.length <= 65_536); actualCount++; yield bytes;
    }
  }
  const expected = Buffer.concat(original), artifact = await cas.publishChunks(published(), expected.length);
  assert(originalCount > 100_000); assert.equal(actualCount, Math.ceil(expected.length / 65_536));
  assert.deepEqual(await cas.read(artifact.ref), expected); assert.equal(artifact.byteLength, expected.length);
});
test('failure/cancel joins the actual input generator and never flushes its partial tail', async () => {
  let joined = false, consumed = 0;
  async function* failing() {
    try { consumed++; yield Buffer.from('small prefix'); throw new Error('source failed before EOF'); }
    finally { joined = true; }
  }
  const result = coalesceSessionHandoffPublication(failing());
  await assert.rejects(result.next(), /source failed before EOF/u); assert.equal(consumed, 1); assert.equal(joined, true);
  const controller = new AbortController(); let cancelJoined = false;
  async function* cancellable() {
    try { yield Buffer.alloc(65_536); controller.abort(new Error('cancel output')); yield Buffer.from('discard'); }
    finally { cancelJoined = true; }
  }
  const cancelled = coalesceSessionHandoffPublication(cancellable(), controller.signal);
  assert.equal((await cancelled.next()).done, false);
  await assert.rejects(cancelled.next(), /cancel output/u); assert.equal(cancelJoined, true);
});
