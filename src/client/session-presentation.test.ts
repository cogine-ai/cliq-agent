import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { readInstalledSessionContext } from '../control/session.js';
import { createClientApplication, type ClientUpdate } from './application.js';
import { sessionContextLines } from './view.js';
import { protocolClient, sessionSnapshot, ref } from './testing/protocol.js';

// Immutable wire/artifact data only; server-side source lineage authority is
// deliberately not reconstructed or claimed by the display fixture.
function fixture(wrongSession = false) {
  const projection = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId: wrongSession ? 'foreign' : 'session',
    contextRevision: 7, throughItemSeq: 2, projectionDigest: '', segments: [{ kind: 'summary', fromItemSeq: 1, throughItemSeq: 2,
      compactionItemId: 'compaction', summaryRef: ref, summaryDigest: ref, sourceItemsDigest: ref, retainedItemIds: ['original-terminal'] }] };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const bytes = canonicalJsonBytes(projection), snapshot = sessionSnapshot();
  snapshot.session.latestItemSeq = 2; snapshot.session.contextProjectionRef = canonicalSha256(projection);
  const f = protocolClient({ 'session.get': async () => ({ protocolVersion: 1, ok: true, result: { method: 'session.get', snapshot,
    items: [], highWaterItemSeq: 2, nextItemSeq: 2 } }),
    'artifact.get': async (request: { digest: string; offset: number }) => ({ protocolVersion: 1, ok: true, result: { method: 'artifact.get',
      artifact: { schemaVersion: 1, ref: request.digest, digest: request.digest, sizeBytes: bytes.length, mediaType: 'application/json' },
      offset: request.offset, nextOffset: bytes.length, bytesBase64: bytes.toString('base64'), eof: true } }) });
  return { ...f, snapshot, projection };
}

test('captured Session presentation preserves whole summary boundaries and refuses a foreign immutable graph', async () => {
  const f = fixture();
  try {
    const projection = await readInstalledSessionContext(f.session, f.snapshot.session);
    assert.equal(canonicalJsonBytes(projection).toString(), canonicalJsonBytes(f.projection).toString());
    assert.match(sessionContextLines(projection).join('\n'), /1–2 · summary · 1 retained/u);
  } finally { await f.session.close(); }
  const bad = fixture(true);
  try { await assert.rejects(readInstalledSessionContext(bad.session, bad.snapshot.session), /captured snapshot/u); }
  finally { await bad.session.close(); }
});

test('a Session show uses the same application connection and emits its referenced graph as display data', async () => {
  const f = fixture(), updates: ClientUpdate[] = [], app = createClientApplication(f.session, update => { updates.push(update); });
  try {
    // Read only the head, with its exact source cut; no Session mutation or new Run.
    await app.execute({ kind: 'request', request: { protocolVersion: 1, method: 'session.get', sessionId: 'session', afterItemSeq: 2 } });
    assert.equal(updates.filter(update => update.kind === 'context').length, 1);
    assert.deepEqual(f.calls.map(call => call.method), ['session.get', 'artifact.get']);
  } finally { await app.close(); }
});
