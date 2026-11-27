// Pure closed wire data; no Session, native resource, authentication or Run
// authority is created by these decoder regressions.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { decodeInstalledControlRequest, decodeInstalledControlResponse } from './control-wire.js';
import { sessionSnapshot, ref } from '../client/testing/protocol.js';

function fixture() {
  const bytes = canonicalJsonBytes({ schemaVersion: 1, format: 'cliq-session-context-page-v1', kind: 'leaf', height: 0,
    fromItemSeq: 1, throughItemSeq: 1, segments: [{ kind: 'raw', fromItemSeq: 1, throughItemSeq: 1,
      items: [{ sourceSessionId: 'session', itemSeq: 1, itemId: 'item', kind: 'run_terminal', payloadRef: ref }] }] });
  const snapshot = sessionSnapshot(); snapshot.session.latestItemSeq = 1;
  const request = { protocolVersion: 1 as const, method: 'session.get' as const, sessionId: 'session', contextPage: {
    contextProjectionRef: snapshot.session.contextProjectionRef, expectedContextRevision: snapshot.session.contextRevision, path: [] as number[] } };
  const response = { protocolVersion: 1 as const, ok: true as const, result: { method: 'session.get' as const, snapshot,
    items: [], highWaterItemSeq: 1, nextItemSeq: 1, contextPage: { contextProjectionRef: request.contextPage.contextProjectionRef,
      contextRevision: request.contextPage.expectedContextRevision, path: [] as number[], artifact: { schemaVersion: 1 as const,
        ref: canonicalSha256(JSON.parse(bytes.toString())), digest: canonicalSha256(JSON.parse(bytes.toString())), sizeBytes: bytes.length,
        mediaType: 'application/json' }, bytesBase64: bytes.toString('base64') } } };
  return { request, response };
}

test('Session context query permits only the exact root/revision and bounded dense child ordinal path', () => {
  const { request } = fixture(); assert.deepEqual(decodeInstalledControlRequest(request), request);
  for (const path of [[-1], [128], [0.5], ['0'], Array(8).fill(0), Array(1)])
    assert.throws(() => decodeInstalledControlRequest({ ...request, contextPage: { ...request.contextPage, path } }), TypeError);
  for (const extra of [{ digest: ref }, { afterItemSeq: 0 }, { limit: 1 }])
    assert.throws(() => decodeInstalledControlRequest({ ...request, ...extra }), TypeError);
  for (const extra of [{ targetRef: ref }, { verified: true }, { namespace: 'cas' }])
    assert.throws(() => decodeInstalledControlRequest({ ...request, contextPage: { ...request.contextPage, ...extra } }), TypeError);
});

test('Session context response binds full bytes and exact current snapshot/root/path, with no metadata response fallback', () => {
  const { request, response } = fixture(); assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  const { contextPage: _page, ...normal } = response.result;
  assert.throws(() => decodeInstalledControlResponse({ ...response, result: normal }, request), /captured head/u);
  assert.throws(() => decodeInstalledControlResponse(response, { protocolVersion: 1, method: 'session.get', sessionId: 'session' }), /unsolicited/u);
  for (const change of [{ bytesBase64: Buffer.from('changed').toString('base64') }, { path: [0] }, { contextRevision: 8 },
    { contextProjectionRef: 'b'.repeat(64) }, { targetRef: ref }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...response.result,
      contextPage: { ...response.result.contextPage, ...change } } }, request), TypeError);
  for (const change of [{ id: 'foreign' }, { contextRevision: 8 }, { contextProjectionRef: 'b'.repeat(64) }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...response.result,
      snapshot: { ...response.result.snapshot, session: { ...response.result.snapshot.session, ...change } } } }, request), TypeError);
});

test('Session context revision refusal binds the authenticated Session and does not select a replacement graph', () => {
  const { request, response } = fixture();
  const refusal = { protocolVersion: 1, ok: false, method: 'session.get', error: { schemaVersion: 1, code: 'REVISION_CONFLICT', retryable: true,
    messageCode: 'control.revision_conflict', currentRevision: 7, conflict: { resourceKind: 'session', currentSnapshot: response.result.snapshot } } };
  assert.deepEqual(decodeInstalledControlResponse(refusal, request), refusal);
  assert.throws(() => decodeInstalledControlResponse(refusal, { protocolVersion: 1, method: 'session.get', sessionId: 'session' }),
    /wrong resource kind/u, 'ordinary Session metadata reads never accept this page-only revision refusal');
  assert.throws(() => decodeInstalledControlResponse({ ...refusal, error: { ...refusal.error, currentRevision: 8 } }, request), /revision differs/u);
  assert.throws(() => decodeInstalledControlResponse({ ...refusal, error: { ...refusal.error, retryable: false } }, request), /unexpected revision conflict/u);
  assert.throws(() => decodeInstalledControlResponse({ ...refusal, error: { ...refusal.error, unexpected: true } }, request), TypeError);
  assert.throws(() => decodeInstalledControlResponse({ ...refusal, error: { ...refusal.error, conflict: { resourceKind: 'run',
    currentSnapshot: response.result.snapshot } } }, request), /invalid conflict resource/u);
  assert.throws(() => decodeInstalledControlResponse({ ...refusal, error: { ...refusal.error, conflict: { resourceKind: 'session',
    currentSnapshot: { ...response.result.snapshot, session: { ...response.result.snapshot.session, id: 'foreign' } } } } }, request), /requested Session/u);
});
