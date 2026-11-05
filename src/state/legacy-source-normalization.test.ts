import test from 'node:test';
import assert from 'node:assert/strict';
import { projectLegacySessionItem, projectLegacySessionMetadata, legacyWorkspaceLookupPath } from './legacy-source-context.js';
import { LegacySessionSourceStream } from './legacy-source-stream.js';
import { createHash } from 'node:crypto';

const sourcePath = 'sessions/2026/01/02/original.json', at = '2026-01-04T00:00:00.000Z';
test('recognized historical prose/name/workspace data uses the specified NFC transform', () => {
  const metadata = projectLegacySessionMetadata(sourcePath, { version: 5, app: 'cliq', id: 'original',
    cwd: '/old/Cafe\u0301', name: 'Cafe\u0301', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: at }, at);
  assert.equal(metadata.name, 'Café'); assert.equal(metadata.legacyWorkspacePath, '/old/Cafe\u0301');
  assert.equal(metadata.legacyWorkspaceDisplayPath, '/old/Café'); assert.equal(legacyWorkspaceLookupPath(metadata), undefined);
  const projected = projectLegacySessionItem({ sourcePath, publicationPreparedAt: at,
    item: { kind: 'legacy_record', ordinal: 0, value: { id: 'record', ts: '2026-01-01T00:00:00.000Z',
      kind: 'user', role: 'user', content: 'Cafe\u0301' } } });
  assert.equal(projected.payload.kind, 'legacy_record');
  if (projected.payload.kind === 'legacy_record') assert.equal(projected.payload.content.contentUtf8, 'Café');
});
test('raw framing preserves NFD lookup bytes while only display/name becomes NFC', () => {
  const value = { version: 5, app: 'cliq', id: 'original', cwd: '/old/Cafe\u0301', name: 'Cafe\u0301', model: {},
    lifecycle: { status: 'idle', turn: 0 }, records: [], createdAt: at, updatedAt: at };
  const bytes = Buffer.from(JSON.stringify(value)), stream = new LegacySessionSourceStream({ byteCount: bytes.length,
    contentDigest: createHash('sha256').update(bytes).digest('hex') });
  stream.feed(bytes); const metadata = projectLegacySessionMetadata(sourcePath, stream.finish(), at);
  assert.equal(metadata.legacyWorkspacePath, value.cwd); assert.equal(metadata.legacyWorkspaceDisplayPath, '/old/Café');
  assert.equal(legacyWorkspaceLookupPath(metadata), undefined);
  const nfcBytes = Buffer.from(JSON.stringify({ ...value, cwd: '/old/Café' }));
  const nfcStream = new LegacySessionSourceStream({ byteCount: nfcBytes.length,
    contentDigest: createHash('sha256').update(nfcBytes).digest('hex') });
  nfcStream.feed(nfcBytes);
  const nfc = projectLegacySessionMetadata(sourcePath, nfcStream.finish(), at);
  assert.equal(legacyWorkspaceLookupPath(nfc), '/old/Café', 'eligibility still requires a later genuine descriptor capture and Trust gate');
});
test('NFC does not normalize malformed dates/ownership ids or admit NUL prose', () => {
  const original = { id: 'record', ts: '2026-01-01T00:00:00.000Z', kind: 'user', role: 'user', content: 'text' };
  for (const change of [{ content: 'a\0b' }, { ts: '2026-01-01' }, { role: 'system' }])
    assert.throws(() => projectLegacySessionItem({ sourcePath, publicationPreparedAt: at,
      item: { kind: 'legacy_record', ordinal: 0, value: { ...original, ...change } } }));
  assert.throws(() => projectLegacySessionMetadata(sourcePath, { version: 5, app: 'cliq', id: 'different', cwd: '/old',
    createdAt: at, updatedAt: at }, at));
});
