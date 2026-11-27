// Real retained-data SQLite/CAS reader only. No StateOwner, Run, authentication,
// admission, native birth, physical backup or publication-durability proof.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { walkSessionContextPageEdges } from '../kernel/session-context-page-reader.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { Session, SessionContextSegment } from '../kernel/types.js';
import { ArtifactCatalog, insertArtifactMetadata } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { applyKernelSchema } from './schema.js';
import { projectLegacySessionItem } from './legacy-source-context.js';
import { appendSessionContextGraph, publishSessionContextGraph } from './session-context-graph.js';
import { assertCurrentSessionContextGraph, consumeFrozenSessionContext, readCurrentSessionContextGraph, readSessionContextGraphHead } from './session-context-stream.js';
import { sessionContextModelMessages } from './agent-context.js';
import { KernelStorageError } from './errors.js';

const at = '2026-01-04T00:00:00.000Z', createdAt = '2026-01-02T00:00:00.000Z';
async function fixture(t: TestContext, count: number, text = 'Old role/configuration remains user history.') {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-inert-session-pages-'));
  const driver = openSqliteDriver(path.join(root, 'retained-data.sqlite3'));
  t.after(async () => { driver.close(); await rm(root, { recursive: true, force: true }); });
  applyKernelSchema(driver);
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const workspaceCore = { schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: 'inert-principal', platform: 'linux',
    kind: 'legacy_unavailable', legacyCanonicalRootPath: '/old/session', unavailableReason: 'missing', observedAt: at };
  const workspace = await artifacts.publishCanonical({ ...workspaceCore, identityDigest: canonicalSha256(workspaceCore) }, workspaceCore.format);
  insertArtifactMetadata(driver, workspace, at);
  const sourcePath = 'sessions/2026/01/02/old_session.json';
  async function* segments(): AsyncIterableIterator<SessionContextSegment> {
    for (let index = 0; index < count; index++) {
      const item = projectLegacySessionItem({ sourcePath, publicationPreparedAt: at,
        item: { kind: 'legacy_record', ordinal: index, value: { id: `record-${index}`, ts: '2026-01-01T00:00:00.000Z',
          kind: 'system', role: 'system', content: text } } });
      // These are ordinary immutable retained-data fixture bytes, deliberately
      // not a claim that the production CAS publication/backup protocol ran.
      // The actual reader must independently verify their complete hash/EOF/
      // ownership/no-follow/descriptor close before it can consume them.
      const bytes = canonicalJsonBytes(item.payload);
      await writeFile(path.join(root, item.payloadRef), bytes, { flag: 'wx', mode: 0o400 });
      driver.transaction(connection => {
        insertArtifactMetadata(connection, { ref: item.payloadRef, byteLength: bytes.length,
          mediaType: 'application/json', schemaKind: item.payload.format }, at);
        connection.prepare('INSERT INTO items(item_id,session_id,run_id,item_seq,kind,payload_ref,created_at) VALUES(?,?,NULL,?,?,?,?)')
          .run(item.itemId, 'old_session', index + 1, item.payload.kind, item.payloadRef, at);
      });
      yield { kind: 'raw', fromItemSeq: index + 1, throughItemSeq: index + 1,
        items: [{ sourceSessionId: 'old_session', itemSeq: index + 1, itemId: item.itemId, kind: item.payload.kind, payloadRef: item.payloadRef }] };
    }
  }
  const graph = await publishSessionContextGraph(artifacts, { sessionId: 'old_session', contextRevision: 1,
    throughItemSeq: count, segments: segments() });
  insertArtifactMetadata(driver, graph.artifact, at);
  driver.prepare(`INSERT INTO sessions(id,workspace_identity_ref,name,parent_session_id,forked_through_item_seq,context_revision,
    latest_item_seq,context_projection_ref,created_at,updated_at,principal_id,admission_method,admission_key,admission_intent_digest,admission_request_id)
    VALUES(?,?,NULL,NULL,NULL,1,?,?,?,?,?,?,?, ?,NULL)`).run('old_session', workspace.ref, count, graph.artifact.ref,
      createdAt, at, 'inert-principal', 'state.migrate', 'inert-key', 'a'.repeat(64));
  const session: Session = { schemaVersion: 1, id: 'old_session', workspaceIdentityRef: workspace.ref, contextRevision: 1,
    latestItemSeq: count, contextProjectionRef: graph.artifact.ref, createdAt, updatedAt: at };
  return { driver, artifacts, session };
}
test('2,000 retained Legacy items traverse the real paged SQL/CAS/typed/model consumer without raw roles', async t => {
  const f = await fixture(t, 2_000); let count = 0;
  const read = await consumeFrozenSessionContext(f.driver, f.artifacts, 'inert-principal', f.session, entry => {
    const message = sessionContextModelMessages([entry], count)[0]!;
    assert.equal(message.role, 'user'); assert.equal(message.sourceKind, 'session_legacy');
    assert.equal(message.index, count++);
  });
  assert.equal(count, 2_000); assert.equal(read.cut.itemCount, 2_000);
  f.driver.readSnapshot(connection => assertCurrentSessionContextGraph(connection, read.cut));
  assert.equal(f.driver.prepare('SELECT count(*) AS n FROM state_owners').get<{ n: bigint }>()!.n, 0n);
  assert.equal(f.driver.prepare('SELECT count(*) AS n FROM runs').get<{ n: bigint }>()!.n, 0n);
});
test('all uncatalogued internal pages remain typed reachable and a prior same-byte descriptor never controls their use', async t => {
  const f = await fixture(t, 70), head = await readSessionContextGraphHead(f.artifacts, f.session.contextProjectionRef);
  const edges = [];
  for await (const edge of walkSessionContextPageEdges(f.artifacts, head)) {
    assert.equal(edge.purpose, 'session_context_page');
    assert.equal(f.driver.prepare('SELECT ref FROM artifacts WHERE ref=?').get(edge.ref), undefined);
    await f.artifacts.verifyBytes(edge.ref); edges.push(edge);
  }
  assert(edges.length > 1, 'the full real tree includes its branch and every leaf');
  const original = await f.artifacts.describe(edges[0]!.ref, 'application/octet-stream', 'cliq-source-file-blob-v1');
  insertArtifactMetadata(f.driver, original, at);
  const declaration = f.driver.prepare('SELECT * FROM artifacts WHERE ref=?').get(original.ref);
  let count = 0;
  await consumeFrozenSessionContext(f.driver, f.artifacts, 'inert-principal', f.session, () => { count++; });
  assert.equal(count, 70, 'readability depends on every original page/typed payload, not its metadata label');
  assert.deepEqual(f.driver.prepare('SELECT * FROM artifacts WHERE ref=?').get(original.ref), declaration);
});
test('real immutability rejects replacement while a later legitimate append preserves the frozen cut', async t => {
  const f = await fixture(t, 70); let count = 0;
  assert.throws(() => f.driver.prepare('UPDATE items SET payload_ref=? WHERE session_id=? AND item_seq=1')
    .run('b'.repeat(64), 'old_session'), /items are immutable/u);
  const frozen = await consumeFrozenSessionContext(f.driver, f.artifacts, 'inert-principal', f.session, async () => {
    if (++count !== 70) return;
    const laterAt = '2026-01-05T00:00:00.000Z';
    const next = projectLegacySessionItem({ sourcePath: 'sessions/2026/01/02/old_session.json', publicationPreparedAt: laterAt,
      item: { kind: 'legacy_record', ordinal: 70, value: { id: 'later-record', ts: '2026-01-01T00:00:00.000Z',
        kind: 'system', role: 'system', content: 'A real later retained user-history append.' } } });
    const payload = await f.artifacts.publishCanonical(next.payload, next.payload.format);
    const head = await readSessionContextGraphHead(f.artifacts, f.session.contextProjectionRef);
    assert.equal(head.schemaVersion, 2); if (head.schemaVersion !== 2) return assert.fail();
    const appended = await appendSessionContextGraph(f.artifacts, head, { kind: 'raw', fromItemSeq: 71, throughItemSeq: 71,
      items: [{ sourceSessionId: f.session.id, itemSeq: 71, itemId: next.itemId, kind: next.payload.kind, payloadRef: payload.ref }] },
    {});
    f.driver.transaction(connection => {
      insertArtifactMetadata(connection, payload, laterAt);
      insertArtifactMetadata(connection, appended.artifact, laterAt);
      connection.prepare('INSERT INTO items(item_id,session_id,run_id,item_seq,kind,payload_ref,created_at) VALUES(?,?,NULL,71,?,?,?)')
        .run(next.itemId, f.session.id, next.payload.kind, payload.ref, laterAt);
      connection.prepare('UPDATE sessions SET context_revision=2,latest_item_seq=71,context_projection_ref=?,updated_at=? WHERE id=?')
        .run(appended.artifact.ref, laterAt, f.session.id);
    });
  });
  assert.equal(count, 70);
  assert.equal(frozen.cut.itemCount, 70, 'the captured prefix never borrows the later current head');
  assert.throws(() => f.driver.readSnapshot(connection => assertCurrentSessionContextGraph(connection, frozen.cut)),
    error => error instanceof KernelStorageError && error.code === 'REVISION_CONFLICT');
  let currentCount = 0;
  await readCurrentSessionContextGraph(f.driver, f.artifacts, 'inert-principal', f.session.id, 2,
    { consume: () => { currentCount++; } });
  assert.equal(currentCount, 71);
});
test('certainly impossible fixed model prefix is completely read but creates no Run/claim', async t => {
  const f = await fixture(t, 40, 'prose '.repeat(6_000)); let count = 0, profileReads = 0;
  await assert.rejects(readCurrentSessionContextGraph(f.driver, f.artifacts, 'inert-principal', f.session.id, 1,
    { modelProfile: async () => { profileReads++; return { provider: 'anthropic', model: 'fixed-model' }; }, consume: () => { count++; } }),
  error => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST' && /compact the Session/u.test(error.message));
  assert.equal(count, 40, 'overflow does not skip the remaining typed graph');
  assert.equal(profileReads, 1, 'the one exact profile is resolved at the first actual visible entry');
  assert.equal(f.driver.prepare('SELECT count(*) AS n FROM runs').get<{ n: bigint }>()!.n, 0n);
  assert.equal(f.driver.prepare('SELECT count(*) AS n FROM run_journal').get<{ n: bigint }>()!.n, 0n);
});
test('cancellation joins the current source cursor and never returns a complete context cut', async t => {
  const f = await fixture(t, 70), controller = new AbortController(); let count = 0;
  await assert.rejects(consumeFrozenSessionContext(f.driver, f.artifacts, 'inert-principal', f.session, () => {
    if (++count === 3) controller.abort(new Error('cancel retained data read'));
  }, controller.signal), /cancel retained data read/u);
  assert.equal(count, 3);
  // The same real read-only data can still be inspected after the cancelled
  // consumer has actually joined; no execution/owner is resumed or invented.
  let all = 0; await consumeFrozenSessionContext(f.driver, f.artifacts, 'inert-principal', f.session, () => { all++; });
  assert.equal(all, 70);
});

test('an empty real Session graph has zero context contribution without resolving model authority', async t => {
  const f = await fixture(t, 0); let profileReads = 0, visible = 0;
  const read = await readCurrentSessionContextGraph(f.driver, f.artifacts, 'inert-principal', f.session.id, 1,
    { modelProfile: async () => { profileReads++; throw new Error('empty context cannot require an unrelated assembly'); },
      consume: () => { visible++; } });
  assert.equal(profileReads, 0); assert.equal(visible, 0); assert.equal(read.cut.itemCount, 0);
  f.driver.readSnapshot(connection => assertCurrentSessionContextGraph(connection, read.cut));
  assert.equal(f.driver.prepare('SELECT count(*) AS n FROM state_owners').get<{ n: bigint }>()!.n, 0n);
  assert.equal(f.driver.prepare('SELECT count(*) AS n FROM runs').get<{ n: bigint }>()!.n, 0n);
});
test('a failed first visible-entry profile joins its real retained-data cursor and never returns a complete cut', async t => {
  const f = await fixture(t, 70), reason = new Error('original full model profile was rejected'); let calls = 0, visible = 0;
  await assert.rejects(readCurrentSessionContextGraph(f.driver, f.artifacts, 'inert-principal', f.session.id, 1,
    { modelProfile: async () => { calls++; throw reason; }, consume: () => { visible++; } }), error => error === reason);
  assert.equal(calls, 1); assert.equal(visible, 0);
  let complete = 0;
  await consumeFrozenSessionContext(f.driver, f.artifacts, 'inert-principal', f.session, () => { complete++; });
  assert.equal(complete, 70); assert.equal(f.driver.prepare('SELECT count(*) AS n FROM runs').get<{ n: bigint }>()!.n, 0n);
});
