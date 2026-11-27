// Actual retained-data SQLite/CAS consumer only. No StateOwner, Run, admission,
// control authentication, native birth or physical backup proof is constructed.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { projectLegacySessionItem, projectLegacySessionMetadata, assertProjectedLegacyItem } from './legacy-source-context.js';
import { ArtifactCatalog, insertArtifactMetadata } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { applyKernelSchema } from './schema.js';
import { readSessionContextCut } from './session-context.js';
import { sessionContextModelMessages } from './agent-context.js';
import { KernelStorageError } from './errors.js';

const sourcePath = 'sessions/2026/01/02/child_original.json';
const parentRecordedAt = '2026-01-01T00:00:00.000Z', childCreatedAt = '2026-01-02T00:00:00.000Z';
const preparedAt = '2026-01-04T00:00:00.000Z';
const header = { version: 5, app: 'cliq', id: 'child_original', cwd: '/old/fork',
  createdAt: childCreatedAt, updatedAt: '2026-01-03T00:00:00.000Z' };
const original = { id: 'record_from_parent', ts: parentRecordedAt, kind: 'system', role: 'system',
  content: 'Original system prose remains historical user context.' };
function projected() {
  return projectLegacySessionItem({ sourcePath, item: { kind: 'legacy_record', ordinal: 0, value: original },
    publicationPreparedAt: preparedAt });
}
async function retainedFixture(t: TestContext, indexedAt: string) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-legacy-fork-context-'));
  const driver = openSqliteDriver(path.join(root, 'retained-data.sqlite3'));
  t.after(async () => { driver.close(); await rm(root, { recursive: true, force: true }); });
  applyKernelSchema(driver);
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const item = projected(), metadata = projectLegacySessionMetadata(sourcePath, header, preparedAt);
  const payload = await artifacts.publishCanonical(item.payload, item.payload.format);
  const workspaceData = { schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: 'inert-principal', platform: 'linux',
    kind: 'legacy_unavailable', legacyCanonicalRootPath: '/old/fork', unavailableReason: 'missing', observedAt: preparedAt };
  const workspace = await artifacts.publishCanonical({ ...workspaceData, identityDigest: canonicalSha256(workspaceData) }, workspaceData.format);
  const contextData = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId: metadata.legacySessionId,
    contextRevision: 1, throughItemSeq: 1, segments: [{ kind: 'raw', fromItemSeq: 1, throughItemSeq: 1,
      items: [{ sourceSessionId: metadata.legacySessionId, itemSeq: 1, itemId: item.itemId, kind: 'legacy_record', payloadRef: payload.ref }] }], projectionDigest: '' };
  contextData.projectionDigest = digestOmitting(contextData, 'projectionDigest');
  const context = await artifacts.publishCanonical(contextData, contextData.format);
  driver.transaction(connection => {
    for (const value of [payload, workspace, context]) insertArtifactMetadata(connection, value, preparedAt);
    connection.prepare(`INSERT INTO sessions(id,workspace_identity_ref,name,parent_session_id,forked_through_item_seq,context_revision,
      latest_item_seq,context_projection_ref,created_at,updated_at,principal_id,admission_method,admission_key,admission_intent_digest,admission_request_id)
      VALUES(?,?,NULL,NULL,NULL,1,1,?,?,?,?,?,?,?,NULL)`).run(metadata.legacySessionId, workspace.ref, context.ref,
      metadata.createdAt, metadata.updatedAt, 'inert-principal', 'state.migrate', 'inert-import-key', 'a'.repeat(64));
    connection.prepare('INSERT INTO items(item_id,session_id,run_id,item_seq,kind,payload_ref,created_at) VALUES(?,?,NULL,1,?,?,?)')
      .run(item.itemId, metadata.legacySessionId, item.payload.kind, payload.ref, indexedAt);
  });
  return { driver, artifacts, item, metadata };
}

test('ordinary old fork history earlier than the child consumes through the unchanged full Session reader', async t => {
  const fixture = await retainedFixture(t, preparedAt);
  assert(fixture.item.payload.kind === 'legacy_record');
  assert.equal(fixture.item.payload.content.recordedAt, parentRecordedAt);
  assert.equal(fixture.metadata.createdAt, childCreatedAt);
  assert.equal(fixture.metadata.updatedAt, preparedAt);
  assert.equal(fixture.item.createdAt, preparedAt);
  const result = await readSessionContextCut(fixture.driver, fixture.artifacts, 'inert-principal', 'child_original');
  const messages = sessionContextModelMessages(result.entries);
  assert.equal(messages.length, 1); assert.equal(messages[0]?.role, 'user'); assert.equal(messages[0]?.sourceKind, 'session_legacy');
  assert.match(messages[0]!.contentUtf8, /Original system prose remains historical user context/);
  assert.equal(result.cut.session.parentSessionId, undefined, 'no unproved Kernel fork lineage was manufactured');
});

test('using the old copied record time as a new child index timestamp still fails the original consumer guard', async t => {
  const fixture = await retainedFixture(t, parentRecordedAt);
  await assert.rejects(readSessionContextCut(fixture.driver, fixture.artifacts, 'inert-principal', 'child_original'),
    error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');
});

test('source metadata rejects future, noncausal and path-mismatched headers without inventing timestamps', () => {
  for (const change of [{ updatedAt: '2026-01-05T00:00:00.000Z' }, { createdAt: '2026-01-04T00:00:00.000Z' },
    { id: 'different_source' }, { version: 6 }, { app: 'other' }])
    assert.throws(() => projectLegacySessionMetadata(sourcePath, { ...header, ...change }, preparedAt));
});

test('old record action/configuration fields cannot enter the closed payload or restore a tool/system role', () => {
  const value = projectLegacySessionItem({ sourcePath, publicationPreparedAt: preparedAt,
    item: { kind: 'legacy_record', ordinal: 0, value: { ...original, activeTxId: 'old', permission: 'allow',
      action: { type: 'tool', tool: 'bash', arguments: { command: 'never-execute' } } } } });
  assertProjectedLegacyItem(value);
  assert.equal(Object.hasOwn(value.payload.content, 'action'), false);
  assert.equal(Object.hasOwn(value.payload.content, 'permission'), false);
  assert.throws(() => projectLegacySessionItem({ sourcePath, publicationPreparedAt: preparedAt,
    item: { kind: 'legacy_record', ordinal: 0, value: { ...original, role: 'assistant' } } }));
  assert.throws(() => assertProjectedLegacyItem({ ...value, payloadRef: 'b'.repeat(64) }));
});
