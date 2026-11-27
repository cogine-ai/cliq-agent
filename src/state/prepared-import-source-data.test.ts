// Real inert retained-data SQLite/CAS. No Owner, Run, installed identity,
// credential, native candidate or physical backup proof is constructed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { applyKernelSchema } from './schema.js';
import { appendPreparedImportRows, finalizePreparedImportSession, readPreparedImportSessionHeader,
  readPreparedImportSessionItemsPage, readPreparedImportSessionItemTail, readPreparedImportSessionsPage,
  type PreparedImportArtifactRow, type PreparedLegacyItemRow } from './prepared-import-candidate.js';
import { projectLegacySessionItem } from './legacy-source-context.js';
import { projectLegacyPlanSource, projectLegacyHandoffSource } from './legacy-source-artifacts.js';
import { publishSessionContextGraph } from './session-context-graph.js';
import { readCurrentSessionContextGraph } from './session-context-stream.js';
import { sessionContextModelMessages } from './agent-context.js';
import { legacyImportContextSegments } from './legacy-import-source.js';

const at = '2026-10-02T00:00:00.000Z', createdAt = '2026-10-01T00:00:00.000Z';
test('bounded Legacy grouping rejects a changed source prefix and joins its original iterator on cancellation', async () => {
  const row = (seq: number): PreparedLegacyItemRow => ({ item_id: `inert-${seq}`, session_id: 'inert', run_id: null,
    item_seq: BigInt(seq), kind: 'legacy_record', payload_ref: 'a'.repeat(64), created_at: at });
  const finish = async (items: readonly PreparedLegacyItemRow[]) => {
    for await (const _segment of legacyImportContextSegments('inert', items)) { /* full data prefix only */ }
  };
  await assert.rejects(finish([row(1), row(3)]), /prefix/);
  await assert.rejects(finish([{ ...row(1), session_id: 'foreign' }]), /prefix/);
  let joined = false;
  async function* original() {
    try { for (let seq = 1; seq <= 128; seq++) yield row(seq); }
    finally { await Promise.resolve(); joined = true; }
  }
  const stop = new AbortController(), reason = new Error('original data cancellation');
  const grouped = legacyImportContextSegments('inert', original(), stop.signal);
  const first = await grouped.next(); assert.equal(first.done, false);
  if (!first.done) { assert.equal(first.value.fromItemSeq, 1); assert.equal(first.value.throughItemSeq, 64); }
  stop.abort(reason); await assert.rejects(grouped.next(), error => error === reason); assert.equal(joined, true);
});
test('fixed preview cursors and finalization retain a large five-kind history through the real paged/model consumer', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-inert-import-source-'));
  const driver = openSqliteDriver(path.join(root, 'retained-data.sqlite3'));
  t.after(async () => { driver.close(); await rm(root, { recursive: true, force: true }); }); applyKernelSchema(driver);
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const meta = (value: Awaited<ReturnType<ArtifactCatalog['publishCanonical']>>): PreparedImportArtifactRow => ({
    ref: value.ref, byte_length: BigInt(value.byteLength), media_type: value.mediaType, schema_kind: value.schemaKind, created_at: at });
  const missing = { schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: 'inert-principal', platform: 'linux',
    kind: 'legacy_unavailable', legacyCanonicalRootPath: '/old/session', unavailableReason: 'missing', observedAt: at };
  const workspace = await artifacts.publishCanonical({ ...missing, identityDigest: canonicalSha256(missing) }, missing.format);
  const empty = await publishSessionContextGraph(artifacts, { sessionId: 'old_session', contextRevision: 1, throughItemSeq: 0, segments: [] });
  appendPreparedImportRows(driver, { items: [], artifacts: [meta(workspace), meta(empty.artifact)], sessions: [{
    id: 'old_session', workspace_identity_ref: workspace.ref, name: null, parent_session_id: null, forked_through_item_seq: null,
    context_revision: 1n, latest_item_seq: 0n, context_projection_ref: empty.artifact.ref, created_at: createdAt, updated_at: at,
    principal_id: 'inert-principal', admission_method: 'state.migrate', admission_key: 'inert-import',
    admission_intent_digest: 'a'.repeat(64), admission_request_id: null }] });
  const original = readPreparedImportSessionHeader(driver, 'old_session')!;
  assert.deepEqual(readPreparedImportSessionsPage(driver, ''), [original]); assert.deepEqual(readPreparedImportSessionsPage(driver, 'old_session'), []);
  const sourcePath = 'sessions/2026/10/01/old_session.json';
  const projected = (index: number) => projectLegacySessionItem({ sourcePath, publicationPreparedAt: at,
    item: { kind: 'legacy_record', ordinal: index, value: { id: `record_${index}`, ts: createdAt,
      kind: 'system', role: 'system', content: `Historical user context ${index}` } } });
  let seq = 0n, items: PreparedLegacyItemRow[] = [], metadata: PreparedImportArtifactRow[] = [];
  const append = async (value: ReturnType<typeof projected>) => {
    const bytes = canonicalJsonBytes(value.payload);
    // Retained fixture bytes are not production publication/backup evidence.
    await writeFile(path.join(root, value.payloadRef), bytes, { flag: 'wx', mode: 0o400 });
    items.push({ item_id: value.itemId, session_id: 'old_session', run_id: null, item_seq: ++seq,
      kind: value.payload.kind, payload_ref: value.payloadRef, created_at: at });
    metadata.push({ ref: value.payloadRef, byte_length: BigInt(bytes.length), media_type: 'application/json', schema_kind: value.payload.format, created_at: at });
    if (items.length === 64) { appendPreparedImportRows(driver, { sessions: [], items, artifacts: metadata }); items = []; metadata = []; }
  };
  for (let index = 0; index < 2_000; index++) await append(projected(index));
  await append(projectLegacySessionItem({ sourcePath, publicationPreparedAt: at, item: { kind: 'legacy_compaction', ordinal: 0,
    value: { id: 'old_compaction', status: 'active', createdAt: at, coveredRange: { startIndexInclusive: 0, endIndexExclusive: 100 },
      firstKeptRecordId: 'record_100', summaryMarkdown: 'Only historical user summary' } } }));
  await append(projectLegacySessionItem({ sourcePath, publicationPreparedAt: at, item: { kind: 'legacy_bookmark', ordinal: 0,
    value: { id: 'old_bookmark', kind: 'manual', createdAt: at, recordIndex: 2_000, turn: 1 } } }));
  const planPath = 'plans/workspace/old_session/old_plan/plan.json';
  await append(projectLegacyPlanSource({ sourcePath: planPath, legacyRootPath: '/old/cliq', publicationPreparedAt: at,
    value: { id: 'old_plan', sessionId: 'old_session', workspaceId: 'workspace', title: 'Historical approved plan', status: 'approved',
      contentMarkdown: 'No execution permission', items: [], createdAt, updatedAt: at,
      paths: { json: `/old/cliq/${planPath}`, markdown: '/old/cliq/plans/workspace/old_session/old_plan/plan.md' } } }));
  const handoffPath = 'handoffs/old_handoff/handoff.json';
  await append(projectLegacyHandoffSource({ sourcePath: handoffPath, legacyRootPath: '/old/cliq', publicationPreparedAt: at,
    value: { id: 'old_handoff', sessionId: 'old_session', checkpointId: 'old_bookmark', createdAt: at, summarySource: 'handoff-only',
      provider: 'deepseek', model: 'old', summaryMarkdown: 'Historical handoff',
      paths: { json: `/old/cliq/${handoffPath}`, markdown: '/old/cliq/handoffs/old_handoff/HANDOFF.md' } } }));
  if (items.length) appendPreparedImportRows(driver, { sessions: [], items, artifacts: metadata });
  assert.equal(seq, 2_004n); assert.equal(readPreparedImportSessionItemTail(driver, 'old_session'), seq);
  async function* contextItems(): AsyncIterableIterator<PreparedLegacyItemRow> {
    let after = 0n;
    for (;;) {
      const page = readPreparedImportSessionItemsPage(driver, 'old_session', after); if (!page.length) return;
      assert(page.length <= 64);
      yield* page;
      after = page.at(-1)!.item_seq;
    }
  }
  let publishedGraphObjects = 0;
  const graph = await publishSessionContextGraph(artifacts, { sessionId: 'old_session', contextRevision: 1,
    throughItemSeq: Number(seq), segments: legacyImportContextSegments('old_session', contextItems()) }, { onPublished: artifact => {
    publishedGraphObjects++;
    appendPreparedImportRows(driver, { sessions: [], items: [], artifacts: [meta(artifact)] }); } });
  assert.throws(() => finalizePreparedImportSession(driver, original, { contextProjectionRef: graph.artifact.ref, throughItemSeq: seq - 1n }), /tail/);
  finalizePreparedImportSession(driver, original, { contextProjectionRef: graph.artifact.ref, throughItemSeq: seq });
  assert.throws(() => finalizePreparedImportSession(driver, original, { contextProjectionRef: graph.artifact.ref, throughItemSeq: seq }), /changed/);
  let seen = 0; const kinds = new Set<string>();
  await readCurrentSessionContextGraph(driver, artifacts, 'inert-principal', 'old_session', 1, { consume: entry => {
    const message = sessionContextModelMessages([entry], seen++)[0]!;
    assert.equal(message.role, 'user'); assert.equal(message.sourceKind, 'session_legacy'); kinds.add(entry.sourceKind);
  } });
  assert.equal(seen, Number(seq)); assert.deepEqual([...kinds], ['legacy_record', 'legacy_compaction', 'legacy_bookmark', 'legacy_plan', 'legacy_handoff']);
  assert.equal(publishedGraphObjects, 10, '2004 real items require eight bounded leaves, one branch and one head, without dropping history');
  assert.equal(driver.prepare('SELECT COUNT(*) AS n FROM runs').get<{ n: bigint }>()!.n, 0n);
  assert.equal(driver.prepare('SELECT COUNT(*) AS n FROM state_owners').get<{ n: bigint }>()!.n, 0n);
});
