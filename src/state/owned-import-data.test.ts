// Ordinary retained data only. No StateOwner, Run, native scope, authenticated
// identity, installed factory or authority-marker fixture is manufactured.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeOwnedImportInventory, decodeOwnedImportInventoryPage, decodeOwnedLegacyImportRequest,
  decodeOwnedLegacyImportResponse, type OwnedImportInventoryV1 } from '../kernel/owned-import-data.js';
import { LEGACY_SESSION_CONTEXT_KINDS } from '../kernel/legacy-context.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readOwnedImportInventory } from './owned-import-inventory.js';
import { decodePreparedLegacySessionRow, decodePreparedLegacyItemRow, decodePreparedImportArtifactRow } from './owned-import-preview-audit.js';
import type { HeldMigrationBackupEntry } from './native-owner.js';
import type { PreparedImportRow } from './prepared-import-candidate.js';

const at = '2026-10-02T00:00:00.000Z', ref = 'a'.repeat(64), migrationId = 'x'.repeat(43);
function retainedEntry(relative: string): HeldMigrationBackupEntry {
  return { canonicalRootRelativePath: relative, sourceIdentity: { ownerUid: 1000, deviceId: '1', fileId: '2' },
    backupIdentity: { ownerUid: 1000, deviceId: '1', fileId: '3' }, kind: 'regular_file', mode: 384,
    purpose: 'backup_only', contentDigest: ref, byteCount: 12, linkCount: 1 };
}
function leaf(entries: readonly HeldMigrationBackupEntry[]) {
  return { schemaVersion: 1, format: 'cliq-owned-import-inventory-page-v1', kind: 'leaf', height: 0,
    firstPath: entries[0]!.canonicalRootRelativePath, lastPath: entries.at(-1)!.canonicalRootRelativePath,
    entryCount: entries.length, entries };
}
test('fixed import row data rejects executable/fork fields and preserves all five context-only kinds', () => {
  const session = { id: 'inert-session', workspace_identity_ref: ref, name: null, parent_session_id: null,
    forked_through_item_seq: null, context_revision: 1n, latest_item_seq: 4n, context_projection_ref: ref,
    created_at: at, updated_at: at, principal_id: 'inert-principal', admission_method: 'state.migrate',
    admission_key: migrationId, admission_intent_digest: ref, admission_request_id: null };
  assert.equal(decodePreparedLegacySessionRow(session), session);
  const changes: readonly PreparedImportRow[] = [{ context_revision: 2n }, { admission_key: ref }, { parent_session_id: 'old-parent' },
    { admission_request_id: 'old-request' }, { forked_through_item_seq: 2n }, { unknown: null }];
  for (const change of changes) assert.throws(() => decodePreparedLegacySessionRow({ ...session, ...change }));
  for (const kind of LEGACY_SESSION_CONTEXT_KINDS) {
    const item = { item_id: 'inert-item', session_id: session.id, run_id: null, item_seq: 1n, kind, payload_ref: ref, created_at: at };
    assert.equal(decodePreparedLegacyItemRow(item), item);
    assert.throws(() => decodePreparedLegacyItemRow({ ...item, run_id: 'execution' }));
    assert.throws(() => decodePreparedLegacyItemRow({ ...item, item_seq: 0n }));
    assert.throws(() => decodePreparedLegacyItemRow({ ...item, kind: 'tool_result' }));
  }
  let accessed = false;
  const accessor = { ...session };
  Object.defineProperty(accessor, 'id', { enumerable: true, get() { accessed = true; return 'x'; } });
  assert.throws(() => decodePreparedLegacySessionRow(accessor)); assert.equal(accessed, false);
  assert.throws(() => decodePreparedLegacySessionRow(new Proxy(session, {})));
});
test('first metadata declaration is scalar data and a schema label grants no extra row family', () => {
  const ordinary = { ref, media_type: 'application/octet-stream', schema_kind: 'untyped-original-bytes', byte_length: 12n, created_at: at };
  assert.equal(decodePreparedImportArtifactRow(ordinary), ordinary);
  assert.equal(decodePreparedImportArtifactRow({ ...ordinary, schema_kind: 'different-later-purpose' }).byte_length, ordinary.byte_length);
  assert.throws(() => decodePreparedImportArtifactRow({ ...ordinary, byte_length: -1n }));
  assert.throws(() => decodePreparedImportArtifactRow({ ...ordinary, permission: 'execute' }));
});
test('inventory pages preserve raw descendant UTF-8 and reject root credential and ambiguous edges', () => {
  const rawNfd = 'unknown/cafe\u0301.txt', normalized = rawNfd.normalize('NFC');
  assert.notEqual(rawNfd, normalized);
  const decoded = decodeOwnedImportInventoryPage(leaf([retainedEntry(rawNfd)]));
  assert.equal(decoded.kind, 'leaf'); if (decoded.kind !== 'leaf') return;
  assert.equal(decoded.entries[0]!.canonicalRootRelativePath, rawNfd);
  assert.doesNotThrow(() => decodeOwnedImportInventoryPage(leaf([retainedEntry('unknown/auth.json')])));
  assert.throws(() => decodeOwnedImportInventoryPage(leaf([retainedEntry('auth.json')])));
  assert.throws(() => decodeOwnedImportInventoryPage(leaf([retainedEntry('a/../b')])));
  assert.throws(() => decodeOwnedImportInventoryPage(leaf([retainedEntry(Array(65).fill('a').join('/'))])));
  assert.throws(() => decodeOwnedImportInventoryPage(leaf([retainedEntry('z'), retainedEntry('a')])));
  assert.throws(() => decodeOwnedImportInventoryPage({ ...leaf([retainedEntry('a')]), entryCount: 2 }));
  assert.throws(() => decodeOwnedImportInventoryPage(leaf(Array.from({ length: 65 }, (_, index) => retainedEntry(String(index).padStart(3, '0'))))));
});
test('retained inventory walks all real CAS pages and refuses a full-stream digest or count mismatch', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-owned-import-data-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(root));
  const entries = Array.from({ length: 96 }, (_, index) => retainedEntry('ordinary/' + String(index).padStart(4, '0')));
  const pages = [];
  for (let index = 0; index < entries.length; index += 32) {
    const page = decodeOwnedImportInventoryPage(leaf(entries.slice(index, index + 32)));
    const artifact = await artifacts.publishCanonical(page, page.format);
    pages.push({ ref: artifact.ref, firstPath: page.firstPath, lastPath: page.lastPath, entryCount: page.entryCount });
  }
  const branch = decodeOwnedImportInventoryPage({ schemaVersion: 1, format: 'cliq-owned-import-inventory-page-v1',
    kind: 'branch', height: 1, firstPath: pages[0]!.firstPath, lastPath: pages.at(-1)!.lastPath,
    entryCount: entries.length, children: pages });
  const top = await artifacts.publishCanonical(branch, branch.format);
  const hash = createHash('sha256').update('cliq-owned-import-inventory-entries-v1\n');
  for (const entry of entries) hash.update(canonicalJsonBytes(entry)).update('\n');
  const core = { schemaVersion: 1, format: 'cliq-owned-legacy-import-inventory-v1', migrationId,
    preparationRef: ref, preparationDigest: ref, legacyRootIdentityRef: ref, legacyRootIdentityDigest: ref,
    rootPageRef: top.ref, pageHeight: 1, entryCount: entries.length, entriesDigest: hash.digest('hex'), inventoryDigest: '' };
  core.inventoryDigest = digestOmitting(core, 'inventoryDigest');
  const manifest = decodeOwnedImportInventory(core);
  let seen = 0, pageCount = 0;
  for await (const event of readOwnedImportInventory(artifacts, manifest)) {
    if (event.kind === 'page') { pageCount++; continue; }
    assert.deepEqual(event.entry, entries[seen++]);
  }
  assert.equal(seen, 96); assert.equal(pageCount, 4);
  const changed = (delta: Partial<OwnedImportInventoryV1>) => {
    const next = { ...core, ...delta, inventoryDigest: '' }; next.inventoryDigest = digestOmitting(next, 'inventoryDigest');
    return decodeOwnedImportInventory(next);
  };
  const finish = async (input: OwnedImportInventoryV1) => { for await (const _event of readOwnedImportInventory(artifacts, input)) { /* consume exact EOF */ } };
  await assert.rejects(finish(changed({ entryCount: 95 })));
  await assert.rejects(finish(changed({ entriesDigest: ref })));
  await assert.rejects(finish(changed({ pageHeight: 2 })));
  assert.equal(canonicalSha256(manifest), canonicalSha256(core));
});
test('original request and prepared response have a closed data wire and no preclaimed commit clock', () => {
  const request = { protocolVersion: 1, method: 'state.migrate', requestId: '019a1234-1234-7123-8123-123456789abc', migrationId,
    legacyRootCanonicalAbsolutePath: '/home/inert/legacy' };
  assert.doesNotThrow(() => decodeOwnedLegacyImportRequest(request));
  assert.throws(() => decodeOwnedLegacyImportRequest({ ...request, requestId: 'not-original-uuidv7' }));
  assert.throws(() => decodeOwnedLegacyImportRequest({ ...request, verified: true }));
  const response = { protocolVersion: 1, method: 'state.migrate', status: 'completed', requestId: request.requestId,
    migrationId, preparationRef: ref, preparationDigest: ref, receiptRef: ref, receiptDigest: ref, completedAt: at };
  assert.doesNotThrow(() => decodeOwnedLegacyImportResponse(response));
  assert.throws(() => decodeOwnedLegacyImportResponse({ ...response, committedAt: at }));
});

