import assert from 'node:assert/strict';
import { readdir, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { decodeSourceManifest, decodeSourceProjection } from './decoders.js';
import { decodeSourceIncludeAuthorization } from './source-include-artifacts.js';
import { createSourceInspectionFixture, sourceInspectionRequest } from './testing/source-inspection-fixtures.js';
import { readSourceIncludeClassification } from './source-include-classification.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { uuidv7 } from './testing/fixtures.js';
import { decodeAuthorizationConsumptionReceipt } from './authorization-artifacts.js';
import { digestOmitting } from '../kernel/identity.js';
import { readSourceProjectionData } from './source-projection-data.js';
import { decodeSandboxProfile } from './execution-closure.js';

test('an explicit ordinary selector is captured, retired and replayed through the original SourceInspection lifecycle', async t => {
  const fixture = await createSourceInspectionFixture(t, 'ordinary-include');
  await writeFile(path.join(fixture.workspace, 'note.txt'), 'original included bytes\n');
  const request = sourceInspectionRequest({ ...fixture.request, sourceIncludes: [{ path: 'note.txt', scope: 'entry' }] });
  const result = await fixture.store.captureSubmittedSource({ request, identity: fixture.identity });
  assert.equal(result.phase, 'retired');
  if (result.phase !== 'retired' || result.outcome.kind !== 'captured') assert.fail('the real include did not capture and retire');
  const source = decodeSourceManifest(await fixture.store.artifacts.readCanonical(result.outcome.sourceManifestRef));
  const projection = decodeSourceProjection(await fixture.store.artifacts.readCanonical(source.sourceProjectionRef));
  assert.equal(projection.explicitIncludes.length, 1);
  const selector = projection.explicitIncludes[0]!;
  assert.deepEqual({ path: selector.path, scope: selector.scope }, request.sourceIncludes[0]);
  const authorization = decodeSourceIncludeAuthorization(await fixture.store.artifacts.readCanonical(selector.authorizationRef));
  assert.equal(authorization.kind, 'builtin_nonignored');
  assert.equal(authorization.inspectionId, result.inspectionId);
  assert.equal(authorization.workspaceIdentityDigest, result.workspaceIdentityDigest);
  assert.equal(authorization.admissionIntentDigest, result.admissionIntentDigest);
  assert.equal(authorization.capturedEntriesRef, source.entriesRef);
  assert.equal(authorization.capturedTreeDigest, source.treeDigest);
  if (authorization.kind !== 'builtin_nonignored') assert.fail('the ordinary entry acquired another permission branch');
  const classified = await readSourceIncludeClassification(fixture.store.artifacts,authorization.classificationEvidenceRef);
  assert.equal(classified.entries.length,1);
  assert.equal(classified.entries[0]!.path,'note.txt');
  for (const ref of [selector.authorizationRef,authorization.classificationEvidenceRef,...classified.evidence.pageRefs]) {
    const original = path.join(fixture.stateRoot,'cas',ref), displaced = path.join(fixture.directory,`missing-${ref}`);
    await rename(original,displaced);
    try {
      await assert.rejects(fixture.store.captureSubmittedSource({request,identity:fixture.identity}),{code:'RECOVERY_REQUIRED'});
    } finally { await rename(displaced,original); }
  }
  assert.deepEqual(await fixture.store.captureSubmittedSource({ request, identity: fixture.identity }), result);
});

async function grantedFixture(t: Parameters<typeof createSourceInspectionFixture>[0], label: string) {
  const fixture = await createSourceInspectionFixture(t, label);
  await writeFile(path.join(fixture.workspace, 'note.txt'), 'a grant does not change ordinary classification\n');
  const workspace = await fixture.store.artifacts.readCanonical<WorkspaceIdentityV1>(fixture.session.workspaceIdentityRef);
  assert.equal(workspace.kind, 'live');
  if (workspace.kind !== 'live') assert.fail('the real Session must hold its live workspace');
  const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(),
    decision: { kind: 'read_scope', purpose: 'source', target: { sessionId: fixture.session.id,
      expectedWorkspaceIdentityDigest: workspace.identityDigest, path: 'note.txt', scope: 'entry' } } };
  const created = await fixture.store.createAuthorization({ ...core, requestDigest: canonicalSha256(core) }, fixture.identity);
  const grantId = created.response.result.grant.grantId;
  const request = sourceInspectionRequest({ ...fixture.request,
    sourceIncludes: [{ path: 'note.txt', scope: 'entry', readGrantId: grantId }] });
  const driver = (fixture.store as unknown as { driver: SqliteDriver }).driver;
  return { ...fixture, driver, grantId, request };
}

test('the first real capture consumes consent once even when later classification rejects an unnecessary grant', async t => {
  const fixture = await grantedFixture(t, 'include-burn');
  assert.equal(readAuthorizationGrant(fixture.driver, fixture.grantId)?.state, 'active');
  const result = await fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity });
  if (result.phase !== 'retired' || result.outcome.kind !== 'failed') assert.fail('unnecessary consent must fail and fully retire');
  const response = await fixture.store.artifacts.readCanonical<{ error: { code: string } }>(result.outcome.errorResponseRef);
  assert.equal(response.error.code, 'INVALID_REQUEST');
  const grant = readAuthorizationGrant(fixture.driver, fixture.grantId);
  assert.equal(grant?.state, 'consumed');
  if (grant?.state !== 'consumed') assert.fail('the original capture transaction must consume its grant');
  assert.equal(grant.useCount, 1);
  const receipt = decodeAuthorizationConsumptionReceipt(await fixture.store.artifacts.readCanonical(grant.consumptionReceiptRef));
  assert.deepEqual(receipt.consumer, { kind: 'source_inspection', inspectionId: result.inspectionId,
    admissionIntentDigest: result.admissionIntentDigest });
  assert(receipt.consumedAt <= result.createdAt && result.createdAt < grant.expiresAt);
  const target = await fixture.store.artifacts.readCanonical<{ sourceReadGrantRefs: string[] }>(result.targetRef);
  assert.equal(target.sourceReadGrantRefs.length, 1);
  for (const ref of [grant.consumptionReceiptRef, target.sourceReadGrantRefs[0]!]) {
    assert(fixture.driver.prepare('SELECT ref FROM artifacts WHERE ref=?').get(ref), 'first transaction registers the exact receipt/snapshot');
  }
  const before = readAuthorizationGrant(fixture.driver, fixture.grantId);
  assert.deepEqual(await fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity }), result);
  assert.deepEqual(readAuthorizationGrant(fixture.driver, fixture.grantId), before);
  assert.deepEqual(await readdir(path.join(fixture.stateRoot, 'runtime', 'source-inspections')), []);
});

test('an actual first-capture SQL rollback leaves consent active and no capturing row or metadata authority', async t => {
  const fixture = await grantedFixture(t, 'include-rollback');
  const before = readAuthorizationGrant(fixture.driver, fixture.grantId);
  const artifactsBefore = fixture.driver.prepare('SELECT * FROM artifacts ORDER BY ref').all();
  fixture.driver.exec(`CREATE TRIGGER test_include_capture_abort BEFORE INSERT ON source_inspection_attempts
    BEGIN SELECT RAISE(ABORT, 'owned include capture rollback'); END`);
  try {
    await assert.rejects(fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity }),
      /owned include capture rollback/);
    assert.deepEqual(readAuthorizationGrant(fixture.driver, fixture.grantId), before);
    assert.deepEqual(fixture.driver.prepare('SELECT * FROM source_inspection_attempts').all(), []);
    assert.deepEqual(fixture.driver.prepare('SELECT * FROM artifacts ORDER BY ref').all(), artifactsBefore);
    assert.deepEqual(await readdir(path.join(fixture.stateRoot, 'runtime', 'source-inspections')), []);
  } finally { fixture.driver.exec('DROP TRIGGER test_include_capture_abort'); }
  const result = await fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity });
  if (result.phase !== 'retired' || result.outcome.kind !== 'failed') assert.fail('the original request must reach the genuine classification refusal');
  assert.equal(readAuthorizationGrant(fixture.driver, fixture.grantId)?.state, 'consumed');
});

test('immutable inherited selection verifies original entries rather than treating a new base-role tree as the capture', async t => {
  const fixture = await createSourceInspectionFixture(t, 'include-origin');
  await writeFile(path.join(fixture.workspace, 'note.txt'), 'original bytes\n');
  const request = sourceInspectionRequest({ ...fixture.request, sourceIncludes: [{ path: 'note.txt', scope: 'entry' }] });
  const result = await fixture.store.captureSubmittedSource({ request, identity: fixture.identity });
  if (result.phase !== 'retired' || result.outcome.kind !== 'captured') assert.fail('the actual ordinary capture must retire');
  const original = decodeSourceManifest(await fixture.store.artifacts.readCanonical(result.outcome.sourceManifestRef));
  const projection = decodeSourceProjection(await fixture.store.artifacts.readCanonical(original.sourceProjectionRef));
  const target = await fixture.store.artifacts.readCanonical<{ sandboxProfileRef: string }>(result.targetRef);
  const resources = decodeSandboxProfile(await fixture.store.artifacts.readCanonical(target.sandboxProfileRef)).resources;
  const content = Buffer.from('later private source bytes\n');
  const file = await fixture.store.artifacts.publishBytes(content, 'application/octet-stream', 'cliq-workspace-file-v1');
  const entries = [{ path: 'note.txt', kind: 'file' as const, mode: 0o644, size: content.length, blobRef: file.ref }];
  const entryCore = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries };
  const captured = await fixture.store.artifacts.publishCanonical({ ...entryCore, entryCount: 1, byteCount: content.length,
    treeDigest: canonicalSha256(entryCore) }, 'cliq-workspace-entries-v1');
  // Inert source data only. This creates no child allocation, Delivery A,
  // native proof or authority to adopt the changed tree into a Run.
  const inherited = { ...original, entriesRef: captured.ref, treeDigest: canonicalSha256(entryCore), manifestDigest: '' };
  inherited.manifestDigest = digestOmitting(inherited, 'manifestDigest');
  assert.notEqual(inherited.entriesRef, original.entriesRef);
  const classified = await readSourceProjectionData(fixture.store.artifacts, inherited, projection, resources);
  assert.equal(classified.includes(entries[0]!), true);
  assert.equal(classified.includeObservations[0]?.capturedEntriesRef, original.entriesRef);
  const originalPath = path.join(fixture.stateRoot, 'cas', original.entriesRef), displaced = path.join(fixture.directory, 'original-entries');
  await rename(originalPath, displaced);
  try {
    assert(await fixture.store.artifacts.readCanonical(inherited.entriesRef), 'new entries do not substitute for original provenance');
    await assert.rejects(readSourceProjectionData(fixture.store.artifacts, inherited, projection, resources), { code: 'ENOENT' });
  } finally { await rename(displaced, originalPath); }
  assert.equal((await readSourceProjectionData(fixture.store.artifacts, inherited, projection, resources)).includes(entries[0]!), true);
});
