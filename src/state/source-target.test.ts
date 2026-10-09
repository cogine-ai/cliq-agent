import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, open, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { SourceInspectionRetirementEvidenceV1, SourceInspectionTargetV1 } from '../kernel/execution.js';
import type { SourceManifest, WorkspaceEntryManifest } from '../kernel/types.js';
import { testFixture } from '../model/testing/fixtures.js';
import { createWorkspaceTrustContext, writePersistedWorkspaceTrust } from '../session/trust.js';
import { normalizeRunSubmitRequest, runSubmitIntentDigest } from './source-target.js';
import { insertArtifactMetadata } from './artifacts.js';
import { admissionKey, uuidv7 } from './testing/fixtures.js';
import { signedToolBundle } from './testing/tool-authority.js';
import { fixtureSandboxProfile } from './testing/worker-launch.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { createSourceInspectionFixture, sourceInspectionRequest as inlineRequest } from './testing/source-inspection-fixtures.js';

test('inline submit normalization closes its schema and freezes defaults into intent, not request identity', () => {
  const first = normalizeRunSubmitRequest(inlineRequest());
  assert.equal(first.request.budgets.wallTimeMs, 86_400_000);
  assert.equal(first.request.sandboxResources.maxGenerationBytes, 20 * 1024 ** 3);
  assert.equal(first.request.maxChangedPaths, 10_000);
  assert.equal(first.request.maxChangedBytes, 512 * 1024 ** 2);
  const explicit = normalizeRunSubmitRequest(inlineRequest({ budgets: first.request.budgets,
    sandboxResources: first.request.sandboxResources, maxChangedPaths: first.request.maxChangedPaths,
    maxChangedBytes: first.request.maxChangedBytes }));
  assert.equal(runSubmitIntentDigest('principal', first.request), runSubmitIntentDigest('principal', explicit.request));
  assert.notEqual(first.originalRequestDigest, explicit.originalRequestDigest);
  assert.throws(() => normalizeRunSubmitRequest(inlineRequest({ sourceManifestRef: 'a'.repeat(64) })), { code: 'INVALID_REQUEST' });
  assert.throws(() => normalizeRunSubmitRequest(inlineRequest({ model: { provider: 'ollama', model: 'local', endpoint: { kind: 'registered', endpointRegistrationId: 'endpoint' } } })), { code: 'INVALID_REQUEST' });
  assert.throws(() => normalizeRunSubmitRequest(inlineRequest({ sourceExcludes: [{ path: 'secret', scope: 'entry', readGrantId: 'grant' }] })), { code: 'INVALID_REQUEST' });
  assert.throws(() => normalizeRunSubmitRequest(inlineRequest({ verifiers: [{ id: 'gate', version: '1', required: true,
    executable: { kind: 'toolchain', toolId: 'node' }, argv: [], cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: 'identity' }] })), { code: 'INVALID_REQUEST' });
});

for (const outcome of ['captured', 'failed'] as const) for (const missing of ['retirement', 'inspector'] as const) {
  test(`retained ${outcome} source replay requires its actual ${missing} evidence bytes`, async t => {
    const fixture = await createSourceInspectionFixture(t, `${outcome}-${missing}`);
    await writeFile(path.join(fixture.workspace, 'note.txt'), 'retirement provenance\n');
    const request = outcome === 'captured' ? fixture.request : inlineRequest({ ...fixture.request,
      sourceIncludes: [{ path: 'note.txt', scope: 'entry' }] });
    const retired = await fixture.store.captureSubmittedSource({ request, identity: fixture.identity });
    if (retired.phase !== 'retired' || retired.outcome.kind !== outcome) assert.fail('actual fixture did not retire its expected outcome');
    const evidence = await fixture.store.artifacts.readCanonical<SourceInspectionRetirementEvidenceV1>(retired.retirementEvidenceRef);
    const ref = missing === 'retirement' ? retired.retirementEvidenceRef : evidence.inspectorIdentityRef;
    const published = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, ref), displaced = path.join(fixture.directory, `missing-${ref}`);
    await rename(published, displaced);
    try {
      await assert.rejects(fixture.store.captureSubmittedSource({ request, identity: fixture.identity }), { code: 'RECOVERY_REQUIRED' });
    } finally { await rename(displaced, published); }
    assert.deepEqual(await fixture.store.captureSubmittedSource({ request, identity: fixture.identity }), retired);
  });
}

test('retained source replay rejects a real foreign INTERNAL error without adopting its request association', async t => {
  const fixture = await createSourceInspectionFixture(t, 'foreign-error');
  await writeFile(path.join(fixture.workspace, 'note.txt'), 'genuine source retirement\n');
  const request = inlineRequest({ ...fixture.request, sourceIncludes: [{ path: 'note.txt', scope: 'entry' }] });
  const retired = await fixture.store.captureSubmittedSource({ request, identity: fixture.identity });
  if (retired.phase !== 'retired' || retired.outcome.kind !== 'failed') assert.fail('actual capture must retire its supported failure prefix');
  const foreign = await fixture.store.artifacts.publishCanonical({ protocolVersion: 1, ok: false, method: 'run.submit',
    error: { schemaVersion: 1, messageCode: 'source_capture_failed', code: 'INTERNAL', retryable: false,
      errorId: identityHash('cliq-source-inspection-error-v1', 'another-inspection') } }, 'cliq-control-response-v1');
  const damaged = { ...retired, outcome: { kind: 'failed', errorResponseRef: foreign.ref }, rowDigest: '' };
  damaged.rowDigest = digestOmitting(damaged, 'rowDigest');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const guard = driver.prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='source_inspections_validate_update'")
      .get<{ sql: string }>()!;
    function injectRow(json: string) {
      // Deliberate durable-data corruption at the actual SQLite seam. Restore
      // the exact guard in the same transaction; do not fake capture/death/
      // cleanup evidence or weaken any production writer.
      driver.transaction(connection => {
        connection.exec('DROP TRIGGER source_inspections_validate_update');
        connection.prepare('UPDATE source_inspection_attempts SET row_json=? WHERE inspection_id=?').run(json, retired.inspectionId);
        connection.exec(guard.sql);
      });
    }
    driver.transaction(connection => insertArtifactMetadata(connection, foreign, retired.retiredAt));
    const follower = inlineRequest({ ...request, requestId: uuidv7() });
    injectRow(canonicalJsonBytes(damaged).toString());
    try {
      await assert.rejects(fixture.store.captureSubmittedSource({ request: follower, identity: fixture.identity }), { code: 'RECOVERY_REQUIRED' });
      assert.equal(driver.prepare("SELECT request_id FROM control_requests WHERE principal_id=? AND method='run.submit' AND request_id=?")
        .get(fixture.identity.principalId, follower.requestId), undefined);
    } finally { injectRow(canonicalJsonBytes(retired).toString()); }
    assert.deepEqual(await fixture.store.captureSubmittedSource({ request, identity: fixture.identity }), retired);
  } finally { driver.close(); }
});

test('source shutdown during an actual error publication retires as cancellation with its matching retained error', async t => {
  const fixture = await createSourceInspectionFixture(t, 'late-cancel');
  await writeFile(path.join(fixture.workspace, 'note.txt'), 'actual source, unsupported explicit include\n');
  const request = inlineRequest({ ...fixture.request, sourceIncludes: [{ path: 'note.txt', scope: 'entry' }] });
  const sample = await open(path.join(fixture.workspace, 'note.txt'), 'r');
  const prototype = Object.getPrototypeOf(sample) as FileHandle; await sample.close();
  const originalWrite = prototype.writeFile;
  let closing: Promise<void> | undefined, reached = false;
  prototype.writeFile = async function (this: FileHandle, ...args: Parameters<FileHandle['writeFile']>) {
    await originalWrite.apply(this, args);
    if (!reached && args[0] instanceof Uint8Array && Buffer.from(args[0]).includes(Buffer.from('"messageCode":"source_capture_rejected"'))) {
      reached = true;
      // Actual CAS bytes are written before shutdown requests cancellation.
      // The owned task must still join cleanup and publish its final class.
      closing = fixture.store.close();
    }
  };
  try {
    const retired = await fixture.store.captureSubmittedSource({ request, identity: fixture.identity });
    assert.equal(reached, true);
    if (retired.phase !== 'retired' || retired.outcome.kind !== 'cancelled') assert.fail('shutdown must retire the owned capture as cancelled');
    const response = await fixture.store.artifacts.readCanonical<{ error: { code: string } }>(retired.outcome.errorResponseRef);
    assert.equal(response.error.code, 'CANCEL_REQUESTED');
    assert.equal(retired.cancelRequested, true);
    await closing;
    assert.deepEqual(await readdir(path.join(fixture.stateRoot, 'runtime', 'source-inspections')), []);
  } finally { prototype.writeFile = originalWrite; await closing; }
});

test('source shutdown between actual 64 KiB writes joins native readers and interrupted CAS cleanup before owner release', async t => {
  const fixture = await createSourceInspectionFixture(t, 'chunk-cancel');
  const bytes = Buffer.alloc(256 * 1024, 0x71), marker = Buffer.from('actual-cancellation-source-chunk'); marker.copy(bytes);
  const source = path.join(fixture.workspace, 'large.txt'); await writeFile(source, bytes);
  const sample = await open(source, 'r'), prototype = Object.getPrototypeOf(sample) as FileHandle; await sample.close();
  const originalWrite = prototype.writeFile;
  let closing: Promise<void> | undefined, chunks = 0;
  prototype.writeFile = async function (this: FileHandle, ...args: Parameters<FileHandle['writeFile']>) {
    await originalWrite.apply(this, args);
    if (args[0] instanceof Uint8Array && args[0].byteLength === 64 * 1024 && Buffer.from(args[0]).includes(marker)) {
      chunks++;
      closing ??= fixture.store.close();
    }
  };
  try {
    const retired = await fixture.store.captureSubmittedSource({ request: fixture.request, identity: fixture.identity });
    assert.equal(chunks, 1, 'shutdown must interrupt the real file stream after its first bounded write');
    if (retired.phase !== 'retired' || retired.outcome.kind !== 'cancelled') assert.fail('chunk interruption must retire as cancellation');
    const response = await fixture.store.artifacts.readCanonical<{ error: { code: string } }>(retired.outcome.errorResponseRef);
    assert.equal(response.error.code, 'CANCEL_REQUESTED');
    await closing;
    const members = await readdir(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY));
    assert.ok(!members.some(member => member.startsWith('.tmp-')), 'interrupted CAS temporary must be joined and removed');
    assert.ok(!members.includes(createHash('sha256').update(bytes).digest('hex')), 'incomplete source bytes must not be published');
    assert.deepEqual(await readdir(path.join(fixture.stateRoot, 'runtime', 'source-inspections')), []);
    const successor = await openStateStore(fixture.stateRoot, fixture.authority);
    try {
      assert.deepEqual(await successor.captureSubmittedSource({ request: fixture.request,
        identity: await publishInProcessChannel(successor) }), retired);
    } finally { await successor.close(); }
  } finally { prototype.writeFile = originalWrite; await closing; }
});

test('failed capture retires genuine resources and associates later request ids to the same redacted error before live reinspection', async t => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'cliq-source-target-error-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const stateRoot = path.join(directory, 'state'), home = path.join(directory, 'home'), workspace = path.join(directory, 'workspace');
  for (const member of [stateRoot, home, workspace]) await mkdir(member, { mode: 0o700 });
  await writeFile(path.join(workspace, 'secret.txt'), 'never capture this unsupported include\n');
  await writePersistedWorkspaceTrust(await createWorkspaceTrustContext(workspace, home), 'trusted');
  const signed = await signedToolBundle(testFixture().assembly, []);
  const profile = fixtureSandboxProfile(); profile.allowedOwners = ['source_inspection']; profile.profileDigest = digestOmitting(profile, 'profileDigest');
  const store = await openStateStore(stateRoot, { bundle: signed.bundle, releaseKeys: signed.releaseKeys,
    sourceInspection: { controlledHome: home, sandboxProfile: profile } });
  try {
    const identity = await publishInProcessChannel(store);
    const created = await store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('source-error-session'), workspacePath: workspace });
    const request = inlineRequest({ sessionId: created.session.id, workspacePath: workspace,
      sourceIncludes: [{ path: 'secret.txt', scope: 'entry' }] });
    const retired = await store.captureSubmittedSource({ request, identity });
    assert.equal(retired.phase, 'retired');
    if (retired.phase !== 'retired' || retired.outcome.kind !== 'failed') assert.fail('unsupported source request must fail after real retirement');
    const errorResponseRef = retired.outcome.errorResponseRef;
    const error = await store.artifacts.readCanonical(errorResponseRef);
    assert.deepEqual(error, { protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1,
      messageCode: 'source_capture_rejected', code: 'INVALID_REQUEST', retryable: false,
      issues: [{ path: 'source', issueCode: 'source_changed_or_unsupported' }] } });
    assert.deepEqual(await readdir(path.join(stateRoot, 'runtime', 'source-inspections')), []);
    await rename(workspace, `${workspace}-moved`);
    const reconnected = await publishInProcessChannel(store, 'rpc'), later = inlineRequest({ ...request, requestId: uuidv7() });
    assert.deepEqual(await store.captureSubmittedSource({ request: later, identity: reconnected }), retired);
    const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const controls = driver.prepare(`SELECT request_id,request_digest,response_ref,channel_identity_ref FROM control_requests
        WHERE principal_id = ? AND method = 'run.submit' ORDER BY request_id`).all<{
          request_id: string; request_digest: string; response_ref: string; channel_identity_ref: string }>(identity.principalId);
      assert.equal(controls.length, 2);
      assert.ok(controls.some(row => row.request_id === request.requestId && row.request_digest === request.requestDigest && row.response_ref === errorResponseRef));
      assert.ok(controls.some(row => row.request_id === later.requestId && row.request_digest === later.requestDigest &&
        row.response_ref === errorResponseRef && row.channel_identity_ref === reconnected.channelIdentityRef));
    } finally { driver.close(); }
    await assert.rejects(store.captureSubmittedSource({ identity: reconnected,
      request: inlineRequest({ ...request, admissionKey: admissionKey('source-error-different-key') }) }), { code: 'REQUEST_ID_CONFLICT' });
    await assert.rejects(store.captureSubmittedSource({ identity: reconnected,
      request: inlineRequest({ ...request, requestId: uuidv7(), objective: 'different intent' }) }), { code: 'ADMISSION_KEY_CONFLICT' });
  } finally { await store.close(); }
});

test('actual source capture owns its reservation, joins cleanup and replays frozen bytes without reopening the live workspace', async t => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'cliq-source-target-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const stateRoot = path.join(directory, 'state'), home = path.join(directory, 'home'), workspace = path.join(directory, 'workspace');
  for (const member of [stateRoot, home, workspace]) await mkdir(member, { mode: 0o700 });
  await writeFile(path.join(workspace, 'note.txt'), 'the actual original source\n');
  const trust = await createWorkspaceTrustContext(workspace, home); await writePersistedWorkspaceTrust(trust, 'trusted');
  const fixture = testFixture(), signed = await signedToolBundle(fixture.assembly, []);
  const profile = fixtureSandboxProfile(); profile.allowedOwners = ['source_inspection']; profile.profileDigest = digestOmitting(profile, 'profileDigest');
  // Real Ed25519 test bootstrap and native owner/FS; this test performs no
  // process launch and makes no installed Linux/VM qualification claim.
  const authority = { bundle: signed.bundle, releaseKeys: signed.releaseKeys, sourceInspection: { controlledHome: home, sandboxProfile: profile } };
  let store = await openStateStore(stateRoot, authority);
  try {
    const identity = await publishInProcessChannel(store);
    const created = await store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('source-session'), workspacePath: workspace });
    const request = inlineRequest({ sessionId: created.session.id, workspacePath: workspace });
    const retired = await store.captureSubmittedSource({ request, identity });
    assert.equal(retired.phase, 'retired');
    if (retired.phase !== 'retired' || retired.outcome.kind !== 'captured') assert.fail('real source capture did not retire successfully');
    const target = await store.artifacts.readCanonical<SourceInspectionTargetV1>(retired.targetRef);
    assert.equal(target.admissionIntentDigest, runSubmitIntentDigest(identity.principalId, normalizeRunSubmitRequest(request).request));
    assert.equal(target.originalRequestDigest, request.requestDigest);
    assert.deepEqual(await store.artifacts.readCanonical(target.originalRequestRef), request);
    const manifest = await store.artifacts.readCanonical<SourceManifest>(retired.outcome.sourceManifestRef);
    const entries = await store.artifacts.readCanonical<WorkspaceEntryManifest>(manifest.entriesRef);
    const file = entries.entries.find(entry => entry.path === 'note.txt');
    assert.ok(file?.kind === 'file');
    assert.equal((await store.artifacts.readBytes(file.blobRef)).toString(), 'the actual original source\n');
    const evidence = await store.artifacts.readCanonical<SourceInspectionRetirementEvidenceV1>(retired.retirementEvidenceRef);
    assert.equal(evidence.captureOwnerClosure.kind, 'local_resources_joined');
    assert.deepEqual(evidence.processClosure, { kind: 'not_planned' });
    assert.equal(evidence.stagingObservation, 'exact_reserved_root_absent');
    assert.deepEqual(await readdir(path.join(stateRoot, 'runtime', 'source-inspections')), []);
    await assert.rejects(readFile(path.join(stateRoot, 'runtime', 'source-inspections', identityHash(retired.inspectionId, retired.stagingNonceDigest))), { code: 'ENOENT' });
    await writeFile(path.join(workspace, 'note.txt'), 'later mutable source\n');
    await rename(workspace, `${workspace}-moved`);
    assert.deepEqual(await store.captureSubmittedSource({ request, identity }), retired);
    await store.close(); store = await openStateStore(stateRoot, authority);
    assert.deepEqual(await store.captureSubmittedSource({ request, identity: await publishInProcessChannel(store) }), retired);
  } finally { await store.close(); }
});
