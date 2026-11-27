import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { StateOwnerContext } from './state-owner.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { admissionKey, createQueuedFixture, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { readRootRunAdmissionOrigin } from './run-admission-origin.js';
import { validateVerifierRunAdmission } from './verifier-admission.js';

// Actual Store, SQLite, CAS and genuine owner/channel lifetimes. No native
// launch, model dispatch, accepted child or installed qualification is made.
test('an empty-verifier root closes its original request, direct consent, frozen Session and initial response across reopen', async () => {
  const fixture = await createQueuedFixture('root-admission-origin');
  try {
    const driver = Reflect.get(fixture.store, 'driver') as SqliteDriver;
    const original = await readRootRunAdmissionOrigin(driver, fixture.store.artifacts, fixture.runId);
    assert.equal(original.run.id, fixture.runId); assert.equal(original.verifierRequests.length, 0);
    assert.deepEqual(original.authorizationReceiptRefs, []); original.assertUnchanged(driver);
    const { rename, stat } = await import('node:fs/promises'), path = await import('node:path');
    const corePath = path.join(fixture.stateRoot, 'cas', original.control.requestDigest), retainedCore = path.join(fixture.stateRoot, 'held-original-request-test');
    await rename(corePath, retainedCore);
    try {
      await assert.rejects(readRootRunAdmissionOrigin(driver, fixture.store.artifacts, fixture.runId), { code: 'ENOENT' });
      await assert.rejects(stat(corePath), { code: 'ENOENT' }, 'history cannot recreate missing original request bytes');
    } finally { await rename(retainedCore, corePath); }
    original.assertUnchanged(driver);
    const spec = original.spec, source = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(spec.baseWorkspaceManifestRef);
    const identity = await publishInProcessChannel(fixture.store);
    const second = await fixture.store.admitRun({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('root-origin-other'),
      sessionId: original.run.sessionId, expectedContextRevision: original.admittedContext.sessionContextRevision,
      workspacePath: fixture.workspace, objective: 'another legal Run', allowUnverified: true, sourceProjectionRef: spec.sourceProjectionRef,
      frozenIgnoreRulesRef: source.frozenIgnoreRulesRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
      verifierSpecRef: spec.verifierSpecRef, assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef });
    const other = await readRootRunAdmissionOrigin(driver, fixture.store.artifacts, second.run.id);
    assert.notEqual(original.control.responseRef, other.control.responseRef);
    driver.transaction(connection => connection.prepare('UPDATE control_requests SET response_ref=? WHERE principal_id=? AND method=? AND request_id=?')
      .run(other.control.responseRef, original.principalId, 'run.submit', original.admission.admission_request_id!));
    try {
      await assert.rejects(readRootRunAdmissionOrigin(driver, fixture.store.artifacts, fixture.runId), { code: 'RECOVERY_REQUIRED' });
      await assert.rejects(validateVerifierRunAdmission(driver, fixture.store.artifacts, Reflect.get(fixture.store, 'owner') as StateOwnerContext,
        fixture.runtimeAuthority, fixture.runId), { code: 'RECOVERY_REQUIRED' });
    } finally {
      driver.transaction(connection => connection.prepare('UPDATE control_requests SET response_ref=? WHERE principal_id=? AND method=? AND request_id=?')
        .run(original.control.responseRef, original.principalId, 'run.submit', original.admission.admission_request_id!));
    }
    driver.transaction(connection => connection.prepare('UPDATE control_requests SET request_digest=? WHERE principal_id=? AND method=? AND request_id=?')
      .run(other.control.requestDigest, original.principalId, 'run.submit', original.admission.admission_request_id!));
    try { await assert.rejects(readRootRunAdmissionOrigin(driver, fixture.store.artifacts, fixture.runId), { code: 'RECOVERY_REQUIRED' }); }
    finally {
      driver.transaction(connection => connection.prepare('UPDATE control_requests SET request_digest=? WHERE principal_id=? AND method=? AND request_id=?')
        .run(original.control.requestDigest, original.principalId, 'run.submit', original.admission.admission_request_id!));
    }
    original.assertUnchanged(driver);
    await fixture.store.close(); fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const restored = await readRootRunAdmissionOrigin(Reflect.get(fixture.store, 'driver') as SqliteDriver, fixture.store.artifacts, fixture.runId);
    assert.deepEqual(canonicalJsonBytes(restored.initialResponse), canonicalJsonBytes(original.initialResponse));
    assert.deepEqual(canonicalJsonBytes(restored.requestCore), canonicalJsonBytes(original.requestCore));
    assert.deepEqual(await validateVerifierRunAdmission(Reflect.get(fixture.store, 'driver') as SqliteDriver, fixture.store.artifacts,
      Reflect.get(fixture.store, 'owner') as StateOwnerContext, fixture.runtimeAuthority, fixture.runId), { authorizationReceiptRefs: [] });
  } finally { await disposeFixture(fixture); }
});
