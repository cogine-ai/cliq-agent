// Actual StateOwner, SQLite, CAS and Ed25519 consent transactions. The signed
// fixture image is explicitly inert: these tests never mount it or claim a
// verifier/native invocation or Linux installation qualification.
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { VerifierRequest } from '../kernel/control-submit.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import { decodeAuthorizationConsumptionReceipt } from './authorization-artifacts.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createQueuedFixture, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';
import { verifierRequestCoreDigest } from './verifier-template.js';

test('explicit execution consent consumes one real identity atomically, replays, revokes independently and survives owner restart', async t => {
  const signed = await signedVerifierAuthority();
  const f = await createQueuedFixture('verifier-explicit-consent', { runtimeAuthority: { bundle: signed.bundle, releaseKeys: signed.releaseKeys },
    assembly: async store => {
      for (const object of signed.objects) await store.artifacts.publishBytes(object.bytes, 'application/octet-stream', 'offline-verifier-object');
      const assembly = (await import('../model/testing/fixtures.js')).testFixture().assembly;
      return (await store.artifacts.publishCanonical(assembly, assembly.format)).ref;
    } });
  const driver = openSqliteDriver(path.join(f.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    let channel = await publishInProcessChannel(f.store);
    const identityCore = () => ({ protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), decision: {
      kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: signed.manifestId, toolId: 'node' } } });
    const createIdentity = async (ttlMs?: number) => {
      const core = { ...identityCore(), ...(ttlMs === undefined ? {} : { ttlMs }) }, request = { ...core, requestDigest: canonicalSha256(core) };
      return { request, result: await f.store.createAuthorization(request, channel) };
    };
    const first = await createIdentity(), identityId = first.result.response.result.grant.grantId;
    const verifier: VerifierRequest = { id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
      argv: ['--test', '--test-concurrency=1', 'check.mjs'].map(value => ({ kind: 'non_secret_literal', value })), cwd: '.', env: {},
      writableEphemeralPaths: [], identityReadGrantId: identityId };
    const executionCore = (selectedIdentity = identityId) => ({ protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(),
      decision: { kind: 'verifier_execution', verifierId: verifier.id,
        verifierRequestDigest: verifierRequestCoreDigest({ ...verifier, identityReadGrantId: selectedIdentity }),
        executionIdentityGrantId: selectedIdentity, maxCandidateGenerations: 2, maxAttemptsPerCandidate: 1 } });
    const core = executionCore(), request = { ...core, requestDigest: canonicalSha256(core) };
    const created = await f.store.createAuthorization(request, channel), executionId = created.response.result.grant.grantId;
    assert.equal(created.replayed, false); assert.equal(created.response.result.grant.targetKind, 'verifier_execution');
    const identity = readAuthorizationGrant(driver, identityId), execution = readAuthorizationGrant(driver, executionId);
    assert.equal(identity?.state, 'consumed'); assert.equal(execution?.state, 'active');
    assert(identity?.state === 'consumed' && execution?.target.kind === 'verifier_execution');
    const receipt = decodeAuthorizationConsumptionReceipt(await f.store.artifacts.readCanonical(identity.consumptionReceiptRef));
    assert.deepEqual(receipt.consumer, { kind: 'authorization_derivation', derivedGrantId: executionId });
    assert.equal(receipt.consumedAt, execution.createdAt); assert.equal(execution.target.executionIdentityTargetDigest, identity.targetDigest);
    assert.deepEqual((await f.store.createAuthorization(request, channel)).response, created.response);
    assert.deepEqual((await f.store.createAuthorization(first.request, channel)).response, first.result.response);
    const reused = executionCore();
    await assert.rejects(f.store.createAuthorization({ ...reused, requestDigest: canonicalSha256(reused) }, channel),
      error => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'AUTHORIZATION_REQUIRED');
    const revokeCore = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: identityId };
    const revoked = await f.store.revokeAuthorization({ ...revokeCore, requestDigest: canonicalSha256(revokeCore) }, channel);
    assert.equal(revoked.response.result.method, 'authorization.revoke');
    if (revoked.response.result.method === 'authorization.revoke') assert.equal(revoked.response.result.disposition, 'already_consumed');
    assert.equal(readAuthorizationGrant(driver, executionId)?.state, 'active', 'revoking the consumed identity cannot revoke accepted derived authority');

    const second = await createIdentity(), secondId = second.result.response.result.grant.grantId, secondCore = executionCore(secondId);
    const secondRequest = { ...secondCore, requestDigest: canonicalSha256(secondCore) };
    const count = () => driver.prepare('SELECT count(*) AS count FROM authorization_grants').get<{ count: bigint }>()!.count;
    const before = count(); driver.exec("CREATE TRIGGER explicit_verifier_derivation_failure BEFORE INSERT ON authorization_grants BEGIN SELECT RAISE(ABORT,'original derivation transaction rejected'); END");
    try { await assert.rejects(f.store.createAuthorization(secondRequest, channel), /original derivation transaction rejected/); }
    finally { driver.exec('DROP TRIGGER explicit_verifier_derivation_failure'); }
    assert.equal(count(), before); assert.equal(readAuthorizationGrant(driver, secondId)?.state, 'active', 'failure rolls back the preceding identity consume');
    await f.store.createAuthorization(secondRequest, channel);
    assert.equal(readAuthorizationGrant(driver, secondId)?.state, 'consumed');

    const cancelled = await createIdentity(), cancelledId = cancelled.result.response.result.grant.grantId;
    const cancelledRevoke = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: cancelledId };
    await f.store.revokeAuthorization({ ...cancelledRevoke, requestDigest: canonicalSha256(cancelledRevoke) }, channel);
    const cancelledExecution = executionCore(cancelledId);
    await assert.rejects(f.store.createAuthorization({ ...cancelledExecution, requestDigest: canonicalSha256(cancelledExecution) }, channel),
      error => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'AUTHORIZATION_REQUIRED');
    assert.equal(readAuthorizationGrant(driver, cancelledId)?.state, 'revoked');
    const beforeExpired = count();
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    try {
      const expired = await createIdentity(1000), expiredId = expired.result.response.result.grant.grantId;
      t.mock.timers.tick(1000);
      const expiredExecution = executionCore(expiredId);
      await assert.rejects(f.store.createAuthorization({ ...expiredExecution, requestDigest: canonicalSha256(expiredExecution) }, channel),
        error => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'AUTHORIZATION_REQUIRED');
      assert.equal(count(), beforeExpired + 1n); assert.equal(readAuthorizationGrant(driver, expiredId)?.state, 'active',
        'expired authorization is not consumed or silently replaced');
    } finally { t.mock.timers.reset(); }

    const saved = driver.prepare('SELECT grant_id,owner_principal_id,state,row_json FROM authorization_grants WHERE grant_id=?')
      .get<{ grant_id: string; owner_principal_id: string; state: string; row_json: string }>(executionId)!;
    driver.prepare('DELETE FROM authorization_grants WHERE grant_id=?').run(executionId);
    try { await assert.rejects(f.store.createAuthorization(first.request, channel), { code: 'RECOVERY_REQUIRED' }); }
    finally { driver.prepare('INSERT INTO authorization_grants(grant_id,owner_principal_id,state,row_json) VALUES(?,?,?,?)')
      .run(saved.grant_id, saved.owner_principal_id, saved.state, saved.row_json); }
    await f.store.close(); f.store = await openStateStore(f.stateRoot, f.runtimeAuthority); channel = await publishInProcessChannel(f.store);
    assert.deepEqual((await f.store.createAuthorization(request, channel)).response, created.response);
    assert.equal(readAuthorizationGrant(driver, identityId)?.state, 'consumed');
  } finally { driver.close(); await disposeFixture(f); }
});
