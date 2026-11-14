import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeCredentialAuthorityRecord, decodeEndpointAuthorityRecord, type EndpointCredentialGrantBinding,
  type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { digestOmitting } from '../kernel/identity.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { readCredentialRedemptionFailureCause } from './credential-redemption-failure.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
type Prepared = Awaited<ReturnType<Fixture['agent']['prepareModel']>>;
const revision = (fixture: Fixture) => fixture.store.getRun(fixture.runId).revision;
const prepare = (fixture: Fixture) => fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
const driverOf = (fixture: Fixture): SqliteDriver =>
  openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));

async function credentialRefusal(fixture: Fixture, prepared: Prepared,
  failure: 'revoked' | 'expired' | 'credential_binding_changed' = 'revoked') {
  const credentialGrantRef = fixture.authority.assembly.provider.credentialGrantRefs[0]!;
  const binding = await fixture.store.artifacts.readCanonical<EndpointCredentialGrantBinding>(credentialGrantRef);
  const endpoint = await fixture.store.artifacts.readCanonical<EndpointRegistrationV1>(binding.endpointRegistrationRef);
  const observedAt = sampleCanonicalNow(), { bindingDigest: _, ...recordBody } = binding;
  const latest = { ...recordBody, authorityRevision: binding.authorityRevision + 1,
    ...(['expired', 'credential_binding_changed'].includes(failure) ? { secretGeneration: binding.secretGeneration + 1 } : {}),
    ...(failure === 'expired' ? { expiresAt: observedAt } : {}),
    platformItem: { kind: 'linux_secret_service', schema: 'org.freedesktop.Secret.Generic', collection: 'default', itemId: 'offline-test-item' },
    state: failure === 'revoked' ? 'revoked' : 'active',
    ...(failure === 'revoked' ? { revokedAt: observedAt, revokedByRequestId: uuidv7(), revokedByRequestDigest: canonicalSha256('offline-revoke') } : {}),
    recordDigest: '' };
  latest.recordDigest = digestOmitting(latest, 'recordDigest');
  const record = decodeCredentialAuthorityRecord(latest);
  const endpointRecord = decodeEndpointAuthorityRecord({ schemaVersion: 1, endpointRegistrationId: endpoint.endpointRegistrationId,
    authorityRevision: 1, ownerPrincipalId: endpoint.ownerPrincipalId, sourceRequestId: uuidv7(), sourceRequestDigest: canonicalSha256('offline-endpoint'),
    registration: endpoint, expectedRegistrationArtifactRef: binding.endpointRegistrationRef,
    createdAt: endpoint.createdAt, state: 'active', recordDigest: '' });
  endpointRecord.recordDigest = digestOmitting(endpointRecord, 'recordDigest');
  const refusal = { schemaVersion: 1, format: 'cliq-credential-redemption-refusal-v1', runId: fixture.runId,
    opId: prepared.entry.opId, attempt: prepared.entry.attempt, requestRef: prepared.entry.requestRef,
    credentialGrantRef, endpointRegistrationRef: binding.endpointRegistrationRef,
    credentialAuthorityRecord: record, endpointAuthorityRecord: decodeEndpointAuthorityRecord(endpointRecord),
    observedAt, refusalDigest: '' };
  refusal.refusalDigest = digestOmitting(refusal, 'refusalDigest');
  return { refusal, binding, observedAt };
}

for (const failure of ['revoked', 'expired', 'credential_binding_changed'] as const) {
  test(`readCredentialRedemptionFailureCause reproduces a settled ${failure} refusal without a claim`, async () => {
    const fixture = await createAgentFixture(`credential-cause-${failure}`, undefined, { mode: 'plan' });
    try {
      const prepared = await prepare(fixture);
      const { refusal, binding, observedAt } = await credentialRefusal(fixture, prepared, failure);
      const artifact = await fixture.store.artifacts.publishCanonical(refusal, 'cliq-invocation-error-v1');
      await fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
        opId: prepared.entry.opId, attempt: prepared.entry.attempt, errorRef: artifact.ref });
      const cut = await fixture.store.readRecoveryClosure(fixture.runId);
      const driver = driverOf(fixture);
      try {
      const cause = await readCredentialRedemptionFailureCause(driver, fixture.store.artifacts, cut, observedAt);
      assert.equal(cause?.failureKind, 'credential_redemption_failed');
      assert.equal(cause?.failureCode, failure);
      assert.equal(cause?.credentialGrantRef, refusal.credentialGrantRef);
      assert.equal(cause?.credentialGrantDigest, binding.bindingDigest);
      assert.equal(cause?.failingOpId, prepared.entry.opId);
      } finally { driver.close(); }
    } finally { await disposeFixture(fixture); }
  });
}

test('readCredentialRedemptionFailureCause stays absent when the Run still holds budget', async () => {
  const fixture = await createAgentFixture('credential-cause-budget', undefined, { mode: 'plan' });
  try {
    const prepared = await prepare(fixture);
    const { refusal, observedAt } = await credentialRefusal(fixture, prepared);
    const artifact = await fixture.store.artifacts.publishCanonical(refusal, 'cliq-invocation-error-v1');
    await fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
      opId: prepared.entry.opId, attempt: prepared.entry.attempt, errorRef: artifact.ref });
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    cut.run = { ...cut.run, budgetReserved: { modelTokens: 1, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
    const driver = driverOf(fixture);
    try {
      assert.equal(await readCredentialRedemptionFailureCause(driver, fixture.store.artifacts, cut, observedAt), undefined);
    } finally { driver.close(); }
  } finally { await disposeFixture(fixture); }
});

test('readCredentialRedemptionFailureCause rejects a refusal that rewrites frozen authority revision', async () => {
  const fixture = await createAgentFixture('credential-cause-tamper', undefined, { mode: 'plan' });
  try {
    const prepared = await prepare(fixture);
    const { refusal, observedAt } = await credentialRefusal(fixture, prepared, 'credential_binding_changed');
    const tampered = { ...refusal, credentialAuthorityRecord: { ...refusal.credentialAuthorityRecord, authorityRevision: refusal.credentialAuthorityRecord.authorityRevision - 1 } };
    tampered.refusalDigest = digestOmitting(tampered, 'refusalDigest');
    const artifact = await fixture.store.artifacts.publishCanonical(tampered, 'cliq-invocation-error-v1');
    await fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
      opId: prepared.entry.opId, attempt: prepared.entry.attempt, errorRef: artifact.ref });
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const driver = driverOf(fixture);
    try {
      await assert.rejects(readCredentialRedemptionFailureCause(driver, fixture.store.artifacts, cut, observedAt), TypeError);
    } finally { driver.close(); }
  } finally { await disposeFixture(fixture); }
});