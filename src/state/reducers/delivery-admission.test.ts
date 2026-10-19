// Existing real StateStore seam; no fixture-created successful verifier,
// delivery Run, permission grant or native publication proof.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../../kernel/canonical.js';
import type { HeldInstalledRuntime } from '../installed-runtime.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import type { StateOwnerContext } from '../state-owner.js';
import type { VerifiedDeliverySource } from '../delivery-source-authority.js';
import { prepareInstalledDelivery, admitInstalledDelivery, readDeliveryRunAdmission } from './delivery-admission.js';
import { createAgentFixture } from '../testing/agent-fixtures.js';
import { admissionKey, disposeFixture, uuidv7 } from '../testing/fixtures.js';

test('delivery preparation rejects a structural source before inspecting it or opening mutable workspace', async () => {
  const fixture = await createAgentFixture('delivery-prepare-forgery', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    let inspected = false;
    const forged = Object.defineProperty({}, 'run', { get() { inspected = true; throw new Error('not source authority'); } });
    const core = { protocolVersion: 1, method: 'run.apply', requestId: uuidv7(), admissionKey: admissionKey('delivery-forgery'),
      sourceRunId: fixture.runId, expectedRunResultRef: 'a'.repeat(64) };
    await assert.rejects(prepareInstalledDelivery({ ...held, artifacts: fixture.store.artifacts,
      selected: undefined as unknown as HeldInstalledRuntime, request: { ...core, requestDigest: canonicalSha256(core) },
      identity: { principalId: fixture.principalId, channelIdentityRef: fixture.channelIdentityRef,
        channelIdentityDigest: (await fixture.store.artifacts.readCanonical<{ identityDigest: string }>(fixture.channelIdentityRef)).identityDigest },
      source: forged as VerifiedDeliverySource, capture: undefined as never }), /verified delivery source/);
    assert.equal(inspected, false);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('a structural prepared delivery cannot authorize an admission or execute its getters', async () => {
  let observed = false;
  const forged = Object.defineProperty({}, 'run', { get() { observed = true; throw new Error('not preparation authority'); } });
  await assert.rejects(admitInstalledDelivery(undefined as unknown as SqliteDriver, undefined as never,
    undefined as unknown as StateOwnerContext, forged as never, undefined as never), /prepared delivery/);
  assert.equal(observed, false);
});

test('delivery history cannot relabel an existing real agent admission or borrow its future result', async () => {
  const fixture = await createAgentFixture('delivery-history-kind', undefined, { mode: 'plan' });
  try {
    const held = fixture.store as unknown as { driver: SqliteDriver };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(readDeliveryRunAdmission(held.driver, fixture.store.artifacts, fixture.runId), { code: 'ARTIFACT_MISMATCH' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
