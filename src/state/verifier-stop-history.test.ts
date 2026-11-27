// Retained-data readers use the actual isolated StateStore/CAS. These cases
// establish absence/refusal, not native verifier execution or physical death.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { readVerifierFailureCause, readVerifierIntegrityCause, validateVerifierStoppedHistory } from './verifier-stop-history.js';
import { readAgentStop } from './stop-recovery.js';
import { publishInProcessChannel } from './store.js';
import { uuidv7 } from './testing/fixtures.js';

test('a Run with no verifier result has no verification or integrity stop authority', async () => {
  const fixture = await createAgentFixture('verifier-stop-absence', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(await validateVerifierStoppedHistory(driver, fixture.store.artifacts, cut), new Set());
    assert.equal(await readVerifierIntegrityCause(driver, fixture.store.artifacts, cut, cut.run.updatedAt), undefined);
    assert.equal(await readVerifierFailureCause(driver, fixture.store.artifacts, cut, cut.run.updatedAt), undefined);
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('a winning cancellation cannot hide an unowned historical verifier denial', async () => {
  const fixture = await createAgentFixture('verifier-denial-history-refusal', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await fixture.agent.cancelRun({ requestId: uuidv7(), expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      ...await publishInProcessChannel(fixture.store) });
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    // Explicit read-only candidate data is not installed into items/Journal.
    const item = { schemaVersion: 1, itemId: 'unowned-denial', runId: fixture.runId, kind: 'policy_decision', subjectKind: 'verifier_launch',
      opId: 'not-a-planned-operation', principalId: fixture.principalId, decisionRef: 'a'.repeat(64), policyChannelEvidenceRef: 'a'.repeat(64),
      policyChannelEvidenceDigest: 'b'.repeat(64), createdAt: cut.run.updatedAt, decisionSource: 'direct_policy', decision: 'deny',
      denialOutcome: { kind: 'stop_intent', subjectKind: 'verifier_launch', stopIntentRef: cut.run.stopIntentRef } };
    const artifact = await fixture.store.artifacts.publishCanonical(item, 'cliq-policy-decision-item-v1');
    const changed = { ...cut, items: [...cut.items, { schemaVersion: 1 as const, itemId: item.itemId, itemSeq: cut.items.length + 1,
      payloadRef: artifact.ref, payloadDigest: artifact.ref, createdAt: item.createdAt }] };
    await assert.rejects(readAgentStop(driver, fixture.store.artifacts, changed), /verifier denial|policy denial/);
  } finally { driver.close(); await disposeFixture(fixture); }
});
