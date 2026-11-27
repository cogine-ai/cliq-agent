// Negative original-StateStore and opaque-owner cases only. No test below
// manufactures a publication task, physical effect or successful receipt.
import assert from 'node:assert/strict';
import test from 'node:test';
import type { InvocationJournalEntry } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { preparePublicationInitialAmbiguitySettlement, preparePublicationPreparationSettlement, preparePublicationReceivedSettlement, preparePublicationReconciliationSettlement,
  preparePublicationSettlement } from './publication-settlement.js';
import { preparePublicationInvocationSettlement, preparePublicationReconciliationInvocationSettlement,
  settleValidatedInvocation } from './reducers/invocation.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';

test('received publication settlement cannot reconstruct an owner from a receipt, handoff or callback', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('forged received result must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'withReadSignal', { get() { assert.fail('forged received result must not reach CAS'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  const forged = Object.defineProperty({}, 'completion', { get() { assert.fail('forged received data must not be inspected'); } });
  await assert.rejects(preparePublicationReceivedSettlement(driver, artifacts, owner,
    { execution: {}, receivedResult: forged as never }), /genuine same-execution received publication result/);
  const accessor = Object.defineProperty({ receivedResult: forged }, 'execution', { enumerable: true,
    get() { assert.fail('received settlement input getters must not run'); } });
  await assert.rejects(preparePublicationReceivedSettlement(driver, artifacts, owner, accessor as never), /closed original received publication input/);
  for (const extra of [{ receiptRef: 'a'.repeat(64) }, { evidenceRef: 'a'.repeat(64) }, { native: {} }, { commit: () => assert.fail('caller callback') }])
    await assert.rejects(preparePublicationReceivedSettlement(driver, artifacts, owner,
      { execution: {}, receivedResult: forged, ...extra } as never), /closed original received publication input/);
  await assert.rejects(preparePublicationInvocationSettlement(driver, artifacts, owner, forged as never).settle(1),
    /exact original registered completion owner/);
  await assert.rejects(preparePublicationReconciliationInvocationSettlement(driver, artifacts, owner, forged as never).settle(1),
    /exact original registered reconciliation owner/);
  await assert.rejects(preparePublicationReconciliationSettlement(driver, artifacts, owner,
    { execution: {}, recoveryResult: forged as never }), /genuine same-execution publication inspection result/);
  await assert.rejects(preparePublicationReconciliationSettlement(driver, artifacts, owner,
    { execution: {}, recoveryResult: forged, evidenceRef: 'a'.repeat(64) } as never), /closed original publication inspection input/);
  await assert.rejects(preparePublicationInitialAmbiguitySettlement(driver, artifacts, owner, forged as never),
    /genuine same-owner publication initial ambiguity/);
  const hostileMaintenance = Object.defineProperty({}, 'kind', { get() { assert.fail('initial maintenance data cannot replace the genuine task brand'); } });
  for (const candidate of [hostileMaintenance, { kind: 'closed_maintenance', claim: {}, evidenceRef: 'a'.repeat(64),
    continuation: () => assert.fail('caller maintenance continuation') }])
    await assert.rejects(preparePublicationInitialAmbiguitySettlement(driver, artifacts, owner, candidate as never),
      /genuine same-owner publication initial ambiguity/);
});

test('publication settlement rejects structural owners and caller evidence before storage or accessors', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('forged owner must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('forged owner must not reach CAS'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  const forged = Object.defineProperty({}, 'native', { get() { assert.fail('forged owner must not expose a native handle'); } });
  await assert.rejects(preparePublicationSettlement(driver, artifacts, owner, { execution: {}, publicationOwner: forged as never }), /exact original invocation owner/);
  await assert.rejects(preparePublicationPreparationSettlement(driver, artifacts, owner,
    { execution: {}, publicationOwner: forged as never }), /exact original invocation owner/);
  await assert.rejects(preparePublicationInvocationSettlement(driver, artifacts, owner, forged as never).settle(1),
    /exact original registered completion owner/);
  const accessor = Object.defineProperty({ publicationOwner: forged }, 'execution', { enumerable: true,
    get() { assert.fail('closed settlement input must reject getters'); } });
  await assert.rejects(preparePublicationSettlement(driver, artifacts, owner, accessor as never), /closed original publication input/);
  await assert.rejects(preparePublicationSettlement(driver, artifacts, owner, { execution: {}, publicationOwner: forged,
    evidenceRef: 'a'.repeat(64) } as never), /closed original publication input/);
  await assert.rejects(preparePublicationPreparationSettlement(driver, artifacts, owner, accessor as never), /closed original publication input/);
  await assert.rejects(preparePublicationPreparationSettlement(driver, artifacts, owner, { execution: {}, publicationOwner: forged,
    errorRef: 'a'.repeat(64), consumed: { toolCalls: 0 } } as never), /closed original publication input/);
});

test('a callback and arbitrary ambiguity refs cannot settle a corrupt publication claim', async () => {
  const fixture = await createAgentFixture('publication-settlement-bypass');
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: 0, dispatchId: 'original-model-only' });
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const inert = await fixture.store.artifacts.publishCanonical({ inert: 'not a native birth, ambiguity or receipt' }, 'inert-test-data');
    // Present corrupt, schema-decodable retained data to the actual reducer.
    // These refs explicitly do not constitute genuine publication authority.
    const rows = held.driver.prepare('SELECT seq,entry_json FROM run_journal WHERE run_id=? ORDER BY seq')
      .all<{ seq: bigint; entry_json: string }>(fixture.runId);
    held.driver.exec('DROP TRIGGER run_journal_immutable_update');
    for (const row of rows) {
      const entry = JSON.parse(row.entry_json) as InvocationJournalEntry;
      const changed = { ...entry, opKind: 'publish', replayClass: 'reconcile',
        ...(entry.phase === 'dispatch_claimed' ? { evidenceRef: inert.ref, evidenceDigest: inert.ref } : {}) };
      held.driver.prepare('UPDATE run_journal SET op_kind=?,entry_json=? WHERE run_id=? AND seq=?')
        .run('publish', JSON.stringify(changed), fixture.runId, row.seq);
    }
    const before = fixture.store.getRun(fixture.runId);
    const journal = held.driver.prepare('SELECT entry_json FROM run_journal WHERE run_id=? ORDER BY seq').all(fixture.runId);
    let called = false;
    await assert.rejects(settleValidatedInvocation(held.driver, fixture.store.artifacts, held.owner,
      { runId: fixture.runId, expectedRunRevision: before.revision, opId: prepared.entry.opId, attempt: 0 },
      { phase: 'unknown', evidenceRef: inert.ref, evidenceDigest: inert.ref },
      async () => { called = true; return { metadata: [] }; }), { code: 'INVALID_REQUEST' });
    assert.equal(called, false);
    assert.deepEqual(fixture.store.getRun(fixture.runId), before);
    assert.deepEqual(held.driver.prepare('SELECT entry_json FROM run_journal WHERE run_id=? ORDER BY seq').all(fixture.runId), journal);
  } finally { await disposeFixture(fixture); }
});
