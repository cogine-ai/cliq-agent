// Real StateStore/CAS corruption and brand refusals only. These cases create
// no delivery authorization, native publication claim or installation proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import type { InvocationJournalEntry } from '../kernel/types.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { StateOwnerContext } from './state-owner.js';
import { advancePublicationPath, assertOwnedPublicationArtifacts, assertOwnedPublicationPath, claimPublicationInvocation, preparePublicationInvocation, preparePublicationMaintenance,
  readOwnedPublicationCompletion, readOwnedPublicationDispatchState, readOwnedPublicationPreparationClosure, retirePublicationPreparation } from './publication-invocation.js';
import { assertOwnedPublicationReconciliationSql, prepareOwnedPublicationReconciliation,
  readOwnedPublicationReconciliationResult, assertOwnedPublicationInitialAmbiguitySql, prepareOwnedPublicationInitialAmbiguity,
  readOwnedPublicationInitialAmbiguity, snapshotPublicationReconciliationPrefix, prepareOwnedPublicationMaintenanceAmbiguity,
  readOwnedPublicationReconciliationProgress, classifyOwnedPublicationReconciliationCompletion,
  readOwnedPublicationLateObservation, assertOwnedPublicationLateObservationSql, acceptOwnedPublicationLateObservationAudit,
  classifyPublicationObservationCompletion } from './publication-invocation.js';
import { claimValidatedInvocation, prepareInvocation } from './reducers/invocation.js';
import { prepareValidatedInvocation } from './reducers/invocation.js';

test('ordinary claim rejects a typed publish row instead of accepting its retained fields as authority', async () => {
  const fixture = await createAgentFixture('publication-ordinary-claim');
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision,
      leaseEpoch: fixture.leaseEpoch });
    const driver = (fixture.store as unknown as { driver: SqliteDriver }).driver;
    // Corrupt an actual retained row: this is deliberately NOT a publication
    // producer or permission fixture, and must never reach dispatch.
    // As in existing recovery-tampering regressions, disable only this test
    // database's update trigger to present corrupt retained input to the reader.
    driver.exec('DROP TRIGGER run_journal_immutable_update');
    const altered: InvocationJournalEntry = { ...prepared.entry, opKind: 'publish', replayClass: 'reconcile' };
    driver.prepare('UPDATE run_journal SET op_kind = ?, entry_json = ? WHERE run_id = ? AND seq = ?')
      .run('publish', JSON.stringify(altered), fixture.runId, BigInt(altered.seq));
    const before = driver.prepare('SELECT entry_json FROM run_journal WHERE run_id = ? ORDER BY seq').all(fixture.runId);
    await assert.rejects(fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: altered.opId, attempt: 0, dispatchId: 'must-not-dispatch' }), { code: 'INVALID_REQUEST' });
    const inert = await fixture.store.artifacts.publishCanonical({ format: 'cliq-publication-preparation-closure-v1',
      retirement: { kind: 'no_birth' } }, 'inert-test-data');
    // Registered bytes and a familiar label cannot refund an undispatched
    // publication: only its original joined owner supplies that fixed closure.
    await assert.rejects(fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      opId: altered.opId, attempt: 0, errorRef: inert.ref }), { code: 'INVALID_REQUEST' });
    assert.deepEqual(driver.prepare('SELECT entry_json FROM run_journal WHERE run_id = ? ORDER BY seq').all(fixture.runId), before);
    assert.deepEqual(fixture.store.getRun(fixture.runId), prepared.run);
  } finally { await disposeFixture(fixture); }
});

test('publication preparation, claim attachment and original path friend reject structural owners before storage or getters', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('structural authority must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('structural authority must not reach CAS'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  const hostile = Object.defineProperty({}, 'runId', { get() { assert.fail('must reject the task/execution brand first'); } });
  await assert.rejects(preparePublicationInvocation(driver, artifacts, owner, { execution: {}, task: {} as never,
    worker: hostile as never, workspaceRoot: hostile as never, expectedRunRevision: 1 }), /genuine same-owner in-flight/);
  await assert.rejects(preparePublicationMaintenance(driver, artifacts, owner, { execution: {}, task: {} as never,
    workspaceRoot: hostile as never, expectedRunRevision: 1 }), /genuine same-owner original task/);
  await assert.rejects(prepareValidatedInvocation(driver, artifacts, owner, { reservation: {
    modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } } as never), /ordinary invocation reservation must be nonzero/);
  const badInput = Object.defineProperty({ task: {}, worker: {}, workspaceRoot: {}, expectedRunRevision: 1 }, 'execution',
    { enumerable: true, get() { assert.fail('closed owning input must reject accessors'); } });
  await assert.rejects(preparePublicationInvocation(driver, artifacts, owner, badInput as never), /closed owning input/);
  await assert.rejects(preparePublicationInvocation(driver, artifacts, owner, { execution: {}, task: {} as never, worker: hostile as never,
    workspaceRoot: hostile as never, expectedRunRevision: 1, evidenceRef: 'a'.repeat(64) } as never), /closed owning input/);
  const maintenanceAccessor = Object.defineProperty({ task: {}, workspaceRoot: hostile, expectedRunRevision: 1 }, 'execution',
    { enumerable: true, get() { assert.fail('maintenance must reject getters before reading its owning task'); } });
  await assert.rejects(preparePublicationMaintenance(driver, artifacts, owner, maintenanceAccessor as never), /closed original task input/);
  for (const extra of [{ evidenceRef: 'a'.repeat(64) }, { creatorReceiptRef: 'a'.repeat(64) }, { consume() { assert.fail('caller authority callback'); } }])
    await assert.rejects(preparePublicationMaintenance(driver, artifacts, owner, { execution: {}, task: {} as never,
      workspaceRoot: hostile as never, expectedRunRevision: 1, ...extra } as never), /closed original task input/);
  for (const token of [{}, Object.defineProperty({}, 'native', { get() { assert.fail('must not read a forged native handle'); } })]) {
    await assert.rejects(retirePublicationPreparation(driver, owner, {}, token as never), /exact original invocation owner/);
    assert.throws(() => readOwnedPublicationPreparationClosure(driver, owner, {}, token as never), /exact original invocation owner/);
    assert.throws(() => readOwnedPublicationDispatchState(driver, owner, {}, token), /exact original invocation owner/);
    assert.throws(() => assertOwnedPublicationArtifacts(driver, owner, {}, token as never, artifacts), /exact original invocation owner/);
    assert.throws(() => assertOwnedPublicationPath(driver, owner, {}, token), /exact original invocation owner/);
    assert.throws(() => claimPublicationInvocation(driver, owner, token as never), /exact original invocation owner/);
    assert.throws(() => advancePublicationPath(driver, owner, {}, token as never), /exact original invocation owner/);
    assert.throws(() => readOwnedPublicationCompletion(driver, owner, {}, token), /exact original invocation owner/);
    await assert.rejects(claimValidatedInvocation(driver, artifacts, owner, { runId: 'data-only', expectedRunRevision: 1,
      leaseEpoch: 1, opId: 'data-only', attempt: 0, dispatchId: 'data-only' }, undefined, token as never), /exact original invocation owner/);
  }
  await assert.rejects(prepareInvocation(driver, artifacts, owner, { opKind: 'publish' } as never), { code: 'INVALID_REQUEST' });
});

test('publication inspection and known-result friends reject structural tasks and results before any storage or getters', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('a structural probe must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('a structural probe must not reach CAS'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  const hostile = Object.defineProperty({}, 'runId', { get() { assert.fail('must reject the genuine task/result brand first'); } });
  await assert.rejects(prepareOwnedPublicationReconciliation(driver, artifacts, owner, {}, hostile as never), /genuine same-owner original task/);
  await assert.rejects(readOwnedPublicationReconciliationResult(driver, artifacts, owner, {}, hostile as never), /genuine same-execution publication inspection result/);
  assert.throws(() => assertOwnedPublicationReconciliationSql(driver, artifacts, owner, {}, hostile as never, driver),
    /genuine same-execution publication inspection result/);
});

test('publication progress transfer rejects structural sources before task, storage or getters', () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('a structural progress source must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('a structural progress source must not reach CAS'); } }) as ArtifactCatalog;
  const hostile = Object.defineProperty({}, 'run', { get() { assert.fail('must reject the progress source brand before getters'); } });
  assert.throws(() => readOwnedPublicationReconciliationProgress(driver, artifacts, {} as StateOwnerContext, {}, hostile as never, hostile as never),
    /genuine same-task publication progress transfer/);
});

test('late publication audit cannot be supplied as data or relabelled as an in-deadline result', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('a structural late source must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('a structural late source must not reach CAS'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  for (const token of [{}, { kind: 'late_audit', evidenceRef: 'a'.repeat(64) },
    Object.defineProperty({}, 'evidence', { get() { assert.fail('must reject the private source before getters'); } })]) {
    assert.throws(() => classifyOwnedPublicationReconciliationCompletion(driver, artifacts, owner, {}, token as never),
      /genuine same-execution publication completion/);
    await assert.rejects(readOwnedPublicationLateObservation(driver, artifacts, owner, {}, token as never),
      /genuine same-execution late publication observation/);
    assert.throws(() => assertOwnedPublicationLateObservationSql(driver, artifacts, owner, {}, token as never, driver),
      /genuine same-execution late publication observation/);
    assert.throws(() => acceptOwnedPublicationLateObservationAudit(driver, artifacts, owner, {}, token as never, token as never),
      /genuine same-execution late publication observation/);
    await assert.rejects(readOwnedPublicationReconciliationResult(driver, artifacts, owner, {}, token as never),
      /genuine same-execution publication inspection result/);
  }
});

test('publication timing uses actual completion, not an earlier path read, without granting probe authority', () => {
  const at = (seconds: number) => `2026-10-19T00:00:${String(seconds).padStart(2, '0')}.000Z`;
  assert.equal(classifyPublicationObservationCompletion(at(0), at(30), at(29), at(29)), 'within_probe');
  assert.equal(classifyPublicationObservationCompletion(at(0), at(30), at(29), at(30)), 'within_probe');
  assert.equal(classifyPublicationObservationCompletion(at(0), at(30), at(29), at(31)), 'late_audit');
  assert.equal(classifyPublicationObservationCompletion(at(0), at(30), at(31), at(31)), 'late_audit');
  for (const times of [[at(1), at(30), at(0), at(31)], [at(0), at(30), at(31), at(29)],
    [at(30), at(0), at(31), at(31)], [at(0), at(30), 'not-a-time', at(31)]])
    assert.throws(() => classifyPublicationObservationCompletion(...times as [string, string, string, string]));
});

test('initial publication ambiguity requires actual native worker death before input, storage or artifact access', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('structural worker death must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('structural worker death must not reach CAS'); } }) as ArtifactCatalog;
  const input = Object.defineProperty({}, 'runId', { get() { assert.fail('native worker death brand must precede input access'); } });
  const owner = {} as StateOwnerContext;
  await assert.rejects(prepareOwnedPublicationInitialAmbiguity(driver, artifacts, owner, input as never, {} as never),
    /actual native containment observation/);
  await assert.rejects(prepareOwnedPublicationMaintenanceAmbiguity(driver, artifacts, owner, {}, input as never),
    /genuine same-owner original task/);
  await assert.rejects(readOwnedPublicationInitialAmbiguity(driver, artifacts, owner, input as never),
    /genuine same-owner publication initial ambiguity/);
  assert.throws(() => assertOwnedPublicationInitialAmbiguitySql(driver, artifacts, owner, input as never, driver),
    /genuine same-owner publication initial ambiguity/);
});

test('publication reconciliation copies retained data without exporting policy evaluator functions or mutable private maps', () => {
  // Deliberately incomplete pure data: this exercises only copying. It is not
  // a Delivery source, retained full-R graph, native owner or permission.
  const evaluator = { evaluate() { assert.fail('a data projection cannot evaluate policy'); } };
  const authorization = { evaluator, context: { planRef: 'original-plan' } };
  const entry = { authorization, history: [{ seq: 1 }], operation: { path: 'file' } };
  const original = { admission: { run: { id: 'data-only' } }, authorization, entries: new Map([['operation', entry]]),
    forward: [entry], abort: [], abortResults: [{ operation: { path: 'directory' }, claimed: entry }], resultRefs: new Set(['original-result']) };
  const copied = snapshotPublicationReconciliationPrefix(original as never);
  assert.equal(Object.hasOwn(copied.authorization!, 'evaluator'), false);
  assert.equal(Object.hasOwn(copied.entries.get('operation')!.authorization, 'evaluator'), false);
  assert.equal(Object.hasOwn(copied.forward[0]!.authorization, 'evaluator'), false);
  assert.equal(Object.hasOwn(copied.abortResults[0]!.claimed!.authorization, 'evaluator'), false);
  copied.entries.clear(); copied.resultRefs.clear();
  assert.equal(original.entries.size, 1); assert.equal(original.resultRefs.size, 1);
  assert.equal(original.authorization.evaluator, evaluator);
  assert.throws(() => { copied.forward[0]!.operation.path = 'changed'; }, TypeError);
  assert.equal(original.forward[0]!.operation.path, 'file');
});

test('ordinary publication completion and ambiguity cannot settle a corrupt typed row using arbitrary artifact refs', async () => {
  const fixture = await createAgentFixture('publication-ordinary-settlement');
  try {
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: 0, dispatchId: 'original-model-only' });
    const driver = (fixture.store as unknown as { driver: SqliteDriver }).driver;
    const data = await fixture.store.artifacts.publishCanonical({ untrusted: 'not native evidence' }, 'inert-test-data');
    const rows = driver.prepare('SELECT seq,entry_json FROM run_journal WHERE run_id=? ORDER BY seq')
      .all<{ seq: bigint; entry_json: string }>(fixture.runId);
    driver.exec('DROP TRIGGER run_journal_immutable_update');
    for (const row of rows) {
      const original = JSON.parse(row.entry_json) as InvocationJournalEntry;
      driver.prepare('UPDATE run_journal SET op_kind=?,entry_json=? WHERE run_id=? AND seq=?')
        .run('publish', JSON.stringify({ ...original, opKind: 'publish', replayClass: 'reconcile',
          // Keep this corrupt row schema-decodable so the public settlement
          // gate itself is exercised. These inert bytes are NOT a birth proof.
          ...(original.phase === 'dispatch_claimed' ? { evidenceRef: data.ref, evidenceDigest: data.ref } : {}) }), fixture.runId, row.seq);
    }
    const before = driver.prepare('SELECT entry_json FROM run_journal WHERE run_id=? ORDER BY seq').all(fixture.runId);
    const input = { runId: fixture.runId, opId: prepared.entry.opId, attempt: 0, expectedRunRevision: prepared.run.revision };
    await assert.rejects(fixture.store.completeInvocation({ ...input, resultRef: data.ref,
      consumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } }), { code: 'INVALID_REQUEST' });
    await assert.rejects(fixture.store.markInvocationUnknown({ ...input, evidenceRef: data.ref, evidenceDigest: data.ref }), { code: 'INVALID_REQUEST' });
    assert.deepEqual(driver.prepare('SELECT entry_json FROM run_journal WHERE run_id=? ORDER BY seq').all(fixture.runId), before);
    assert.deepEqual(fixture.store.getRun(fixture.runId), prepared.run);
  } finally { await disposeFixture(fixture); }
});
