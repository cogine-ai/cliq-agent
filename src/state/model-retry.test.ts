import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { ModelRetryPendingError } from './errors.js';
import { AgentHandoffPendingError } from './reducers/agent.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, disposeFixture } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
type Prepared = Awaited<ReturnType<Fixture['agent']['prepareModel']>>;
const prepare = (fixture: Fixture) => fixture.agent.prepareModel({
  expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch
});
const claim = (fixture: Fixture, prepared: Prepared) => fixture.store.claimInvocationDispatch({
  runId: fixture.runId, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch,
  opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: `dispatch:${prepared.entry.opId}:${prepared.entry.attempt}`
});
async function failBeforeDispatch(fixture: Fixture, prepared: Prepared) {
  const error = await fixture.store.artifacts.publishCanonical({ reason: 'offline pre-dispatch failure' }, 'cliq-invocation-error-v1');
  return fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, opId: prepared.entry.opId,
    attempt: prepared.entry.attempt, expectedRunRevision: fixture.store.getRun(fixture.runId).revision, errorRef: error.ref });
}
async function unknown(fixture: Fixture, prepared: Prepared) {
  // Existing M2 settlement seam, not a broker release/revocation proof or live transport fixture.
  const evidence = await fixture.store.artifacts.publishCanonical({ reason: 'offline ambiguous model fixture' }, 'cliq-invocation-ambiguity-evidence-v1');
  return fixture.store.markInvocationUnknown({ runId: fixture.runId, opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: fixture.store.getRun(fixture.runId).revision, evidenceRef: evidence.ref, evidenceDigest: evidence.ref });
}
function response(fixture: Fixture, prepared: Prepared, status = 200) {
  const reader = fixture.agent.model.start(prepared.prepared, { status, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify(status === 200
    ? { id: 'response', object: 'response', status: 'completed', model: 'model-1', output: [
      { type: 'message', id: 'msg', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'done', annotations: [] }] }
    ] }
    : { error: { message: 'provider rejected this request' } })));
  return reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput);
}

test('pre-dispatch replacements are free, contiguous and do not consume the three dispatches', async () => {
  const fixture = await createAgentFixture('model-pre-dispatch-retry');
  try {
    for (let attempt = 0; attempt < 4; attempt++) {
      const prepared = await prepare(fixture);
      assert.equal(prepared.entry.attempt, attempt);
      assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
        { kind: 'pending', attempt, phase: 'prepared', dispatchedAttempts: 0 });
      const pending = await fixture.store.readRecoveryClosure(fixture.runId);
      await assert.rejects(prepare(fixture), { code: 'STATE_TRANSITION_INVALID' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), pending);
      const failed = await failBeforeDispatch(fixture, prepared);
      assert.deepEqual(failed.run.budgetConsumed, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 });
      assert.deepEqual(failed.run.budgetReserved, failed.run.budgetConsumed);
      assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
        { kind: 'ready', nextAttempt: attempt + 1, dispatchedAttempts: 0 });
    }
    const prepared = await prepare(fixture);
    await claim(fixture, prepared);
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
      { kind: 'pending', attempt: 4, phase: 'dispatch_claimed', dispatchedAttempts: 1 });
    await assert.rejects(claim(fixture, prepared), { code: 'STATE_TRANSITION_INVALID' });
    await assert.rejects(prepare(fixture), { code: 'STATE_TRANSITION_INVALID' });
  } finally { await disposeFixture(fixture); }
});

test('unknown attempts retain full charges, exact backoff, stable bytes and an exhaustion handoff', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-retry-backoff');
  try {
    const original = await prepare(fixture);
    await claim(fixture, original);
    const first = await unknown(fixture, original);
    assert.deepEqual(first.settlement.consumed, original.entry.budgetDelta);
    const notBefore = new Date(now + 500).toISOString();
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
      { kind: 'backoff', nextAttempt: 1, dispatchedAttempts: 1, notBefore });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    now += 499;
    await assert.rejects(prepare(fixture), error => error instanceof ModelRetryPendingError && error.notBefore === notBefore && error.nextAttempt === 1);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    now++;
    const race = await Promise.allSettled([prepare(fixture), prepare(fixture)]);
    const winners = race.filter(result => result.status === 'fulfilled');
    assert.equal(winners.length, 1);
    assert.equal(race.filter(result => result.status === 'rejected' && result.reason.code === 'REVISION_CONFLICT').length, 1);
    const replacement = winners[0]!.value;
    assert.equal(replacement.entry.attempt, 1);
    assert.equal(replacement.entry.opId, original.entry.opId);
    assert.notEqual(replacement.entry.requestRef, original.entry.requestRef);
    assert.deepEqual(replacement.prepared.outbound, original.prepared.outbound);
    assert.deepEqual(replacement.prepared.request.reservation, original.prepared.request.reservation);

    // Failing before a second dispatch must not restart the first dispatch's delay.
    now += 100;
    const failed = await failBeforeDispatch(fixture, replacement);
    assert.deepEqual(failed.run.budgetConsumed, first.run.budgetConsumed);
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
      { kind: 'ready', nextAttempt: 2, dispatchedAttempts: 1 });
    const second = await prepare(fixture);
    await claim(fixture, second);
    await unknown(fixture, second);
    now += 1999;
    await assert.rejects(prepare(fixture), error => error instanceof ModelRetryPendingError && error.nextAttempt === 3 && error.notBefore === new Date(now + 1).toISOString());
    now++;
    const third = await prepare(fixture);
    assert.equal(third.entry.attempt, 3);
    assert.deepEqual(third.prepared.outbound, original.prepared.outbound);
    await claim(fixture, third);
    const last = await unknown(fixture, third);
    assert.deepEqual(last.run.budgetConsumed, { modelTokens: original.entry.budgetDelta.modelTokens * 3,
      costMicros: original.entry.budgetDelta.costMicros * 3, toolCalls: 0, repairAttempts: 0 });
    assert.deepEqual(last.run.budgetReserved, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 });
    const exhausted = await fixture.agent.readModelAttempt();
    assert.equal(exhausted?.disposition, 'stop_required');
    assert.deepEqual(exhausted?.retry, { kind: 'exhausted', attempt: 3, dispatchedAttempts: 3, evidenceRef: last.entry.evidenceRef });
    assert.ok(Object.isFrozen(exhausted?.retry));
    const terminal = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(prepare(fixture), error => error instanceof AgentHandoffPendingError && error.reason === 'model_retry_exhausted' &&
      error.disposition === 'stop_required' && error.evidenceRef === last.entry.evidenceRef);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), terminal);
    assert.equal(terminal.run.status, 'running'); // Stop/drain is the owner's responsibility, not this gate's.
    assert.deepEqual(terminal.journal.filter(row => row.phase === 'dispatch_claimed').map(row => row.attempt), [0, 2, 3]);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry, exhausted?.retry);
  } finally { await disposeFixture(fixture); }
});

test('retry reservation and Journal roll back together, and old model results cannot replace a newer attempt', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-retry-atomicity');
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const original = await prepare(fixture);
    await claim(fixture, original);
    const late = response(fixture, original);
    await unknown(fixture, original);
    now += 500;
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec(`CREATE TRIGGER fail_model_retry BEFORE INSERT ON run_journal WHEN NEW.phase = 'prepared'
      BEGIN SELECT RAISE(ABORT, 'injected model retry failure'); END`);
    await assert.rejects(prepare(fixture), /injected model retry failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_model_retry');
    const replacement = await prepare(fixture);
    const pending = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.completeModel({ opId: original.entry.opId, attempt: 0,
      expectedRunRevision: pending.run.revision, result: late }), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), pending);
    await claim(fixture, replacement);
    const result = response(fixture, replacement);
    const completed = await fixture.agent.completeModel({ opId: replacement.entry.opId, attempt: 1,
      expectedRunRevision: replacement.run.revision, result });
    assert.equal(completed.disposition, 'candidate_required');
    assert.equal(completed.run.budgetConsumed.modelTokens, original.entry.budgetDelta.modelTokens * 2);
    assert.equal((await fixture.agent.readModelAttempt())?.retry.kind, 'completed');
    await assert.rejects(prepare(fixture), error => error instanceof AgentHandoffPendingError && error.disposition === 'candidate_required');
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('received provider rejections stay completed observations, never transport retries', async () => {
  const fixture = await createAgentFixture('model-rejected-not-retry');
  try {
    const prepared = await prepare(fixture);
    await claim(fixture, prepared);
    const result = response(fixture, prepared, 429);
    assert.equal(result.kind, 'unusable');
    const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: prepared.run.revision, result });
    assert.equal(completed.entry.phase, 'completed');
    assert.deepEqual(completed.settlement.consumed, prepared.entry.budgetDelta);
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
      { kind: 'completed', attempt: 0, dispatchedAttempts: 1, resultRef: completed.entry.resultRef });
    await assert.rejects(prepare(fixture), error => error instanceof AgentHandoffPendingError && error.disposition === 'stop_required');
  } finally { await disposeFixture(fixture); }
});

test('a retry needs new available budget even when its original outcome is unknown', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-retry-budget', { modelTokens: 40_960 });
  try {
    const original = await prepare(fixture);
    await claim(fixture, original);
    await unknown(fixture, original);
    now += 500;
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal((await fixture.agent.readModelAttempt())?.retry.kind, 'ready');
    await assert.rejects(prepare(fixture), { code: 'BUDGET_EXHAUSTED' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('recovery and shared model claim reject a bypassed backoff or substituted retry body', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-retry-corruption');
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const original = await prepare(fixture);
    await claim(fixture, original);
    now += 100;
    const settled = await unknown(fixture, original);
    now += 500;
    const replacement = await prepare(fixture);
    const retained = await fixture.store.readRecoveryClosure(fixture.runId);
    // Deliberate corruption of this disposable database; no production writer can update Journal rows.
    fault.exec('DROP TRIGGER run_journal_immutable_update');
    const rewrite = (entry: typeof replacement.entry) => fault.prepare('UPDATE run_journal SET entry_json = ? WHERE run_id = ? AND seq = ?')
      .run(JSON.stringify(entry), fixture.runId, BigInt(entry.seq));
    // The row remains ordered and its real settlement artifact is unchanged: only their binding catches this.
    rewrite({ ...settled.entry, timestamp: new Date(Date.parse(settled.entry.timestamp) - 100).toISOString() });
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(prepare(fixture), /retry clock differs/);
    await assert.rejects(claim(fixture, replacement), /retry clock differs/);
    rewrite(settled.entry);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), retained);
    rewrite({ ...replacement.entry, timestamp: new Date(now - 1).toISOString() });
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(claim(fixture, replacement), error => (error as Error).cause instanceof TypeError && /backoff/.test(String((error as Error).cause)));
    rewrite(replacement.entry);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), retained);

    const body = await fixture.store.artifacts.publishBytes(Buffer.alloc(replacement.prepared.request.bodyByteCount, 32), 'application/json', 'cliq-model-request-body-v1');
    const request = { ...replacement.prepared.request, bodyBytesRef: body.ref };
    request.requestDigest = digestOmitting(request, 'requestDigest');
    const artifact = await fixture.store.artifacts.publishCanonical(request, request.format);
    rewrite({ ...replacement.entry, requestRef: artifact.ref });
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(claim(fixture, replacement), error => (error as Error).cause instanceof TypeError && /original request/.test(String((error as Error).cause)));
    rewrite(replacement.entry);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), retained);
    await claim(fixture, replacement);
  } finally { fault.close(); await disposeFixture(fixture); }
});

for (const gate of ['prepare', 'claim'] as const) test(`model ${gate} rejects a changed intermediate retry even when the first and latest requests match`, async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture(`model-retry-intermediate-${gate}`);
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const original = await prepare(fixture);
    await claim(fixture, original);
    await unknown(fixture, original);
    now += 500;
    const middle = await prepare(fixture);
    await claim(fixture, middle);
    await unknown(fixture, middle);
    now += 2000;
    const current = gate === 'claim' ? await prepare(fixture) : undefined;
    if (current) assert.deepEqual(current.prepared.outbound, original.prepared.outbound);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);

    // Keep the middle attempt internally consistent, including a valid rehashed body/request and all phase refs.
    // Only comparing the first and latest requests misses this R0 -> R1 -> R0 history.
    const originalBytes = Buffer.from(middle.prepared.outbound.bodyBytes);
    const changedBytes = Buffer.from(originalBytes.toString('utf8').replace('Use tools carefully.', 'Use tools precisely.'));
    assert.notDeepEqual(changedBytes, originalBytes);
    assert.equal(changedBytes.byteLength, originalBytes.byteLength);
    const body = await fixture.store.artifacts.publishBytes(changedBytes, 'application/json', 'cliq-model-request-body-v1');
    const request = { ...middle.prepared.request, bodyBytesRef: body.ref };
    request.requestDigest = digestOmitting(request, 'requestDigest');
    const artifact = await fixture.store.artifacts.publishCanonical(request, request.format);
    // Deliberate corruption of this disposable database; production Journal rows are append-only.
    fault.exec('DROP TRIGGER run_journal_immutable_update');
    const rewrite = (requestRef: string) => fault.prepare(`UPDATE run_journal SET entry_json = json_set(entry_json, '$.requestRef', ?)
      WHERE run_id = ? AND op_id = ? AND attempt = ?`).run(requestRef, fixture.runId, middle.entry.opId, BigInt(middle.entry.attempt));
    rewrite(artifact.ref);
    const readJournal = () => fault.prepare('SELECT entry_json FROM run_journal WHERE run_id = ? ORDER BY seq').all(fixture.runId);
    const corruptJournal = readJournal();
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), /original request bytes or authority/);
    await assert.rejects(current ? claim(fixture, current) : prepare(fixture),
      { code: 'RECOVERY_REQUIRED', message: 'model retry changes its original request bytes or authority' });
    assert.deepEqual(readJournal(), corruptJournal);
    assert.deepEqual(fixture.store.getRun(fixture.runId), before.run);
    rewrite(middle.entry.requestRef);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const next = current ?? await prepare(fixture);
    await claim(fixture, next);
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
      { kind: 'pending', attempt: 2, phase: 'dispatch_claimed', dispatchedAttempts: 3 });
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('model claim rejects a null original request instead of resetting retry authority', async () => {
  const fixture = await createAgentFixture('model-retry-null-original');
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const original = await prepare(fixture);
    await failBeforeDispatch(fixture, original);
    const current = await prepare(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const invalid = await fixture.store.artifacts.publishCanonical(null, 'cliq-model-request-v1');
    // Canonical CAS bytes are not proof of a valid request shape. Corrupt all original attempt refs together.
    fault.exec('DROP TRIGGER run_journal_immutable_update');
    const rewrite = (requestRef: string) => fault.prepare(`UPDATE run_journal SET entry_json = json_set(entry_json, '$.requestRef', ?)
      WHERE run_id = ? AND op_id = ? AND attempt = 0`).run(requestRef, fixture.runId, original.entry.opId);
    rewrite(invalid.ref);
    const readJournal = () => fault.prepare('SELECT entry_json FROM run_journal WHERE run_id = ? ORDER BY seq').all(fixture.runId);
    const corruptJournal = readJournal();
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(claim(fixture, current), { code: 'RECOVERY_REQUIRED' });
    assert.deepEqual(readJournal(), corruptJournal);
    assert.deepEqual(fixture.store.getRun(fixture.runId), before.run);
    rewrite(original.entry.requestRef);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await claim(fixture, current);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('reopening during backoff derives readiness from settlement and keeps the request across worker generations', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-retry-restart', undefined, { mode: 'default' });
  try {
    const original = await prepare(fixture);
    await claim(fixture, original);
    await unknown(fixture, original);
    const retry = (await fixture.agent.readModelAttempt())!.retry;
    const checkpointId = identityHash('cliq-model-retry-test-checkpoint-v1', fixture.runId);
    const proof = await quiescedToolCheckpoint(fixture, checkpointId);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    const generation = closure.workspaceGenerations.find(row => row.phase === 'checkpointing')!;
    await fixture.store.sealWorkerGeneration({ launchId: fixture.launchId, expectedRunRevision: closure.run.revision,
      expectedGenerationRowVersion: generation.rowVersion, quiesceId: 'tool-test-quiesce', checkpointId,
      contextManifestRef: closure.latestCheckpoint.contextManifestRef, ...proof.checkpoint,
      snapshotEvidenceDigest: proof.snapshot.evidenceDigest, checkpointReason: 'handoff' });
    await fixture.store.close();
    now += 499;
    fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed?.releaseKeys });
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry, retry);
    const worker = await activateFixtureWorker(fixture, 'model-retry-resumed');
    fixture.leaseEpoch = worker.leaseEpoch;
    await assert.rejects(prepare(fixture), { code: 'MODEL_RETRY_PENDING' });
    now++;
    const replacement = await prepare(fixture);
    assert.equal(replacement.entry.attempt, 1);
    assert.deepEqual(replacement.prepared.outbound, original.prepared.outbound);
    assert.equal(replacement.entry.budgetDelta.modelTokens, original.entry.budgetDelta.modelTokens);
    await claim(fixture, replacement);
    assert.deepEqual((await fixture.agent.readModelAttempt())?.retry,
      { kind: 'pending', attempt: 1, phase: 'dispatch_claimed', dispatchedAttempts: 2 });
  } finally { await disposeFixture(fixture); }
});
