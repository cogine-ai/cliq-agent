import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ModelResponseFailureEvidenceV1 } from '../kernel/stop.js';
import type { SupervisorInspectorIdentityV1, TerminalDetail } from '../kernel/types.js';
import type { NormalPromptProjectionV1 } from '../model/request.js';
import type { ModelFailureStopIntent } from '../runtime/stop.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { fixtureInspector, quiescedToolCheckpoint } from './testing/tool-effects.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
type Prepared = Awaited<ReturnType<Fixture['agent']['prepareModel']>>;
const revision = (fixture: Fixture) => fixture.store.getRun(fixture.runId).revision;
const prepare = (fixture: Fixture) => fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
const claim = (fixture: Fixture, prepared: Prepared) => fixture.store.claimInvocationDispatch({ runId: fixture.runId,
  expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt,
  dispatchId: `dispatch:${prepared.entry.opId}:${prepared.entry.attempt}` });
const stop = async (fixture: Fixture) => fixture.agent.stopForModelFailure({ expectedRunRevision: revision(fixture),
  ...(await fixtureInspector(fixture)).identity });
async function reopen(fixture: Fixture) {
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
}
const usableBytes = (text: string) => JSON.stringify({ id: 'response', object: 'response', status: 'completed', model: 'model-1', output: [
  { type: 'message', id: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text, annotations: [] }] }
] });
async function complete(fixture: Fixture, bytes = '{', status = 200) {
  const prepared = await prepare(fixture);
  await claim(fixture, prepared);
  const response = fixture.agent.model.start(prepared.prepared, { status, mediaType: 'application/json' });
  response.push(Buffer.from(bytes));
  const result = response.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput);
  const completed = await fixture.agent.completeModel({ expectedRunRevision: revision(fixture), opId: prepared.entry.opId,
    attempt: prepared.entry.attempt, result });
  return { prepared, completed, result };
}

for (const [label, bytes, status] of [
  ['malformed', '{', 200],
  ['provider-rejected', '{"error":{"message":"rate limited"}}', 429],
  ['oversized', 'x'.repeat(1_048_578), 200],
  ['empty-end', usableBytes(''), 200]
] as const) test(`${label} response stops with exact runtime evidence, full charges and one restart-safe Session publication`, async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture(`model-failure-${label}`, undefined, { mode: 'plan' });
  try {
    const { prepared, completed, result } = await complete(fixture, bytes, status);
    assert.equal(result.kind, 'unusable');
    assert.equal(completed.entry.phase, 'completed');
    assert.equal(completed.disposition, 'stop_required');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(before.run.budgetConsumed, prepared.entry.budgetDelta);
    assert.equal(before.items.length, 0);
    await assert.rejects(fixture.agent.stopForResourceFailure({ expectedRunRevision: revision(fixture) }), { code: 'STATE_TRANSITION_INVALID' });
    const stopped = await stop(fixture);
    const intent = await fixture.store.artifacts.readCanonical<ModelFailureStopIntent>(stopped.run.stopIntentRef!);
    const evidence = await fixture.store.artifacts.readCanonical<ModelResponseFailureEvidenceV1>(intent.runtimeFailureRef);
    assert.deepEqual(intent, { schemaVersion: 1, runId: fixture.runId, createdAt: stopped.run.updatedAt, origin: 'runtime',
      targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'runtime', failingOpId: prepared.entry.opId,
      runtimeFailureRef: canonicalSha256(evidence), runtimeFailureDigest: evidence.evidenceDigest });
    assert.equal(evidence.failureKind, 'model_unusable_response');
    assert.equal(evidence.unusableResponseRef, completed.entry.resultRef);
    assert.equal(evidence.evidenceDigest, digestOmitting(evidence, 'evidenceDigest'));
    assert.equal(evidence.frontierRef, before.run.frontierRef);
    assert.equal(evidence.frontierDigest, before.run.frontierRef);
    assert.deepEqual((await stop(fixture)).run, stopped.run);
    await assert.rejects(prepare(fixture), { code: 'AGENT_HANDOFF_PENDING' });
    now += 10_000;
    await reopen(fixture); // The old inspector is history, not authority for the new retirement observation.
    const sessionBefore = fixture.store.getSession(stopped.run.sessionId);
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const input = { expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint };
    const terminal = await fixture.agent.commitTerminalStop(input);
    assert.equal(terminal.run.status, 'failed');
    assert.equal(terminal.run.terminalReason, 'runtime_failed');
    assert.equal(terminal.run.cancelRequested, false);
    assert.equal(terminal.run.resultRef, undefined);
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    assert.equal(detail.primaryEvidenceRef, intent.runtimeFailureRef);
    assert.deepEqual(detail.reasonDetail, { kind: 'runtime', failingOpId: prepared.entry.opId,
      runtimeFailureRef: intent.runtimeFailureRef, runtimeFailureDigest: evidence.evidenceDigest });
    assert.deepEqual(await fixture.agent.commitTerminalStop(input), terminal);
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.journal, before.journal);
    assert.deepEqual(after.items, before.items);
    assert.deepEqual(after.run.budgetConsumed, before.run.budgetConsumed);
    assert.deepEqual(after.run.budgetReserved, before.run.budgetReserved);
    assert.equal(after.latestCheckpoint.contextManifestRef, before.latestCheckpoint.contextManifestRef);
    const session = fixture.store.getSession(stopped.run.sessionId);
    assert.equal(session.contextRevision, sessionBefore.contextRevision + 1);
    assert.equal(session.latestItemSeq, sessionBefore.latestItemSeq + 1);
  } finally { await disposeFixture(fixture); }
});

test('pending, free pre-dispatch failures and a successful candidate cannot be classified as model failure', async () => {
  const fixture = await createAgentFixture('model-failure-ineligible', undefined, { mode: 'plan' });
  try {
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    for (let attempt = 0; attempt < 4; attempt++) {
      const prepared = await prepare(fixture);
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      const error = await fixture.store.artifacts.publishCanonical({ reason: 'offline pre-dispatch failure' }, 'cliq-invocation-error-v1');
      await fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, expectedRunRevision: revision(fixture),
        opId: prepared.entry.opId, attempt, errorRef: error.ref });
      await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    }
    const { completed } = await complete(fixture, usableBytes('done'));
    assert.equal(completed.disposition, 'candidate_required');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

for (const finalResponse of [false, true]) test(`unknown attempts remain unresolved even after ${finalResponse ? 'a received rejection' : 'retry exhaustion'}`, async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture(`model-failure-unknown-${finalResponse}`, undefined, { mode: 'plan' });
  try {
    for (let attempt = 0; attempt < (finalResponse ? 1 : 3); attempt++) {
      const prepared = await prepare(fixture);
      await claim(fixture, prepared);
      const claimed = await fixture.store.readRecoveryClosure(fixture.runId);
      await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), claimed);
      const evidence = await fixture.store.artifacts.publishCanonical({ reason: 'offline ambiguous model fixture' }, 'cliq-invocation-ambiguity-evidence-v1');
      await fixture.store.markInvocationUnknown({ runId: fixture.runId, expectedRunRevision: revision(fixture),
        opId: prepared.entry.opId, attempt, evidenceRef: evidence.ref, evidenceDigest: evidence.ref });
      now += attempt === 0 ? 500 : 2000;
    }
    if (finalResponse) await complete(fixture, '{"error":{}}', 503);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal((await fixture.agent.readModelAttempt())?.disposition, 'stop_required');
    await assert.rejects(stop(fixture), { code: 'STATE_TRANSITION_INVALID' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('model failure requires the current inspector and rejects caller-selected reason or evidence', async () => {
  const fixture = await createAgentFixture('model-failure-inspector', undefined, { mode: 'plan' });
  try {
    await complete(fixture);
    const { inspector, identity } = await fixtureInspector(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const command = { expectedRunRevision: revision(fixture), ...identity };
    await assert.rejects(fixture.agent.stopForModelFailure({ ...command, reason: 'runtime_failed' } as never), { code: 'INVALID_REQUEST' });
    await assert.rejects(fixture.agent.stopForModelFailure({ ...command, runtimeFailureRef: canonicalSha256('diagnostic') } as never), { code: 'INVALID_REQUEST' });
    await assert.rejects(fixture.agent.stopForModelFailure({ ...command, inspectorIdentityDigest: canonicalSha256('wrong') }), /inspector/);
    for (const change of [
      { supervisorInstanceId: 'foreign-owner' }, { supervisorExecutableDigest: canonicalSha256('foreign-executable') },
      { instanceNonceDigest: canonicalSha256('foreign-nonce') }, { supervisorEntryVersion: 'foreign-version' },
      { runtimeBundleRef: canonicalSha256('foreign-bundle') },
      { stateLockIdentityDigest: canonicalSha256('foreign-lock') }, { activatedAt: '9999-01-01T00:00:00.000Z' },
      { extra: 'not a closed inspector' }
    ]) {
      const forged = { ...inspector, ...change };
      forged.identityDigest = digestOmitting(forged, 'identityDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(forged, forged.format);
      await assert.rejects(fixture.agent.stopForModelFailure({ expectedRunRevision: revision(fixture),
        inspectorIdentityRef: artifact.ref, inspectorIdentityDigest: forged.identityDigest }), /inspector/);
    }
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    await reopen(fixture);
    await assert.rejects(fixture.agent.stopForModelFailure(command), /inspector/);
    await stop(fixture);
  } finally { await disposeFixture(fixture); }
});

test('model failure observations enforce the five-second commit boundary and can be freshly reobserved', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-failure-freshness', undefined, { mode: 'plan' });
  try {
    await complete(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const publish = fixture.store.artifacts.publishCanonical.bind(fixture.store.artifacts);
    let delay = 5001;
    const slow = t.mock.method(fixture.store.artifacts, 'publishCanonical', async (value: unknown, kind: string) => {
      const artifact = await publish(value, kind);
      if (kind === 'cliq-stop-intent-v1') now += delay;
      return artifact;
    });
    await assert.rejects(stop(fixture), /observation is stale/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    delay = 5000;
    const stopped = await stop(fixture);
    assert.ok(stopped.run.stopIntentRef);
    slow.mock.restore();
    await reopen(fixture);
  } finally { await disposeFixture(fixture); }
});

test('concurrent model stops have one winner; evidence metadata, stop state and terminal Session writes are atomic', async () => {
  const fixture = await createAgentFixture('model-failure-atomic', undefined, { mode: 'plan' });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await complete(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const counts = () => ['artifacts', 'run_events'].map((table) => fault.prepare(`SELECT count(*) AS count FROM ${table}`).get());
    const priorCounts = counts();
    fault.exec("CREATE TRIGGER fail_model_stop BEFORE UPDATE ON runs WHEN NEW.stop_intent_ref IS NOT OLD.stop_intent_ref BEGIN SELECT RAISE(ABORT, 'injected model stop failure'); END");
    await assert.rejects(stop(fixture), /injected model stop failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    assert.deepEqual(counts(), priorCounts);
    fault.exec('DROP TRIGGER fail_model_stop');
    const command = { expectedRunRevision: revision(fixture), ...(await fixtureInspector(fixture)).identity };
    const raced = await Promise.allSettled([fixture.agent.stopForModelFailure(command), fixture.agent.stopForModelFailure(command)]);
    const winner = raced.find(result => result.status === 'fulfilled');
    assert.ok(winner?.status === 'fulfilled');
    assert.equal(raced.filter(result => result.status === 'rejected' && result.reason.code === 'REVISION_CONFLICT').length, 1);
    const proof = await quiescedToolCheckpoint(fixture, winner.value.checkpointId);
    const pending = await fixture.store.readRecoveryClosure(fixture.runId), session = fixture.store.getSession(before.run.sessionId);
    fault.exec("CREATE TRIGGER fail_model_terminal BEFORE INSERT ON items WHEN NEW.session_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected model terminal failure'); END");
    const input = { expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint };
    await assert.rejects(fixture.agent.commitTerminalStop(input), /injected model terminal failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), pending);
    assert.deepEqual(fixture.store.getSession(session.id), session);
    fault.exec('DROP TRIGGER fail_model_terminal');
    await fixture.agent.commitTerminalStop(input);
    await reopen(fixture);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('rehashing substituted failure evidence cannot change its Journal, frontier, inspector or closed branch', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-failure-corruption', undefined, { mode: 'plan' });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const claimed = await claimTool(fixture, await prepareTool(fixture));
    await fixture.agent.completeTool({ expectedRunRevision: revision(fixture), opId: claimed.entry.opId, attempt: claimed.entry.attempt,
      observationRef: await observation(fixture, claimed, 'earlier tool result') });
    await complete(fixture);
    now += 10_000;
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const earlierRequest = await fixture.store.artifacts.readCanonical<{ promptProjectionRef: string }>(before.journal[0]!.requestRef);
    const earlierProjection = await fixture.store.artifacts.readCanonical<NormalPromptProjectionV1>(earlierRequest.promptProjectionRef);
    const stopped = await stop(fixture);
    const intent = await fixture.store.artifacts.readCanonical<ModelFailureStopIntent>(stopped.run.stopIntentRef!);
    const evidence = await fixture.store.artifacts.readCanonical<ModelResponseFailureEvidenceV1>(intent.runtimeFailureRef);
    const inspector = await fixture.store.artifacts.readCanonical<SupervisorInspectorIdentityV1>(evidence.inspectorIdentityRef);
    const foreignInspector = { ...inspector, supervisorInstanceId: 'foreign-owner', identityDigest: '' };
    foreignInspector.identityDigest = digestOmitting(foreignInspector, 'identityDigest');
    const foreignArtifact = await fixture.store.artifacts.publishCanonical(foreignInspector, foreignInspector.format);
    const foreignNonce = { ...inspector, instanceNonceDigest: canonicalSha256('foreign-nonce'), identityDigest: '' };
    foreignNonce.identityDigest = digestOmitting(foreignNonce, 'identityDigest');
    const nonceArtifact = await fixture.store.artifacts.publishCanonical(foreignNonce, foreignNonce.format);
    for (const change of [
      { runId: 'foreign-run' }, { failingOpId: 'foreign-op' },
      { frontierDigest: canonicalSha256('foreign-frontier') },
      { frontierRef: earlierProjection.frontierDigest, frontierDigest: earlierProjection.frontierDigest },
      { unusableResponseRef: evidence.frontierRef }, { unusableResponseDigest: canonicalSha256('foreign-response') },
      { observedAt: new Date(now - 5001).toISOString() }, { observedAt: new Date(now + 1).toISOString() },
      { inspectorIdentityRef: foreignArtifact.ref, inspectorIdentityDigest: foreignInspector.identityDigest },
      { inspectorIdentityRef: nonceArtifact.ref, inspectorIdentityDigest: foreignNonce.identityDigest },
      { failureKind: 'model_attempts_exhausted' }, { failureCode: 'transport_exhausted' }
    ]) {
      const forged = { ...evidence, ...change };
      forged.evidenceDigest = digestOmitting(forged, 'evidenceDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(forged, forged.format);
      const substituted = await fixture.store.artifacts.publishCanonical({ ...intent, failingOpId: forged.failingOpId,
        runtimeFailureRef: artifact.ref, runtimeFailureDigest: forged.evidenceDigest }, 'cliq-stop-intent-v1');
      fault.prepare('UPDATE runs SET stop_intent_ref = ? WHERE id = ?').run(substituted.ref, fixture.runId);
      try { await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' }); }
      finally { fault.prepare('UPDATE runs SET stop_intent_ref = ? WHERE id = ?').run(stopped.run.stopIntentRef!, fixture.runId); }
    }
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint });
    assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).items, before.items);
    assert.equal(terminal.run.budgetConsumed.toolCalls, 1);
    const detail = await fixture.store.artifacts.readCanonical<TerminalDetail>(terminal.run.terminalDetailRef!);
    const wrongPrimary = await fixture.store.artifacts.publishCanonical({ ...detail, primaryEvidenceRef: stopped.run.stopIntentRef }, 'cliq-terminal-detail-v1');
    fault.prepare('UPDATE runs SET terminal_detail_ref = ? WHERE id = ?').run(wrongPrimary.ref, fixture.runId);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
    fault.prepare('UPDATE runs SET terminal_detail_ref = ? WHERE id = ?').run(terminal.run.terminalDetailRef!, fixture.runId);
    await reopen(fixture);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('deadline and user cancellation supersede model failure without changing the received response or its charges', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('model-failure-priority', { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    await complete(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const failed = await stop(fixture);
    now += 60_000;
    const expired = await stop(fixture);
    assert.notEqual(expired.run.stopIntentRef, failed.run.stopIntentRef);
    assert.equal((await fixture.store.artifacts.readCanonical<{ origin: string }>(expired.run.stopIntentRef!)).origin, 'deadline');
    const cancelled = await fixture.agent.cancelRun({ requestId: uuidv7(),
      expectedRunRevision: revision(fixture), ...await publishInProcessChannel(fixture.store) });
    assert.deepEqual((await stop(fixture)).run, cancelled.run);
    const proof = await quiescedToolCheckpoint(fixture, cancelled.checkpointId);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture), checkpoint: proof.checkpoint });
    assert.equal(terminal.run.status, 'cancelled');
    assert.deepEqual((await fixture.store.readRecoveryClosure(fixture.runId)).journal, before.journal);
    assert.deepEqual(terminal.run.budgetConsumed, before.run.budgetConsumed);
    await reopen(fixture);
  } finally { await disposeFixture(fixture); }
});
