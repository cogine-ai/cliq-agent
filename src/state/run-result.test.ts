// Real StateStore consumer seam with retained offline model/seal fixtures.
// These checks establish terminal invariants, not provider/native qualification.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { FinalCandidateItem, RunResult, VerificationClosureV1 } from '../kernel/result.js';
import type { DirectUnverifiedConsentV1, RunFrontier, RunSpec, SessionRunTerminalItem } from '../kernel/types.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { ResultUnavailableError } from './control-read.js';
import { loadRunResult, type RunResultPhase } from './run-result.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
const revision = (fixture: Fixture) => fixture.store.getRun(fixture.runId).revision;
async function candidate(fixture: Fixture) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: revision(fixture), leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: 'run-result-dispatch' });
  const reader = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  reader.push(Buffer.from(JSON.stringify({ id: 'run-result-response', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'message', id: 'run-result-message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'The proposed change is ready.', annotations: [] }] }] })));
  const completed = await fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: prepared.run.revision, result: reader.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
  assert.equal(completed.disposition, 'candidate_required');
  const producerId = identityHash('cliq-model-turn-item-v1', fixture.runId, prepared.entry.opId, String(prepared.entry.attempt));
  const owner = await fixture.agent.beginFinalCandidate({ expectedRunRevision: completed.run.revision });
  const proof = await quiescedToolCheckpoint(fixture,
    identityHash('cliq-final-candidate-checkpoint-v1', fixture.runId, producerId), true);
  return owner.complete({ expectedRunRevision: completed.run.revision, checkpoint: proof.checkpoint });
}
async function reopen(fixture: Fixture) {
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material,
    releaseKeys: fixture.signed.releaseKeys });
}

test('explicitly consented empty verification publishes one unverified immutable result and Session outcome across reopen and replay', async () => {
  const fixture = await createAgentFixture('run-result-empty', undefined, { mode: 'plan' });
  try {
    await candidate(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const item = await fixture.store.artifacts.readCanonical<FinalCandidateItem>(before.items.at(-1)!.payloadRef);
    const session = fixture.store.getSession(before.run.sessionId);
    const verificationRequest = { expectedRunRevision: revision(fixture) };
    const verified = await fixture.agent.completeVerification(verificationRequest);
    assert.equal(verified.run.status, 'queued'); assert.equal(verified.run.nextStep, 'finalize');
    assert.equal(verified.run.resultRef, undefined);
    const frontier = await fixture.store.artifacts.readCanonical<Extract<RunFrontier, { kind: 'finalize' }>>(verified.run.frontierRef!);
    const closure = await fixture.store.artifacts.readCanonical<VerificationClosureV1>(frontier.verificationClosureRef);
    assert.deepEqual(closure.dependency, { kind: 'none' });
    assert.deepEqual(closure.verification, { kind: 'local', outcome: 'unverified',
      unverifiedConsentRef: before.runSpec.unverifiedConsentRef, entries: [] });
    assert.equal(closure.candidateItemId, item.itemId); assert.equal(closure.resultSourceRef, item.resultSourceRef);
    assert.equal(fixture.store.getSession(session.id).latestItemSeq, session.latestItemSeq);
    await reopen(fixture);
    assert.equal((await fixture.agent.completeVerification(verificationRequest)).verificationClosureRef, frontier.verificationClosureRef);
    const request = { expectedRunRevision: revision(fixture) };
    const phases: RunResultPhase[] = [];
    // Borrow the actual already-held fixture owner, never manufacture a lock
    // or native proof merely to exercise an inert diagnostic callback.
    const held = fixture.store as unknown as { driver: SqliteDriver; owner: StateOwnerContext };
    const resultOwner = loadRunResult(held.driver, fixture.store.artifacts, held.owner,
      { run: before.run, spec: before.runSpec, principalId: fixture.principalId }, value => {
        phases.push(value);
        throw new Error('an inert diagnosis consumer cannot decide the result');
      });
    const committed = await resultOwner.commitRunResult(request);
    assert.deepEqual(phases, ['result_recovery', 'result_basis', 'result_finalization', 'result_publication', 'result_session', 'result_commit']);
    assert.equal(committed.run.status, 'completed_unverified'); assert.equal(committed.run.terminalReason, 'no_required_verifier');
    assert.equal(committed.run.nextStep, null); assert.equal(committed.run.frontierRef, undefined);
    assert.equal(committed.run.stopIntentRef, undefined); assert.equal(committed.run.terminalDetailRef, undefined);
    const result = await fixture.store.artifacts.readCanonical<RunResult>(committed.resultRef);
    const inspectionIdentity = await publishInProcessChannel(fixture.store);
    const inspected = await fixture.store.readControl({ protocolVersion: 1, method: 'run.result', runId: fixture.runId }, inspectionIdentity);
    assert.equal(inspected.method, 'run.result');
    if (inspected.method !== 'run.result') throw new Error('result inspection selected another method');
    assert.equal(inspected.runId, fixture.runId); assert.equal(inspected.result.ref, committed.resultRef);
    assert.equal(inspected.result.digest, committed.resultRef); assert.equal(inspected.result.schemaVersion, 1);
    assert.equal(inspected.result.sizeBytes, (await fixture.store.artifacts.readBytes(committed.resultRef)).byteLength);
    assert.equal(inspected.verificationClosureRef, result.verificationClosureRef);
    const inspectedDiff = await fixture.store.readControl({ protocolVersion: 1, method: 'run.diff', runId: fixture.runId }, inspectionIdentity);
    assert.equal(inspectedDiff.method, 'run.diff');
    if (inspectedDiff.method !== 'run.diff') throw new Error('diff inspection selected another method');
    assert.equal(inspectedDiff.diff.ref, result.diffRef); assert.equal(inspectedDiff.diff.digest, result.diffRef);
    assert.equal(inspectedDiff.diff.sizeBytes, (await fixture.store.artifacts.readBytes(result.diffRef)).byteLength);
    for (const key of ['baseSourceRef', 'resultSourceRef', 'diffRef', 'summaryRef'] as const) assert.equal(result[key], item[key]);
    assert.equal(result.verificationClosureRef, frontier.verificationClosureRef); assert.deepEqual(result.verificationReceiptRefs, []);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.journal, before.journal); assert.deepEqual(after.items, before.items);
    assert.deepEqual(after.run.budgetConsumed, before.run.budgetConsumed); assert.deepEqual(after.run.budgetReserved, before.run.budgetReserved);
    const terminalSession = fixture.store.getSession(session.id);
    assert.equal(terminalSession.latestItemSeq, session.latestItemSeq + 1); assert.equal(terminalSession.contextRevision, session.contextRevision + 1);
    const projection = await fixture.store.artifacts.readCanonical<{ segments: Array<{ kind: string; items?: Array<{ payloadRef: string }> }> }>(terminalSession.contextProjectionRef);
    const segment = projection.segments.at(-1)!;
    assert.equal(segment.kind, 'raw'); assert.equal(segment.items!.length, 1);
    const terminal = await fixture.store.artifacts.readCanonical<SessionRunTerminalItem>(segment.items![0]!.payloadRef);
    assert.equal(terminal.resultRef, committed.resultRef); assert.equal(terminal.summaryRef, item.summaryRef);
    assert.equal(terminal.status, 'completed_unverified'); assert.equal(terminal.terminalDetailRef, undefined);
    await reopen(fixture);
    assert.deepEqual(await fixture.agent.commitRunResult(request), committed);
    assert.deepEqual(fixture.store.getSession(session.id), terminalSession);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), after);
  } finally { await disposeFixture(fixture); }
});

test('an actual later channel cannot be substituted as the historical consent channel even with rehashed matching control data', async () => {
  const fixture = await createAgentFixture('run-result-late-channel', undefined, { mode: 'plan' });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await candidate(fixture);
    const cut = await fixture.store.readRecoveryClosure(fixture.runId);
    const original = writer.prepare(`SELECT c.response_ref FROM control_requests c JOIN runs r
      ON c.principal_id=r.principal_id AND c.request_id=r.admission_request_id AND c.method='run.submit' WHERE r.id=?`)
      .get<{ response_ref: string }>(fixture.runId)!;
    const later = await publishInProcessChannel(fixture.store);
    const consent = await fixture.store.artifacts.readCanonical<DirectUnverifiedConsentV1>(cut.runSpec.unverifiedConsentRef!);
    Object.assign(consent, { channelIdentityRef: later.channelIdentityRef, channelIdentityDigest: later.channelIdentityDigest });
    consent.consentDigest = digestOmitting(consent, 'consentDigest');
    const consentRef = (await fixture.store.artifacts.publishCanonical(consent, 'cliq-direct-unverified-consent-v1')).ref;
    const spec: RunSpec = { ...cut.runSpec, unverifiedConsentRef: consentRef };
    const specRef = (await fixture.store.artifacts.publishCanonical(spec, 'cliq-run-spec-v1')).ref;
    const response = await fixture.store.artifacts.readCanonical<{ result: { snapshot: { run: { specRef: string } } } }>(original.response_ref);
    response.result.snapshot.run.specRef = specRef;
    const responseRef = (await fixture.store.artifacts.publishCanonical(response, 'cliq-control-application-response-v1')).ref;
    writer.prepare('UPDATE runs SET spec_ref=? WHERE id=?').run(specRef, fixture.runId);
    writer.prepare('UPDATE control_requests SET response_ref=?,channel_identity_ref=?,channel_identity_digest=? WHERE response_ref=?')
      .run(responseRef, later.channelIdentityRef, later.channelIdentityDigest, original.response_ref);
    const before = fixture.store.getRun(fixture.runId);
    await assert.rejects(async () => {
      const agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed.releaseKeys });
      await agent.completeVerification({ expectedRunRevision: before.revision });
    });
    assert.deepEqual(fixture.store.getRun(fixture.runId), before);
  } finally { writer.close(); await disposeFixture(fixture); }
});

for (const stop of ['cancel', 'deadline'] as const) test(`a durable finalize frontier remains ${stop === 'cancel' ? 'cancellable' : 'deadline-fenced'} and never publishes a stopped result`, async t => {
  let now = Date.now(); t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture(`run-result-stop-${stop}`, { wallTimeMs: 60_000 }, { mode: 'plan' });
  try {
    await candidate(fixture); await fixture.agent.completeVerification({ expectedRunRevision: revision(fixture) });
    await reopen(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    if (stop === 'deadline') {
      now = Date.parse(before.run.deadlineAt);
      await assert.rejects(fixture.agent.commitRunResult({ expectedRunRevision: revision(fixture) }), { code: 'LEASE_FENCED' });
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
      await fixture.agent.expireRun({ expectedRunRevision: revision(fixture) });
    } else await fixture.agent.cancelRun({ requestId: uuidv7(), expectedRunRevision: revision(fixture), ...await publishInProcessChannel(fixture.store) });
    await assert.rejects(fixture.agent.commitRunResult({ expectedRunRevision: revision(fixture) }), { code: 'STATE_TRANSITION_INVALID' });
    await assert.rejects(fixture.agent.completeVerification({ expectedRunRevision: revision(fixture) }), { code: 'STATE_TRANSITION_INVALID' });
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: revision(fixture) });
    assert.equal(terminal.run.status, stop === 'cancel' ? 'cancelled' : 'failed');
    assert.equal(terminal.run.terminalReason, stop === 'cancel' ? 'cancelled_by_user' : 'budget_exhausted');
    assert.equal(terminal.run.resultRef, undefined);
    await reopen(fixture);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(after.run, terminal.run); assert.deepEqual(after.items, before.items); assert.deepEqual(after.journal, before.journal);
    const identity = await publishInProcessChannel(fixture.store);
    for (const method of ['run.result', 'run.diff'] as const) {
      await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method, runId: fixture.runId }, identity), error => {
        assert.ok(error instanceof ResultUnavailableError);
        assert.deepEqual(error.controlError, { schemaVersion: 1, code: 'RESULT_UNAVAILABLE', messageCode: 'run.result_unavailable',
          retryable: false, runId: fixture.runId, status: terminal.run.status, terminalDetailRef: terminal.run.terminalDetailRef });
        return true;
      });
    }
    assert.equal(fixture.store.getSession(before.run.sessionId).latestItemSeq, 1);
  } finally { await disposeFixture(fixture); }
});

test('verification and result transaction failures leave no partial frontier, result or Session outcome and retry once', async () => {
  const fixture = await createAgentFixture('run-result-atomic', undefined, { mode: 'plan' });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await candidate(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    writer.exec("CREATE TRIGGER fail_verification BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected verification failure'); END");
    await assert.rejects(fixture.agent.completeVerification({ expectedRunRevision: revision(fixture) }), /injected verification failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    writer.exec('DROP TRIGGER fail_verification');
    await fixture.agent.completeVerification({ expectedRunRevision: revision(fixture) });
    const finalized = await fixture.store.readRecoveryClosure(fixture.runId), session = fixture.store.getSession(before.run.sessionId);
    writer.exec("CREATE TRIGGER fail_result BEFORE INSERT ON items WHEN NEW.session_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected result failure'); END");
    await assert.rejects(fixture.agent.commitRunResult({ expectedRunRevision: revision(fixture) }), /injected result failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), finalized);
    assert.deepEqual(fixture.store.getSession(session.id), session);
    writer.exec('DROP TRIGGER fail_result');
    const request = { expectedRunRevision: revision(fixture) }, result = await fixture.agent.commitRunResult(request);
    assert.deepEqual(await fixture.agent.commitRunResult(request), result);
    assert.equal(fixture.store.getSession(session.id).latestItemSeq, session.latestItemSeq + 1);
    await reopen(fixture);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('a result and an independent root stop share Session commit order without losing or coalescing either outcome', async () => {
  const fixture = await createAgentFixture('run-result-session', undefined, { mode: 'plan' });
  try {
    await candidate(fixture); await fixture.agent.completeVerification({ expectedRunRevision: revision(fixture) });
    const { run, runSpec: spec } = await fixture.store.readRecoveryClosure(fixture.runId);
    const source = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(spec.sourceProjectionRef);
    const second = await fixture.store.admitRun({ requestId: uuidv7(), admissionKey: admissionKey('result-second-root'),
      sessionId: run.sessionId, expectedContextRevision: 1, workspacePath: fixture.workspace, objective: 'another root', allowUnverified: true,
      assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef, verifierSpecRef: spec.verifierSpecRef,
      sourceProjectionRef: spec.sourceProjectionRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
      frozenIgnoreRulesRef: source.frozenIgnoreRulesRef, credentialGrantRefs: spec.credentialGrantRefs, budgets: spec.budgets,
      ...await publishInProcessChannel(fixture.store) });
    const secondAgent = await fixture.store.loadAgentRun({ runId: second.run.id, material: fixture.authority.material, releaseKeys: fixture.signed.releaseKeys });
    const stopped = await secondAgent.cancelRun({ requestId: uuidv7(), expectedRunRevision: second.run.revision, ...await publishInProcessChannel(fixture.store) });
    const [completed] = await Promise.all([fixture.agent.commitRunResult({ expectedRunRevision: run.revision }),
      secondAgent.commitTerminalStop({ expectedRunRevision: stopped.run.revision })]);
    assert.equal(completed.run.status, 'completed_unverified');
    const session = fixture.store.getSession(run.sessionId);
    assert.equal(session.latestItemSeq, 2); assert.equal(session.contextRevision, 3);
    const projection = await fixture.store.artifacts.readCanonical<{ segments: Array<{ kind: string; fromItemSeq: number; throughItemSeq: number;
      items: Array<{ payloadRef: string }> }> }>(session.contextProjectionRef);
    assert.deepEqual(projection.segments.map(segment => [segment.kind, segment.fromItemSeq, segment.throughItemSeq]), [['raw', 1, 1], ['raw', 2, 2]]);
    const items = await Promise.all(projection.segments.map(segment => fixture.store.artifacts.readCanonical<SessionRunTerminalItem>(segment.items[0]!.payloadRef)));
    assert.deepEqual(items.map(item => item.runId).sort(), [run.id, second.run.id].sort());
    await fixture.store.readRecoveryClosure(second.run.id); await reopen(fixture);
    await fixture.store.readRecoveryClosure(second.run.id);
  } finally { await disposeFixture(fixture); }
});

test('a missing original unverified consent cannot be replaced by the empty verifier list', async () => {
  const fixture = await createAgentFixture('run-result-no-consent', undefined, { mode: 'plan' });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await candidate(fixture);
    const { runSpec: original } = await fixture.store.readRecoveryClosure(fixture.runId);
    const { unverifiedConsentRef: _consent, ...spec } = original;
    const specRef = (await fixture.store.artifacts.publishCanonical(spec, 'cliq-run-spec-v1')).ref;
    writer.prepare('UPDATE runs SET spec_ref=? WHERE id=?').run(specRef, fixture.runId);
    const before = fixture.store.getRun(fixture.runId);
    await assert.rejects(async () => {
      const agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed.releaseKeys });
      await agent.completeVerification({ expectedRunRevision: before.revision });
    });
    assert.deepEqual(fixture.store.getRun(fixture.runId), before);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('empty verification rejects a rehashed foreign original admission response instead of accepting only its channel and timestamp', async () => {
  const fixture = await createAgentFixture('run-result-original-response', undefined, { mode: 'plan' });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await candidate(fixture);
    const row = writer.prepare(`SELECT c.response_ref FROM control_requests c JOIN runs r
      ON c.principal_id=r.principal_id AND c.request_id=r.admission_request_id AND c.method='run.submit' WHERE r.id=?`)
      .get<{ response_ref: string }>(fixture.runId)!;
    const original = await fixture.store.artifacts.readCanonical<{ result: { snapshot: { run: { id: string } } } }>(row.response_ref);
    original.result.snapshot.run.id = 'foreign-original-run';
    const replacement = await fixture.store.artifacts.publishCanonical(original, 'cliq-control-application-response-v1');
    writer.prepare('UPDATE control_requests SET response_ref=? WHERE response_ref=?').run(replacement.ref, row.response_ref);
    const before = fixture.store.getRun(fixture.runId), session = fixture.store.getSession(before.sessionId);
    await assert.rejects(fixture.agent.completeVerification({ expectedRunRevision: before.revision }));
    assert.deepEqual(fixture.store.getRun(fixture.runId), before); assert.deepEqual(fixture.store.getSession(session.id), session);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('a rehashed same-source closure cannot replace the exact proof installed by the finalize transaction', async t => {
  let now = Date.now(); t.mock.method(Date, 'now', () => now);
  const fixture = await createAgentFixture('run-result-exact-closure', undefined, { mode: 'plan' });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await candidate(fixture); now += 10;
    const finalized = await fixture.agent.completeVerification({ expectedRunRevision: revision(fixture) });
    const frontier = await fixture.store.artifacts.readCanonical<Extract<RunFrontier, { kind: 'finalize' }>>(finalized.run.frontierRef!);
    const closure = await fixture.store.artifacts.readCanonical<VerificationClosureV1>(frontier.verificationClosureRef);
    closure.createdAt = new Date(now - 1).toISOString(); closure.closureDigest = digestOmitting(closure, 'closureDigest');
    frontier.verificationClosureRef = (await fixture.store.artifacts.publishCanonical(closure, closure.format)).ref;
    const frontierRef = (await fixture.store.artifacts.publishCanonical(frontier, 'cliq-run-frontier-v1')).ref;
    writer.prepare('UPDATE runs SET frontier_ref=? WHERE id=?').run(frontierRef, fixture.runId);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), { code: 'RECOVERY_REQUIRED' });
  } finally { writer.close(); await disposeFixture(fixture); }
});
