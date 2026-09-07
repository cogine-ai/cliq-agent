import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ToolApprovalDecisionV1, ToolApprovalWait, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { batch, prepareTool, claimTool, observation } from './testing/tool-calls.js';
import { postEffectObservation, quiescedToolCheckpoint } from './testing/tool-effects.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { openSqliteDriver } from './sqlite-driver.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
async function ask(fixture: Fixture) {
  const result = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
  assert.equal(result.disposition, 'approval_required');
  if (result.disposition !== 'approval_required') throw new Error('test expected ask');
  return result;
}
async function wait(fixture: Fixture) {
  const pending = await ask(fixture);
  const proof = pending.run.activeWorkerLaunchId ? await quiescedToolCheckpoint(fixture, pending.checkpointId) : undefined;
  return fixture.agent.waitForToolApproval({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef,
    ...(proof ? { checkpoint: proof.checkpoint } : {}) });
}
async function control(fixture: Fixture, decision: 'allow' | 'deny', ttlMs?: number) {
  const run = fixture.store.getRun(fixture.runId);
  return { principalId: 'cliq-m2-principal', requestId: uuidv7(), expectedRunRevision: run.revision, waitingOnRef: run.waitingOnRef!,
    decision, ...(ttlMs === undefined ? {} : { ttlMs }), ...await publishInProcessChannel(fixture.store, 'cliq-m2-principal') };
}
async function reopen(fixture: Fixture) {
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
}

test('approval survives restart, concurrent control replay and fresh worker activation without widening the original call', async () => {
  const fixture = await createAgentFixture('approval-allow', undefined, { mode: 'default', tools: ['bash', 'read'] });
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf ok' } }, { name: 'read', input: { path: 'a' } }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const waiting = await wait(fixture);
    assert.equal(waiting.run.status, 'waiting');
    assert.equal(waiting.run.activeWorkerLaunchId, undefined);
    assert.equal(waiting.run.frontierRef, before.run.frontierRef);
    assert.deepEqual(waiting.run.budgetReserved, before.run.budgetReserved);
    const held = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.ok(held.workerLaunches.every((launch) => launch.phase === 'retired'));
    assert.ok(held.workspaceGenerations.every((generation) => generation.phase === 'sealed'));
    assert.deepEqual(held.journal, before.journal);
    assert.deepEqual(held.items, before.items);
    await assert.rejects(fixture.agent.prepareTool({ expectedRunRevision: waiting.run.revision, leaseEpoch: fixture.leaseEpoch }), { code: 'LEASE_FENCED' });
    await reopen(fixture);
    await assert.rejects(fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material }), { code: 'RECOVERY_REQUIRED' });
    const input = await control(fixture, 'allow');
    const approvals = await Promise.all([fixture.agent.approveTool(input), fixture.agent.approveTool(input)]);
    assert.deepEqual(approvals.map((result) => result.replayed).sort(), [false, true]);
    assert.deepEqual(approvals[0]!.response, approvals[1]!.response);
    const approved = approvals[0]!;
    assert.equal(approved.run.status, 'queued');
    assert.equal(approved.run.waitingOnRef, undefined);
    assert.equal(approved.run.frontierRef, waiting.run.frontierRef);
    assert.throws(() => { approved.run.revision = 1; }, TypeError);
    await assert.rejects(fixture.agent.approveTool({ ...input, decision: 'deny' }), { code: 'REQUEST_ID_CONFLICT' });
    await reopen(fixture);
    assert.deepEqual((await fixture.agent.approveTool({ ...input, ...await publishInProcessChannel(fixture.store, input.principalId) })).response, approved.response);
    const oldEpoch = fixture.leaseEpoch;
    Object.assign(fixture, await activateFixtureWorker(fixture, 'approved-first-worker'));
    const prepared = await prepareTool(fixture);
    assert.equal(prepared.request.callIndex, 0);
    assert.equal(prepared.request.frontierRef, waiting.run.frontierRef);
    assert.equal(prepared.entry.attempt, 0);
    assert.equal(fixture.leaseEpoch, oldEpoch + 1);
    const grant = await fixture.store.artifacts.readCanonical<ToolOperationGrantV1>(prepared.entry.grantRef!);
    assert.equal(grant.provenance.kind, 'user_approval');
    if (grant.provenance.kind !== 'user_approval') throw new Error('wrong provenance');
    assert.equal(grant.provenance.waitingSubjectRef, waiting.waitingOnRef);
    assert.equal(grant.provenance.decisionRef, approved.response.result.decisionRef);
    const decision = await fixture.store.artifacts.readCanonical<ToolApprovalDecisionV1>(grant.provenance.decisionRef);
    assert.equal(decision.requestedTtlMs, undefined);
    assert.equal(grant.expiresAt, new Date(Math.min(Date.parse(grant.issuedAt) + 3_600_000, Date.parse(prepared.run.deadlineAt))).toISOString());
    const claimed = await claimTool(fixture, prepared);
    const effect = await postEffectObservation(fixture, await observation(fixture, claimed, { stdout: 'ok' }), prepared.checkpointId);
    await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0, expectedRunRevision: prepared.run.revision, observationRef: effect.observationRef });
    Object.assign(fixture, await activateFixtureWorker(fixture, 'approved-next-worker'));
    const second = await prepareTool(fixture);
    assert.notEqual(second.entry.grantRef, prepared.entry.grantRef);
    const read = await claimTool(fixture, second);
    await fixture.agent.completeTool({ opId: second.entry.opId, attempt: 0, expectedRunRevision: second.run.revision, observationRef: await observation(fixture, read, 'next') });
    const projection = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    const visible = Buffer.from(projection.prepared.outbound.bodyBytes).toString('utf8');
    for (const ref of [waiting.waitingOnRef, grant.provenance.decisionRef, prepared.entry.grantRef!, decision.channelIdentityRef]) assert.ok(!visible.includes(ref));
    assert.deepEqual(projection.projection.messages.filter((message) => message.role === 'tool').map((message) => message.contentUtf8), ['{"stdout":"ok"}', '"next"']);
    assert.equal(fixture.store.getRun(fixture.runId).budgetConsumed.toolCalls, 2);
  } finally { await disposeFixture(fixture); }
});

test('denial closes one ordered call without dispatch or charge and a later ask can wait without a worker', async () => {
  const fixture = await createAgentFixture('approval-deny', undefined, { mode: 'default', tools: ['bash'] });
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf first' } }, { name: 'bash', input: { command: 'printf second' } }]);
    const first = await wait(fixture);
    const firstInput = await control(fixture, 'deny', 5000);
    const denied = await fixture.agent.approveTool(firstInput);
    const decision = await fixture.store.artifacts.readCanonical<ToolApprovalDecisionV1>(denied.response.result.decisionRef);
    assert.equal(decision.requestedTtlMs, 5000);
    assert.equal(decision.grantExpiresAt, undefined);
    assert.equal(denied.run.status, 'queued');
    assert.equal(denied.run.budgetConsumed.toolCalls, 0);
    assert.equal((await fixture.agent.readToolInvocation()).invocation.index, 1);
    await reopen(fixture);
    const second = await wait(fixture);
    assert.notEqual(second.waitingOnRef, first.waitingOnRef);
    assert.notEqual(second.run.frontierRef, first.run.frontierRef);
    assert.deepEqual((await fixture.agent.approveTool(firstInput)).response, denied.response);
    await assert.rejects(fixture.agent.approveTool({ ...await control(fixture, 'allow'), waitingOnRef: first.waitingOnRef }), { code: 'STATE_TRANSITION_INVALID' });
    await fixture.agent.approveTool(await control(fixture, 'deny'));
    const closed = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(closed.run.nextStep, 'agent');
    assert.equal(closed.run.budgetConsumed.toolCalls, 0);
    assert.equal(closed.journal.filter((entry) => entry.opKind !== 'model').length, 0);
    const values = await Promise.all(closed.items.map((item) => fixture.store.artifacts.readCanonical<{ kind: string; grantRef?: string }>(item.payloadRef)));
    assert.equal(values.filter((item) => item.kind === 'tool_result').length, 2);
    assert.ok(values.every((item) => item.grantRef === undefined));
    await reopen(fixture);
  } finally { await disposeFixture(fixture); }
});

test('wait and approval commit faults leave no partial generation, checkpoint, control response or decision', async () => {
  const fixture = await createAgentFixture('approval-atomic', undefined, { mode: 'default', tools: ['bash'] });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf ok' } }]);
    const pending = await ask(fixture);
    await assert.rejects(fixture.agent.waitForToolApproval({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef }), /retirement proof/);
    const proof = await quiescedToolCheckpoint(fixture, pending.checkpointId);
    const input = { expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef, checkpoint: proof.checkpoint };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const death = await fixture.store.artifacts.readCanonical<Record<string, unknown>>(proof.checkpoint.retirementEvidenceRef);
    (death.owner as Record<string, unknown>).workerLaunchId = 'foreign-launch';
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
    const foreignDeath = await fixture.store.artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1');
    await assert.rejects(fixture.agent.waitForToolApproval({ ...input,
      checkpoint: { ...proof.checkpoint, retirementEvidenceRef: foreignDeath.ref } }), /retired worker owner/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec("CREATE TRIGGER fail_approval_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected approval checkpoint failure'); END");
    await assert.rejects(fixture.agent.waitForToolApproval(input), /injected approval checkpoint failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_approval_checkpoint');
    await fixture.agent.waitForToolApproval(input);
    const approve = await control(fixture, 'allow');
    const waiting = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec("CREATE TRIGGER fail_approval_control BEFORE INSERT ON control_requests BEGIN SELECT RAISE(ABORT, 'injected approval control failure'); END");
    await assert.rejects(fixture.agent.approveTool(approve), /injected approval control failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), waiting);
    fault.exec('DROP TRIGGER fail_approval_control');
    const result = await fixture.agent.approveTool(approve);
    assert.equal(result.replayed, false);
    await reopen(fixture);
    assert.equal((await fixture.agent.approveTool(approve)).replayed, true);
  } finally { fault.close(); await disposeFixture(fixture); }
});

for (const phase of ['before_prepare', 'prepared', 'claimed'] as const) test(`grant expiry at ${phase} preserves reality and never strands or silently advances the call`, async (t) => {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture(`approval-expiry-${phase}`, undefined, { mode: 'default', tools: ['bash'] });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf ok' } }]);
    const initialWait = await wait(fixture);
    const input = await control(fixture, 'allow', 1000);
    await fixture.agent.approveTool(input);
    let prepared: Awaited<ReturnType<typeof prepareTool>> | undefined;
    let claimed: Awaited<ReturnType<typeof claimTool>> | undefined;
    if (phase !== 'before_prepare') {
      Object.assign(fixture, await activateFixtureWorker(fixture, `expiry-first-${phase}`));
      prepared = await prepareTool(fixture);
      if (phase === 'claimed') claimed = await claimTool(fixture, prepared);
    }
    clock += 1000; // Exact expiry is closed, with a still-live worker lease.
    if (phase === 'claimed') {
      await assert.rejects(fixture.agent.prepareTool({ expectedRunRevision: prepared!.run.revision, leaseEpoch: fixture.leaseEpoch }), /tool attempt already exists/);
    } else {
      if (prepared) await assert.rejects(claimTool(fixture, prepared), { code: 'LEASE_FENCED' });
      const pending = await ask(fixture);
      assert.notEqual(pending.waitingOnRef, initialWait.waitingOnRef);
      const proof = pending.run.activeWorkerLaunchId ? await quiescedToolCheckpoint(fixture, pending.checkpointId) : undefined;
      const renewal = { expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef, ...(proof ? { checkpoint: proof.checkpoint } : {}) };
      const before = await fixture.store.readRecoveryClosure(fixture.runId);
      if (phase === 'prepared') {
        fault.exec("CREATE TRIGGER fail_expiry_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected expiry checkpoint failure'); END");
        await assert.rejects(fixture.agent.waitForToolApproval(renewal), /injected expiry checkpoint failure/);
        assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
        fault.exec('DROP TRIGGER fail_expiry_checkpoint');
      }
      const renewed = await fixture.agent.waitForToolApproval(renewal);
      assert.equal(renewed.run.frontierRef, initialWait.run.frontierRef);
      assert.equal(renewed.run.budgetReserved.toolCalls, 0);
      assert.equal(renewed.run.budgetConsumed.toolCalls, 0);
      const history = (await fixture.store.readRecoveryClosure(fixture.runId)).journal.filter((entry) => entry.opKind === 'tool');
      assert.deepEqual(history.map((entry) => entry.phase), phase === 'prepared' ? ['prepared', 'failed'] : []);
      await reopen(fixture);
      assert.equal((await fixture.agent.approveTool(input)).replayed, true);
      assert.equal(fixture.store.getRun(fixture.runId).waitingOnRef, renewed.waitingOnRef);
      await fixture.agent.approveTool(await control(fixture, 'allow'));
      Object.assign(fixture, await activateFixtureWorker(fixture, `expiry-renewed-${phase}`));
      const next = await prepareTool(fixture);
      assert.equal(next.entry.attempt, phase === 'prepared' ? 1 : 0);
      if (prepared) {
        assert.notEqual(next.entry.grantRef, prepared.entry.grantRef);
        assert.deepEqual(next.request, prepared.request);
      }
      prepared = next;
      claimed = await claimTool(fixture, prepared);
    }
    const effect = await postEffectObservation(fixture, await observation(fixture, claimed!, 'ok'), prepared!.checkpointId);
    await fixture.agent.completeTool({ opId: prepared!.entry.opId, attempt: prepared!.entry.attempt,
      expectedRunRevision: prepared!.run.revision, observationRef: effect.observationRef });
    await reopen(fixture);
    assert.equal(fixture.store.getRun(fixture.runId).nextStep, 'agent');
    assert.equal(fixture.store.getRun(fixture.runId).budgetConsumed.toolCalls, 1);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('approval rejects stale, foreign, malformed, cancelled and expired requests without changing the wait', async (t) => {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('approval-control-fences', undefined, { mode: 'default', tools: ['bash'] });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf ok' } }]);
    await wait(fixture);
    const input = await control(fixture, 'allow');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    for (const change of [
      { expectedRunRevision: input.expectedRunRevision - 1 }, { waitingOnRef: canonicalSha256('foreign-wait') },
      { principalId: 'foreign-principal' }, { channelIdentityDigest: canonicalSha256('foreign-channel') },
      { decision: 'yes' }, { ttlMs: 0 }, { ttlMs: -1 }, { ttlMs: 1.5 }, { ttlMs: 86_400_001 }, { ttlMs: Infinity },
      { requestId: 'not-uuid-v7' }, { unsafeAutoAllow: true }
    ]) {
      await assert.rejects(fixture.agent.approveTool({ ...input, ...change } as typeof input));
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    }
    writer.prepare('UPDATE runs SET cancel_requested = 1 WHERE id = ?').run(fixture.runId);
    await assert.rejects(fixture.agent.approveTool(input), { code: 'REVISION_CONFLICT' });
    writer.prepare('UPDATE runs SET cancel_requested = 0 WHERE id = ?').run(fixture.runId);
    clock = Date.parse(before.run.deadlineAt);
    await assert.rejects(fixture.agent.approveTool(input), /lifetime/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('an approval wait cannot substitute its call, policy evidence or workspace bytes', async () => {
  const fixture = await createAgentFixture('approval-wait-proof', undefined, { mode: 'default', tools: ['bash'] });
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf ok' } }]);
    const pending = await ask(fixture);
    const original = await fixture.store.artifacts.readCanonical<ToolApprovalWait>(pending.waitingOnRef);
    for (const alter of [
      (value: ToolApprovalWait) => { value.subject.callId = 'another-call'; },
      (value: ToolApprovalWait) => { value.subject.policyChannelEvidenceDigest = canonicalSha256('different-evidence'); },
      (value: ToolApprovalWait) => { value.frontierRef = canonicalSha256('different-frontier'); },
      (value: ToolApprovalWait) => { value.subject.kind = 'delivery_plan' as never; },
      (value: ToolApprovalWait) => { Object.assign(value.subject, { childMode: 'mutating' }); }
    ]) {
      const changed = structuredClone(original); alter(changed);
      const artifact = await fixture.store.artifacts.publishCanonical(changed, 'cliq-waiting-subject-v1');
      await assert.rejects(fixture.agent.waitForToolApproval({ expectedRunRevision: pending.run.revision, waitingOnRef: artifact.ref }));
    }
    const proof = await quiescedToolCheckpoint(fixture, pending.checkpointId, true);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.agent.waitForToolApproval({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef,
      checkpoint: proof.checkpoint }), /unchanged ready workspace/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('recovery refuses an approval whose authenticated control-row or channel ownership has been substituted', async () => {
  const fixture = await createAgentFixture('approval-recovery-proof', undefined, { mode: 'default', tools: ['bash'] });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf ok' } }]);
    await wait(fixture);
    const input = await control(fixture, 'allow');
    await fixture.agent.approveTool(input);
    writer.prepare("UPDATE control_requests SET channel_identity_digest = ? WHERE method = 'run.approve'").run(canonicalSha256('substituted-channel'));
    await assert.rejects(fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys }), /control-row owner/);
    writer.prepare("UPDATE control_requests SET channel_identity_digest = ? WHERE method = 'run.approve'").run(input.channelIdentityDigest);
    const fake = await fixture.store.artifacts.publishCanonical({ protocolVersion: 1, ok: true, result: { method: 'run.submit' } }, 'cliq-control-application-response-v1');
    writer.prepare("UPDATE control_requests SET response_ref = ? WHERE method = 'run.approve'").run(fake.ref);
    await assert.rejects(fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys }), /approval response/);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('a queued approval renewal cannot retain a competing preactivated worker', async (t) => {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('approval-pending-worker', undefined, { mode: 'default', tools: ['bash'] });
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'printf ok' } }]);
    await wait(fixture);
    await fixture.agent.approveTool(await control(fixture, 'allow', 1));
    // The fixture uses the real registration/reservation/preactivation reducers; only final activation fails.
    await assert.rejects(activateFixtureWorker(fixture, 'competing-worker', 0));
    clock++;
    const pending = await ask(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.ok(before.workerLaunches.some((launch) => launch.phase === 'preactivated'));
    await assert.rejects(fixture.agent.waitForToolApproval({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef }), /pending worker launch/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
