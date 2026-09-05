import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { rename } from 'node:fs/promises';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ToolObservationV1, ToolPolicyChannelEvidenceV1, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore } from './store.js';
import { postEffectObservation } from './testing/tool-effects.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;

async function batch(fixture: Fixture, calls: Array<{ name: string; input: unknown }>) {
  const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
  await fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: fixture.leaseEpoch, opId: prepared.entry.opId, attempt: 0, dispatchId: 'model-dispatch' });
  const response = fixture.agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  response.push(Buffer.from(JSON.stringify({ id: 'response', object: 'response', status: 'completed', model: 'model-1',
    output: calls.map((call, index) => ({ type: 'function_call', id: `wire-${index}`, call_id: `call-${index}`,
      name: call.name, arguments: JSON.stringify(call.input) })) })));
  return fixture.agent.completeModel({ opId: prepared.entry.opId, attempt: 0, expectedRunRevision: prepared.run.revision,
    result: response.finish(sampleCanonicalNow(), fixture.agent.resolveToolInput) });
}

async function prepareTool(fixture: Fixture) {
  const result = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
  assert.equal(result.disposition, 'prepared');
  if (result.disposition !== 'prepared') throw new Error('test expected a direct policy allow');
  return result;
}

async function claimTool(fixture: Fixture, prepared: Awaited<ReturnType<typeof prepareTool>>) {
  return fixture.agent.claimTool({ expectedRunRevision: prepared.run.revision, leaseEpoch: fixture.leaseEpoch,
    opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId: `tool-dispatch-${prepared.request.callIndex}` });
}

async function observation(fixture: Fixture, claimed: Awaited<ReturnType<typeof claimTool>>, content: unknown) {
  const value: ToolObservationV1 = { schemaVersion: 1, format: 'cliq-tool-observation-v1', runId: fixture.runId,
    opId: claimed.entry.opId, attempt: claimed.entry.attempt, requestRef: claimed.entry.requestRef, targetRef: claimed.entry.target,
    grantRef: claimed.entry.grantRef!, dispatchId: claimed.entry.dispatchId!, outcome: 'executed', content,
    observedAt: sampleCanonicalNow(), observationDigest: '' };
  value.observationDigest = digestOmitting(value, 'observationDigest');
  return (await fixture.store.artifacts.publishCanonical(value, value.format)).ref;
}

test('canonical allow, permanent claim and ordered results continue through the real loaded Run without authority in prompts', async () => {
  const fixture = await createAgentFixture('tool-ordered', undefined, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: './a.ts' } }, { name: 'read', input: { path: 'a.ts' } }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const first = await prepareTool(fixture);
    assert.throws(() => { first.entry.budgetDelta.toolCalls = 0; }, TypeError);
    assert.throws(() => { first.request.toolName = 'bash'; }, TypeError);
    assert.throws(() => { first.target.toolName = 'bash'; }, TypeError);
    const grant = await fixture.store.artifacts.readCanonical<ToolOperationGrantV1>(first.entry.grantRef!);
    const evidence = await fixture.store.artifacts.readCanonical<ToolPolicyChannelEvidenceV1>(grant.provenance.channelEvidenceRef);
    assert.equal(evidence.effectiveDisposition, 'allow');
    assert.deepEqual(evidence.matchedRuleIds, []);
    assert.equal(evidence.channel, 'fs-read');
    assert.equal(grant.requestDigest, first.request.requestDigest);
    assert.equal(grant.targetDigest, first.target.targetDigest);
    assert.equal(grant.maxDispatchedAttempts, 3);
    assert.notEqual(grant.requestRef, grant.requestDigest);
    assert.notEqual(first.target.targetDigest, first.request.targetRef);
    await assert.rejects(fixture.agent.claimTool({ expectedRunRevision: first.run.revision - 1,
      leaseEpoch: fixture.leaseEpoch, opId: first.entry.opId, attempt: 0, dispatchId: 'stale-revision' }), { code: 'REVISION_CONFLICT' });
    await assert.rejects(fixture.agent.claimTool({ expectedRunRevision: first.run.revision,
      leaseEpoch: fixture.leaseEpoch + 1, opId: first.entry.opId, attempt: 0, dispatchId: 'foreign-lease' }), { code: 'LEASE_FENCED' });
    await assert.rejects(fixture.store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: first.run.revision,
      leaseEpoch: fixture.leaseEpoch, opId: first.entry.opId, attempt: 0, dispatchId: 'bypass' }), { code: 'INVALID_REQUEST' });
    const claimed = await claimTool(fixture, first);
    assert.throws(() => { claimed.entry.budgetDelta.toolCalls = 99; }, TypeError);
    await assert.rejects(claimTool(fixture, first), { code: 'STATE_TRANSITION_INVALID' });
    const resultRef = await observation(fixture, claimed, { text: 'first value' });
    const input = { opId: first.entry.opId, attempt: 0, expectedRunRevision: first.run.revision, observationRef: resultRef };
    await assert.rejects(fixture.store.completeInvocation({ ...input, runId: fixture.runId, resultRef,
      consumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } }), { code: 'INVALID_REQUEST' });
    const completed = await fixture.agent.completeTool(input);
    assert.equal(completed.run.budgetConsumed.toolCalls, 1);
    assert.equal(completed.run.budgetReserved.toolCalls, 0);
    await assert.rejects(fixture.agent.completeTool(input), { code: 'REVISION_CONFLICT' });
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    const next = await fixture.agent.readToolInvocation();
    assert.equal(next.invocation.index, 1);
    assert.deepEqual(next.invocation.input, { path: 'a.ts' });
    assert.equal(next.loopSignature, claimed.loopSignature);
    const second = await prepareTool(fixture);
    assert.notEqual(second.entry.opId, first.entry.opId);
    const secondClaim = await claimTool(fixture, second);
    await fixture.agent.completeTool({ opId: second.entry.opId, attempt: 0, expectedRunRevision: second.run.revision,
      observationRef: await observation(fixture, secondClaim, { text: 'second value' }) });
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(await Promise.all(after.items.map(async (item) => (await fixture.store.artifacts.readCanonical<{ kind: string }>(item.payloadRef)).kind)),
      ['model_turn', 'assistant_tool_batch', 'policy_decision', 'tool_result', 'policy_decision', 'tool_result']);
    assert.equal(after.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    assert.equal(after.run.nextStep, 'agent');
    assert.equal(after.run.budgetConsumed.toolCalls, 2);
    const model = await fixture.agent.prepareModel({ expectedRunRevision: after.run.revision, leaseEpoch: fixture.leaseEpoch });
    assert.deepEqual(model.projection.messages.filter((message) => message.role === 'tool').map((message) => message.contentUtf8),
      ['{"text":"first value"}', '{"text":"second value"}']);
    const visible = Buffer.from(model.prepared.outbound.bodyBytes).toString('utf8');
    for (const ref of [first.entry.grantRef!, grant.provenance.channelEvidenceRef, grant.policyRef, first.request.targetRef]) assert.ok(!visible.includes(ref));
  } finally { await disposeFixture(fixture); }
});

test('direct deny closes exactly its own call with no Journal or charge, while ask never creates a grant or skips ahead', async () => {
  const fixture = await createAgentFixture('tool-deny-ask', undefined, { tools: ['bash', 'read'], mode: 'default' });
  try {
    await batch(fixture, [{ name: 'bash', input: { command: 'rm -rf a' } }, { name: 'bash', input: { command: 'printf ok' } }, { name: 'read', input: { path: 'a' } }]);
    const denied = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    assert.equal(denied.disposition, 'denied');
    const beforeAsk = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(beforeAsk.run.budgetConsumed.toolCalls, 0);
    assert.equal(beforeAsk.journal.filter((entry) => entry.opKind !== 'model').length, 0);
    const ask = await fixture.agent.prepareTool({ expectedRunRevision: denied.run.revision, leaseEpoch: fixture.leaseEpoch });
    assert.equal(ask.disposition, 'approval_required');
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), beforeAsk);
    assert.equal((await fixture.agent.readToolInvocation()).invocation.index, 1);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    assert.equal((await fixture.agent.readToolInvocation()).invocation.index, 1);
  } finally { await disposeFixture(fixture); }
});

test('tool settlement fault injection rolls back Journal, budget, result, frontier and Checkpoint together', async () => {
  const fixture = await createAgentFixture('tool-atomic', undefined, { mode: 'default' });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const input = { opId: prepared.entry.opId, attempt: 0, expectedRunRevision: prepared.run.revision,
      observationRef: await observation(fixture, claimed, 'result') };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec("CREATE TRIGGER fail_tool_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected tool checkpoint failure'); END");
    await assert.rejects(fixture.agent.completeTool(input), /injected tool checkpoint failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_tool_checkpoint');
    const completed = await fixture.agent.completeTool(input);
    assert.equal(completed.entry.phase, 'completed');
    assert.equal(completed.run.nextStep, 'agent');
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    assert.equal(fixture.store.getRun(fixture.runId).budgetConsumed.toolCalls, 1);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('only trusted loaded authority can prepare, and racing admissions commit one grant and reservation', async () => {
  const fixture = await createAgentFixture('tool-race', undefined, { mode: 'default' });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const input = { expectedRunRevision: before.run.revision, leaseEpoch: fixture.leaseEpoch };
    const unqualified = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material });
    await assert.rejects(unqualified.prepareTool(input), { code: 'RECOVERY_REQUIRED' });
    await assert.rejects(fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: [] }), /trusted release signature/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    const profilePath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, canonicalSha256(fixture.signed!.profile));
    await rename(profilePath, `${profilePath}.withheld`);
    try {
      await assert.rejects(fixture.agent.prepareTool(input));
      assert.deepEqual(fixture.store.getRun(fixture.runId), before.run);
    } finally { await rename(`${profilePath}.withheld`, profilePath); }
    const raced = await Promise.allSettled([fixture.agent.prepareTool(input), fixture.agent.prepareTool(input)]);
    assert.equal(raced.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(raced.filter((result) => result.status === 'rejected').length, 1);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.run.budgetReserved.toolCalls, 1);
    assert.equal(after.journal.filter((entry) => entry.opKind === 'tool').length, 1);
    const items = await Promise.all(after.items.map((item) => fixture.store.artifacts.readCanonical<{ kind: string }>(item.payloadRef)));
    assert.equal(items.filter((item) => item.kind === 'policy_decision').length, 1);
    const prepared = after.journal.at(-1)!;
    for (const ref of [prepared.requestRef, prepared.target]) {
      const artifactPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, ref);
      await rename(artifactPath, `${artifactPath}.withheld`);
      try {
        await assert.rejects(fixture.agent.claimTool({ expectedRunRevision: after.run.revision, leaseEpoch: fixture.leaseEpoch,
          opId: prepared.opId, attempt: prepared.attempt, dispatchId: 'missing-authority' }));
        assert.deepEqual(fixture.store.getRun(fixture.runId), after.run);
      } finally { await rename(`${artifactPath}.withheld`, artifactPath); }
    }
    await assert.rejects(fixture.agent.completeTool({ expectedRunRevision: after.run.revision, opId: prepared.opId,
      attempt: prepared.attempt, observationRef: canonicalSha256('unclaimed result') }), /permanent dispatch claim/);
  } finally { await disposeFixture(fixture); }
});

test('schema/size failures and received tool errors remain fully charged, model-safe results while later calls continue', async () => {
  const fixture = await createAgentFixture('tool-output', undefined, { mode: 'default', outputSchema: { type: 'string' } });
  try {
    await batch(fixture, ['a', 'b', 'c'].map((path) => ({ name: 'read', input: { path } })));
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const completed = await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0, expectedRunRevision: prepared.run.revision,
      observationRef: await observation(fixture, claimed, { privateDiagnostic: 'must not enter prompt' }) });
    assert.equal(completed.entry.phase, 'completed');
    assert.equal(completed.run.budgetConsumed.toolCalls, 1);
    assert.equal((await fixture.agent.readToolInvocation()).invocation.index, 1);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    const item = await fixture.store.artifacts.readCanonical<{ resultRef: string }>(closure.items.at(-1)!.payloadRef);
    const payload = await fixture.store.artifacts.readCanonical<{ modelContentRef: string }>(item.resultRef);
    const content = await fixture.store.artifacts.readCanonical<{ content: unknown }>(payload.modelContentRef);
    assert.deepEqual(content.content, { code: 'TOOL_PROTOCOL_ERROR' });
    const second = await prepareTool(fixture), secondClaim = await claimTool(fixture, second);
    await fixture.agent.completeTool({ opId: second.entry.opId, attempt: 0, expectedRunRevision: second.run.revision,
      observationRef: await observation(fixture, secondClaim, 'x'.repeat(1_048_577)) });
    const third = await prepareTool(fixture), thirdClaim = await claimTool(fixture, third);
    const raw = await fixture.store.artifacts.readCanonical<ToolObservationV1>(await observation(fixture, thirdClaim, 'unused'));
    assert.equal(raw.outcome, 'executed');
    if (raw.outcome !== 'executed') throw new Error('expected executed fixture');
    const { content: _content, observationDigest: _digest, ...base } = raw;
    const diagnostic = await fixture.store.artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-tool-execution-diagnostic-v1',
      message: 'private filesystem error' }, 'cliq-tool-execution-diagnostic-v1');
    const errorCore = { ...base, outcome: 'error' as const, code: 'TOOL_EXECUTION_FAILED' as const,
      diagnosticRef: diagnostic.ref, diagnosticDigest: diagnostic.ref };
    const error = await fixture.store.artifacts.publishCanonical({ ...errorCore, observationDigest: canonicalSha256(errorCore) }, raw.format);
    const last = await fixture.agent.completeTool({ opId: third.entry.opId, attempt: 0, expectedRunRevision: third.run.revision, observationRef: error.ref });
    assert.equal(last.entry.phase, 'completed');
    assert.equal(last.run.budgetConsumed.toolCalls, 3);
    assert.equal(last.run.budgetReserved.toolCalls, 0);
    const model = await fixture.agent.prepareModel({ expectedRunRevision: last.run.revision, leaseEpoch: fixture.leaseEpoch });
    assert.deepEqual(model.projection.messages.filter((message) => message.role === 'tool').map((message) => message.contentUtf8),
      ['{"code":"TOOL_PROTOCOL_ERROR"}', '{"code":"TOOL_PROTOCOL_ERROR"}', '{"code":"TOOL_EXECUTION_FAILED"}']);
  } finally { await disposeFixture(fixture); }
});

test('mutating completion requires exact retirement/snapshot proof and seals result, budget and post-effect workspace atomically', async () => {
  const fixture = await createAgentFixture('tool-post-effect', undefined, { mode: 'accept-edits', tools: ['edit'] });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const raw = await observation(fixture, claimed, { changed: true });
    const input = { opId: prepared.entry.opId, attempt: 0, expectedRunRevision: prepared.run.revision, observationRef: raw };
    await assert.rejects(fixture.agent.completeTool(input), /post-effect checkpoint/);
    const proof = await postEffectObservation(fixture, raw, prepared.checkpointId);
    input.observationRef = proof.observationRef;
    const forged = { ...proof.snapshot, checkpointId: 'foreign-checkpoint' };
    forged.evidenceDigest = digestOmitting(forged, 'evidenceDigest');
    const artifact = await fixture.store.artifacts.publishCanonical(forged, forged.format);
    const bad = structuredClone(proof.observation);
    bad.postEffect!.snapshotEvidenceRef = artifact.ref;
    bad.observationDigest = digestOmitting(bad, 'observationDigest');
    const badArtifact = await fixture.store.artifacts.publishCanonical(bad, bad.format);
    await assert.rejects(fixture.agent.completeTool({ ...input, observationRef: badArtifact.ref }), /snapshot differs/);
    for (const mutate of [
      (death: Record<string, unknown>) => { (death.backend as Record<string, unknown>).remainingTrackedDescendants = 1; },
      (death: Record<string, unknown>) => { (death.owner as Record<string, unknown>).workerLaunchId = 'foreign-launch'; }
    ]) {
      const death = await fixture.store.artifacts.readCanonical<Record<string, unknown>>(proof.observation.postEffect!.retirementEvidenceRef);
      mutate(death);
      death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
      const bad = structuredClone(proof.observation);
      bad.postEffect!.retirementEvidenceRef = (await fixture.store.artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1')).ref;
      bad.observationDigest = digestOmitting(bad, 'observationDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(bad, bad.format);
      await assert.rejects(fixture.agent.completeTool({ ...input, observationRef: artifact.ref }), /death|owner/);
    }
    for (const field of ['processIdentityRef', 'stateLockIdentityDigest', 'supervisorExecutableDigest']) {
      const death = await fixture.store.artifacts.readCanonical<Record<string, unknown>>(proof.observation.postEffect!.retirementEvidenceRef);
      const inspector = await fixture.store.artifacts.readCanonical<Record<string, unknown>>(death.inspectorIdentityRef as string);
      inspector[field] = canonicalSha256('foreign-inspector-binding');
      inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
      death.inspectorIdentityRef = (await fixture.store.artifacts.publishCanonical(inspector, 'cliq-supervisor-inspector-identity-v1')).ref;
      death.inspectorIdentityDigest = inspector.identityDigest;
      death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
      const bad = structuredClone(proof.observation);
      bad.postEffect!.retirementEvidenceRef = (await fixture.store.artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1')).ref;
      bad.observationDigest = digestOmitting(bad, 'observationDigest');
      const artifact = await fixture.store.artifacts.publishCanonical(bad, bad.format);
      await assert.rejects(fixture.agent.completeTool({ ...input, observationRef: artifact.ref }), /current trusted state owner/);
    }
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const sealInput = { launchId: fixture.launchId, expectedRunRevision: before.run.revision,
      expectedGenerationRowVersion: before.workspaceGenerations[0]!.rowVersion, quiesceId: 'tool-test-quiesce', checkpointId: prepared.checkpointId,
      contextManifestRef: before.latestCheckpoint.contextManifestRef, workspaceStateRef: proof.workspaceStateRef,
      snapshotEvidenceRef: proof.observation.postEffect!.snapshotEvidenceRef, snapshotEvidenceDigest: proof.snapshot.evidenceDigest,
      retirementEvidenceRef: proof.observation.postEffect!.retirementEvidenceRef, checkpointReason: 'auto' as const };
    const sealing = fixture.store.sealWorkerGeneration(sealInput);
    sealInput.launchId = 'caller-swapped-launch';
    await assert.rejects(sealing, /post-effect Checkpoint together/);
    fault.exec("CREATE TRIGGER fail_effect_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected effect checkpoint failure'); END");
    await assert.rejects(fixture.agent.completeTool(input), /injected effect checkpoint failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_effect_checkpoint');
    const completed = await fixture.agent.completeTool(input);
    assert.equal(completed.run.status, 'queued');
    assert.equal(completed.run.activeWorkerLaunchId, undefined);
    assert.equal(completed.run.nextStep, 'agent');
    assert.equal(completed.run.budgetConsumed.toolCalls, 1);
    const after = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(after.latestCheckpoint.workspaceStateRef, proof.workspaceStateRef);
    assert.notEqual(proof.workspaceStateRef, proof.priorWorkspaceStateRef);
    assert.equal(after.latestCheckpoint.journalSeq, completed.entry.seq);
    assert.equal(after.workspaceGenerations[0]!.phase, 'sealed');
    const trigger = fault.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'checkpoints_immutable_update'").get<{ sql: string }>()!.sql;
    assert.throws(() => fault.prepare('UPDATE checkpoints SET workspace_state_ref = ? WHERE id = ?').run(proof.priorWorkspaceStateRef, prepared.checkpointId), /immutable/);
    // Deliberately bypass the immutability guard to test recovery's independent corruption detection.
    fault.exec('DROP TRIGGER checkpoints_immutable_update');
    fault.prepare('UPDATE checkpoints SET workspace_state_ref = ? WHERE id = ?').run(proof.priorWorkspaceStateRef, prepared.checkpointId);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), /pre-effect workspace/);
    fault.prepare('UPDATE checkpoints SET workspace_state_ref = ? WHERE id = ?').run(proof.workspaceStateRef, prepared.checkpointId);
    fault.exec(trigger);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot);
    fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    assert.equal(fixture.store.getRun(fixture.runId).budgetConsumed.toolCalls, 1);
  } finally { fault.close(); await disposeFixture(fixture); }
});
