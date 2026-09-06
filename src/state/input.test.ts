import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import type { ContinuationItem, RunFrontier, RunSpec } from '../kernel/types.js';
import type { RunInput, UserInputPayloadV1, UserInputValue } from '../kernel/user-input.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { activateFixtureWorker, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { validateUserInputRecovery } from './input-recovery.js';

type Fixture = Awaited<ReturnType<typeof createAgentFixture>>;
const question = { prompt: 'Which name should I use?', responseKind: 'text', maximumResponseBytes: 128 };
async function pendingInput(fixture: Fixture) {
  const pending = await fixture.agent.prepareTool({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
  assert.ok(pending.disposition === 'input_required');
  return pending;
}
async function waitForInput(fixture: Fixture) {
  const pending = await pendingInput(fixture);
  const proof = pending.run.activeWorkerLaunchId ? await quiescedToolCheckpoint(fixture, pending.checkpointId) : undefined;
  return fixture.agent.waitForInput({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef,
    ...(proof ? { checkpoint: proof.checkpoint } : {}) });
}
async function command(fixture: Fixture, input: UserInputValue): Promise<RunInput> {
  const run = fixture.store.getRun(fixture.runId);
  return { principalId: 'cliq-m2-principal', requestId: uuidv7(), expectedRunRevision: run.revision,
    waitingOnRef: run.waitingOnRef!, input, ...await publishInProcessChannel(fixture.store, 'cliq-m2-principal') };
}
async function reopen(fixture: Fixture) {
  await fixture.store.close();
  fixture.store = await openStateStore(fixture.stateRoot);
  fixture.agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
}

test('input survives restart and idempotent reply, then continues the same native batch without dispatching the control call', async () => {
  const fixture = await createAgentFixture('input-text', undefined, { mode: 'default', tools: ['read', 'request_input'] });
  try {
    await batch(fixture, [{ name: 'request_input', input: question }, { name: 'read', input: { path: 'a' } }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const invocation = await fixture.agent.readToolInvocation();
    assert.equal(invocation.kind, 'input');
    assert.equal('subject' in invocation, false);
    const waiting = await waitForInput(fixture);
    assert.equal(waiting.run.status, 'waiting');
    assert.equal(waiting.run.waitingReason, 'input');
    assert.equal(waiting.run.activeWorkerLaunchId, undefined);
    const held = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.deepEqual(held.journal, before.journal);
    assert.deepEqual(held.run.budgetReserved, before.run.budgetReserved);
    assert.deepEqual(held.run.budgetConsumed, before.run.budgetConsumed);
    assert.equal(held.latestCheckpoint.workspaceStateRef, before.latestCheckpoint.workspaceStateRef);
    assert.ok(held.workerLaunches.every((launch) => launch.phase === 'retired'));
    await reopen(fixture);
    const input = await command(fixture, { kind: 'text', value: 'Alice' });
    const replies = await Promise.all([fixture.agent.submitInput(input), fixture.agent.submitInput(input)]);
    assert.deepEqual(replies.map((reply) => reply.replayed).sort(), [false, true]);
    assert.deepEqual(replies[0]!.response, replies[1]!.response);
    const reply = replies[0]!;
    assert.equal(reply.run.status, 'queued');
    assert.equal(reply.run.activeWorkerLaunchId, undefined);
    assert.equal(reply.run.budgetConsumed.toolCalls, 0);
    await assert.rejects(fixture.agent.submitInput({ ...input, input: { kind: 'text', value: 'Bob' } }), { code: 'REQUEST_ID_CONFLICT' });
    await reopen(fixture);
    const current = await fixture.agent.readToolInvocation();
    assert.equal(current.invocation.toolName, 'read');
    assert.equal(current.invocation.index, 1);
    Object.assign(fixture, await activateFixtureWorker(fixture, 'input-next-worker'));
    const prepared = await prepareTool(fixture);
    const claimed = await claimTool(fixture, prepared);
    await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
      expectedRunRevision: prepared.run.revision, observationRef: await observation(fixture, claimed, 'file content') });
    const model = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    assert.deepEqual(model.projection.messages.map((message) => message.role), ['system', 'user', 'assistant', 'tool', 'tool', 'user']);
    assert.deepEqual(model.projection.messages.slice(-3).map((message) => message.contentUtf8), ['"Alice"', '"file content"', 'Alice']);
    const items = await Promise.all((await fixture.store.readRecoveryClosure(fixture.runId)).items.map((row) => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef)));
    const user = items.find((item) => item.kind === 'user_input');
    assert.ok(user?.kind === 'user_input');
    const payload = await fixture.store.artifacts.readCanonical<UserInputPayloadV1>(user.inputRef);
    assert.equal(payload.byteCount, 5);
    assert.equal(payload.value, 'Alice');
    const wire = Buffer.from(model.prepared.outbound.bodyBytes).toString('utf8');
    for (const value of [user.principalId, user.promptRef, user.inputRef, payload.channelIdentityRef, waiting.waitingOnRef]) assert.ok(!wire.includes(value));
    const replay = await fixture.agent.submitInput({ ...input, ...await publishInProcessChannel(fixture.store, input.principalId) });
    assert.deepEqual(replay.response, reply.response);
    assert.equal(fixture.store.getRun(fixture.runId).budgetConsumed.toolCalls, 1);
  } finally { await disposeFixture(fixture); }
});

test('successive text and schema-bound JSON answers can wait worker-free and resume with cause input', async () => {
  const fixture = await createAgentFixture('input-json', undefined, { mode: 'plan', tools: ['request_input'] });
  try {
    await batch(fixture, [{ name: 'request_input', input: question }, { name: 'request_input', input: {
      prompt: 'Choose a count and labels', responseKind: 'json', maximumResponseBytes: 64,
      responseSchema: { type: 'object', properties: { count: { type: 'integer', minimum: 1, maximum: 3 },
        labels: { type: 'array', minItems: 1, maxItems: 2, items: { type: 'string', enum: ['a', 'b'] } } },
      required: ['count', 'labels'], additionalProperties: false }
    } }]);
    await waitForInput(fixture);
    await fixture.agent.submitInput(await command(fixture, { kind: 'text', value: '李明' }));
    const waiting = await waitForInput(fixture);
    assert.equal(waiting.run.activeWorkerLaunchId, undefined);
    await reopen(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    for (const value of [{ count: '2', labels: ['a'] }, { count: 4, labels: ['a'] }, { count: 1, labels: ['c'] },
      { count: 1, labels: [] }, { count: 1, labels: ['a'], extra: true }, null]) {
      await assert.rejects(fixture.agent.submitInput(await command(fixture, { kind: 'json', value })), /response schema/);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    }
    const input = await command(fixture, { kind: 'json', value: { labels: ['a', 'b'], count: 2 } });
    const reply = await fixture.agent.submitInput(input);
    (input.input.value as { count: number }).count = 3;
    assert.equal(reply.run.status, 'queued');
    assert.equal(reply.run.budgetConsumed.toolCalls, 0);
    const frontier = await fixture.store.artifacts.readCanonical<RunFrontier>(reply.run.frontierRef!);
    assert.ok(frontier.kind === 'agent');
    assert.equal(frontier.cause, 'input');
    await reopen(fixture);
    Object.assign(fixture, await activateFixtureWorker(fixture, 'input-resumed-model'));
    const model = await fixture.agent.prepareModel({ expectedRunRevision: fixture.store.getRun(fixture.runId).revision, leaseEpoch: fixture.leaseEpoch });
    assert.deepEqual(model.projection.messages.slice(-4).map((message) => [message.role, message.contentUtf8]), [
      ['tool', '"李明"'], ['tool', '{"count":2,"labels":["a","b"]}'], ['user', '李明'], ['user', '{"count":2,"labels":["a","b"]}']
    ]);
  } finally { await disposeFixture(fixture); }
});

test('invalid request_input schema rejects the whole native batch before any ordinary tool dispatch', async () => {
  const fixture = await createAgentFixture('input-batch-invalid', undefined, { mode: 'default', tools: ['read', 'request_input'] });
  try {
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }, { name: 'request_input', input: {
      prompt: 'Unsafe schema', responseKind: 'json', maximumResponseBytes: 64, responseSchema: { $ref: 'https://example.invalid/schema' }
    } }]);
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(closure.run.nextStep, 'agent');
    assert.equal(closure.run.budgetConsumed.toolCalls, 0);
    assert.ok(closure.journal.every((entry) => entry.opKind === 'model'));
    const items = await Promise.all(closure.items.map((row) => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef)));
    assert.deepEqual(items.filter((item) => item.kind === 'tool_result').map((item) => item.outcome), ['batch_not_executed', 'error']);
    assert.ok(!items.some((item) => item.kind === 'input_request'));
  } finally { await disposeFixture(fixture); }
});

test('different request IDs racing one input wait have exactly one committed winner', async () => {
  const fixture = await createAgentFixture('input-race', undefined, { mode: 'default', tools: ['request_input'] });
  try {
    await batch(fixture, [{ name: 'request_input', input: question }]);
    await waitForInput(fixture);
    const first = await command(fixture, { kind: 'text', value: 'Alice' });
    const second = await command(fixture, { kind: 'text', value: 'Bob' });
    const results = await Promise.allSettled([fixture.agent.submitInput(first), fixture.agent.submitInput(second)]);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    const rejected = results.find((result) => result.status === 'rejected');
    assert.ok(rejected?.status === 'rejected');
    assert.equal(rejected.reason.code, 'REVISION_CONFLICT');
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await Promise.all(closure.items.map((row) => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef)));
    assert.equal(items.filter((item) => item.kind === 'user_input').length, 1);
    assert.equal(items.filter((item) => item.kind === 'tool_result').length, 1);
    assert.ok(closure.journal.every((entry) => entry.opKind === 'model'));
    await reopen(fixture);
  } finally { await disposeFixture(fixture); }
});

test('input rejects stale, foreign, malformed, oversized, cancelled and expired requests without changing the wait', async (t) => {
  let clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('input-fences', undefined, { mode: 'default', tools: ['request_input'] });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'request_input', input: { ...question, maximumResponseBytes: 6 } }]);
    await waitForInput(fixture);
    const input = await command(fixture, { kind: 'text', value: '李明' });
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    for (const change of [{ expectedRunRevision: input.expectedRunRevision - 1 }, { waitingOnRef: canonicalSha256('other-wait') },
      { principalId: 'foreign' }, { channelIdentityDigest: canonicalSha256('other-channel') }, { requestId: 'invalid' }, { extra: true },
      { input: { kind: 'text', value: '1234567' } }, { input: { kind: 'text', value: 'e\u0301' } }, { input: { kind: 'text', value: '\0' } },
      { input: { kind: 'text', value: '\ud800' } }, { input: { kind: 'text', value: null } }, { input: { kind: 'json', value: '李明' } },
      { input: { kind: 'text', value: 'ok', extra: true } }, { input: { kind: 'json', value: Infinity } }]) {
      await assert.rejects(fixture.agent.submitInput({ ...input, ...change } as RunInput));
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    }
    const { input: _value, ...approval } = input;
    await assert.rejects(fixture.agent.approveTool({ ...approval, decision: 'allow' }), { code: 'STATE_TRANSITION_INVALID' });
    writer.prepare('UPDATE runs SET cancel_requested = 1 WHERE id = ?').run(fixture.runId);
    await assert.rejects(fixture.agent.submitInput(input), { code: 'REVISION_CONFLICT' });
    writer.prepare('UPDATE runs SET cancel_requested = 0 WHERE id = ?').run(fixture.runId);
    clock = Date.parse(before.run.deadlineAt);
    await assert.rejects(fixture.agent.submitInput(input), { code: 'REVISION_CONFLICT' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('input wait and reply commit faults roll back worker retirement, request, response and checkpoint together', async () => {
  const fixture = await createAgentFixture('input-atomic', undefined, { mode: 'default', tools: ['request_input'] });
  const fault = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'request_input', input: question }]);
    const pending = await pendingInput(fixture);
    await assert.rejects(fixture.agent.waitForInput({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef }), /retirement proof/);
    const proof = await quiescedToolCheckpoint(fixture, pending.checkpointId);
    const wait = { expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef, checkpoint: proof.checkpoint };
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const death = await fixture.store.artifacts.readCanonical<Record<string, unknown>>(proof.checkpoint.retirementEvidenceRef);
    (death.owner as Record<string, unknown>).workerLaunchId = 'foreign-launch';
    death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
    const foreign = await fixture.store.artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1');
    await assert.rejects(fixture.agent.waitForInput({ ...wait, checkpoint: { ...wait.checkpoint, retirementEvidenceRef: foreign.ref } }), /retired worker owner/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec("CREATE TRIGGER fail_input_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected input checkpoint failure'); END");
    await assert.rejects(fixture.agent.waitForInput(wait), /injected input checkpoint failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    fault.exec('DROP TRIGGER fail_input_checkpoint');
    await fixture.agent.waitForInput(wait);
    const input = await command(fixture, { kind: 'text', value: 'Alice' });
    const waiting = await fixture.store.readRecoveryClosure(fixture.runId);
    fault.exec("CREATE TRIGGER fail_input_control BEFORE INSERT ON control_requests BEGIN SELECT RAISE(ABORT, 'injected input control failure'); END");
    await assert.rejects(fixture.agent.submitInput(input), /injected input control failure/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), waiting);
    fault.exec('DROP TRIGGER fail_input_control');
    assert.equal((await fixture.agent.submitInput(input)).replayed, false);
    await reopen(fixture);
    assert.equal((await fixture.agent.submitInput({ ...input, ...await publishInProcessChannel(fixture.store, input.principalId) })).replayed, true);
  } finally { fault.close(); await disposeFixture(fixture); }
});

test('recovery rejects substituted input control ownership and immutable response snapshots', async () => {
  const fixture = await createAgentFixture('input-recovery-owner', undefined, { mode: 'default', tools: ['request_input'] });
  const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    await batch(fixture, [{ name: 'request_input', input: question }]);
    await waitForInput(fixture);
    const input = await command(fixture, { kind: 'text', value: 'Alice' });
    const reply = await fixture.agent.submitInput(input);
    const load = () => fixture.store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed!.releaseKeys });
    writer.prepare("UPDATE control_requests SET channel_identity_digest = ? WHERE method = 'run.input'").run(canonicalSha256('foreign-channel'));
    await assert.rejects(load(), /control-row owner/);
    writer.prepare("UPDATE control_requests SET channel_identity_digest = ? WHERE method = 'run.input'").run(input.channelIdentityDigest);
    const fake = structuredClone(reply.response);
    fake.result.snapshot.run.revision++;
    const ref = await fixture.store.artifacts.publishCanonical(fake, 'cliq-control-application-response-v1');
    writer.prepare("UPDATE control_requests SET response_ref = ? WHERE method = 'run.input'").run(ref.ref);
    await assert.rejects(load(), /committed snapshot/);
  } finally { writer.close(); await disposeFixture(fixture); }
});

test('recovery rejects an executed input result when its entire input history is missing', async () => {
  const fixture = await createAgentFixture('input-orphan-result', undefined, { mode: 'default', tools: ['request_input'] });
  try {
    await batch(fixture, [{ name: 'request_input', input: question }]);
    await waitForInput(fixture);
    await fixture.agent.submitInput(await command(fixture, { kind: 'text', value: 'Alice' }));
    const closure = await fixture.store.readRecoveryClosure(fixture.runId);
    const items = await Promise.all(closure.items.map((row) => fixture.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef)));
    await assert.rejects(validateUserInputRecovery({ artifacts: fixture.store.artifacts, run: closure.run,
      spec: await fixture.store.artifacts.readCanonical<RunSpec>(closure.run.specRef),
      journal: closure.journal, checkpoints: [closure.latestCheckpoint],
      items: new Map(items.filter((item) => item.kind !== 'input_request' && item.kind !== 'user_input').map((item) => [item.itemId, item]))
    }), /input result has no owning authenticated input/);
  } finally { await disposeFixture(fixture); }
});

test('a queued input wait cannot retain a competing preactivated worker', async () => {
  const fixture = await createAgentFixture('input-pending-worker', undefined, { mode: 'default', tools: ['request_input'] });
  try {
    await batch(fixture, [{ name: 'request_input', input: question }, { name: 'request_input', input: question }]);
    await waitForInput(fixture);
    await fixture.agent.submitInput(await command(fixture, { kind: 'text', value: 'Alice' }));
    await assert.rejects(activateFixtureWorker(fixture, 'input-competing-worker', 0));
    const pending = await pendingInput(fixture);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.ok(before.workerLaunches.some((launch) => launch.phase === 'preactivated'));
    await assert.rejects(fixture.agent.waitForInput({ expectedRunRevision: pending.run.revision, waitingOnRef: pending.waitingOnRef }), /pending worker launch/);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
