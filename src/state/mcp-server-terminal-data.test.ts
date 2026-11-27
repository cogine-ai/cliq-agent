// Pure budget/Journal/closed receipt data. These tests create no native owner,
// process, SQLite claim, signed runtime, containment or cleanup authority.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpServerInstanceIdentity, mcpServerLaunchOperationId } from '../kernel/mcp-stdio.js';
import type { BudgetSettlementV1, InvocationJournalEntry, Run } from '../kernel/types.js';
import { mcpServerTerminalData, mcpServerFailedLaunchData, isMcpLocalStopAdvance } from './mcp-server-terminal-data.js';

const ref = canonicalSha256, at = '2026-11-01T00:00:00.000Z', done = '2026-11-01T00:01:00.000Z';
const budget = (toolCalls: number) => ({ modelTokens: 0, costMicros: 0, toolCalls, repairAttempts: 0 });
test('only a newer Stop over otherwise identical original Run data permits local uncommitted restaging', () => {
  const original: Run = { id: 'run', sessionId: 'session', specRef: ref('spec'), status: 'running', nextStep: 'agent', frontierRef: ref('frontier'),
    revision: 1, leaseEpoch: 1, latestCheckpointId: 'checkpoint', budgetConsumed: budget(0), budgetReserved: budget(2),
    repairCount: 0, cancelRequested: false, createdAt: at, updatedAt: at, deadlineAt: '2026-11-01T00:02:00.000Z' };
  const stopped: Run = { ...original, revision: 2, updatedAt: done, cancelRequested: true, stopIntentRef: ref('stop') };
  assert.equal(isMcpLocalStopAdvance(original, stopped), true);
  for (const changed of [{ ...stopped, revision: 1 }, { ...stopped, cancelRequested: false },
    { ...stopped, stopIntentRef: undefined }, { ...stopped, updatedAt: '2026-10-31T00:00:00.000Z' },
    { ...stopped, frontierRef: ref('other frontier') }, { ...stopped, leaseEpoch: 2 },
    { ...stopped, budgetConsumed: budget(1) }, { ...stopped, budgetReserved: budget(1) },
    { ...stopped, activeWorkerLaunchId: 'other-worker' }, { ...stopped, status: 'waiting' as const }])
    assert.equal(isMcpLocalStopAdvance(original, changed), false);
});
function failedData(claimed: boolean) {
  const original = data(), claim = { ...original.claim, sandboxLaunchSpecRef: original.instance.sandboxLaunchSpecRef };
  const core = { schemaVersion: 1, format: 'cliq-mcp-server-launch-failure-v1', runId: 'run', launchOpId: original.prepared.opId, attempt: 0,
    preparedJournalSeq: original.prepared.seq, ...(claimed ? { claimedJournalSeq: claim.seq } : { claimStatus: 'not_claimed' }),
    targetRef: original.prepared.target, requestRef: original.prepared.requestRef, grantRef: original.prepared.grantRef,
    dispatchId: claim.dispatchId, sandboxLaunchSpecRef: claim.sandboxLaunchSpecRef, nativeClosure: original.nativeClosure,
    stoppedAt: at, instance: 'not_initialized', closure: 'plan_quiescent', noSpawnEvidenceRef: ref('inert no-spawn locator'), reason: 'cancel' };
  return { prepared: original.prepared, ...(claimed ? { claim } : {}), terminalSeq: 7, settledAt: done,
    failure: { ...core, failureDigest: ref(core) }, run: { id: 'run', budgetConsumed: budget(4), budgetReserved: budget(2) } };
}
function successorData(claimed: boolean) {
  const source = failedData(claimed), { failureDigest: _digest, noSpawnEvidenceRef: _noSpawn, ...original } = source.failure;
  const core = { ...original, reason: 'creator_lost_before_effect_claim', instance: claimed ? 'setup_outcome_unavailable' : 'not_initialized',
    nativeClosure: { ...original.nativeClosure, kind: 'linux_successor_cleanup', cleanupRawRef: ref('inert cleanup bytes'), cleanupProjectionRef: ref('inert cleanup projection') },
    ...(claimed ? { closure: 'containment_dead', processContainmentRef: ref('inert retained original containment'), containmentDeathEvidenceRef: ref('inert current death') }
      : { closure: 'plan_quiescent', noSpawnEvidenceRef: ref('inert current no-spawn') }) };
  return { ...source, failure: { ...core, failureDigest: ref(core) } };
}
test('a claimed successor closure preserves an unavailable setup outcome and its separate full launch charge', () => {
  const source = successorData(true), local = mcpServerFailedLaunchData(source);
  assert.equal(local.failure.instance, 'setup_outcome_unavailable'); assert.equal(local.failure.reason, 'creator_lost_before_effect_claim');
  assert.deepEqual(local.settlement.consumed, budget(1)); assert.deepEqual(local.settlement.released, budget(1));
  for (const key of ['instanceIdentityRef', 'instanceIdentityDigest', 'stoppedItemId', 'disposition', 'owningCallClosureCause'])
    assert.equal(Object.hasOwn(local.failure, key), false);
  const unclaimed = mcpServerFailedLaunchData(successorData(false));
  assert.equal(unclaimed.failure.instance, 'not_initialized'); assert.equal(unclaimed.failure.claimStatus, 'not_claimed');
  assert.deepEqual(unclaimed.settlement.consumed, budget(0)); assert.deepEqual(unclaimed.settlement.released, budget(1));
});
test('unavailable setup cannot borrow an original join, initialized identity, no-spawn or fabricated claim', () => {
  const source = successorData(true), { failureDigest: _digest, ...core } = source.failure;
  for (const changed of [
    { ...core, nativeClosure: { kind: 'linux_original_join', lifecycleRawRef: ref('raw'), lifecycleProjectionRef: ref('projection') } },
    { ...core, claimStatus: 'not_claimed' }, { ...core, reason: 'transport_failure' },
    { ...core, instance: 'initialized', instanceIdentityRef: ref('invented identity'), instanceIdentityDigest: ref('invented identity digest') },
    { ...core, closure: 'plan_quiescent', noSpawnEvidenceRef: ref('not a created process') },
    { ...core, disposition: 'owning_call_not_dispatched', stoppedItemId: 'invented audit', owningCallClosureCause: { kind: 'original_call_deadline', deadlineMs: 1 } }
  ]) assert.throws(() => mcpServerFailedLaunchData({ ...source, failure: { ...changed, failureDigest: ref(changed) } }));
  assert.throws(() => mcpServerFailedLaunchData({ ...source, claim: undefined }));
});

test('a genuinely unclaimed no-spawn local failure releases only its unused reservation at zero without inventing claim fields', () => {
  const source = failedData(false), before = ref(source), local = mcpServerFailedLaunchData(source);
  assert.equal(ref(source), before); assert.equal(local.failure.claimStatus, 'not_claimed');
  assert.equal('claimedJournalSeq' in local.failure, false);
  assert.deepEqual(local.settlement.consumed, budget(0)); assert.deepEqual(local.settlement.released, budget(1));
  assert.deepEqual(local.settlement.budgetConsumedAfter, budget(4)); assert.deepEqual(local.settlement.budgetReservedAfter, budget(1));
  assert.deepEqual(local.terminal.budgetDelta, budget(0)); assert.equal(local.terminal.phase, 'failed');
  for (const key of ['dispatchId', 'brokerFenceTokenDigest', 'sandboxLaunchSpecRef', 'stateOwnerEpoch', 'supervisorInstanceId'])
    assert.equal(Object.hasOwn(local.terminal, key), false);
});

test('a claimed local launch remains charged once and the data planner cannot turn it into the zero branch', () => {
  const source = failedData(true), local = mcpServerFailedLaunchData(source);
  const claim = source.claim; assert(claim);
  assert.deepEqual(local.settlement.consumed, budget(1)); assert.deepEqual(local.settlement.released, budget(1));
  assert.deepEqual(local.settlement.budgetConsumedAfter, budget(5)); assert.deepEqual(local.settlement.budgetReservedAfter, budget(1));
  assert.equal(local.terminal.dispatchId, claim.dispatchId); assert.equal(local.failure.claimedJournalSeq, claim.seq);
  assert.throws(() => mcpServerFailedLaunchData({ ...source, claim: undefined }));
  assert.throws(() => mcpServerFailedLaunchData({ ...failedData(false), claim: source.claim }));
  assert.throws(() => mcpServerFailedLaunchData({ ...source, terminalSeq: claim.seq }));
  assert.throws(() => mcpServerFailedLaunchData({ ...source, settledAt: '2026-10-31T00:00:00.000Z' }));
});
function data(terminalPhase: 'completed' | 'unknown' = 'completed') {
  const launchOpId = mcpServerLaunchOperationId('run', 'batch', 0, 'call', ref('registry manifest'), 0);
  const prepared: InvocationJournalEntry = { seq: 5, runId: 'run', opId: launchOpId, opKind: 'mcp-server', attempt: 0,
    leaseEpoch: 1, phase: 'prepared', target: ref('target'), requestRef: ref('request'), grantRef: ref('grant'),
    replayClass: 'retry', budgetDelta: budget(1), timestamp: at };
  const claim: InvocationJournalEntry = { ...prepared, seq: 6, phase: 'dispatch_claimed', dispatchId: 'launch-dispatch', budgetDelta: budget(0) };
  const instanceCore = { schemaVersion: 1, format: 'cliq-mcp-server-instance-identity-v1', runId: 'run', batchItemId: 'batch', callId: 'call', callIndex: 0,
    registrationId: 'server', registryRevisionRef: ref('registry'), registryManifestDigest: ref('registry manifest'), lifecycleSeq: 0,
    launchOpId, launchAttempt: 0, launchDispatchId: 'launch-dispatch', sandboxLaunchSpecRef: ref('spec'), processContainmentRef: ref('containment'),
    initializeDigest: ref('initialize'), capabilityDigest: ref('capability'), probedToolsListDigest: ref('tools'), instanceNonceDigest: ref('nonce'), initializedAt: at };
  const instance = decodeMcpServerInstanceIdentity({ ...instanceCore, identityDigest: ref(instanceCore) });
  const effectCore = { schemaVersion: 1 as const, format: 'cliq-budget-settlement-v1' as const, runId: 'run', opId: 'tool-effect', attempt: 0,
    preparedJournalSeq: 3, terminalJournalSeq: 8, terminalPhase, reserved: budget(1), consumed: budget(1), released: budget(1),
    budgetConsumedBefore: budget(4), budgetConsumedAfter: budget(5), budgetReservedBefore: budget(2), budgetReservedAfter: budget(1), settledAt: done };
  const effect: BudgetSettlementV1 = { ...effectCore, settlementDigest: ref(effectCore) };
  return { effect, prepared, claim, instance, instanceRef: ref(instance), deathRef: ref('data death locator'), observedAt: at,
    nativeClosure: { kind: 'linux_original_join' as const, lifecycleRawRef: ref('data raw locator'), lifecycleProjectionRef: ref('data projection locator') },
    disposition: terminalPhase === 'completed' ? 'completed' as const : 'owning_call_unknown' as const };
}
test('local completion follows the exact original effect by one Journal sequence and charges each reservation once', () => {
  const source = data(), before = ref(source), local = mcpServerTerminalData(source);
  assert.equal(ref(source), before); assert.equal(local.terminalSeq, 9); assert.equal(local.settlement.terminalPhase, 'completed');
  assert.deepEqual(local.settlement.budgetConsumedBefore, budget(5)); assert.deepEqual(local.settlement.budgetConsumedAfter, budget(6));
  assert.deepEqual(local.settlement.budgetReservedBefore, budget(1)); assert.deepEqual(local.settlement.budgetReservedAfter, budget(0));
  assert.equal(local.stopped.cause, 'normal'); assert.equal(local.stopped.instanceIdentityRef, source.instanceRef);
  assert.equal(local.stopped.kind, 'mcp_server_stopped'); assert.equal(local.terminalPlan.schemaKind, 'cliq-mcp-server-launch-receipt-v1');
});
test('UNKNOWN keeps the original whole effect charge and creates only the local owning-call-unknown failure audit', () => {
  const source = data('unknown'), before = ref(source), local = mcpServerTerminalData(source);
  assert.equal(ref(source), before); assert.equal(source.effect.terminalPhase, 'unknown'); assert.equal(local.settlement.terminalPhase, 'failed');
  assert.deepEqual(local.settlement.budgetConsumedAfter, budget(6)); assert.equal(local.terminalPlan.schemaKind, 'cliq-mcp-server-launch-failure-v1');
  assert.equal('disposition' in local.stopped && local.stopped.disposition, 'owning_call_unknown');
  assert.equal(local.stopped.cause, 'lease_release'); assert.equal(local.stopped.callId, 'call');
});
test('terminal data rejects refunds, shared launch/effect identities, changed instance and wrong branch', () => {
  const source = data();
  for (const effect of [{ ...source.effect, consumed: budget(0) }, { ...source.effect, released: budget(0) },
    { ...source.effect, budgetConsumedAfter: budget(4) }, { ...source.effect, terminalJournalSeq: source.claim.seq },
    { ...source.effect, opId: source.prepared.opId }, { ...source.effect, terminalPhase: 'unknown' as const }])
    assert.throws(() => mcpServerTerminalData({ ...source, effect }));
  assert.throws(() => mcpServerTerminalData({ ...source, instanceRef: ref('another instance') }));
  assert.throws(() => mcpServerTerminalData({ ...source, observedAt: '2026-11-01T00:02:00.000Z' }));
});
