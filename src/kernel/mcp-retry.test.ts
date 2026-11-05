import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { identityHash } from './identity.js';
import { decodeMcpHttpRetryClaimIdentity, decodeMcpJoinedDispatchData, decodeMcpRetryDispatchClosure, mcpRetryState, mcpRetryTerminalCause, mcpRetryPositiveFailureAction, mcpRetryLastClaimedTerminal } from './mcp-retry.js';
import { decodeWireJournal } from './control-wire-data.js';
import type { InvocationJournalEntry } from './types.js';
const ref = (name: string) => canonicalSha256(name), epoch = Date.parse('2026-11-03T00:00:00.000Z');
const at = (offset: number) => new Date(epoch + offset).toISOString();
const budget = { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, zero = { ...budget, toolCalls: 0 };
const policy = { maxDispatchedAttempts: 3, postAttemptDelaysMs: [500, 2000] };
function prepared(attempt: number, seq: number, offset: number): InvocationJournalEntry {
  return { runId: 'run', opId: 'op', opKind: 'mcp', attempt, seq, leaseEpoch: attempt + 1, phase: 'prepared', target: ref('target'),
    requestRef: ref('request'), replayClass: 'retry', idempotencyKey: identityHash('cliq-mcp-tool-idempotency-v1', 'run', 'op', ref('registry'), 'effect'),
    grantRef: ref(`grant-${attempt}`), budgetDelta: budget, timestamp: at(offset),
    ...(attempt ? { evidenceRef: ref(`closure-${attempt - 1}`), evidenceDigest: ref(`closure-semantic-${attempt - 1}`) } : {}) };
}
function unknown(attempt: number, seq: number, offset: number): InvocationJournalEntry[] {
  const first = prepared(attempt, seq, offset), claim: InvocationJournalEntry = { ...first, seq: seq + 1, phase: 'dispatch_claimed',
    dispatchId: `dispatch-${attempt}`, supervisorInstanceId: 'supervisor', stateOwnerEpoch: 1, brokerFenceTokenDigest: ref(`token-${attempt}`),
    evidenceRef: ref(`original-http-claim-${attempt}`), evidenceDigest: ref(`original-http-claim-data-${attempt}`),
    budgetDelta: zero, timestamp: at(offset + 1) };
  const terminal: InvocationJournalEntry = { ...claim, seq: seq + 2, phase: 'unknown', evidenceRef: ref(`ambiguity-${attempt}`),
    evidenceDigest: ref(`ambiguity-semantic-${attempt}`), budgetSettlementRef: ref(`settlement-${attempt}`), budgetDelta: budget, timestamp: at(offset + 2) };
  return [first, claim, terminal];
}
test('MCP retry derives its literal backoffs and three full-once UNKNOWN ceiling without changing original deadline/key', () => {
  const first = unknown(0, 1, 0), deadline = epoch + 10_000;
  assert.deepEqual(mcpRetryState(policy, first, at(501), deadline), { kind: 'backoff', nextAttempt: 1, dispatchedAttempts: 1, notBefore: at(502) });
  assert.deepEqual(mcpRetryState(policy, first, at(502), deadline), { kind: 'ready', nextAttempt: 1, dispatchedAttempts: 1 });
  const second = [...first, ...unknown(1, 4, 502)];
  assert.deepEqual(mcpRetryState(policy, second, at(2503), deadline), { kind: 'backoff', nextAttempt: 2, dispatchedAttempts: 2, notBefore: at(2504) });
  const third = [...second, ...unknown(2, 7, 2504)];
  assert.deepEqual(mcpRetryState(policy, third, at(2600), deadline), { kind: 'exhausted', attempt: 2, dispatchedAttempts: 3, lastPhase: 'unknown' });
  assert.throws(() => mcpRetryState(policy, [...third, prepared(3, 10, 3000)], at(3000), deadline));
  assert.deepEqual(mcpRetryState(policy, first, at(10_000), deadline), { kind: 'deadline', attempt: 0, dispatchedAttempts: 1, lastPhase: 'unknown' });
});
test('MCP retry rejects missing old dispatch closure, changed request/key, unsettled prior attempt and early new preparation', () => {
  const first = unknown(0, 1, 0), next = prepared(1, 4, 502), deadline = epoch + 10_000;
  const { evidenceRef: _evidence, evidenceDigest: _digest, ...missing } = next;
  for (const changed of [missing, { ...next, idempotencyKey: ref('another-key') }, { ...next, requestRef: ref('another-request') }, { ...next, timestamp: at(501) }])
    assert.throws(() => mcpRetryState(policy, [...first, changed], at(502), deadline));
  assert.throws(() => mcpRetryState(policy, [...first.slice(0, 2), next], at(502), deadline));
  assert.throws(() => mcpRetryState({ ...policy, maxDispatchedAttempts: 4 }, first, at(502), deadline));
});
test('two original stdio launch claims stop as actual call resource exhaustion without inventing a third productive attempt', () => {
  const entries = [...unknown(0, 1, 0), ...unknown(1, 4, 502)], before = structuredClone(entries);
  const state = mcpRetryState(policy, entries, at(504), epoch + 30_000);
  assert.equal(state.kind, 'backoff'); assert.equal(state.dispatchedAttempts, 2);
  assert.deepEqual(mcpRetryTerminalCause(state, 'unknown', { used: 2, limit: 2 }), {
    failureKind: 'mcp_call_resource_exhausted', resource: 'server_launch_capacity', used: 2, limit: 2 });
  assert.equal(mcpRetryTerminalCause(state, 'unknown'), undefined, 'HTTP retains its third dispatched-attempt capacity and real backoff');
  assert.equal(mcpRetryTerminalCause(state, 'unknown', { used: 2, limit: 3 }), undefined);
  assert.equal(mcpRetryTerminalCause(state, 'failed', { used: 2, limit: 2 }), undefined, 'positive failure needs its ordinary failed-result owner');
  assert.deepEqual(entries, before, 'the planner appends no fake preparation, claim, failure, refund or charge');
  const third = [...entries, ...unknown(2, 7, 2504)];
  assert.deepEqual(mcpRetryTerminalCause(mcpRetryState(policy, third, at(2506), epoch + 30_000), 'unknown'), { failureKind: 'retry_unknown_exhausted' });
  for (const capacity of [{ used: 3, limit: 2 }, { used: 2, limit: 4 }, { used: 1.5, limit: 2 }])
    assert.throws(() => mcpRetryTerminalCause(state, 'unknown', capacity));
});
test('MCP preclaim refund replaces without a dispatched charge and completed work cannot be retried', () => {
  const first = prepared(0, 1, 0), failed: InvocationJournalEntry = { ...first, seq: 2, phase: 'failed', budgetDelta: zero,
    errorRef: ref('positive-local-failure'), budgetSettlementRef: ref('free-settlement'), timestamp: at(1) };
  assert.deepEqual(mcpRetryState(policy, [first, failed], at(1), epoch + 10_000), { kind: 'ready', nextAttempt: 1, dispatchedAttempts: 0 });
  const current = unknown(0, 1, 0), claim = current[1], final = current[2];
  assert(claim); assert(final);
  const completed: InvocationJournalEntry = { ...claim, phase: 'completed', seq: final.seq, timestamp: final.timestamp,
    budgetDelta: budget, budgetSettlementRef: ref('completed-settlement'), resultRef: ref('known-result') };
  assert.deepEqual(mcpRetryState(policy, [first, claim, completed], at(502), epoch + 10_000), { kind: 'completed', attempt: 0, dispatchedAttempts: 1 });
  assert.throws(() => mcpRetryState(policy, [first, claim, completed, prepared(1, 4, 502)], at(502), epoch + 10_000));
});
test('MCP joined-dispatch data requires complete original transport custody, irreversible revocation and zero matching releases', () => {
  const joined = { kind: 'mcp_http_owner_joined', purpose: 'run', brokerFenceTokenDigest: ref('token'), networkStarted: true, requestStarted: true,
    setupReleased: true, effectReleased: true, completedStages: ['initialize', 'initialized', 'tools_list'], tokenRevoked: true,
    matchingActiveReleaseCount: 0, networkJoined: true, tasksJoined: true };
  assert.equal(decodeMcpJoinedDispatchData(joined).purpose, 'run');
  for (const changed of [{ ...joined, tokenRevoked: false }, { ...joined, matchingActiveReleaseCount: 1 }, { ...joined, networkJoined: false },
    { ...joined, completedStages: ['tools_call'] }, { ...joined, sameSocketClosed: true }]) assert.throws(() => decodeMcpJoinedDispatchData(changed));
  const stdio = { kind: 'mcp_stdio_owner_joined', purpose: 'run', releaseFenceTokenDigest: ref('stdio-token'), execReleased: true, setupReleased: true,
    effectReleased: true, completedStages: ['initialize', 'initialized', 'tools_list'], tokenRevoked: true, matchingActiveReleaseCount: 0,
    processJoined: true, pipesJoined: true, tasksJoined: true, outputCustodyRetired: true };
  assert.equal(decodeMcpJoinedDispatchData(stdio).kind, 'mcp_stdio_owner_joined');
  for (const name of ['processJoined', 'pipesJoined', 'tasksJoined', 'outputCustodyRetired']) assert.throws(() => decodeMcpJoinedDispatchData({ ...stdio, [name]: false }));
});

test('an unclaimed failed replacement preserves the original UNKNOWN while a later real claim supersedes its visible outcome', () => {
  const first = unknown(0, 1, 0), next = prepared(1, 4, 502), failed: InvocationJournalEntry = { ...next, seq: 5, phase: 'failed',
    errorRef: ref('actual preclaim failure'), budgetSettlementRef: ref('actual zero refund'), budgetDelta: zero, timestamp: at(503) };
  delete failed.evidenceRef; delete failed.evidenceDigest;
  const entries = [...first, next, failed], before = structuredClone(entries);
  assert.deepEqual(mcpRetryLastClaimedTerminal(entries), first[2]);
  const expired = mcpRetryState(policy, entries, at(10_000), epoch + 10_000);
  assert.deepEqual(mcpRetryTerminalCause(expired, mcpRetryLastClaimedTerminal(entries)!.phase), { failureKind: 'retry_unknown_exhausted' });
  assert.equal(expired.dispatchedAttempts, 1, 'the unclaimed replacement does not consume productive attempt capacity');
  const later = unknown(1, 4, 502), completed: InvocationJournalEntry = { ...later[2]!, phase: 'completed', resultRef: ref('actual later result') };
  assert.deepEqual(mcpRetryLastClaimedTerminal([...first, ...later.slice(0, 2), completed]), completed);
  const positive: InvocationJournalEntry = { ...later[2]!, phase: 'failed', errorRef: ref('actual later positive failure'), budgetDelta: zero };
  assert.deepEqual(mcpRetryLastClaimedTerminal([...first, ...later.slice(0, 2), positive]), positive);
  assert.equal(mcpRetryLastClaimedTerminal([...first, ...later.slice(0, 2)]), undefined, 'a live later claim cannot borrow the older unused result');
  assert.deepEqual(entries, before, 'original UNKNOWN, charge, claim and closure remain immutable data');
});

test('a real unclaimed replacement can be refunded at terminal without hiding the older UNKNOWN or inventing another attempt', () => {
  const entries = [...unknown(0, 1, 0), prepared(1, 4, 502)], before = structuredClone(entries), deadline = epoch + 10_000;
  const pending = mcpRetryState(policy, entries, at(503), deadline);
  assert.deepEqual(pending, { kind: 'pending', dispatchedAttempts: 1, attempt: 1, phase: 'prepared' });
  assert.deepEqual(mcpRetryTerminalCause(pending, 'unknown', { used: 2, limit: 2 }), {
    failureKind: 'mcp_call_resource_exhausted', resource: 'server_launch_capacity', used: 2, limit: 2 });
  assert.equal(mcpRetryTerminalCause(pending, 'unknown', undefined, { sampledAt: at(9_999), deadlineMs: deadline }), undefined);
  assert.deepEqual(mcpRetryTerminalCause(pending, 'unknown', undefined, { sampledAt: at(10_000), deadlineMs: deadline }), {
    failureKind: 'retry_unknown_exhausted' });
  const claimed = mcpRetryState(policy, [...entries, unknown(1, 4, 502)[1]!], at(10_000), deadline);
  assert.equal(mcpRetryTerminalCause(claimed, 'unknown', { used: 2, limit: 2 }, { sampledAt: at(10_000), deadlineMs: deadline }), undefined,
    'an actual later live claim still requires its own real settlement/closure');
  assert.deepEqual(entries, before, 'terminal planning appends no fictional failed row and charges no unclaimed replacement');
});

test('a positively failed retry retains its call until real stop, capacity or original deadline closes it', () => {
  const first = unknown(0, 1, 0), failed = { ...first[2]!, phase: 'failed' as const, budgetDelta: zero, errorRef: ref('actual-no-release') };
  const entries = [...first.slice(0, 2), failed], before = structuredClone(entries), deadline = epoch + 10_000;
  const backoff = mcpRetryState(policy, entries, at(501), deadline), ready = mcpRetryState(policy, entries, at(502), deadline);
  assert.equal(mcpRetryPositiveFailureAction(backoff, 'failed', false), 'retry');
  assert.equal(mcpRetryPositiveFailureAction(ready, 'failed', false), 'retry');
  assert.equal(mcpRetryPositiveFailureAction(ready, 'failed', true), 'result');
  assert.equal(mcpRetryPositiveFailureAction(ready, 'failed', false, { used: 2, limit: 2 }), 'result');
  assert.equal(mcpRetryPositiveFailureAction(mcpRetryState(policy, entries, at(10_000), deadline), 'failed', false), 'result');
  assert.throws(() => mcpRetryPositiveFailureAction(ready, 'unknown', false));
  assert.throws(() => mcpRetryPositiveFailureAction(ready, 'failed', false, { used: 3, limit: 2 }));
  assert.deepEqual(entries, before, 'selection never changes the actual failed settlement or issues a new claim');
});

test('three real positive post-claim failures exhaust productive capacity despite zero consumption', () => {
  const positive = (attempt: number, seq: number, offset: number) => {
    const rows = unknown(attempt, seq, offset);
    delete rows[0]!.evidenceRef; delete rows[0]!.evidenceDigest;
    rows[2] = { ...rows[2]!, phase: 'failed', errorRef: ref(`positive-${attempt}`), budgetDelta: zero };
    return rows;
  };
  const first = positive(0, 1, 0), second = [...first, ...positive(1, 4, 502)], third = [...second, ...positive(2, 7, 2504)];
  assert.equal(mcpRetryState(policy, second, at(2503), epoch + 10_000).kind, 'backoff');
  const exhausted = mcpRetryState(policy, third, at(2506), epoch + 10_000);
  assert.deepEqual(exhausted, { kind: 'exhausted', dispatchedAttempts: 3, attempt: 2, lastPhase: 'failed' });
  assert.equal(mcpRetryPositiveFailureAction(exhausted, 'failed', false), 'result');
  assert.equal(mcpRetryTerminalCause(exhausted, 'failed'), undefined, 'a positive failure is never rewritten as an ambiguous terminal result');
  assert.throws(() => mcpRetryState(policy, [...third, prepared(3, 10, 3000)], at(3000), epoch + 10_000));
});
test('only later MCP retry preparation can carry its previous dispatch closure pair', () => {
  const next = prepared(1, 4, 502);
  assert.equal(decodeWireJournal(next).evidenceRef, next.evidenceRef);
  for (const changed of [{ ...next, opKind: 'tool' }, { ...next, replayClass: 'manual' }, { ...next, replayClass: 'reconcile' },
    { ...next, attempt: 0 }, { ...next, budgetSettlementRef: ref('not-a-prepared-field') }]) assert.throws(() => decodeWireJournal(changed));
  const { evidenceDigest: _missing, ...partial } = next;
  assert.throws(() => decodeWireJournal(partial));
});
test('HTTP retry claim identity roots its exact original native binding and deadline without a self-reference', () => {
  const binding = { runId: 'run', opId: 'op', attempt: 0, dispatchId: 'dispatch', dispatchJournalSeq: 2, requestRef: ref('request'), requestDigest: ref('request-data'),
    targetRef: ref('target'), targetDigest: ref('target-data'), grantRef: ref('grant'), grantDigest: ref('grant-data'), registryRef: ref('registry'),
    manifestDigest: ref('manifest'), toolContractDigest: ref('contract'), batchItemId: 'batch', callId: 'call', callIndex: 0,
    supervisorInstanceId: 'supervisor', stateOwnerEpoch: 1, workerLaunchId: 'worker', leaseEpoch: 1, brokerFenceTokenDigest: ref('token'), deadlineMs: epoch + 30_000 };
  const core = { schemaVersion: 1, format: 'cliq-mcp-http-retry-claim-identity-v1', binding }, value = { ...core, identityDigest: canonicalSha256(core) };
  const checked = decodeMcpHttpRetryClaimIdentity(value);
  assert.deepEqual(checked.binding, binding); assert.equal(checked.binding.deadlineMs, epoch + 30_000);
  assert.throws(() => decodeMcpHttpRetryClaimIdentity({ ...value, binding: { ...binding, deadlineMs: epoch + 60_000 } }));
  const extra = { ...core, binding: { ...binding, claimIdentityRef: ref('forbidden-back-edge') } };
  assert.throws(() => decodeMcpHttpRetryClaimIdentity({ ...extra, identityDigest: canonicalSha256(extra) }));
  assert.equal(Object.hasOwn(checked.binding, 'claimIdentityRef'), false);
});

test('retry closure admits only the original joined token or strict successor death and exact next attempt', () => {
  const joined = { kind: 'mcp_http_owner_joined', purpose: 'run', brokerFenceTokenDigest: ref('token'), networkStarted: true, requestStarted: true,
    setupReleased: true, effectReleased: true, completedStages: ['initialize', 'initialized', 'tools_list'], tokenRevoked: true,
    matchingActiveReleaseCount: 0, networkJoined: true, tasksJoined: true };
  const core = { schemaVersion: 1, format: 'cliq-mcp-retry-dispatch-closure-v1', runId: 'run', opId: 'op', attempt: 0, nextAttempt: 1,
    preparedJournalSeq: 1, dispatchId: 'dispatch', dispatchJournalSeq: 2, unknownJournalSeq: 3, requestRef: ref('request'), requestDigest: ref('request-data'),
    targetRef: ref('target'), targetDigest: ref('target-data'), grantRef: ref('grant'), grantDigest: ref('grant-data'), registryRef: ref('registry'),
    manifestDigest: ref('manifest'), toolContractDigest: ref('contract'), brokerFenceTokenDigest: ref('token'), unknownEvidenceRef: ref('ambiguity'),
    unknownEvidenceDigest: ref('ambiguity-data'), budgetSettlementRef: ref('settlement'), originalClaimIdentity: {
      kind: 'http_retry_binding', ref: ref('original-identity'), digest: ref('original-identity-data') },
    claimingSupervisorInstanceId: 'original-supervisor', claimingStateOwnerEpoch: 1, inspectorIdentityRef: ref('inspector'),
    inspectorIdentityDigest: ref('inspector-data'), inspectorStateOwnerEpoch: 1, callDeadlineMs: epoch + 30_000, observedAt: at(502),
    kind: 'original_native_joined', joined };
  const stamped = (value: object) => ({ ...value, evidenceDigest: canonicalSha256(value) });
  assert.equal(decodeMcpRetryDispatchClosure(stamped(core)).nextAttempt, 1);
  for (const invalid of [{ ...core, nextAttempt: 2 }, { ...core, inspectorStateOwnerEpoch: 2 },
    { ...core, joined: { ...joined, tokenRevoked: false } }, { ...core, joined: { ...joined, brokerFenceTokenDigest: ref('foreign-token') } },
    { ...core, originalClaimIdentity: { ...core.originalClaimIdentity, kind: 'stdio_instance' } }, { ...core, clock: 'caller-time' }])
    assert.throws(() => decodeMcpRetryDispatchClosure(stamped(invalid)));
  const { joined: _joined, kind: _kind, ...common } = core;
  const successor = { ...common, inspectorStateOwnerEpoch: 2, kind: 'broker_process_domain_dead',
    deathEvidenceRef: ref('death'), deathEvidenceDigest: ref('death-data') };
  assert.equal(decodeMcpRetryDispatchClosure(stamped(successor)).kind, 'broker_process_domain_dead');
  assert.throws(() => decodeMcpRetryDispatchClosure(stamped({ ...successor, inspectorStateOwnerEpoch: 1 })));
  assert.throws(() => decodeMcpRetryDispatchClosure({ ...stamped(core), callDeadlineMs: epoch + 60_000 }));
});
