import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeWireRun, decodeWireSession, decodeWireCheckpoint, decodeWireEvent, decodeWireJournal, decodeWireBudget,
  decodeWireArtifactDescriptor, decodeWireGrantSummary, decodeWireRuntimeBundleSummary,
  decodeWireRunItemReference, decodeWireSessionItem, assertControlWireJson } from './control-wire-data.js';
import { decodeInvocationJournalEntry, decodeBudgetUsage } from '../state/invariants.js';
import { KernelStorageError } from '../state/errors.js';

// Pure public data only. These fixtures provide no installed peer, owner,
// execution grant, retained artifact membership or physical retirement proof.
const at = '2026-10-18T00:00:00.000Z';
const ref = 'a'.repeat(64);
const budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const queued = { id: 'run-1', sessionId: 'session-1', specRef: ref, status: 'queued', nextStep: 'agent',
  frontierRef: ref, revision: 1, leaseEpoch: 0, latestCheckpointId: 'checkpoint-1',
  budgetReserved: budget, budgetConsumed: budget, repairCount: 0, cancelRequested: false,
  createdAt: at, deadlineAt: at, updatedAt: at } as const;

test('public Run data closes the current status and metadata matrix without conferring authority', () => {
  assert.deepEqual(decodeWireRun(queued), queued);
  const { frontierRef: _frontier, ...base } = queued;
  const terminal = { ...base, status: 'succeeded', nextStep: null, resultRef: ref, terminalReason: 'verified' };
  assert.deepEqual(decodeWireRun(terminal), terminal);
  for (const value of [{ ...queued, status: 'running' }, { ...queued, waitingOnRef: ref },
    { ...queued, cancelRequested: 1 }, { ...queued, authority: 'not a grant' },
    { ...terminal, frontierRef: ref }, { ...terminal, stopIntentRef: ref },
    { ...terminal, terminalReason: 'cancelled_by_user' }, { ...terminal, cancelRequested: true }])
    assert.throws(() => decodeWireRun(value), TypeError);
});

test('public Run state data preserves waiting, running and both stopped terminal branches', () => {
  const { frontierRef: _frontier, ...base } = queued;
  for (const run of [{ ...queued, status: 'running', activeWorkerLaunchId: 'launch-1' },
    { ...queued, status: 'waiting', waitingReason: 'reconciliation', waitingOnRef: ref },
    { ...base, status: 'completed_unverified', nextStep: null, resultRef: ref, terminalReason: 'no_required_verifier' },
    { ...base, status: 'failed', nextStep: null, terminalDetailRef: ref, stopIntentRef: ref, terminalReason: 'runtime_failed' },
    { ...base, status: 'cancelled', nextStep: null, terminalDetailRef: ref, stopIntentRef: ref, terminalReason: 'parent_cancelled' }])
    assert.deepEqual(decodeWireRun(run), run);
  for (const run of [{ ...queued, status: 'waiting' }, { ...queued, activeWorkerLaunchId: 'launch-1' },
    { ...base, status: 'cancelled', nextStep: null, terminalDetailRef: ref, terminalReason: 'cancelled_by_user' },
    { ...base, status: 'failed', nextStep: null, terminalDetailRef: ref, stopIntentRef: ref, terminalReason: 'verified' },
    { ...queued, budgetReserved: { ...budget, costMicros: 0.5 } }, { ...queued, revision: 0 },
    { ...queued, createdAt: '2026-10-18T00:00:00Z' }, { ...queued, parentRunId: 'e\u0301' }])
    assert.throws(() => decodeWireRun(run), TypeError);
});

test('public history data preserves Session lineage and binds historical events to their captured Run', () => {
  const session = { schemaVersion: 1, id: 'session-1', workspaceIdentityRef: ref, contextProjectionRef: ref,
    parentSessionId: 'parent-1', forkedThroughItemSeq: 2, contextRevision: 1, latestItemSeq: 3, createdAt: at, updatedAt: at };
  assert.deepEqual(decodeWireSession(session), session);
  assert.throws(() => decodeWireSession({ ...session, forkedThroughItemSeq: 4 }), TypeError);
  const { parentSessionId: _parent, ...noParent } = session;
  assert.throws(() => decodeWireSession(noParent), TypeError);
  const checkpoint = { schemaVersion: 1, id: 'checkpoint-1', runId: 'run-1', basedOnRunRevision: 0,
    runItemSeq: 0, journalSeq: 0, contextManifestRef: ref, workspaceStateRef: ref, reason: 'initial', createdAt: at };
  assert.deepEqual(decodeWireCheckpoint(checkpoint), checkpoint);
  assert.throws(() => decodeWireCheckpoint({ ...checkpoint, reason: 'restore' }), TypeError);
  const snapshot = { schemaVersion: 1, operation: 'agent', run: { ...queued, revision: 3 }, latestRunItemSeq: 4 } as const;
  const event = { schemaVersion: 1, kind: 'state_changed', runId: 'run-1', eventSeq: 1, runRevision: 1,
    status: 'queued', nextStep: 'agent', frontierRef: ref, latestRunItemSeq: 2, occurredAt: at };
  assert.deepEqual(decodeWireEvent(event, snapshot), event);
  for (const value of [{ ...event, runId: 'other' }, { ...event, runRevision: 4 },
    { ...event, latestRunItemSeq: 5 }, { ...event, kind: 'provider_delta' }])
    assert.throws(() => decodeWireEvent(value, snapshot), TypeError);
  const progress = { schemaVersion: 1, kind: 'progress', runId: 'run-1', eventSeq: 2, observedRunRevision: 2,
    phase: 'verify', completedUnits: 5, totalUnits: 4, occurredAt: at };
  assert.deepEqual(decodeWireEvent(progress, snapshot), progress);
});

test('one shared Journal decoder preserves closed phases and the storage error projection', () => {
  const prepared = { seq: 1, runId: 'run-1', opId: 'op-1', opKind: 'tool', attempt: 0, leaseEpoch: 1,
    phase: 'prepared', target: 'tool', requestRef: ref, replayClass: 'retry', budgetDelta: budget, timestamp: at };
  const claim = { ...prepared, phase: 'dispatch_claimed', dispatchId: 'dispatch-1', supervisorInstanceId: 'supervisor-1', stateOwnerEpoch: 1 };
  for (const entry of [prepared, claim, { ...claim, phase: 'completed', resultRef: ref, budgetSettlementRef: ref },
    { ...claim, phase: 'unknown', evidenceRef: ref, evidenceDigest: ref, budgetSettlementRef: ref },
    { ...claim, phase: 'abandoned', attestationRef: ref, budgetSettlementRef: ref },
    { ...claim, phase: 'failed', opKind: 'verifier', errorRef: ref, budgetSettlementRef: ref },
    { ...prepared, phase: 'failed', errorRef: ref, budgetSettlementRef: ref }]) {
    assert.deepEqual(decodeWireJournal(entry), entry);
    assert.deepEqual(decodeInvocationJournalEntry(entry), entry);
  }
  for (const entry of [{ ...prepared, resultRef: ref }, { ...claim, phase: 'completed', budgetSettlementRef: ref },
    { ...claim, phase: 'unknown', evidenceRef: ref, budgetSettlementRef: ref },
    { ...claim, phase: 'failed', errorRef: ref, budgetSettlementRef: ref },
    { ...prepared, phase: 'failed', errorRef: ref, budgetSettlementRef: ref, budgetDelta: { ...budget, toolCalls: 1 } }]) {
    assert.throws(() => decodeWireJournal(entry), TypeError);
    assert.throws(() => decodeInvocationJournalEntry(entry), error => error instanceof KernelStorageError && error.code === 'STATE_TRANSITION_INVALID');
  }
  assert.deepEqual(decodeWireBudget(budget), budget);
  assert.throws(() => decodeWireBudget({ ...budget, toolCalls: -1 }), TypeError);
  assert.throws(() => decodeBudgetUsage({ ...budget, toolCalls: -1 }), {
    name: 'KernelStorageError', code: 'STATE_TRANSITION_INVALID', message: 'BudgetUsage.toolCalls must be at least 0' });
  assert.throws(() => decodeInvocationJournalEntry({ ...prepared, resultRef: ref }), {
    name: 'KernelStorageError', code: 'STATE_TRANSITION_INVALID', message: 'Journal(prepared).resultRef is not legal in this state' });
  // Retained-data callers historically accept safe bigint inputs. Wire JSON
  // excludes them before this shared decoder, without changing storage calls.
  const retained = { ...prepared, seq: 1n, attempt: 0n };
  assert.equal(decodeInvocationJournalEntry(retained), retained);
});

test('public descriptors and summaries close all fields without importing the underlying authority', () => {
  const descriptor = { schemaVersion: 1, ref, digest: ref, sizeBytes: 3, mediaType: 'text/plain' };
  assert.deepEqual(decodeWireArtifactDescriptor(descriptor), descriptor);
  assert.throws(() => decodeWireArtifactDescriptor({ ...descriptor, digest: 'b'.repeat(64) }), TypeError);
  assert.throws(() => decodeWireArtifactDescriptor({ ...descriptor, mediaType: 'a'.repeat(129) }), TypeError);
  const bundle = { schemaVersion: 1, runtimeBundleRef: ref, bundleDigest: ref, bundleVersion: '1.0.0' };
  assert.deepEqual(decodeWireRuntimeBundleSummary(bundle), bundle);
  assert.throws(() => decodeWireRuntimeBundleSummary({ ...bundle, bundleDigest: 'b'.repeat(64) }), TypeError);
  const grant = { schemaVersion: 1, grantId: 'grant-1', state: 'active', targetKind: 'execution_identity_read',
    purpose: 'verifier', targetDigest: ref, useCount: 0, rowVersion: 1, createdAt: at, expiresAt: '2026-10-18T01:00:00.000Z' };
  assert.deepEqual(decodeWireGrantSummary(grant), grant);
  assert.deepEqual(decodeWireGrantSummary({ ...grant, state: 'consumed', useCount: 1, rowVersion: 2, consumedAt: at }),
    { ...grant, state: 'consumed', useCount: 1, rowVersion: 2, consumedAt: at });
  for (const bad of [{ ...grant, consumedAt: at }, { ...grant, useCount: 1 }, { ...grant, purpose: 'source' },
    { ...grant, state: 'revoked', rowVersion: 2, revokedAt: '2026-10-17T00:00:00.000Z' }, { ...grant, ownerPrincipalId: 'not public' }])
    assert.throws(() => decodeWireGrantSummary(bad), TypeError);
  const item = { schemaVersion: 1, itemId: 'item-1', itemSeq: 1, payloadRef: ref, payloadDigest: ref, createdAt: at };
  assert.deepEqual(decodeWireRunItemReference(item), item);
  assert.throws(() => decodeWireRunItemReference({ ...item, payloadDigest: 'b'.repeat(64) }), TypeError);
  const { payloadDigest: _digest, ...sessionItem } = item;
  assert.deepEqual(decodeWireSessionItem({ ...sessionItem, sessionId: 'ancestor-1', kind: 'run_terminal' }),
    { ...sessionItem, sessionId: 'ancestor-1', kind: 'run_terminal' });
});

test('control data rejects accessors, hidden fields, sparse arrays and non-JSON values before reading them', () => {
  let read = false;
  const getter = Object.defineProperty({ ...queued }, 'id', { enumerable: true, get() { read = true; return 'run-1'; } });
  assert.throws(() => decodeWireRun(getter), TypeError); assert.equal(read, false);
  for (const value of [new Date(), [1, , 3], { x: undefined }, { x: 1n }, { x: Infinity },
    Object.defineProperty({}, 'x', { value: 1 }), { [Symbol('x')]: 1 }]) assert.throws(() => assertControlWireJson(value), TypeError);
});
