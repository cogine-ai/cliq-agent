import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { RunSnapshotV1 } from '../kernel/types.js';
import { manualInvocationPresentation } from './mcp-presentation.js';

test('all human consumers present the exact manual invocation and terminal risk from the immutable wait', () => {
  const ref = 'a'.repeat(64), at = '2026-11-01T00:00:00.000Z';
  const wait = { schemaVersion: 1, kind: 'reconciliation', runId: 'run-1', createdFromRevision: 5, createdAt: at, frontierRef: ref,
    subject: { kind: 'invocation', recovery: 'manual', opKind: 'mcp', opId: 'mcp-calendar', attempt: 0 },
    probeState: { phase: 'manual_only', automaticProbeCount: 0, userProbeCount: 0 } };
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
  const snapshot: RunSnapshotV1 = { schemaVersion: 1, operation: 'agent', latestRunItemSeq: 3,
    run: { id: 'run-1', sessionId: 'session-1', specRef: ref, status: 'waiting', nextStep: 'agent', waitingReason: 'reconciliation',
      waitingOnRef: canonicalSha256(wait), revision: 6, leaseEpoch: 1, latestCheckpointId: 'checkpoint-1', frontierRef: ref,
      budgetReserved: { ...budget, toolCalls: 0 }, budgetConsumed: budget, repairCount: 0, cancelRequested: false,
      createdAt: at, deadlineAt: at, updatedAt: at } };
  const shown = manualInvocationPresentation(snapshot, wait);
  assert.equal(shown.reconciliation, 'manual');
  assert.match(shown.text, /"mcp-calendar" · attempt 0/u);
  assert.match(shown.text, /effect may have occurred/u);
  assert.match(shown.text, /result will not be used/u);
  assert.match(shown.text, /stops this Run and retains its original charge/u);
  assert.match(shown.text, new RegExp(`--wait ${snapshot.run.waitingOnRef} --resolution abandon_run --acknowledge-exact-risk`, 'u'));
  assert.equal(manualInvocationPresentation({...snapshot,run:{...snapshot.run,stopIntentRef:ref,cancelRequested:true}},wait).text,shown.text,
    'an existing higher-priority Stop still permits terminal-only exact-risk acknowledgement');
  for (const changed of [{ ...wait, subject: { ...wait.subject, opId: 'other' } }, { ...wait, runId: 'other' },
    { ...wait, subject: { kind: 'publication' } }, { ...wait, probeState: { ...wait.probeState, userProbeCount: 1 } }])
    assert.throws(() => manualInvocationPresentation(snapshot, changed));
  assert.throws(() => manualInvocationPresentation({ ...snapshot, operation: 'delivery' }, wait));
});
