import assert from 'node:assert/strict';
import { test } from 'node:test';
import { projectInstalledRunProgress, projectInstalledSupervisorStatus } from './installed-run-progress.js';

const sensitive = 'untrusted-provider-prompt-secret-path-error';
function cut() {
  return { snapshot: { run: { status: 'running', revision: 4, nextStep: 'agent', leaseEpoch: 1,
    activeWorkerLaunchId: sensitive, specRef: sensitive, objective: sensitive } },
    journal: [{ opKind: 'model', phase: 'prepared', attempt: 0, seq: 1, requestRef: sensitive, target: sensitive },
      { opKind: 'model', phase: 'dispatch_claimed', attempt: 0, seq: 2, error: sensitive }],
    nextJournalSeq: 2, highWaterJournalSeq: 2,
    checkpoints: [{ reason: 'initial', workspaceStateRef: sensitive }], providerResponse: sensitive };
}

test('installed Run progress retains only bounded closed public state, counters and Journal tuples', () => {
  assert.deepEqual(projectInstalledRunProgress(cut(), { requestsReceived: 0, providerFailure: false, raw: sensitive }), {
    diagnosticOnly: true, kind: 'public_progress', requestsReceived: 0, providerFailure: false,
    run: { status: 'running', revision: 4, nextStep: 'agent', leaseEpoch: 1, waitingReason: null,
      hasActiveWorker: true, hasStopIntent: false, hasResult: false },
    journal: { rowCount: 2, pageComplete: true, phaseCounts: { prepared: 1, dispatch_claimed: 1, completed: 0,
      failed: 0, unknown: 0, abandoned: 0 }, opKindCounts: { model: 2, tool: 0, 'mcp-server': 0, mcp: 0, verifier: 0, publish: 0 },
      tail: [['model', 'prepared', 0, 1], ['model', 'dispatch_claimed', 0, 2]] },
    checkpoints: { count: 1, automatic: 0 },
  });
  assert(!JSON.stringify(projectInstalledRunProgress(cut(), { requestsReceived: 1, providerFailure: false })).includes(sensitive));
});

test('progress projection refuses unknown enums, invalid counters and oversized pages without echoing input', () => {
  const cases: Array<[unknown, unknown]> = [
    [{ ...cut(), snapshot: { run: { ...cut().snapshot.run, status: sensitive } } }, { requestsReceived: 0, providerFailure: false }],
    [{ ...cut(), snapshot: { run: { ...cut().snapshot.run, nextStep: sensitive } } }, { requestsReceived: 0, providerFailure: false }],
    [{ ...cut(), snapshot: { run: { ...cut().snapshot.run, revision: undefined } } }, { requestsReceived: 0, providerFailure: false }],
    [{ ...cut(), journal: [{ ...cut().journal[0], phase: sensitive }] }, { requestsReceived: 0, providerFailure: false }],
    [{ ...cut(), journal: Array.from({ length: 257 }, () => cut().journal[0]) }, { requestsReceived: 0, providerFailure: false }],
    [{ ...cut(), checkpoints: [{ reason: sensitive }] }, { requestsReceived: 0, providerFailure: false }],
    [{ ...cut(), checkpoints: Array.from({ length: 257 }, () => cut().checkpoints[0]) }, { requestsReceived: 0, providerFailure: false }],
    [cut(), { requestsReceived: -1, providerFailure: false }], [cut(), { requestsReceived: 0, providerFailure: sensitive }],
    [{ ...cut(), nextJournalSeq: Number.MAX_SAFE_INTEGER + 1 }, { requestsReceived: 0, providerFailure: false }],
  ];
  for (const [input, counters] of cases) assert.deepEqual(projectInstalledRunProgress(input, counters),
    { diagnosticOnly: true, kind: 'public_progress_projection_refused' });
});

test('a larger valid Journal keeps complete counts and only its final sixteen closed tuples', () => {
  const input = { ...cut(), journal: Array.from({ length: 32 }, (_, index) =>
    ({ opKind: 'model', phase: 'completed', attempt: 0, seq: index + 1, resultRef: sensitive })),
    nextJournalSeq: 32, highWaterJournalSeq: 32 };
  const projected = projectInstalledRunProgress(input, { requestsReceived: 2, providerFailure: false });
  assert(projected && typeof projected === 'object' && 'journal' in projected);
  assert.deepEqual(projected.journal, { rowCount: 32, pageComplete: true,
    phaseCounts: { prepared: 0, dispatch_claimed: 0, completed: 32, failed: 0, unknown: 0, abandoned: 0 },
    opKindCounts: { model: 32, tool: 0, 'mcp-server': 0, mcp: 0, verifier: 0, publish: 0 },
    tail: Array.from({ length: 16 }, (_, index) => ['model', 'completed', 0, index + 17]) });
});

test('Supervisor status diagnostic contains only the existing closed health and queue counters', () => {
  const status = { health: 'degraded', queue: { queuedRuns: 1, runningRuns: 0, capacity: 1 }, incompatiblePinnedRunCount: 0,
    error: sensitive, activeRuntimeBundle: sensitive };
  assert.deepEqual(projectInstalledSupervisorStatus(status), { diagnosticOnly: true, kind: 'supervisor_status', health: 'degraded',
    queue: { queuedRuns: 1, runningRuns: 0, capacity: 1 }, incompatiblePinnedRunCount: 0 });
  assert.deepEqual(projectInstalledSupervisorStatus({ ...status, health: 'recovering' }),
    { diagnosticOnly: true, kind: 'supervisor_status_projection_refused' });
  assert(!JSON.stringify(projectInstalledSupervisorStatus(status)).includes(sensitive));
});
