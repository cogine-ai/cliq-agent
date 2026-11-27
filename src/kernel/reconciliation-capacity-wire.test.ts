import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { decodeInstalledControlRequest, decodeInstalledControlResponse } from './control-wire.js';

// Closed wire data only; retryable backpressure grants no automatic retry,
// target selection, nonce, StateOwner or permission to repeat an effect.
test('only run.reconcile accepts the exact shared inspection-capacity refusal', () => {
  const core = { protocolVersion: 1, method: 'run.reconcile', requestId: '01900000-0000-7000-8000-000000000001',
    runId: 'run', expectedRevision: 4, waitingOnRef: 'a'.repeat(64), resolution: { kind: 'probe_now' } };
  const request = decodeInstalledControlRequest({ ...core, requestDigest: canonicalSha256(core) });
  const response = { protocolVersion: 1, ok: false, method: 'run.reconcile', error: { schemaVersion: 1, code: 'RESOURCE_EXHAUSTED',
    retryable: true, resourceKind: 'reconciliation_probes', retryAfterMs: 1000, messageCode: 'run.reconciliation_capacity' } };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const change of [{ retryable: false }, { retryAfterMs: 999 }, { resourceKind: 'run_queue' }, { resourceKind: 'state_storage' },
    { messageCode: 'run.queue_capacity' }, { code: 'RATE_LIMITED' }, { probeNonceDigest: 'b'.repeat(64) }, { automaticRetry: true }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, error: { ...response.error, ...change } }, request));
  for (const method of ['mcp.list', 'session.list', 'supervisor.status'] as const)
    assert.throws(() => decodeInstalledControlResponse({ ...response, method }, { protocolVersion: 1, method }));
});
