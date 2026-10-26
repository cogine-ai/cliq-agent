import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeInstalledControlRequest, decodeInstalledControlResponse } from './control-wire.js';
import { canonicalJsonBytes } from './canonical.js';
import { measureBoundedJsonValue, parseJsonStrict } from './json.js';

test('public Run and authorization list requests use closed normalized filters and the original 100-row ceiling', () => {
  assert.deepEqual(decodeInstalledControlRequest({ protocolVersion: 1, method: 'run.list', statuses: ['waiting', 'queued'] }),
    { protocolVersion: 1, method: 'run.list', statuses: ['queued', 'waiting'], limit: 50 });
  assert.deepEqual(decodeInstalledControlRequest({ protocolVersion: 1, method: 'authorization.list', state: 'active', limit: 100 }),
    { protocolVersion: 1, method: 'authorization.list', state: 'active', limit: 100 });
  for (const value of [
    { method: 'run.list', statuses: ['queued', 'queued'] }, { method: 'run.list', statuses: ['new_status'] },
    { method: 'run.list', operation: 'shell' }, { method: 'run.list', limit: 101 },
    { method: 'authorization.list', state: 'expired' }, { method: 'authorization.list', targetKind: 'credential' },
    { method: 'authorization.list', cursor: '' }, { method: 'authorization.list', principalId: 'caller-authority' },
  ]) assert.throws(() => decodeInstalledControlRequest({ protocolVersion: 1, ...value }));
});

test('a complete 100-entry maximum-width Run or grant page fits the unchanged wire and JSON aggregate bounds', t => {
  const ref = 'a'.repeat(64), id = (index: number) => '\u0001'.repeat(123) + Array.from(index.toString(7).padStart(5, '0'), value =>
    String.fromCharCode(1 + Number(value))).join('');
  const at = '2026-10-26T00:00:00.000Z', later = '2026-10-27T00:00:00.000Z';
  const budget = { modelTokens: Number.MAX_SAFE_INTEGER, costMicros: Number.MAX_SAFE_INTEGER,
    toolCalls: Number.MAX_SAFE_INTEGER, repairAttempts: Number.MAX_SAFE_INTEGER };
  // Closed response-data boundary only, not an admissible Run/grant or native
  // observation. Control characters maximize actual JSON escaping overhead.
  const runs = Array.from({ length: 100 }, (_, index) => ({ schemaVersion: 1, operation: 'agent', latestRunItemSeq: Number.MAX_SAFE_INTEGER,
    run: { id: id(index), sessionId: id(200), parentRunId: id(300), specRef: ref, status: 'waiting', nextStep: 'tool',
      frontierRef: ref, waitingReason: 'reconciliation', waitingOnRef: ref, revision: Number.MAX_SAFE_INTEGER,
      leaseEpoch: Number.MAX_SAFE_INTEGER, latestCheckpointId: id(400), budgetReserved: budget, budgetConsumed: budget,
      repairCount: Number.MAX_SAFE_INTEGER, cancelRequested: true, stopIntentRef: ref, parentCancellationRef: ref,
      createdAt: at, updatedAt: at, deadlineAt: later } }));
  const grants = Array.from({ length: 100 }, (_, index) => ({ schemaVersion: 1, grantId: id(index), state: 'consumed',
    targetKind: 'dependency_install_scripts', purpose: 'dependency_install_scripts', targetDigest: ref, useCount: 1, rowVersion: 2,
    createdAt: at, expiresAt: later, consumedAt: at }));
  for (const [method, entries] of [['run.list', runs], ['authorization.list', grants]] as const) {
    const key = method === 'run.list' ? 'runs' : 'grants';
    const request = decodeInstalledControlRequest({ protocolVersion: 1, method, limit: 100 });
    const value = { protocolVersion: 1, ok: true, result: { method, [key]: entries, nextCursor: '\u0001'.repeat(512) } };
    const bytes = canonicalJsonBytes(value), measured = measureBoundedJsonValue(value);
    assert(bytes.length <= 1_048_576); assert(measured.containerEntries <= 10000); assert(measured.maxContainerDepth <= 32);
    t.diagnostic(JSON.stringify({ method, entries: 100, bytes: bytes.length, ...measured, protocolDataOnly: true }));
    const decoded = decodeInstalledControlResponse(parseJsonStrict(bytes.toString('utf8')), request);
    assert.deepEqual(canonicalJsonBytes(decoded), bytes, 'all original fields and four budget dimensions survive the strict parser');
    assert.throws(() => decodeInstalledControlResponse({ ...value, result: { ...value.result, [key]: entries.slice(0, 99) } }, request), /original page/);
  }
});

test('list responses cannot introduce an extra field or a cursor on an empty materialized page', () => {
  for (const method of ['run.list', 'authorization.list'] as const) {
    const request = decodeInstalledControlRequest({ protocolVersion: 1, method, limit: 1 });
    const result = method === 'run.list' ? { method, runs: [] } : { method, grants: [] };
    assert.deepEqual(decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result }, request),
      { protocolVersion: 1, ok: true, result });
    for (const addition of [{ nextCursor: 'unissued' }, { authority: true }])
      assert.throws(() => decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result: { ...result, ...addition } }, request));
  }
});
