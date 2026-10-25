import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeControlFrame, decodeInstalledControlRequest, decodeInstalledControlResponse,
  CONTROL_METHODS_V1, INSTALLED_CONTROL_FEATURES, UnsupportedExecutionIdentityRequestError } from './control-wire.js';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting, identityHash } from './identity.js';

// Pure wire conformance: no installed selection, peer, grant or execution proof.
test('connected composition ceiling is immutable while the actual Supervisor selects enabled capabilities', () => {
  assert.deepEqual(INSTALLED_CONTROL_FEATURES, ['session.get', 'run.get', 'run.attach', 'supervisor.status', 'credential.finalize',
    'session.create', 'session.list', 'session.fork', 'session.compact', 'session.handoff.create', 'run.submit', 'run.cancel', 'authorization.create', 'authorization.revoke', 'run.result', 'run.diff', 'artifact.get', 'run.apply', 'run.approve', 'run.reconcile']);
  assert.throws(() => Reflect.apply(Array.prototype.push, INSTALLED_CONTROL_FEATURES, ['unexpected.method']));
  assert.throws(() => Reflect.apply(Array.prototype.push, CONTROL_METHODS_V1, ['unexpected.method']));
});

test('Session continuity has one closed wire contract and no Session execution or hidden append authority', () => {
  const compactCore = { protocolVersion: 1, method: 'session.compact', requestId: '019a0012-0000-7000-8000-000000000900', sessionId: 'session',
    expectedContextRevision: 2, fromItemSeq: 1, throughItemSeq: 1, summaryMarkdown: 'e\u0301\r\nsummary', retainedItemIds: ['item'] };
  const compact = { ...compactCore, requestDigest: canonicalSha256(compactCore) };
  assert.deepEqual(decodeInstalledControlRequest(compact), compact, 'wire digest binds original spelling before summary normalization');
  for (const extra of [{ requestId: compact.requestId }, { leaseEpoch: 1 }, { checkpointId: 'not-authority' }, { importRef: 'a'.repeat(64) }])
    assert.throws(() => decodeInstalledControlRequest({ protocolVersion: 1, method: 'session.handoff.create', sessionId: 'session', expectedContextRevision: 2, ...extra }));
  const tooMany = { ...compactCore, retainedItemIds: Array.from({ length: 257 }, (_, index) => `item-${index}`) };
  assert.throws(() => decodeInstalledControlRequest({ ...tooMany, requestDigest: canonicalSha256(tooMany) }));
  for (const method of ['session.append', 'session.resume', 'session.items', 'session.handoff.import'])
    assert.throws(() => decodeInstalledControlRequest({ protocolVersion: 1, method, sessionId: 'session' }));
  const list = { protocolVersion: 1, method: 'session.list', limit: 1 } as const;
  const capacity = { protocolVersion: 1, ok: false, method: 'session.list', error: { schemaVersion: 1, code: 'RESOURCE_EXHAUSTED',
    retryable: true, resourceKind: 'state_storage', retryAfterMs: 1000, messageCode: 'control.list_cut_capacity' } };
  assert.deepEqual(decodeInstalledControlResponse(capacity, list), capacity);
  assert.throws(() => decodeInstalledControlResponse({ ...capacity, error: { ...capacity.error, resourceKind: 'run_queue' } }, list));
  const busy = { protocolVersion: 1, ok: false, method: 'session.list', error: { schemaVersion: 1, code: 'RATE_LIMITED',
    retryable: true, retryAfterMs: 1000, messageCode: 'control.list_cut_busy' } };
  assert.deepEqual(decodeInstalledControlResponse(busy, list), busy);
  assert.throws(() => decodeInstalledControlResponse({ ...busy, error: { ...busy.error, messageCode: 'run.credential_scope_busy' } }, list));
});

test('control wire owns read defaults and closes request fields before retention', () => {
  const request = { protocolVersion: 1, method: 'run.get', runId: 'run-1' };
  const decoded = decodeInstalledControlRequest(request);
  request.runId = 'changed';
  assert.deepEqual(decoded, { protocolVersion: 1, method: 'run.get', runId: 'run-1',
    afterItemSeq: 0, afterJournalSeq: 0, itemLimit: 100, journalLimit: 100, checkpointLimit: 100 });
  assert(Object.isFrozen(decoded));
  for (const bad of [{ ...request, grant: 'not authority' }, { ...request, afterItemSeq: undefined },
    { ...request, itemLimit: 0 }, { ...request, afterJournalSeq: '0' }])
    assert.throws(() => decodeInstalledControlRequest(bad));
  let invoked = false;
  assert.throws(() => decodeInstalledControlRequest(Object.defineProperty({ ...request }, 'runId',
    { enumerable: true, get() { invoked = true; return 'run-1'; } })));
  assert.equal(invoked, false);
});

test('shared control frame parser accepts only complete bounded canonical UTF-8 JSON', () => {
  const bytes = Buffer.from('{"method":"supervisor.status","protocolVersion":1}');
  assert.deepEqual({ ...decodeControlFrame(bytes) as Record<string, unknown> }, { method: 'supervisor.status', protocolVersion: 1 });
  for (const bad of [Buffer.alloc(0), Buffer.from('{"protocolVersion":1,"method":"supervisor.status"}'),
    Buffer.from('{"method":"supervisor.status","method":"run.get","protocolVersion":1}'),
    Buffer.from([0xc0, 0x80]), Buffer.from(' '.repeat(1024 * 1024 + 1))])
    assert.throws(() => decodeControlFrame(bad));
});

test('control history binds contiguous bounded pages and opaque checkpoint cursors to one request', () => {
  const ref = 'a'.repeat(64), at = '2026-10-18T00:00:00.000Z';
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const run = { id: 'run-1', sessionId: 'session-1', specRef: ref, status: 'queued', nextStep: 'agent', frontierRef: ref,
    revision: 2, leaseEpoch: 0, latestCheckpointId: 'checkpoint-1', budgetReserved: budget, budgetConsumed: budget,
    repairCount: 0, cancelRequested: false, createdAt: at, deadlineAt: at, updatedAt: at };
  const snapshot = { schemaVersion: 1, operation: 'agent', run, latestRunItemSeq: 2 };
  const item = { schemaVersion: 1, itemId: 'item-1', itemSeq: 1, payloadRef: ref, payloadDigest: ref, createdAt: at };
  const cursor = Buffer.from('{"checkpointId":"checkpoint-1","createdAt":"2026-10-18T00:00:00.000Z","runId":"run-1","schemaVersion":1}').toString('base64url');
  const request = { protocolVersion: 1, method: 'run.get', runId: 'run-1', itemLimit: 1 } as const;
  const result = { method: 'run.get', snapshot, items: [item], journal: [], checkpoints: [], highWaterItemSeq: 2,
    highWaterJournalSeq: 0, highWaterCheckpointCursor: cursor, nextItemSeq: 1, nextJournalSeq: 0 };
  const response = { protocolVersion: 1, ok: true, result };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const bad of [{ ...result, items: [{ ...item, itemSeq: 2 }] }, { ...result, nextItemSeq: 0 },
    { ...result, items: [item, { ...item, itemId: 'item-2', itemSeq: 2 }], nextItemSeq: 2 },
    { ...result, nextCheckpointCursor: cursor }, { ...result, snapshot: { ...snapshot, run: { ...run, id: 'other' } } }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: bad }, request));
  const prepared = { seq: 1, runId: 'run-1', opId: 'op-1', opKind: 'tool', attempt: 0, leaseEpoch: 1,
    phase: 'prepared', target: 'tool', requestRef: ref, replayClass: 'retry', budgetDelta: budget, timestamp: at };
  const journalPage = { ...result, journal: [prepared], highWaterJournalSeq: 1, nextJournalSeq: 1 };
  assert.doesNotThrow(() => decodeInstalledControlResponse({ ...response, result: journalPage }, request));
  for (const opId of ['e\u0301', '\u0000', '\ud800'])
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...journalPage, journal: [{ ...prepared, opId }] } }, request));
  const overMembers = { ...result, journal: Array.from({ length: 1000 }, (_, index) => ({ ...prepared, seq: index + 1 })),
    highWaterJournalSeq: 1000, nextJournalSeq: 1000 };
  assert.throws(() => decodeInstalledControlResponse({ ...response, result: overMembers }, { ...request, journalLimit: 1000 }), /container entries/u);
  const attach = { protocolVersion: 1, method: 'run.attach', runId: 'run-1', afterEventSeq: 0, limit: 1 } as const;
  const event = { schemaVersion: 1, kind: 'progress', runId: 'run-1', eventSeq: 1, observedRunRevision: 1, phase: 'agent', occurredAt: at };
  const attached = { method: 'run.attach', snapshot, earliestRetainedEventSeq: 1, latestRetainedEventSeq: 2,
    highWaterEventSeq: 2, events: [event], nextEventSeq: 1 };
  assert.doesNotThrow(() => decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result: attached }, attach));
  for (const bad of [{ ...attached, events: [{ ...event, eventSeq: 2 }], nextEventSeq: 2 }, { ...attached, nextEventSeq: 0 }])
    assert.throws(() => decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result: bad }, attach));
});

test('one canonical request decoder covers current methods, not unimplemented capabilities', () => {
  const requestId = '01900000-0000-7000-8000-000000000001';
  const session = { protocolVersion: 1, method: 'session.create', requestId, admissionKey: 'a'.repeat(22), workspacePath: '/workspace' };
  const cancel = { protocolVersion: 1, method: 'run.cancel', requestId, runId: 'run-1', expectedRevision: 2 };
  const create = { protocolVersion: 1, method: 'authorization.create', requestId,
    decision: { kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: 'manifest', toolId: 'node' } } };
  const revoke = { protocolVersion: 1, method: 'authorization.revoke', requestId, grantId: 'grant-1' };
  for (const core of [session, cancel, create, revoke]) {
    const request = { ...core, requestDigest: canonicalSha256(core) };
    assert.deepEqual(decodeInstalledControlRequest(request), request);
    assert.throws(() => decodeInstalledControlRequest({ ...request, requestDigest: 'a'.repeat(64) }));
  }
  for (const decision of [null, [], false]) {
    const core = { ...create, decision }, request = { ...core, requestDigest: canonicalSha256(core) };
    assert.throws(() => decodeInstalledControlRequest(request), error => error instanceof TypeError && !(error instanceof UnsupportedExecutionIdentityRequestError));
  }
  assert.deepEqual(decodeInstalledControlRequest({ protocolVersion: 1, method: 'credential.finalize', requestId,
    operationId: 'a'.repeat(43), attempt: 1, commandDigest: 'b'.repeat(64) }),
  { protocolVersion: 1, method: 'credential.finalize', requestId, operationId: 'a'.repeat(43), attempt: 1, commandDigest: 'b'.repeat(64) });
  assert.throws(() => decodeInstalledControlRequest({ ...cancel, method: 'run.apply' }));
  assert.throws(() => decodeInstalledControlRequest({ ...cancel, method: 'run.approve' }));
  assert.throws(() => decodeInstalledControlRequest({ protocolVersion: 1, method: 'credential.finalize', requestId,
    requestDigest: 'a'.repeat(64), operationId: 'a'.repeat(43), attempt: 1, commandDigest: 'b'.repeat(64) }));
});

test('publication reconciliation wire freezes only the exact no-new-effect probe request', () => {
  const core = { protocolVersion: 1, method: 'run.reconcile', requestId: '01900000-0000-7000-8000-000000000001',
    runId: 'delivery-1', expectedRevision: 9, waitingOnRef: 'a'.repeat(64), resolution: { kind: 'probe_now' } };
  const request = { ...core, requestDigest: canonicalSha256(core) };
  assert.deepEqual(decodeInstalledControlRequest(request), request);
  assert(Object.isFrozen(decodeInstalledControlRequest(request)));
  for (const bad of [{ ...core, expectedRevision: 0 }, { ...core, expectedRevision: Number.MAX_SAFE_INTEGER + 1 },
    { ...core, waitingOnRef: 'not-a-ref' }, { ...core, target: '/not-caller-authority' },
    { ...core, resolution: { kind: 'probe_now', evidenceRef: 'b'.repeat(64) } },
    { ...core, resolution: { kind: 'abandon_run', acknowledgeExactRisk: true } },
    { ...core, resolution: 'probe_now' }])
    assert.throws(() => decodeInstalledControlRequest({ ...bad, requestDigest: canonicalSha256(bad) }));
  assert.throws(() => decodeInstalledControlRequest({ ...request, requestDigest: 'b'.repeat(64) }));
});

test('reconciliation response reports an enqueue, never an inspection result or another wait', () => {
  const ref = 'a'.repeat(64), at = '2026-10-19T00:00:00.000Z';
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const core = { protocolVersion: 1, method: 'run.reconcile', requestId: '01900000-0000-7000-8000-000000000001',
    runId: 'delivery-1', expectedRevision: 9, waitingOnRef: ref, resolution: { kind: 'probe_now' } } as const;
  const request = { ...core, requestDigest: canonicalSha256(core) };
  const run = { id: 'delivery-1', sessionId: 'session-1', specRef: ref, status: 'waiting', waitingReason: 'reconciliation',
    waitingOnRef: 'b'.repeat(64), nextStep: 'delivery', frontierRef: ref, revision: 10, leaseEpoch: 1,
    latestCheckpointId: 'checkpoint-1', budgetReserved: budget, budgetConsumed: budget,
    repairCount: 0, cancelRequested: false, createdAt: at, deadlineAt: at, updatedAt: at };
  const result = { method: 'run.reconcile', snapshot: { schemaVersion: 1, operation: 'delivery', run, latestRunItemSeq: 3 },
    resolution: { kind: 'probe_enqueued', dispatchDigest: 'c'.repeat(64), userProbeCount: 1 } };
  const response = { protocolVersion: 1, ok: true, result };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const changed of [{ id: 'other' }, { revision: 9 }, { revision: 11 }, { waitingOnRef: ref },
    { status: 'queued' }, { waitingReason: 'approval' }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...result,
      snapshot: { ...result.snapshot, run: { ...run, ...changed } } } }, request));
  for (const resolution of [{ ...result.resolution, userProbeCount: 0 }, { ...result.resolution, dispatchDigest: 'bad' },
    { ...result.resolution, evidenceRef: ref }, { kind: 'completed', evidenceRef: ref }, { kind: 'abandoned', evidenceRef: ref }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...result, resolution } }, request));
});

test('reconciliation revision refusal binds the current Run without becoming malformed data or retry permission', () => {
  const ref = 'a'.repeat(64), at = '2026-10-19T00:00:00.000Z';
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const core = { protocolVersion: 1, method: 'run.reconcile', requestId: '01900000-0000-7000-8000-000000000001',
    runId: 'delivery-1', expectedRevision: 9, waitingOnRef: ref, resolution: { kind: 'probe_now' } } as const;
  const request = { ...core, requestDigest: canonicalSha256(core) };
  const snapshot = { schemaVersion: 1, operation: 'delivery', run: { id: core.runId, sessionId: 'session-1', specRef: ref,
    status: 'waiting', waitingReason: 'reconciliation', waitingOnRef: 'b'.repeat(64), nextStep: 'delivery', frontierRef: ref,
    revision: 10, leaseEpoch: 1, latestCheckpointId: 'checkpoint-1', budgetReserved: budget, budgetConsumed: budget,
    repairCount: 0, cancelRequested: false, createdAt: at, deadlineAt: at, updatedAt: at }, latestRunItemSeq: 3 };
  const error = { schemaVersion: 1, code: 'REVISION_CONFLICT', retryable: true, messageCode: 'control.revision_conflict',
    currentRevision: 10, conflict: { resourceKind: 'run', currentSnapshot: snapshot } };
  const response = { protocolVersion: 1, ok: false, method: 'run.reconcile', error };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const bad of [{ ...error, currentRevision: 9 }, { ...error, retryable: false }, { ...error, evidenceRef: ref },
    { ...error, conflict: { resourceKind: 'session', currentSnapshot: snapshot } },
    { ...error, conflict: { resourceKind: 'run', currentSnapshot: { ...snapshot, run: { ...snapshot.run, id: 'other' } } } }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, error: bad }, request));
  assert.throws(() => decodeInstalledControlResponse({ ...response, method: 'run.cancel' }, request));
});

test('control wire binds bounded artifact pages to the original request', () => {
  const digest = 'a'.repeat(64);
  const request = { protocolVersion: 1, method: 'artifact.get', digest, offset: 0, length: 3 } as const;
  const response = { protocolVersion: 1, ok: true, result: { method: 'artifact.get',
    artifact: { schemaVersion: 1, ref: digest, digest, sizeBytes: 3, mediaType: 'text/plain' },
    offset: 0, bytesBase64: 'YWJj', nextOffset: 3, eof: true } };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const result of [{ ...response.result, nextOffset: 2 }, { ...response.result, bytesBase64: 'YWJj\n' },
    { ...response.result, offset: 1 }, { ...response.result, eof: false },
    { ...response.result, artifact: { ...response.result.artifact, digest: 'b'.repeat(64) } }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, result }, request));
});

test('control refusals are closed typed data, not remote exception messages or retry authority', () => {
  const request = { protocolVersion: 1, method: 'run.result', runId: 'run-1' } as const;
  const response = { protocolVersion: 1, ok: false, method: 'run.result', error: { schemaVersion: 1,
    code: 'RESULT_UNAVAILABLE', retryable: true, messageCode: 'run.result_unavailable', runId: 'run-1', status: 'running', currentRevision: 2 } };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const error of [{ ...response.error, runId: 'another' }, { ...response.error, retryable: false },
    { ...response.error, status: 'succeeded' }, { ...response.error, currentRevision: 0 },
    { ...response.error, cause: 'remote exception' }, { ...response.error, code: 'RECOVERY_REQUIRED' }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, error }, request));
  assert.throws(() => decodeInstalledControlResponse({ ...response, method: 'run.diff' }, request));
  const invalid = { protocolVersion: 1, ok: false, method: 'run.result', error: { schemaVersion: 1,
    code: 'INVALID_REQUEST', retryable: false, messageCode: 'control.invalid_request', issues: [{ path: 'request', issueCode: 'invalid_request' }] } };
  assert.deepEqual(decodeInstalledControlResponse(invalid, request), invalid);
  assert.throws(() => decodeInstalledControlResponse({ ...invalid,
    error: { ...invalid.error, issues: [{ path: 'request', issueCode: 'invalid_request', stack: 'not diagnostic data' }] } }, request));
});

test('revision and expired-event refusals carry the exact requested resource and snapshot revision', () => {
  const ref = 'a'.repeat(64), at = '2026-10-18T00:00:00.000Z';
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const snapshot = { schemaVersion: 1, operation: 'agent', run: { id: 'run-1', sessionId: 'session-1', specRef: ref,
    status: 'queued', nextStep: 'agent', frontierRef: ref, revision: 2, leaseEpoch: 0, latestCheckpointId: 'checkpoint-1',
    budgetReserved: budget, budgetConsumed: budget, repairCount: 0, cancelRequested: false, createdAt: at, deadlineAt: at, updatedAt: at }, latestRunItemSeq: 0 };
  const core = { protocolVersion: 1, method: 'run.cancel', requestId: '01900000-0000-7000-8000-000000000001', runId: 'run-1', expectedRevision: 1 } as const;
  const request = { ...core, requestDigest: canonicalSha256(core) };
  const error = { schemaVersion: 1, code: 'REVISION_CONFLICT', retryable: true, messageCode: 'control.revision_conflict',
    currentRevision: 2, conflict: { resourceKind: 'run', currentSnapshot: snapshot } };
  const response = { protocolVersion: 1, ok: false, method: 'run.cancel', error };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const bad of [{ ...error, currentRevision: 1 }, { ...error, retryable: false },
    { ...error, conflict: { resourceKind: 'run', currentSnapshot: { ...snapshot, run: { ...snapshot.run, id: 'other' } } } }])
    assert.throws(() => decodeInstalledControlResponse({ ...response, error: bad }, request));
  const attach = { protocolVersion: 1, method: 'run.attach', runId: 'run-1', afterEventSeq: 0 } as const;
  const expired = { protocolVersion: 1, ok: false, method: 'run.attach', error: { schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED',
    retryable: false, messageCode: 'control.event_cursor_expired', earliestEventSeq: 3, latestEventSeq: 5, snapshot } };
  assert.deepEqual(decodeInstalledControlResponse(expired, attach), expired);
  assert.throws(() => decodeInstalledControlResponse(expired, { ...attach, afterEventSeq: 2 }));
});

test('control hello and result inspection retain exact connected capabilities and artifact references', () => {
  const digest = 'a'.repeat(64);
  const hello = { protocolVersion: 1, method: 'control.hello', clientBuild: 'test',
    controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    requestedFeatureIds: ['run.result', 'run.diff', 'run.apply'] } as const;
  const result = { method: 'control.hello', protocolVersion: 1, serverBuild: 'cliq-installed-v1',
    controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, enabledFeatureIds: ['run.result', 'run.diff'],
    supervisorInstanceId: 'supervisor-1', activeRuntimeBundle: { schemaVersion: 1, runtimeBundleRef: digest, bundleDigest: digest, bundleVersion: '1' } };
  assert.deepEqual(decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result }, hello),
    { protocolVersion: 1, ok: true, result });
  assert.deepEqual(decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result: { ...result, enabledFeatureIds: ['run.apply'] } }, hello),
    { protocolVersion: 1, ok: true, result: { ...result, enabledFeatureIds: ['run.apply'] } });
  for (const enabledFeatureIds of [['run.approve'], ['run.diff', 'run.result'], ['run.result', 'run.result'], ['session.get']])
    assert.throws(() => decodeInstalledControlResponse({ protocolVersion: 1, ok: true, result: { ...result, enabledFeatureIds } }, hello));
  for (const method of ['run.result', 'run.diff'] as const) {
    const descriptor = { schemaVersion: 1, ref: digest, digest, sizeBytes: 0, mediaType: 'application/json' };
    const request = { protocolVersion: 1, method, runId: 'run-1' } as const;
    const result = method === 'run.result' ? { method, runId: 'run-1', result: descriptor, verificationClosureRef: digest }
      : { method, runId: 'run-1', diff: descriptor };
    const response = { protocolVersion: 1, ok: true, result };
    assert.deepEqual(decodeInstalledControlResponse(response, request), response);
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...result, runId: 'another' } }, request));
    assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...result, publishPermit: digest } }, request));
  }
});

test('installed public snapshots, status and authorization results share the same closed response contract', () => {
  const ref = 'a'.repeat(64), at = '2026-10-18T00:00:00.000Z', expiresAt = '2026-10-18T00:01:00.000Z';
  const requestId = '01900000-0000-7000-8000-000000000001';
  const session = { schemaVersion: 1, id: 'session-1', workspaceIdentityRef: ref, contextProjectionRef: ref,
    contextRevision: 1, latestItemSeq: 1, createdAt: at, updatedAt: at };
  const sessionRequest = { protocolVersion: 1, method: 'session.create', requestId, admissionKey: 'a'.repeat(22), workspacePath: '/workspace' } as const;
  const created = { protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: { schemaVersion: 1, session } } };
  assert.deepEqual(decodeInstalledControlResponse(created, { ...sessionRequest, requestDigest: canonicalSha256(sessionRequest) }), created);
  const page = { protocolVersion: 1, ok: true, result: { method: 'session.get', snapshot: { schemaVersion: 1, session }, items: [
    { schemaVersion: 1, sessionId: 'ancestor-1', itemId: 'item-1', itemSeq: 1, kind: 'compaction', payloadRef: ref, createdAt: at }
  ], highWaterItemSeq: 1, nextItemSeq: 1 } };
  const sessionGet = { protocolVersion: 1, method: 'session.get', sessionId: 'session-1' } as const;
  assert.deepEqual(decodeInstalledControlResponse(page, sessionGet), page);
  assert.throws(() => decodeInstalledControlResponse({ ...page, result: { ...page.result, nextItemSeq: 0 } }, sessionGet));
  const bundle = { schemaVersion: 1, runtimeBundleRef: ref, bundleDigest: ref, bundleVersion: '1' };
  const status = { protocolVersion: 1, ok: true, result: { method: 'supervisor.status', health: 'degraded',
    supervisorInstanceId: 'supervisor-1', queue: { queuedRuns: 0, runningRuns: 0, capacity: 0 }, stateSchemaVersion: 1,
    activeRuntimeBundle: bundle, installedRuntimeBundles: [bundle], incompatiblePinnedRunCount: 0 } };
  assert.deepEqual(decodeInstalledControlResponse(status, { protocolVersion: 1, method: 'supervisor.status' }), status);
  assert.throws(() => decodeInstalledControlResponse({ ...status, result: { ...status.result, queue: { ...status.result.queue, permit: true } } },
    { protocolVersion: 1, method: 'supervisor.status' }));
  const grant = { schemaVersion: 1, grantId: 'grant-1', state: 'active', targetKind: 'execution_identity_read', purpose: 'verifier',
    targetDigest: ref, useCount: 0, rowVersion: 1, createdAt: at, expiresAt };
  const createCore = { protocolVersion: 1, method: 'authorization.create', requestId,
    decision: { kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: 'manifest', toolId: 'node' } } } as const;
  const create = { protocolVersion: 1, ok: true, result: { method: 'authorization.create', grant } };
  assert.deepEqual(decodeInstalledControlResponse(create, { ...createCore, requestDigest: canonicalSha256(createCore) }), create);
  for (const wrong of [{ ...grant, targetKind: 'read_scope', purpose: 'source' },
    { ...grant, state: 'consumed', useCount: 1, rowVersion: 2, consumedAt: at }])
    assert.throws(() => decodeInstalledControlResponse({ ...create, result: { ...create.result, grant: wrong } },
      { ...createCore, requestDigest: canonicalSha256(createCore) }));
  const revokeCore = { protocolVersion: 1, method: 'authorization.revoke', requestId, grantId: grant.grantId } as const;
  const revokeRequest = { ...revokeCore, requestDigest: canonicalSha256(revokeCore) };
  const revoke = { protocolVersion: 1, ok: true, result: { method: 'authorization.revoke', disposition: 'revoked',
    grant: { ...grant, state: 'revoked', rowVersion: 2, revokedAt: at } } };
  assert.deepEqual(decodeInstalledControlResponse(revoke, revokeRequest), revoke);
  assert.throws(() => decodeInstalledControlResponse({ ...revoke, result: { ...revoke.result, disposition: 'already_consumed' } }, revokeRequest));
  const budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const run = { id: 'run-1', sessionId: session.id, specRef: ref, status: 'queued', nextStep: 'agent', frontierRef: ref,
    revision: 1, leaseEpoch: 0, latestCheckpointId: 'checkpoint-1', budgetReserved: budget, budgetConsumed: budget,
    repairCount: 0, cancelRequested: false, createdAt: at, deadlineAt: at, updatedAt: at };
  const snapshot = { schemaVersion: 1, operation: 'agent', run, latestRunItemSeq: 0 };
  const submitCore = { protocolVersion: 1, method: 'run.submit', requestId, admissionKey: 'a'.repeat(22), sessionId: session.id,
    expectedContextRevision: 1, workspacePath: '/workspace', objective: 'inspect', model: { provider: 'ollama', model: 'test' },
    policyMode: 'default', verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
    registeredMcpServerIds: [], skillIds: [], allowUnverified: true } as const;
  const submitted = { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot } };
  // Test data remains ordinary JSON, not an admitted Run or execution handle.
  const submitRequest = decodeInstalledControlRequest({ ...submitCore, requestDigest: canonicalSha256(submitCore) });
  assert.deepEqual(decodeInstalledControlResponse(submitted, submitRequest), submitted);
  assert.throws(() => decodeInstalledControlResponse({ ...submitted, result: { ...submitted.result,
    snapshot: { ...snapshot, run: { ...run, sessionId: 'other' } } } }, submitRequest));
  const cancelCore = { protocolVersion: 1, method: 'run.cancel', requestId, runId: run.id, expectedRevision: run.revision } as const;
  const cancelRequest = { ...cancelCore, requestDigest: canonicalSha256(cancelCore) };
  const cancelled = { protocolVersion: 1, ok: true, result: { method: 'run.cancel',
    snapshot: { ...snapshot, run: { ...run, revision: 2, cancelRequested: true, stopIntentRef: ref } } } };
  assert.deepEqual(decodeInstalledControlResponse(cancelled, cancelRequest), cancelled);
  assert.throws(() => decodeInstalledControlResponse({ ...cancelled, result: { ...cancelled.result,
    snapshot: { ...cancelled.result.snapshot, run: { ...cancelled.result.snapshot.run, id: 'other' } } } }, cancelRequest));
});

test('credential continuation result is the original committed pure-data operation, not a new mutation', () => {
  const at = '2026-10-18T00:00:00.000Z', ref = 'a'.repeat(64), requestId = '01900000-0000-7000-8000-000000000001';
  const subjectCore = { schemaVersion: 1, format: 'cliq-credential-external-subject-v1', endpointIdentityDigest: ref,
    subject: { kind: 'opaque_generation', opaqueSubjectId: 'a'.repeat(43), scopes: ['endpoint_exact_only'], audiences: [] }, observedAt: at };
  const externalSubject = { ...subjectCore, subjectDigest: canonicalSha256(subjectCore) };
  const target = { credentialGrantId: 'grant-1', ownerPrincipalId: 'principal', purpose: 'model_endpoint', endpointRegistrationRef: ref,
    endpointIdentityDigest: ref, tlsPolicyDigest: ref, externalSubjectDigest: externalSubject.subjectDigest };
  const command = { schemaVersion: 1, ...target, kind: 'enroll', secretSubmissionId: 'submission-1', externalSubject,
    credentialTargetDigest: canonicalSha256(target) };
  const commandCore = { ...command, commandDigest: canonicalSha256(command) };
  const original = { protocolVersion: 1, method: 'credential.finalize', requestId,
    operationId: identityHash('principal', requestId, commandCore.commandDigest, 1), attempt: 1, commandDigest: commandCore.commandDigest } as const;
  const operation = { schemaVersion: 1, operationId: original.operationId, requestId, requestDigest: original.commandDigest,
    channelIdentityRef: ref, channelIdentityDigest: ref, commandCore, attempt: 1, ownerPrincipalId: 'principal', kind: 'enroll',
    credentialGrantId: 'grant-1', credentialTargetDigest: commandCore.credentialTargetDigest, intendedAuthorityRevision: 1,
    intendedSecretGeneration: 1, intendedExternalSubjectDigest: externalSubject.subjectDigest,
    platformItem: { kind: 'linux_secret_service', schema: 'org.freedesktop.Secret.Generic', collection: 'default', itemId: '/org/freedesktop/secrets/collection/default/item/1' },
    createdAt: at, phase: 'committed', committedAuthorityRevision: 1, finishedAt: at, operationDigest: '' };
  operation.operationDigest = digestOmitting(operation, 'operationDigest');
  const response = { protocolVersion: 1, ok: true, result: { method: 'credential.finalize', operation } };
  assert.deepEqual(decodeInstalledControlResponse(response, original), response);
  assert.throws(() => decodeInstalledControlResponse(response, { ...original, operationId: 'b'.repeat(43) }));
  assert.throws(() => decodeInstalledControlResponse(response, { ...original, commandDigest: 'b'.repeat(64) }));
});
test('installed delivery decoding preserves original wire identity without exposing internal capture or execution fields', () => {
  const core = { protocolVersion: 1, method: 'run.apply', requestId: '01900000-0000-7000-8000-000000000001',
    admissionKey: 'a'.repeat(32), sourceRunId: 'source-cafe\u0301', expectedRunResultRef: 'a'.repeat(64), budgets: { toolCalls: 3 } };
  const request = { ...core, requestDigest: canonicalSha256(core) };
  assert.deepEqual(decodeInstalledControlRequest(request), request);
  for (const extras of [{ workspacePath: '/tmp/work' }, { capturedWorkspaceRef: 'b'.repeat(64) }, { objective: 'changed' },
    { policyMode: 'yolo' }, { allowUnverified: true }, { budgets: { modelTokens: 1 } }]) {
    const value = { ...core, ...extras };
    assert.throws(() => decodeInstalledControlRequest({ ...value, requestDigest: canonicalSha256(value) }));
  }
});

test('delivery wire success is an explicit delivery snapshot and never relabels an agent Run as apply', () => {
  const core = { protocolVersion: 1, method: 'run.apply', requestId: '01900000-0000-7000-8000-000000000001',
    admissionKey: 'a'.repeat(22), sourceRunId: 'source-run', expectedRunResultRef: 'a'.repeat(64) } as const;
  const request = { ...core, requestDigest: canonicalSha256(core) };
  const at = '2026-10-18T00:00:00.000Z', budget = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const run = { id: 'delivery-run', sessionId: 'session', specRef: 'a'.repeat(64), status: 'queued', nextStep: 'delivery',
    frontierRef: 'b'.repeat(64), revision: 1, leaseEpoch: 0, latestCheckpointId: 'initial', budgetReserved: budget,
    budgetConsumed: budget, repairCount: 0, cancelRequested: false, createdAt: at, deadlineAt: '2026-10-19T00:00:00.000Z', updatedAt: at };
  const snapshot = { schemaVersion: 1, operation: 'delivery', run, latestRunItemSeq: 0 };
  const response = { protocolVersion: 1, ok: true, result: { method: 'run.apply', snapshot } };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...response.result,
    snapshot: { ...snapshot, operation: 'agent' } } }, request), /explicit delivery/);
  assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...response.result,
    snapshot: { ...snapshot, run: { ...run, id: request.sourceRunId } } } }, request), /distinct explicit delivery/);
  assert.throws(() => decodeInstalledControlResponse({ ...response, result: { ...response.result, capturedWorkspaceRef: 'a'.repeat(64) } }, request));
});

test('delivery capacity refusal retains the fixed Run queue contract without model credential retry authority', () => {
  const core = { protocolVersion: 1, method: 'run.apply', requestId: '01900000-0000-7000-8000-000000000001',
    admissionKey: 'a'.repeat(22), sourceRunId: 'source-run', expectedRunResultRef: 'a'.repeat(64) } as const;
  const request = { ...core, requestDigest: canonicalSha256(core) };
  const response = { protocolVersion: 1, ok: false, method: 'run.apply', error: { schemaVersion: 1,
    code: 'RESOURCE_EXHAUSTED', retryable: true, resourceKind: 'run_queue', retryAfterMs: 1000, messageCode: 'run.queue_capacity' } };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
  for (const changed of [{ retryAfterMs: 1001 }, { resourceKind: 'model' }, { retryable: false },
    { code: 'RATE_LIMITED', messageCode: 'run.credential_scope_busy' }]) {
    const error = { ...response.error, ...changed };
    if (changed.code === 'RATE_LIMITED') Reflect.deleteProperty(error, 'resourceKind');
    assert.throws(() => decodeInstalledControlResponse({ ...response, error }, request));
  }
});

test('installed approval binds the exact wait, revision and one public digest without client authority fields', () => {
  const core = { protocolVersion: 1, method: 'run.approve', requestId: '01900000-0000-7000-8000-000000000001',
    runId: 'delivery-run', expectedRevision: 7, waitingOnRef: 'a'.repeat(64), decision: 'allow', ttlMs: 1 } as const;
  const request = { ...core, requestDigest: canonicalSha256(core) };
  assert.deepEqual(decodeInstalledControlRequest(request), request);
  for (const changed of [{ expectedRevision: 0 }, { decision: 'allow_always' }, { ttlMs: 0 }, { ttlMs: 86_400_001 },
    { grantRef: 'b'.repeat(64) }, { principalId: 'forged' }]) {
    const value = { ...core, ...changed };
    assert.throws(() => decodeInstalledControlRequest({ ...value, requestDigest: canonicalSha256(value) }));
  }
  const response = { protocolVersion: 1, ok: false, method: 'run.approve', error: { schemaVersion: 1,
    code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'control.method_not_enabled' } };
  assert.deepEqual(decodeInstalledControlResponse(response, request), response);
});
