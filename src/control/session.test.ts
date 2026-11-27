import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { createInstalledControlSession } from './session.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { ResourceRetirementError } from '../state/errors.js';
import type { SessionResumeInput } from './session.js';

const hello = { method: 'control.hello' as const, protocolVersion: 1 as const, serverBuild: 'inert-protocol-fixture',
  controlSchemaRange: { min: 1 as const, max: 1 as const }, headlessSchemaRange: { min: 3, max: 3 },
  enabledFeatureIds: ['supervisor.status', 'artifact.get'], supervisorInstanceId: 'inert',
  activeRuntimeBundle: { schemaVersion: 1 as const, runtimeBundleRef: 'a'.repeat(64), bundleDigest: 'a'.repeat(64), bundleVersion: '1' } };
const refusal = { protocolVersion: 1, ok: false, method: 'supervisor.status',
  error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'inert_refusal' } };

// The existing InstalledSupervisorClient byte-consumer seam. No authenticated
// socket, installation, Run, native resource proof or execution authority.
test('schema3 session preserves a closed refusal and detaches without cancellation', async () => {
  let calls = 0, closed = 0, cancellations = 0;
  const client = { hello, 'supervisor.status': async () => { calls++; return refusal; }, close: async () => { closed++; },
    'run.cancel': async () => { cancellations++; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client);
  assert.deepEqual(await session.request({ protocolVersion: 1, method: 'supervisor.status' }), refusal);
  await session.close(); await session.close();
  assert.equal(calls, 1); assert.equal(closed, 1); assert.equal(cancellations, 0);
});

test('schema3 session follows actual artifact offsets and returns bytes only after the complete digest passes', async () => {
  const bytes = Buffer.from('完整工件\n🧠'), digest = createHash('sha256').update(bytes).digest('hex');
  const descriptor = { schemaVersion: 1, ref: digest, digest, sizeBytes: bytes.length, mediaType: 'text/plain' };
  const offsets: number[] = [];
  const client = { hello, close: async () => {}, 'artifact.get': async (request: { offset: number }) => {
    offsets.push(request.offset);
    const part = bytes.subarray(request.offset, request.offset + 3), next = request.offset + part.length;
    return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: descriptor,
      offset: request.offset, bytesBase64: part.toString('base64'), nextOffset: next, eof: next === bytes.length } };
  } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client);
  assert.deepEqual(await session.artifact(digest, { maxBytes: bytes.length }), bytes);
  assert.deepEqual(offsets, [0, 3, 6, 9, 12, 15]);
  await session.close();
});

test('unsupported schema and unknown capabilities refuse before any client dispatch', async () => {
  let calls = 0;
  const client = { hello: { ...hello, headlessSchemaRange: { min: 1, max: 1 } }, close: async () => {},
    'supervisor.status': async () => { calls++; return refusal; } } as unknown as InstalledSupervisorClient;
  assert.throws(() => createInstalledControlSession(client), /schema 3/);
  const session = createInstalledControlSession({ ...client, hello } as InstalledSupervisorClient);
  await assert.rejects(session.request({ protocolVersion: 1, method: 'session.list' }));
  assert.equal(calls, 0); await session.close();
});

const at = '2026-10-25T00:00:00.000Z', ref = 'a'.repeat(64);
function snapshot() {
  return { schemaVersion: 1, operation: 'agent', latestRunItemSeq: 0, run: { id: 'run', sessionId: 'session', specRef: ref,
    status: 'queued', nextStep: 'agent', frontierRef: ref, revision: 1, leaseEpoch: 0, latestCheckpointId: 'checkpoint',
    budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0,
    cancelRequested: false, createdAt: at, updatedAt: at, deadlineAt: '2026-10-25T01:00:00.000Z' } };
}

test('resume reads current Session context and returns one exact new admission before any dispatch', async () => {
  const calls: string[] = [];
  const client = { hello: { ...hello, enabledFeatureIds: ['session.get', 'run.submit'] }, close: async () => {},
    'session.get': async () => { calls.push('session.get'); return { protocolVersion: 1, ok: true, result: { method: 'session.get',
      snapshot: { schemaVersion: 1, session: { schemaVersion: 1, id: 'session', workspaceIdentityRef: ref, contextRevision: 7,
        latestItemSeq: 0, contextProjectionRef: ref, createdAt: at, updatedAt: at } }, items: [], highWaterItemSeq: 0, nextItemSeq: 0 } }; },
    'run.submit': async () => { calls.push('run.submit'); return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: snapshot() } }; }
  } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client);
  const intent: SessionResumeInput = { protocolVersion: 1, method: 'run.submit', requestId: '019a0012-0000-7000-8000-000000000901',
    admissionKey: Buffer.alloc(16, 1).toString('base64url'), sessionId: 'session', workspacePath: '/workspace', objective: 'Continue the retained context.',
    model: { provider: 'ollama', model: 'fixture' }, policyMode: 'plan', verifiers: [], dependency: { mode: 'none' },
    sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true };
  const prepared = await session.prepareResume(intent);
  assert.deepEqual(calls, ['session.get']); assert.equal(prepared.expectedContextRevision, 7); assert.equal(prepared.requestId, intent.requestId);
  const { requestDigest, ...core } = prepared; assert.equal(requestDigest, canonicalSha256(core)); assert(Object.isFrozen(prepared));
  assert((await session.request(prepared)).ok); assert.deepEqual(calls, ['session.get', 'run.submit']);
  await assert.rejects(session.prepareResume({ ...intent, expectedContextRevision: 1 } as SessionResumeInput));
  assert.deepEqual(calls, ['session.get', 'run.submit']); await session.close();
});

test('attach drains the captured high-water with backpressure from its exact retained cursor', async () => {
  const cursors: number[] = [];
  const client = { hello: { ...hello, enabledFeatureIds: ['run.attach'] }, close: async () => {},
    'run.attach': async (request: { afterEventSeq: number }) => {
      cursors.push(request.afterEventSeq);
      if (request.afterEventSeq === 0) return { protocolVersion: 1, ok: false, method: 'run.attach', error: {
        schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED', retryable: false, messageCode: 'expired',
        earliestEventSeq: 5, latestEventSeq: 7, snapshot: snapshot() } };
      const next = request.afterEventSeq + 1;
      return { protocolVersion: 1, ok: true, result: { method: 'run.attach', snapshot: snapshot(),
        earliestRetainedEventSeq: 5, latestRetainedEventSeq: 7, highWaterEventSeq: 7, nextEventSeq: next,
        events: [{ schemaVersion: 1, kind: 'progress', runId: 'run', eventSeq: next, observedRunRevision: 1,
          phase: 'agent', completedUnits: next, occurredAt: at }] } };
    } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client), pages = session.attach({ protocolVersion: 1, method: 'run.attach',
    runId: 'run', afterEventSeq: 4, limit: 1 });
  const first = await pages.next();
  assert.deepEqual(first.value?.events, [{ schemaVersion: 3, protocolVersion: 1, type: 'progress', runId: 'run', eventSeq: 5,
    timestamp: at, payload: { observedRunRevision: 1, phase: 'agent', completedUnits: 5 } }]);
  assert.deepEqual(cursors, [4]);
  assert.equal((await pages.next()).value?.events[0]?.eventSeq, 6);
  assert.equal((await pages.next()).value?.events[0]?.eventSeq, 7);
  assert.equal((await pages.next()).done, true); assert.deepEqual(cursors, [4, 5, 6]); await session.close();
});

test('expired attach ends its original cut with the authoritative snapshot instead of chasing retention', async () => {
  let calls = 0;
  const client = { hello: { ...hello, enabledFeatureIds: ['run.attach'] }, close: async () => {},
    'run.attach': async () => { calls++; return { protocolVersion: 1, ok: false, method: 'run.attach', error: {
      schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED', retryable: false, messageCode: 'expired',
      earliestEventSeq: 5, latestEventSeq: 7, snapshot: snapshot() } }; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client), pages = [];
  for await (const page of session.attach({ protocolVersion: 1, method: 'run.attach', runId: 'run', afterEventSeq: 0 })) pages.push(page);
  assert.equal(calls, 1); assert.equal(pages.length, 1); assert.equal(pages[0]!.response.ok, false);
  if (!pages[0]!.response.ok && pages[0]!.response.error.code === 'EVENT_CURSOR_EXPIRED')
    assert.deepEqual(pages[0]!.response.error.snapshot, snapshot());
  else assert.fail('expiry must retain its closed snapshot');
  await session.close();
});

test('attach fixes the first high-water and bounds later requests while the real producer keeps growing', async () => {
  const sent: Array<{ afterEventSeq: number; limit: number }> = [];
  const client = { hello: { ...hello, enabledFeatureIds: ['run.attach'] }, close: async () => {},
    'run.attach': async (request: { afterEventSeq: number; limit: number }) => {
      sent.push({ afterEventSeq: request.afterEventSeq, limit: request.limit });
      const high = sent.length === 1 ? 3 : 99, next = request.afterEventSeq + request.limit;
      return { protocolVersion: 1, ok: true, result: { method: 'run.attach', snapshot: snapshot(),
        earliestRetainedEventSeq: 1, latestRetainedEventSeq: high, highWaterEventSeq: high, nextEventSeq: next,
        events: Array.from({ length: request.limit }, (_, index) => ({ schemaVersion: 1, kind: 'progress', runId: 'run',
          eventSeq: request.afterEventSeq + index + 1, observedRunRevision: 1, phase: 'agent', occurredAt: at })) } };
    } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client), events = [];
  for await (const page of session.attach({ protocolVersion: 1, method: 'run.attach', runId: 'run', afterEventSeq: 0, limit: 2 })) events.push(...page.events);
  assert.deepEqual(sent, [{ afterEventSeq: 0, limit: 2 }, { afterEventSeq: 2, limit: 1 }]);
  assert.deepEqual(events.map(event => event.eventSeq), [1, 2, 3]); await session.close();
});

test('lost mutation response is replayed only after explicit reconnect with the exact original identity', async () => {
  const core = { protocolVersion: 1, method: 'run.cancel', runId: 'run', expectedRevision: 1,
    requestId: '019a0011-0000-7000-8000-000000000011' };
  const original = { ...core, requestDigest: canonicalSha256(core) }, received: unknown[] = [];
  let closes = 0, connections = 0;
  const make = (lost: boolean) => ({ hello: { ...hello, enabledFeatureIds: ['run.cancel'] },
    close: async () => { closes++; }, 'run.cancel': async (request: unknown) => {
      received.push(request); if (lost) throw new Error('lost response');
      return { protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1,
        code: 'RUN_TERMINAL', retryable: false, messageCode: 'terminal' } };
    } }) as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(make(true), async () => { connections++; return make(false); });
  await assert.rejects(session.request(original), /lost response/); assert.equal(received.length, 1);
  await session.reconnect(); assert.equal(received.length, 1); assert.equal(connections, 1);
  await session.request(original); assert.deepEqual(received, [original, original]);
  await session.close(); assert.equal(closes, 2);
});

test('uncertain original close prevents reconnect and never promotes a replacement client', async () => {
  const failure = new ResourceRetirementError('inert uncertain close', new Error('inert cause')); let connections = 0;
  const client = { hello, close: async () => { throw failure; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client, async () => { connections++; return client; });
  await assert.rejects(session.reconnect(), error => error === failure); assert.equal(connections, 0);
  await assert.rejects(session.request({ protocolVersion: 1, method: 'supervisor.status' }), error => error === failure);
  await assert.rejects(session.close(), error => error === failure);
});

test('only explicit user cancellation creates a new valid request identity and sends once', async () => {
  const received: Record<string, unknown>[] = [];
  const client = { hello: { ...hello, enabledFeatureIds: ['run.cancel'] }, close: async () => {},
    'run.cancel': async (request: Record<string, unknown>) => {
      received.push(request); return { protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1,
        code: 'RUN_TERMINAL', retryable: false, messageCode: 'terminal' } };
    } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client);
  await session.cancel('run', 17); assert.equal(received.length, 1);
  const { requestDigest, ...core } = received[0]!;
  assert.equal(core.expectedRevision, 17); assert.equal(core.runId, 'run'); assert.equal(requestDigest, canonicalSha256(core));
  assert.match(core.requestId as string, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  await session.close(); assert.equal(received.length, 1);
});

test('explicit close joins the original in-flight request without retrying or cancelling the Run', async () => {
  let reject!: (error: Error) => void, finished = false, closed = 0;
  const failure = new Error('original query detached'), pending = new Promise<never>((_, no) => { reject = no; });
  const client = { hello, 'supervisor.status': async () => { try { return await pending; } finally { finished = true; } },
    close: async () => { closed++; reject(failure); } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client), query = session.request({ protocolVersion: 1, method: 'supervisor.status' });
  void query.catch(() => {});
  await session.close(); await assert.rejects(query, error => error === failure);
  assert.equal(finished, true); assert.equal(closed, 1);
});

test('failed client close still joins the original pending request and preserves retirement failure priority', async () => {
  const failure = new ResourceRetirementError('inert original close failed', new Error('inert cause'));
  let release!: () => void, joined = false, closeReturned = false;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const client = { hello, 'supervisor.status': async () => { try { await gate; throw new Error('query detached'); }
    finally { joined = true; } }, close: async () => { throw failure; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client), request = session.request({ protocolVersion: 1, method: 'supervisor.status' });
  void request.catch(() => {});
  const closing = session.close(); void closing.catch(() => {}).finally(() => { closeReturned = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(closeReturned, false); assert.equal(joined, false);
  release(); await assert.rejects(closing, error => error === failure); assert.equal(joined, true);
});

test('closing during a failed reconnect still retires the original client and gives close uncertainty priority', async () => {
  let connect!: () => void, oldCloses = 0;
  const entered = new Promise<void>(resolve => { connect = resolve; });
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const failure = new ResourceRetirementError('inert final close failed', new Error('inert cause'));
  const client = { hello, close: async () => { if (++oldCloses > 1) throw failure; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client, async () => { connect(); await gate; throw new Error('connect failed'); });
  const switching = session.reconnect(); void switching.catch(() => {}); await entered;
  const closing = session.close(); void closing.catch(() => {}); release();
  await assert.rejects(switching, /connect failed/);
  await assert.rejects(closing, error => error === failure); assert.equal(oldCloses, 2);
});

test('artifact corruption, changed descriptors, oversize and nonadvancing pages never return partial bytes', async () => {
  const data = Buffer.from('abc'), digest = createHash('sha256').update(data).digest('hex');
  for (const fault of ['hash', 'descriptor', 'size', 'offset', 'empty', 'base64'] as const) {
    let calls = 0;
    const client = { hello, close: async () => {}, 'artifact.get': async (request: { offset: number }) => {
      calls++;
      const descriptor = { schemaVersion: 1, ref: digest, digest, sizeBytes: fault === 'size' ? 65 * 1024 * 1024 : 3,
        mediaType: fault === 'descriptor' && calls > 1 ? 'application/json' : 'text/plain' };
      const bytes = (fault === 'hash' ? Buffer.from('xyz') : data).subarray(request.offset, request.offset + 1);
      const next = request.offset + bytes.length;
      return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: descriptor,
        offset: fault === 'offset' ? request.offset + 1 : request.offset,
        bytesBase64: fault === 'base64' ? '!!!!' : fault === 'empty' ? '' : bytes.toString('base64'),
        nextOffset: fault === 'empty' ? request.offset : next, eof: next === 3 } };
    } } as unknown as InstalledSupervisorClient;
    const session = createInstalledControlSession(client);
    await assert.rejects(session.artifact(digest, { maxBytes: 64 * 1024 * 1024 }), TypeError, fault);
    assert(calls >= 1 && calls <= 3); await session.close();
  }
});
