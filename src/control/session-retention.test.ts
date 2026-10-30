import assert from 'node:assert/strict';
import test from 'node:test';
import { Readable, Writable } from 'node:stream';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { CONTROL_V1_SOURCE_DIGEST, decodeInstalledControlRequest, decodeInstalledControlResponse } from './v1.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { ResourceRetirementError } from '../state/errors.js';
import { createClientApplication } from '../client/application.js';
import { ClientPendingRequestError, ClientRequestPersistenceError } from '../client/errors.js';
import { clientMutation } from '../client/commands.js';
import type { ClientUpdate } from '../client/types.js';
import type { PendingClientMutation, PendingRequestMetadata, PendingRequestRecord, PendingRequests } from '../client/pending-requests.js';
import { hello, sessionSnapshot, runSnapshot } from '../client/testing/protocol.js';
import { createInstalledControlSession } from './session.js';
import { runClientInvocation } from '../client/entry.js';

const originalRequest = () => clientMutation({ method: 'run.cancel', runId: 'run', expectedRevision: 1 }) as PendingClientMutation;
const refusal = () => ({ protocolVersion: 1, ok: false, method: 'run.cancel', error: {
  schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } });
function metadata(request: PendingClientMutation): PendingRequestMetadata {
  return { schemaVersion: 1, protocolVersion: 1, method: request.method, requestId: request.requestId, requestDigest: request.requestDigest,
    stateRoot: { deviceId: '1', fileId: '2', ownerUid: 123 }, sourceBundleDigest: canonicalSha256('wire fixture'), controlSourceDigest: CONTROL_V1_SOURCE_DIGEST };
}

/** Powerless byte-data composition. It verifies shared consumer order/fences;
 * it proves no physical fsync, peer authentication, installed Run or native
 * cleanup. Independent real Linux private-files regressions cover the files. */
function data(initial: readonly PendingRequestRecord[] = []) {
  const records = new Map(initial.map(value => [value.request.requestId, value]));
  const events: string[] = [];
  let beforeRetain: (() => Promise<void>) | undefined, beforeResolve: (() => Promise<void>) | undefined;
  const store = {
    async list() { events.push('list'); return [...records.values()].map(value => ({ metadata: value.metadata,
      state: value.response === undefined ? 'unresolved' as const : 'known' as const })); },
    async load(id: string) { events.push('load'); const value = records.get(id); if (!value) throw new Error('record absent'); return value; },
    async retain(supplied: unknown) {
      const request = decodeInstalledControlRequest(supplied) as PendingClientMutation;
      events.push('retain.begin'); await beforeRetain?.();
      const previous = records.get(request.requestId);
      if (previous && !previous.bytes.equals(canonicalJsonBytes(request))) throw new Error('original bytes differ');
      const value = previous ?? Object.freeze({ metadata: metadata(request), request, bytes: canonicalJsonBytes(request) });
      records.set(request.requestId, value); events.push('retain.joined'); return { ...value, existing: previous !== undefined };
    },
    async resolve(supplied: unknown, value: unknown) {
      const request = decodeInstalledControlRequest(supplied) as PendingClientMutation;
      const response = decodeInstalledControlResponse(value, request);
      events.push('response.begin'); await beforeResolve?.();
      const previous = records.get(request.requestId); if (!previous) throw new Error('original absent');
      const result = { ...previous, response }; records.set(request.requestId, result); events.push('response.joined'); return result;
    },
    async acknowledge(id: string) { const previous = records.get(id); if (!previous?.response) throw new Error('response unknown');
      events.push('acknowledge:' + id); records.delete(id); },
    async close() {}
  } as PendingRequests;
  return { store, events, records, retainHook(hook?: () => Promise<void>) { beforeRetain = hook; }, resolveHook(hook?: () => Promise<void>) { beforeResolve = hook; } };
}
function record(request: PendingClientMutation, known = false): PendingRequestRecord {
  return { request, bytes: canonicalJsonBytes(request), metadata: metadata(request),
    ...(known ? { response: decodeInstalledControlResponse(refusal(), request) } : {}) };
}
const peer = (send: (value: unknown) => Promise<unknown>) => ({ hello, close: async () => {}, 'run.cancel': send,
  'supervisor.status': async () => ({ protocolVersion: 1, ok: false, method: 'supervisor.status', error: {
    schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } }) }) as unknown as InstalledSupervisorClient;

test('the shared mutation waits for complete original persistence and complete strict-response persistence before returning', async () => {
  const saved = data(), original = originalRequest(); let sent = 0, returned = false;
  let retaining!: () => void, allowRetain!: () => void, resolving!: () => void, allowResolve!: () => void;
  const retained = new Promise<void>(resolve => { retaining = resolve; }), retainGate = new Promise<void>(resolve => { allowRetain = resolve; });
  const resolved = new Promise<void>(resolve => { resolving = resolve; }), resolveGate = new Promise<void>(resolve => { allowResolve = resolve; });
  saved.retainHook(async () => { retaining(); await retainGate; }); saved.resolveHook(async () => { resolving(); await resolveGate; });
  const session = createInstalledControlSession(peer(async value => {
    sent++; assert(saved.records.has(original.requestId)); assert.deepEqual(canonicalJsonBytes(value), canonicalJsonBytes(original)); return refusal();
  }), undefined, saved.store);
  try {
    const request = session.request(original).then(value => { returned = true; return value; });
    await retained; assert.equal(sent, 0); assert.equal(session.pendingRequest, undefined);
    allowRetain(); await resolved; assert.equal(sent, 1); assert.equal(returned, false); assert.deepEqual(session.pendingRequest, original);
    allowResolve(); assert.equal((await request).ok, false); assert.equal(session.pendingRequest, undefined);
    assert.deepEqual(saved.events, ['list', 'retain.begin', 'retain.joined', 'response.begin', 'response.joined']);
    await session.close(); assert(saved.records.get(original.requestId)?.response, 'SDK/session close must preserve an unacknowledged known result');
  } finally { allowRetain(); allowResolve(); await session.close(); }
});

test('startup unknowns fence new mutations and convenience cancel without installing a different memory pending or disconnecting reads', async () => {
  const original = originalRequest(), saved = data([record(original)]); let sends = 0;
  const bytes: Buffer[] = [], updates: ClientUpdate[] = [];
  const remote = peer(async value => { sends++; bytes.push(canonicalJsonBytes(value)); return refusal(); });
  const session = createInstalledControlSession(remote, async () => remote, saved.store), app = createClientApplication(session, update => { updates.push(update); });
  try {
    const other = originalRequest();
    await assert.rejects(app.execute({ kind: 'request', request: other }), ClientPendingRequestError);
    assert.equal(app.pendingRequest, undefined); assert(!updates.some(update => update.kind === 'pending'));
    await assert.rejects(session.cancel('run', 1), ClientPendingRequestError); assert.equal(sends, 0);
    assert.equal((await app.execute({ kind: 'request', request: { protocolVersion: 1, method: 'supervisor.status' } }))?.ok, false);
    assert(!updates.some(update => update.kind === 'connection' && update.state === 'disconnected'));
    await app.execute({ kind: 'reconnect' }); assert.equal(sends, 0);
    assert.deepEqual((await app.requests!.load(original.requestId)).request, original); assert.equal(sends, 0, 'a disk response/read is never a new peer result');
    await app.requests!.replay(original.requestId); assert.equal(sends, 1); assert.deepEqual(bytes[0], canonicalJsonBytes(original));
    await app.execute({ kind: 'request', request: other }); assert.equal(sends, 2);
    assert.equal(saved.events.filter(value => value === 'list').length, 1, 'known history is scanned once, not before each wire request');
  } finally { await app.close(); }
});

test('a prewire storage failure sends nothing, preserves a healthy peer and fences later mutations without a replacement original', async () => {
  const saved = data(), original = originalRequest(), updates: ClientUpdate[] = []; let sends = 0;
  const failure = new Error('owned storage did not sync'); saved.retainHook(async () => { throw failure; });
  const session = createInstalledControlSession(peer(async () => { sends++; return refusal(); }), undefined, saved.store);
  const app = createClientApplication(session, update => { updates.push(update); });
  try {
    await assert.rejects(app.execute({ kind: 'request', request: original }), error => error instanceof ClientRequestPersistenceError && error.cause === failure);
    assert.equal(sends, 0); assert.equal(app.pendingRequest, undefined);
    await assert.rejects(app.execute({ kind: 'request', request: originalRequest() }), ClientRequestPersistenceError); assert.equal(sends, 0);
    await app.execute({ kind: 'request', request: { protocolVersion: 1, method: 'supervisor.status' } });
    assert(!updates.some(update => update.kind === 'pending' || update.kind === 'connection' && update.state === 'disconnected'));
  } finally { await app.close(); }
});

test('response storage failure retains the sent original; a new client explicitly replays its exact bytes after storage recovers', async () => {
  const saved = data(), original = originalRequest(), failure = new Error('response storage did not sync'); let sends = 0;
  const originals: Buffer[] = [], updates: ClientUpdate[] = [];
  saved.resolveHook(async () => { throw failure; });
  const remote = peer(async value => { sends++; originals.push(canonicalJsonBytes(value)); return refusal(); });
  const session = createInstalledControlSession(remote, async () => remote, saved.store), app = createClientApplication(session, update => { updates.push(update); });
  try {
    await assert.rejects(app.execute({ kind: 'request', request: original }), ClientRequestPersistenceError);
    assert.equal(sends, 1); assert.deepEqual(app.pendingRequest, original); assert.equal(saved.records.get(original.requestId)?.response, undefined);
    assert(!updates.some(update => update.kind === 'connection' && update.state === 'disconnected'));
    await app.execute({ kind: 'reconnect' }); assert.equal(sends, 1);
    await assert.rejects(app.execute({ kind: 'request', request: originalRequest() }), ClientPendingRequestError);
  } finally { await app.close(); }
  saved.resolveHook();
  const next = createInstalledControlSession(remote, undefined, saved.store);
  try { await next.requests!.replay(original.requestId); assert.equal(sends, 2); assert.deepEqual(originals[0], originals[1]); }
  finally { await next.close(); }
});

test('malformed peer responses never become known disk results and still disconnect the application', async () => {
  const saved = data(), original = originalRequest(), updates: ClientUpdate[] = []; let sends = 0;
  const session = createInstalledControlSession(peer(async () => { sends++; return { ...refusal(), extra: true }; }), undefined, saved.store);
  const app = createClientApplication(session, update => { updates.push(update); });
  try {
    await assert.rejects(app.execute({ kind: 'request', request: original }));
    assert.equal(sends, 1); assert.deepEqual(app.pendingRequest, original); assert.equal(saved.records.get(original.requestId)?.response, undefined);
    assert(!saved.events.includes('response.begin'));
    assert(updates.some(update => update.kind === 'connection' && update.state === 'disconnected'));
  } finally { await app.close(); }
});

test('known-send acknowledgement is explicit and scoped to this host, preserving older lost output', async () => {
  const older = originalRequest(), original = originalRequest(), saved = data([record(older, true)]);
  const session = createInstalledControlSession(peer(async () => refusal()), undefined, saved.store);
  try {
    await session.request(original); assert.equal(saved.records.size, 2);
    await session.requests!.acknowledgeSent(); assert(saved.records.has(older.requestId)); assert(!saved.records.has(original.requestId));
    await session.requests!.acknowledge(older.requestId); assert.equal(saved.records.size, 0);
  } finally { await session.close(); }
});

test('a resource-retirement error preserves its identity instead of becoming an ordinary persistence error', async () => {
  const saved = data(), failure = new ResourceRetirementError('inert error classification only', new Error('owned close failed'));
  saved.retainHook(async () => { throw failure; });
  const session = createInstalledControlSession(peer(async () => { throw new Error('must not send'); }), undefined, saved.store);
  await assert.rejects(session.request(originalRequest()), error => error === failure);
  await assert.rejects(session.close(), error => error === failure);
});

test('session close joins accepted original persistence and stops before any first wire send', async () => {
  const saved = data(); let retaining!: () => void, release!: () => void, sends = 0;
  const entered = new Promise<void>(resolve => { retaining = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  saved.retainHook(async () => { retaining(); await gate; });
  const session = createInstalledControlSession(peer(async () => { sends++; return refusal(); }), undefined, saved.store);
  const original = originalRequest(), query = session.request(original), rejected = assert.rejects(query, ClientRequestPersistenceError);
  await entered; let joined = false; const closing = session.close().then(() => { joined = true; });
  await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(joined, false); assert.equal(sends, 0);
  release(); await rejected; await closing;
  assert.equal(sends, 0); assert(saved.records.has(original.requestId)); assert.equal(saved.records.get(original.requestId)?.response, undefined);
});

test('explicit replay refuses changed disk data instead of pairing a new original with the previously reviewed request', async () => {
  const original = originalRequest(), replacement = originalRequest(), saved = data([record(original)]); let sends = 0;
  const session = createInstalledControlSession(peer(async () => { sends++; return refusal(); }), undefined, saved.store);
  try {
    const inspected = await session.requests!.load(original.requestId);
    saved.records.set(original.requestId, record(replacement));
    await assert.rejects(session.requests!.replay(original.requestId, inspected.request), ClientRequestPersistenceError);
    assert.equal(sends, 0);
  } finally { await session.close(); }
});

test('prepareResume remains a read-only helper and its prepared admission cannot bypass the startup unknown fence', async () => {
  const saved = data([record(originalRequest())]); let reads = 0, submissions = 0;
  const remote = { ...peer(async () => refusal()),
    'session.get': async () => { reads++; return { protocolVersion: 1, ok: true, result: { method: 'session.get',
      snapshot: sessionSnapshot(), items: [], highWaterItemSeq: 0, nextItemSeq: 0 } }; },
    'run.submit': async () => { submissions++; return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: runSnapshot() } }; }
  } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(remote, undefined, saved.store);
  try {
    const draft = clientMutation({ method: 'run.submit', sessionId: 'session', expectedContextRevision: 1,
      workspacePath: '/owned/workspace', objective: 'An inert new intent', model: { provider: 'ollama', model: 'inert' },
      policyMode: 'plan', verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
      registeredMcpServerIds: [], skillIds: [], allowUnverified: true }, true);
    assert.equal(draft.method, 'run.submit'); if (draft.method !== 'run.submit') throw new Error('inert draft differs');
    const { requestDigest: _digest, expectedContextRevision: _revision, ...intent } = draft;
    const prepared = await session.prepareResume(intent); assert.equal(reads, 1); assert.equal(prepared.expectedContextRevision, 7);
    await assert.rejects(session.request(prepared), ClientPendingRequestError); assert.equal(submissions, 0);
    assert.equal(session.pendingRequest, undefined);
  } finally { await session.close(); }
});

test('replaying an older known record cannot displace the current lost original after reconnect', async () => {
  const older = originalRequest(), original = originalRequest(), saved = data([record(older, true)]);
  const sent: Buffer[] = [];
  const remote = peer(async value => {
    sent.push(canonicalJsonBytes(value)); if (sent.length === 1) throw new Error('original response lost'); return refusal();
  });
  const session = createInstalledControlSession(remote, async () => remote, saved.store), app = createClientApplication(session, () => {});
  try {
    await assert.rejects(app.execute({ kind: 'request', request: original }), /response lost/u);
    await app.execute({ kind: 'reconnect' });
    await assert.rejects(app.requests!.replay(older.requestId), ClientPendingRequestError);
    await assert.rejects(session.requests!.replay(older.requestId), ClientPendingRequestError);
    assert.equal(sent.length, 1); assert.deepEqual(app.pendingRequest, original); assert.deepEqual(session.pendingRequest, original);
    await app.replay(); assert.equal(sent.length, 2); assert.deepEqual(sent[0], sent[1]); assert.equal(app.pendingRequest, undefined);
    assert(saved.records.get(older.requestId)?.response, 'older known output remains available for its own explicit review');
  } finally { await app.close(); }
});

test('explicit request replay keeps its known result until the real output callback joins, even with stdin already at EOF', async () => {
  const original = clientMutation({ method: 'session.create', workspacePath: '/owned/workspace' }, true) as PendingClientMutation;
  const saved = data([record(original)]); let sends = 0, entered!: () => void, release!: () => void, returned = false;
  const blocked = new Promise<void>(resolve => { entered = resolve; });
  const output = new Writable({ write(_chunk, _encoding, done) {
    let completed = false; release = () => { if (!completed) { completed = true; done(); } }; entered();
  } });
  const remote = { ...peer(async () => refusal()), 'session.create': async () => { sends++; return {
    protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: sessionSnapshot() } }; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(remote, undefined, saved.store);
  const work = runClientInvocation(session, { kind: 'request-replay', requestId: original.requestId, json: false }, {
    input: Readable.from([]), output, diagnostic: new Writable({ write(_chunk, _encoding, done) { done(); } }), workspacePath: '/owned/workspace'
  }).then(value => { returned = true; return value; });
  try {
    await blocked; assert.equal(sends, 1); assert(saved.records.get(original.requestId)?.response);
    await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(returned, false);
    release(); assert.equal(await work, 0); assert(saved.records.get(original.requestId)?.response);
    assert(!saved.events.some(value => value.startsWith('acknowledge:')), 'entry has no authority to infer its host stdio join');
  } finally { release?.(); await work; await session.close(); output.destroy(); }
});

test('a failed replay output preserves the exact strict known result for the next client', async () => {
  const original = clientMutation({ method: 'session.create', workspacePath: '/owned/workspace' }, true) as PendingClientMutation;
  const saved = data([record(original)]); let sends = 0;
  const remote = { ...peer(async () => refusal()), 'session.create': async () => { sends++; return {
    protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: sessionSnapshot() } }; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(remote, undefined, saved.store);
  const output = new Writable({ write(_chunk, _encoding, done) { done(new Error('owned output failed')); } });
  const code = await runClientInvocation(session, { kind: 'request-replay', requestId: original.requestId, json: false }, {
    input: Readable.from([]), output, diagnostic: new Writable({ write(_chunk, _encoding, done) { done(); } }), workspacePath: '/owned/workspace'
  });
  assert.equal(code, 1); assert.equal(sends, 1); assert(saved.records.get(original.requestId)?.response);
  assert.deepEqual(saved.records.get(original.requestId)?.bytes, canonicalJsonBytes(original));
  assert(!saved.events.some(value => value.startsWith('acknowledge:'))); await session.close();
});

test('a cancelled real JSONL response writer may detach normally but leaves its already known mutation unacknowledged', async () => {
  const original = originalRequest(), saved = data(), stop = new AbortController(); let blocked!: () => void;
  const entered = new Promise<void>(resolve => { blocked = resolve; });
  let callback: ((error?: Error | null) => void) | undefined, sends = 0;
  const output = new Writable({
    write(chunk: Buffer, _encoding, done) {
      if (chunk.includes(Buffer.from('"method":"run.cancel"'))) { callback = done; blocked(); } else done();
    },
    destroy(error, done) {
      const write = callback; callback = undefined;
      write?.(Object.assign(new Error('actual borrowed write cancelled'), { code: 'ECANCELED', syscall: 'write' }));
      done(error);
    }
  });
  const session = createInstalledControlSession(peer(async () => { sends++; return refusal(); }), undefined, saved.store);
  const input = Readable.from([Buffer.concat([canonicalJsonBytes({ schemaVersion: 3, request: original }), Buffer.from('\n')])]);
  const work = runClientInvocation(session, { kind: 'jsonl' }, { input, output,
    diagnostic: new Writable({ write(_chunk, _encoding, done) { done(); } }), workspacePath: '/owned/workspace', signal: stop.signal });
  await entered; assert.equal(sends, 1); assert(saved.records.get(original.requestId)?.response);
  stop.abort(); assert.equal(await work, 0, 'observer detach retains its existing normal exit contract');
  assert(output.closed); assert(saved.records.get(original.requestId)?.response);
  assert(!saved.events.some(value => value.startsWith('acknowledge:'))); await session.close();
});

for (const mode of ['jsonl', 'rpc'] as const) test(`${mode} input EOF cannot complete before the last actual response write joins`, async () => {
  const original = originalRequest(), saved = data(); let entered!: () => void, complete!: () => void, returned = false, released = false;
  const blocked = new Promise<void>(resolve => { entered = resolve; });
  const output = new Writable({ write(chunk: Buffer, _encoding, done) {
    if (!released && chunk.includes(Buffer.from('"method":"run.cancel"'))) {
      complete = () => { if (!released) { released = true; done(); } }; entered();
    } else done();
  } });
  const helloRequest = { protocolVersion: 1, method: 'control.hello', clientBuild: 'inert-stream', controlSchemaRange: { min: 1, max: 1 },
    headlessSchemaRange: { min: 3, max: 3 }, requestedFeatureIds: ['run.cancel'] };
  const wrap = (request: unknown) => ({ schemaVersion: 3, request });
  const records = mode === 'jsonl' ? [wrap(original)] : [
    { jsonrpc: '2.0', id: 'hello', method: 'control.hello', params: wrap(helloRequest) },
    { jsonrpc: '2.0', id: 'mutation', method: original.method, params: wrap(original) }
  ];
  const input = Readable.from([Buffer.concat(records.map(value => Buffer.concat([canonicalJsonBytes(value), Buffer.from('\n')])))]);
  const session = createInstalledControlSession(peer(async () => refusal()), undefined, saved.store);
  const work = runClientInvocation(session, { kind: mode }, { input, output,
    diagnostic: new Writable({ write(_chunk, _encoding, done) { done(); } }), workspacePath: '/owned/workspace'
  }).then(value => { returned = true; return value; });
  try {
    await blocked; assert(saved.records.get(original.requestId)?.response);
    await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(returned, false);
    complete(); assert.equal(await work, 0); assert(saved.records.get(original.requestId)?.response);
    assert(!saved.events.some(value => value.startsWith('acknowledge:')));
  } finally { complete?.(); await work; await session.close(); output.destroy(); }
});
