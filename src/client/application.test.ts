import { encodeControlCheckpointCursor } from '../kernel/control-wire.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createInstalledControlSession } from '../control/session.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import type { RunSnapshotV1 } from '../kernel/types.js';
import { createClientApplication, ClientBusyError, ClientDisconnectedError, type ClientUpdate } from './application.js';
import { clientMutation, parseClientInvocation } from './commands.js';
import { initialClientView, reduceClientView, runHeadline, terminalText } from './view.js';

// Protocol data only. No actual installation, Store, Run or native receipt is
// created by this consumer fixture; those have independent genuine tests.
const ref = 'a'.repeat(64), at = '2026-10-26T00:00:00.000Z';
const snapshot = () => ({ schemaVersion: 1 as const, operation: 'agent' as const, latestRunItemSeq: 0, run: {
  id: 'run', sessionId: 'session', specRef: ref, status: 'queued' as const, nextStep: 'agent' as const, frontierRef: ref,
  revision: 1, leaseEpoch: 0, latestCheckpointId: 'checkpoint',
  budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
  budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0, cancelRequested: false,
  createdAt: at, updatedAt: at, deadlineAt: '2026-10-27T00:00:00.000Z' } });
const hello = { method: 'control.hello' as const, protocolVersion: 1 as const, serverBuild: 'inert-client-data',
  supervisorInstanceId: 'supervisor', controlSchemaRange: { min: 1 as const, max: 1 as const }, headlessSchemaRange: { min: 3, max: 3 },
  activeRuntimeBundle: { schemaVersion: 1 as const, runtimeBundleRef: ref, bundleDigest: ref, bundleVersion: 'inert' },
  enabledFeatureIds: ['run.get', 'run.attach', 'run.cancel'] };
const get = { protocolVersion: 1 as const, method: 'run.get' as const, runId: 'run' };
function client(overrides: Record<string, unknown> = {}) {
  return createInstalledControlSession({ hello, close: async () => {},
    'run.get': async () => ({ protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: snapshot(), items: [], journal: [], checkpoints: [],
      highWaterItemSeq: 0, highWaterJournalSeq: 0, highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }), nextItemSeq: 0, nextJournalSeq: 0 } }), ...overrides } as unknown as InstalledSupervisorClient,
  async () => ({ hello, close: async () => {}, ...overrides } as unknown as InstalledSupervisorClient));
}

test('uncertain send fences queued commands; explicit reconnect does not redispatch the original mutation', async () => {
  const sent: unknown[] = [], updates: ClientUpdate[] = [];
  let reject!: (reason: unknown) => void;
  const failure = new Error('inert transport failure');
  const session = client({ 'run.cancel': async (request: unknown) => {
    sent.push(request); if (sent.length === 1) return await new Promise((_, no) => { reject = no; });
    return { protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } };
  } });
  const app = createClientApplication(session, update => { updates.push(update); });
  const request = clientMutation({ method: 'run.cancel', runId: 'run', expectedRevision: 1 });
  const pending = app.execute({ kind: 'request', request });
  while (!reject) await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(app.execute({ kind: 'request', request }), ClientBusyError);
  reject(failure); await assert.rejects(pending, error => error === failure);
  await assert.rejects(app.execute({ kind: 'request', request: get }), ClientDisconnectedError);
  await app.execute({ kind: 'reconnect' }); assert.equal(sent.length, 1);
  await app.execute({ kind: 'request', request }); assert.equal(sent.length, 2);
  assert.deepEqual(canonicalJsonBytes(sent[0]), canonicalJsonBytes(sent[1]));
  assert.equal(updates.filter(update => update.kind === 'connection' && update.state === 'disconnected').length, 1);
  await app.close();
});

test('a failed explicit reconnect fences new mutations until a later reconnect succeeds', async () => {
  const failure = new Error('the new original connection failed');
  let broken = true, sends = 0;
  const methods = { hello, close: async () => {}, 'run.cancel': async () => {
    sends++;
    return { protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1,
      code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } };
  } };
  const session = createInstalledControlSession(methods as unknown as InstalledSupervisorClient,
    async () => { if (broken) throw failure; return methods as unknown as InstalledSupervisorClient; });
  const updates: ClientUpdate[] = [], app = createClientApplication(session, update => { updates.push(update); });
  const request = clientMutation({ method: 'run.cancel', runId: 'run', expectedRevision: 1 });
  try {
    await assert.rejects(app.execute({ kind: 'reconnect' }), error => error === failure);
    await assert.rejects(app.execute({ kind: 'request', request }), ClientDisconnectedError);
    assert.equal(sends, 0); assert.equal(app.pendingRequest, undefined);
    assert(updates.some(update => update.kind === 'connection' && update.state === 'disconnected'));
    broken = false; await app.execute({ kind: 'reconnect' });
    assert.equal(sends, 0, 'reconnect alone never submits a new mutation');
    await app.execute({ kind: 'request', request }); assert.equal(sends, 1);
  } finally { await app.close(); }
});

test('an unresolved original request survives reconnect and read-only inspection until its explicit exact replay', async () => {
  let sends = 0, reads = 0, reconnects = 0;
  const sent: Buffer[] = [], failure = new Error('original response was lost');
  const methods = { hello, close: async () => {},
    'run.cancel': async (request: unknown) => {
      sent.push(canonicalJsonBytes(request));
      if (++sends === 1) throw failure;
      return { protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1,
        code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } };
    },
    'run.get': async () => { reads++; return { protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: snapshot(),
      items: [], journal: [], checkpoints: [], highWaterItemSeq: 0, highWaterJournalSeq: 0,
      highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }), nextItemSeq: 0, nextJournalSeq: 0 } }; }
  };
  const session = createInstalledControlSession(methods as unknown as InstalledSupervisorClient,
    async () => { reconnects++; return methods as unknown as InstalledSupervisorClient; });
  const app = createClientApplication(session, () => {});
  const original = clientMutation({ method: 'run.cancel', runId: 'run', expectedRevision: 1 });
  try {
    await assert.rejects(app.execute({ kind: 'request', request: original }), error => error === failure);
    assert.deepEqual(canonicalJsonBytes(app.pendingRequest), canonicalJsonBytes(original));
    assert(Object.isFrozen(app.pendingRequest));
    await assert.rejects(app.replay(), ClientDisconnectedError);
    assert.equal(sends, 1); await app.execute({ kind: 'reconnect' });
    assert.equal(reconnects, 1); assert.equal(sends, 1);
    await app.execute({ kind: 'request', request: get }); assert.equal(reads, 1);
    await assert.rejects(app.execute({ kind: 'request', request: clientMutation({ method: 'run.cancel', runId: 'run', expectedRevision: 2 }) }),
      /original unresolved request/u);
    assert.equal(sends, 1);
    await app.replay(); assert.equal(sends, 2); assert.deepEqual(sent[0], sent[1]);
    assert.equal(app.pendingRequest, undefined);
    await assert.rejects(app.replay(), /no unresolved request/u); assert.equal(sends, 2);
  } finally { await app.close(); }
});

test('closing a followed Run joins the original read and generator and never invokes cancellation', async () => {
  let entered!: () => void, finish!: () => void, joined = false, cancels = 0;
  const started = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { finish = resolve; });
  const session = client({ close: async () => { finish(); }, 'run.cancel': async () => { cancels++; },
    'run.attach': async () => { entered(); await gate; return { protocolVersion: 1, ok: true, result: { method: 'run.attach',
      snapshot: snapshot(), earliestRetainedEventSeq: 1, latestRetainedEventSeq: 1, highWaterEventSeq: 1,
      events: [{ schemaVersion: 1, kind: 'progress', runId: 'run', eventSeq: 1, observedRunRevision: 1, phase: 'agent', occurredAt: at }], nextEventSeq: 1 } }; } });
  const app = createClientApplication(session, () => {});
  const following = app.follow('run').finally(() => { joined = true; });
  const refusal = assert.rejects(following, error => error instanceof Error && error.name === 'AbortError');
  await started; await app.close(); await refusal;
  assert.equal(joined, true); assert.equal(cancels, 0);
});

test('an in-flight artifact read queues one explicit cancel instead of consuming the user command slot', async () => {
  const bytes = Buffer.from('inert client display data'), digest = sha256Bytes(bytes);
  let entered!: () => void, finish!: () => void, cancels = 0;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { finish = resolve; });
  const session = client({ hello: { ...hello, enabledFeatureIds: [...hello.enabledFeatureIds, 'artifact.get'] },
    'artifact.get': async () => { entered(); await gate; return { protocolVersion: 1, ok: true, result: { method: 'artifact.get',
      artifact: { schemaVersion: 1, ref: digest, digest, sizeBytes: bytes.length, mediaType: 'text/plain' }, offset: 0, nextOffset: bytes.length,
      bytesBase64: bytes.toString('base64'), eof: true } }; },
    'run.cancel': async () => { cancels++; return { protocolVersion: 1, ok: false, method: 'run.cancel',
      error: { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } }; } });
  const app = createClientApplication(session, () => {});
  const reading = app.artifact(digest, { maxBytes: 1024 }); await ready;
  const cancelled = assert.doesNotReject(app.execute({ kind: 'request', request: clientMutation({ method: 'run.cancel', runId: 'run', expectedRevision: 1 }) }));
  void cancelled.catch(() => {});
  assert.equal(cancels, 0); finish(); assert.deepEqual(await reading, bytes); await cancelled;
  assert.equal(cancels, 1); await app.close();
});

test('strict-parser snapshots keep all four budget dimensions and replay cannot regress the visible current Run', () => {
  const first = snapshot(), current = { ...first, run: { ...first.run, revision: 3 } };
  const response = (value: typeof first): ClientUpdate => ({ kind: 'response', origin: 'command', request: get, response: {
    protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: value, items: [], journal: [], checkpoints: [],
      highWaterItemSeq: 0, highWaterJournalSeq: 0, highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }), nextItemSeq: 0, nextJournalSeq: 0 } } });
  let view = reduceClientView(initialClientView(), response(parseJsonStrict(canonicalJsonBytes(current).toString('utf8')) as typeof first));
  view = reduceClientView(view, response(first));
  assert.equal(view.run?.run.revision, 3);
  assert.equal(canonicalJsonBytes(view.run!.run.budgetConsumed).toString(), '{"costMicros":0,"modelTokens":0,"repairAttempts":0,"toolCalls":0}');
  assert.equal(runHeadline(view.run!), 'Queued');
  assert.equal(terminalText('\x1b[2J\u202emessage\ntext'), '\\u001b[2J\\u202emessage\ntext');
});

test('terminal Stop results remain terminal in the client while retaining their original stop audit fields', () => {
  for (const [status, terminalReason] of [['cancelled', 'cancelled_by_user'], ['failed', 'budget_exhausted']] as const) {
    const { nextStep: _step, frontierRef: _frontier, ...run } = snapshot().run;
    const terminal: RunSnapshotV1 = { ...snapshot(), run: { ...run, status, terminalReason,
      nextStep: null, stopIntentRef: ref, cancelRequested: true } };
    const original = canonicalJsonBytes(terminal);
    assert.equal(runHeadline(terminal), `${status} · ${terminalReason}`);
    assert.deepEqual(canonicalJsonBytes(terminal), original, 'display must preserve the original terminal audit fields');
  }
  assert.equal(runHeadline({ ...snapshot(), run: { ...snapshot().run, cancelRequested: true, stopIntentRef: ref } }),
    'Stop requested · awaiting completion');
});

test('human commands build canonical intents without release-key, secret or legacy execution options', () => {
  const run = parseClientInvocation(['run', 'make it work', '--provider', 'openai', '--model', 'fixture', '--endpoint', 'registered',
    '--credential-grant', 'grant', '--allow-unverified', '--detach'], '/work');
  assert(run.kind === 'run'); assert.equal(run.intent.objective, 'make it work'); assert.equal(run.detach, true);
  const approval = parseClientInvocation(['approve', 'run', '--revision', '2', '--wait', ref, '--decision', 'allow', '--ttl-ms', '1000'], '/work');
  assert(approval.kind === 'command' && approval.command.kind === 'request' && approval.command.request.method === 'run.approve');
  assert.equal(approval.command.request.ttlMs, 1000);
  const created = parseClientInvocation(['session', 'create', '--name', 'clear name'], '/work');
  assert(created.kind === 'command' && created.command.kind === 'request' && created.command.request.method === 'session.create');
  assert.equal(created.command.request.name, 'clear name');
  for (const argv of [['status', 'run', '--release-keys', 'fake'], ['run', 'prompt', '--api-key', 'inert'],
    ['approve', 'run', '--decision', 'allow'], ['apply', 'run', '--options', '{"method":"run.submit"}'], ['resume']])
    assert.throws(() => parseClientInvocation(argv, '/work'));
});

test('follow renders only complete committed item artifacts and keeps progress out of the transcript', async () => {
  const textCore = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: 'A committed answer.', byteCount: 19 };
  const text = { ...textCore, textDigest: sha256Bytes(canonicalJsonBytes(textCore)) }, textRef = sha256Bytes(canonicalJsonBytes(text));
  const item = { schemaVersion: 1, kind: 'model_turn', itemId: 'answer', runId: 'run', textRef }, itemRef = sha256Bytes(canonicalJsonBytes(item));
  const objects = new Map([[textRef, canonicalJsonBytes(text)], [itemRef, canonicalJsonBytes(item)]]);
  const selected = { ...snapshot(), latestRunItemSeq: 1 }, abort = new AbortController(), updates: ClientUpdate[] = [];
  const session = client({ hello: { ...hello, enabledFeatureIds: [...hello.enabledFeatureIds, 'artifact.get'] },
    'run.attach': async () => ({ protocolVersion: 1, ok: true, result: { method: 'run.attach', snapshot: selected,
      earliestRetainedEventSeq: 1, latestRetainedEventSeq: 1, highWaterEventSeq: 1, nextEventSeq: 1,
      events: [{ schemaVersion: 1, kind: 'progress', runId: 'run', eventSeq: 1, observedRunRevision: 1, phase: 'agent', occurredAt: at }] } }),
    'run.get': async () => ({ protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: selected,
      items: [{ schemaVersion: 1, itemId: 'answer', itemSeq: 1, payloadRef: itemRef, payloadDigest: itemRef, createdAt: at }],
      journal: [], checkpoints: [], highWaterItemSeq: 1, highWaterJournalSeq: 0,
      highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }), nextItemSeq: 1, nextJournalSeq: 0 } }),
    'artifact.get': async (request: { digest: string; offset: number; length: number }) => {
      const bytes = objects.get(request.digest)!; assert(bytes); const part = bytes.subarray(request.offset, request.offset + request.length), next = request.offset + part.length;
      return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: { schemaVersion: 1, ref: request.digest,
        digest: request.digest, sizeBytes: bytes.length, mediaType: 'application/json' }, offset: request.offset, nextOffset: next,
        bytesBase64: part.toString('base64'), eof: next === bytes.length } };
    } });
  const app = createClientApplication(session, update => { updates.push(update); if (update.kind === 'transcript') abort.abort(); });
  await assert.rejects(app.follow('run', 0, abort.signal), { name: 'AbortError' });
  const transcript = updates.filter(update => update.kind === 'transcript');
  assert.equal(transcript.length, 1); assert.equal(transcript[0]!.text, 'Assistant: A committed answer.');
  assert.equal(transcript[0]!.itemSeq, 1); assert.equal(updates.filter(update => update.kind === 'event').length, 1);
  await app.close();
});

test('an artifact transport failure fences the already queued explicit command instead of using the failed connection', async () => {
  let entered!: () => void, finish!: () => void, cancels = 0;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { finish = resolve; });
  const failure = new Error('inert original transport failed');
  const session = client({ hello: { ...hello, enabledFeatureIds: [...hello.enabledFeatureIds, 'artifact.get'] },
    'artifact.get': async () => { entered(); await gate; throw failure; },
    'run.cancel': async () => { cancels++; return { protocolVersion: 1, ok: false, method: 'run.cancel', error: { schemaVersion: 1,
      code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } }; } });
  const app = createClientApplication(session, () => {});
  try {
    const reading = app.artifact(ref, { maxBytes: 1024 }); void reading.catch(() => {}); await ready;
    const command = app.execute({ kind: 'request', request: clientMutation({ method: 'run.cancel', runId: 'run', expectedRevision: 1 }) });
    void command.catch(() => {}); finish();
    await assert.rejects(reading, error => error === failure);
    await assert.rejects(command, ClientDisconnectedError); assert.equal(cancels, 0);
  } finally { finish(); await app.close(); }
});
