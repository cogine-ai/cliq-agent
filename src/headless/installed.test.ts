import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { createInstalledControlSession } from '../control/session.js';
import { runInstalledHeadlessJsonl, runInstalledHeadlessRpc } from './installed.js';
import { decodeHeadlessControlResponse, headlessControlHello } from '../control/v1.js';

const hello = { method: 'control.hello', protocolVersion: 1, serverBuild: 'inert', controlSchemaRange: { min: 1, max: 1 },
  headlessSchemaRange: { min: 3, max: 3 }, enabledFeatureIds: ['supervisor.status'], supervisorInstanceId: 'inert',
  activeRuntimeBundle: { schemaVersion: 1, runtimeBundleRef: 'a'.repeat(64), bundleDigest: 'a'.repeat(64), bundleVersion: '1' } };
const request = { schemaVersion: 3, request: { protocolVersion: 1, method: 'supervisor.status' } };
const refusal = { protocolVersion: 1, ok: false, method: 'supervisor.status', error: { schemaVersion: 1,
  code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'inert' } };
const line = (value: unknown) => Buffer.concat([canonicalJsonBytes(value), Buffer.from('\n')]);
const greeting = (version = 3, features = ['supervisor.status']) => ({ schemaVersion: 3, request: {
  protocolVersion: 1, method: 'control.hello', clientBuild: 'inert', controlSchemaRange: { min: 1, max: 1 },
  headlessSchemaRange: { min: version, max: version }, requestedFeatureIds: features } });

function fixture() {
  let calls = 0, cancels = 0, closed = 0;
  const client = { hello, 'supervisor.status': async () => { calls++; return refusal; },
    'run.cancel': async () => { cancels++; }, close: async () => { closed++; } } as unknown as InstalledSupervisorClient;
  return { session: createInstalledControlSession(client), counts: () => ({ calls, cancels, closed }) };
}

test('schema3 JSONL preserves closed native responses and EOF only detaches the serial adapter', async () => {
  const f = fixture(), output: Buffer[] = [];
  async function* input() { for (const byte of line(request)) yield Buffer.from([byte]); }
  await runInstalledHeadlessJsonl(f.session, input(), async bytes => { output.push(bytes); });
  assert.deepEqual(output.map(bytes => JSON.parse(bytes.toString())), [
    { schemaVersion: 3, protocolVersion: 1, type: 'response', response: { protocolVersion: 1, ok: true, result: hello } },
    { schemaVersion: 3, protocolVersion: 1, type: 'response', response: refusal } ]);
  assert.deepEqual(f.counts(), { calls: 1, cancels: 0, closed: 0 }); await f.session.close();
});

test('schema3 JSONL backpressure stops further dispatch and output failure joins input without cancellation', async () => {
  const f = fixture(); let release!: () => void, entered!: () => void, joined = false, writes = 0;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const failure = new Error('inert output failure');
  async function* input() { try { yield Buffer.concat([line(request), line(request)]); } finally { joined = true; } }
  const pending = runInstalledHeadlessJsonl(f.session, input(), async () => {
    if (++writes === 2) { entered(); await gate; throw failure; }
  });
  await ready; assert.equal(f.counts().calls, 1); release();
  await assert.rejects(pending, error => error === failure);
  assert.equal(joined, true); assert.deepEqual(f.counts(), { calls: 1, cancels: 0, closed: 0 }); await f.session.close();
});

test('schema3 RPC uses the same application contract, requires hello and never dispatches notifications', async () => {
  const f = fixture(), output: any[] = [];
  const rpc = (id: number, method: string, params: unknown) => ({ jsonrpc: '2.0', id, method, params });
  async function* input() {
    yield line(rpc(1, 'supervisor.status', request));
    yield line({ jsonrpc: '2.0', method: 'run.cancel', params: request });
    yield line(rpc(2, 'control.hello', greeting(1)));
    yield line(rpc(3, 'control.hello', greeting(3)));
    yield line(rpc(4, 'supervisor.status', request));
  }
  await runInstalledHeadlessRpc(f.session, input(), async bytes => { output.push(JSON.parse(bytes.toString())); });
  assert.equal(output[0].error.code, -32602); assert.equal(output[1].error.code, -32600);
  assert.equal(output[2].result.response.error.code, 'INCOMPATIBLE_PROTOCOL');
  assert.equal(output[3].result.response.result.method, 'control.hello');
  assert.deepEqual(output[4], { jsonrpc: '2.0', id: 4,
    result: { schemaVersion: 3, protocolVersion: 1, type: 'response', response: refusal } });
  assert.deepEqual(f.counts(), { calls: 1, cancels: 0, closed: 0 }); await f.session.close();
});

test('schema3 malformed bytes, duplicate keys, truncation and oversized frames cannot invoke the Supervisor', async () => {
  for (const bytes of [Buffer.from('\n'), line({ ...request, authority: true }), line({ ...request, schemaVersion: 2 }),
    Buffer.from('{"schemaVersion":3,"schemaVersion":3,"request":{}}\n'), Buffer.from([0xc0, 0x80, 10]),
    line(request).subarray(0, line(request).length - 1), Buffer.alloc(1048577, 32)]) {
    const f = fixture();
    async function* input() { yield bytes; }
    await assert.rejects(runInstalledHeadlessJsonl(f.session, input(), async () => {}));
    assert.deepEqual(f.counts(), { calls: 0, cancels: 0, closed: 0 }); await f.session.close();
  }
});

test('schema3 response wrappers and incompatible original hello remain closed rather than being reinterpreted', () => {
  const wrapped = { schemaVersion: 3, protocolVersion: 1, type: 'response', response: refusal };
  assert.deepEqual(decodeHeadlessControlResponse(wrapped), wrapped);
  for (const value of [{ ...wrapped, extra: true }, { ...wrapped, schemaVersion: 2 }, { ...wrapped, protocolVersion: 2 },
    { ...wrapped, type: 'event' }, { ...wrapped, response: { ...refusal, error: { ...refusal.error, secret: 'inert' } } }])
    assert.throws(() => decodeHeadlessControlResponse(value));
  const value = headlessControlHello(greeting().request as never,
    { ...hello, headlessSchemaRange: { min: 1, max: 1 } } as never);
  assert.equal(value.response.ok, false);
  if (!value.response.ok && value.response.error.code === 'INCOMPATIBLE_PROTOCOL')
    assert.deepEqual(value.response.error.supportedHeadlessRange, { min: 1, max: 1 });
  else assert.fail('the original range1 server must explicitly refuse schema3');
});

for (const mode of ['jsonl', 'rpc'] as const) test(`${mode} explicitly drains every attach page through its actual sent cursor and correlated event records`, async () => {
  const cursors: number[] = [], output: any[] = [];
  const at = '2026-10-25T00:00:00.000Z', ref = 'a'.repeat(64);
  const snapshot = { schemaVersion: 1, operation: 'agent', latestRunItemSeq: 0, run: { id: 'run', sessionId: 'session', specRef: ref,
    status: 'queued', nextStep: 'agent', frontierRef: ref, revision: 1, leaseEpoch: 0, latestCheckpointId: 'checkpoint',
    budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0,
    cancelRequested: false, createdAt: at, updatedAt: at, deadlineAt: '2026-10-25T01:00:00.000Z' } };
  const client = { hello: { ...hello, enabledFeatureIds: ['run.attach'] }, close: async () => {},
    'run.attach': async (request: { afterEventSeq: number }) => {
      cursors.push(request.afterEventSeq); assert(cursors.length <= 3, 'one attach cannot chase a growing producer');
      const next = request.afterEventSeq + 1, high = cursors.length === 1 ? 3 : 99;
      return { protocolVersion: 1, ok: true, result: { method: 'run.attach', snapshot,
        earliestRetainedEventSeq: 1, latestRetainedEventSeq: high, highWaterEventSeq: high, nextEventSeq: next,
        events: [{ schemaVersion: 1, kind: 'progress', runId: 'run', eventSeq: next,
          observedRunRevision: 1, phase: 'agent', occurredAt: at }] } };
    } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client);
  const attach = { schemaVersion: 3, request: { protocolVersion: 1, method: 'run.attach', runId: 'run', afterEventSeq: 0, limit: 1 } };
  async function* input() {
    if (mode === 'rpc') yield line({ jsonrpc: '2.0', id: 'hello', method: 'control.hello', params: greeting(3, ['run.attach']) });
    yield line(mode === 'rpc' ? { jsonrpc: '2.0', id: 'attached', method: 'run.attach', params: attach } : attach);
  }
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const write = async (bytes: Buffer) => {
    const value = JSON.parse(bytes.toString()); output.push(value);
    const record = mode === 'rpc' ? value.params?.record : value;
    if (record?.type === 'progress' && record.eventSeq === 1) { entered(); await gate; }
  };
  const pending = (mode === 'rpc' ? runInstalledHeadlessRpc : runInstalledHeadlessJsonl)(session, input(), write);
  await ready; assert.deepEqual(cursors, [0]); release(); await pending;
  assert.deepEqual(cursors, [0, 1, 2]);
  const records = mode === 'rpc' ? output.filter(value => value.method === 'control.record').map(value => {
    assert.equal(value.params.id, 'attached'); return value.params.record;
  }) : output.slice(1);
  assert.deepEqual(records.map(value => value.type), ['response', 'progress', 'response', 'progress', 'response', 'progress']);
  assert.deepEqual(records.filter(value => value.type === 'progress').map(value => [value.runId, value.eventSeq, value.timestamp]),
    [['run', 1, at], ['run', 2, at], ['run', 3, at]]);
  assert(records.filter(value => value.type === 'response').every(value => value.response.result.snapshot.run.status === 'queued'));
  if (mode === 'rpc') {
    const results = output.filter(value => value.id === 'attached'); assert.equal(results.length, 1);
    assert.equal(results[0].result.response.result.nextEventSeq, 3);
  }
  await session.close();
});

for (const mode of ['jsonl', 'rpc'] as const) test(`${mode} ends an expired attach at EOF with its authoritative snapshot and no cancellation`, async () => {
  let calls = 0, cancels = 0;
  const at = '2026-10-25T00:00:00.000Z', ref = 'a'.repeat(64);
  const snapshot = { schemaVersion: 1, operation: 'agent', latestRunItemSeq: 0, run: { id: 'run', sessionId: 'session', specRef: ref,
    status: 'queued', nextStep: 'agent', frontierRef: ref, revision: 1, leaseEpoch: 0, latestCheckpointId: 'checkpoint',
    budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0,
    cancelRequested: false, createdAt: at, updatedAt: at, deadlineAt: '2026-10-25T01:00:00.000Z' } };
  const expired = { protocolVersion: 1, ok: false, method: 'run.attach', error: { schemaVersion: 1, code: 'EVENT_CURSOR_EXPIRED',
    retryable: false, messageCode: 'expired', earliestEventSeq: 5, latestEventSeq: 7, snapshot } };
  const client = { hello: { ...hello, enabledFeatureIds: ['run.attach'] }, close: async () => {},
    'run.attach': async () => { calls++; return expired; }, 'run.cancel': async () => { cancels++; } } as unknown as InstalledSupervisorClient;
  const session = createInstalledControlSession(client), output: any[] = [];
  const attach = { schemaVersion: 3, request: { protocolVersion: 1, method: 'run.attach', runId: 'run', afterEventSeq: 0 } };
  async function* input() {
    if (mode === 'rpc') yield line({ jsonrpc: '2.0', id: 0, method: 'control.hello', params: greeting(3, ['run.attach']) });
    yield line(mode === 'rpc' ? { jsonrpc: '2.0', id: 1, method: 'run.attach', params: attach } : attach);
  }
  await (mode === 'rpc' ? runInstalledHeadlessRpc : runInstalledHeadlessJsonl)(session, input(), async bytes => { output.push(JSON.parse(bytes.toString())); });
  assert.equal(calls, 1); assert.equal(cancels, 0);
  const result = mode === 'rpc' ? output.at(-1).result : output.at(-1);
  assert.deepEqual(result.response, expired); await session.close();
});
