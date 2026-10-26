import assert from 'node:assert/strict';
import test from 'node:test';
import { createClientHostSession, openCliqClient } from './installed-host.js';
import { protocolClient, hello } from './testing/protocol.js';
import { createInstalledControlSession } from '../control/session.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { ResourceRetirementError } from '../state/errors.js';
import type { HeldInstalledRuntime } from '../state/installed-runtime.js';

// Existing byte-consumer seam, never a genuine installed peer/Run/native proof.
test('the shared SDK host keeps the original pending request through reconnect and joins one explicit replay', async () => {
  let calls = 0, closed = 0;
  const connect = async () => ({ hello: { ...hello, enabledFeatureIds: ['run.cancel'] }, close: async () => { closed++; }, 'run.cancel': async () => {
    calls++; if (calls === 1) throw new Error('lost original response');
    return { protocolVersion: 1, ok: false, method: 'run.cancel', error: {
      schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'inert.closed_refusal' } };
  } } as unknown as InstalledSupervisorClient);
  const host = createClientHostSession(createInstalledControlSession(await connect(), connect)), updates: string[] = [], client = host.application(update => { updates.push(update.kind); });
  const core = { protocolVersion: 1 as const, method: 'run.cancel' as const, requestId: '019a0012-0000-7000-8000-000000000901', runId: 'run', expectedRevision: 1 };
  const request = { ...core, requestDigest: canonicalSha256(core) };
  await assert.rejects(client.execute({ kind: 'request', request }), /lost original response/);
  assert(canonicalJsonBytes(client.pendingRequest).equals(canonicalJsonBytes(request)));
  await client.execute({ kind: 'reconnect' }); assert.equal(calls, 1);
  assert.equal(client.pendingRequest?.method, 'run.cancel');
  assert(canonicalJsonBytes(client.pendingRequest).equals(canonicalJsonBytes(request)));
  const response = await client.replay(); assert.equal(response.ok, false); assert.equal(calls, 2);
  assert.equal(client.pendingRequest, undefined, 'the public getter must not become a stale spread-copy value');
  assert.throws(() => host.application(() => {}), /already has a surface/);
  await client.close(); await host.close(); assert.equal(closed, 2); assert(updates.includes('pending')); assert(updates.includes('response'));
  assert.equal(calls, 2);
});

test('SDK close revokes and joins the original active response without cancelling the server Run', async () => {
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  let closed = 0;
  const f = protocolClient({ close: async () => { closed++; release(); }, 'supervisor.status': async () => {
    entered(); await gate; return { protocolVersion: 1, ok: false, method: 'supervisor.status',
      error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'inert.closed_refusal' } };
  } });
  const client = createClientHostSession(f.session).application(() => {});
  const operation = client.execute({ kind: 'request', request: { protocolVersion: 1, method: 'supervisor.status' } });
  const observed = operation.then(value => ({ value }), error => ({ error })); await ready;
  await client.close(); await observed;
  assert.equal(closed, 1); assert.equal(f.calls.some(call => call.method === 'run.cancel'), false);
});

test('the installed SDK rejects structural selections before reading caller fields and preserves genuine close uncertainty', async () => {
  let accessed = 0;
  const structural = new Proxy({}, { get() { accessed++; throw new Error('must not inspect'); } });
  await assert.rejects(openCliqClient(structural as HeldInstalledRuntime)); assert.equal(accessed, 0);
  const retirement = new ResourceRetirementError('actual protocol fixture close is uncertain', new Error('original close failure'));
  const f = protocolClient({ close: async () => { throw retirement; } });
  const client = createClientHostSession(f.session).application(() => {});
  await assert.rejects(client.close(), error => error === retirement);
  await assert.rejects(client.close(), error => error === retirement);
});

test('SDK detach joins the borrowed output callback without closing or replacing that callback', async () => {
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const f = protocolClient({ 'supervisor.status': async () => ({ protocolVersion: 1, ok: false, method: 'supervisor.status',
    error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'inert.closed_refusal' } }) });
  let delivered = 0;
  const sink = async (update: import('./types.js').ClientUpdate) => {
    if (update.kind === 'response') { delivered++; entered(); await gate; }
  };
  const client = createClientHostSession(f.session).application(sink);
  const operation = client.execute({ kind: 'request', request: { protocolVersion: 1, method: 'supervisor.status' } });
  await ready;
  let joined = false;
  const closing = client.close().then(() => { joined = true; });
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(joined, false, 'a display promise cannot replace the actual in-flight callback join');
  assert.equal(delivered, 1);
  release(); await Promise.all([operation, closing]);
  assert.equal(joined, true); assert.equal(f.calls.some(call => call.method === 'run.cancel'), false);
});
