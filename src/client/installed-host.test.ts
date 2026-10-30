import assert from 'node:assert/strict';
import test from 'node:test';
import { createClientHostSession, openCliqClient } from './installed-host.js';
import { protocolClient, hello } from './testing/protocol.js';
import { createInstalledControlSession } from '../control/session.js';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { joinResourceOperations, ResourceRetirementError } from '../state/errors.js';
import type { HeldInstalledRuntime } from '../state/installed-runtime.js';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import vm from 'node:vm';
import type { PendingRequests } from './pending-requests.js';

/** Execute the original composition bodies over the existing inert protocol
 * seam. No structural object is passed off as a held installation, authenticated
 * peer, native loader, filesystem receipt or Run authority. Real Linux keeps
 * its separate signed-opaque manager-refusal and complete installed campaigns. */
function openingComposition(input: {
  connect(): Promise<InstalledSupervisorClient>;
  data(): Promise<import('./installed-data.js').InstalledClientData>;
}) {
  const declaration = (relative: string, name: string) => {
    const source = ts.createSourceFile(relative, readFileSync(new URL(relative, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
    const node = source.statements.find((node): node is ts.FunctionDeclaration => ts.isFunctionDeclaration(node) && node.name?.text === name);
    assert(node?.body); return node.getText(source).replace(/^export\s+/u, '');
  };
  const code = declaration('../control/session.ts', 'openInstalledControlSession') + '\n' +
    declaration('./installed-host.ts', 'openInstalledClientHost') + '\nglobalThis.openHost = openInstalledClientHost;';
  const context = vm.createContext({ openInstalledSupervisorClient: input.connect, createInstalledControlSession, createClientHostSession,
    openInstalledClientData: input.data, canonicalJsonBytes, joinResourceOperations, ResourceRetirementError,
    withHeldInstalledRuntime: async (_selected: unknown, check: (tuple: object) => Promise<void>) => {
      await check({ stateRoot: { identity: 'inert-root' }, bundleDigest: 'inert-bundle' });
    } });
  vm.runInContext(ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, context);
  return context.openHost as typeof import('./installed-host.js').openInstalledClientHost;
}

test('owned request data waits for the original peer opening and every first mutation waits for durable retention', async () => {
  const events: string[] = []; let release!: (peer: InstalledSupervisorClient) => void;
  const authenticated = new Promise<InstalledSupervisorClient>(resolve => { release = resolve; });
  let started!: () => void; const opening = new Promise<void>(resolve => { started = resolve; });
  const store = { async retain() { events.push('retained'); return { existing: false }; },
    async resolve() { events.push('response retained'); } } as unknown as PendingRequests;
  const data = { requests: store, close: async () => { events.push('data closed'); } } as unknown as import('./installed-data.js').InstalledClientData;
  const peer = { hello: { ...hello, enabledFeatureIds: ['run.cancel'] }, close: async () => { events.push('peer closed'); },
    'run.cancel': async () => { events.push('sent'); return { protocolVersion: 1, ok: false, method: 'run.cancel',
      error: { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } }; } } as unknown as InstalledSupervisorClient;
  const open = openingComposition({ connect: async () => { events.push('opening peer'); started(); return authenticated; },
    data: async () => { events.push('data opened'); return data; } });
  const pending = open({} as HeldInstalledRuntime); await opening;
  assert.deepEqual(events, ['opening peer']);
  release(peer); const host = await pending, app = host.application(() => {});
  assert.deepEqual(events, ['opening peer', 'data opened']);
  const core = { protocolVersion: 1 as const, method: 'run.cancel' as const,
    requestId: '019a0012-0000-7000-8000-000000000902', runId: 'run', expectedRevision: 1 };
  await app.execute({ kind: 'request', request: { ...core, requestDigest: canonicalSha256(core) } });
  await app.close();
  assert.deepEqual(events, ['opening peer', 'data opened', 'retained', 'sent', 'response retained', 'peer closed', 'data closed']);
});

test('manager refusal opens no own data; data failure joins the original peer close and preserves retirement priority', async () => {
  const refusal = new Error('original manager refused'); let dataCalls = 0;
  const refused = openingComposition({ connect: async () => { throw refusal; }, data: async () => { dataCalls++; throw new Error('must not open'); } });
  await assert.rejects(refused({} as HeldInstalledRuntime), error => error === refusal); assert.equal(dataCalls, 0);
  for (const originalIsRetirement of [false, true]) {
    const retirement = new ResourceRetirementError('original owner close is uncertain', new Error('inert retirement'));
    const original = originalIsRetirement ? retirement : new Error('data preparation refused');
    let enter!: () => void, release!: () => void, returned = false, closed = 0;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    const peer = { hello, close: async () => { closed++; enter(); await gate; if (!originalIsRetirement) throw retirement; } } as InstalledSupervisorClient;
    const open = openingComposition({ connect: async () => peer, data: async () => { throw original; } });
    const pending = open({} as HeldInstalledRuntime).then(() => { throw new Error('must refuse'); }, error => { returned = true; return error; });
    await entered; assert.equal(returned, false); assert.equal(closed, 1);
    release(); assert.equal(await pending, retirement); assert.equal(closed, 1);
  }
});

test('borrowed data stays borrowed while the original peer failure is retired', async () => {
  let loaded = 0, dataClosed = 0, peerClosed = 0;
  const data = { stateRoot: { identity: 'inert-root' }, sourceBundleDigest: 'inert-bundle', requests: {},
    close: async () => { dataClosed++; } } as unknown as import('./installed-data.js').InstalledClientData;
  const open = openingComposition({ data: async () => { loaded++; throw new Error('must not load own data'); },
    connect: async () => ({ hello: { ...hello, headlessSchemaRange: { min: 1, max: 1 } }, close: async () => { peerClosed++; } }) as InstalledSupervisorClient });
  await assert.rejects(open({} as HeldInstalledRuntime, data), /headless schema 3/u);
  assert.equal(peerClosed, 1); assert.equal(loaded, 0); assert.equal(dataClosed, 0);
});

test('an already prepared own data family joins after peer failure without hiding its original retirement uncertainty', async () => {
  const retirement = new ResourceRetirementError('original peer close is uncertain', new Error('inert close'));
  const events: string[] = [];
  const data = { requests: {}, close: async () => { events.push('data closed'); throw new Error('ordinary data close failed'); } } as unknown as
    import('./installed-data.js').InstalledClientData;
  const open = openingComposition({ data: async () => { events.push('data opened'); return data; },
    connect: async () => ({ hello: { ...hello, headlessSchemaRange: { min: 1, max: 1 } },
      close: async () => { events.push('peer closed'); throw retirement; } }) as unknown as InstalledSupervisorClient });
  await assert.rejects(open({} as HeldInstalledRuntime), error => error === retirement);
  assert.deepEqual(events, ['data opened', 'peer closed', 'data closed']);
});

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

test('only joined uncancelled text/JSON output may acknowledge known sends; Ink retains them', () => {
  // Routing assertion only. No structural installation/stdio/native handle is
  // supplied to the host, and no render callback is fabricated as delivery.
  const source = ts.createSourceFile('installed-host.ts', readFileSync(new URL('./installed-host.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  let ink: ts.VariableDeclaration | undefined, acknowledgement: ts.CallExpression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'ink') ink = node;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'acknowledgeSent') {
      assert.equal(acknowledgement, undefined); acknowledgement = node;
    }
    ts.forEachChild(node, visit);
  }; visit(source); assert(ink?.initializer); assert(acknowledgement);
  let guarded: ts.Node = acknowledgement;
  while (guarded.parent && !ts.isIfStatement(guarded)) guarded = guarded.parent;
  assert(ts.isIfStatement(guarded));
  const usesInk = new Function('invocation', 'owned', `return (${ink.initializer.getText(source)});`) as
    (invocation: object, owned: object) => boolean;
  const acknowledges = new Function('result', 'signal', 'ink', `return (${guarded.expression.getText(source)});`) as
    (result: number, signal: { aborted: boolean }, ink: boolean) => boolean;
  for (const [invocation, tty, expected] of [
    [{ kind: 'tui' }, true, false], [{ kind: 'tui' }, false, false],
    [{ kind: 'attach', json: false }, true, false], [{ kind: 'attach', json: true }, true, true],
    [{ kind: 'run', json: false, detach: false }, true, false], [{ kind: 'apply', json: false, detach: false }, true, false],
    [{ kind: 'run', json: true, detach: false }, true, true], [{ kind: 'apply', json: false, detach: true }, true, true],
    [{ kind: 'run', json: false, detach: false }, false, true], [{ kind: 'request-replay', json: false }, true, true],
    [{ kind: 'jsonl' }, false, true], [{ kind: 'rpc' }, false, true]
  ] as const) {
    const interactive = usesInk(invocation, { io: { output: { isTTY: tty } } });
    assert.equal(acknowledges(0, { aborted: false }, interactive), expected);
    assert.equal(acknowledges(0, { aborted: true }, interactive), false);
    assert.equal(acknowledges(1, { aborted: false }, interactive), false);
  }
  const text = source.getFullText();
  assert(text.indexOf('await owned.close()') < acknowledgement.getStart(source));
  assert(text.indexOf('if (failure !== undefined) throw failure') < acknowledgement.getStart(source));
});
