import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import path from 'node:path';
import { test, type TestContext } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { SessionContextProjection, SessionItem } from '../kernel/types.js';
import { openInstalledControl } from './installed-control.js';
import { openSqliteDriver } from './sqlite-driver.js';
import type { StateStore } from './store.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';

// This seam qualifies real framing, native UDS authentication and retained
// SQLite/CAS reads. The signed current Node is not an installed SEA, and the
// queued metadata fixture never starts a worker or model/provider runtime.
async function bounded<T>(operation: Promise<T>, timeoutMs = 30_000): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('installed control test timed out')), timeoutMs);
    })]);
  } finally { clearTimeout(timer); }
}

type PeerMessage = { kind: string; id?: number; value?: Record<string, any>; json?: string };
async function connectPeer(t: TestContext, socketPath: string) {
  const script = `import net from 'node:net';
    const socket = net.createConnection(process.argv[1], () => process.send({kind:'ready'}));
    let input = Buffer.alloc(0);
    socket.on('data', chunk => {
      input = Buffer.concat([input, chunk]);
      while (input.length >= 4) {
        const length = input.readUInt32BE(0);
        if (length < 1 || length > 1048576) throw new Error('invalid response frame length');
        if (input.length < 4 + length) break;
        const json = input.subarray(4, 4 + length).toString('utf8');
        input = input.subarray(4 + length);
        process.send({kind:'response', value:JSON.parse(json), json});
      }
    });
    socket.on('error', () => {});
    socket.on('close', () => process.send({kind:'closed'}));
    process.on('message', message => {
      if (message.kind === 'write') socket.write(Buffer.from(message.bytes, 'base64'),
        () => process.send({kind:'sent', id:message.id}));
      if (message.kind === 'pause') { socket.pause(); process.send({kind:'paused'}); }
      if (message.kind === 'resume') { socket.resume(); process.send({kind:'resumed'}); }
    });
    process.on('disconnect', () => { socket.destroy(); process.exit(0); });`;
  const child: ChildProcess = spawn(process.execPath,
    ['--input-type=module', '-e', script, socketPath], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  const exited = once(child, 'exit');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await bounded(exited);
  });
  const messages: PeerMessage[] = [];
  const waiting: Array<{ kind: string; resolve: (message: PeerMessage) => void }> = [];
  child.on('message', (message: PeerMessage) => {
    const index = waiting.findIndex(entry => entry.kind === message.kind);
    if (index < 0) messages.push(message);
    else waiting.splice(index, 1)[0]!.resolve(message);
  });
  const receive = (kind: string, timeoutMs = 30_000): Promise<PeerMessage> => {
    const index = messages.findIndex(message => message.kind === kind);
    if (index >= 0) return Promise.resolve(messages.splice(index, 1)[0]!);
    let entry!: typeof waiting[number];
    const pending = new Promise<PeerMessage>(resolve => { entry = { kind, resolve }; waiting.push(entry); });
    return bounded(pending, timeoutMs).finally(() => {
      const remaining = waiting.indexOf(entry);
      if (remaining >= 0) waiting.splice(remaining, 1);
    });
  };
  await receive('ready');
  let nextId = 0;
  return {
    receive,
    async pause() { child.send({ kind: 'pause' }); await receive('paused'); },
    async resume() { child.send({ kind: 'resume' }); await receive('resumed'); },
    async write(bytes: Buffer) {
      const id = ++nextId;
      child.send({ kind: 'write', id, bytes: bytes.toString('base64') });
      assert.equal((await receive('sent')).id, id);
    },
    async response(timeoutMs = 30_000) {
      const message = await receive('response', timeoutMs);
      assert.equal(message.json, canonicalJsonBytes(message.value).toString('utf8'));
      return message.value!;
    }
  };
}

function frame(value: unknown): Buffer {
  return byteFrame(canonicalJsonBytes(value));
}
function byteFrame(body: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.byteLength);
  return Buffer.concat([header, body]);
}

const compatibleHello = { protocolVersion: 1, method: 'control.hello', clientBuild: 'wire-client-fixture',
  controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, requestedFeatureIds: [] };

/** Retained display arrangement only, not Session mutation or execution qualification. */
async function retainLargeSessionDisplay(store: StateStore, sessionId: string): Promise<void> {
  const session = store.getSession(sessionId);
  const payload = await store.artifacts.publishCanonical({ fixture: 'retained-display-only' }, 'cliq-display-query-fixture-v1');
  const items: SessionItem[] = Array.from({ length: 1000 }, (_, index) => ({ schemaVersion: 1,
    sessionId, itemSeq: index + 1, itemId: `${'display-'.padEnd(124, 'x')}${String(index + 1).padStart(4, '0')}`,
    kind: 'legacy_bookmark', payloadRef: payload.ref, createdAt: session.createdAt }));
  const projection: SessionContextProjection = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId,
    contextRevision: session.contextRevision + 1, throughItemSeq: items.length,
    segments: [{ kind: 'excluded_control', fromItemSeq: 1, throughItemSeq: items.length,
      sourceItemsDigest: canonicalSha256(items.map(({ itemSeq, kind, payloadRef }) => ({ itemSeq, kind, payloadRef }))) }], projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const retained = await store.artifacts.publishCanonical(projection, projection.format);
  const writer = openSqliteDriver(path.join(store.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    writer.transaction(connection => {
      for (const item of items) connection.prepare(`INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at)
        VALUES (?, ?, NULL, ?, ?, ?, ?)`).run(item.itemId, sessionId, item.itemSeq, item.kind, item.payloadRef, item.createdAt);
      connection.prepare('UPDATE sessions SET latest_item_seq = ?, context_revision = ?, context_projection_ref = ? WHERE id = ?')
        .run(items.length, projection.contextRevision, retained.ref, sessionId);
    });
  } finally { writer.close(); }
}

test('compatible split hello unlocks three real bounded reads with coalesced frames in FIFO order', async t => {
  const fixture = await createQueuedFixture('wire');
  t.after(() => disposeFixture(fixture));
  const errors: Error[] = [];
  const service = openInstalledControl(fixture.store,
    { serverBuild: 'installed-control-wire-fixture' }, error => errors.push(error));
  t.after(() => service.close());
  const peer = await connectPeer(t, path.join(fixture.stateRoot, 'runtime/control-v1.sock'));
  const hello = frame({ protocolVersion: 1, method: 'control.hello', clientBuild: 'wire-client-fixture',
    controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    requestedFeatureIds: ['session.get', 'run.get', 'run.attach', 'run.result', 'run.diff', 'run.submit'] });
  await peer.write(hello.subarray(0, 1));
  await peer.write(hello.subarray(1, 3));
  const run = fixture.store.getRun(fixture.runId);
  const session = fixture.store.getSession(run.sessionId);
  await peer.write(Buffer.concat([hello.subarray(3),
    frame({ protocolVersion: 1, method: 'session.get', sessionId: session.id, limit: 1 }),
    frame({ protocolVersion: 1, method: 'run.get', runId: run.id, checkpointLimit: 1 }),
    frame({ protocolVersion: 1, method: 'run.attach', runId: run.id, afterEventSeq: 0, limit: 1 })]));

  const greeting = await peer.response();
  assert.equal(greeting.protocolVersion, 1);
  assert.equal(greeting.ok, true);
  assert.equal(greeting.result.method, 'control.hello');
  assert.equal(greeting.result.serverBuild, 'installed-control-wire-fixture');
  assert.deepEqual(greeting.result.controlSchemaRange, { min: 1, max: 1 });
  assert.deepEqual(greeting.result.headlessSchemaRange, { min: 1, max: 1 });
  assert.deepEqual(greeting.result.enabledFeatureIds, ['session.get', 'run.get', 'run.attach', 'run.result', 'run.diff']);
  assert.ok(greeting.result.supervisorInstanceId);
  assert.equal(greeting.result.activeRuntimeBundle.runtimeBundleRef, canonicalSha256(fixture.runtimeAuthority.bundle));
  assert.equal(greeting.result.activeRuntimeBundle.bundleVersion, fixture.runtimeAuthority.bundle.bundleVersion);

  const sessionRead = await peer.response();
  assert.equal(sessionRead.ok, true);
  assert.deepEqual(sessionRead.result, { method: 'session.get', snapshot: { schemaVersion: 1, session },
    items: [], highWaterItemSeq: 0, nextItemSeq: 0 });
  const runRead = await peer.response();
  assert.equal(runRead.ok, true);
  assert.equal(runRead.result.method, 'run.get');
  assert.deepEqual(runRead.result.snapshot.run, run);
  assert.deepEqual(runRead.result.items, []);
  assert.deepEqual(runRead.result.journal, []);
  assert.equal(runRead.result.checkpoints.length, 1);
  assert.equal(runRead.result.checkpoints[0].id, run.latestCheckpointId);
  assert.equal(runRead.result.checkpoints[0].reason, 'initial');
  const attached = await peer.response();
  assert.equal(attached.ok, true);
  assert.equal(attached.result.method, 'run.attach');
  assert.deepEqual(attached.result.snapshot.run, run);
  assert.equal(attached.result.events.length, 1);
  assert.equal(attached.result.events[0].eventSeq, 1);
  assert.equal(attached.result.nextEventSeq, 1);
  for (const method of ['run.result', 'run.diff']) {
    await peer.write(frame({ protocolVersion: 1, method, runId: run.id }));
    assert.deepEqual(await peer.response(), { protocolVersion: 1, method, ok: false,
      error: { schemaVersion: 1, code: 'RESULT_UNAVAILABLE', messageCode: 'run.result_unavailable', retryable: true,
        runId: run.id, status: run.status, currentRevision: run.revision } });
  }
  assert.deepEqual(fixture.store.getRun(run.id), run, 'wire reads do not execute or mutate the queued Run');
  assert.deepEqual(errors, []);
});

test('malformed and overflowing clients retire only their connection even when the reporter throws', async t => {
  const fixture = await createQueuedFixture('frames');
  t.after(() => disposeFixture(fixture));
  const errors: Error[] = [];
  const service = openInstalledControl(fixture.store, { serverBuild: 'wire-frame-fixture' }, error => {
    errors.push(error);
    throw new Error('deliberately failing consumer reporter');
  });
  t.after(() => service.close());
  const socketPath = path.join(fixture.stateRoot, 'runtime/control-v1.sock');
  const survivor = await connectPeer(t, socketPath);
  await survivor.write(frame(compatibleHello));
  assert.equal((await survivor.response()).ok, true);
  const run = fixture.store.getRun(fixture.runId);
  const oversized = Buffer.alloc(4);
  oversized.writeUInt32BE(1_048_577);
  const badFrames = [Buffer.alloc(4), oversized, byteFrame(Buffer.from([0xc0, 0x80])),
    byteFrame(Buffer.from('{"method":"control.hello","method":"run.submit"}')),
    byteFrame(Buffer.from('{ "method": "run.submit", "protocolVersion": 1 }')),
    frame([]), Buffer.concat([frame(compatibleHello),
      ...Array.from({ length: 65 }, () => frame({ protocolVersion: 1, method: 'run.get', runId: run.id }))])];
  for (const bytes of badFrames) {
    const bad = await connectPeer(t, socketPath);
    await bad.write(bytes);
    await bad.receive('closed');
    await survivor.write(frame({ protocolVersion: 1, method: 'run.get', runId: run.id }));
    assert.deepEqual((await survivor.response()).result.snapshot.run, run);
  }
  assert.ok(errors.length >= badFrames.length);
  assert.deepEqual(fixture.store.getRun(run.id), run);
});

test('hello-first compatibility grants bounded reads only, not client identity or mutation authority', async t => {
  const fixture = await createQueuedFixture('gate');
  t.after(() => disposeFixture(fixture));
  const errors: Error[] = [];
  const service = openInstalledControl(fixture.store, { serverBuild: 'wire-gate-fixture' }, error => errors.push(error));
  t.after(() => service.close());
  const peer = await connectPeer(t, path.join(fixture.stateRoot, 'runtime/control-v1.sock'));
  const run = fixture.store.getRun(fixture.runId);
  await peer.write(frame({ protocolVersion: 1, method: 'run.get', runId: 'not-an-owned-run' }));
  const beforeHello = await peer.response();
  assert.equal(beforeHello.ok, false);
  assert.equal(beforeHello.error.code, 'AUTHORIZATION_REQUIRED');
  assert.equal(beforeHello.error.messageCode, 'control.hello_required');
  await peer.write(frame({ ...compatibleHello, headlessSchemaRange: { min: 2, max: 2 } }));
  const incompatible = await peer.response();
  assert.equal(incompatible.error.code, 'INCOMPATIBLE_PROTOCOL');
  assert.deepEqual(incompatible.error.supportedControlRange, { min: 1, max: 1 });
  assert.deepEqual(incompatible.error.supportedHeadlessRange, { min: 1, max: 1 });
  assert.equal(incompatible.error.upgradeAction, 'upgrade_supervisor');
  await peer.write(frame({ protocolVersion: 1, method: 'run.get', runId: run.id }));
  assert.equal((await peer.response()).error.code, 'AUTHORIZATION_REQUIRED');
  await peer.write(frame(compatibleHello));
  assert.equal((await peer.response()).ok, true);
  await peer.write(Buffer.concat([
    frame({ protocolVersion: 1, method: 'run.submit', objective: 'must not run' }),
    frame({ protocolVersion: 1, method: 'run.get', runId: run.id, principalId: fixture.principalId }),
    frame({ protocolVersion: 1, method: 'legacy.private-method' }),
    frame({ protocolVersion: 1, method: 'run.get', runId: run.id })]));
  const mutator = await peer.response();
  assert.equal(mutator.method, 'run.submit');
  assert.equal(mutator.error.code, 'AUTHORIZATION_REQUIRED');
  const injected = await peer.response();
  assert.equal(injected.error.code, 'INVALID_REQUEST');
  const unknown = await peer.response();
  assert.equal(unknown.error.code, 'INVALID_REQUEST');
  assert.equal(unknown.rejectedMethodDigest, createHash('sha256').update('legacy.private-method').digest('hex'));
  assert.equal(Object.hasOwn(unknown, 'method'), false);
  assert.equal(JSON.stringify(unknown).includes('legacy.private-method'), false);
  assert.deepEqual((await peer.response()).result.snapshot.run, run);
  assert.deepEqual(fixture.store.getRun(run.id), run);
  assert.deepEqual(errors, []);
});

test('closing a service joins pending transport and a fresh listener requires a fresh hello', async t => {
  const fixture = await createQueuedFixture('close');
  t.after(() => disposeFixture(fixture));
  const errors: Error[] = [];
  const first = openInstalledControl(fixture.store, { serverBuild: 'wire-close-fixture' }, error => errors.push(error));
  t.after(() => first.close());
  const socketPath = path.join(fixture.stateRoot, 'runtime/control-v1.sock');
  const partial = await connectPeer(t, socketPath);
  await partial.write(frame(compatibleHello).subarray(0, 5));
  const ownerEpoch = fixture.store.ownerEpoch;
  const closing = first.close();
  assert.equal(first.close(), closing);
  await closing;
  await partial.receive('closed');
  assert.equal(fixture.store.ownerEpoch, ownerEpoch, 'closing transport does not retire the Store owner');
  const second = openInstalledControl(fixture.store, { serverBuild: 'wire-close-fixture' }, error => errors.push(error));
  t.after(() => second.close());
  const fresh = await connectPeer(t, socketPath);
  const run = fixture.store.getRun(fixture.runId);
  await fresh.write(frame({ protocolVersion: 1, method: 'run.get', runId: run.id }));
  assert.equal((await fresh.response()).error.code, 'AUTHORIZATION_REQUIRED');
  await fresh.write(Buffer.concat([frame(compatibleHello), frame({ protocolVersion: 1, method: 'run.get', runId: run.id })]));
  assert.equal((await fresh.response()).ok, true);
  assert.deepEqual((await fresh.response()).result.snapshot.run, run);
  await second.close();
  await fresh.receive('closed');
  assert.deepEqual(errors, []);
});

test('a real slow-reader backpressure cannot block an independent authenticated control peer', async t => {
  const fixture = await createQueuedFixture('slow');
  t.after(() => disposeFixture(fixture));
  const run = fixture.store.getRun(fixture.runId);
  await retainLargeSessionDisplay(fixture.store, run.sessionId);
  const errors: Error[] = [];
  const service = openInstalledControl(fixture.store, { serverBuild: 'wire-backpressure-fixture' }, error => errors.push(error));
  t.after(() => service.close());
  const socketPath = path.join(fixture.stateRoot, 'runtime/control-v1.sock');
  const slow = await connectPeer(t, socketPath);
  const fast = await connectPeer(t, socketPath);
  for (const peer of [slow, fast]) {
    await peer.write(frame(compatibleHello));
    assert.equal((await peer.response()).ok, true);
  }
  await slow.pause();
  await slow.write(frame({ protocolVersion: 1, method: 'session.get', sessionId: run.sessionId, limit: 1000 }));
  await fast.write(frame({ protocolVersion: 1, method: 'run.get', runId: run.id }));
  try {
    assert.deepEqual((await fast.response(3000)).result.snapshot.run, run,
      'another peer must receive its bounded read while the first peer is still paused');
  } finally { await slow.resume(); }
  const large = await slow.response();
  assert.equal(large.result.method, 'session.get');
  assert.equal(large.result.items.length, 1000);
  assert.equal(large.result.items[0].itemSeq, 1);
  assert.equal(large.result.items[999].itemSeq, 1000);
  assert.equal(large.result.nextItemSeq, 1000);
  assert.ok(canonicalJsonBytes(large).byteLength > 300_000);
  assert.deepEqual(fixture.store.getRun(run.id), run);
  assert.deepEqual(errors, []);
});

test('outstanding capacity is shared across peers and shutdown joins real backpressured writes', async t => {
  const fixture = await createQueuedFixture('budget');
  t.after(() => disposeFixture(fixture));
  const run = fixture.store.getRun(fixture.runId);
  await retainLargeSessionDisplay(fixture.store, run.sessionId);
  const errors: Error[] = [];
  const service = openInstalledControl(fixture.store, { serverBuild: 'wire-budget-fixture' }, error => errors.push(error));
  t.after(() => service.close());
  const socketPath = path.join(fixture.stateRoot, 'runtime/control-v1.sock');
  const paused = await connectPeer(t, socketPath);
  const overflowing = await connectPeer(t, socketPath);
  for (const peer of [paused, overflowing]) {
    await peer.write(frame(compatibleHello));
    assert.equal((await peer.response()).ok, true);
  }
  await paused.pause();
  await paused.write(frame({ protocolVersion: 1, method: 'session.get', sessionId: run.sessionId, limit: 1000 }));
  const reads = Buffer.concat(Array.from({ length: 32 }, () => frame({ protocolVersion: 1, method: 'run.get', runId: run.id })));
  await paused.write(reads);
  await overflowing.write(reads);
  await overflowing.receive('closed', 3000);

  const survivor = await connectPeer(t, socketPath);
  await survivor.write(Buffer.concat([frame(compatibleHello), frame({ protocolVersion: 1, method: 'run.get', runId: run.id })]));
  assert.equal((await survivor.response(3000)).ok, true);
  assert.deepEqual((await survivor.response(3000)).result.snapshot.run, run);
  // The first peer remains paused. Shutdown must independently destroy its
  // transferred socket, join active callbacks and discard its queued reads.
  await bounded(service.close(), 3000);
  // pause also defers the client's EOF observation. Resume only after the
  // server's close has already completed with all write callbacks joined.
  await paused.resume();
  await paused.receive('closed', 3000);
  await survivor.receive('closed');
  assert.deepEqual(fixture.store.getRun(run.id), run);
  assert.ok(errors.length > 0, 'the bounded overflow is reported, not silently accepted');
});
