import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import type { LocalSocketPeerObservationV1, PlatformProcessIdentityV1 } from '../kernel/types.js';
import type { AuthenticatedControlIdentity, LocalControlConnection, LocalControlListener } from './control-channel.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { admissionKey, createActiveFixture, makePrivateDir, uuidv7, type ActiveFixture } from './testing/fixtures.js';

// Internal transport integration only. No generated wire protocol, installed
// Supervisor, sandbox execution or peer JSON attestation is being simulated.
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  void promise.catch(() => {});
  return { promise, resolve, reject };
}
async function bounded<T>(promise: Promise<T>): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try { return await Promise.race([promise, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('local control integration timed out')), 30_000);
  })]); } finally { clearTimeout(timer); }
}

async function fixture(t: TestContext, seeded?: Pick<ActiveFixture, 'stateRoot' | 'workspace' | 'store'>) {
  const stateRoot = seeded?.stateRoot ?? await makePrivateDir('.cliq-local-control-');
  const workspace = seeded?.workspace ?? await makePrivateDir('.cliq-local-control-ws-');
  let store = seeded?.store ?? await openStateStore(stateRoot);
  let listener: LocalControlListener;
  const queue: LocalControlConnection[] = [];
  let next = deferred<LocalControlConnection>();
  const errors: Error[] = [];
  const listen = () => {
    listener = store.openLocalControl(connection => {
      queue.push(connection); next.resolve(connection);
    }, error => { errors.push(error); next.reject(error); });
  };
  const reader = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  t.after(async () => {
    await listener?.close(); await store.close(); reader.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  });
  listen();
  const connect = async () => {
    const script = `import net from 'node:net';
      const socket = net.createConnection(process.argv[1], () => process.send({kind:'ready',pid:process.pid}));
      socket.on('error', () => {}); process.on('disconnect', () => { socket.destroy(); process.exit(0); });`;
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, path.join(stateRoot, 'runtime/control-v1.sock')],
      { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    const exited = once(child, 'exit');
    t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await bounded(exited); });
    await bounded(once(child, 'message'));
    const connection = queue.shift() ?? await bounded(next.promise);
    if (queue[0] === connection) queue.shift();
    next = deferred<LocalControlConnection>();
    return { connection, child, exited };
  };
  return { stateRoot, workspace, reader, errors, connect, get store() { return store; },
    async reopen() { await listener.close(); await store.close(); store = await openStateStore(stateRoot); listen(); } };
}

test('native connection derives principal before real Session admission and preserves its peer audit closure', async t => {
  const f = await fixture(t);
  const { connection, child } = await f.connect();
  let identity!: AuthenticatedControlIdentity;
  const admitted = await connection.dispatch(authenticated => {
    identity = authenticated;
    return f.store.createSession({ ...authenticated, workspacePath: f.workspace, requestId: uuidv7(), admissionKey: admissionKey('native-session') });
  });
  const inProcess = await publishInProcessChannel(f.store);
  assert.equal(identity.principalId, inProcess.principalId);
  assert.equal(admitted.replayed, false);
  const closure = await readHistoricalControlChannel(f.reader, f.store.artifacts, identity);
  assert.equal(closure.channel.client, 'rpc');
  assert.equal(closure.channel.transport.kind, 'uds_peer');
  if (closure.channel.transport.kind !== 'uds_peer') throw new Error('expected native transport');
  const peer = await f.store.artifacts.readCanonical<LocalSocketPeerObservationV1>(closure.channel.transport.peerObservationRef);
  const processIdentity = await f.store.artifacts.readCanonical<PlatformProcessIdentityV1>(peer.peerProcessIdentityRef);
  assert.equal(peer.peerPid, child.pid);
  assert.equal(processIdentity.pid, child.pid);
  assert.notEqual(processIdentity.pid, process.pid);
  assert.equal(peer.peerUid, process.geteuid!());
  const row = f.reader.prepare('SELECT channel_identity_ref, channel_identity_digest FROM control_requests WHERE method = ?').get('session.create');
  assert.equal(row!.channel_identity_ref, identity.channelIdentityRef);
  assert.equal(row!.channel_identity_digest, identity.channelIdentityDigest);
  // Merely retaining a real observation is no permission to use it outside
  // the owner-minted authenticated request scope, even while the peer lives.
  await assert.rejects(f.store.createSession({ ...identity, workspacePath: f.workspace, requestId: uuidv7(), admissionKey: admissionKey('outside-native-frame') }),
    { code: 'ARTIFACT_MISMATCH' });
  assert.deepEqual(f.errors, []);
});

test('new native connections and owner restart replay one committed admission without rewriting original channel provenance', async t => {
  const f = await fixture(t);
  const request = { workspacePath: f.workspace, requestId: uuidv7(), admissionKey: admissionKey('native-reconnect') };
  const first = await f.connect();
  let original!: AuthenticatedControlIdentity;
  const admitted = await first.connection.dispatch(identity => { original = identity; return f.store.createSession({ ...request, ...identity }); });
  first.connection.close();
  await f.reopen();
  const second = await f.connect();
  let reconnected!: AuthenticatedControlIdentity;
  const replay = await second.connection.dispatch(identity => { reconnected = identity; return f.store.createSession({ ...request, ...identity }); });
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.response, admitted.response);
  assert.equal(reconnected.principalId, original.principalId);
  assert.notEqual(reconnected.channelIdentityRef, original.channelIdentityRef);
  const rows = f.reader.prepare('SELECT channel_identity_ref FROM control_requests WHERE method = ?').all('session.create');
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.channel_identity_ref, original.channelIdentityRef);
  await readHistoricalControlChannel(f.reader, f.store.artifacts, original);
  assert.equal(f.reader.prepare('SELECT count(*) AS n FROM sessions').get<{ n: bigint }>()!.n, 1n);
  await assert.rejects(second.connection.dispatch(identity => f.store.createSession({ ...request, ...identity, name: 'changed intent' })),
    { code: 'REQUEST_ID_CONFLICT' });
});

test('peer death blocks replay before StateStore can return a committed response', async t => {
  const f = await fixture(t);
  const request = { workspacePath: f.workspace, requestId: uuidv7(), admissionKey: admissionKey('native-death') };
  const { connection, child, exited } = await f.connect();
  await connection.dispatch(identity => f.store.createSession({ ...request, ...identity }));
  child.kill('SIGKILL'); await bounded(exited);
  let reachedStore = false;
  await assert.rejects(connection.dispatch(identity => { reachedStore = true; return f.store.createSession({ ...request, ...identity }); }));
  assert.equal(reachedStore, false);
  assert.equal(f.reader.prepare('SELECT count(*) AS n FROM sessions').get<{ n: bigint }>()!.n, 1n);
});

test('closing StateStore drains in-flight authenticated scopes before releasing durable ownership', async t => {
  const f = await fixture(t);
  const { connection } = await f.connect();
  const entered = deferred<void>();
  const release = deferred<void>();
  const dispatch = connection.dispatch(async () => { entered.resolve(); await release.promise; return 'finished'; });
  await bounded(entered.promise);
  let closed = false;
  const closing = f.store.close().then(() => { closed = true; });
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(closed, false);
  await assert.rejects(connection.dispatch(async () => 'cannot dispatch again'));
  release.resolve();
  assert.equal(await bounded(dispatch), 'finished');
  await bounded(closing);
  assert.equal(closed, true);
});

test('copied identities and delayed work cannot borrow another authenticated frame on the same live connection', async t => {
  const f = await fixture(t);
  const { connection } = await f.connect();
  const entered = deferred<AuthenticatedControlIdentity>();
  const proceed = deferred<void>();
  const delayedTrigger = deferred<void>();
  let delayed!: Promise<unknown>;
  const request = { workspacePath: f.workspace, requestId: uuidv7(), admissionKey: admissionKey('scoped-native-request') };
  const legitimate = connection.dispatch(async identity => {
    delayed = delayedTrigger.promise.then(() => f.store.createSession({ ...request, ...identity,
      requestId: uuidv7(), admissionKey: admissionKey('delayed-closed-frame') }));
    void delayed.catch(() => {});
    entered.resolve(identity);
    await proceed.promise;
    return f.store.createSession({ ...request, ...identity });
  });
  const copied = await bounded(entered.promise);
  await assert.rejects(f.store.createSession({ ...request, ...copied, requestId: uuidv7(), admissionKey: admissionKey('copied-active-channel') }),
    { code: 'ARTIFACT_MISMATCH' });
  proceed.resolve(); await bounded(legitimate);
  const secondEntered = deferred<void>();
  const secondRelease = deferred<void>();
  const second = connection.dispatch(async () => { secondEntered.resolve(); await secondRelease.promise; });
  await bounded(secondEntered.promise);
  delayedTrigger.resolve();
  await assert.rejects(delayed, { code: 'ARTIFACT_MISMATCH' });
  secondRelease.resolve(); await bounded(second);
  assert.equal(f.reader.prepare('SELECT count(*) AS n FROM sessions').get<{ n: bigint }>()!.n, 1n);
});

test('bounded Run reads survive real native reconnect and owner restart without treating events as Run truth', async t => {
  // The worker/generation are explicit offline persistence fixtures, not a
  // claim that strong execution or the installed public protocol is qualified.
  const seeded = await createActiveFixture('nr');
  const f = await fixture(t, seeded);
  const first = await f.connect();
  let copied!: AuthenticatedControlIdentity;
  const firstPage = await first.connection.dispatch(async identity => {
    copied = identity;
    const session = await f.store.readControl({ protocolVersion: 1, method: 'session.get',
      sessionId: f.store.getRun(seeded.runId).sessionId }, identity);
    if (session.method !== 'session.get') throw new Error('expected Session page');
    assert.equal(session.highWaterItemSeq, 0);
    return f.store.readControl({ protocolVersion: 1, method: 'run.attach', runId: seeded.runId, afterEventSeq: 0, limit: 1 }, identity);
  });
  if (firstPage.method !== 'run.attach') throw new Error('expected attach page');
  assert.equal(firstPage.events.length, 1);
  assert.ok(firstPage.nextEventSeq < firstPage.highWaterEventSeq);
  await assert.rejects(f.store.readControl({ protocolVersion: 1, method: 'run.get', runId: seeded.runId }, copied),
    { code: 'ARTIFACT_MISMATCH' });

  // Pause only the real immutable CAS read after the SQL cut. A real reducer
  // can commit meanwhile without changing that cut's Run or stream high-waters.
  const catalog = f.store.artifacts;
  const readCanonical = catalog.readCanonical.bind(catalog);
  const captured = deferred<void>();
  const release = deferred<void>();
  const originalRun = f.store.getRun(seeded.runId);
  let pause = true;
  catalog.readCanonical = async <T>(ref: string): Promise<T> => {
    const value = await readCanonical<T>(ref);
    if (pause && ref === originalRun.specRef) {
      pause = false; captured.resolve(); await release.promise;
    }
    return value;
  };
  const reading = first.connection.dispatch(identity => f.store.readControl({ protocolVersion: 1, method: 'run.get',
    runId: seeded.runId }, identity));
  void reading.catch(() => {});
  try {
    await bounded(captured.promise);
    const request = await catalog.publishCanonical({ fixture: 'read-cut-race' }, 'cliq-tool-request-v1');
    await f.store.prepareInvocation({ runId: seeded.runId, expectedRunRevision: originalRun.revision,
      leaseEpoch: seeded.leaseEpoch, opId: 'read-cut-race', opKind: 'tool', target: 'fixture.read', requestRef: request.ref,
      replayClass: 'retry', idempotencyKey: 'read-cut-race-0',
      reservation: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 } });
  } finally { release.resolve(); catalog.readCanonical = readCanonical; }
  const fixedCut = await bounded(reading);
  if (fixedCut.method !== 'run.get') throw new Error('expected Run read cut');
  assert.deepEqual(fixedCut.snapshot.run, originalRun);
  assert.equal(fixedCut.highWaterJournalSeq, 0);
  assert.deepEqual(fixedCut.journal, []);

  first.connection.close();
  const before = f.store.getRun(seeded.runId);
  await f.reopen();
  const second = await f.connect();
  const nextPage = await second.connection.dispatch(identity => f.store.readControl({ protocolVersion: 1, method: 'run.attach',
    runId: seeded.runId, afterEventSeq: firstPage.nextEventSeq }, identity));
  if (nextPage.method !== 'run.attach') throw new Error('expected attach page');
  assert.equal(nextPage.nextEventSeq, nextPage.highWaterEventSeq);
  assert.deepEqual([...firstPage.events, ...nextPage.events].map(event => event.eventSeq),
    Array.from({ length: nextPage.highWaterEventSeq }, (_, index) => index + 1));
  const detail = await second.connection.dispatch(identity => f.store.readControl({ protocolVersion: 1, method: 'run.get',
    runId: seeded.runId }, identity));
  if (detail.method !== 'run.get') throw new Error('expected Run detail');
  assert.deepEqual(detail.snapshot.run, before, 'reconnect never rewrites, cancels, or recovers Run authority from display events');
  assert.equal(detail.snapshot.latestRunItemSeq, detail.highWaterItemSeq);
  assert.equal(detail.highWaterJournalSeq, 1, 'only a later cut sees the concurrently committed Journal entry');
  assert.ok(detail.checkpoints.some(checkpoint => checkpoint.id === before.latestCheckpointId));
  assert.equal(f.reader.prepare('SELECT count(*) AS n FROM control_requests').get<{ n: bigint }>()!.n, 2n,
    'read requests create no mutation replay rows');
  second.child.kill('SIGKILL'); await bounded(second.exited);
  let reachedRead = false;
  await assert.rejects(second.connection.dispatch(identity => {
    reachedRead = true;
    return f.store.readControl({ protocolVersion: 1, method: 'run.attach', runId: seeded.runId, afterEventSeq: nextPage.nextEventSeq }, identity);
  }));
  assert.equal(reachedRead, false);
});
