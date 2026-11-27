import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs';
import { readFile, rm } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import type { LocalSocketPeerObservationV1, PlatformProcessIdentityV1 } from '../kernel/types.js';
import type { AuthenticatedControlIdentity, LocalControlConnection, LocalControlListener } from './control-channel.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { ResourceRetirementError } from './errors.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel } from './store.js';
import { admissionKey, createActiveFixture, makePrivateDir, uuidv7, type ActiveFixture } from './testing/fixtures.js';
import { createAgentFixture } from './testing/agent-fixtures.js';

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

async function fixture(t: TestContext, seeded?: Pick<ActiveFixture, 'stateRoot' | 'workspace' | 'store' | 'runtimeAuthority'>,
  beforeAuthentication?: (connection: LocalControlConnection) => void) {
  const stateRoot = seeded?.stateRoot ?? await makePrivateDir('.cliq-local-control-');
  const workspace = seeded?.workspace ?? await makePrivateDir('.cliq-local-control-ws-');
  let store = seeded?.store ?? await openStateStore(stateRoot);
  let listener: LocalControlListener;
  const queue: LocalControlConnection[] = [];
  let next = deferred<LocalControlConnection>();
  let retainedRetirement: ResourceRetirementError | undefined;
  const errors: Error[] = [];
  const listen = () => {
    listener = store.openLocalControl(connection => {
      beforeAuthentication?.(connection);
      queue.push(connection); next.resolve(connection);
    }, error => { errors.push(error); next.reject(error); });
  };
  const reader = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  t.after(async () => {
    if (retainedRetirement) {
      // This branch runs only in the isolated retirement child. A refused
      // close retains the real StateOwner until that process actually exits.
      assert.equal(process.env.CLIQ_LOCAL_CONTROL_RETIREMENT_CHILD, '1');
      for (let retry = 0; retry < 2; retry++) {
        await assert.rejects(listener.close(), error => error === retainedRetirement);
        await assert.rejects(store.close(), error => error === retainedRetirement);
      }
      assert.equal(reader.prepare("SELECT state FROM state_owners WHERE state='active'").get()?.state, 'active');
      reader.close();
      t.diagnostic(JSON.stringify({ retainedAuthenticationFixture: { stateRoot, workspace } }));
      return;
    }
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
    retainRetirement(error: ResourceRetirementError) { retainedRetirement = error; },
    async reopen() { await listener.close(); await store.close(); store = await openStateStore(stateRoot, seeded?.runtimeAuthority); listen(); } };
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

test('native authentication yields before and between bounded executable-image batches without changing the digest', async t => {
  const batchBytes = 1024 * 1024;
  const executable = fs.statSync(process.execPath, { bigint: true });
  const expectedDigest = createHash('sha256').update(await readFile(process.execPath)).digest('hex');
  let initialProbeRan = false;
  let initialProbe: ReturnType<typeof setImmediate> | undefined;
  const f = await fixture(t, undefined, () => {
    // Accept owns preparation now. Arm the probe in its real consumer callback,
    // before that producer starts, rather than after connect has already yielded.
    initialProbe = setImmediate(() => { initialProbeRan = true; });
  });
  const originalRead = fs.readSync;
  let probe: ReturnType<typeof setImmediate> | undefined;
  let probeCount = 0;
  let uninterruptedBytes = 0;
  let imageBytes = 0;
  // Observe only the OS boundary. The descriptor, peer observation, transport,
  // authentication closure and eventual dispatch remain real production paths.
  const reading = t.mock.method(fs, 'readSync', (...args: unknown[]) => {
    const image = fs.fstatSync(args[0] as number, { bigint: true });
    const matches = image.dev === executable.dev && image.ino === executable.ino;
    if (matches) {
      assert.equal(initialProbeRan, true, 'authentication yields before the first executable-image read');
      if (!probe) probe = setImmediate(() => {
        uninterruptedBytes = 0;
        probeCount++;
        probe = undefined;
      });
    }
    const count: number = Reflect.apply(originalRead, fs, args);
    if (matches) {
      imageBytes += count;
      uninterruptedBytes += count;
      assert.ok(uninterruptedBytes <= batchBytes,
        'one uninterrupted executable-image batch must not exceed 1 MiB');
    }
    return count;
  });
  syncBuiltinESMExports();
  try {
    const { connection } = await f.connect();
    const identity = await bounded(connection.dispatch(async authenticated => authenticated));
    assert.equal(initialProbeRan, true);
    if (executable.size > BigInt(batchBytes)) assert.ok(probeCount > 0);
    assert.equal(BigInt(imageBytes), executable.size, 'the digest covers every actual executable byte');
    const closure = await readHistoricalControlChannel(f.reader, f.store.artifacts, identity);
    if (closure.channel.transport.kind !== 'uds_peer') throw new Error('expected native transport');
    const peer = await f.store.artifacts.readCanonical<LocalSocketPeerObservationV1>(closure.channel.transport.peerObservationRef);
    const processIdentity = await f.store.artifacts.readCanonical<PlatformProcessIdentityV1>(peer.peerProcessIdentityRef);
    assert.equal(processIdentity.executableImageDigest, expectedDigest,
      'yielding preserves the independently computed SHA-256 of the actual peer executable');
    assert.deepEqual(f.errors, []);
  } finally {
    reading.mock.restore();
    syncBuiltinESMExports();
    if (initialProbe) clearImmediate(initialProbe);
    if (probe) clearImmediate(probe);
  }
});

test('closing a native connection while authentication yields stops image reads and never dispatches the operation', async t => {
  const batchBytes = 1024 * 1024;
  const executable = fs.statSync(process.execPath, { bigint: true });
  let connection!: LocalControlConnection;
  const closed = deferred<void>();
  let probe: ReturnType<typeof setImmediate> | undefined;
  let closedAtProbe = false;
  let imageBytes = 0;
  let readsAfterClose = 0;
  let reachedOperation = false;
  const closeAtProbe = () => {
    closedAtProbe = true;
    connection.close();
    closed.resolve();
  };
  // Large real executables exercise close between batches. A small host Node
  // still proves cancellation at the initial yield, without inventing an image
  // size or claiming cross-batch coverage where the executable fits one batch.
  const f = await fixture(t, undefined, accepted => {
    connection = accepted;
    if (executable.size <= BigInt(batchBytes)) probe = setImmediate(closeAtProbe);
  });
  const originalRead = fs.readSync;
  const reading = t.mock.method(fs, 'readSync', (...args: unknown[]) => {
    if (closedAtProbe) readsAfterClose++;
    const image = fs.fstatSync(args[0] as number, { bigint: true });
    const matches = image.dev === executable.dev && image.ino === executable.ino;
    if (matches) {
      if (!probe) probe = setImmediate(closeAtProbe);
    }
    const count: number = Reflect.apply(originalRead, fs, args);
    if (matches) imageBytes += count;
    return count;
  });
  syncBuiltinESMExports();
  try {
    await f.connect();
    await assert.rejects(bounded(connection.dispatch(async () => { reachedOperation = true; })));
    await bounded(closed.promise);
    assert.equal(readsAfterClose, 0, 'the closed native observation is never read again');
    assert.equal(reachedOperation, false, 'closed authentication cannot create an authenticated request frame');
    if (executable.size <= BigInt(batchBytes)) {
      assert.equal(imageBytes, 0, 'initial-yield close prevents even the first native image read');
    } else {
      assert.ok(imageBytes > 0 && imageBytes <= batchBytes,
        'between-batch close stops after at most the first real 1 MiB image batch');
    }
    assert.deepEqual(f.errors, []);
  } finally {
    reading.mock.restore();
    syncBuiltinESMExports();
    if (probe) clearImmediate(probe);
  }
});

const authenticationPublications = ['cliq-platform-process-identity-v1', 'cliq-local-principal-identity-v1',
  'cliq-local-socket-peer-observation-v1', 'cliq-local-control-channel-identity-v1'] as const;
test('native authentication publishes exactly one fixed four-object durability group', async t => {
  const f = await fixture(t);
  const catalog = f.store.artifacts, publish = catalog.publishCanonicalFour.bind(catalog);
  let groups = 0;
  catalog.publishCanonicalFour = async values => { groups++; return publish(values); };
  const { connection, child, exited } = await f.connect();
  try {
    await bounded(connection.dispatch(async identity => identity));
    assert.equal(groups, 1, 'authentication must use one shared phase group, not four independent lifecycles');
  } finally {
    catalog.publishCanonicalFour = publish;
    if (child.connected) child.disconnect(); await bounded(exited);
  }
});
test('native authentication enables authority only after its complete real CAS group return joins', async t => {
  const f = await fixture(t);
  const firstCompleted = deferred<void>(), release = deferred<void>();
  const catalog = f.store.artifacts, publish = catalog.publishCanonicalFour.bind(catalog);
  const values = new Map<string, unknown>(), results = new Map<string, PublishedArtifact>();
  let operationEntered = false, dispatchJoined = false;
  catalog.publishCanonicalFour = async entries => {
    for (const entry of entries) values.set(entry.schemaKind, entry.value);
    const result = await publish(entries); // All original fsync/hash/close work is real.
    result.forEach(artifact => results.set(artifact.schemaKind, artifact)); firstCompleted.resolve();
    await release.promise; // Only the already-joined real return value is delayed.
    return result;
  };
  const { connection, child, exited } = await f.connect();
  const dispatch = connection.dispatch(async identity => { operationEntered = true; return identity; });
  void dispatch.then(() => { dispatchJoined = true; }, () => { dispatchJoined = true; });
  try {
    await bounded(firstCompleted.promise);
    assert.deepEqual([...values.keys()], authenticationPublications,
      'the group contains exactly the four original complete canonical objects');
    assert.equal(operationEntered, false); assert.equal(dispatchJoined, false);
    for (const value of values.values()) {
      assert.equal(Object.isFrozen(value), true, 'precomputed identity bytes cannot change while siblings publish');
      const record = value as Record<string, unknown>;
      for (const nested of Object.values(record)) if (nested && typeof nested === 'object') assert.equal(Object.isFrozen(nested), true);
    }
    release.resolve();
    const identity = await bounded(dispatch);
    assert.equal(results.size, 4);
    for (const [kind, result] of results) {
      const bytes = canonicalJsonBytes(values.get(kind));
      assert.deepEqual(result, { ref: sha256Bytes(bytes), byteLength: bytes.length, mediaType: 'application/json', schemaKind: kind });
      assert.deepEqual(await catalog.readBytes(result.ref), bytes, 'every retained artifact contains the complete original canonical bytes');
    }
    assert.equal(identity.channelIdentityRef, results.get(authenticationPublications[3])!.ref);
    await readHistoricalControlChannel(f.reader, catalog, identity);
    assert.equal(operationEntered, true); assert.equal(dispatchJoined, true);
    assert.deepEqual(f.errors, []);
  } finally {
    release.resolve(); await bounded(Promise.allSettled([dispatch])); catalog.publishCanonicalFour = publish;
    if (child.connected) child.disconnect(); await bounded(exited);
  }
});

for (const closeKind of ['connection', 'store'] as const) for (const stage of [1, 2, 3, 4]) {
  test(`closing ${closeKind} at authentication namespace stage ${stage} joins the whole real group without authority`, async t => {
    const f = await fixture(t);
    const entered = deferred<void>(), release = deferred<void>();
    const open = fs.promises.open.bind(fs.promises), casRoot = path.join(f.stateRoot, KERNEL_CAS_DIRECTORY);
    let rootSyncs = 0, active = 0, operationEntered = false, closeJoined = false, dispatchJoined = false;
    // The actual directory sync completes first; only its JS await return is
    // gated. This tests ownership/join, not physical in-flight fsync or 2s stop.
    t.mock.method(fs.promises, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args);
      if (args[0] !== casRoot && !String(args[0]).startsWith(`${casRoot}/`)) return handle;
      active++;
      const close = handle.close.bind(handle), sync = handle.sync.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); active--; });
      if (args[0] === casRoot) t.mock.method(handle, 'sync', async () => {
        await sync(); if (++rootSyncs === stage) { entered.resolve(); await release.promise; }
      });
      return handle;
    });
    const { connection, child, exited } = await f.connect();
    const dispatch = connection.dispatch(async () => { operationEntered = true; });
    void dispatch.then(() => { dispatchJoined = true; }, () => { dispatchJoined = true; });
    let closing: Promise<void> | undefined;
    try {
      await bounded(entered.promise);
      assert.equal(rootSyncs, stage);
      if (closeKind === 'connection') connection.close();
      else {
        closing = f.store.close().then(() => { closeJoined = true; });
        void closing.catch(() => {});
      }
      await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(dispatchJoined, false, 'the original pending authentication must join its return-value gate');
      if (closing) assert.equal(closeJoined, false, 'the pending authentication must join before StateOwner release');
      await assert.rejects(connection.dispatch(async () => { operationEntered = true; }));
      assert.equal(operationEntered, false);
      release.resolve();
      await assert.rejects(bounded(dispatch), { code: 'ARTIFACT_MISMATCH' });
      assert.equal(dispatchJoined, true);
      assert.equal(operationEntered, false, 'closed authentication never mints an authenticated operation scope');
      assert.equal(rootSyncs, 4, 'all four actual namespace stages finish despite cancellation');
      assert.equal(active, 0, 'every actual original file and root descriptor joins');
      assert.deepEqual(f.errors, []);
      // Connection-only cancellation is checked while its original listener
      // and Store remain open. Only afterward release durable ownership.
      if (!closing) closing = f.store.close().then(() => { closeJoined = true; });
      await bounded(closing);
      assert.equal(closeJoined, true);
    } finally {
      release.resolve();
      await bounded(Promise.allSettled([dispatch, ...(closing ? [closing] : [])]));
      t.mock.restoreAll();
      if (child.connected) child.disconnect();
      await bounded(exited);
    }
  });
}

for (const field of ['ref', 'byteLength', 'mediaType', 'schemaKind', 'failure'] as const) {
  test(`authentication joins every real CAS return and rejects an inconsistent ${field} without activating authority`, async t => {
    const f = await fixture(t);
    const catalog = f.store.artifacts, publish = catalog.publishCanonicalFour.bind(catalog);
    const alternate = await catalog.publishBytes(Buffer.from('real alternative bytes'), 'text/plain', 'real-alternative');
    const firstCompleted = deferred<void>(), release = deferred<void>();
    const failure = new Error('logical return-value delivery failed after real CAS close');
    let operationEntered = false, dispatchJoined = false, completed = 0;
    catalog.publishCanonicalFour = async values => {
      const result = await publish(values);
      completed = result.length; firstCompleted.resolve();
      await release.promise;
      if (field === 'failure') throw failure;
      return [{ ...result[0], [field]: alternate[field] }, result[1], result[2], result[3]];
    };
    const { connection, child, exited } = await f.connect();
    const dispatch = connection.dispatch(async () => { operationEntered = true; });
    void dispatch.then(() => { dispatchJoined = true; }, () => { dispatchJoined = true; });
    try {
      await bounded(firstCompleted.promise);
      await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(dispatchJoined, false, 'an ordinary failure or inconsistent return cannot abandon a pending sibling');
      assert.equal(operationEntered, false);
      release.resolve();
      let refused: unknown;
      await assert.rejects(bounded(dispatch), error => {
        refused = error;
        return field === 'failure' ? error === failure : (error as { code?: string }).code === 'ARTIFACT_MISMATCH';
      });
      assert.equal(completed, 4, 'all four original full publications have really returned');
      assert.equal(dispatchJoined, true); assert.equal(operationEntered, false);
      await assert.rejects(connection.dispatch(async () => { operationEntered = true; }));
      assert.equal(operationEntered, false);
      assert.equal(f.reader.prepare('SELECT count(*) AS n FROM control_requests').get<{ n: bigint }>()!.n, 0n);
      assert.equal(f.errors.length, 1, 'accepted preparation reports its genuine publication failure once');
      assert.equal(f.errors[0], refused, 'the reporter retains the same original failure as dispatch');
    } finally {
      release.resolve(); await bounded(Promise.allSettled([dispatch])); catalog.publishCanonicalFour = publish;
      if (child.connected) child.disconnect(); await bounded(exited);
    }
  });
}

for (const fault of ['none', 'root_close', 'bytes'] as const) {
  test(`real authentication CAS descriptors fully join with bounded delivered ownership under ${fault}`, async t => {
    if (fault === 'root_close' && process.env.CLIQ_LOCAL_CONTROL_RETIREMENT_CHILD !== '1') {
      // Retirement uncertainty deliberately keeps the original Store alive.
      // Join its actual process and all stdio before touching the retained root.
      const environment: NodeJS.ProcessEnv = { ...process.env, CLIQ_LOCAL_CONTROL_RETIREMENT_CHILD: '1' };
      delete environment.NODE_TEST_CONTEXT;
      const child = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-concurrency=1', '--import', 'tsx', '--test-name-pattern',
        '^real authentication CAS descriptors fully join with bounded delivered ownership under root_close$', fileURLToPath(import.meta.url)],
      { env: environment, encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
      assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stdout + child.stderr);
      for (const line of child.stdout.split('\n')) if (line.startsWith('# {"diagnosticOnly":')) t.diagnostic(line.slice(2));
      const marker = child.stdout.split('\n').find(line => line.startsWith('# {"retainedAuthenticationFixture":'));
      assert.ok(marker, 'the child verifies the same retirement refusal through listener and Store close retries');
      const { retainedAuthenticationFixture: retained } = JSON.parse(marker.slice(2)) as {
        retainedAuthenticationFixture: { stateRoot: string; workspace: string } };
      const successor = await openStateStore(retained.stateRoot);
      try { assert.equal(successor.ownerEpoch, 2); }
      finally { await successor.close(); }
      await rm(retained.stateRoot, { recursive: true, force: true });
      await rm(retained.workspace, { recursive: true, force: true });
      return; // Component cleanup after real process exit, never a production recovery proof.
    }
    const f = await fixture(t);
    const catalog = f.store.artifacts, publish = catalog.publishCanonicalFour.bind(catalog);
    const open = fs.promises.open.bind(fs.promises), casRoot = path.join(f.stateRoot, KERNEL_CAS_DIRECTORY);
    const active = new Set<Awaited<ReturnType<typeof open>>>();
    const closeFailure = new Error('actual CAS root close returned an error after closing its real descriptor');
    const operationFailure = new Error('ordinary return-value failure after real CAS close');
    const gate = deferred<void>(), entered = deferred<void>();
    let peak = 0, opened = 0, closed = 0, fileSyncs = 0, rootSyncs = 0, changedBytes = false, rootCloseFailed = false;
    let operationEntered = false, dispatchJoined = false, settled = 0, writeFailed = false;
    t.mock.method(fs.promises, 'open', async (...args: Parameters<typeof open>) => {
      const handle = await open(...args);
      if (args[0] !== casRoot && !String(args[0]).startsWith(`${casRoot}/`)) return handle;
      active.add(handle); opened++; peak = Math.max(peak, active.size);
      const close = handle.close.bind(handle), sync = handle.sync.bind(handle), writeFile = handle.writeFile.bind(handle);
      t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === casRoot) rootSyncs++; else fileSyncs++; });
      t.mock.method(handle, 'close', async () => {
        await close(); // Never report a fabricated close or recycle an unclosed descriptor.
        assert.equal(active.delete(handle), true); closed++;
        if (fault === 'root_close' && args[0] === casRoot && !rootCloseFailed) {
          rootCloseFailed = true; throw closeFailure;
        }
      });
      if (String(args[0]).includes('/.tmp-stream-')) {
        t.mock.method(handle, 'writeFile', async (...writeArgs: Parameters<typeof writeFile>) => {
          await writeFile(...writeArgs);
          if (fault === 'bytes' && !changedBytes) { changedBytes = true; await handle.write(Buffer.from('!'), 0, 1, 0); }
          if (fault === 'root_close' && !writeFailed) { writeFailed = true; throw operationFailure; }
        });
      }
      return handle;
    });
    catalog.publishCanonicalFour = async values => {
      try { return await publish(values); }
      finally { entered.resolve(); await gate.promise; settled++; }
    };
    const { connection, child, exited } = await f.connect();
    const dispatch = connection.dispatch(async () => { operationEntered = true; });
    void dispatch.then(() => { dispatchJoined = true; }, () => { dispatchJoined = true; });
    try {
      await bounded(entered.promise);
      assert.equal(active.size, 0, 'every actual CAS handle closes before the return-value gate');
      assert.equal(dispatchJoined, false); assert.equal(operationEntered, false);
      gate.resolve();
      let refused: unknown;
      if (fault === 'none') await bounded(dispatch);
      else if (fault === 'root_close') await assert.rejects(bounded(dispatch), error => {
        assert.ok(error instanceof ResourceRetirementError); assert.equal(error.cause, closeFailure); assert.notEqual(error, operationFailure);
        refused = error; f.retainRetirement(error); return true;
      });
      else await assert.rejects(bounded(dispatch), error => {
        refused = error; return error instanceof Error && /^artifact [0-9a-f]{64} is corrupt$/u.test(error.message);
      });
      assert.equal(settled, 1); assert.equal(active.size, 0); assert.equal(opened, closed);
      assert.equal(operationEntered, fault === 'none');
      assert.ok(peak > 2 && peak <= 5, 'one shared root plus four files bounds delivered CAS ownership, not all Supervisor OS descriptors');
      assert.equal(rootSyncs, fault === 'root_close' ? 2 : 4, 'failed prefix and cleanup, or all four original namespace barriers, actually synchronize');
      assert.equal(fileSyncs, fault === 'root_close' ? 3 : 4, 'every successfully written original file actually synchronizes');
      assert.equal(changedBytes, fault === 'bytes'); assert.equal(rootCloseFailed, fault === 'root_close');
      t.diagnostic(JSON.stringify({ diagnosticOnly: true, scope: 'delivered_authentication_cas_handles', fault,
        peak, opened, closed, rootSyncs, fileSyncs, allJoined: active.size === 0,
        physicalStopQualified: false, fullSupervisorDescriptorPeakQualified: false }));
      assert.equal(f.errors.length, fault === 'none' ? 0 : 1);
      if (fault !== 'none') assert.equal(f.errors[0], refused, 'genuine storage and integrity failures reach the reporter unchanged');
    } finally {
      gate.resolve(); await bounded(Promise.allSettled([dispatch])); catalog.publishCanonicalFour = publish;
      t.mock.restoreAll();
      if (child.connected) child.disconnect(); await bounded(exited);
    }
  });
}

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
  const seeded = await createAgentFixture('nr');
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

  // Pause the final real authenticated-channel CAS read after the SQL cut,
  // not the immutable RunSpec preflight that now precedes it. A real reducer
  // can commit meanwhile without changing that cut's Run or stream high-waters.
  const readCanonical = ArtifactCatalog.prototype.readCanonical;
  const captured = deferred<void>();
  const release = deferred<void>();
  const originalRun = f.store.getRun(seeded.runId);
  let pause = true, selectedSpec = false;
  const pausedRead = t.mock.method(ArtifactCatalog.prototype, 'readCanonical', async function<T>(this: ArtifactCatalog, ref: string): Promise<T> {
    const value = await readCanonical.call(this, ref) as T;
    if (ref === originalRun.specRef) selectedSpec = true;
    if (pause && selectedSpec && ref === copied.channelIdentityRef) {
      pause = false; captured.resolve(); await release.promise;
    }
    return value;
  });
  const reading = first.connection.dispatch(identity => f.store.readControl({ protocolVersion: 1, method: 'run.get',
    runId: seeded.runId }, identity));
  void reading.catch(() => {});
  try {
    await bounded(captured.promise);
    await seeded.agent.prepareModel({ expectedRunRevision: originalRun.revision, leaseEpoch: seeded.leaseEpoch });
  } finally { release.resolve(); pausedRead.mock.restore(); }
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
