import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { setImmediate as nextTurn } from 'node:timers/promises';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeControlFrame, decodeInstalledControlResponse } from '../kernel/control-wire.js';
import { addCanonicalDuration, digestOmitting } from '../kernel/identity.js';
import type { Checkpoint, InvocationJournalEntry, LocalControlChannelIdentityV1, RunItemReferenceV1, SessionContextProjection, SessionItem } from '../kernel/types.js';
import { insertArtifactMetadata } from './artifacts.js';
import { EventCursorExpiredError, ResultUnavailableError } from './control-read.js';
import { KernelStorageError } from './errors.js';
import { openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { admissionKey, createActiveFixture, disposeFixture, makePrivateDir, uuidv7 } from './testing/fixtures.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { openInstalledControl } from './installed-control.js';

const isCode = (code: KernelStorageError['code']) => (error: unknown) => error instanceof KernelStorageError && error.code === code;

async function readPagePeer(t: TestContext, socketPath: string) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import net from 'node:net';
    const socket=net.createConnection(process.argv[1],()=>process.send({kind:'ready'}));
    let input=Buffer.alloc(0);
    socket.on('data',chunk=>{input=Buffer.concat([input,chunk]);while(input.length>=4){
      const length=input.readUInt32BE(0);if(length<1||length>1048576)throw new Error('invalid frame');
      if(input.length<length+4)break;process.send({kind:'frame',body:input.subarray(4,length+4).toString('base64')});
      input=input.subarray(length+4);}});
    socket.on('error',()=>{});process.on('message',body=>socket.write(Buffer.from(body,'base64')));
    process.on('disconnect',()=>{socket.destroy();process.exit(0);});`, socketPath], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  const exited = once(child, 'exit');
  t.after(async () => { if (child.connected) child.disconnect(); await exited; });
  await once(child, 'message');
  return async (request: object) => {
    const received = once(child, 'message');
    const body = canonicalJsonBytes(request), header = Buffer.alloc(4); header.writeUInt32BE(body.length);
    child.send(Buffer.concat([header, body]).toString('base64'));
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const [frame] = await Promise.race([received, new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('real read page timed out')), 30_000);
      })]);
      return decodeControlFrame(Buffer.from((frame as { body: string }).body, 'base64'));
    } finally { clearTimeout(timer); }
  };
}

test('real UDS run pages fit the unchanged strict frame parser and retain every Journal row across pages', async t => {
  const fixture = await createActiveFixture('pg');
  t.after(() => disposeFixture(fixture));
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  t.after(() => driver.close());
  const run = fixture.store.getRun(fixture.runId);
  const initial = (await fixture.store.readRecoveryClosure(run.id)).latestCheckpoint;
  const checkpoints = [initial, ...Array.from({ length: 999 }, (_, index) => ({ ...initial, id: `page-checkpoint-${String(index).padStart(4, '0')}` }))]
    .sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
  const journal: InvocationJournalEntry[] = Array.from({ length: 1000 }, (_, index) => ({ seq: index + 1,
    runId: run.id, opId: `op-${index}`, opKind: 'tool', attempt: 0, leaseEpoch: 1, phase: 'prepared', target: 'tool',
    requestRef: run.specRef, replayClass: 'retry', budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, timestamp: run.createdAt }));
  driver.transaction(connection => {
    for (const entry of journal) connection.prepare(`INSERT INTO run_journal
      (run_id,seq,op_id,op_kind,attempt,phase,entry_json) VALUES(?,?,?,?,?,?,?)`).run(run.id, entry.seq,
        entry.opId, entry.opKind, entry.attempt, entry.phase, canonicalJsonBytes(entry).toString('utf8'));
    for (const checkpoint of checkpoints) if (checkpoint.id !== initial.id) connection.prepare(`INSERT INTO checkpoints
      (id,schema_version,run_id,based_on_run_revision,run_item_seq,context_manifest_ref,journal_seq,workspace_state_ref,created_at,reason)
      VALUES(?,1,?,?,?,?,?,?,?,?)`).run(checkpoint.id, run.id, checkpoint.basedOnRunRevision, checkpoint.runItemSeq,
        checkpoint.contextManifestRef, checkpoint.journalSeq, checkpoint.workspaceStateRef, checkpoint.createdAt, checkpoint.reason);
    // Retained display rows only: no workflow transition, Run authority or
    // execution proof is fabricated by this bounded page fixture.
    connection.prepare('DELETE FROM run_events WHERE run_id = ?').run(run.id);
    for (let seq = 1; seq <= 1000; seq++) {
      const event = { schemaVersion: 1, kind: 'state_changed', runId: run.id, eventSeq: seq, runRevision: 1,
        status: 'queued', nextStep: 'agent', frontierRef: run.frontierRef!, latestRunItemSeq: 0, occurredAt: run.createdAt };
      connection.prepare('INSERT INTO run_events(run_id,event_seq,payload_json,occurred_at) VALUES(?,?,?,?)')
        .run(run.id, seq, canonicalJsonBytes(event).toString('utf8'), event.occurredAt);
    }
  });
  const errors: Error[] = [], service = openInstalledControl(fixture.store, { serverBuild: 'read-page-fixture' }, error => errors.push(error));
  t.after(() => service.close());
  const exchange = await readPagePeer(t, path.join(fixture.stateRoot, 'runtime/control-v1.sock'));
  await exchange({ protocolVersion: 1, method: 'control.hello', clientBuild: 'read-page-fixture',
    controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 }, requestedFeatureIds: ['run.get', 'run.attach'] });
  const observed: InvocationJournalEntry[] = [];
  let afterJournalSeq = 0, pages = 0;
  do {
    const request = { protocolVersion: 1, method: 'run.get', runId: run.id, journalLimit: 1000, afterJournalSeq } as const;
    const response = decodeInstalledControlResponse(await exchange(request), request);
    assert(response.ok && response.result.method === 'run.get');
    assert.equal(response.result.highWaterJournalSeq, 1000);
    assert(response.result.journal.length > 0);
    assert.equal(response.result.journal[0]!.seq, afterJournalSeq + 1);
    if (pages === 0) {
      const next = journal[response.result.nextJournalSeq]!;
      assert(next);
      const over = { ...response, result: { ...response.result, journal: [...response.result.journal, next], nextJournalSeq: next.seq } };
      assert.throws(() => decodeControlFrame(canonicalJsonBytes(over)), /more than 10000/u,
        'the first omitted row must really exceed the complete frame member budget');
    }
    observed.push(...response.result.journal); afterJournalSeq = response.result.nextJournalSeq; pages++;
  } while (afterJournalSeq < 1000);
  assert(pages > 1, 'the strict container bound requires a real shorter first page');
  assert.deepEqual(observed, journal);
  const seenCheckpoints: Checkpoint[] = [];
  let checkpointCursor: string | undefined, checkpointPages = 0;
  do {
    const request = { protocolVersion: 1, method: 'run.get', runId: run.id, afterJournalSeq: 1000,
      checkpointLimit: 1000, ...(checkpointCursor ? { checkpointCursor } : {}) } as const;
    const response = decodeInstalledControlResponse(await exchange(request), request);
    assert(response.ok && response.result.method === 'run.get');
    assert(response.result.checkpoints.length > 0);
    seenCheckpoints.push(...response.result.checkpoints); checkpointCursor = response.result.nextCheckpointCursor; checkpointPages++;
    if (checkpointCursor === response.result.highWaterCheckpointCursor) break;
  } while (checkpointPages < 10);
  assert(checkpointPages > 1); assert.deepEqual(seenCheckpoints, checkpoints);
  let afterEventSeq = 0, eventPages = 0;
  const eventSequences: number[] = [];
  do {
    const request = { protocolVersion: 1, method: 'run.attach', runId: run.id, afterEventSeq, limit: 1000 } as const;
    const response = decodeInstalledControlResponse(await exchange(request), request);
    assert(response.ok && response.result.method === 'run.attach');
    assert(response.result.events.length > 0);
    eventSequences.push(...response.result.events.map(event => event.eventSeq));
    afterEventSeq = response.result.nextEventSeq; eventPages++;
  } while (afterEventSeq < 1000);
  assert(eventPages > 1); assert.deepEqual(eventSequences, Array.from({ length: 1000 }, (_, index) => index + 1));
  assert.deepEqual(errors, []);
});

test('artifact.get returns short verified registered-CAS pages and exact EOF without changing authority', async () => {
  const fixture = await createActiveFixture('control-read-artifact');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const bytes = Buffer.from(Array.from({ length: 70_013 }, (_, index) => index % 251));
    const artifact = await fixture.store.artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-query-data-fixture-v1');
    driver.transaction(connection => insertArtifactMetadata(connection, artifact, fixture.store.getRun(fixture.runId).createdAt));
    const footprint = () => ({ fence: driver.prepare('SELECT * FROM canonical_time_fence').get(),
      requests: driver.prepare('SELECT count(*) AS n FROM control_requests').get(), run: fixture.store.getRun(fixture.runId) });
    const before = footprint();
    const request = { protocolVersion: 1 as const, method: 'artifact.get' as const, digest: artifact.ref, offset: 0, length: 4 * 1024 * 1024 };
    const first = await fixture.store.readControl(request, identity);
    assert.ok(first.method === 'artifact.get');
    assert.deepEqual(first, { method: 'artifact.get', artifact: { schemaVersion: 1, ref: artifact.ref, digest: artifact.ref,
      sizeBytes: bytes.length, mediaType: 'application/octet-stream' }, offset: 0,
      bytesBase64: bytes.subarray(0, 65_536).toString('base64'), nextOffset: 65_536, eof: false });
    const last = await fixture.store.readControl({ ...request, offset: first.nextOffset }, identity);
    assert.ok(last.method === 'artifact.get');
    assert.equal(last.bytesBase64, bytes.subarray(65_536).toString('base64'));
    assert.equal(last.nextOffset, bytes.length);
    assert.equal(last.eof, true);
    const end = await fixture.store.readControl({ ...request, offset: bytes.length, length: 1 }, identity);
    assert.ok(end.method === 'artifact.get');
    assert.equal(end.offset, bytes.length);
    assert.equal(end.nextOffset, bytes.length);
    assert.equal(end.bytesBase64, '');
    assert.equal(end.eof, true);
    assert.deepEqual(footprint(), before);
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('artifact.get rejects unregistered bytes, foreign principals and invalid ranges without treating catalog labels as authority', async () => {
  const fixture = await createActiveFixture('control-read-artifact-bounds');
  const foreign = await createActiveFixture('control-read-artifact-foreign');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store), foreignIdentity = await publishInProcessChannel(foreign.store);
    const artifact = await fixture.store.artifacts.publishBytes(Buffer.alloc(0), 'application/octet-stream', 'not-an-access-control-label');
    const request = { protocolVersion: 1 as const, method: 'artifact.get' as const, digest: artifact.ref, offset: 0, length: 1 };
    await assert.rejects(fixture.store.readControl(request, identity), isCode('NOT_FOUND'));
    driver.transaction(connection => insertArtifactMetadata(connection, artifact, fixture.store.getRun(fixture.runId).createdAt));
    const empty = await fixture.store.readControl(request, identity);
    assert.deepEqual(empty, { method: 'artifact.get', artifact: { schemaVersion: 1, ref: artifact.ref, digest: artifact.ref,
      sizeBytes: 0, mediaType: 'application/octet-stream' }, offset: 0, bytesBase64: '', nextOffset: 0, eof: true });
    await assert.rejects(fixture.store.readControl(request, { ...identity, principalId: foreignIdentity.principalId }), isCode('ARTIFACT_MISMATCH'));
    // Even complete genuine foreign channel/principal bytes remain data, not
    // this root's authenticated identity. Do not rely on a missing CAS file.
    const foreignChannel = await foreign.store.artifacts.readCanonical<LocalControlChannelIdentityV1>(foreignIdentity.channelIdentityRef);
    await fixture.store.artifacts.publishCanonical(foreignChannel, foreignChannel.format);
    await fixture.store.artifacts.publishCanonical(await foreign.store.artifacts.readCanonical(foreignChannel.principalIdentityRef), 'cliq-local-principal-identity-v1');
    await assert.rejects(fixture.store.readControl(request, foreignIdentity), isCode('ARTIFACT_MISMATCH'));
    const foreignRef = foreign.store.getRun(foreign.runId).specRef;
    await assert.rejects(fixture.store.readControl({ ...request, digest: foreignRef }, identity), isCode('NOT_FOUND'));
    const malformed: unknown[] = [
      { ...request, digest: 'A'.repeat(64) }, { ...request, digest: 'sha256:' + artifact.ref },
      ...[-1, 1.5, true, '0', null, Number.MAX_SAFE_INTEGER + 1].map(offset => ({ ...request, offset })),
      ...[0, -1, 1.5, true, '1', null, 4 * 1024 * 1024 + 1].map(length => ({ ...request, length })),
      ...['requestId', 'principalId', 'schemaKind', 'channelIdentityRef'].map(key => ({ ...request, [key]: 'not-accepted' })),
      { protocolVersion: 1, method: 'artifact.get', digest: artifact.ref, offset: 0 },
      { ...request, offset: 1 }, { ...request, offset: Number.MAX_SAFE_INTEGER }
    ];
    let getterReads = 0;
    malformed.push(Object.create(request), Object.defineProperty({ ...request }, 'hidden', { value: true }),
      { ...request, [Symbol('hidden')]: true }, Object.defineProperty({ ...request }, 'digest', {
        enumerable: true, get() { getterReads += 1; return artifact.ref; }
      }));
    for (const value of malformed) await assert.rejects(fixture.store.readControl(value as never, identity), isCode('INVALID_REQUEST'));
    assert.equal(getterReads, 0, 'query normalization must not execute caller accessors');
  } finally { driver.close(); await disposeFixture(foreign); await disposeFixture(fixture); }
});

test('artifact.get snapshots the caller request and verifies bytes beyond the selected page before returning it', async () => {
  const fixture = await createActiveFixture('control-read-artifact-integrity');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const original = Buffer.alloc(131_081, 97);
    const artifact = await fixture.store.artifacts.publishBytes(original, 'application/octet-stream', 'cliq-query-data-fixture-v1');
    driver.transaction(connection => insertArtifactMetadata(connection, artifact, fixture.store.getRun(fixture.runId).createdAt));
    const request = { protocolVersion: 1 as const, method: 'artifact.get' as const, digest: artifact.ref, offset: 1, length: 7 };
    const reading = fixture.store.readControl(request, identity);
    request.digest = '0'.repeat(64); request.offset = 100; request.length = 4;
    const result = await reading;
    assert.ok(result.method === 'artifact.get');
    assert.equal(result.artifact.ref, artifact.ref);
    assert.equal(result.offset, 1);
    assert.equal(result.bytesBase64, original.subarray(1, 8).toString('base64'));
    const target = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, artifact.ref);
    const corrupt = Buffer.from(original); corrupt[corrupt.length - 1] = 98;
    await fs.chmod(target, 0o600); await fs.writeFile(target, corrupt); await fs.chmod(target, 0o400);
    await assert.rejects(fixture.store.readControl({ ...request, digest: artifact.ref, offset: 0, length: 1 }, identity), isCode('ARTIFACT_MISMATCH'));
    // Restore the test-owned bytes, not an alternate artifact or grant.
    await fs.chmod(target, 0o600); await fs.writeFile(target, original); await fs.chmod(target, 0o400);
    driver.prepare("UPDATE artifacts SET media_type = '' WHERE ref = ?").run(artifact.ref);
    await assert.rejects(fixture.store.readControl({ ...request, digest: artifact.ref, offset: 0, length: 1 }, identity), isCode('RECOVERY_REQUIRED'));
    driver.prepare('UPDATE artifacts SET media_type = ? WHERE ref = ?').run(artifact.mediaType, artifact.ref);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const reconnected = await publishInProcessChannel(fixture.store);
    assert.equal(reconnected.principalId, identity.principalId);
    const after = await fixture.store.readControl({ ...request, digest: artifact.ref, offset: 1, length: 7 }, reconnected);
    assert.deepEqual(after, result);
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('StateStore close cancels and joins the original artifact query before releasing its owner', async () => {
  const fixture = await createActiveFixture('control-read-artifact-join');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const originalOpen = fs.open;
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  let entered!: () => void;
  const closingHandle = new Promise<void>(resolve => { entered = resolve; });
  let reading: Promise<unknown> | undefined, closing: Promise<void> | undefined;
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const artifact = await fixture.store.artifacts.publishBytes(Buffer.alloc(65_539, 7), 'application/octet-stream', 'cliq-query-data-fixture-v1');
    driver.transaction(connection => insertArtifactMetadata(connection, artifact, fixture.store.getRun(fixture.runId).createdAt));
    const target = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, artifact.ref);
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      if (args[0] === target) {
        const actualClose = handle.close.bind(handle);
        handle.close = async () => { await actualClose(); entered(); await held; };
      }
      return handle;
    }) as typeof fs.open;
    reading = fixture.store.readControl({ protocolVersion: 1, method: 'artifact.get', digest: artifact.ref, offset: 0, length: 1 }, identity);
    const observedRead = assert.rejects(reading, isCode('LEASE_FENCED'));
    await closingHandle;
    let closed = false;
    closing = fixture.store.close().then(() => { closed = true; });
    await nextTurn();
    assert.equal(closed, false, 'verified staging bytes cannot outlive an unjoined original CAS close');
    assert.equal(driver.prepare("SELECT state FROM state_owners WHERE state='active'").get()?.state, 'active');
    await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method: 'artifact.get', digest: artifact.ref, offset: 0, length: 1 }, identity), isCode('LEASE_FENCED'));
    release();
    await observedRead; await closing;
    assert.equal(closed, true);
    fs.open = originalOpen;
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const successor = await publishInProcessChannel(fixture.store);
    const reread = await fixture.store.readControl({ protocolVersion: 1, method: 'artifact.get', digest: artifact.ref, offset: 0, length: 1 }, successor);
    assert.ok(reread.method === 'artifact.get');
    assert.equal(reread.bytesBase64, 'Bw==', 'the cancelled original query must preserve the registered bytes for its genuine successor');
  } finally {
    release(); await reading?.catch(() => {}); await closing?.catch(() => {});
    fs.open = originalOpen; driver.close(); await disposeFixture(fixture);
  }
});

test('an uncertain actual artifact close overrides shutdown cancellation and retains the original Store owner until process death', async () => {
  const directory = await makePrivateDir('.cliq-artifact-query-retirement-');
  // Same real Store/CAS seam in an independent process: the injected negative
  // observation follows FileHandle.close; it never fabricates death or a join.
  const script = `import assert from 'node:assert/strict';
    import { promises as fs } from 'node:fs';
    import path from 'node:path';
    import { openStateStore, publishInProcessChannel } from ${JSON.stringify(new URL('./store.ts', import.meta.url).href)};
    import { openSqliteDriver } from ${JSON.stringify(new URL('./sqlite-driver.ts', import.meta.url).href)};
    import { insertArtifactMetadata } from ${JSON.stringify(new URL('./artifacts.ts', import.meta.url).href)};
    import { ResourceRetirementError } from ${JSON.stringify(new URL('./errors.ts', import.meta.url).href)};
    import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from ${JSON.stringify(new URL('../config.ts', import.meta.url).href)};
    const exercise = async () => {
      const root = process.argv[1], store = await openStateStore(root);
      const identity = await publishInProcessChannel(store);
      const artifact = await store.artifacts.publishBytes(Buffer.from('actual immutable query bytes'), 'application/octet-stream', 'cliq-query-data-fixture-v1');
      const writer = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
      try { writer.transaction(connection => insertArtifactMetadata(connection, artifact, '2026-10-01T00:00:00.000Z')); }
      finally { writer.close(); }
      const originalOpen = fs.open, target = path.join(root, KERNEL_CAS_DIRECTORY, artifact.ref);
      const failure = Object.assign(new Error('uncertainty after actual query FileHandle.close'), { code: 'EIO' });
      let actualCloses = 0, retained;
      fs.open = async (...args) => {
        const handle = await originalOpen(...args);
        if (args[0] === target) {
          const actualClose = handle.close.bind(handle);
          handle.close = async () => {
            await actualClose(); actualCloses += 1;
            store.beginClose();
            throw failure;
          };
        }
        return handle;
      };
      try { await assert.rejects(store.readControl({ protocolVersion: 1, method: 'artifact.get', digest: artifact.ref, offset: 0, length: 1 }, identity), error => {
        assert.ok(error instanceof ResourceRetirementError); assert.equal(error.cause, failure); retained = error; return true;
      }); } finally { fs.open = originalOpen; }
      assert.equal(actualCloses, 1);
      for (let retry = 0; retry < 2; retry += 1) await assert.rejects(store.close(), error => error === retained);
      process.send({ state: 'retained', actualCloses });
    };
    process.on('message', message => { if (message === 'exercise') void exercise().catch(() => process.send({ state: 'failed' })); });
    process.send({ state: 'ready' });`;
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script, directory],
    { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  const exited = once(child, 'exit'), closed = once(child, 'close');
  let successorClosed = false;
  const reply = async () => (await once(child, 'message', { signal: AbortSignal.timeout(30_000) }))[0] as { state: string; actualCloses?: number };
  try {
    assert.equal((await reply()).state, 'ready');
    const pending = reply(); child.send('exercise');
    assert.deepEqual(await pending, { state: 'retained', actualCloses: 1 });
    const native = await loadNativeStateOwner();
    let wronglyAcquired: HeldStateOwnerLock | undefined;
    try { wronglyAcquired = native.acquireLock(directory, false); }
    catch (error) { assert.match(String(error), /OS lock is already held/); }
    if (wronglyAcquired) { wronglyAcquired.close(); assert.fail('an uncertain query close released the real original owner'); }
    child.kill('SIGKILL');
    assert.equal((await exited)[1], 'SIGKILL'); await closed;
    const successor = await openStateStore(directory);
    try { assert.equal(successor.ownerEpoch, 2); }
    finally { await successor.close(); successorClosed = true; }
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited; await closed;
    if (successorClosed) await fs.rm(directory, { recursive: true, force: true });
    else console.error(`preserving uncertain artifact query fixture: ${directory}`);
  }
});

test('control reads expose the empty Session and the admitted Run initial checkpoint without payload bytes', async () => {
  const fixture = await createActiveFixture('control-read-initial');
  const inspector = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const footprint = () => ({ fence: inspector.prepare('SELECT * FROM canonical_time_fence').get(),
      requests: inspector.prepare('SELECT count(*) AS n FROM control_requests').get() });
    const before = footprint();
    const run = fixture.store.getRun(fixture.runId);
    const session = await fixture.store.readControl({ protocolVersion: 1, method: 'session.get', sessionId: run.sessionId }, identity);
    assert.ok(session.method === 'session.get');
    assert.deepEqual(session, { method: 'session.get', snapshot: { schemaVersion: 1, session: fixture.store.getSession(run.sessionId) },
      items: [], highWaterItemSeq: 0, nextItemSeq: 0 });

    const result = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: run.id }, identity);
    assert.ok(result.method === 'run.get');
    assert.deepEqual(result.snapshot, { schemaVersion: 1, operation: 'agent', run, latestRunItemSeq: 0 });
    assert.deepEqual(result.items, []);
    assert.deepEqual(result.journal, []);
    assert.equal(result.highWaterItemSeq, 0);
    assert.equal(result.highWaterJournalSeq, 0);
    assert.equal(result.nextItemSeq, 0);
    assert.equal(result.nextJournalSeq, 0);
    assert.equal(result.checkpoints.length, 1);
    const checkpoint = result.checkpoints[0]!;
    assert.equal(checkpoint.id, run.latestCheckpointId);
    assert.equal(checkpoint.reason, 'initial');
    const cursor = canonicalJsonBytes({ schemaVersion: 1, runId: run.id, createdAt: checkpoint.createdAt, checkpointId: checkpoint.id })
      .toString('base64url');
    assert.equal(result.highWaterCheckpointCursor, cursor);
    assert.equal(result.nextCheckpointCursor, cursor);
    const caughtUp = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: run.id,
      afterItemSeq: 0, afterJournalSeq: 0, checkpointCursor: cursor }, identity);
    assert.ok(caughtUp.method === 'run.get');
    assert.deepEqual(caughtUp.checkpoints, []);
    assert.equal(caughtUp.nextCheckpointCursor, cursor);
    assert.equal(caughtUp.highWaterCheckpointCursor, cursor);
    const attached = await fixture.store.readControl({ protocolVersion: 1, method: 'run.attach', runId: run.id, afterEventSeq: 0 }, identity);
    assert.ok(attached.method === 'run.attach');
    for (const method of ['run.result', 'run.diff'] as const) {
      await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method, runId: run.id }, identity), error => {
        assert.ok(error instanceof ResultUnavailableError);
        assert.deepEqual(error.controlError, { schemaVersion: 1, code: 'RESULT_UNAVAILABLE', messageCode: 'run.result_unavailable',
          retryable: true, runId: run.id, status: run.status, currentRevision: run.revision });
        return true;
      });
      await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method, runId: 'unknown-run' }, identity), isCode('NOT_FOUND'));
      await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method, runId: run.id, requestId: uuidv7() } as never, identity),
        isCode('INVALID_REQUEST'));
    }
    // Query authority is read-only: it does not advance canonical time or allocate mutator replay rows.
    assert.deepEqual(footprint(), before);
  } finally { inspector.close(); await disposeFixture(fixture); }
});

/** Explicit retained display fixtures for the query algorithm, not execution/fork qualification. */
async function seedSessionView(store: StateStore, driver: SqliteDriver, sessionId: string, physical: SessionItem[], logical: SessionItem[],
  lineage?: { parentSessionId: string; forkedThroughItemSeq: number }): Promise<void> {
  const session = store.getSession(sessionId);
  const projection: SessionContextProjection = { schemaVersion: 1, format: 'cliq-session-context-v1', sessionId,
    contextRevision: session.contextRevision + 1, throughItemSeq: logical.length,
    segments: logical.length === 0 ? [] : [{ kind: 'excluded_control', fromItemSeq: 1, throughItemSeq: logical.length,
      sourceItemsDigest: canonicalSha256(logical.map(({ itemSeq, kind, payloadRef }) => ({ itemSeq, kind, payloadRef }))) }], projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const artifact = await store.artifacts.publishCanonical(projection, projection.format);
  driver.transaction(connection => {
    for (const item of physical) connection.prepare(`INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at)
      VALUES (?, ?, NULL, ?, ?, ?, ?)`).run(item.itemId, sessionId, item.itemSeq, item.kind, item.payloadRef, item.createdAt);
    connection.prepare(`UPDATE sessions SET latest_item_seq = ?, context_revision = ?, context_projection_ref = ?,
      parent_session_id = ?, forked_through_item_seq = ? WHERE id = ?`)
      .run(logical.length, projection.contextRevision, artifact.ref, lineage?.parentSessionId ?? null, lineage?.forkedThroughItemSeq ?? null, sessionId);
  });
}

test('Session pages expose the frozen logical nested-fork prefix, not later ancestor items or compactions', async () => {
  const fixture = await createActiveFixture('control-read-lineage');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const parentId = fixture.store.getRun(fixture.runId).sessionId;
    const payload = await fixture.store.artifacts.publishCanonical({ fixture: 'retained-display', secretBody: 'not-in-query-result' }, 'cliq-display-query-fixture-v1');
    const createdAt = fixture.store.getSession(parentId).createdAt;
    const item = (sessionId: string, itemSeq: number, itemId: string): SessionItem => ({ schemaVersion: 1, sessionId, itemSeq,
      itemId, kind: 'legacy_bookmark', payloadRef: payload.ref, createdAt });
    const parent = [item(parentId, 1, 'parent-1'), item(parentId, 2, 'parent-2'), item(parentId, 3, 'parent-3')];
    await seedSessionView(fixture.store, driver, parentId, parent, parent);
    const makeChild = async (label: string) => (await fixture.store.createSession({ ...identity, requestId: uuidv7(),
      admissionKey: admissionKey(label), workspacePath: fixture.workspace })).session.id;
    const childId = await makeChild('read-child');
    const child = item(childId, 3, 'child-3');
    await seedSessionView(fixture.store, driver, childId, [child], [...parent.slice(0, 2), child],
      { parentSessionId: parentId, forkedThroughItemSeq: 2 });
    const grandchildId = await makeChild('read-grandchild');
    const grandchild = item(grandchildId, 4, 'grandchild-4');
    await seedSessionView(fixture.store, driver, grandchildId, [grandchild], [...parent.slice(0, 2), child, grandchild],
      { parentSessionId: childId, forkedThroughItemSeq: 3 });
    const request = { protocolVersion: 1 as const, method: 'session.get' as const, sessionId: grandchildId, limit: 1 };
    const first = await fixture.store.readControl(request, identity);
    assert.ok(first.method === 'session.get');
    assert.deepEqual(first.items, [parent[0]]);
    assert.equal(first.highWaterItemSeq, 4);
    assert.equal(first.nextItemSeq, 1);
    const parentAppend = item(parentId, 4, 'parent-4');
    const parentCompaction = { ...item(parentId, 5, 'parent-compaction'), kind: 'legacy_compaction' as const };
    await seedSessionView(fixture.store, driver, parentId, [parentAppend, parentCompaction], [...parent, parentAppend, parentCompaction]);
    const childAppend = item(childId, 4, 'child-4');
    await seedSessionView(fixture.store, driver, childId, [childAppend], [...parent.slice(0, 2), child, childAppend],
      { parentSessionId: parentId, forkedThroughItemSeq: 2 });
    const rest = await fixture.store.readControl({ ...request, afterItemSeq: first.nextItemSeq, limit: 1000 }, identity);
    assert.ok(rest.method === 'session.get');
    assert.deepEqual(rest.items, [parent[1], child, grandchild]);
    assert.equal(rest.snapshot.session.contextRevision, first.snapshot.session.contextRevision);
    assert.equal(rest.highWaterItemSeq, 4);
    assert.equal(rest.nextItemSeq, 4);
    assert.equal(canonicalJsonBytes(rest).includes(Buffer.from('not-in-query-result')), false);
    const caughtUp = await fixture.store.readControl({ ...request, afterItemSeq: rest.nextItemSeq }, identity);
    assert.ok(caughtUp.method === 'session.get');
    assert.deepEqual(caughtUp.items, []);
    assert.equal(caughtUp.nextItemSeq, 4);
    await assert.rejects(fixture.store.readControl({ ...request, afterItemSeq: 5 }, identity), isCode('INVALID_REQUEST'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('Session pagination defaults to 100, accepts the 1000 upper bound, and keeps payloads as bounded references', async () => {
  const fixture = await createActiveFixture('control-read-session-pages');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const session = fixture.store.getSession(fixture.store.getRun(fixture.runId).sessionId);
    const payload = await fixture.store.artifacts.publishBytes(Buffer.alloc(1024 * 1024, 0x61), 'application/octet-stream', 'cliq-display-query-fixture-v1');
    const items: SessionItem[] = Array.from({ length: 1001 }, (_, index) => ({ schemaVersion: 1, sessionId: session.id,
      itemId: `display-${index + 1}`.padEnd(128, 'd'), itemSeq: index + 1, kind: 'legacy_bookmark', payloadRef: payload.ref, createdAt: session.createdAt }));
    await seedSessionView(fixture.store, driver, session.id, items, items);
    const request = { protocolVersion: 1 as const, method: 'session.get' as const, sessionId: session.id };
    const defaultPage = await fixture.store.readControl(request, identity);
    assert.ok(defaultPage.method === 'session.get');
    assert.deepEqual(defaultPage.items, items.slice(0, 100));
    assert.equal(defaultPage.nextItemSeq, 100);
    assert.equal(defaultPage.highWaterItemSeq, 1001);
    const largePage = await fixture.store.readControl({ ...request, afterItemSeq: defaultPage.nextItemSeq, limit: 1000 }, identity);
    assert.ok(largePage.method === 'session.get');
    assert.deepEqual(largePage.items, items.slice(100));
    assert.equal(largePage.nextItemSeq, 1001);
    assert.ok(canonicalJsonBytes(largePage.items).byteLength <= 1024 * 1024);
    const single = await fixture.store.readControl({ ...request, afterItemSeq: 1000, limit: 1 }, identity);
    assert.ok(single.method === 'session.get');
    assert.deepEqual(single.items, [items[1000]]);
    assert.ok(canonicalJsonBytes(single.items).byteLength < 1024);
    const caughtUp = await fixture.store.readControl({ ...request, afterItemSeq: 1001 }, identity);
    assert.ok(caughtUp.method === 'session.get');
    assert.deepEqual(caughtUp.items, []);
    assert.equal(caughtUp.nextItemSeq, 1001);
    // Corrupt retained metadata is not a legitimate large item and must not become a stalled empty page.
    const malformed: SessionItem = { ...items[0]!, itemId: 'x'.repeat(1024 * 1024), itemSeq: 1002 };
    await seedSessionView(fixture.store, driver, session.id, [malformed], [...items, malformed]);
    await assert.rejects(fixture.store.readControl({ ...request, afterItemSeq: 1001, limit: 1 }, identity), isCode('RECOVERY_REQUIRED'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('checkpoint pages sort equal timestamps by bytewise id and require an exact canonical retained Run-bound cursor', async () => {
  const fixture = await createActiveFixture('control-read-checkpoints');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const initial = (await fixture.store.readRecoveryClosure(fixture.runId)).latestCheckpoint;
    // Retained metadata fixture: no worker/fork/execution backend is claimed by these additional rows.
    const before: Checkpoint = { ...initial, id: '!checkpoint', basedOnRunRevision: fixture.runRevision, reason: 'auto' };
    const after: Checkpoint = { ...initial, id: '~checkpoint', basedOnRunRevision: fixture.runRevision, reason: 'auto' };
    for (const checkpoint of [after, before]) driver.prepare(`INSERT INTO checkpoints
      (id, schema_version, run_id, based_on_run_revision, run_item_seq, context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason)
      VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(checkpoint.id, checkpoint.runId, checkpoint.basedOnRunRevision, checkpoint.runItemSeq, checkpoint.contextManifestRef,
        checkpoint.journalSeq, checkpoint.workspaceStateRef, checkpoint.createdAt, checkpoint.reason);
    const encode = (value: unknown) => canonicalJsonBytes(value).toString('base64url');
    const core = { schemaVersion: 1, runId: fixture.runId, createdAt: initial.createdAt, checkpointId: initial.id };
    const beforeCursor = encode({ ...core, checkpointId: before.id });
    const initialCursor = encode(core);
    const afterCursor = encode({ ...core, checkpointId: after.id });
    const request = { protocolVersion: 1 as const, method: 'run.get' as const, runId: fixture.runId, checkpointLimit: 1 };
    const first = await fixture.store.readControl(request, identity);
    assert.ok(first.method === 'run.get');
    assert.deepEqual(first.checkpoints, [before]);
    assert.equal(first.nextCheckpointCursor, beforeCursor);
    assert.equal(first.highWaterCheckpointCursor, afterCursor);
    const second = await fixture.store.readControl({ ...request, checkpointCursor: first.nextCheckpointCursor }, identity);
    assert.ok(second.method === 'run.get');
    assert.deepEqual(second.checkpoints, [initial]);
    assert.equal(second.nextCheckpointCursor, initialCursor);
    const third = await fixture.store.readControl({ ...request, checkpointCursor: second.nextCheckpointCursor }, identity);
    assert.ok(third.method === 'run.get');
    assert.deepEqual(third.checkpoints, [after]);
    assert.equal(third.nextCheckpointCursor, afterCursor);
    const all = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId }, identity);
    assert.ok(all.method === 'run.get');
    assert.deepEqual(all.checkpoints, [before, initial, after]);
    const end = await fixture.store.readControl({ ...request, checkpointCursor: afterCursor }, identity);
    assert.ok(end.method === 'run.get');
    assert.deepEqual(end.checkpoints, []);
    assert.equal(end.nextCheckpointCursor, afterCursor);
    assert.equal(end.highWaterCheckpointCursor, afterCursor);
    const badCursors: unknown[] = [null, 0, '', '!', afterCursor + '=', 'x'.repeat(1025),
      Buffer.from(JSON.stringify(core)).toString('base64url'), // Same object, non-JCS key order.
      Buffer.from(`{"schemaVersion":1,"runId":"${fixture.runId}","createdAt":"${initial.createdAt}","checkpointId":"${initial.id}","checkpointId":"${initial.id}"}`).toString('base64url'),
      Buffer.from([0xff, 0xfe]).toString('base64url'),
      encode({ ...core, unknown: true }), encode({ ...core, schemaVersion: 2 }), encode({ ...core, runId: 'other-run' }),
      encode({ ...core, checkpointId: 'missing-checkpoint' }), encode({ ...core, createdAt: addCanonicalDuration(initial.createdAt, 1) }),
      encode({ ...core, createdAt: initial.createdAt.replace(/\.\d{3}Z/u, 'Z') }),
      encode({ ...core, createdAt: '2026-10-06T00:00:00+00:00' }), encode({ ...core, checkpointId: 'e\u0301' })];
    for (const checkpointCursor of badCursors) await assert.rejects(fixture.store.readControl(
      { ...request, checkpointCursor } as Parameters<StateStore['readControl']>[0], identity), isCode('INVALID_REQUEST'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('checkpoint bounds reject independently malformed first-page and high-water keys without changing their ordering', async () => {
  // Each corrupt row gets its own database, so a first-page failure cannot mask
  // a malformed maximum being omitted from the captured high-water.
  for (const field of ['id', 'createdAt'] as const) for (const prefix of ['!', '~~']) {
    const fixture = await createActiveFixture(`control-read-checkpoint-bound-${field}-${prefix.length}`);
    const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const identity = await publishInProcessChannel(fixture.store);
      const initial = (await fixture.store.readRecoveryClosure(fixture.runId)).latestCheckpoint;
      const malformed = { ...initial, id: 'malformed-checkpoint', [field]: prefix + 'x'.repeat(1_048_576) };
      // SQL must bound text before materializing it, but sorting must still use
      // the original keys, not the NULL sentinel from the guarded projection.
      driver.prepare(`INSERT INTO checkpoints
        (id, schema_version, run_id, based_on_run_revision, run_item_seq, context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason)
        VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(malformed.id, initial.runId, initial.basedOnRunRevision, initial.runItemSeq,
          initial.contextManifestRef, initial.journalSeq, initial.workspaceStateRef, malformed.createdAt, initial.reason);
      await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId,
        checkpointLimit: 1000 }, identity), isCode('RECOVERY_REQUIRED'));
    } finally { driver.close(); await disposeFixture(fixture); }
  }
});

async function assertMetadataCap(exact: boolean): Promise<void> {
  const fixture = await createActiveFixture(`control-read-byte-${exact ? 'exact' : 'priority'}`);
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store), run = fixture.store.getRun(fixture.runId);
    const payload = await fixture.store.artifacts.publishCanonical({ fixture: 'metadata-cap', body: 'not-embedded' }, 'cliq-query-metadata-fixture-v1');
    const items: RunItemReferenceV1[] = Array.from({ length: 1000 }, (_, index) => ({ schemaVersion: 1,
      itemId: `item-${index + 1}`.padEnd(128, 'i'), itemSeq: index + 1, payloadRef: payload.ref, payloadDigest: payload.ref, createdAt: run.createdAt }));
    // Closed retained metadata only, not a claim of dispatch or execution.
    const entry = (seq: number, target = 't'): InvocationJournalEntry => ({ seq, runId: run.id, opId: `op-${seq}`, opKind: 'tool',
      attempt: 0, leaseEpoch: 1, phase: 'prepared', target, requestRef: payload.ref, replayClass: 'retry',
      budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, timestamp: run.createdAt });
    const journal = [entry(1), entry(2, 's'.repeat(2000))];
    const insertJournal = (connection: SqliteConnection, value: InvocationJournalEntry) =>
      connection.prepare('INSERT INTO run_journal(run_id,seq,op_id,op_kind,attempt,phase,entry_json) VALUES(?,?,?,?,?,?,?)')
        .run(run.id, value.seq, value.opId, value.opKind, value.attempt, value.phase, canonicalJsonBytes(value).toString('utf8'));
    driver.transaction(connection => {
      for (const item of items) connection.prepare(`INSERT INTO items(item_id,session_id,run_id,item_seq,kind,payload_ref,created_at)
        VALUES(?,NULL,?,?,'model_turn',?,?)`).run(item.itemId, run.id, item.itemSeq, item.payloadRef, item.createdAt);
    });
    const request = { protocolVersion: 1 as const, method: 'run.get' as const, runId: run.id,
      itemLimit: 1000, journalLimit: 1000, checkpointLimit: 1000 };
    const probe = await fixture.store.readControl(request, identity);
    assert(probe.method === 'run.get'); assert.equal(probe.items.length, 1000);
    const { nextCheckpointCursor: _cursor, ...withoutCheckpointCursor } = probe;
    const firstFrame = (target: string) => ({ protocolVersion: 1, ok: true, result: {
      ...withoutCheckpointCursor, journal: [entry(1, target)], checkpoints: [], highWaterJournalSeq: 2, nextJournalSeq: 1 } });
    const gap = exact ? 0 : 1000;
    const remaining = 1_048_576 - gap - canonicalJsonBytes(firstFrame('t')).byteLength;
    assert(remaining > 0);
    journal[0] = entry(1, 't'.repeat(remaining + 1));
    driver.transaction(connection => { for (const value of journal) insertJournal(connection, value); });
    const capped = await fixture.store.readControl(request, identity);
    assert(capped.method === 'run.get');
    assert.deepEqual(capped.items, items); assert.deepEqual(capped.journal, journal.slice(0, 1)); assert.deepEqual(capped.checkpoints, []);
    assert.equal(capped.nextItemSeq, 1000); assert.equal(capped.highWaterItemSeq, 1000);
    assert.equal(capped.nextJournalSeq, 1); assert.equal(capped.highWaterJournalSeq, 2); assert.equal(capped.nextCheckpointCursor, undefined);
    const frame = { protocolVersion: 1, ok: true, result: capped };
    assert.equal(canonicalJsonBytes(frame).byteLength, 1_048_576 - gap);
    assert.doesNotThrow(() => decodeControlFrame(canonicalJsonBytes(frame)));
    assert(canonicalJsonBytes({ ...frame, result: { ...capped, journal, nextJournalSeq: 2 } }).byteLength > 1_048_576);
    const checkpoint = await fixture.store.readControl({ ...request, afterItemSeq: 1000, afterJournalSeq: 2 }, identity);
    assert(checkpoint.method === 'run.get'); assert.equal(checkpoint.checkpoints.length, 1);
    // A later Checkpoint may fit but cannot leapfrog the first non-fitting Journal row.
    if (!exact) assert(canonicalJsonBytes({ ...frame, result: { ...capped, checkpoints: checkpoint.checkpoints,
      nextCheckpointCursor: checkpoint.nextCheckpointCursor } }).byteLength <= 1_048_576);
    const rest = await fixture.store.readControl({ ...request, afterItemSeq: 1000, afterJournalSeq: capped.nextJournalSeq }, identity);
    assert(rest.method === 'run.get'); assert.deepEqual(rest.items, []); assert.deepEqual(rest.journal, journal.slice(1));
    assert.deepEqual(rest.checkpoints, checkpoint.checkpoints); assert.equal(rest.nextJournalSeq, 2);
    const end = await fixture.store.readControl({ ...request, afterItemSeq: 1000, afterJournalSeq: 2,
      checkpointCursor: rest.nextCheckpointCursor }, identity);
    assert(end.method === 'run.get'); assert.deepEqual([end.items, end.journal, end.checkpoints], [[], [], []]);
    // The row itself is under 1 MiB, but cannot fit even alone once the actual
    // snapshot and final envelope are included. Refuse instead of an empty loop.
    const oversized = entry(3);
    oversized.target = 'x'.repeat(1_048_575 - canonicalJsonBytes(oversized).byteLength + 1);
    assert.equal(canonicalJsonBytes(oversized).byteLength, 1_048_575);
    insertJournal(driver, oversized);
    await assert.rejects(fixture.store.readControl({ ...request, afterItemSeq: 1000, afterJournalSeq: 2 }, identity), isCode('RECOVERY_REQUIRED'));
  } finally { driver.close(); await disposeFixture(fixture); }
}

test('run.get budgets complete strict frames inclusively and stops before the first non-fitting candidate', async () => {
  await assertMetadataCap(false);
  await assertMetadataCap(true);
});

test('terminal event retention accepts earliest minus one and expiry carries the same authoritative snapshot and bounds', async () => {
  // Existing signed/offline worker fixture proves SQLite reducers, not actual OS containment or provider I/O.
  const fixture = await createAgentFixture('control-read-retention', undefined, { mode: 'plan' });
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const stopped = await fixture.agent.cancelRun({ ...identity, requestId: uuidv7(), expectedRunRevision: fixture.store.getRun(fixture.runId).revision });
    const proof = await quiescedToolCheckpoint(fixture, stopped.checkpointId);
    const terminal = await fixture.agent.commitTerminalStop({ expectedRunRevision: stopped.run.revision, checkpoint: proof.checkpoint });
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0 };
    const before = await fixture.store.readControl(request, identity);
    assert.ok(before.method === 'run.attach');
    const anchor = before.events.at(-1)!;
    assert.ok(anchor.kind === 'state_changed');
    assert.equal(anchor.status, 'cancelled');
    assert.equal(anchor.nextStep, null);
    assert.equal(anchor.terminalReason, 'cancelled_by_user');
    assert.ok(anchor.eventSeq > 1);
    // Display-retention fixture represents the post-window GC state; the authoritative Run is unchanged.
    driver.prepare('DELETE FROM run_events WHERE run_id = ? AND event_seq < ?').run(fixture.runId, anchor.eventSeq);
    const retained = await fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq - 1 }, identity);
    assert.ok(retained.method === 'run.attach');
    assert.deepEqual(retained.events, [anchor]);
    assert.equal(retained.earliestRetainedEventSeq, anchor.eventSeq);
    assert.equal(retained.latestRetainedEventSeq, anchor.eventSeq);
    assert.equal(retained.highWaterEventSeq, anchor.eventSeq);
    assert.equal(retained.nextEventSeq, anchor.eventSeq);
    assert.deepEqual(retained.snapshot.run, terminal.run);
    await assert.rejects(fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq - 2 }, identity), error => {
      assert.ok(error instanceof EventCursorExpiredError);
      assert.equal(error.code, 'EVENT_CURSOR_EXPIRED');
      assert.equal(error.retryable, false);
      assert.equal(error.earliestEventSeq, anchor.eventSeq);
      assert.equal(error.latestEventSeq, anchor.eventSeq);
      assert.deepEqual(error.snapshot, retained.snapshot);
      return true;
    });
    const caughtUp = await fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq }, identity);
    assert.ok(caughtUp.method === 'run.attach');
    assert.deepEqual(caughtUp.events, []);
    assert.equal(caughtUp.nextEventSeq, anchor.eventSeq);
    await assert.rejects(fixture.store.readControl({ ...request, afterEventSeq: anchor.eventSeq + 1 }, identity), isCode('INVALID_REQUEST'));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('attach refuses a missing event inside its retained interval instead of advancing a reconnect cursor past it', async () => {
  const fixture = await createAgentFixture('control-read-event-gap');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    await fixture.agent.prepareModel({ expectedRunRevision: fixture.runRevision, leaseEpoch: fixture.leaseEpoch });
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0 };
    const intact = await fixture.store.readControl(request, identity);
    assert.ok(intact.method === 'run.attach');
    assert.deepEqual(intact.events.map(event => event.eventSeq), [1, 2, 3]);
    const authoritative = fixture.store.getRun(fixture.runId);
    // Corruption inside the retained range is not legal prefix retention. Bounds stay 1..3.
    driver.prepare('DELETE FROM run_events WHERE run_id = ? AND event_seq = 2').run(fixture.runId);
    await assert.rejects(fixture.store.readControl(request, identity), isCode('RECOVERY_REQUIRED'));
    const firstPage = await fixture.store.readControl({ ...request, limit: 1 }, identity);
    assert.ok(firstPage.method === 'run.attach');
    assert.deepEqual(firstPage.events.map(event => event.eventSeq), [1]);
    assert.equal(firstPage.earliestRetainedEventSeq, 1);
    assert.equal(firstPage.highWaterEventSeq, 3);
    assert.equal(firstPage.nextEventSeq, 1);
    await assert.rejects(fixture.store.readControl({ ...request, afterEventSeq: firstPage.nextEventSeq, limit: 1 }, identity),
      isCode('RECOVERY_REQUIRED'));
    assert.deepEqual(fixture.store.getRun(fixture.runId), authoritative, 'display corruption cannot rewrite authoritative Run state');
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('retained event metadata rejects coercible arrays and malformed scalar bounds instead of echoing them', async () => {
  const fixture = await createActiveFixture('control-read-bad-events');
  const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const row = driver.prepare('SELECT event_seq, payload_json FROM run_events WHERE run_id = ? ORDER BY event_seq LIMIT 1')
      .get<{ event_seq: bigint; payload_json: string }>(fixture.runId)!;
    const state = JSON.parse(row.payload_json) as Record<string, unknown>;
    const progress = { schemaVersion: 1, kind: 'progress', runId: fixture.runId, eventSeq: Number(row.event_seq),
      observedRunRevision: fixture.runRevision, phase: 'agent', occurredAt: state.occurredAt };
    const malformed = [
      { ...state, status: ['queued'] }, { ...state, nextStep: ['agent'] },
      { ...state, frontierRef: [state.frontierRef] }, { ...state, latestRunItemSeq: -1 },
      { ...progress, phase: ['agent'] }, { ...progress, messageRef: ['a'.repeat(64)] },
      { ...progress, completedUnits: 0.5 }, { ...progress, totalUnits: Number.MAX_SAFE_INTEGER + 1 }
    ];
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0 };
    for (const event of malformed) {
      // Display-row corruption fixtures never change authoritative Run state or native process identity.
      driver.prepare('UPDATE run_events SET payload_json = ? WHERE run_id = ? AND event_seq = ?')
        .run(JSON.stringify(event), fixture.runId, row.event_seq);
      await assert.rejects(fixture.store.readControl(request, identity), isCode('RECOVERY_REQUIRED'));
    }
    driver.prepare('UPDATE run_events SET payload_json = ? WHERE run_id = ? AND event_seq = ?')
      .run(row.payload_json, fixture.runId, row.event_seq);
    const restored = await fixture.store.readControl(request, identity);
    assert.ok(restored.method === 'run.attach');
    assert.deepEqual(canonicalJsonBytes(restored.events[0]), canonicalJsonBytes(state));
  } finally { driver.close(); await disposeFixture(fixture); }
});

test('control queries reject future cursors, malformed bounds and identifiers, and every mutation-only field', async () => {
  const fixture = await createActiveFixture('control-read-validation');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const sessionId = fixture.store.getRun(fixture.runId).sessionId;
    const valid = [
      { protocolVersion: 1, method: 'session.get', sessionId },
      { protocolVersion: 1, method: 'run.get', runId: fixture.runId },
      { protocolVersion: 1, method: 'run.attach', runId: fixture.runId, afterEventSeq: 0 }
    ];
    const reject = (request: unknown) => assert.rejects(
      fixture.store.readControl(request as Parameters<StateStore['readControl']>[0], identity), isCode('INVALID_REQUEST')
    );
    for (const request of valid) {
      for (const field of ['requestId', 'requestDigest', 'admissionKey', 'principalId', 'channelIdentityRef', 'unexpected']) {
        await reject({ ...request, [field]: 'not-a-query-field' });
      }
      await reject({ ...request, protocolVersion: 2 });
      const idField = request.method === 'session.get' ? 'sessionId' : 'runId';
      for (const id of ['', 'x'.repeat(129), 'e\u0301', 'x\0y', '\ud800', 1, null]) await reject({ ...request, [idField]: id });
    }
    for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, '1', null]) {
      await reject({ ...valid[0], afterItemSeq: value });
      await reject({ ...valid[1], afterItemSeq: value });
      await reject({ ...valid[1], afterJournalSeq: value });
      await reject({ ...valid[2], afterEventSeq: value });
    }
    for (const limit of [0, -1, 1.5, 1001, Number.MAX_SAFE_INTEGER + 1, '1', null]) {
      await reject({ ...valid[0], limit });
      await reject({ ...valid[1], itemLimit: limit });
      await reject({ ...valid[1], journalLimit: limit });
      await reject({ ...valid[1], checkpointLimit: limit });
      await reject({ ...valid[2], limit });
    }
    await reject({ ...valid[0], afterItemSeq: 1 });
    await reject({ ...valid[1], afterItemSeq: 1 });
    await reject({ ...valid[1], afterJournalSeq: 1 });
    const attached = await fixture.store.readControl(valid[2] as Parameters<StateStore['readControl']>[0], identity);
    assert.ok(attached.method === 'run.attach');
    await reject({ ...valid[2], afterEventSeq: attached.highWaterEventSeq + 1 });
    await reject({ protocolVersion: 1, method: 'run.attach', runId: fixture.runId });
    await reject({ protocolVersion: 1, method: 'run.list' });
    await reject(null);
    await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: 'missing' }, identity), isCode('NOT_FOUND'));
    await assert.rejects(fixture.store.readControl({ protocolVersion: 1, method: 'session.get', sessionId: 'missing' }, identity), isCode('NOT_FOUND'));
  } finally { await disposeFixture(fixture); }
});

test('a later attach page sees a committed reducer transition, while the earlier snapshot and cut remain unchanged', async () => {
  const fixture = await createAgentFixture('control-read-events');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const request = { protocolVersion: 1 as const, method: 'run.attach' as const, runId: fixture.runId, afterEventSeq: 0, limit: 1 };
    const first = await fixture.store.readControl(request, identity);
    assert.ok(first.method === 'run.attach');
    assert.equal(first.events.length, 1);
    assert.equal(first.events[0]!.eventSeq, 1);
    assert.equal(first.nextEventSeq, 1);
    assert.equal(first.earliestRetainedEventSeq, 1);
    assert.ok(first.nextEventSeq < first.highWaterEventSeq);
    const beforeBytes = canonicalJsonBytes(first);
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.runRevision, leaseEpoch: fixture.leaseEpoch });
    const second = await fixture.store.readControl({ ...request, afterEventSeq: first.nextEventSeq, limit: 100 }, identity);
    assert.ok(second.method === 'run.attach');
    assert.equal(second.highWaterEventSeq, first.highWaterEventSeq + 1);
    assert.equal(second.latestRetainedEventSeq, second.highWaterEventSeq);
    assert.equal(second.snapshot.run.revision, prepared.run.revision);
    assert.deepEqual(second.events.map(event => event.eventSeq),
      Array.from({ length: second.highWaterEventSeq - 1 }, (_, index) => index + 2));
    const transition = second.events.at(-1)!;
    assert.ok(transition.kind === 'state_changed');
    assert.equal(transition.runRevision, prepared.run.revision);
    assert.equal(second.nextEventSeq, second.highWaterEventSeq);
    assert.deepEqual(canonicalJsonBytes(first), beforeBytes);
    const caughtUp = await fixture.store.readControl({ ...request, afterEventSeq: second.nextEventSeq }, identity);
    assert.ok(caughtUp.method === 'run.attach');
    assert.deepEqual(caughtUp.events, []);
    assert.equal(caughtUp.nextEventSeq, second.nextEventSeq);
  } finally { await disposeFixture(fixture); }
});

test('run journal cursors and checkpoint cursors survive owner reopen with a fresh authenticated channel', async () => {
  const fixture = await createAgentFixture('control-read-reopen');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const prepared = await fixture.agent.prepareModel({ expectedRunRevision: fixture.runRevision, leaseEpoch: fixture.leaseEpoch });
    const first = await fixture.store.readControl({ protocolVersion: 1, method: 'run.get', runId: fixture.runId, journalLimit: 1 }, identity);
    assert.ok(first.method === 'run.get');
    assert.deepEqual(first.journal, [prepared.entry]);
    assert.equal(first.highWaterJournalSeq, 1);
    assert.equal(first.nextJournalSeq, 1);
    const errorArtifact = await fixture.store.artifacts.publishCanonical({ fixture: 'not-dispatched' }, 'cliq-tool-error-v1');
    const failed = await fixture.store.failInvocationBeforeDispatch({ runId: fixture.runId, opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: prepared.run.revision, errorRef: errorArtifact.ref });
    assert.equal(first.snapshot.run.revision, prepared.run.revision);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const fresh = await publishInProcessChannel(fixture.store);
    assert.equal(fresh.principalId, identity.principalId);
    assert.notEqual(fresh.channelIdentityRef, identity.channelIdentityRef);
    const request = { protocolVersion: 1 as const, method: 'run.get' as const, runId: fixture.runId,
      afterJournalSeq: first.nextJournalSeq, checkpointCursor: first.nextCheckpointCursor };
    const next = await fixture.store.readControl(request, fresh);
    assert.ok(next.method === 'run.get');
    assert.deepEqual(next.journal, [failed.entry]);
    assert.equal(next.snapshot.run.revision, failed.run.revision);
    assert.equal(next.highWaterJournalSeq, 2);
    assert.equal(next.nextJournalSeq, 2);
    assert.deepEqual(next.checkpoints, []);
    assert.equal(next.nextCheckpointCursor, first.nextCheckpointCursor);
    assert.equal(next.highWaterCheckpointCursor, first.highWaterCheckpointCursor);
    assert.deepEqual(await fixture.store.readControl(request, fresh), next);
    // In-process provenance identifies this same host process/root, not the retired owner epoch.
    assert.deepEqual(await fixture.store.readControl(request, identity), next);
  } finally { await disposeFixture(fixture); }
});
