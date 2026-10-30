import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { CONTROL_FRAME_BYTES, CONTROL_V1_SOURCE_DIGEST, decodeInstalledControlRequest } from '../control/v1.js';
import { MAX_JSON_CONTAINER_ENTRIES, MAX_JSON_DEPTH, measureBoundedJsonValue } from '../kernel/json.js';
import { clientMutation } from './commands.js';
import { decodePendingRequestFiles, openPendingRequests, type PendingClientMutation, type PendingRequestMetadata } from './pending-requests.js';
import { openPrivateClientDirectory } from './private-files.js';
import { loadNativeStateOwner } from '../state/native-owner.js';
import { ClientBusyError, ClientPendingRequestError } from './errors.js';
import { runSnapshot, sessionSnapshot } from './testing/protocol.js';

const linux = process.platform === 'linux', bundle = canonicalSha256('original source bundle');
const request = () => clientMutation({ method: 'session.create', workspacePath: '/owned/workspace', name: 'Original e\u0301' }, true) as PendingClientMutation;
function metadata(original: PendingClientMutation): PendingRequestMetadata {
  return { schemaVersion: 1, protocolVersion: 1, method: original.method, requestId: original.requestId, requestDigest: original.requestDigest,
    stateRoot: { deviceId: '1', fileId: '2', ownerUid: 123 }, sourceBundleDigest: bundle, controlSourceDigest: CONTROL_V1_SOURCE_DIGEST };
}
const knownResponse = () => ({ protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: sessionSnapshot() } });

// Pure wire-data regressions below create no connection, StateOwner, Run,
// credential or installation. They are not qualification evidence.
test('pending files preserve exact original Unicode/request identity independently of source bundle hints', () => {
  const original = request(), bytes = canonicalJsonBytes(original), data = metadata(original);
  const result = decodePendingRequestFiles(canonicalJsonBytes(data), bytes, canonicalJsonBytes(knownResponse()));
  assert.deepEqual(result.bytes, bytes); assert.equal(result.request.requestId, original.requestId);
  assert.equal(result.request.requestDigest, original.requestDigest); assert.equal(result.response?.ok, true);
  assert(Object.isFrozen(result.request)); assert(Object.isFrozen(result.metadata.stateRoot));
  const older = { ...data, sourceBundleDigest: canonicalSha256('older still-compatible bundle'), controlSourceDigest: 'a'.repeat(64) };
  assert.deepEqual(decodePendingRequestFiles(canonicalJsonBytes(older), bytes).request, original);
  result.bytes.fill(0); assert.deepEqual(decodePendingRequestFiles(canonicalJsonBytes(data), bytes).bytes, bytes);
});

test('separate original request bytes keep the exact wire byte, depth and node limits', () => {
  const input = (value: unknown) => clientMutation({ method: 'run.input', runId: 'run', expectedRevision: 1,
    waitingOnRef: canonicalSha256('original wait'), input: { kind: 'json', value } }) as PendingClientMutation;
  let value: unknown = [];
  for (let index = 1; index < MAX_JSON_DEPTH - 2; index++) value = [value];
  const deep = input(value);
  assert.equal(measureBoundedJsonValue(deep).maxContainerDepth, MAX_JSON_DEPTH);
  assert.throws(() => measureBoundedJsonValue({ metadata: metadata(deep), request: deep }));
  assert.deepEqual(decodePendingRequestFiles(canonicalJsonBytes(metadata(deep)), canonicalJsonBytes(deep)).request, deep);
  const overhead = measureBoundedJsonValue(input([])).containerEntries;
  const many = input(Array(MAX_JSON_CONTAINER_ENTRIES - overhead).fill(0));
  assert.equal(measureBoundedJsonValue(many).containerEntries, MAX_JSON_CONTAINER_ENTRIES);
  assert.deepEqual(decodePendingRequestFiles(canonicalJsonBytes(metadata(many)), canonicalJsonBytes(many)).request, many);
  const empty = input(''), full = input('x'.repeat(CONTROL_FRAME_BYTES - canonicalJsonBytes(empty).length));
  const bytes = canonicalJsonBytes(full); assert.equal(bytes.length, CONTROL_FRAME_BYTES);
  assert.equal(decodePendingRequestFiles(canonicalJsonBytes(metadata(full)), bytes).bytes.length, CONTROL_FRAME_BYTES);
  assert.throws(() => decodePendingRequestFiles(canonicalJsonBytes(metadata(full)), Buffer.concat([bytes, Buffer.from(' ')])));
});

test('pending decoders reject noncanonical, mixed, secret-continuation and malicious response data', () => {
  const original = request(), bytes = canonicalJsonBytes(original), data = metadata(original), meta = canonicalJsonBytes(data);
  for (const bad of [Buffer.from('{}'), Buffer.from(JSON.stringify(data, null, 2)), Buffer.alloc(4097), Buffer.from([255]),
    canonicalJsonBytes({ ...data, apiKey: 'never accepted' }), canonicalJsonBytes({ ...data, protocolVersion: 2 }),
    canonicalJsonBytes({ ...data, requestDigest: canonicalSha256('other bytes') })]) assert.throws(() => decodePendingRequestFiles(bad, bytes));
  assert.throws(() => decodePendingRequestFiles(meta, Buffer.from(JSON.stringify(original, null, 2))));
  assert.throws(() => decodePendingRequestFiles(meta, canonicalJsonBytes(request())));
  const continuation = { protocolVersion: 1, method: 'credential.finalize', requestId: original.requestId,
    operationId: 'operation', attempt: 1, commandDigest: canonicalSha256('command') };
  assert.throws(() => decodePendingRequestFiles(meta, canonicalJsonBytes(continuation)));
  for (const response of [
    { ...knownResponse(), extra: true },
    { protocolVersion: 1, ok: false, method: 'session.create', error: { schemaVersion: 1, code: 'NOT_A_CLOSED_CODE', retryable: false, messageCode: 'bad' } },
    { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: runSnapshot() } }
  ]) assert.throws(() => decodePendingRequestFiles(meta, bytes, canonicalJsonBytes(response)));
});

async function fixture() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-pending-data-')), root = path.join(home, 'state');
  await mkdir(root, { mode: 0o700 });
  const physical = await lstat(root, { bigint: true });
  const binding = { stateRoot: { canonicalPath: root, deviceId: String(physical.dev), fileId: String(physical.ino), ownerUid: Number(physical.uid) }, sourceBundleDigest: bundle };
  const native = await loadNativeStateOwner();
  const directoryPath = path.join(home, 'client'), directory = await openPrivateClientDirectory(directoryPath, { create: true, native });
  const pending = await openPendingRequests(directory, binding);
  return { home, root, binding, directoryPath, directory, pending, native,
    async close() { await pending.close(); try { await directory.close(); } finally { await rm(home, { recursive: true, force: true }); } } };
}

test('real files retain an unknown request across restart and a strict known response across output loss', { skip: !linux }, async () => {
  const f = await fixture(), original = request();
  try {
    const retained = await f.pending.retain(original); assert.equal(retained.existing, false);
    assert.deepEqual(retained.bytes, canonicalJsonBytes(original));
    await f.pending.close(); await f.directory.close();
    const directory = await openPrivateClientDirectory(f.directoryPath, { native: f.native }), pending = await openPendingRequests(directory,
      { ...f.binding, sourceBundleDigest: canonicalSha256('upgraded current bundle') });
    try {
      assert.equal((await pending.list())[0]?.state, 'unresolved');
      assert.deepEqual((await pending.load(original.requestId)).request, original);
      await assert.rejects(pending.retain(original), ClientPendingRequestError);
      assert.equal((await pending.retain(original, { replay: true })).existing, true);
      await pending.resolve(original, knownResponse()); // No output occurred.
    } finally { await pending.close(); await directory.close(); }
    const nextDirectory = await openPrivateClientDirectory(f.directoryPath, { native: f.native }), next = await openPendingRequests(nextDirectory, f.binding);
    try {
      assert.deepEqual((await next.load(original.requestId)).response, knownResponse());
      const entry = (await next.list())[0]; assert.equal(entry?.state, 'known'); assert.equal(entry?.knownSessionId, 'session');
      assert.equal(entry?.metadata.sourceBundleDigest, bundle, 'an upgrade never rewrites original provenance');
      assert.deepEqual(await readFile(path.join(f.directoryPath, 'requests-v1', original.requestId, 'request.json')), canonicalJsonBytes(original));
    } finally { await next.close(); await nextDirectory.close(); }
  } finally { await f.close(); }
});

test('same original acknowledgements are idempotent; conflicting bytes and unknown responses never replace a record', { skip: !linux }, async () => {
  const f = await fixture(), original = request();
  try {
    await f.pending.retain(original);
    const changedCore = { ...original, name: 'changed' } as Record<string, unknown>; delete changedCore.requestDigest;
    const changed = decodeInstalledControlRequest({ ...changedCore, requestDigest: canonicalSha256(changedCore) });
    await assert.rejects(f.pending.retain(changed), /conflicts with the retained original bytes/u);
    await assert.rejects(f.pending.resolve(changed, knownResponse()), /retained original request/u);
    assert.throws(() => f.pending.resolve(original, { ok: true }));
    assert.equal((await f.pending.list())[0]?.state, 'unresolved');
    const results = await Promise.all([f.pending.resolve(original, knownResponse()), f.pending.resolve(original, knownResponse())]);
    assert(results.every(value => value.response?.ok));
    const otherResponse = { protocolVersion: 1, ok: false, method: 'session.create',
      error: { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.not_found' } };
    await assert.rejects(f.pending.resolve(original, otherResponse), /conflicts with the retained original response/u);
    assert.deepEqual((await f.pending.load(original.requestId)).response, knownResponse());
  } finally { await f.close(); }
});

test('incomplete/corrupted actual request groups are retained and block replacement; a replaced StateRoot cannot reuse them', { skip: !linux }, async () => {
  const f = await fixture(), original = request();
  try {
    const group = path.join(f.directoryPath, 'requests-v1', original.requestId);
    await mkdir(group, { mode: 0o700 }); await writeFile(path.join(group, 'request.json'), canonicalJsonBytes(original), { mode: 0o600 });
    await assert.rejects(f.pending.retain(original), /incomplete/u); await assert.rejects(f.pending.list(), /incomplete/u);
    assert.deepEqual(await readdir(group), ['request.json']);
    await rename(f.root, f.root + '-old'); await mkdir(f.root, { mode: 0o700 });
    await assert.rejects(f.pending.load(original.requestId), /another physical StateRoot/u);
    assert.deepEqual(await readdir(group), ['request.json']);
  } finally { await f.close(); }
});

test('response persistence failure preserves the original unresolved request and never claims a known result', { skip: !linux }, async () => {
  const f = await fixture(), original = request(); let prototype: any, write: any;
  try {
    await f.pending.retain(original);
    const filename = path.join(f.directoryPath, 'requests-v1', original.requestId, 'request.json'), sample = await open(filename);
    prototype = Object.getPrototypeOf(sample); write = prototype.writeFile; await sample.close();
    const failure = Object.assign(new Error('injected response descriptor storage failure'), { code: 'ENOSPC' });
    prototype.writeFile = async function() { throw failure; };
    await assert.rejects(f.pending.resolve(original, knownResponse()), error => error === failure);
    prototype.writeFile = write;
    const retained = await f.pending.load(original.requestId); assert.equal(retained.response, undefined);
    assert.deepEqual(retained.bytes, canonicalJsonBytes(original));
    assert.deepEqual(await readdir(path.dirname(filename)), ['metadata.json', 'request.json']);
  } finally { if (prototype) prototype.writeFile = write; await f.close(); }
});

test('explicit actual-file acknowledgement refuses unknown results and retires only the complete known group', { skip: !linux }, async () => {
  const f = await fixture(), original = request();
  try {
    await f.pending.retain(original);
    await assert.rejects(f.pending.acknowledge(original.requestId), /strictly known original response/u);
    assert.equal((await f.pending.list())[0]?.state, 'unresolved');
    await f.pending.resolve(original, knownResponse());
    await Promise.all([f.pending.acknowledge(original.requestId), f.pending.acknowledge(original.requestId)]);
    assert.deepEqual(await f.pending.list(), []);
    assert.deepEqual(await readdir(path.join(f.directoryPath, 'requests-v1')), []);
    await f.directory.replace('preferences.json', Buffer.from('root family remains usable'));
  } finally { await f.close(); }
});

test('independent actual stores atomically fence foreign unknowns, release busy locks and preserve original replay', { skip: !linux }, async () => {
  const f = await fixture(), first = request(), second = request();
  const otherDirectory = await openPrivateClientDirectory(f.directoryPath, { native: f.native });
  const other = await openPendingRequests(otherDirectory, f.binding);
  let entered!: () => void, release!: () => void;
  const inside = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const holding = f.directory.withLock(async () => { entered(); await gate; });
  try {
    await inside;
    await assert.rejects(other.retain(second), ClientBusyError);
    await assert.rejects(other.list(), ClientBusyError);
    assert.deepEqual(await readdir(path.join(f.directoryPath, 'requests-v1')), []);
    release(); await holding;
    await f.pending.retain(first);
    await assert.rejects(other.retain(second), ClientPendingRequestError);
    await assert.rejects(other.retain(second, { replay: true }), ClientPendingRequestError);
    assert.deepEqual(await readdir(path.join(f.directoryPath, 'requests-v1')), [first.requestId]);
    const replayed = await other.retain(first, { replay: true });
    assert.equal(replayed.existing, true); assert.deepEqual(replayed.bytes, canonicalJsonBytes(first));
    await other.resolve(first, knownResponse());
    assert.equal((await f.pending.load(first.requestId)).response?.ok, true);
    await f.pending.acknowledge(first.requestId);
    await other.retain(second);
    assert.equal((await f.pending.list())[0]?.metadata.requestId, second.requestId);
  } finally {
    release(); await holding; await other.close(); await otherDirectory.close(); await f.close();
  }
});

test('two real Linux processes cannot publish different unknown requests from simultaneous empty startup cuts', {
  skip: !linux, timeout: 20_000,
}, async t => {
  const f = await fixture(), originals = [request(), request()];
  const children = originals.map(original => {
    const child = fork(fileURLToPath(new URL('./testing/pending-request-child.ts', import.meta.url)), [], {
      execPath: process.execPath, execArgv: ['--import', 'tsx'], stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    let output = 0;
    for (const stream of [child.stdout!, child.stderr!]) stream.on('data', bytes => { output += bytes.length; if (output > 4096) child.kill('SIGKILL'); });
    const closed = new Promise<void>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => code === 0 && signal === null ? resolve() : reject(new Error('owned pending-data child did not join successfully')));
    });
    void closed.catch(() => {});
    const ready = once(child, 'message'); child.send({ directoryPath: f.directoryPath, binding: f.binding, request: original });
    return { child, closed, ready };
  });
  const abort = () => { for (const owner of children) if (owner.child.exitCode === null && owner.child.signalCode === null) owner.child.kill('SIGKILL'); };
  t.signal.addEventListener('abort', abort, { once: true });
  try {
    for (const owner of children) {
      const [message] = await Promise.race([owner.ready, owner.closed.then(() => { throw new Error('owned child closed before ready'); })]);
      assert.deepEqual(message, { kind: 'ready' });
    }
    const results = children.map(owner => {
      const result = once(owner.child, 'message'); owner.child.send({ kind: 'retain' });
      return Promise.race([result, owner.closed.then(() => { throw new Error('owned child closed before result'); })]);
    });
    const outcomes = await Promise.all(results);
    assert.equal(outcomes.filter(([value]) => value.kind === 'created').length, 1);
    assert(outcomes.every(([value]) => ['created', 'busy', 'pending'].includes(value.kind)));
    await Promise.all(children.map(owner => owner.closed));
    const winner = originals[outcomes.findIndex(([value]) => value.kind === 'created')]!;
    const records = await f.pending.list(); assert.equal(records.length, 1);
    assert.equal(records[0]!.state, 'unresolved'); assert.equal(records[0]!.metadata.requestId, winner.requestId);
    assert.deepEqual((await f.pending.load(winner.requestId)).bytes, canonicalJsonBytes(winner));
    assert.deepEqual(await readdir(path.join(f.directoryPath, 'requests-v1')), [winner.requestId]);
  } finally {
    t.signal.removeEventListener('abort', abort);
    for (const owner of children) if (owner.child.exitCode === null && owner.child.signalCode === null) owner.child.kill('SIGTERM');
    await Promise.allSettled(children.map(owner => owner.closed)); await f.close();
  }
});
