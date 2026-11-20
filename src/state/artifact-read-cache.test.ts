import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ArtifactCatalog, withArtifactReadCache } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { ResourceRetirementError } from './errors.js';
import { digestOmitting } from '../kernel/identity.js';
import type { WorkspaceEntryManifest, WorkspaceStateManifest } from '../kernel/types.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';

async function files(t: import('node:test').TestContext) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-read-cache-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'objects'); await mkdir(root, { mode: 0o700 });
  const cas = new ContentAddressedStore(root), artifacts = new ArtifactCatalog(cas);
  return { root, cas, artifacts };
}

test('verified JSON byte copies retain independent decoding, raw verification and fresh later traversals', async t => {
  const { root, cas, artifacts } = await files(t);
  const { ref } = await artifacts.publishCanonical({ value: 'original' }, 'inert-cache-data');
  const read = cas.read.bind(cas); let reads = 0, returned: Buffer | undefined;
  t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => { reads++; returned = await read(...args); return returned; });
  await withArtifactReadCache(async () => {
    const first = await artifacts.readCanonical<{ value: string }>(ref); first.value = 'caller mutation';
    returned!.fill(0);
    assert.deepEqual(await artifacts.withReadSignal(new AbortController().signal).readCanonical(ref), { value: 'original' });
    assert.equal(reads, 1);
    await artifacts.readBytes(ref); await artifacts.readBytes(ref);
    assert.equal(reads, 3, 'explicit raw-byte reads retain their complete independent verification');
  });
  await chmod(path.join(root, ref), 0o600); await writeFile(path.join(root, ref), 'corrupt'); await chmod(path.join(root, ref), 0o400);
  await assert.rejects(withArtifactReadCache(() => artifacts.readCanonical(ref)));
  assert.equal(reads, 4, 'a later traversal cannot borrow the earlier verified copy');
});

test('nested and failed traversals keep independent fresh byte ownership', async t => {
  const { cas, artifacts } = await files(t);
  const { ref } = await artifacts.publishCanonical({ value: 'original' }, 'inert-cache-data');
  const read = cas.read.bind(cas); let reads = 0;
  t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => { reads++; return read(...args); });
  const failure = new Error('original traversal failed');
  await assert.rejects(withArtifactReadCache(async () => {
    await artifacts.readCanonical(ref);
    await withArtifactReadCache(() => artifacts.readCanonical(ref));
    assert.equal(reads, 2);
    await artifacts.readCanonical(ref); assert.equal(reads, 2);
    throw failure;
  }), error => error === failure);
  await withArtifactReadCache(() => artifacts.readCanonical(ref));
  assert.equal(reads, 3);
});

test('cache byte exhaustion continues complete original reads without changing accepted inputs', async t => {
  const { cas, artifacts } = await files(t);
  const refs: string[] = [];
  for (let index = 0; index < 65; index++) refs.push((await artifacts.publishCanonical({ index,
    text: 'x'.repeat(1024 * 1024 - 256) }, 'inert-cache-capacity')).ref);
  const read = cas.read.bind(cas), counts = new Map<string, number>();
  t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => {
    counts.set(args[0], (counts.get(args[0]) ?? 0) + 1); return read(...args);
  });
  await withArtifactReadCache(async () => {
    for (const ref of refs) await artifacts.readCanonical(ref);
    await artifacts.readCanonical(refs[0]!); await artifacts.readCanonical(refs[19]!);
    await artifacts.readCanonical(refs.at(-1)!);
  });
  assert.equal(counts.get(refs[0]!), 1);
  assert.equal(counts.get(refs[19]!), 1, 'the original project exceeds the previous 16 MiB reuse capacity');
  assert.equal(counts.get(refs.at(-1)!), 2);
});

test('a cached JSON read preserves its caller cancellation and CAS identity', async t => {
  const first = await files(t), second = await files(t);
  const { ref } = await first.artifacts.publishCanonical({ value: 'owned' }, 'inert-cache-data');
  const abort = new AbortController(), reason = new Error('original reader closed');
  await withArtifactReadCache(async () => {
    await first.artifacts.readCanonical(ref);
    const interrupted = new AbortController(), interruption = new Error('cached read cancelled during its yield');
    const pending = first.artifacts.withReadSignal(interrupted.signal).readCanonical(ref);
    interrupted.abort(interruption);
    await assert.rejects(pending, error => error === interruption);
    abort.abort(reason);
    await assert.rejects(first.artifacts.withReadSignal(abort.signal).readCanonical(ref), error => error === reason);
    await assert.rejects(second.artifacts.readCanonical(ref), { code: 'ENOENT' });
    assert.deepEqual(await first.artifacts.readCanonical(ref), { value: 'owned' });
  });
});

test('a closed traversal cannot lend its cache to a deferred reader', async t => {
  const { artifacts } = await files(t);
  const { ref } = await artifacts.publishCanonical({ value: 'original' }, 'inert-cache-data');
  let release!: () => void, later!: Promise<unknown>;
  const gate = new Promise<void>(resolve => { release = resolve; });
  await withArtifactReadCache(async () => {
    await artifacts.readCanonical(ref);
    later = (async () => { await gate; return artifacts.readCanonical(ref); })();
  });
  release();
  await assert.rejects(later, { code: 'RECOVERY_REQUIRED' });
  assert.deepEqual(await artifacts.readCanonical(ref), { value: 'original' });
});

test('recovery verification retains bounded binary bytes, hashes each use and keeps later readers fresh', async t => {
  const { root, cas, artifacts } = await files(t);
  const bytes = Buffer.from([0xff, 0, 1, 2]);
  const { ref } = await artifacts.publishBytes(bytes, 'application/octet-stream', 'inert-binary-data');
  const verify = cas.verify.bind(cas);
  let verifications = 0, returned: Buffer | undefined;
  t.mock.method(cas, 'verify', async (...args: Parameters<typeof cas.verify>) => {
    verifications++;
    const result = await verify(...args); returned = result.bytes; return result;
  });
  await withArtifactReadCache(async () => {
    await artifacts.verifyBytes(ref);
    assert.deepEqual(returned, bytes);
    returned!.fill(0);
    await artifacts.verifyBytes(ref);
    assert.equal(verifications, 1, 'the immutable copy must be independent of the verifier result buffer');
    await assert.rejects(artifacts.readCanonical(ref), { code: 'ARTIFACT_MISMATCH' });
    const abort = new AbortController(), reason = new Error('original verification cancelled');
    const pending = artifacts.withReadSignal(abort.signal).verifyBytes(ref);
    abort.abort(reason); await assert.rejects(pending, error => error === reason);
  });
  await artifacts.verifyBytes(ref);
  assert.equal(verifications, 2, 'verification outside the projection must read the real object');
  assert.equal(returned, undefined, 'ordinary discard verification retains no result buffer');
  await chmod(path.join(root, ref), 0o600); await writeFile(path.join(root, ref), Buffer.from([0xfe, 0, 1, 2]));
  await chmod(path.join(root, ref), 0o400);
  await assert.rejects(withArtifactReadCache(() => artifacts.verifyBytes(ref)), /corrupt/u);
});

for (const mode of ['existence', 'exact-size'] as const) test(`a failed original ${mode} verification close cannot populate the recovery byte cache`, async t => {
  const { root, artifacts } = await files(t);
  const { ref } = await artifacts.publishBytes(Buffer.from('original'), 'application/octet-stream', 'inert-binary-data');
  const open = fs.open.bind(fs), failure = new Error('original descriptor close failed');
  let opened = 0, closed = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args);
    if (args[0] === path.join(root, ref)) {
      opened++;
      const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => {
        await close(); closed++;
        if (closed === 1) throw failure;
      });
    }
    return handle;
  });
  const verify = () => mode === 'existence' ? artifacts.verifyBytes(ref) : artifacts.verifyChunks(ref, Buffer.byteLength('original'));
  await withArtifactReadCache(async () => {
    await assert.rejects(verify(), error => error instanceof ResourceRetirementError && error.cause === failure);
    await verify();
    assert.equal(opened, 2, 'failed retirement must force a new complete actual read');
    assert.equal(closed, opened);
    await verify(); assert.equal(opened, 2);
  });
});

test('exact-size discard reuse preserves full byte count, cancellation and fresh traversal integrity', async t => {
  const { root, artifacts } = await files(t);
  const bytes = Buffer.from([0xff, 0, 1, 2]), file = await artifacts.publishBytes(bytes, 'application/octet-stream', 'inert-discard-data');
  const open = fs.open.bind(fs); let opened = 0, closed = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await open(...args);
    if (args[0] === path.join(root, file.ref)) {
      opened++;
      const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); closed++; });
    }
    return handle;
  });
  await withArtifactReadCache(async () => {
    await assert.rejects(artifacts.verifyChunks(file.ref, -1), TypeError);
    assert.equal(opened, 0);
    await assert.rejects(artifacts.verifyChunks(file.ref, bytes.length - 1), /unexpected byte count/u);
    await artifacts.verifyChunks(file.ref, bytes.length);
    assert.equal(opened, 2); assert.equal(closed, opened);
    await assert.rejects(artifacts.verifyChunks(file.ref, bytes.length + 1), /unexpected byte count/u);
    await artifacts.verifyBytes(file.ref);
    const abort = new AbortController(), reason = new Error('exact-size cached verification cancelled');
    const pending = artifacts.withReadSignal(abort.signal).verifyChunks(file.ref, bytes.length);
    abort.abort(reason); await assert.rejects(pending, error => error === reason);
    await artifacts.verifyChunks(file.ref, bytes.length);
    assert.equal(opened, 2);
  });
  await chmod(path.join(root, file.ref), 0o600); await writeFile(path.join(root, file.ref), Buffer.from([0xfe, 0, 1, 2]));
  await chmod(path.join(root, file.ref), 0o400);
  await assert.rejects(withArtifactReadCache(() => artifacts.verifyChunks(file.ref, bytes.length)), /corrupt/u);
  assert.equal(opened, 3); assert.equal(closed, opened);
});

test('medium dependency bytes reuse one complete joined read and retain fresh later verification', async t => {
  const { root, cas, artifacts } = await files(t);
  const bytes = Buffer.alloc(9 * 1024 * 1024, 0x81);
  const { ref } = await artifacts.publishBytes(bytes, 'application/octet-stream', 'inert-dependency-binary');
  const verify = cas.verify.bind(cas); let physical = 0;
  t.mock.method(cas, 'verify', async (...args: Parameters<typeof cas.verify>) => { physical++; return verify(...args); });
  await withArtifactReadCache(async () => {
    await artifacts.verifyBytes(ref);
    await artifacts.verifyBytes(ref);
    await artifacts.verifyChunks(ref, bytes.length);
    assert.equal(physical, 1, 'the original complete dependency verification is reusable inside this traversal');
    await assert.rejects(artifacts.verifyChunks(ref, bytes.length + 1), /unexpected byte count/u);
    const abort = new AbortController(), reason = new Error('medium cached read cancelled');
    abort.abort(reason);
    await assert.rejects(artifacts.withReadSignal(abort.signal).verifyBytes(ref), error => error === reason);
    assert.equal(physical, 1);
  });
  await withArtifactReadCache(() => artifacts.verifyBytes(ref));
  assert.equal(physical, 2, 'a separate projection still performs a complete fresh physical verification');
  await chmod(path.join(root, ref), 0o600); await writeFile(path.join(root, ref), Buffer.from([0xfe]));
  await chmod(path.join(root, ref), 0o400);
  await assert.rejects(withArtifactReadCache(() => artifacts.verifyBytes(ref)), /corrupt/u);
  assert.equal(physical, 3);
});

test('large verification inputs retain the complete discard path inside a recovery traversal', async t => {
  const { cas, artifacts } = await files(t);
  const { ref } = await artifacts.publishBytes(Buffer.alloc(16 * 1024 * 1024 + 1, 0x81), 'application/octet-stream', 'inert-binary-data');
  const verify = cas.verify.bind(cas);
  let verifications = 0;
  t.mock.method(cas, 'verify', async (...args: Parameters<typeof cas.verify>) => {
    verifications++;
    const result = await verify(...args); assert.equal(result.bytes, undefined); return result;
  });
  await withArtifactReadCache(async () => { await artifacts.verifyBytes(ref); await artifacts.verifyBytes(ref); });
  assert.equal(verifications, 2);
});

test('JSON objects above one MiB retain their accepted size and independent decoding', async t => {
  const { cas, artifacts } = await files(t);
  const value = { text: 'x'.repeat(1024 * 1024) };
  const { ref } = await artifacts.publishCanonical(value, 'inert-large-cache-data');
  const read = cas.read.bind(cas); let reads = 0;
  t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => { reads++; return read(...args); });
  await withArtifactReadCache(async () => {
    assert.deepEqual(await artifacts.readCanonical(ref), value);
    assert.deepEqual(await artifacts.readCanonical(ref), value);
  });
  assert.equal(reads, 1);
});

test('recovery existence checks and decoders share one complete original workspace-object read per traversal', async t => {
  // Real SQLite/CAS with the existing offline fixture. No installed/native
  // execution authority or provider qualification is produced.
  const fixture = await createAgentFixture('recovery-verified-workspace-bytes');
  try {
    const initial = await fixture.store.readRecoveryClosure(fixture.runId);
    const ref = initial.latestCheckpoint.workspaceStateRef;
    const open = fs.open.bind(fs);
    let opened = 0, closed = 0;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args);
      if (String(args[0]).endsWith(path.sep + ref)) {
        opened++;
        const close = handle.close.bind(handle);
        t.mock.method(handle, 'close', async () => { await close(); closed++; });
      }
      return handle;
    });
    const first = await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(first.latestCheckpoint.workspaceStateRef, ref);
    t.diagnostic(`original workspace-object reads ${opened}, joined ${closed}`);
    assert.equal(opened, 1, 'one immutable graph traversal must share fully verified bytes across existence and decoding checks');
    assert.equal(closed, opened);
    await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(opened, 2, 'the next recovery cut must read the actual CAS object again');
    assert.equal(closed, opened);
  } finally { await disposeFixture(fixture); }
});

for (const medium of [false, true]) test(`sealed recovery shares verified ${medium ? 'medium dependency' : 'small file'} bytes with exact-size discard checks`, async t => {
  const clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('recovery-sealed-small-bytes', undefined, { mode: 'accept-edits', tools: ['edit'] });
  try {
    // Existing offline history over real SQLite/CAS. This proves data reads,
    // not native retirement or installed execution.
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const proof = await quiescedToolCheckpoint(fixture, prepared.checkpointId, medium ? 'x'.repeat(9 * 1024 * 1024) : 'small complete file bytes');
    const result = await fixture.store.artifacts.readCanonical<ToolObservationV1>(await observation(fixture, claimed, { changed: true }));
    result.postEffect = proof.checkpoint; result.observationDigest = digestOmitting(result, 'observationDigest');
    const published = await fixture.store.artifacts.publishCanonical(result, result.format);
    await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: prepared.run.revision, observationRef: published.ref });
    const state = await fixture.store.artifacts.readCanonical<WorkspaceStateManifest>(proof.workspaceStateRef);
    const entries = await fixture.store.artifacts.readCanonical<WorkspaceEntryManifest>(state.entriesRef);
    const file = entries.entries[0]!;
    if (file.kind !== 'file') assert.fail('the sealed fixture requires its actual persisted file');
    const open = fs.open.bind(fs); let opened = 0, closed = 0;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args);
      if (String(args[0]).endsWith(path.sep + file.blobRef)) {
        opened++;
        const close = handle.close.bind(handle);
        t.mock.method(handle, 'close', async () => { await close(); closed++; });
      }
      return handle;
    });
    await fixture.store.readRecoveryClosure(fixture.runId);
    t.diagnostic(`sealed ${medium ? 'medium' : 'small'}-file reads ${opened}, joined ${closed}`);
    assert.equal(opened, 1, 'all discard-only sealed-history checks hash the same fully verified byte copy');
    assert.equal(closed, opened);
    await fixture.store.readRecoveryClosure(fixture.runId);
    assert.equal(opened, 2, 'a later recovery projection must start with fresh physical reads');
    assert.equal(closed, opened);
  } finally { await disposeFixture(fixture); }
});
