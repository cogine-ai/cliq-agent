import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../kernel/identity.js';
import type { Checkpoint, FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntryManifest, WorkspaceGenerationIdentityV1, WorkspaceStateManifest } from '../../kernel/types.js';
import { ArtifactCatalog } from '../../state/artifacts.js';
import { ContentAddressedStore } from '../../state/cas.js';
import { loadNativeStateOwner, type BorrowedGenerationForExecution } from '../../state/native-owner.js';
import { borrowRunWorkspaceForExecution, materializeRunWorkspace, type RunWorkspaceGeneration } from './generation.js';
import * as producer from './generation.js';

test('uncertain native generation close is sticky and never retries a reused descriptor or releases the owner lock', async () => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-close-'));
  await chmod(root, 0o700);
  try {
    // Poisoning a native process is intentionally irreversible. Use a real
    // disposable child, not a production fault flag or a fake native factory.
    const source = `
      import assert from 'node:assert/strict';
      import { closeSync, openSync, fstatSync } from 'node:fs';
      import path from 'node:path';
      import { loadNativeStateOwner, borrowGenerationForExecution } from ${JSON.stringify(new URL('../../state/native-owner.ts', import.meta.url).href)};
      const root = process.argv.at(-1);
      const native = await loadNativeStateOwner();
      const held = native.acquireLock(root, true);
      const tree = held.createGenerationTree('native-retirement-fixture', 'a'.repeat(43));
      const borrowed = borrowGenerationForExecution(tree);
      closeSync(borrowed.fd);
      assert.throws(() => borrowed.close(), { code: 'ERR_CLIQ_RESOURCE_RETIREMENT' });
      const replacement = openSync(path.join(root, 'runtime', 'state-owner.lock'), 'r');
      assert.equal(replacement, borrowed.fd, 'the test must exercise actual numeric descriptor reuse');
      assert.throws(() => borrowed.close(), { code: 'ERR_CLIQ_RESOURCE_RETIREMENT' });
      fstatSync(replacement);
      assert.throws(() => tree.close(), { code: 'ERR_CLIQ_RESOURCE_RETIREMENT' });
      fstatSync(replacement);
      assert.throws(() => held.close(), { code: 'RECOVERY_REQUIRED' });
      fstatSync(replacement);
      assert.throws(() => native.acquireLock(root, false), /already held/);
      closeSync(replacement);
    `;
    execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source, root], { stdio: 'pipe' });
    const native = await loadNativeStateOwner(), successor = native.acquireLock(root, false);
    successor.assertHeld(); successor.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

async function symlinkCheckpoint(artifacts: ArtifactCatalog, manifest: WorkspaceEntryManifest): Promise<Checkpoint> {
  const entriesRef = (await artifacts.publishCanonical(manifest, manifest.format)).ref;
  const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1',
    sources: [], rules: [], rulesDigest: '' };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
  const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: rulesRef,
    frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [], maxChangedPaths: 1000,
    maxChangedBytes: 1024 * 1024, projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionRef = (await artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
  const base: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base', workspaceIdentityDigest: entriesRef,
    entriesRef, sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
    frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: manifest.treeDigest, manifestDigest: '' };
  base.manifestDigest = digestOmitting(base, 'manifestDigest');
  const state: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: 'symlink-run',
    baseWorkspaceManifestRef: (await artifacts.publishCanonical(base, base.format)).ref, entriesRef,
    invalidatedEphemeralPaths: [], sourceProjectionDigest: projection.projectionDigest, stateDigest: '' };
  state.stateDigest = digestOmitting(state, 'stateDigest');
  return { schemaVersion: 1, id: 'symlink-checkpoint', runId: state.runId, basedOnRunRevision: 0, runItemSeq: 0,
    contextManifestRef: entriesRef, journalSeq: 0, createdAt: '2026-10-08T00:00:00.000Z', reason: 'initial',
    workspaceStateRef: (await artifacts.publishCanonical(state, state.format)).ref };
}

test('a registered materialization owner separates real birth from ready private execution', async (t) => {
  const create = Reflect.get(producer, 'createRunWorkspaceMaterialization');
  assert.equal(typeof create, 'function', 'real materialization requires its synchronous resource owner');
  const readBirth = Reflect.get(producer, 'readRunWorkspaceBirth');
  assert.equal(typeof readBirth, 'function');
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-birth-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let materialization: { close(): Promise<void> } | undefined;
  t.after(async () => { await materialization?.close(); held.close(); await rm(root, { recursive: true, force: true }); });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const bytes = Buffer.from('frozen private payload');
  const blob = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [{ path: 'payload', kind: 'file', mode: 0o644, size: bytes.length, blobRef: blob.ref }],
    entryCount: 1, byteCount: bytes.length, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  const generationCreationNonceDigest = sha256Bytes(Buffer.from('owned fixed generation intent'));
  const before = readdirSync(root).sort();
  const preparing = create({ filesystem: held, artifacts, checkpoint, generationCreationNonceDigest });
  materialization = preparing;
  assert.equal(typeof Reflect.get(preparing, 'then'), 'undefined', 'the owner must be registerable before its asynchronous work');
  await assert.rejects(preparing.finish(), /actual completed birth/u);
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.deepEqual(readdirSync(root).sort(), before);
  const beforeBirth = Date.now(), birth = await preparing.birth(), afterBirth = Date.now();
  const observed = readBirth(held, birth);
  assert.equal(observed.creationNonceDigest, generationCreationNonceDigest);
  assert.equal(observed.runId, checkpoint.runId); assert.equal(observed.sourceCheckpointId, checkpoint.id);
  assert.equal(observed.sourceWorkspaceStateRef, checkpoint.workspaceStateRef);
  const directory = path.join(root, 'runs', checkpoint.runId, 'generations', observed.generationId);
  const actual = await lstat(directory, { bigint: true });
  assert.equal(observed.directoryIdentity.deviceId, actual.dev.toString());
  assert.equal(observed.directoryIdentity.fileId, actual.ino.toString());
  assert.equal(observed.directoryIdentity.ownerUid, Number(actual.uid));
  assert(Date.parse(observed.createdAt) >= beforeBirth && Date.parse(observed.createdAt) <= afterBirth);
  assert.equal(new Date(observed.createdAt).toISOString(), observed.createdAt);
  assert.deepEqual(await readdir(directory), [], 'birth must precede every payload write');
  assert.throws(() => Reflect.apply(borrowRunWorkspaceForExecution, undefined, [preparing]), /invalid Run workspace generation/);
  assert.throws(() => Reflect.apply(borrowRunWorkspaceForExecution, undefined, [birth]), /invalid Run workspace generation/);
  assert.equal(await preparing.birth(), birth, 'birth must retain one actual tree, not allocate a replacement');
  assert.equal(typeof preparing.finish, 'function', 'only a complete materialization can become a RunWorkspace');
  const generation = await preparing.finish();
  assert.equal(generation.generationId, observed.generationId);
  assert.equal(await preparing.finish(), generation, 'completion must not copy a second physical tree');
  assert.equal((await generation.observe()).workspaceStateRef, checkpoint.workspaceStateRef);
  assert.deepEqual(await readFile(path.join(directory, 'payload')), bytes);
  const borrowed = borrowRunWorkspaceForExecution(generation);
  t.after(() => borrowed.close()); borrowed.assertHeld();
  assert.equal(borrowed.identity.fileId, observed.directoryIdentity.fileId);
  if (process.platform === 'linux') {
    const authority = await generation.publishMaterializedAuthority();
    const identity = await artifacts.readCanonical<WorkspaceGenerationIdentityV1>(authority.generationRef);
    assert.equal(identity.createdAt, observed.createdAt); assert.equal(identity.creationNonceDigest, generationCreationNonceDigest);
  } else await assert.rejects(generation.publishMaterializedAuthority(), { code: 'UNSUPPORTED_PLATFORM' });
  await preparing.close();
  assert.throws(() => borrowed.assertHeld(), /closed|changed/);
});

test('closing actual materialization joins its partial writer before a fresh native retirement observation', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-owner-close-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let materialization: { close(): Promise<void> } | undefined, watcher: NodeJS.Immediate | undefined;
  t.after(async () => {
    if (watcher) clearImmediate(watcher);
    await materialization?.close(); held.close(); await rm(root, { recursive: true, force: true });
  });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const bytes = Buffer.alloc(1024 * 1024, 0x72);
  const blob = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
  const last = await artifacts.publishBytes(Buffer.from('last'), 'application/octet-stream', 'cliq-workspace-file-v1');
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [
    { path: 'stream.bin', kind: 'file', mode: 0o644, size: bytes.length, blobRef: blob.ref },
    { path: 'z-last', kind: 'file', mode: 0o644, size: 4, blobRef: last.ref }
  ], entryCount: 2, byteCount: bytes.length + 4, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  const preparing = producer.createRunWorkspaceMaterialization({ filesystem: held, artifacts, checkpoint });
  materialization = preparing;
  const birth = await preparing.birth(), data = producer.readRunWorkspaceBirth(held, birth);
  const directory = path.join(root, 'runs', checkpoint.runId, 'generations', data.generationId);
  let joined: Promise<void> | undefined, interruptedSize: number | undefined, observationFailure: unknown;
  const observeWrite = () => {
    try {
      const size = statSync(path.join(directory, 'stream.bin')).size;
      if (size > 0 && size < bytes.length) {
        interruptedSize = size; joined = preparing.close(); void joined.catch(() => {}); return;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        observationFailure = error; joined = preparing.close(); void joined.catch(() => {}); return;
      }
    }
    watcher = setImmediate(observeWrite);
  };
  watcher = setImmediate(observeWrite);
  await assert.rejects(preparing.finish(), { code: 'LEASE_FENCED' });
  assert.equal(observationFailure, undefined);
  assert(joined && interruptedSize, 'close must interrupt a real partial native file writer');
  await joined;
  assert.equal((await stat(path.join(directory, 'stream.bin'))).size, interruptedSize);
  await assert.rejects(stat(path.join(directory, 'z-last')), { code: 'ENOENT' });
  assert(readdirSync(path.join(root, 'objects')).every(name => /^[0-9a-f]{64}$/u.test(name)));
  const readRetirement = Reflect.get(producer, 'readRunWorkspaceBirthRetirement');
  assert.equal(typeof readRetirement, 'function', 'close requires a separate fresh original-native retirement observation');
  const before = Date.now(), first = readRetirement(held, birth), second = readRetirement(held, birth), after = Date.now();
  assert.equal(first.generationId, data.generationId); assert.equal(first.resourcesRetired, true);
  for (const observed of [first, second]) {
    assert(Date.parse(observed.observedAt) >= before && Date.parse(observed.observedAt) <= after);
    assert.equal(new Date(observed.observedAt).toISOString(), observed.observedAt);
  }
  assert(second.observedAt >= first.observedAt);
  assert.throws(() => producer.readRunWorkspaceBirth(held, birth), /closed|changed/);
  held.close();
  const successor = (await loadNativeStateOwner()).acquireLock(root, false);
  try {
    assert.throws(() => producer.readRunWorkspaceBirth(successor, birth), { code: 'ARTIFACT_MISMATCH' });
    assert.throws(() => producer.readRunWorkspaceBirthRetirement(successor, birth), { code: 'ARTIFACT_MISMATCH' });
  } finally { successor.close(); }
});

test('a materialization close joins its minted workspace snapshot and CAS cleanup before reporting retirement', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-owner-snapshot-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let materialization: producer.RunWorkspaceMaterialization | undefined, watcher: NodeJS.Immediate | undefined;
  t.after(async () => {
    if (watcher) clearImmediate(watcher);
    await materialization?.close(); held.close(); await rm(root, { recursive: true, force: true });
  });
  const objects = path.join(root, 'objects'); await mkdir(objects, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(objects));
  const bytes = Buffer.alloc(1024 * 1024, 0x74);
  const blob = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [{ path: 'stream.bin', kind: 'file', mode: 0o644, size: bytes.length, blobRef: blob.ref }],
    entryCount: 1, byteCount: bytes.length, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  materialization = producer.createRunWorkspaceMaterialization({ filesystem: held, artifacts, checkpoint });
  const preparing = materialization, birth = await preparing.birth(), generation = await preparing.finish();
  assert.throws(() => producer.readRunWorkspaceBirthRetirement(held, birth), { code: 'RECOVERY_REQUIRED' });
  let joined: Promise<void> | undefined, interruptedTemporary: string | undefined, temporaryAfterJoin: boolean | undefined;
  let observationFailure: unknown;
  const observePublication = () => {
    try {
      for (const name of readdirSync(objects)) {
        if (!name.startsWith('.tmp-stream-')) continue;
        const size = statSync(path.join(objects, name)).size;
        if (size > 0 && size < bytes.length) {
          interruptedTemporary = name;
          joined = preparing.close().then(() => { temporaryAfterJoin = readdirSync(objects).includes(name); });
          void joined.catch(() => {}); return;
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        observationFailure = error; joined = preparing.close(); void joined.catch(() => {}); return;
      }
    }
    watcher = setImmediate(observePublication);
  };
  watcher = setImmediate(observePublication);
  await assert.rejects(generation.observe(), { code: 'LEASE_FENCED' });
  assert.equal(observationFailure, undefined);
  assert(joined && interruptedTemporary, 'close must interrupt an actual native snapshot/CAS publication');
  await joined;
  assert.equal(temporaryAfterJoin, false, 'owner close must join CAS cleanup, not just synchronously close the native cursor');
  await assert.rejects(stat(path.join(objects, interruptedTemporary)), { code: 'ENOENT' });
  assert.equal(producer.readRunWorkspaceBirthRetirement(held, birth).resourcesRetired, true);
  await assert.rejects(generation.observe({ signal: new AbortController().signal }), { code: 'LEASE_FENCED' });
});

test('a fixed materialization intent rejects invalid nonces and never adopts an existing real generation', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-fixed-intent-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  const materializations: producer.RunWorkspaceMaterialization[] = [];
  t.after(async () => {
    for (const materialization of materializations) await materialization.close();
    held.close(); await rm(root, { recursive: true, force: true });
  });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [], entryCount: 0, byteCount: 0, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries), before = readdirSync(root).sort();
  for (const generationCreationNonceDigest of [null, '', 'A'.repeat(64), 'a'.repeat(63), '../escape', 42]) {
    assert.throws(() => Reflect.apply(producer.createRunWorkspaceMaterialization, undefined,
      [{ filesystem: held, artifacts, checkpoint, generationCreationNonceDigest }]), TypeError);
  }
  assert.deepEqual(readdirSync(root).sort(), before);
  const input = { filesystem: held, artifacts, checkpoint, generationCreationNonceDigest: sha256Bytes(Buffer.from('one fixed materialization intent')) };
  const original = producer.createRunWorkspaceMaterialization(input); materializations.push(original);
  const birth = await original.birth(), observed = producer.readRunWorkspaceBirth(held, birth);
  const duplicate = producer.createRunWorkspaceMaterialization(input); materializations.push(duplicate);
  await assert.rejects(duplicate.birth(), /absent.*locator|overwrite|adoption/u);
  assert.deepEqual(producer.readRunWorkspaceBirth(held, birth), observed);
});

test('external cancellation preserves actual birth for registration but forbids payload copying', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-birth-abort-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let materialization: producer.RunWorkspaceMaterialization | undefined;
  t.after(async () => { await materialization?.close(); held.close(); await rm(root, { recursive: true, force: true }); });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [{ path: 'must-not-copy', kind: 'directory', mode: 0o755 }], entryCount: 1, byteCount: 0, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries), cancellation = new AbortController();
  const reason = new Error('stop after the real directory birth, before copying');
  materialization = producer.createRunWorkspaceMaterialization({ filesystem: held, artifacts, checkpoint, signal: cancellation.signal });
  const birth = await materialization.birth(), original = producer.readRunWorkspaceBirth(held, birth);
  cancellation.abort(reason);
  assert.equal(await materialization.birth(), birth);
  assert.deepEqual(producer.readRunWorkspaceBirth(held, birth), original, 'abort must not discard the physical fact before its concrete binding');
  await assert.rejects(materialization.finish(), error => error === reason);
  assert.deepEqual(await readdir(path.join(root, 'runs', checkpoint.runId, 'generations', original.generationId)), []);
  await materialization.close();
  assert.equal(producer.readRunWorkspaceBirthRetirement(held, birth).resourcesRetired, true);
});

test('cancelling a real streaming materialization closes its scope before rejecting', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-cancel-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  let watcher: NodeJS.Immediate | undefined;
  t.after(async () => {
    if (watcher) clearImmediate(watcher);
    generation?.close(); held.close(); await rm(root, { recursive: true, force: true });
  });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const bytes = Buffer.alloc(1024 * 1024, 0x71);
  const blob = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
  const last = await artifacts.publishBytes(Buffer.from('last'), 'application/octet-stream', 'cliq-workspace-file-v1');
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [
    { path: 'stream.bin', kind: 'file', mode: 0o644, size: bytes.length, blobRef: blob.ref },
    { path: 'z-last', kind: 'file', mode: 0o644, size: 4, blobRef: last.ref }
  ], entryCount: 2, byteCount: bytes.length + 4, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  const cancellation = new AbortController(), reason = new Error('stop the actual private stream');
  let interruptedPath: string | undefined;
  // Observe the actual file, not an internal collaborator or fabricated task
  // receipt. Abort only after a real chunk has reached the private generation.
  const observeWrite = () => {
    try {
      const parent = path.join(root, 'runs', checkpoint.runId, 'generations');
      for (const id of readdirSync(parent)) {
        const current = path.join(parent, id, 'stream.bin');
        const size = statSync(current).size;
        if (size > 0 && size < bytes.length) {
          interruptedPath = current; cancellation.abort(reason); return;
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { cancellation.abort(error); return; }
    }
    watcher = setImmediate(observeWrite);
  };
  watcher = setImmediate(observeWrite);
  try {
    await assert.rejects(materializeRunWorkspace({ filesystem: held, artifacts, checkpoint, signal: cancellation.signal })
      .then(value => { generation = value; return value; }), error => error === reason);
  } finally { if (watcher) clearImmediate(watcher); watcher = undefined; }
  assert.ok(interruptedPath, 'cancellation must occur during actual private file writes');
  const partial = await stat(interruptedPath);
  assert.ok(partial.size > 0 && partial.size < bytes.length, 'rejection must stop further materialization');
  await assert.rejects(stat(path.join(path.dirname(interruptedPath), 'z-last')), { code: 'ENOENT' });
  assert.ok(readdirSync(path.join(root, 'objects')).every(name => /^[0-9a-f]{64}$/.test(name)), 'CAS cleanup is joined');
  held.assertHeld();
  generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint });
  assert.equal((await generation.observe()).workspaceStateRef, checkpoint.workspaceStateRef);
});

test('cancelling a real snapshot joins CAS temporary cleanup and leaves its generation usable', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-observe-cancel-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  let watcher: NodeJS.Immediate | undefined;
  t.after(async () => {
    if (watcher) clearImmediate(watcher);
    generation?.close(); held.close(); await rm(root, { recursive: true, force: true });
  });
  const objects = path.join(root, 'objects');
  await mkdir(objects, { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(objects));
  const bytes = Buffer.alloc(1024 * 1024, 0x73);
  const blob = await artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-workspace-file-v1');
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [
    { path: 'stream.bin', kind: 'file', mode: 0o644, size: bytes.length, blobRef: blob.ref }
  ], entryCount: 1, byteCount: bytes.length, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint });
  const cancellation = new AbortController(), reason = new Error('stop the actual snapshot stream');
  let interruptedTemporary: string | undefined;
  const observePublication = () => {
    try {
      for (const name of readdirSync(objects)) {
        if (!name.startsWith('.tmp-stream-')) continue;
        const size = statSync(path.join(objects, name)).size;
        if (size > 0 && size < bytes.length) {
          interruptedTemporary = name; cancellation.abort(reason); return;
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { cancellation.abort(error); return; }
    }
    watcher = setImmediate(observePublication);
  };
  watcher = setImmediate(observePublication);
  try { await assert.rejects(generation.observe({ signal: cancellation.signal }), error => error === reason); }
  finally { if (watcher) clearImmediate(watcher); watcher = undefined; }
  assert.ok(interruptedTemporary, 'abort must occur while real native snapshot chunks are being published');
  await assert.rejects(stat(path.join(objects, interruptedTemporary)), { code: 'ENOENT' });
  assert.ok(readdirSync(objects).every(name => /^[0-9a-f]{64}$/.test(name)), 'rejection waits for exact CAS temporary cleanup');
  assert.equal((await generation.observe()).workspaceStateRef, checkpoint.workspaceStateRef);
});

test('a minted private generation cannot bypass its factory cancellation with another signal', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-lifetime-cancel-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  t.after(async () => { generation?.close(); held.close(); await rm(root, { recursive: true, force: true }); });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [{ path: 'empty', kind: 'directory', mode: 0o755 }], entryCount: 1, byteCount: 0, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  const cancellation = new AbortController(), reason = new Error('the factory task was cancelled');
  generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint, signal: cancellation.signal });
  cancellation.abort(reason);
  const freshSignal = new AbortController().signal;
  await assert.rejects(generation.observe({ signal: freshSignal }), error => error === reason);
  await assert.rejects(generation.publishMaterializedAuthority({ signal: freshSignal }), error => error === reason);
});

test('directory-only materialization yields between real entries for cancellation', async (t) => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), '.cliq-generation-entry-cancel-'));
  await chmod(root, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  let watcher: NodeJS.Immediate | undefined;
  t.after(async () => {
    if (watcher) clearImmediate(watcher);
    generation?.close(); held.close(); await rm(root, { recursive: true, force: true });
  });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: Array.from({ length: 128 }, (_, index) => ({ path: `d${String(index).padStart(3, '0')}`, kind: 'directory', mode: 0o755 })),
    entryCount: 128, byteCount: 0, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  const cancellation = new AbortController(), reason = new Error('stop between actual directory entries');
  let interruptedPath: string | undefined;
  const observeEntries = () => {
    try {
      const parent = path.join(root, 'runs', checkpoint.runId, 'generations');
      for (const id of readdirSync(parent)) {
        const current = path.join(parent, id), count = readdirSync(current).length;
        if (count > 0 && count < entries.entryCount) {
          interruptedPath = current; cancellation.abort(reason); return;
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { cancellation.abort(error); return; }
    }
    watcher = setImmediate(observeEntries);
  };
  watcher = setImmediate(observeEntries);
  try {
    await assert.rejects(materializeRunWorkspace({ filesystem: held, artifacts, checkpoint, signal: cancellation.signal })
      .then(value => { generation = value; return value; }), error => error === reason);
  } finally { if (watcher) clearImmediate(watcher); watcher = undefined; }
  assert.ok(interruptedPath, 'abort must occur after real directory creation, before the complete tree exists');
  assert.ok(readdirSync(interruptedPath).length < entries.entryCount);
  held.assertHeld();
});

test('a real non-Git checkpoint materializes independent private bytes and empty directories', async (t) => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-generation-'));
  await chmod(root, 0o700);
  const source = await mkdtemp(path.join(process.cwd(), '.cliq-generation-source-'));
  await chmod(source, 0o700);
  const native = await loadNativeStateOwner();
  const held = native.acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  let borrowed: BorrowedGenerationForExecution | undefined;
  t.after(async () => {
    borrowed?.close(); generation?.close(); held.close();
    await rm(root, { recursive: true, force: true }); await rm(source, { recursive: true, force: true });
  });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  await mkdir(path.join(source, 'src'), { mode: 0o755 });
  await writeFile(path.join(source, 'src/main'), Buffer.from([0, 1, 2, 255]), { mode: 0o755 });
  await symlink('src/main', path.join(source, 'link'));
  const target = await readlink(path.join(source, 'link'));
  const blob = await artifacts.publishBytes(await readFile(path.join(source, 'src/main')), 'application/octet-stream', 'cliq-workspace-file-v1');
  const entries: WorkspaceEntryManifest = {
    schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [{ path: 'empty', kind: 'directory', mode: 0o755 },
      { path: 'link', kind: 'symlink', mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) },
      { path: 'src', kind: 'directory', mode: 0o755 },
      { path: 'src/main', kind: 'file', mode: 0o755, size: 4, blobRef: blob.ref }],
    entryCount: 4, byteCount: 4 + Buffer.byteLength(target), treeDigest: ''
  };
  // The source graph contains actual captured bytes; snapshot evidence is never fabricated.
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const entriesRef = (await artifacts.publishCanonical(entries, entries.format)).ref;
  const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1',
    sources: [], rules: [], rulesDigest: '' };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
  const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
    frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [],
    maxChangedPaths: 1000, maxChangedBytes: 1024 * 1024, projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionRef = (await artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
  const base: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base',
    workspaceIdentityDigest: blob.ref, entriesRef, sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
    frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: entries.treeDigest, manifestDigest: '' };
  base.manifestDigest = digestOmitting(base, 'manifestDigest');
  const baseRef = (await artifacts.publishCanonical(base, base.format)).ref;
  const state: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: 'real-run',
    baseWorkspaceManifestRef: baseRef, entriesRef, invalidatedEphemeralPaths: [], sourceProjectionDigest: projection.projectionDigest, stateDigest: '' };
  state.stateDigest = digestOmitting(state, 'stateDigest');
  const checkpoint: Checkpoint = { schemaVersion: 1, id: 'ready-checkpoint', runId: state.runId, basedOnRunRevision: 0,
    runItemSeq: 0, contextManifestRef: blob.ref, journalSeq: 0,
    workspaceStateRef: (await artifacts.publishCanonical(state, state.format)).ref,
    createdAt: '2026-10-08T00:00:00.000Z', reason: 'initial' };
  await writeFile(path.join(source, 'src/main'), 'later live-source bytes');

  generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint });
  const generationPath = path.join(root, 'runs', checkpoint.runId, 'generations', generation.generationId);
  assert.deepEqual(await readFile(path.join(generationPath, 'src/main')), Buffer.from([0, 1, 2, 255]));
  assert.equal((await lstat(generationPath)).mode & 0o7777, 0o700);
  assert.equal((await lstat(path.join(generationPath, 'src/main'))).mode & 0o7777, 0o755);
  assert.equal((await lstat(path.join(generationPath, 'src/main'))).nlink, 1);
  assert.notEqual((await lstat(path.join(generationPath, 'src/main'))).ino, (await lstat(path.join(source, 'src/main'))).ino);
  assert.ok((await lstat(path.join(generationPath, 'empty'))).isDirectory());
  assert.equal(await readlink(path.join(generationPath, 'link')), target);
  assert.deepEqual(await readFile(path.join(generationPath, 'link')), Buffer.from([0, 1, 2, 255]));
  const observation = await generation.observe();
  assert.equal(observation.treeDigest, entries.treeDigest);
  assert.equal(observation.descriptorRewalkComplete, true);
  assert.equal(observation.fileFsyncComplete, true);
  assert.equal(observation.directoryFsyncComplete, true);
  assert.equal(observation.entriesRef, entriesRef);
  borrowed = borrowRunWorkspaceForExecution(generation);
  assert.equal(borrowed.identity.fileId, String((await lstat(generationPath)).ino));
  borrowed.assertHeld();
  generation.close();
  assert.throws(() => borrowed.assertHeld(), /closed|changed/);
  borrowed.close();
});

test('frozen symlink chains cannot resolve outside the private generation', async (t) => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-generation-links-'));
  const source = await mkdtemp(path.join(process.cwd(), '.cliq-generation-links-source-'));
  await chmod(root, 0o700); await chmod(source, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  t.after(async () => {
    generation?.close(); held.close();
    await rm(root, { recursive: true, force: true }); await rm(source, { recursive: true, force: true });
  });
  await mkdir(path.join(source, 'a'), { mode: 0o755 });
  await symlink('..', path.join(source, 'a/link'));
  await symlink('a/link/..', path.join(source, 'outerlink'));
  assert.equal(await realpath(path.join(source, 'outerlink')), path.dirname(source));
  const first = await readlink(path.join(source, 'a/link'));
  const outer = await readlink(path.join(source, 'outerlink'));
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [
    { path: 'a', kind: 'directory', mode: 0o755 },
    { path: 'a/link', kind: 'symlink', mode: 0o777, target: first, targetDigest: sha256Bytes(Buffer.from(first)) },
    { path: 'outerlink', kind: 'symlink', mode: 0o777, target: outer, targetDigest: sha256Bytes(Buffer.from(outer)) }
  ], entryCount: 3, byteCount: Buffer.byteLength(first) + Buffer.byteLength(outer), treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  await assert.rejects(async () => { generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint }); },
    (error: unknown) => error instanceof Error && /symlink.*escapes/.test(error.message));
});

test('in-root chained and dangling symlinks preserve exact frozen link text', async (t) => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-generation-safe-links-'));
  const source = await mkdtemp(path.join(process.cwd(), '.cliq-generation-safe-links-source-'));
  await chmod(root, 0o700); await chmod(source, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  t.after(async () => {
    generation?.close(); held.close();
    await rm(root, { recursive: true, force: true }); await rm(source, { recursive: true, force: true });
  });
  await mkdir(path.join(source, 'a'), { mode: 0o755 });
  await symlink('..', path.join(source, 'a/root'));
  await symlink('a/missing', path.join(source, 'dangling'));
  await symlink('a/root/a', path.join(source, 'internal'));
  assert.equal(await realpath(path.join(source, 'internal')), path.join(source, 'a'));
  await assert.rejects(realpath(path.join(source, 'dangling')), { code: 'ENOENT' });
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [{ path: 'a', kind: 'directory', mode: 0o755 }], entryCount: 4, byteCount: 0, treeDigest: '' };
  for (const name of ['a/root', 'dangling', 'internal']) {
    const target = await readlink(path.join(source, name));
    entries.entries.push({ path: name, kind: 'symlink', mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) });
    entries.byteCount += Buffer.byteLength(target);
  }
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint });
  const privateRoot = path.join(root, 'runs', checkpoint.runId, 'generations', generation.generationId);
  assert.equal(await realpath(path.join(privateRoot, 'internal')), path.join(privateRoot, 'a'));
  assert.equal(await readlink(path.join(privateRoot, 'dangling')), 'a/missing');
  await assert.rejects(realpath(path.join(privateRoot, 'dangling')), { code: 'ENOENT' });
  assert.equal((await generation.observe()).workspaceStateRef, checkpoint.workspaceStateRef);
});

test('unresolvable cycles and non-directory symlink traversal fail closed', async (t) => {
  for (const kind of ['cycle', 'non-directory'] as const) {
    const root = await mkdtemp(path.join(process.cwd(), '.cliq-generation-invalid-links-'));
    const source = await mkdtemp(path.join(process.cwd(), '.cliq-generation-invalid-links-source-'));
    await chmod(root, 0o700); await chmod(source, 0o700);
    const held = (await loadNativeStateOwner()).acquireLock(root, true);
    let generation: RunWorkspaceGeneration | undefined;
    t.after(async () => {
      generation?.close(); held.close();
      await rm(root, { recursive: true, force: true }); await rm(source, { recursive: true, force: true });
    });
    await mkdir(path.join(root, 'objects'), { mode: 0o700 });
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
    const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [],
      entryCount: 2, byteCount: 0, treeDigest: '' };
    if (kind === 'cycle') {
      await symlink('second', path.join(source, 'first')); await symlink('first', path.join(source, 'second'));
      await assert.rejects(realpath(path.join(source, 'first')), { code: 'ELOOP' });
      for (const name of ['first', 'second']) {
        const target = await readlink(path.join(source, name));
        entries.entries.push({ path: name, kind: 'symlink', mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) });
        entries.byteCount += Buffer.byteLength(target);
      }
    } else {
      await writeFile(path.join(source, 'file'), 'x'); await symlink('file/..', path.join(source, 'link'));
      // Node realpath can lexical-normalize file/..; stat reaches OS lookup.
      await assert.rejects(stat(path.join(source, 'link')), { code: 'ENOTDIR' });
      const blob = await artifacts.publishBytes(await readFile(path.join(source, 'file')), 'application/octet-stream', 'cliq-workspace-file-v1');
      const target = await readlink(path.join(source, 'link'));
      entries.entries.push({ path: 'file', kind: 'file', mode: 0o644, size: 1, blobRef: blob.ref },
        { path: 'link', kind: 'symlink', mode: 0o777, target, targetDigest: sha256Bytes(Buffer.from(target)) });
      entries.byteCount = 1 + Buffer.byteLength(target);
    }
    entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
    const checkpoint = await symlinkCheckpoint(artifacts, entries);
    await assert.rejects(async () => { generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint }); },
      (error: unknown) => error instanceof Error && error.message.includes(kind === 'cycle' ? 'cycle' : 'non-directory'));
  }
});

test('reopening a frozen ready generation preserves identity or rejects the unsupported host', async (t) => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-generation-reopen-'));
  await chmod(root, 0o700);
  const native = await loadNativeStateOwner();
  let held = native.acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  let borrowed: BorrowedGenerationForExecution | undefined;
  t.after(async () => { borrowed?.close(); generation?.close(); held.close(); await rm(root, { recursive: true, force: true }); });
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1',
    entries: [{ path: 'empty', kind: 'directory', mode: 0o755 }], entryCount: 1, byteCount: 0, treeDigest: '' };
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const checkpoint = await symlinkCheckpoint(artifacts, entries);
  generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint });
  const reopen = (producer as typeof producer & { reopenRunWorkspace(input: {
    filesystem: typeof held; artifacts: ArtifactCatalog; checkpoint: Checkpoint; identity: WorkspaceGenerationIdentityV1;
  }): Promise<RunWorkspaceGeneration> }).reopenRunWorkspace;
  assert.equal(typeof reopen, 'function');
  if (process.platform !== 'linux') {
    // A Darwin staging directory is not a fabricated Linux/VM identity.
    await assert.rejects(reopen({ filesystem: held, artifacts, checkpoint, identity: undefined as unknown as WorkspaceGenerationIdentityV1 }),
      { code: 'UNSUPPORTED_PLATFORM' });
    return;
  }
  const authority = await generation.publishMaterializedAuthority();
  const identity = await artifacts.readCanonical<WorkspaceGenerationIdentityV1>(authority.generationRef);
  const id = generation.generationId;
  generation.close(); held.close(); held = native.acquireLock(root, false);
  generation = await reopen({ filesystem: held, artifacts, checkpoint, identity });
  assert.equal(generation.generationId, id);
  borrowed = borrowRunWorkspaceForExecution(generation); borrowed.assertHeld();
  assert.equal(borrowed.identity.fileId, identity.locator.kind === 'linux_directory' ? identity.locator.directoryFileId : 'invalid');
  const published = await generation.publishMaterializedAuthority();
  assert.equal(published.generationRef, authority.generationRef);
  assert.equal(published.generationIdentityDigest, authority.generationIdentityDigest);
  assert.equal((await generation.observe()).workspaceStateRef, checkpoint.workspaceStateRef);
  await assert.rejects(reopen({ filesystem: held, artifacts, checkpoint: { ...checkpoint, id: 'another-checkpoint' }, identity }),
    { code: 'ARTIFACT_MISMATCH' });
  const observation = await producer.observeRetainedRunWorkspace({ filesystem: held, artifacts, identity, sourceRowVersion: 1 });
  const actual = producer.readRetainedWorkspaceObservation(observation);
  assert.equal(actual.generationRef, authority.generationRef);
  assert.deepEqual(actual.observedState, { kind: 'complete_tree', treeDigest: entries.treeDigest });
  assert.throws(() => producer.readRetainedWorkspaceObservation(Object.freeze({}) as typeof observation), /invalid retained/);
  assert.throws(() => producer.readRetainedWorkspaceRetirement(held, observation), { code: 'RECOVERY_REQUIRED' });
  generation.close();
  const retired = producer.readRetainedWorkspaceRetirement(held, observation);
  assert.equal(retired.generationRef, actual.generationRef);
  assert.equal(retired.treeObservedAt, actual.observedAt);
  assert.ok(retired.observedAt >= retired.treeObservedAt);
  assert.throws(() => producer.readRetainedWorkspaceRetirement(held, Object.freeze({}) as typeof observation), /exact StateOwner/);
  generation.close(); held.close();
  assert.throws(() => producer.readRetainedWorkspaceObservation(observation), /closed|held|changed/);
});
