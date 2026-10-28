import assert from 'node:assert/strict';
import { fstatSync, promises as fs } from 'node:fs';
import { chmod, link, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { setImmediate as scheduleImmediate } from 'node:timers';
import { setImmediate } from 'node:timers/promises';
import ts from 'typescript';
import type { FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntryManifest } from '../kernel/types.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import { ArtifactCatalog } from '../state/artifacts.js';
import { ContentAddressedStore } from '../state/cas.js';
import { loadNativeStateOwner } from '../state/native-owner.js';
import { captureFrozenSourceProjection, publishNonGitSourceProjection } from './source-projection.js';
import { decodeDeliveryCaptureTopology, publicationDirectoryIdentityDigest } from '../kernel/publication.js';
import { ResourceRetirementError } from '../state/errors.js';
import { createSourceInspectionErrorResponse } from '../state/source-inspection-error.js';
import { INSTALLED_SOURCE_REFUSAL_NAME, withInstalledSourceRefusalFixture } from '../state/testing/source-refusal-fixture.js';

// Execute only the actual entries reread expression against inert CAS bytes.
// No native source capture, Run, StateOwner or entries authority is created.
async function entriesReread() {
  const source = await readFile(new URL('./source-projection.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('source-projection-read-data.ts', source, ts.ScriptTarget.Latest, true);
  const expressions: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'readCanonical' && node.arguments[0]?.getText(parsed) === 'entriesArtifact.ref') expressions.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(expressions.length, 1);
  const output = ts.transpileModule(`return ${expressions[0]!.getText(parsed)};`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const read = new Function('artifacts', 'reads', 'entriesArtifact', output);
  return (artifacts: ArtifactCatalog, signal: AbortSignal, ref: string) =>
    read(artifacts, artifacts.withReadSignal(signal), { ref }) as Promise<unknown>;
}

for (const fault of ['cancel', 'ordinary', 'retirement'] as const)
  test(`initial source entries reread joins its actual CAS descriptors and preserves ${fault}`, async t => {
    const directory = await mkdtemp(path.join(process.cwd(), '.cliq-source-reread-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const objects = path.join(directory, 'objects'); await mkdir(objects, { mode: 0o700 });
    const cas = new ContentAddressedStore(objects), artifacts = new ArtifactCatalog(cas);
    const { ref } = await artifacts.publishCanonical({ diagnosticOnly: true, value: 'x'.repeat(3 * 1024 * 1024) }, 'cliq-read-join-data-v1');
    const owner = new AbortController(), reason = new Error('the original source reread was cancelled');
    const ordinary = new Error('the original bounded CAS read failed'), closeFailure = new Error('actual CAS root close report is uncertain');
    let enter!: () => void, release!: () => void, reads = 0, opened = 0, closed = 0, settled = false, originalFailure: unknown;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    const active = new Set<object>(), open = fs.open, originalRead = cas.read.bind(cas);
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await open(...args); active.add(handle); opened++;
      const close = handle.close.bind(handle), read = handle.read.bind(handle);
      if (args[0] === path.join(objects, ref)) t.mock.method(handle, 'read', async (...values: Parameters<typeof handle.read>) => {
        const result = await read(...values); reads++;
        if (reads === 1) { if (fault === 'ordinary') throw ordinary; owner.abort(reason); }
        return result;
      });
      t.mock.method(handle, 'close', async () => {
        if (args[0] === objects) { enter(); await gate; }
        await close(); assert.equal(active.delete(handle), true); closed++;
        if (fault === 'retirement' && args[0] === objects) throw closeFailure;
      });
      return handle;
    });
    t.mock.method(cas, 'read', async (...args: Parameters<typeof cas.read>) => {
      try { return await originalRead(...args); } catch (error) { originalFailure = error; throw error; }
    });
    const reread = await entriesReread(), work = reread(artifacts, owner.signal, ref);
    void work.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.race([entered, work.then(() => { throw new Error('the actual root close gate was bypassed'); })]);
      assert.equal(reads, 1, 'the original signal stops after the first real bounded read, not after the whole object');
      assert.equal(opened, 2); assert.equal(closed, 1); assert.equal(active.size, 1); assert.equal(settled, false);
      release();
      await assert.rejects(work, error => error === originalFailure && (fault === 'retirement'
        ? error instanceof ResourceRetirementError && error.cause === closeFailure : error === (fault === 'ordinary' ? ordinary : reason)));
      assert.equal(closed, 2); assert.equal(active.size, 0);
    } finally { release(); await Promise.allSettled([work]); assert.equal(active.size, 0); t.mock.restoreAll(); }
  });

test('initial source reread cancellation leaves capture publications and retirement on the original catalog', async () => {
  const source = await readFile(new URL('./source-projection.ts', import.meta.url), 'utf8');
  const body = source.slice(source.indexOf('async function captureSourceProjection('));
  assert.match(body, /const reads = signal \? artifacts.withReadSignal\(signal\) : artifacts;/u);
  assert.match(body, /decodeWorkspaceEntries\(await reads.readCanonical\(entriesArtifact.ref\)\)/u);
  assert.match(body, /captureWorkspaceEntries\(workspaceRoot, artifacts,/u);
  assert.doesNotMatch(body, /reads.publish|artifacts =/u);
  assert.match(body, /finally \{ retire\(\[\.\.\.cursors, \.\.\.observed.map\(item => item.entry\)\], operationError\); \}/u);
});

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(process.cwd(), '.cliq-source-projection-'));
  const workspace = path.join(directory, 'source'), home = path.join(workspace, 'managed-home'), state = path.join(workspace, 'managed-state');
  await mkdir(workspace, { mode: 0o700 }); await mkdir(home, { mode: 0o700 }); await mkdir(state, { mode: 0o700 });
  const native = await loadNativeStateOwner(), stateOwnerLock = native.acquireLock(state, true);
  const objects = path.join(state, 'objects'); await mkdir(objects, { mode: 0o700 });
  const workspaceRoot = native.openWorkspaceRoot(workspace), controlledHome = native.openWorkspaceRoot(home);
  t.after(async () => {
    workspaceRoot.close(); controlledHome.close(); stateOwnerLock.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { workspace, home, state, native, input: { workspaceRoot, controlledHome, stateOwnerLock,
    artifacts: new ArtifactCatalog(new ContentAddressedStore(objects)), workspaceIdentityDigest: 'a'.repeat(64),
    sourceIncludes: [], sourceExcludes: [] as Array<{ path: string; scope: 'entry' | 'subtree' }>,
    maxChangedPaths: 0, maxChangedBytes: 0, maxEntries: 100_000, maxBytes: 1024 * 1024, maxSingleFileBytes: 512 * 1024 } };
}

async function heldDescriptors(paths: string[]): Promise<string[]> {
  // Read-only OS resource observation, not a native capture/proof stand-in.
  const identities = new Set(await Promise.all(paths.map(async filename => {
    const info = await stat(filename, { bigint: true }); return `${info.dev}:${info.ino}`;
  })));
  const directory = process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd', observed: string[] = [];
  for (const fd of await readdir(directory)) {
    try {
      assert.match(fd, /^(0|[1-9][0-9]*)$/u);
      const number = Number(fd); assert(Number.isSafeInteger(number));
      const info = fstatSync(number, { bigint: true }), identity = `${info.dev}:${info.ino}`;
      if (identities.has(identity)) observed.push(`${fd}:${identity}`);
    } catch (error) {
      // The listing's own descriptor can close before its entry is inspected.
      if (!['ENOENT', 'EBADF'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
    }
  }
  return observed.sort();
}

test('descriptor observation sees actual directory and file identities through their complete close', async t => {
  const { workspace } = await fixture(t), filename = path.join(workspace, 'observed-file');
  await writeFile(filename, 'descriptor observation data');
  const paths = [workspace, filename], before = await heldDescriptors(paths);
  const handles: Awaited<ReturnType<typeof fs.open>>[] = [];
  try {
    handles.push(await fs.open(workspace, 'r')); handles.push(await fs.open(filename, 'r'));
    const expected = await Promise.all(handles.map(async handle => {
      const info = await handle.stat({ bigint: true }); return `${handle.fd}:${info.dev}:${info.ino}`;
    }));
    assert.deepEqual(await heldDescriptors(paths), [...before, ...expected].sort());
  } finally {
    const closed = await Promise.allSettled(handles.map(handle => handle.close()));
    assert(closed.every(result => result.status === 'fulfilled'));
  }
  assert.deepEqual(await heldDescriptors(paths), before);
});

test('initial non-Git entries and projection graph share one real four-object durability group', async t => {
  const { workspace, state, input } = await fixture(t);
  await writeFile(path.join(workspace, 'file.txt'), 'original source bytes', { mode: 0o644 });
  const groups: string[][] = [], publish = input.artifacts.publishCanonicalFour;
  t.mock.method(input.artifacts, 'publishCanonicalFour', async function(this: ArtifactCatalog, values: Parameters<ArtifactCatalog['publishCanonicalFour']>[0]) {
    groups.push(values.map(value => value.schemaKind)); return Reflect.apply(publish, this, [values]);
  });
  let fileSyncs = 0, rootSyncs = 0;
  const originalOpen = fs.open;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args), sync = handle.sync.bind(handle);
    t.mock.method(handle, 'sync', async () => {
      if ((await handle.stat()).isDirectory()) rootSyncs++; else fileSyncs++;
      return sync();
    });
    return handle;
  });
  const result = await publishNonGitSourceProjection(input);
  assert.deepEqual(groups, [['cliq-workspace-entries-v1', 'cliq-frozen-ignore-rules-v1', 'cliq-source-projection-v1', 'cliq-source-manifest-v1']]);
  assert.equal(fileSyncs, 5, 'the raw file and every actual graph member retain their own file sync');
  assert.equal(rootSyncs, 8, 'one raw publication and one natural graph group retain four directory stages each');
  const entries = await input.artifacts.readCanonical<WorkspaceEntryManifest>(result.entriesRef);
  assert.equal(entries.entries.length, 1); assert(entries.entries[0]!.kind === 'file');
  assert.equal((await input.artifacts.readBytes(entries.entries[0]!.blobRef)).toString(), 'original source bytes');
  assert.equal((await input.artifacts.readCanonical<SourceManifest>(result.baseWorkspaceManifestRef)).entriesRef, result.entriesRef);
  assert.equal((await readdir(path.join(state, 'objects'))).filter(name => name.startsWith('.tmp')).length, 0);
});

for (const fault of ['cancel', 'namespace', 'retirement', 'drift'] as const)
  test(`the source four-object scope holds original descriptors and joins ${fault} before refusal`, async t => {
    const { workspace, state, input } = await fixture(t), filename = path.join(workspace, 'file.txt');
    await writeFile(filename, 'original source bytes', { mode: 0o644 });
    const before = await heldDescriptors([workspace, filename]), objects = path.join(state, 'objects');
    const owner = new AbortController(), reason = new Error('original source graph cancelled'), ordinary = new Error('actual group sync fault');
    const retirement = new Error('actual group root close report is uncertain');
    let enter!: () => void, release!: () => void, rootSyncs = 0, rootOpens = 0, completed = false;
    const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    const active = new Set<object>(), originalOpen = fs.open;
    t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args), isRoot = args[0] === objects, ordinal = isRoot ? ++rootOpens : 0;
      active.add(handle); const sync = handle.sync.bind(handle), close = handle.close.bind(handle);
      t.mock.method(handle, 'sync', async () => {
        await sync();
        if (isRoot && ++rootSyncs === 5) { enter(); await gate; if (fault === 'namespace') throw ordinary; }
      });
      t.mock.method(handle, 'close', async () => {
        await close(); assert(active.delete(handle));
        if (fault === 'retirement' && isRoot && ordinal === 2) throw retirement;
      });
      return handle;
    });
    const work = publishNonGitSourceProjection({ ...input, signal: owner.signal });
    void work.then(() => { completed = true; }, () => { completed = true; });
    try {
      await Promise.race([entered, work.then(() => { throw new Error('the actual group sync cut was bypassed'); })]);
      assert.equal(completed, false);
      // The classification and byte-capture inventories each own a directory
      // cursor with an independent readdir offset. Both remain held through
      // the group, without replacing any original descriptor or retaining a
      // file reader. Their real retirement must still restore the exact set.
      const during = await heldDescriptors([workspace, filename]);
      assert.deepEqual(during.filter(descriptor => before.includes(descriptor)), before);
      const cursors = during.filter(descriptor => !before.includes(descriptor));
      const root = await stat(workspace, { bigint: true });
      assert.equal(cursors.length, 2);
      assert(cursors.every(descriptor => descriptor.endsWith(`:${root.dev}:${root.ino}`)));
      input.workspaceRoot.assertHeld(); input.controlledHome.assertHeld();
      if (fault === 'cancel') owner.abort(reason);
      if (fault === 'drift') await writeFile(filename, 'external metadata changed while the group was in flight');
      release();
      await assert.rejects(work, error => fault === 'retirement' ? error instanceof ResourceRetirementError : fault === 'drift'
        ? error instanceof Error && error.message === 'source entry identity changed or closed' : fault === 'namespace'
          ? error instanceof ResourceRetirementError && error.cause === ordinary : error === reason);
      assert.equal(active.size, 0, 'all actual CAS file/root handles must close before refusing capture');
      assert.deepEqual(await heldDescriptors([workspace, filename]), before);
      assert.equal((await readdir(objects)).filter(name => name.startsWith('.tmp')).length, 0);
    } finally { release(); await Promise.allSettled([work]); t.mock.restoreAll(); }
  });

for (const delivery of [false, true]) test(`initial non-Git ${delivery ? 'delivery' : 'Run'} source retains every file sync and its exact natural-group directory barriers`, async t => {
  const { workspace, state, input } = await fixture(t), objects = path.join(state, 'objects');
  await writeFile(path.join(workspace, 'ordinary'), 'Exact source bytes.\n', { mode: 0o644 });
  const open = fs.open.bind(fs), active = new Set<object>(); let rootSyncs = 0, fileSyncs = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
    const handle = await open(...args); active.add(handle);
    const sync = handle.sync.bind(handle), close = handle.close.bind(handle);
    t.mock.method(handle, 'sync', async () => { await sync(); if (args[0] === objects) rootSyncs++; else fileSyncs++; });
    t.mock.method(handle, 'close', async () => { await close(); assert(active.delete(handle)); });
    return handle;
  });
  const captured = await publishNonGitSourceProjection({ ...input, ...(delivery ? { deliveryCapture: {
    inspectionId: identityHash('cliq-source-inspection-v1', 'durability-data', 'run.apply', 'data-key', 'data-intent'),
    workspaceIdentityRef: 'c'.repeat(64), capturedAt: '2026-10-26T00:00:00.000Z'
  } } : {}) });
  assert.equal(fileSyncs, delivery ? 6 : 5, 'raw source, entries and all original metadata files still sync');
  assert.equal(rootSyncs, delivery ? 12 : 8, 'delivery retains its separate topology group; ordinary entries join the natural four-object closure');
  assert.equal(active.size, 0);
  const source = await input.artifacts.readCanonical<SourceManifest>(captured.baseWorkspaceManifestRef);
  const entries = await input.artifacts.readCanonical<WorkspaceEntryManifest>(source.entriesRef);
  assert.equal(source.sourceProjectionRef, captured.sourceProjectionRef);
  assert.equal(source.frozenIgnoreRulesRef, captured.frozenIgnoreRulesRef);
  const file = entries.entries.find(entry => entry.kind === 'file' && entry.path === 'ordinary');
  assert(file?.kind === 'file'); assert.equal((await input.artifacts.readBytes(file.blobRef)).toString(), 'Exact source bytes.\n');
  if (delivery) {
    const topology = decodeDeliveryCaptureTopology(await input.artifacts.readCanonical(captured.captureTopologyRef!));
    assert.equal(topology.capturedWorkspaceRef, captured.baseWorkspaceManifestRef);
  }
  assert.equal(active.size, 0); input.workspaceRoot.assertHeld();
});

test('frozen capture rejects structural native handles before accessing CAS or caller callbacks', async t => {
  const { input } = await fixture(t);
  let accessed = false;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() {
    accessed = true; throw new Error('structural handles must be refused before CAS');
  } }) as ArtifactCatalog;
  for (const key of ['workspaceRoot', 'controlledHome', 'stateOwnerLock'] as const) {
    await assert.rejects(captureFrozenSourceProjection({ ...input, artifacts, [key]: {} as never,
      sourceProjectionRef: 'b'.repeat(64), sourceProjectionDigest: 'c'.repeat(64) }), TypeError);
    assert.equal(accessed, false);
  }
});

test('delivery topology retains the same held capture directories and raw modes without inventing physical generation evidence', async t => {
  const { workspace, input } = await fixture(t);
  await mkdir(path.join(workspace, 'private'), { mode: 0o700 });
  await mkdir(path.join(workspace, 'empty'), { mode: 0o750 });
  await chmod(path.join(workspace, 'empty'), 0o750);
  await mkdir(path.join(workspace, 'pruned'), { mode: 0o700 });
  await writeFile(path.join(workspace, 'private', 'file'), 'captured\n', { mode: 0o600 });
  await writeFile(path.join(workspace, 'pruned', 'file'), 'not selected\n');
  const selected = { ...input, sourceExcludes: [{ path: 'pruned', scope: 'subtree' as const }],
    deliveryCapture: { inspectionId: identityHash('cliq-source-inspection-v1', 'fixture-principal', 'run.apply', 'fixture-key', 'fixture-intent'),
      workspaceIdentityRef: 'b'.repeat(64), capturedAt: '2026-10-18T00:00:00.000Z' } };
  const result = await publishNonGitSourceProjection(selected);
  assert.ok(result.captureTopologyRef);
  const topology = decodeDeliveryCaptureTopology(await input.artifacts.readCanonical(result.captureTopologyRef));
  assert.equal(topology.inspectionId, selected.deliveryCapture.inspectionId);
  assert.equal(topology.capturedWorkspaceRef, result.baseWorkspaceManifestRef);
  assert.equal(topology.workspaceIdentityRef, selected.deliveryCapture.workspaceIdentityRef);
  assert.equal(topology.workspaceIdentityDigest, input.workspaceIdentityDigest);
  assert.equal(topology.capturedAt, selected.deliveryCapture.capturedAt);
  assert.equal(topology.rootIdentity.mode, 0o700);
  assert.deepEqual(topology.directories.map(entry => [entry.path, entry.mode]), [['empty', 0o750], ['private', 0o700]]);
  assert.deepEqual(topology.fileModes, [{ path: 'private/file', mode: 0o600 }]);
  for (const entry of [topology.rootIdentity, ...topology.directories])
    assert.equal(entry.identityDigest, publicationDirectoryIdentityDigest(input.workspaceIdentityDigest, entry));
  const entries = await input.artifacts.readCanonical<WorkspaceEntryManifest>(result.entriesRef);
  assert.deepEqual(entries.entries.filter(entry => entry.kind === 'directory').map(entry => [entry.path, entry.mode]),
    [['empty', 0o755], ['private', 0o755]], 'logical source modes must not replace physical directory observations');
  assert.equal(result.metadata.some(entry => entry.ref === result.captureTopologyRef && entry.schemaKind === topology.format), true);
  const ordinary = await publishNonGitSourceProjection({ ...input, sourceExcludes: selected.sourceExcludes });
  assert.equal(ordinary.baseWorkspaceManifestRef, result.baseWorkspaceManifestRef);
  assert.equal(ordinary.captureTopologyRef, undefined);
});

test('non-Git projection publishes ordinary real bytes and empty directories while pruning exact exclusions and genuine managed roots', async t => {
  const { workspace, home, state, input } = await fixture(t);
  await mkdir(path.join(workspace, 'dir')); await mkdir(path.join(workspace, 'empty'));
  await mkdir(path.join(workspace, 'excluded'));
  await writeFile(path.join(workspace, 'dir', 'a'), 'real bytes\n', { mode: 0o755 });
  await link(path.join(workspace, 'dir', 'a'), path.join(workspace, 'dir', 'b'));
  await writeFile(path.join(workspace, '.env'), 'user-authorized ordinary source');
  await symlink('dir/a', path.join(workspace, 'safe'));
  await writeFile(path.join(workspace, 'excluded', 'unreadable'), 'excluded bytes');
  await writeFile(path.join(home, 'auth.json'), 'managed credentials');
  await writeFile(path.join(state, 'credential'), 'managed state');
  await chmod(path.join(workspace, 'excluded', 'unreadable'), 0);
  await chmod(path.join(home, 'auth.json'), 0); await chmod(path.join(state, 'credential'), 0);
  input.sourceExcludes = [{ path: 'excluded', scope: 'subtree' }];
  const before = await stat(path.join(workspace, 'dir', 'a'));
  const result = await publishNonGitSourceProjection(input);
  const source = await input.artifacts.readCanonical<SourceManifest>(result.baseWorkspaceManifestRef);
  const entries = await input.artifacts.readCanonical<WorkspaceEntryManifest>(source.entriesRef);
  const projection = await input.artifacts.readCanonical<SourceProjectionSpec>(source.sourceProjectionRef);
  const rules = await input.artifacts.readCanonical<FrozenIgnoreRulesV1>(source.frozenIgnoreRulesRef);
  assert.deepEqual(entries.entries.map(entry => [entry.path, entry.kind]), [
    ['.env', 'file'], ['dir', 'directory'], ['dir/a', 'file'], ['dir/b', 'file'], ['empty', 'directory'], ['safe', 'symlink']
  ]);
  assert.equal(entries.byteCount, 58); assert.equal(entries.entryCount, 6);
  assert.equal(source.role, 'base'); assert.equal(source.workspaceIdentityDigest, 'a'.repeat(64)); assert.equal(source.git, undefined);
  assert.equal(source.manifestDigest, result.manifestDigest); assert.equal(source.treeDigest, result.treeDigest);
  assert.equal(source.frozenIgnoreRulesDigest, rules.rulesDigest); assert.equal(source.sourceProjectionDigest, projection.projectionDigest);
  assert.deepEqual(rules.sources, []); assert.deepEqual(rules.rules, []); assert.equal(rules.repositoryIdentityDigest, undefined);
  assert.deepEqual(projection.explicitIncludes, []); assert.deepEqual(projection.explicitExcludes, input.sourceExcludes);
  assert.equal(projection.maxChangedPaths, 0); assert.equal(projection.maxChangedBytes, 0);
  const a = entries.entries.find(entry => entry.path === 'dir/a'); assert.equal(a?.kind, 'file');
  if (a?.kind !== 'file') throw new Error('missing real source file');
  assert.equal(a.mode, 0o755); assert.deepEqual(await input.artifacts.readBytes(a.blobRef), Buffer.from('real bytes\n'));
  assert.equal(result.metadata.some(item => item.ref === sha256Bytes(Buffer.from('managed credentials'))), false);
  assert.equal(await readFile(path.join(workspace, 'dir', 'a'), 'utf8'), 'real bytes\n');
  const after = await stat(path.join(workspace, 'dir', 'a'));
  assert.equal(after.ino, before.ino); assert.equal(after.mtimeMs, before.mtimeMs); assert.equal(after.ctimeMs, before.ctimeMs);
  input.workspaceRoot.assertHeld(); input.controlledHome.assertHeld(); input.stateOwnerLock.assertHeld();
});

test('frozen projection captures the complete current tree including new paths without rereading ignore or configuration', async t => {
  const { workspace, home, state, input } = await fixture(t);
  await writeFile(path.join(workspace, 'existing'), 'before');
  await mkdir(path.join(workspace, 'excluded'));
  await writeFile(path.join(workspace, 'excluded', 'unreadable'), 'not source');
  input.sourceExcludes = [{ path: 'excluded', scope: 'subtree' }];
  const base = await publishNonGitSourceProjection(input);
  await writeFile(path.join(workspace, 'existing'), 'after');
  await mkdir(path.join(workspace, 'new-directory'));
  await writeFile(path.join(workspace, 'new-directory', 'new-file'), 'new actual bytes');
  await mkdir(path.join(workspace, 'empty'));
  await writeFile(path.join(workspace, '.gitignore'), 'new-directory/\nexisting\n');
  await mkdir(path.join(workspace, '.cliq'));
  await writeFile(path.join(workspace, '.cliq', 'config'), '{invalid: never execute this as configuration');
  await writeFile(path.join(home, 'auth.json'), 'must not read home');
  await writeFile(path.join(state, 'secret'), 'must not read state');
  for (const filename of [path.join(home, 'auth.json'), path.join(state, 'secret'), path.join(workspace, 'excluded', 'unreadable')])
    await chmod(filename, 0);
  const result = await captureFrozenSourceProjection({ ...input,
    sourceProjectionRef: base.sourceProjectionRef, sourceProjectionDigest: base.sourceProjectionDigest });
  const source = await input.artifacts.readCanonical<SourceManifest>(result.resultWorkspaceManifestRef);
  const entries = await input.artifacts.readCanonical<WorkspaceEntryManifest>(result.entriesRef);
  assert.equal(source.role, 'result');
  assert.equal(source.workspaceIdentityDigest, input.workspaceIdentityDigest);
  assert.equal(source.sourceProjectionRef, base.sourceProjectionRef);
  assert.equal(source.sourceProjectionDigest, base.sourceProjectionDigest);
  assert.equal(source.frozenIgnoreRulesRef, base.frozenIgnoreRulesRef);
  assert.equal(source.frozenIgnoreRulesDigest, base.frozenIgnoreRulesDigest);
  assert.deepEqual(entries.entries.map(entry => [entry.path, entry.kind]), [
    ['.cliq', 'directory'], ['.cliq/config', 'file'], ['.gitignore', 'file'], ['empty', 'directory'],
    ['existing', 'file'], ['new-directory', 'directory'], ['new-directory/new-file', 'file']
  ]);
  const added = entries.entries.find(entry => entry.path === 'new-directory/new-file');
  assert(added?.kind === 'file'); assert.equal((await input.artifacts.readBytes(added.blobRef)).toString(), 'new actual bytes');
  const updated = entries.entries.find(entry => entry.path === 'existing');
  assert(updated?.kind === 'file'); assert.equal((await input.artifacts.readBytes(updated.blobRef)).toString(), 'after');
  assert.equal(result.metadata.some(item => item.ref === sha256Bytes(Buffer.from('must not read home'))), false);
  assert.equal(result.metadata.some(item => item.ref === sha256Bytes(Buffer.from('must not read state'))), false);
  assert.equal(result.metadata.filter(item => item.schemaKind === 'cliq-source-projection-v1').length, 1);
  assert.equal(result.metadata.filter(item => item.schemaKind === 'cliq-frozen-ignore-rules-v1').length, 1);
});

test('frozen capture rejects altered, noncanonical and unsupported retained projection closures before source publication', async t => {
  const { workspace, state, input } = await fixture(t);
  await writeFile(path.join(workspace, 'ordinary'), 'actual source bytes');
  const base = await publishNonGitSourceProjection(input);
  const projection = await input.artifacts.readCanonical<SourceProjectionSpec>(base.sourceProjectionRef);
  const rules = await input.artifacts.readCanonical<FrozenIgnoreRulesV1>(base.frozenIgnoreRulesRef);
  const selected = { ...input, sourceProjectionRef: base.sourceProjectionRef, sourceProjectionDigest: base.sourceProjectionDigest };
  await assert.rejects(captureFrozenSourceProjection({ ...selected, sourceProjectionDigest: 'f'.repeat(64) }), /retained digest/);
  const publishProjection = async (changes: object) => {
    const value = { ...projection, ...changes }; value.projectionDigest = digestOmitting(value, 'projectionDigest');
    const artifact = await input.artifacts.publishCanonical(value, 'cliq-source-projection-v1');
    return { ...selected, sourceProjectionRef: artifact.ref, sourceProjectionDigest: value.projectionDigest };
  };
  await assert.rejects(captureFrozenSourceProjection(await publishProjection({ extra: true })), /invalid fields/);
  await assert.rejects(captureFrozenSourceProjection(await publishProjection({ matcherVersion: 'future-matcher' })), /wrong schema/);
  await assert.rejects(captureFrozenSourceProjection(await publishProjection({ explicitIncludes: [
    { path: 'ordinary', scope: 'entry', authorizationRef: 'b'.repeat(64) }
  ] })), {code:'ENOENT'});
  await assert.rejects(captureFrozenSourceProjection(await publishProjection({ explicitExcludes: [
    { path: 'ordinary', scope: 'glob' }
  ] })), /exclude has invalid fields/);
  for (const changedRules of [{ ...rules, extra: true }, { ...rules, repositoryIdentityDigest: 'b'.repeat(64) },
    { ...rules, matcherVersion: 'future-matcher' }, { ...rules, rules: [{}] }, { ...rules, sources: [{}] }]) {
    changedRules.rulesDigest = digestOmitting(changedRules, 'rulesDigest');
    const artifact = await input.artifacts.publishCanonical(changedRules, 'cliq-frozen-ignore-rules-v1');
    await assert.rejects(captureFrozenSourceProjection(await publishProjection({ frozenIgnoreRulesRef: artifact.ref,
      frozenIgnoreRulesDigest: changedRules.rulesDigest })), /invalid fields|nonempty ignore matching/);
  }
  await assert.rejects(captureFrozenSourceProjection(await publishProjection({ frozenIgnoreRulesDigest: 'f'.repeat(64) })), /ignore rules differ/);
  const noncanonical = await input.artifacts.publishBytes(Buffer.from(JSON.stringify(projection) + '\n'), 'application/json', 'cliq-source-projection-v1');
  await assert.rejects(captureFrozenSourceProjection({ ...selected, sourceProjectionRef: noncanonical.ref }), /not canonical JSON/);
  const original = await readFile(path.join(state, 'objects', base.frozenIgnoreRulesRef));
  await chmod(path.join(state, 'objects', base.frozenIgnoreRulesRef), 0o600);
  await writeFile(path.join(state, 'objects', base.frozenIgnoreRulesRef), Buffer.concat([original, Buffer.from(' ')]));
  await chmod(path.join(state, 'objects', base.frozenIgnoreRulesRef), 0o400);
  await assert.rejects(captureFrozenSourceProjection(selected), /artifact [a-f0-9]{64} is corrupt/);
  input.workspaceRoot.assertHeld(); input.stateOwnerLock.assertHeld();
});

test('frozen capture closes every actual capture descriptor after payload-time inode drift without publishing a result', async t => {
  const { workspace, input } = await fixture(t);
  await mkdir(path.join(workspace, 'directory'));
  const ordinary = path.join(workspace, 'directory', 'ordinary'), excluded = path.join(workspace, 'excluded');
  await writeFile(ordinary, 'before'); await writeFile(excluded, 'before');
  input.sourceExcludes = [{ path: 'excluded', scope: 'entry' }];
  const base = await publishNonGitSourceProjection(input), bytes = Buffer.from('new actual bytes');
  await writeFile(ordinary, bytes);
  const named = [workspace, path.join(workspace, 'directory'), ordinary, excluded];
  const before = await heldDescriptors(named), excludedBefore = await stat(excluded);
  const originalOpen = fs.open; let changed = false;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (typeof args[0] === 'string' && path.basename(args[0]).startsWith('.tmp-stream-')) {
      const originalWrite = handle.writeFile.bind(handle);
      handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => {
        await originalWrite(...writeArgs);
        if (!changed && writeArgs[0] instanceof Uint8Array && Buffer.from(writeArgs[0]).equals(bytes)) {
          changed = true; await rename(excluded, `${excluded}-original`); await writeFile(excluded, 'foreign replacement');
        }
      };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(captureFrozenSourceProjection({ ...input,
      sourceProjectionRef: base.sourceProjectionRef, sourceProjectionDigest: base.sourceProjectionDigest }), /changed|identity/);
    assert.equal(changed, true); assert.notEqual((await stat(excluded)).ino, excludedBefore.ino);
  } finally { fs.open = originalOpen; }
  assert.deepEqual(await heldDescriptors([...named, `${excluded}-original`]), before);
  assert.equal(await readFile(excluded, 'utf8'), 'foreign replacement');
  input.workspaceRoot.assertHeld(); input.controlledHome.assertHeld(); input.stateOwnerLock.assertHeld();
});

test('frozen capture cooperatively cancels real payload reading and fully joins its original descriptors', async t => {
  const { workspace, input } = await fixture(t);
  const base = await publishNonGitSourceProjection(input);
  await mkdir(path.join(workspace, 'new-directory'));
  const ordinary = path.join(workspace, 'new-directory', 'ordinary');
  await writeFile(ordinary, Buffer.alloc(65536 * 3, 0x63));
  const named = [workspace, path.join(workspace, 'new-directory'), ordinary], before = await heldDescriptors(named);
  const cancellation = new AbortController(), reason = new Error('cancel actual frozen source payload');
  const originalOpen = fs.open; let cancelled = false;
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (typeof args[0] === 'string' && path.basename(args[0]).startsWith('.tmp-stream-')) {
      const originalWrite = handle.writeFile.bind(handle);
      handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => {
        await originalWrite(...writeArgs);
        if (!cancelled && writeArgs[0] instanceof Uint8Array && writeArgs[0].byteLength === 65536) {
          cancelled = true; cancellation.abort(reason);
        }
      };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(captureFrozenSourceProjection({ ...input,
      sourceProjectionRef: base.sourceProjectionRef, sourceProjectionDigest: base.sourceProjectionDigest,
      signal: cancellation.signal }), error => error === reason);
    assert.equal(cancelled, true);
  } finally { fs.open = originalOpen; }
  assert.deepEqual(await heldDescriptors(named), before);
  input.workspaceRoot.assertHeld(); input.controlledHome.assertHeld(); input.stateOwnerLock.assertHeld();
});

test('non-Git selectors cannot enable managed roots, escape, fake native handles or borrow include authority', async t => {
  const { workspace, home, input, native } = await fixture(t);
  for (const selector of ['../outside', '/absolute', '.git/config', 'managed-home', 'managed-state/credential'])
    await assert.rejects(publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: selector, scope: 'subtree' }] }), /canonical|hard-excluded/);
  await assert.rejects(publishNonGitSourceProjection({ ...input, sourceIncludes: [{ path: 'ordinary', scope: 'entry' }] }),
    {code:'INVALID_REQUEST',message:'explicit source includes require original registered capture authority'});
  await assert.rejects(publishNonGitSourceProjection({ ...input, sourceIncludes: [{ path: 'ordinary', scope: 'entry' }],
    includeCapture:{owner:{},target:{}} as never }), {code:'ARTIFACT_MISMATCH'});
  await assert.rejects(publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: 'ordinary', scope: 'entry', readGrantId: 'forged' } as never] }), /unknown fields/);
  await assert.rejects(publishNonGitSourceProjection({ ...input, workspaceRoot: { ...input.workspaceRoot } }), /invalid native source/);
  await assert.rejects(publishNonGitSourceProjection({ ...input, stateOwnerLock: { ...input.stateOwnerLock } }), /invalid StateOwner lock/);
  await assert.rejects(publishNonGitSourceProjection({ ...input, workspaceRoot: input.controlledHome }), /inside a controlled/);
  await mkdir(path.join(home, 'child'));
  const child = native.openWorkspaceRoot(path.join(home, 'child')); t.after(() => child.close());
  await assert.rejects(publishNonGitSourceProjection({ ...input, workspaceRoot: child }), /inside a controlled/);
  await mkdir(path.join(workspace, 'dir')); await writeFile(path.join(workspace, 'dir', 'file'), 'ordinary');
  await assert.rejects(publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: 'dir', scope: 'entry' }] }), /required directory ancestor/);
});

test('non-Git metadata classification finishes before opening payloads and applies distinct entry, total and single-file ceilings', async t => {
  const { workspace, state, input } = await fixture(t);
  await writeFile(path.join(workspace, 'ordinary'), 'readable');
  await writeFile(path.join(workspace, 'too-large'), '123456789'); await chmod(path.join(workspace, 'too-large'), 0);
  await assert.rejects(publishNonGitSourceProjection({ ...input, maxSingleFileBytes: 8 }), /capture file\/total limit/);
  assert.deepEqual(await readdir(path.join(state, 'objects')), []);
  await assert.rejects(publishNonGitSourceProjection({ ...input, maxBytes: 16 }), /capture file\/total limit/);
  assert.deepEqual(await readdir(path.join(state, 'objects')), []);
  await assert.rejects(publishNonGitSourceProjection({ ...input, maxEntries: 1 }), /inventory exceeds/);
  assert.deepEqual(await readdir(path.join(state, 'objects')), []);
  await chmod(path.join(workspace, 'too-large'), 0o600);
  const exact = await publishNonGitSourceProjection({ ...input, maxBytes: 17, maxSingleFileBytes: 9 });
  assert.equal(exact.byteCount, 17);
  await assert.rejects(publishNonGitSourceProjection({ ...input, maxEntries: 100_001 }), /fixed capture\/result bounds/);
});

test('non-Git projection rejects symlink lookup chains through genuine controlled roots without following secret bytes', async t => {
  const { workspace, home, input } = await fixture(t);
  await writeFile(path.join(home, 'auth.json'), 'secret'); await chmod(path.join(home, 'auth.json'), 0);
  await symlink('managed-home/auth.json', path.join(workspace, 'direct'));
  await assert.rejects(publishNonGitSourceProjection(input), /symlink references a hard-excluded/);
  await rm(path.join(workspace, 'direct'));
  await symlink('managed-state/../ordinary', path.join(workspace, 'first'));
  await symlink('first', path.join(workspace, 'second'));
  await assert.rejects(publishNonGitSourceProjection(input), /symlink references a hard-excluded/);
});

test('non-Git projection prunes an actual special entry but refuses selectors into it and rejects nested repositories', async t => {
  const { workspace, input, native } = await fixture(t);
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(path.join(workspace, 'socket'), resolve); });
  try {
    const projected = await publishNonGitSourceProjection(input);
    assert.equal(projected.entryCount, 0);
    await assert.rejects(publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: 'socket/child', scope: 'entry' }] }), /hard-excluded/);
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
  await mkdir(path.join(workspace, 'nested')); await mkdir(path.join(workspace, 'nested', '.git'));
  await assert.rejects(publishNonGitSourceProjection(input), /nested Git metadata/);
  const pruned = await publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: 'nested', scope: 'subtree' }] });
  assert.equal(pruned.entryCount, 0);
  await mkdir(path.join(workspace, '.git'));
  const gitRoot = native.openWorkspaceRoot(workspace); t.after(() => gitRoot.close());
  await assert.rejects(publishNonGitSourceProjection({ ...input, workspaceRoot: gitRoot }), /Git source inspection is not implemented/);
});

test('owned source refusal uses the original native inventory and exact public error classification', async t => {
  const { workspace, input } = await fixture(t);
  const expected = { protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1,
    messageCode: 'source_capture_rejected', code: 'INVALID_REQUEST', retryable: false,
    issues: [{ path: 'source', issueCode: 'source_changed_or_unsupported' }] } };
  await mkdir(path.join(workspace, 'nested')); await mkdir(path.join(workspace, 'nested', '.git'));
  await assert.rejects(publishNonGitSourceProjection(input), error => {
    // The native Error is retained as INTERNAL; it is not relabelled to make
    // an installed fixture's exact INVALID_REQUEST assertion pass.
    assert.equal(createSourceInspectionErrorResponse(error, 'owned-inspection', false, 'run.submit').error.code, 'INTERNAL');
    return true;
  });
  await rm(path.join(workspace, 'nested'), { recursive: true });
  await mkdir(path.join(workspace, 'vendor')); await mkdir(path.join(workspace, 'vendor', '.git'));
  await withInstalledSourceRefusalFixture({ workspace, uid: process.getuid!(), gid: process.getgid!() }, async () => {
    await assert.rejects(publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: 'vendor', scope: 'subtree' }] }), error => {
      assert.deepEqual(createSourceInspectionErrorResponse(error, 'owned-inspection', false, 'run.submit'), expected); return true;
    });
  });
  assert.deepEqual(await fs.readdir(workspace), ['managed-home', 'managed-state', 'vendor']);
  const original = Error('original owned callback failure');
  await assert.rejects(withInstalledSourceRefusalFixture({ workspace, uid: process.getuid!(), gid: process.getgid!() }, async () => {
    throw original;
  }), error => error === original);
  assert.deepEqual(await fs.readdir(workspace), ['managed-home', 'managed-state', 'vendor']);
  const originalName = path.join(workspace, INSTALLED_SOURCE_REFUSAL_NAME), retainedName = originalName + '-retained';
  await assert.rejects(withInstalledSourceRefusalFixture({ workspace, uid: process.getuid!(), gid: process.getgid!() }, async () => {
    await rename(originalName, retainedName); await mkdir(originalName); throw original;
  }), error => error instanceof AggregateError && error.errors[0] === original);
  assert((await fs.lstat(originalName)).isDirectory()); assert((await fs.lstat(retainedName)).isDirectory());
  await fs.rmdir(originalName); await fs.rmdir(retainedName);
});

test('non-Git metadata inventory yields for cancellation even when every ordinary directory is excluded', async t => {
  const { workspace, state, input } = await fixture(t);
  for (let index = 0; index < 24; index++) await mkdir(path.join(workspace, `excluded-${index}`));
  const cancellation = new AbortController(), reason = new Error('cancel metadata inventory');
  scheduleImmediate(() => cancellation.abort(reason));
  await assert.rejects(publishNonGitSourceProjection({ ...input, signal: cancellation.signal,
    sourceExcludes: Array.from({ length: 24 }, (_, index) => ({ path: `excluded-${index}`, scope: 'subtree' as const })) }), error => error === reason);
  assert.deepEqual(await readdir(path.join(state, 'objects')), []);
  input.workspaceRoot.assertHeld();
});

test('non-Git source selection stays descriptor-held through payload publication and refuses later metadata drift', async t => {
  const { workspace, state, input } = await fixture(t);
  const bytes = Buffer.from('real selected source');
  await writeFile(path.join(workspace, 'ordinary'), bytes);
  const excluded = path.join(workspace, 'excluded'); await writeFile(excluded, 'before');
  const originalOpen = fs.open;
  let changed = false;
  // A real OS write seam only: publication writes its actual bytes, then an
  // external writer changes an excluded leaf already used in classification.
  // No native observation, capture result or permission is mocked.
  fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (typeof args[0] === 'string' && args[0].startsWith(path.join(state, 'objects', '.tmp-stream-'))) {
      const actualWrite = handle.writeFile.bind(handle);
      handle.writeFile = async (...writeArgs: Parameters<typeof handle.writeFile>) => {
        await actualWrite(...writeArgs);
        if (!changed && writeArgs[0] instanceof Uint8Array && Buffer.from(writeArgs[0]).equals(bytes)) {
          changed = true; await writeFile(excluded, 'after!');
        }
      };
    }
    return handle;
  }) as typeof fs.open;
  try {
    await assert.rejects(publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: 'excluded', scope: 'entry' }] }), /changed|identity/);
    assert.equal(changed, true); assert.equal(await readFile(excluded, 'utf8'), 'after!');
  } finally { fs.open = originalOpen; }
  input.workspaceRoot.assertHeld(); input.stateOwnerLock.assertHeld();
});
