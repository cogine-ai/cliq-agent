import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { chmod, link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { setImmediate as scheduleImmediate } from 'node:timers';
import type { FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntryManifest } from '../kernel/types.js';
import { sha256Bytes } from '../kernel/identity.js';
import { ArtifactCatalog } from '../state/artifacts.js';
import { ContentAddressedStore } from '../state/cas.js';
import { loadNativeStateOwner } from '../state/native-owner.js';
import { publishNonGitSourceProjection } from './source-projection.js';

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

test('non-Git selectors cannot enable managed roots, escape, fake native handles or request unimplemented include authority', async t => {
  const { workspace, home, input, native } = await fixture(t);
  for (const selector of ['../outside', '/absolute', '.git/config', 'managed-home', 'managed-state/credential'])
    await assert.rejects(publishNonGitSourceProjection({ ...input, sourceExcludes: [{ path: selector, scope: 'subtree' }] }), /canonical|hard-excluded/);
  await assert.rejects(publishNonGitSourceProjection({ ...input, sourceIncludes: [{ path: 'ordinary', scope: 'entry' }] }), /includes.*not implemented/);
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
