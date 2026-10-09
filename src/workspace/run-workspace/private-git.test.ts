import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../kernel/identity.js';
import type { Checkpoint, FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntryManifest, WorkspaceStateManifest } from '../../kernel/types.js';
import { ArtifactCatalog } from '../../state/artifacts.js';
import { ContentAddressedStore } from '../../state/cas.js';
import { loadNativeStateOwner } from '../../state/native-owner.js';
import { captureLiveWorkspaceIdentity } from '../../state/workspace-identity.js';
import { materializeRunWorkspace, type RunWorkspaceGeneration } from './generation.js';

const run = promisify(execFile);

test('a frozen real unborn Git checkpoint restores independent canonical private Git metadata', async (t) => {
  const root = await mkdtemp(path.join(process.cwd(), '.cliq-private-git-'));
  const source = await mkdtemp(path.join(process.cwd(), '.cliq-private-git-source-'));
  await chmod(root, 0o700); await chmod(source, 0o700);
  const held = (await loadNativeStateOwner()).acquireLock(root, true);
  let generation: RunWorkspaceGeneration | undefined;
  t.after(async () => {
    generation?.close(); held.close();
    await rm(root, { recursive: true, force: true }); await rm(source, { recursive: true, force: true });
  });
  const env = { PATH: process.env.PATH, HOME: source, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  // Git here creates/verifies a real external fixture; the producer executes no ambient Git.
  await run('git', ['init', '--quiet', '--template=', '--object-format=sha1', '--initial-branch=main', source], { env });
  await run('git', ['-C', source, 'read-tree', '--empty'], { env });
  const sourceIndexBytes = await readFile(path.join(source, '.git/index'));
  assert.equal(sourceIndexBytes.subarray(0, 12).toString('hex'), '444952430000000200000000');
  assert.deepEqual(sourceIndexBytes.subarray(-20), createHash('sha1').update(sourceIndexBytes.subarray(0, -20)).digest());
  // RFC canonical v2 drops source Git's optional empty TREE accelerator.
  const indexBytes = Buffer.from('44495243000000020000000039d890139ee5356c7ef572216cebcd27aa41f9df', 'hex');
  const headBytes = await readFile(path.join(source, '.git/HEAD'));
  assert.equal(headBytes.toString(), 'ref: refs/heads/main\n');
  const captured = await captureLiveWorkspaceIdentity({ workspacePath: source, ownerPrincipalId: 'staging-test-principal' });
  const repositoryIdentityDigest = captured.repository!.repositoryIdentityDigest;
  await mkdir(path.join(root, 'objects'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'objects')));
  const indexBlob = await artifacts.publishBytes(indexBytes, 'application/octet-stream', 'cliq-git-index-bytes-v1');
  const index = { schemaVersion: 1, format: 'cliq-git-index-snapshot-v1', repositoryIdentityDigest,
    objectFormat: 'sha1', canonicalIndexVersion: 2, entries: [], canonicalIndexBytesRef: indexBlob.ref,
    canonicalIndexBytesDigest: indexBlob.ref, canonicalIndexByteCount: indexBytes.length,
    indexTreeObjectId: '4b825dc642cb6eb9a060e54bf8d69288fbee4904', snapshotDigest: '' };
  index.snapshotDigest = digestOmitting(index, 'snapshotDigest');
  const indexRef = (await artifacts.publishCanonical(index, index.format)).ref;
  const closure = { schemaVersion: 1, format: 'cliq-git-object-closure-v1', repositoryIdentityDigest,
    objectFormat: 'sha1', packs: [], reachableObjectIds: [], closureDigest: '' };
  closure.closureDigest = digestOmitting(closure, 'closureDigest');
  const objectClosureRef = (await artifacts.publishCanonical(closure, closure.format)).ref;
  const fileMode = (await run('git', ['-C', source, 'config', '--get', 'core.filemode'], { env })).stdout.trim() === 'true';
  const config = { schemaVersion: 1, format: 'cliq-sanitized-git-config-v1',
    core: { repositoryFormatVersion: 0, fileMode, bare: false }, configDigest: '' };
  config.configDigest = digestOmitting(config, 'configDigest');
  const sanitizedConfigRef = (await artifacts.publishCanonical(config, config.format)).ref;
  const git = { schemaVersion: 1, format: 'cliq-private-git-v1', head: { kind: 'unborn', branch: 'main' }, indexRef,
    refs: [], objectClosureRef, objectClosureDigest: closure.closureDigest,
    sanitizedConfigRef, sanitizedConfigDigest: config.configDigest, manifestDigest: '' };
  git.manifestDigest = digestOmitting(git, 'manifestDigest');
  const privateGitStateRef = (await artifacts.publishCanonical(git, git.format)).ref;
  const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [],
    entryCount: 0, byteCount: 0, treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: [] }) };
  const entriesRef = (await artifacts.publishCanonical(entries, entries.format)).ref;
  const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', repositoryIdentityDigest,
    matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesRef = (await artifacts.publishCanonical(rules, rules.format)).ref;
  const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: rulesRef,
    frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [], maxChangedPaths: 1000,
    maxChangedBytes: 1024 * 1024, projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionRef = (await artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
  const base: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base',
    workspaceIdentityDigest: captured.identity.identityDigest, entriesRef, sourceProjectionRef: projectionRef,
    sourceProjectionDigest: projection.projectionDigest, frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
    git: { repositoryIdentityDigest, head: { kind: 'unborn', branch: 'main' }, indexRef, indexTreeObjectId: index.indexTreeObjectId },
    treeDigest: entries.treeDigest, manifestDigest: '' };
  base.manifestDigest = digestOmitting(base, 'manifestDigest');
  const state: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: 'unborn-run',
    baseWorkspaceManifestRef: (await artifacts.publishCanonical(base, base.format)).ref, entriesRef, privateGitStateRef,
    invalidatedEphemeralPaths: [], sourceProjectionDigest: projection.projectionDigest, stateDigest: '' };
  state.stateDigest = digestOmitting(state, 'stateDigest');
  const checkpoint: Checkpoint = { schemaVersion: 1, id: 'unborn-checkpoint', runId: state.runId, basedOnRunRevision: 0,
    runItemSeq: 0, contextManifestRef: entriesRef, journalSeq: 0, createdAt: '2026-10-08T00:00:00.000Z', reason: 'initial',
    workspaceStateRef: (await artifacts.publishCanonical(state, state.format)).ref };
  await writeFile(path.join(source, '.git/config'), '[core]\n\thooksPath = /untrusted/live/hooks\n[remote "origin"]\n\turl = https://example.invalid\n');
  await writeFile(path.join(source, '.git/HEAD'), 'ref: refs/heads/later\n');

  generation = await materializeRunWorkspace({ filesystem: held, artifacts, checkpoint });
  const privateRoot = path.join(root, 'runs', state.runId, 'generations', generation.generationId);
  const privateGit = path.join(privateRoot, '.git');
  assert.notEqual((await lstat(privateGit)).ino, (await lstat(path.join(source, '.git'))).ino);
  assert.equal((await lstat(privateGit)).mode & 0o7777, 0o700);
  for (const name of ['HEAD', 'index', 'config']) {
    const info = await lstat(path.join(privateGit, name));
    assert.equal(info.mode & 0o7777, 0o600); assert.equal(info.nlink, 1);
  }
  assert.deepEqual(await readFile(path.join(privateGit, 'HEAD')), headBytes);
  assert.deepEqual(await readFile(path.join(privateGit, 'index')), indexBytes);
  assert.equal(sha256Bytes(await readFile(path.join(privateGit, 'index'))), index.canonicalIndexBytesDigest);
  assert.deepEqual(await readdir(path.join(privateGit, 'refs/heads')), []);
  assert.deepEqual(await readdir(path.join(privateGit, 'objects/pack')), []);
  assert.equal((await run('git', ['--git-dir', privateGit, '--work-tree', privateRoot, 'symbolic-ref', 'HEAD'], { env })).stdout,
    'refs/heads/main\n');
  assert.equal((await run('git', ['--git-dir', privateGit, '--work-tree', privateRoot, 'ls-files', '--stage'], { env })).stdout, '');
  const configBytes = await readFile(path.join(privateGit, 'config'), 'utf8');
  assert.doesNotMatch(configBytes, /hook|remote|include|credential|worktree/i);
  const observation = await generation.observe();
  assert.equal(observation.workspaceStateRef, checkpoint.workspaceStateRef);
  assert.equal(observation.entriesRef, entriesRef);
  assert.equal(observation.treeDigest, entries.treeDigest);
  assert.equal(observation.fileFsyncComplete, true); assert.equal(observation.directoryFsyncComplete, true);
});
