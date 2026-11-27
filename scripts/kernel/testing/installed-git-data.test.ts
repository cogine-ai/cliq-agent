// Complete inert Git/CAS bytes only. No accepted Run, StateOwner, trusted-Git
// completion, native proof, grant, or installed qualification is created.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../../../src/kernel/control-submit.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import type { SourceManifest, WorkspaceStateManifest } from '../../../src/kernel/types.js';
import { ArtifactCatalog } from '../../../src/state/artifacts.js';
import { ContentAddressedStore } from '../../../src/state/cas.js';
import { publishSourceGitArtifacts } from '../../../src/workspace/source-git-artifacts.js';
import { privateGitSourceHead } from '../../../src/workspace/private-git-data.js';
import { assertInstalledGitState, installedGitDataReader } from './installed-git-data.js';
import { preparingGitNativeInputData } from './preparing-git-native.js';

test('installed Git reader preserves complete bounds, canonical bytes, hashes, exact EOF and cancellation', async () => {
  const data = canonicalJsonBytes({ inert: true }), ref = sha256Bytes(data);
  const reader = installedGitDataReader(async () => data);
  const consume = async (stream: AsyncIterable<Buffer>) => { const chunks: Buffer[] = []; for await (const bytes of stream) chunks.push(bytes); return Buffer.concat(chunks); };
  const decoded = await reader.readCanonical(ref); assert.equal(Object.getPrototypeOf(decoded), null);
  assert.deepEqual(canonicalJsonBytes(decoded), data);
  assert.deepEqual(await consume(reader.readChunks(ref, data.length)), data);
  await assert.rejects(reader.readBoundedBytes(ref, data.length - 1));
  await assert.rejects(consume(reader.readChunks(ref, data.length + 1)));
  await assert.rejects(installedGitDataReader(async () => Buffer.from('{}')).readCanonical(ref));
  const noncanonical = Buffer.from('{ "inert":true}');
  await assert.rejects(installedGitDataReader(async () => noncanonical).readCanonical(sha256Bytes(noncanonical)));
  const controller = new AbortController(); let reads = 0;
  const cancelled = installedGitDataReader(async () => { reads++; return data; }).withReadSignal(controller.signal);
  controller.abort(); await assert.rejects(cancelled.readBoundedBytes(ref, data.length)); assert.equal(reads, 0);
});

test('installed ordinary Git state rereads the original complete private/index/pack closure and rejects substitutions', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'installed-git-data-'));
  try {
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(directory)), repositoryIdentityDigest = 'a'.repeat(64);
    const expected = { repositoryIdentityDigest, resources: DEFAULT_SANDBOX_RESOURCES };
    const [inspection, index, pack, packIndex] = preparingGitNativeInputData(repositoryIdentityDigest, expected.resources);
    const stream = async function* (bytes: Buffer) { yield bytes; };
    const published = await publishSourceGitArtifacts(artifacts, { inspection: stream(inspection), index: stream(index),
      pack: stream(pack), packIndex: stream(packIndex) }, expected);
    const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base',
      workspaceIdentityDigest: 'b'.repeat(64), entriesRef: 'c'.repeat(64), sourceProjectionRef: 'd'.repeat(64),
      sourceProjectionDigest: 'e'.repeat(64), frozenIgnoreRulesRef: 'f'.repeat(64), frozenIgnoreRulesDigest: '1'.repeat(64),
      git: { repositoryIdentityDigest, indexRef: published.indexRef, indexTreeObjectId: published.index.indexTreeObjectId,
        head: privateGitSourceHead({ manifestRef: published.privateGitStateRef, manifest: published.manifest,
          index: published.index, closure: published.closure, pack: published.pack, config: published.output.sanitizedConfig }) },
      treeDigest: '2'.repeat(64), manifestDigest: '' };
    source.manifestDigest = digestOmitting(source, 'manifestDigest');
    const state: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: 'inert-state-data',
      baseWorkspaceManifestRef: canonicalSha256(source), entriesRef: source.entriesRef, privateGitStateRef: published.privateGitStateRef,
      invalidatedEphemeralPaths: [], sourceProjectionDigest: source.sourceProjectionDigest, stateDigest: '' };
    state.stateDigest = digestOmitting(state, 'stateDigest');
    const reads = new Set<string>(), read = async (ref: string) => { reads.add(ref); return artifacts.readBytes(ref); };
    await assertInstalledGitState(installedGitDataReader(read), source, state, expected.resources, true);
    for (const ref of [published.privateGitStateRef, published.indexRef, published.index.canonicalIndexBytesRef,
      published.manifest.objectClosureRef, published.manifest.sanitizedConfigRef, published.closure.packs[0]!.packRef,
      published.pack.packBytesRef, published.pack.packIndexBytesRef]) assert(reads.has(ref), 'every original Git leaf must be consumed');
    for (const corruptRef of [published.index.canonicalIndexBytesRef, published.pack.packBytesRef, published.pack.packIndexBytesRef]) {
      await assert.rejects(assertInstalledGitState(installedGitDataReader(async ref => {
        const bytes = await artifacts.readBytes(ref); if (ref !== corruptRef) return bytes;
        const replaced = Buffer.from(bytes); replaced[0] = replaced[0]! ^ 1; return replaced;
      }), source, state, expected.resources, true));
    }
    await assert.rejects(assertInstalledGitState(installedGitDataReader(read), source, { ...state, privateGitStateRef: undefined }, expected.resources, true));
    await assert.rejects(assertInstalledGitState(installedGitDataReader(read), source, state, expected.resources, false));
    await assert.rejects(assertInstalledGitState(installedGitDataReader(read), { ...source, git: undefined }, state, expected.resources, false));
  } finally { await rm(directory, { recursive: true }); }
});
