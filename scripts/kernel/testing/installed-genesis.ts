// Independent installed StateOwner/genesis/CAS observations; no authority producer.
import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import { KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import type { StateOwnerAcquisitionEvidenceV1, StateRootIdentityV1 } from '../../../src/kernel/types.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { assertSignedKernelSchemaEntry } from '../../../src/state/signed-schema.js';
import { inspectInstalledOwnerHistory } from './installed-read-control.js';
import { qualifyInstalledOwnerProcess, readInstalledCasJson } from './installed-owner-history.js';

type GenesisContent = { entryId: string; role: string; relativePath: string; version?: string;
  executable: boolean; bytes: Uint8Array };

/** Qualification data only. Reconstruct the entire signed seed by its actual
 * members, including schema8, without assuming a particular object count. */
export function expectedInstalledGenesisSeed(input: { bundle: RuntimeBundleManifest; contents: readonly GenesisContent[] }) {
  assertSignedKernelSchemaEntry(input.bundle);
  assert.equal(input.contents.length, input.bundle.entries.length, 'every signed entry has its original full content');
  const ids = new Set<string>(), seed = new Map<string, { artifactRef: string; byteCount: number; bytes: Buffer }>();
  const add = (bytes: Uint8Array) => {
    const raw = Buffer.from(bytes), ref = sha256Bytes(raw), previous = seed.get(ref);
    if (previous) assert.deepEqual(raw, previous.bytes, 'equal CAS refs contain equal full bytes');
    else seed.set(ref, { artifactRef: ref, byteCount: raw.byteLength, bytes: raw });
  };
  add(canonicalJsonBytes(input.bundle));
  for (const content of input.contents) {
    assert(!ids.has(content.entryId), 'signed content identity cannot repeat'); ids.add(content.entryId);
    const entry = input.bundle.entries.find(item => item.entryId === content.entryId);
    assert(entry, 'content must belong to the exact original signed bundle');
    const version = content.version ?? (content.entryId === 'kernel_schema' ? '8' : content.entryId === 'schema_conversion' ? '7-to-8' : '1');
    assert.equal(content.role, entry.role); assert.equal(content.relativePath, entry.relativePath);
    assert.equal(content.executable, entry.executable); assert.equal(version, entry.version);
    assert.equal(content.bytes.byteLength, entry.byteCount); assert.equal(sha256Bytes(content.bytes), entry.digest);
    if (!content.executable) add(content.bytes);
  }
  return [...seed.values()].map(({ artifactRef, byteCount }) => ({ artifactRef, byteCount }))
    .sort((left, right) => left.artifactRef < right.artifactRef ? -1 : left.artifactRef > right.artifactRef ? 1 : 0);
}

export async function qualifyInstalledGenesis(input: {
  stateRoot: string; pid: number; uid: number; selectedImage: string; bundle: RuntimeBundleManifest;
  contents: readonly GenesisContent[]; report: Record<string, unknown>;
}) {
  input.report.qualified = false;
  const bundleDigest = canonicalSha256(input.bundle);
  const imageDigest = sha256Bytes(input.contents[0]!.bytes);
  const casJson = <T>(ref: string) => readInstalledCasJson<T>(input, ref);
  const history = inspectInstalledOwnerHistory(input.stateRoot); assert.equal(history.owners.length, 1);
  const owner = history.owners[0]; input.report.owner = owner;
  assert(owner); assert.equal(owner.state, 'active'); assert.equal(owner.ownerEpoch, 1);
  assert.equal(owner.runtimeBundleRef, bundleDigest); assert.equal(owner.runtimeBundleManifestDigest, input.bundle.manifestDigest);
  assert.equal(owner.supervisorExecutableDigest, imageDigest);
  const identity = await qualifyInstalledOwnerProcess({ ...input, imageDigest }, owner, input.report);
  const acquisition = await casJson<StateOwnerAcquisitionEvidenceV1>(owner.acquisitionEvidenceRef);
  input.report.acquisition = acquisition;
  assert.equal(acquisition.kind, 'genesis'); assert(acquisition.kind === 'genesis');
  assert.equal(acquisition.ownerEpoch, 1); assert.equal(acquisition.ownerTableObservation, 'empty');
  assert.equal(acquisition.runtimeBundleRef, bundleDigest);
  assert.equal(acquisition.runtimeBundleManifestDigest, input.bundle.manifestDigest);
  assert.equal(acquisition.processIdentityRef, owner.processIdentityRef);
  assert.equal(acquisition.evidenceDigest, digestOmitting(acquisition, 'evidenceDigest'));
  assert.equal(owner.acquisitionEvidenceDigest, acquisition.evidenceDigest);
  const generation = await casJson<Record<string, any>>(acquisition.kernelGenerationIdentityRef);
  input.report.generation = generation;
  assert.equal(generation.origin, 'fresh_installed'); assert.equal(generation.stateSchemaVersion, KERNEL_STATE_SCHEMA_VERSION);
  assert.equal(generation.runtimeBundleRef, bundleDigest); assert.equal(generation.runtimeBundleManifestDigest, input.bundle.manifestDigest);
  assert.equal(generation.generationDigest, digestOmitting(generation, 'generationDigest'));
  assert.equal(acquisition.kernelGenerationIdentityDigest, generation.generationDigest);
  const root = await casJson<StateRootIdentityV1>(generation.stateRootIdentityRef); input.report.stateRoot = root;
  const actualRoot = await lstat(input.stateRoot, { bigint: true });
  assert(actualRoot.isDirectory() && !actualRoot.isSymbolicLink());
  assert.equal(root.identityDigest, digestOmitting(root, 'identityDigest'));
  assert.equal(generation.stateRootIdentityDigest, root.identityDigest);
  assert.deepEqual(canonicalJsonBytes(root), canonicalJsonBytes({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
    canonicalAbsolutePath: input.stateRoot, ownerUid: input.uid, deviceId: actualRoot.dev.toString(),
    directoryFileId: actualRoot.ino.toString(), mode: 0o700, openedNoFollow: true, layoutVersion: 1,
    identityDigest: root.identityDigest }));
  const namespace = await casJson<Record<string, any>>(generation.casNamespaceManifestRef);
  input.report.namespace = namespace;
  const seed = expectedInstalledGenesisSeed(input);
  assert.equal(namespace.snapshotBoundary, 'generation_birth');
  assert.deepEqual(canonicalJsonBytes(namespace.entries), canonicalJsonBytes(seed)); assert.equal(namespace.objectCount, seed.length);
  assert.equal(namespace.totalBytes, seed.reduce((total, entry) => total + entry.byteCount, 0));
  assert.equal(namespace.rootDigest, canonicalSha256(seed));
  assert.equal(namespace.manifestDigest, digestOmitting(namespace, 'manifestDigest'));
  assert.equal(generation.casNamespaceManifestDigest, namespace.manifestDigest);
  assert.equal(generation.casRootDigest, namespace.rootDigest);
  assert.deepEqual(inspectInstalledOwnerHistory(input.stateRoot), history);
  input.report.qualified = true;
  return { owner, identity };
}
