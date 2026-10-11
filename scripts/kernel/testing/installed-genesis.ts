// Independent installed StateOwner/genesis/CAS observations; no authority producer.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readFile, readlink, stat } from 'node:fs/promises';
import path from 'node:path';
import { KERNEL_CAS_DIRECTORY, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { PlatformProcessIdentityV1, StateOwnerAcquisitionEvidenceV1, StateRootIdentityV1 } from '../../../src/kernel/types.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { inspectInstalledOwner } from './installed-read-control.js';

export async function qualifyInstalledGenesis(input: {
  stateRoot: string; pid: number; uid: number; selectedImage: string; bundle: RuntimeBundleManifest;
  contents: readonly { executable: boolean; bytes: Buffer }[]; report: Record<string, unknown>;
}) {
  input.report.qualified = false;
  const bundleDigest = canonicalSha256(input.bundle), manifestBytes = canonicalJsonBytes(input.bundle);
  const imageDigest = sha256Bytes(input.contents[0]!.bytes);
  const casJson = async <T>(ref: string): Promise<T> => {
    assert.match(ref, /^[0-9a-f]{64}$/u);
    const filename = path.join(input.stateRoot, KERNEL_CAS_DIRECTORY, ref);
    const before = await lstat(filename, { bigint: true });
    assert(before.isFile() && !before.isSymbolicLink()); assert.equal(before.nlink, 1n);
    assert.equal(before.uid, BigInt(input.uid)); assert.equal(before.mode & 0o7777n, 0o400n);
    const bytes = await readFile(filename);
    const after = await lstat(filename, { bigint: true });
    for (const key of ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const)
      assert.equal(after[key], before[key]);
    assert.equal(BigInt(bytes.byteLength), after.size); assert.equal(sha256Bytes(bytes), ref);
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as T;
    assert.deepEqual(canonicalJsonBytes(value), bytes);
    return value;
  };
  const owner = inspectInstalledOwner(input.stateRoot); input.report.owner = owner;
  assert(owner); assert.equal(owner.state, 'active'); assert.equal(owner.ownerEpoch, 1);
  assert.equal(owner.runtimeBundleRef, bundleDigest); assert.equal(owner.runtimeBundleManifestDigest, input.bundle.manifestDigest);
  assert.equal(owner.supervisorExecutableDigest, imageDigest);
  const identity = await casJson<PlatformProcessIdentityV1>(owner.processIdentityRef); input.report.identity = identity;
  assert.equal(identity.pid, input.pid); assert.equal(identity.ownerUid, input.uid);
  assert.equal(identity.identityDigest, digestOmitting(identity, 'identityDigest'));
  assert.equal(owner.processIdentityDigest, identity.identityDigest);
  const procStat = await readFile(`/proc/${input.pid}/stat`, 'utf8');
  assert(procStat.startsWith(`${input.pid} (`));
  const procFields = procStat.slice(procStat.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert(!['Z', 'X', 'x'].includes(procFields[0]!)); assert.match(procFields[19]!, /^(0|[1-9][0-9]*)$/u);
  assert.equal(identity.processStartToken, `linux-proc-start-ticks:${procFields[19]}`);
  const selectedInfo = await lstat(input.selectedImage, { bigint: true });
  const bootstrapInfo = await lstat(path.join(input.stateRoot, 'runtime/bootstrap'), { bigint: true });
  const actualImage = `/proc/${input.pid}/exe`;
  assert.equal(await readlink(actualImage), input.selectedImage, 'actual process must execute selected inode, not bootstrap');
  const actualInfo = await stat(actualImage, { bigint: true });
  for (const key of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const)
    assert.equal(actualInfo[key], selectedInfo[key]);
  assert(actualInfo.dev !== bootstrapInfo.dev || actualInfo.ino !== bootstrapInfo.ino,
    'identical signed bytes do not prove terminal selected-inode exec');
  assert.equal(identity.executableImageDigest, createHash('sha256').update(await readFile(actualImage)).digest('hex'));
  assert.equal(identity.executableImageDigest, imageDigest);
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
  const seed = [manifestBytes, ...input.contents.filter(entry => !entry.executable).map(entry => entry.bytes)]
    .map(bytes => ({ artifactRef: sha256Bytes(bytes), byteCount: bytes.byteLength }))
    .sort((left, right) => left.artifactRef < right.artifactRef ? -1 : left.artifactRef > right.artifactRef ? 1 : 0);
  assert.equal(seed.length, 4); assert.equal(namespace.snapshotBoundary, 'generation_birth');
  assert.deepEqual(canonicalJsonBytes(namespace.entries), canonicalJsonBytes(seed)); assert.equal(namespace.objectCount, seed.length);
  assert.equal(namespace.totalBytes, seed.reduce((total, entry) => total + entry.byteCount, 0));
  assert.equal(namespace.rootDigest, canonicalSha256(seed));
  assert.equal(namespace.manifestDigest, digestOmitting(namespace, 'manifestDigest'));
  assert.equal(generation.casNamespaceManifestDigest, namespace.manifestDigest);
  assert.equal(generation.casRootDigest, namespace.rootDigest);
  assert.deepEqual(inspectInstalledOwner(input.stateRoot), owner);
  input.report.qualified = true;
  return { owner, identity };
}
