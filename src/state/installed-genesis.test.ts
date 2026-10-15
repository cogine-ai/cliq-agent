// Approved fresh_installed contract. These tests exercise actual installation
// and StateOwner acquisition, not SEA execution or complete I1 qualification.
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { StateOwnerAcquisitionEvidenceV1 } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ContentAddressedStore } from './cas.js';
import { KernelStorageError } from './errors.js';
import { createInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner } from './state-owner.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';
import { writeInstalledControlPackage } from './testing/installed-control-fixture.js';

function ownerAt(stateRoot: string) {
  const inspector = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const owner = readLatestStateOwner(inspector);
    assert(owner, 'successful Store opening must retain its StateOwner');
    return owner;
  } finally { inspector.close(); }
}

type NamespaceManifest = {
  schemaVersion: number; format: string; snapshotBoundary: string;
  entries: Array<{ artifactRef: string; byteCount: number }>;
  objectCount: number; totalBytes: number; rootDigest: string; manifestDigest: string;
};

test('fresh_empty genesis records the actual opened database schema, not its artifact structure version', async () => {
  const stateRoot = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-fresh-schema-')));
  await chmod(stateRoot, 0o700);
  let store: StateStore | undefined;
  try {
    store = await openStateStore(stateRoot);
    const owner = ownerAt(stateRoot);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(owner.acquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'genesis');
    assert(acquisition.kind === 'genesis');
    const generation = await store.artifacts.readCanonical<Record<string, unknown>>(acquisition.kernelGenerationIdentityRef);
    assert.equal(generation.schemaVersion, 1);
    assert.equal(generation.origin, 'fresh_empty');
    const inspector = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    let actualSchema: number;
    try { actualSchema = Number(inspector.prepare('PRAGMA user_version').get<{ user_version: unknown }>()!.user_version); }
    finally { inspector.close(); }
    assert.equal(actualSchema, KERNEL_STATE_SCHEMA_VERSION);
    assert.equal(generation.stateSchemaVersion, actualSchema);
    assert.equal(generation.generationDigest, digestOmitting(generation, 'generationDigest'));
    assert.equal(acquisition.kernelGenerationIdentityDigest, generation.generationDigest);
    assert.equal(canonicalSha256(generation), acquisition.kernelGenerationIdentityRef);
  } finally {
    await store?.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') test('a real signed initial installation acquires genesis without discarding its CAS payloads and reopens normally', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-genesis-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  let store: StateStore | undefined;
  try {
    const signed = await writeInstalledControlPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installed = await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    assert.deepEqual(selected.bundle, signed.bundle);
    assert.equal(selected.bundleDigest, installed.bundleDigest);
    assert.notEqual(installed.bundleDigest, installed.manifestDigest);
    const cas = new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
    const expectedEntries = signed.seedObjects.map(({ artifactRef, bytes }) => ({ artifactRef, byteCount: bytes.byteLength }))
      .sort((left, right) => left.artifactRef < right.artifactRef ? -1 : left.artifactRef > right.artifactRef ? 1 : 0);
    assert.equal(expectedEntries.length, 4, 'manifest, policy, PEM and acyclic root are the installed CAS seed');
    assert.deepEqual((await readdir(path.join(stateRoot, KERNEL_CAS_DIRECTORY))).sort(), expectedEntries.map(entry => entry.artifactRef));
    for (const object of signed.seedObjects) assert.deepEqual(await cas.read(object.artifactRef), object.bytes);

    const authority = { bundle: selected.bundle, releaseKeys: signed.releaseKeys };
    store = await openStateStore(stateRoot, authority, selected);
    assert.equal(store.ownerEpoch, 1);
    // Independent durable audit of the public acquisition/generation contract,
    // not installation evidence or an input used to authorize the opening.
    const first = ownerAt(stateRoot);
    assert.equal(first.runtimeBundleRef, installed.bundleDigest);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(first.acquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'genesis');
    assert(acquisition.kind === 'genesis');
    assert.equal(acquisition.ownerTableObservation, 'empty');
    assert.equal(acquisition.runtimeBundleRef, installed.bundleDigest);
    assert.equal(acquisition.runtimeBundleManifestDigest, signed.bundle.manifestDigest);
    const generation = await store.artifacts.readCanonical<Record<string, unknown>>(acquisition.kernelGenerationIdentityRef);
    assert.equal(generation.origin, 'fresh_installed');
    assert.equal(generation.stateSchemaVersion, KERNEL_STATE_SCHEMA_VERSION);
    assert.equal(generation.runtimeBundleRef, installed.bundleDigest);
    assert.equal(generation.runtimeBundleManifestDigest, signed.bundle.manifestDigest);
    assert.equal(generation.generationDigest, digestOmitting(generation, 'generationDigest'));
    assert.equal(acquisition.kernelGenerationIdentityDigest, generation.generationDigest);
    assert.equal(canonicalSha256(generation), acquisition.kernelGenerationIdentityRef);
    const namespaceRef = generation.casNamespaceManifestRef;
    assert(typeof namespaceRef === 'string');
    const namespace = await store.artifacts.readCanonical<NamespaceManifest>(namespaceRef);
    assert.equal(namespace.schemaVersion, 1);
    assert.equal(namespace.format, 'cliq-cas-namespace-manifest-v1');
    assert.equal(namespace.snapshotBoundary, 'generation_birth');
    assert.deepEqual(namespace.entries, expectedEntries);
    assert.equal(namespace.objectCount, 4);
    assert.equal(namespace.totalBytes, signed.seedObjects.reduce((total, object) => total + object.bytes.byteLength, 0));
    assert.equal(namespace.rootDigest, canonicalSha256(expectedEntries));
    assert.equal(namespace.manifestDigest, digestOmitting(namespace, 'manifestDigest'));
    assert.equal(generation.casNamespaceManifestDigest, namespace.manifestDigest);
    assert.equal(generation.casRootDigest, namespace.rootDigest);
    await store.close(); store = undefined;

    // CAS has grown with genuine owner evidence. Reopening is the existing
    // successor acquisition, not another pristine-installation genesis.
    store = await openStateStore(stateRoot, authority, selected);
    assert.equal(store.ownerEpoch, 2);
    const successor = ownerAt(stateRoot);
    const reacquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(successor.acquisitionEvidenceRef);
    assert.equal(reacquisition.kind, 'acquire_after_graceful_release');
    assert(reacquisition.kind === 'acquire_after_graceful_release');
    assert.equal(reacquisition.priorOwnerEpoch, 1);
    for (const object of signed.seedObjects) assert.deepEqual(await cas.read(object.artifactRef), object.bytes);
  } finally {
    await store?.close();
    await selected?.close();
    await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') test('installed Supervisor status reports real initial inventory and schema, without advertising execution readiness', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-status-')));
  await chmod(fixture, 0o700);
  const stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  let store: StateStore | undefined;
  try {
    const signed = await writeInstalledControlPackage(path.join(fixture, 'package'));
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installed = await runtime.installInitial({ packageRoot: path.join(fixture, 'package'), stateRoot });
    selected = await runtime.openSelected(stateRoot);
    store = await openStateStore(stateRoot, { bundle: selected.bundle, releaseKeys: signed.releaseKeys }, selected);
    const identity = await publishInProcessChannel(store);
    const summary = { schemaVersion: 1, runtimeBundleRef: installed.bundleDigest,
      bundleDigest: installed.bundleDigest, bundleVersion: signed.bundle.bundleVersion };
    const owner = ownerAt(stateRoot);
    assert.deepEqual(await store.readSupervisorStatus(identity), {
      method: 'supervisor.status', health: 'degraded', supervisorInstanceId: owner.supervisorInstanceId,
      queue: { queuedRuns: 0, runningRuns: 0, capacity: 0 }, stateSchemaVersion: KERNEL_STATE_SCHEMA_VERSION,
      activeRuntimeBundle: summary, installedRuntimeBundles: [summary], incompatiblePinnedRunCount: 0,
    });
    // This handle is a borrowed installation, not owned by StateStore. Its
    // real closure must revoke inventory observations even while Store lives.
    await selected.close();
    await assert.rejects(store.readSupervisorStatus(identity),
      error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
  } finally {
    await store?.close(); await selected?.close();
    await rm(fixture, { recursive: true, force: true });
  }
});

test('StateStore rejects a structural installed-runtime lookalike before calling any supplied methods', async () => {
  const stateRoot = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-lookalike-')));
  await chmod(stateRoot, 0o700);
  let asserted = 0;
  let closed = 0;
  let observed = 0;
  const lookalike: HeldInstalledRuntime = {
    get bundle(): RuntimeBundleManifest { observed++; throw new Error('untrusted bundle getter must not execute'); },
    get bundleDigest(): string { observed++; throw new Error('untrusted digest getter must not execute'); },
    async assertHeld() { asserted++; throw new Error('untrusted lookalike assertion must not execute'); },
    async close() { closed++; throw new Error('untrusted lookalike close must not execute'); },
  };
  let opened: StateStore | undefined;
  let rejection: unknown;
  try {
    try { opened = await openStateStore(stateRoot, undefined, lookalike); }
    catch (error) { rejection = error; }
    // The current implementation wrongly ignores the handle and can acquire a
    // real schema-only owner. Join that actual owner before reporting RED.
    if (opened) { await opened.close(); opened = undefined; }
    assert(rejection instanceof KernelStorageError, 'unbranded input must be rejected, not ignored or structurally cloned');
    assert.equal(rejection.code, 'ARTIFACT_MISMATCH');
    assert.equal(asserted, 0);
    assert.equal(closed, 0);
    assert.equal(observed, 0);
  } finally {
    await opened?.close();
    await rm(stateRoot, { recursive: true, force: true });
  }
});
