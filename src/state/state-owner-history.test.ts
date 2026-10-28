import assert from 'node:assert/strict';
import { chmod, mkdtemp, realpath, rename, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { digestOmitting } from '../kernel/identity.js';
import { testFixture } from '../model/testing/fixtures.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import type { KernelGenerationIdentityV1, StateOwnerAcquisitionEvidenceV1, StateOwnerRecordV1,
  StateOwnerTransitionEvidenceV1 } from '../kernel/types.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { openStateStore, type StateStore } from './store.js';
import { childFor, ownerAt } from './testing/state-owner-process.js';
import { readStateOwner } from './state-owner.js';
import { signedToolBundle } from './testing/tool-authority.js';
import { createInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { writeInstalledControlPackage } from './testing/installed-control-fixture.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { kernelSchemaBirthRecipe } from './schema.js';

// A real signed ordinary Store and native owner on the current host. This
// tests retained manifest reading, not a Linux installation or execution.
for (const schemaVersion of [1, 2] as const) test(`a signed manifest${schemaVersion} reopens and rewalks both actual owner epochs`, async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-manifest-version-')));
  await chmod(root, 0o700);
  let store: StateStore | undefined;
  try {
    const signed = await signedToolBundle(testFixture().assembly, [], schemaVersion);
    store = await openStateStore(root, signed);
    assert.equal(store.ownerEpoch, 1);
    assert.equal(ownerAt(root).runtimeBundleRef, canonicalSha256(signed.bundle));
    await store.close(); store = undefined;
    store = await openStateStore(root, signed);
    assert.equal(store.ownerEpoch, 2);
    const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
    try {
      const history = await readRetainedStateOwnerHistory(driver, store.artifacts, 2);
      assert.deepEqual(history.entries.map(entry => entry.owner.ownerEpoch), [1, 2]);
      for (const entry of history.entries) {
        assert.equal(entry.owner.runtimeBundleRef, canonicalSha256(signed.bundle));
        assert.equal(entry.owner.runtimeBundleManifestDigest, signed.bundle.manifestDigest);
      }
      driver.transaction(connection => history.assertUnchanged(connection));
      await store.close(); store = undefined;
      assert.throws(() => driver.transaction(connection => history.assertUnchanged(connection)), /history changed before commit/u);
    } finally { driver.close(); }
  } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
});

test('retained manifest2 reading rejects missing, substituted and cross-version custody fields before using the birth', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-manifest-closure-')));
  await chmod(root, 0o700);
  let store: StateStore | undefined;
  try {
    const signed = await signedToolBundle(testFixture().assembly, [], 2);
    store = await openStateStore(root, signed);
    const original = ownerAt(root);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(original.acquisitionEvidenceRef);
    const { installedLayout: _layout, ...missing } = signed.bundle as typeof signed.bundle & { installedLayout: string };
    const malformed = [missing, { ...signed.bundle, installedLayout: 'another-layout' },
      { ...signed.bundle, installedLayout: null }, { ...signed.bundle, extraCustody: true },
      { ...signed.bundle, schemaVersion: 1 }, { ...signed.bundle, schemaVersion: 3 }];
    const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
    try {
      for (const value of malformed) {
        const { signature, manifestDigest: _digest, ...core } = value;
        const replacement = { ...core, manifestDigest: canonicalSha256(core), signature };
        const manifest = await store.artifacts.publishCanonical(replacement, 'cliq-test-rejection-input');
        const changedAcquisition = { ...acquisition, runtimeBundleRef: manifest.ref,
          runtimeBundleManifestDigest: replacement.manifestDigest, evidenceDigest: '' };
        changedAcquisition.evidenceDigest = digestOmitting(changedAcquisition, 'evidenceDigest');
        const acquired = await store.artifacts.publishCanonical(changedAcquisition, acquisition.format);
        const changedOwner = { ...original, runtimeBundleRef: manifest.ref, runtimeBundleManifestDigest: replacement.manifestDigest,
          acquisitionEvidenceRef: acquired.ref, acquisitionEvidenceDigest: changedAcquisition.evidenceDigest, rowDigest: '' };
        changedOwner.rowDigest = digestOmitting(changedOwner, 'rowDigest');
        try {
          replaceRow(driver, changedOwner); // Rejection-only data; never an input to acquire or execute anything.
          await assert.rejects(readRetainedStateOwnerHistory(driver, store.artifacts, 1),
            { code: 'RECOVERY_REQUIRED', message: 'retained StateOwner runtime manifest is invalid' });
        } finally { replaceRow(driver, original); }
      }
      const genuine = await readRetainedStateOwnerHistory(driver, store.artifacts, 1);
      driver.transaction(connection => genuine.assertUnchanged(connection));
    } finally { driver.close(); }
  } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
});

test('reopening rewalks the original process graph beyond the immediate predecessor', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-history-')));
  await chmod(root, 0o700);
  let store: StateStore | undefined;
  let originalProcessRef = '';
  try {
    for (let epoch = 1; epoch <= 3; epoch++) {
      store = await openStateStore(root);
      assert.equal(store.ownerEpoch, epoch);
      if (epoch === 1) originalProcessRef = ownerAt(root).processIdentityRef;
      await store.close(); store = undefined;
    }
    const object = path.join(root, KERNEL_CAS_DIRECTORY, originalProcessRef);
    const retained = path.join(root, 'retained-original-process');
    await rename(object, retained);
    try {
      await assert.rejects(async () => { store = await openStateStore(root); }, { code: 'ENOENT' });
    } finally { await rename(retained, object); }
  } finally {
    await store?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('a historical takeover inspector retains its exact successor witness without following later history', async (t) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-inspector-')));
  await chmod(root, 0o700);
  let store: StateStore | undefined;
  try {
    const first = await childFor(t, root);
    assert.equal((await first.request('acquire')).epoch, 1);
    first.child.kill('SIGKILL'); assert.equal((await first.exited)[1], 'SIGKILL');
    const second = await childFor(t, root);
    assert.equal((await second.request('acquire')).epoch, 2);
    second.child.kill('SIGKILL'); assert.equal((await second.exited)[1], 'SIGKILL');
    store = await openStateStore(root);
    assert.equal(store.ownerEpoch, 3);
    const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
    try {
      const cut = await readRetainedStateOwnerHistory(driver, store.artifacts, 2);
      assert.deepEqual(cut.entries.map(entry => entry.owner.ownerEpoch), [1, 2]);
      assert.equal(cut.entries[1]!.transition?.kind, 'superseded_after_owner_death');
      assert.equal(Reflect.get(cut, 'successorWitness')?.owner.ownerEpoch, 3);
      driver.transaction(connection => cut.assertUnchanged(connection));
      await store.close(); store = undefined;
      assert.throws(() => driver.transaction(connection => cut.assertUnchanged(connection)),
        /retained StateOwner history changed before commit/u);
      store = await openStateStore(root);
      assert.equal(store.ownerEpoch, 4);
      const later = path.join(root, KERNEL_CAS_DIRECTORY, ownerAt(root).processIdentityRef);
      const saved = path.join(root, 'later-process-outside-historical-proof');
      await rename(later, saved);
      try {
        const historical = await readRetainedStateOwnerHistory(driver, store.artifacts, 2);
        assert.equal(historical.successorWitness!.owner.ownerEpoch, 3);
        assert.equal(historical.successorWitness!.owner.state, 'terminal');
        driver.transaction(connection => historical.assertUnchanged(connection));
      } finally { await rename(saved, later); }
    } finally { driver.close(); }
  } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
});

/** Corruption of this disposable database is only a rejection input. No
 * fabricated row is ever used to acquire a Store or authorize native work. */
function replaceRow(driver: SqliteDriver, record: StateOwnerRecordV1): void {
  const trigger = driver.prepare("SELECT sql FROM sqlite_master WHERE name = 'state_owners_validate_update'").get<{ sql: string }>()!.sql;
  driver.transaction(connection => {
    connection.exec('DROP TRIGGER state_owners_validate_update');
    connection.prepare('UPDATE state_owners SET record_json = ?, row_digest = ? WHERE owner_epoch = ?')
      .run(JSON.stringify(record), record.rowDigest, BigInt(record.ownerEpoch));
    connection.exec(trigger);
  });
}

// Test-only regression pending an actual Linux RED. The original installation
// and StateOwner are genuine; only the corrupted retained graph is a refusal
// input. Non-Linux registration never substitutes a portable installed owner.
if (process.platform === 'linux') test('a genuine installed birth cannot omit mandatory signed seed members from a rehashed snapshot', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-installed-seed-')));
  await chmod(fixture, 0o700);
  const stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined, store: StateStore | undefined;
  try {
    const signed = await writeInstalledControlPackage(path.join(fixture, 'package'));
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot: path.join(fixture, 'package'), stateRoot });
    selected = await runtime.openSelected(stateRoot);
    store = await openStateStore(stateRoot, { bundle: selected.bundle, releaseKeys: signed.releaseKeys }, selected);
    const original = ownerAt(stateRoot);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(original.acquisitionEvidenceRef);
    assert(acquisition.kind === 'genesis');
    const generation = await store.artifacts.readCanonical<KernelGenerationIdentityV1>(acquisition.kernelGenerationIdentityRef);
    assert.equal(generation.origin, 'fresh_installed');
    const namespace = await store.artifacts.readCanonical<{ entries: Array<{ artifactRef: string; byteCount: number }>;
      objectCount: number; totalBytes: number; rootDigest: string; manifestDigest: string }>(generation.casNamespaceManifestRef);
    const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const genuine = await readRetainedStateOwnerHistory(driver, store.artifacts, 1);
      assert.equal(genuine.entries[0]!.owner.rowDigest, original.rowDigest);
      driver.transaction(connection => genuine.assertUnchanged(connection));
      for (const role of ['trust_store', 'policy_engine'] as const) {
        const required = signed.bundle.entries.find(entry => entry.role === role)!;
        assert(required && !required.executable);
        const member = namespace.entries.find(entry => entry.artifactRef === required.digest);
        assert(member); assert.equal(member.byteCount, required.byteCount);
        const entries = namespace.entries.filter(entry => entry.artifactRef !== required.digest);
        assert.equal(entries.length, namespace.entries.length - 1);
        const changedNamespace = { ...namespace, entries, objectCount: entries.length,
          totalBytes: namespace.totalBytes - member.byteCount, rootDigest: canonicalSha256(entries), manifestDigest: '' };
        changedNamespace.manifestDigest = digestOmitting(changedNamespace, 'manifestDigest');
        const snapshot = await store.artifacts.publishCanonical(changedNamespace, 'cliq-cas-namespace-manifest-v1');
        const changedGeneration = { ...generation, casNamespaceManifestRef: snapshot.ref,
          casNamespaceManifestDigest: changedNamespace.manifestDigest, casRootDigest: changedNamespace.rootDigest, generationDigest: '' };
        changedGeneration.generationDigest = digestOmitting(changedGeneration, 'generationDigest');
        const birth = await store.artifacts.publishCanonical(changedGeneration, generation.format);
        const changedAcquisition = { ...acquisition, kernelGenerationIdentityRef: birth.ref,
          kernelGenerationIdentityDigest: changedGeneration.generationDigest, evidenceDigest: '' };
        changedAcquisition.evidenceDigest = digestOmitting(changedAcquisition, 'evidenceDigest');
        const acquired = await store.artifacts.publishCanonical(changedAcquisition, acquisition.format);
        const changedOwner = { ...original, acquisitionEvidenceRef: acquired.ref,
          acquisitionEvidenceDigest: changedAcquisition.evidenceDigest, rowDigest: '' };
        changedOwner.rowDigest = digestOmitting(changedOwner, 'rowDigest');
        try {
          replaceRow(driver, changedOwner);
          // The signed package and every actual original CAS payload are
          // unchanged. Self-consistent omission hashes must still be refused.
          await selected.assertHeld();
          for (const object of signed.seedObjects) assert.deepEqual(await store.artifacts.readBytes(object.artifactRef), object.bytes);
          await assert.rejects(readRetainedStateOwnerHistory(driver, store.artifacts, 1),
            error => error instanceof Error && Reflect.get(error, 'code') === 'RECOVERY_REQUIRED',
            `mandatory signed ${role} seed member must remain in the retained birth snapshot`);
        } finally { replaceRow(driver, original); }
      }
    } finally { driver.close(); }
  } finally {
    try { await store?.close(); }
    finally { try { await selected?.close(); } finally { await rm(fixture, { recursive: true, force: true }); } }
  }
});

if (process.platform === 'linux') test('retained installed genesis requires its exact original companion source and complete inventory', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-companion-source-')));
  await chmod(fixture, 0o700);
  const stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined, store: StateStore | undefined;
  try {
    const signed = await writeInstalledControlPackage(path.join(fixture, 'package'), { modelAuthority: true });
    assert(signed.modelAuthority);
    const companion = signed.modelAuthority;
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot: path.join(fixture, 'package'), stateRoot });
    selected = await runtime.openSelected(stateRoot);
    store = await openStateStore(stateRoot, { bundle: selected.bundle, releaseKeys: signed.releaseKeys }, selected);
    const original = ownerAt(stateRoot);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(original.acquisitionEvidenceRef);
    assert(acquisition.kind === 'genesis');
    const generation = await store.artifacts.readCanonical<Record<string, unknown>>(acquisition.kernelGenerationIdentityRef);
    assert.deepEqual(generation.modelAuthoritySource,
      { kind: 'present', closureRef: companion.closureRef, closureDigest: companion.closure.closureDigest });
    assert(typeof generation.casNamespaceManifestRef === 'string');
    const namespace = await store.artifacts.readCanonical<{ entries: Array<{ artifactRef: string; byteCount: number }>;
      objectCount: number; totalBytes: number; rootDigest: string; manifestDigest: string }>(generation.casNamespaceManifestRef);
    const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const genuine = await readRetainedStateOwnerHistory(driver, store.artifacts, 1);
      assert.equal(genuine.entries[0]!.owner.rowDigest, original.rowDigest);
      driver.transaction(connection => genuine.assertUnchanged(connection));
      const artifacts = store.artifacts;
      // Rehashed artifacts/rows below are exclusively rejection inputs. The
      // actual held installation and every original payload remain untouched.
      const refuses = async (changed: Record<string, unknown>, name: string, typedFailure?: RegExp) => {
        const changedGeneration = { ...changed, generationDigest: '' };
        changedGeneration.generationDigest = digestOmitting(changedGeneration, 'generationDigest');
        const birth = await artifacts.publishCanonical(changedGeneration, 'cliq-kernel-generation-identity-v1');
        const changedAcquisition = { ...acquisition, kernelGenerationIdentityRef: birth.ref,
          kernelGenerationIdentityDigest: changedGeneration.generationDigest, evidenceDigest: '' };
        changedAcquisition.evidenceDigest = digestOmitting(changedAcquisition, 'evidenceDigest');
        const acquired = await artifacts.publishCanonical(changedAcquisition, acquisition.format);
        const changedOwner = { ...original, acquisitionEvidenceRef: acquired.ref,
          acquisitionEvidenceDigest: changedAcquisition.evidenceDigest, rowDigest: '' };
        changedOwner.rowDigest = digestOmitting(changedOwner, 'rowDigest');
        try {
          replaceRow(driver, changedOwner);
          await assert.rejects(readRetainedStateOwnerHistory(driver, artifacts, 1),
            error => error instanceof Error && Reflect.get(error, 'code') === 'RECOVERY_REQUIRED' &&
              (!typedFailure || (error.cause instanceof TypeError && typedFailure.test(error.cause.message))), name);
        } finally { replaceRow(driver, original); }
      };
      const { modelAuthoritySource: _source, ...missingSource } = generation;
      await refuses(missingSource, 'a present companion cannot be inferred from CAS when its original source is missing');
      for (const source of [
        { kind: 'none' },
        { kind: 'present', closureRef: companion.closureRef },
        { kind: 'present', closureRef: companion.closureRef, closureDigest: 'f'.repeat(64) },
        { kind: 'none', closureRef: companion.closureRef, closureDigest: companion.closure.closureDigest },
      ]) await refuses({ ...generation, modelAuthoritySource: source }, 'companion source must be exact, unambiguous and inventory-matched');
      const changedSnapshot = async (entries: typeof namespace.entries) => {
        entries = [...entries].sort((left, right) => left.artifactRef < right.artifactRef ? -1 : 1);
        const changed = { ...namespace, entries, objectCount: entries.length,
          totalBytes: entries.reduce((sum, entry) => sum + entry.byteCount, 0), rootDigest: canonicalSha256(entries), manifestDigest: '' };
        changed.manifestDigest = digestOmitting(changed, 'manifestDigest');
        const snapshot = await artifacts.publishCanonical(changed, 'cliq-cas-namespace-manifest-v1');
        return { ...generation, casNamespaceManifestRef: snapshot.ref,
          casNamespaceManifestDigest: changed.manifestDigest, casRootDigest: changed.rootDigest };
      };
      for (const required of [companion.closureRef, ...companion.objects.keys()]) {
        assert(namespace.entries.some(entry => entry.artifactRef === required));
        await refuses(await changedSnapshot(namespace.entries.filter(entry => entry.artifactRef !== required)),
          'every original companion root/catalog/price/signature must remain in the retained birth inventory');
      }
      const extra = await artifacts.publishCanonical({ fixture: 'unowned-companion-inventory-member' }, 'cliq-test-rejection-input');
      const extraEntry = { artifactRef: extra.ref, byteCount: extra.byteLength };
      await refuses(await changedSnapshot([...namespace.entries, extraEntry]), 'a retained companion inventory cannot add an unowned object');
      const catalog = companion.closure.objects.find(object => object.kind === 'model_catalog_entry')!;
      await refuses(await changedSnapshot(namespace.entries.map(entry => entry.artifactRef === catalog.artifactRef ? extraEntry : entry)),
        'a retained companion inventory cannot substitute another honestly published object');
      // Keep source, namespace and every omission digest mutually consistent,
      // but remove the catalog inside the companion. This must reach typed
      // catalog/price closure validation, not just namespace equality checks.
      const { closureDigest: _digest, signature: _signature, ...companionCore } = companion.closure;
      const reducedCore = { ...companionCore, objects: companion.closure.objects.filter(object => object.kind !== 'model_catalog_entry') };
      const reduced = { ...reducedCore, closureDigest: canonicalSha256(reducedCore), signature: companion.closure.signature };
      const reducedArtifact = await artifacts.publishCanonical(reduced, reduced.format);
      const base = namespace.entries.filter(entry => entry.artifactRef !== companion.closureRef && !companion.objects.has(entry.artifactRef));
      const reducedSnapshot = await changedSnapshot([...base,
        { artifactRef: reducedArtifact.ref, byteCount: reducedArtifact.byteLength },
        ...reduced.objects.map(({ artifactRef, byteCount }) => ({ artifactRef, byteCount }))]);
      await refuses({ ...reducedSnapshot,
        modelAuthoritySource: { kind: 'present', closureRef: reducedArtifact.ref, closureDigest: reduced.closureDigest } },
        'a self-consistent retained source and namespace cannot replace a complete catalog/price closure',
        /model authority tuple or signature inventory is incomplete/u);
      await selected.assertHeld();
      for (const object of signed.seedObjects) assert.deepEqual(await artifacts.readBytes(object.artifactRef), object.bytes);
      const restored = await readRetainedStateOwnerHistory(driver, artifacts, 1);
      assert.equal(restored.entries[0]!.owner.rowDigest, original.rowDigest);
      driver.transaction(connection => restored.assertUnchanged(connection));
    } finally { driver.close(); }
  } finally {
    try { await store?.close(); }
    finally { try { await selected?.close(); } finally { await rm(fixture, { recursive: true, force: true }); } }
  }
});

test('retained signed owners bind the selected executable identity without inventing executable CAS objects', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-signed-history-')));
  await chmod(root, 0o700);
  const authority = await signedToolBundle(testFixture().assembly, []);
  let store: StateStore | undefined;
  try {
    store = await openStateStore(root, authority); await store.close(); store = undefined;
    store = await openStateStore(root, authority);
    const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
    try {
      const cut = await readRetainedStateOwnerHistory(driver, store.artifacts, 2);
      assert.equal(cut.entries[0]!.owner.runtimeBundleRef, cut.entries[1]!.owner.runtimeBundleRef);
      assert.equal(cut.entries[0]!.process.executableImageDigest,
        authority.bundle.entries.find(entry => entry.role === 'supervisor')!.digest);
      await assert.rejects(store.artifacts.readBytes(cut.entries[0]!.owner.supervisorExecutableDigest), { code: 'ENOENT' });
      driver.transaction(connection => cut.assertUnchanged(connection));
    } finally { driver.close(); }
  } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
});

test('a rehashed grandparent takeover cannot substitute its original successor identity', async (t) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-grandparent-')));
  await chmod(root, 0o700);
  let store: StateStore | undefined;
  try {
    const child = await childFor(t, root);
    assert.equal((await child.request('acquire')).epoch, 1);
    child.child.kill('SIGKILL'); assert.equal((await child.exited)[1], 'SIGKILL');
    store = await openStateStore(root); await store.close(); store = undefined;
    store = await openStateStore(root);
    const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
    const originals = [1, 2, 3].map(epoch => readStateOwner(driver, epoch)!);
    try {
      const first = originals[0]!; assert(first.state === 'terminal');
      const transition = await store.artifacts.readCanonical<StateOwnerTransitionEvidenceV1>(first.transitionEvidenceRef);
      assert(transition.kind === 'superseded_after_owner_death');
      const forged = { ...transition, successorInstanceNonceDigest: 'f'.repeat(64), evidenceDigest: '' };
      forged.evidenceDigest = digestOmitting(forged, 'evidenceDigest');
      const artifact = await store.artifacts.publishCanonical(forged, forged.format);
      let previous: StateOwnerRecordV1 = { ...first, transitionEvidenceRef: artifact.ref,
        transitionEvidenceDigest: forged.evidenceDigest, rowDigest: '' };
      previous.rowDigest = digestOmitting(previous, 'rowDigest');
      replaceRow(driver, previous);
      for (const original of originals.slice(1)) {
        assert(previous.state === 'terminal');
        const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(original.acquisitionEvidenceRef);
        assert(acquisition.kind !== 'genesis');
        const changed: Exclude<StateOwnerAcquisitionEvidenceV1, { kind: 'genesis' }> = { ...acquisition, priorTerminalRowDigest: previous.rowDigest,
          priorTransitionEvidenceRef: previous.transitionEvidenceRef, priorTransitionEvidenceDigest: previous.transitionEvidenceDigest,
          evidenceDigest: '' };
        changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest');
        const next = await store.artifacts.publishCanonical(changed, changed.format);
        previous = { ...original, acquisitionEvidenceRef: next.ref, acquisitionEvidenceDigest: changed.evidenceDigest, rowDigest: '' };
        previous.rowDigest = digestOmitting(previous, 'rowDigest'); replaceRow(driver, previous);
      }
      await assert.rejects(readRetainedStateOwnerHistory(driver, store.artifacts, 3),
        /transition evidence does not match its prior\/successor/u);
    } finally {
      for (const original of originals) replaceRow(driver, original);
      driver.close();
    }
  } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
});

for (const runtimeKind of ['schema-only', 'signed'] as const)
  test(`retained ${runtimeKind} genesis rejects a self-rehashed known older birth from a real Store`, async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-birth-source-')));
    await chmod(root, 0o700);
    let store: StateStore | undefined;
    try {
      const authority = runtimeKind === 'signed' ? await signedToolBundle(testFixture().assembly, []) : undefined;
      store = await openStateStore(root, authority);
      const original = ownerAt(root);
      const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(original.acquisitionEvidenceRef);
      assert(acquisition.kind === 'genesis');
      const generation = await store.artifacts.readCanonical<KernelGenerationIdentityV1>(acquisition.kernelGenerationIdentityRef);
      assert.equal(generation.origin, 'fresh_empty');
      const prior = kernelSchemaBirthRecipe(6);
      assert.equal(generation.stateSchemaVersion, KERNEL_STATE_SCHEMA_VERSION);
      assert(prior.userVersion < generation.stateSchemaVersion);
      const originalSchema = await store.artifacts.readCanonical<{ userVersion: number; schemaDigest: string; manifestDigest: string }>(
        generation.pristineSchemaManifestRef);
      const schema = { ...originalSchema, userVersion: prior.userVersion, schemaDigest: prior.schemaDigest, manifestDigest: '' };
      schema.manifestDigest = digestOmitting(schema, 'manifestDigest');
      const schemaArtifact = await store.artifacts.publishCanonical(schema, 'cliq-kernel-schema-manifest-v1');
      const originalDatabase = await store.artifacts.readCanonical<{ userVersion: number; contentDigest: string }>(generation.databaseImageRef);
      const database = { ...originalDatabase, userVersion: prior.userVersion, contentDigest: prior.emptyDatabaseContentDigest };
      const databaseArtifact = await store.artifacts.publishCanonical(database, 'cliq-kernel-empty-database-v1');
      const changedGeneration = { ...generation, stateSchemaVersion: prior.userVersion,
        pristineSchemaManifestRef: schemaArtifact.ref, pristineSchemaManifestDigest: schema.manifestDigest,
        pristineSchemaDigest: prior.schemaDigest, databaseImageRef: databaseArtifact.ref,
        databaseImageDigest: databaseArtifact.ref, databaseIdentityDigest: databaseArtifact.ref,
        databaseContentDigest: prior.emptyDatabaseContentDigest, generationDigest: '' };
      changedGeneration.generationDigest = digestOmitting(changedGeneration, 'generationDigest');
      const birth = await store.artifacts.publishCanonical(changedGeneration, generation.format);
      const changedAcquisition = { ...acquisition, kernelGenerationIdentityRef: birth.ref,
        kernelGenerationIdentityDigest: changedGeneration.generationDigest, evidenceDigest: '' };
      changedAcquisition.evidenceDigest = digestOmitting(changedAcquisition, 'evidenceDigest');
      const acquired = await store.artifacts.publishCanonical(changedAcquisition, acquisition.format);
      const changedOwner = { ...original, acquisitionEvidenceRef: acquired.ref,
        acquisitionEvidenceDigest: changedAcquisition.evidenceDigest, rowDigest: '' };
      changedOwner.rowDigest = digestOmitting(changedOwner, 'rowDigest');
      const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
      try {
        const genuine = await readRetainedStateOwnerHistory(driver, store.artifacts, 1);
        driver.transaction(connection => genuine.assertUnchanged(connection));
        try {
          // Only the disposable refusal input changes; the original runtime,
          // genuine native owner and current database schema remain untouched.
          replaceRow(driver, changedOwner);
          await assert.rejects(readRetainedStateOwnerHistory(driver, store.artifacts, 1), error =>
            error instanceof Error && Reflect.get(error, 'code') === 'RECOVERY_REQUIRED' &&
            (runtimeKind === 'schema-only' ? /original runtime schema/u : /original schema authority/u).test(error.message));
        } finally {
          replaceRow(driver, original);
          const restored = await readRetainedStateOwnerHistory(driver, store.artifacts, 1);
          assert.equal(restored.entries[0]!.owner.rowDigest, original.rowDigest);
          driver.transaction(connection => restored.assertUnchanged(connection));
        }
      } finally { driver.close(); }
    } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
  });

for (const fault of ['generation_digest', 'unsupported_origin', 'unsupported_schema', 'foreign_root', 'extra_field'] as const)
  test(`retained genesis rejects a self-rehashed ${fault} graph from a real birth`, async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-invalid-birth-')));
    await chmod(root, 0o700);
    let store: StateStore | undefined;
    try {
      store = await openStateStore(root);
      const original = ownerAt(root);
      const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(original.acquisitionEvidenceRef);
      assert(acquisition.kind === 'genesis');
      const generation = await store.artifacts.readCanonical<KernelGenerationIdentityV1>(acquisition.kernelGenerationIdentityRef);
      const changed: Record<string, unknown> = { ...generation };
      if (fault === 'generation_digest') changed.generationDigest = 'f'.repeat(64);
      if (fault === 'unsupported_origin') changed.origin = 'migrated_candidate';
      if (fault === 'unsupported_schema') changed.stateSchemaVersion = generation.stateSchemaVersion + 1;
      if (fault === 'foreign_root') changed.stateRootIdentityDigest = 'f'.repeat(64);
      if (fault === 'extra_field') changed.unpublishedAuthority = true;
      if (fault !== 'generation_digest') changed.generationDigest = digestOmitting(changed, 'generationDigest');
      const changedGeneration = await store.artifacts.publishCanonical(changed, generation.format);
      const replacementAcquisition = { ...acquisition, kernelGenerationIdentityRef: changedGeneration.ref,
        kernelGenerationIdentityDigest: changed.generationDigest, evidenceDigest: '' };
      replacementAcquisition.evidenceDigest = digestOmitting(replacementAcquisition, 'evidenceDigest');
      const artifact = await store.artifacts.publishCanonical(replacementAcquisition, acquisition.format);
      const replacement = { ...original, acquisitionEvidenceRef: artifact.ref,
        acquisitionEvidenceDigest: replacementAcquisition.evidenceDigest, rowDigest: '' };
      replacement.rowDigest = digestOmitting(replacement, 'rowDigest');
      const driver = openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
      try {
        replaceRow(driver, replacement);
        await assert.rejects(readRetainedStateOwnerHistory(driver, store.artifacts, 1),
          error => error instanceof Error && Reflect.get(error, 'code') === 'RECOVERY_REQUIRED');
      } finally { replaceRow(driver, original); driver.close(); }
    } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
  });

test('reopening requires the retained genesis birth graph rather than just a genesis label', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-birth-')));
  await chmod(root, 0o700);
  let store: StateStore | undefined;
  try {
    store = await openStateStore(root);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(ownerAt(root).acquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'genesis'); assert(acquisition.kind === 'genesis');
    const object = path.join(root, KERNEL_CAS_DIRECTORY, acquisition.kernelGenerationIdentityRef);
    const retained = path.join(root, 'retained-generation-birth');
    await store.close(); store = undefined;
    await rename(object, retained);
    try {
      await assert.rejects(async () => { store = await openStateStore(root); }, { code: 'ENOENT' });
    } finally { await rename(retained, object); }
  } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
});

test('the retained cut binds the original root and detects a real graceful owner transition', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-owner-cut-')));
  await chmod(root, 0o700);
  let store: StateStore | undefined;
  const inspect = () => openSqliteDriver(path.join(root, KERNEL_DATABASE_FILENAME));
  try {
    store = await openStateStore(root); await store.close(); store = undefined;
    store = await openStateStore(root);
    const driver = inspect();
    try {
      const cut = await readRetainedStateOwnerHistory(driver, store.artifacts, 2);
      assert.deepEqual(cut.entries.map(entry => [entry.owner.ownerEpoch, entry.owner.state, entry.acquisition.kind]),
        [[1, 'terminal', 'genesis'], [2, 'active', 'acquire_after_graceful_release']]);
      assert.equal(Reflect.get(cut, 'rootIdentity')?.canonicalAbsolutePath, root);
      assert(Object.isFrozen(cut)); assert(Object.isFrozen(cut.entries)); assert(Object.isFrozen(cut.entries[0]!.owner));
      driver.transaction(connection => cut.assertUnchanged(connection));
      await store.close(); store = undefined;
      assert.throws(() => driver.transaction(connection => cut.assertUnchanged(connection)),
        /retained StateOwner history changed before commit/u);
    } finally { driver.close(); }
  } finally { await store?.close(); await rm(root, { recursive: true, force: true }); }
});
