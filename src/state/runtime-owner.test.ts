import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readdir, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { PlatformProcessIdentityV1, StateOwnerAcquisitionEvidenceV1 } from '../kernel/types.js';
import { testFixture } from '../model/testing/fixtures.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner } from './state-owner.js';
import { openStateStore, type StateStore, type StateStoreRuntimeAuthority } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';
import { signedToolBundle } from './testing/tool-authority.js';

function resign(bundle: RuntimeBundleManifest): StateStoreRuntimeAuthority {
  const keys = generateKeyPairSync('ed25519');
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  return { bundle, releaseKeys: [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }] };
}
function ownerAt(stateRoot: string) {
  const reader = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try { return readLatestStateOwner(reader)!; } finally { reader.close(); }
}

test('signed state-owner bootstrap authenticates the actual process before publishing authority', async () => {
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-bootstrap-');
  let store: StateStore | undefined;
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    const altered = structuredClone(authority.bundle);
    altered.entries.find(entry => entry.role === 'supervisor')!.digest = canonicalSha256('another executable');
    await assert.rejects(openStateStore(stateRoot, resign(altered)), /does not match this process/);
    const incompatible = structuredClone(authority.bundle);
    incompatible.stateSchemaRange = { min: 99, max: 99 };
    await assert.rejects(openStateStore(stateRoot, resign(incompatible)), /state schema/);
    await assert.rejects(openStateStore(stateRoot, { ...authority, releaseKeys: [] }), /trusted release signature/);
    const unsigned = structuredClone(authority.bundle);
    unsigned.bundleVersion = 'altered after signing';
    await assert.rejects(openStateStore(stateRoot, { ...authority, bundle: unsigned }), /RuntimeBundle identity/);
    assert.deepEqual(await readdir(stateRoot), []);

    // Snapshot all trusted bootstrap input before its first asynchronous process/filesystem read.
    const expectedBundle = structuredClone(authority.bundle);
    const opening = openStateStore(stateRoot, authority);
    authority.bundle.entries[0]!.digest = canonicalSha256('mutated caller input');
    store = await opening;
    const owner = ownerAt(stateRoot);
    const supervisor = expectedBundle.entries.find(entry => entry.role === 'supervisor')!;
    assert.equal(owner.runtimeBundleRef, canonicalSha256(expectedBundle));
    assert.equal(owner.runtimeBundleManifestDigest, expectedBundle.manifestDigest);
    assert.equal(owner.supervisorEntryId, supervisor.entryId);
    assert.equal(owner.supervisorEntryVersion, supervisor.version);
    assert.equal(owner.supervisorExecutableDigest, supervisor.digest);
    const process = await store.artifacts.readCanonical<PlatformProcessIdentityV1>(owner.processIdentityRef);
    assert.equal(process.executableImageDigest, supervisor.digest);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(owner.acquisitionEvidenceRef);
    assert.equal(acquisition.evidenceDigest, digestOmitting(acquisition, 'evidenceDigest'));
    assert.equal(acquisition.runtimeBundleRef, owner.runtimeBundleRef);
    assert.equal(acquisition.instanceNonceDigest, owner.instanceNonceDigest);
    assert.equal(acquisition.kind, 'genesis');
  } finally { await store?.close(); await rm(stateRoot, { recursive: true, force: true }); }
});

test('signed-owner reopen requires explicit trusted roots and the same runtime, with a fresh owner nonce', async () => {
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-reopen-');
  let store: StateStore | undefined;
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    store = await openStateStore(stateRoot, authority);
    const first = ownerAt(stateRoot);
    await store.close();
    const released = ownerAt(stateRoot);
    await assert.rejects(openStateStore(stateRoot), /same signed Supervisor authority/);
    await assert.rejects(openStateStore(stateRoot, { ...authority, releaseKeys: [] }), /trusted release signature/);
    const changed = structuredClone(authority.bundle);
    changed.bundleVersion = 'new unadmitted runtime';
    await assert.rejects(openStateStore(stateRoot, resign(changed)), /runtime upgrades need their own transition/);
    assert.deepEqual(ownerAt(stateRoot), released);
    const writer = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    const forged = { ...released, supervisorEntryVersion: 'foreign-entry', rowDigest: '' };
    forged.rowDigest = digestOmitting(forged, 'rowDigest');
    const trigger = writer.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'state_owners_validate_update'").get<{ sql: string }>()!.sql;
    // Deliberate corruption in this disposable database; normal writers cannot rewrite historical owners.
    const rewrite = (value: typeof released) => writer.transaction((connection) => {
      connection.exec('DROP TRIGGER state_owners_validate_update');
      connection.prepare('UPDATE state_owners SET record_json = ?, row_digest = ? WHERE owner_epoch = ?')
        .run(JSON.stringify(value), value.rowDigest, BigInt(value.ownerEpoch));
      connection.exec(trigger);
    });
    try {
      rewrite(forged);
      await assert.rejects(openStateStore(stateRoot, authority), /same signed Supervisor authority/);
    } finally { rewrite(released); writer.close(); }
    store = await openStateStore(stateRoot, authority);
    const second = ownerAt(stateRoot);
    assert.equal(second.ownerEpoch, first.ownerEpoch + 1);
    assert.equal(second.runtimeBundleRef, first.runtimeBundleRef);
    assert.equal(second.supervisorExecutableDigest, first.supervisorExecutableDigest);
    assert.notEqual(second.instanceNonceDigest, first.instanceNonceDigest);
    const acquisition = await store.artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(second.acquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'acquire_after_graceful_release');
    assert.equal(acquisition.instanceNonceDigest, second.instanceNonceDigest);
  } finally { await store?.close(); await rm(stateRoot, { recursive: true, force: true }); }
});

test('signed-owner reopen refuses a missing retained runtime before committing a successor', async () => {
  const stateRoot = await makePrivateDir('.cliq-runtime-owner-missing-');
  let store: StateStore | undefined;
  try {
    const authority = await signedToolBundle(testFixture().assembly, []);
    store = await openStateStore(stateRoot, authority);
    await store.close();
    const released = ownerAt(stateRoot);
    const retained = path.join(stateRoot, KERNEL_CAS_DIRECTORY, released.runtimeBundleRef);
    const saved = path.join(stateRoot, 'saved-runtime');
    await rename(retained, saved);
    try {
      await assert.rejects(async () => { store = await openStateStore(stateRoot, authority); }, { code: 'ENOENT' });
      assert.deepEqual(ownerAt(stateRoot), released);
    } finally { await rename(saved, retained); }
    store = await openStateStore(stateRoot, authority);
    assert.equal(ownerAt(stateRoot).ownerEpoch, released.ownerEpoch + 1);
  } finally { await store?.close(); await rm(stateRoot, { recursive: true, force: true }); }
});
