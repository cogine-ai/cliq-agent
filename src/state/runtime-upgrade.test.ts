import assert from 'node:assert/strict';
import { sign } from 'node:crypto';
import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { testFixture } from '../model/testing/fixtures.js';
import { builtinInputContracts } from '../tools/builtin-inputs.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSignedSchemaConversion, schemaConversionProfile, signedKernelSchemaProfile } from './signed-schema.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner } from './state-owner.js';
import { assertCapturedUpgradeOwnerReleased } from './runtime-upgrade.js';
import { openStateStore } from './store.js';
import { signedToolBundle } from './testing/tool-authority.js';
import { createInstalledQualificationPublisher, qualificationPublisherMaterial } from './testing/qualification-publisher.js';

function resign(bundle: RuntimeBundleManifest, material: ReturnType<typeof qualificationPublisherMaterial>) {
  const copy = structuredClone(bundle); copy.publisherKeyId = material.releaseKeys[0]!.keyId;
  const { signature: _signature, manifestDigest: _digest, ...core } = copy;
  copy.manifestDigest = canonicalSha256(core);
  copy.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${copy.manifestDigest}`), material.privateKey).toString('base64');
  return copy;
}
async function fixture(label: string) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), label))); await chmod(root, 0o700); return root;
}

test('fresh signed8 binds the complete schema in its original owner transaction and retains immutable trusted composition', async () => {
  const root = await fixture('cliq-signed8-birth-'), authority = await signedToolBundle(testFixture().assembly, []);
  const roots = authority.releaseKeys.map(key => ({ ...key }));
  const store = await openStateStore(root, { bundle: authority.bundle, releaseKeys: roots });
  try {
    const originalPem = roots[0]!.publicKeyPem;
    const foreign = qualificationPublisherMaterial(createInstalledQualificationPublisher());
    roots[0]!.publicKeyPem = foreign.releaseKeys[0]!.publicKeyPem;
    roots.push({ keyId: 'foreign', publicKeyPem: foreign.releaseKeys[0]!.publicKeyPem });
    assert.equal(store.artifacts.releaseTrustRoots().length, 1);
    assert.equal(store.artifacts.releaseTrustRoots()[0]!.publicKeyPem, originalPem);
    assert.equal(store.artifacts.withReadSignal(new AbortController().signal).releaseTrustRoots()[0]!.publicKeyPem, originalPem);
    const driver = openSqliteDriver(path.join(root, 'kernel.sqlite3'));
    try {
      const profile = signedKernelSchemaProfile(), schemaRef = canonicalSha256(profile);
      assert(driver.prepare('SELECT ref FROM artifacts WHERE ref=?').get(schemaRef));
      assert.equal(canonicalSha256(await store.artifacts.readCanonical(schemaRef)), schemaRef);
      await readRetainedStateOwnerHistory(driver, store.artifacts, 1);
      const untrusted = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'cas')));
      await assert.rejects(readRetainedStateOwnerHistory(driver, untrusted, 1), { code: 'RECOVERY_REQUIRED' });
    } finally { driver.close(); }
  } finally { await store.close(); await rm(root, { recursive: true, force: true }); }
});

test('a valid publisher signature without the exact full schema cannot mint a new signed8 owner', async () => {
  const initial = await signedToolBundle(testFixture().assembly, []), material = qualificationPublisherMaterial(createInstalledQualificationPublisher());
  for (const mode of ['missing', 'substituted'] as const) {
    const root = await fixture(`cliq-signed8-${mode}-`);
    try {
      const bundle = structuredClone(initial.bundle);
      if (mode === 'missing') bundle.entries = bundle.entries.filter(entry => entry.role !== 'schema');
      else bundle.entries.find(entry => entry.entryId === 'kernel_schema')!.digest = '0'.repeat(64);
      await assert.rejects(openStateStore(root, { bundle: resign(bundle, material), releaseKeys: material.releaseKeys }), { code: 'ARTIFACT_MISMATCH' });
      const driver = openSqliteDriver(path.join(root, 'kernel.sqlite3'));
      try { assert.equal(driver.prepare('SELECT count(*) AS n FROM state_owners').get<{ n: bigint }>()!.n, 0n); }
      finally { driver.close(); }
    } finally { await rm(root, { recursive: true, force: true }); }
  }
});

test('signed conversion uses the original actual public key, never an equal label or a key found in CAS', async () => {
  const root = await fixture('cliq-upgrade-signature-'); await mkdir(path.join(root, 'cas'), { mode: 0o700 });
  try {
    const original = await signedToolBundle(testFixture().assembly, []);
    const material = qualificationPublisherMaterial(createInstalledQualificationPublisher());
    const foreign = qualificationPublisherMaterial(createInstalledQualificationPublisher());
    const sourceCore = structuredClone(original.bundle);
    sourceCore.entries = sourceCore.entries.filter(entry => !['kernel_schema', 'schema_conversion'].includes(entry.entryId));
    const inputSchema = builtinInputContracts.edit.inputSchema;
    sourceCore.entries.push({ entryId: 'installed-edit-input-schema', role: 'schema', version: '1', relativePath: 'schemas/edit.input.json',
      executable: false, digest: canonicalSha256(inputSchema), byteCount: canonicalJsonBytes(inputSchema).length });
    sourceCore.stateSchemaRange = { min: 1, max: 7 };
    const source = resign(sourceCore, material), profile = signedKernelSchemaProfile(), conversion = schemaConversionProfile(source);
    const targetCore = structuredClone(source); targetCore.stateSchemaRange = { min: 8, max: 8 };
    targetCore.entries.push({ entryId: 'kernel_schema', role: 'schema', version: '8', relativePath: 'schema/kernel-v8.json', executable: false,
      digest: canonicalSha256(profile), byteCount: canonicalJsonBytes(profile).length },
    { entryId: 'schema_conversion', role: 'schema', version: '7-to-8', relativePath: 'schema/convert-v7-to-v8.json', executable: false,
      digest: canonicalSha256(conversion), byteCount: canonicalJsonBytes(conversion).length });
    const target = resign(targetCore, material), catalog = new ArtifactCatalog(new ContentAddressedStore(path.join(root, 'cas')), undefined, material.releaseKeys);
    await catalog.publishCanonical(profile, 'cliq-signed-kernel-schema-v1'); await catalog.publishCanonical(conversion, 'cliq-signed-schema-conversion-v1');
    await catalog.publishCanonical(inputSchema, 'cliq-tool-input-schema-v1');
    await catalog.publishCanonical(foreign.releaseKeys, 'untrusted-key-in-CAS');
    assert.equal((await readSignedSchemaConversion(catalog, source, target, catalog.releaseTrustRoots())).profileDigest, conversion.profileDigest);
    for (const entryId of ['kernel_schema', 'schema_conversion']) {
      for (const change of [{ role: 'tool_adapter' }, { executable: true }, { version: 'other' },
        { relativePath: 'schema/unrelated.json' }, { digest: '0'.repeat(64) }, { byteCount: 1 }]) {
        const altered = structuredClone(targetCore);
        Object.assign(altered.entries.find(entry => entry.entryId === entryId)!, change);
        await assert.rejects(readSignedSchemaConversion(catalog, source, resign(altered, material), catalog.releaseTrustRoots()));
      }
      const alteredSource = structuredClone(source);
      alteredSource.entries.push(structuredClone(target.entries.find(entry => entry.entryId === entryId)!));
      assert.throws(() => schemaConversionProfile(resign(alteredSource, material)), { code: 'ARTIFACT_MISMATCH' });
    }
    const replaced = resign(targetCore, foreign); // same keyId; a genuinely different Ed25519 public key.
    await assert.rejects(readSignedSchemaConversion(catalog, source, replaced, catalog.releaseTrustRoots()), /signature/);
    await assert.rejects(readSignedSchemaConversion(catalog, source, target, foreign.releaseKeys), /signature/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('a captured real owner accepts only its own genuine graceful release, not a same-unit successor cut', async () => {
  const root = await fixture('cliq-upgrade-original-owner-');
  let store = await openStateStore(root);
  const driver = openSqliteDriver(path.join(root, 'kernel.sqlite3'));
  try {
    const captured = readLatestStateOwner(driver)!;
    assert.throws(() => assertCapturedUpgradeOwnerReleased(captured, captured), { code: 'RECOVERY_REQUIRED' });
    await store.close();
    const originalRelease = readLatestStateOwner(driver)!;
    assert.doesNotThrow(() => assertCapturedUpgradeOwnerReleased(captured, originalRelease));
    store = await openStateStore(root);
    const successor = readLatestStateOwner(driver)!;
    assert.equal(successor.ownerEpoch, captured.ownerEpoch + 1);
    await store.close(); const successorRelease = readLatestStateOwner(driver)!;
    assert.doesNotThrow(() => assertCapturedUpgradeOwnerReleased(successor, successorRelease));
    assert.throws(() => assertCapturedUpgradeOwnerReleased(captured, successorRelease), { code: 'RECOVERY_REQUIRED' });
    assert.throws(() => assertCapturedUpgradeOwnerReleased(successor, originalRelease), { code: 'RECOVERY_REQUIRED' });
    // This real Store transition proves the exact data-cut refusal. It does
    // not claim to hit the systemd GetAll→StopUnit scheduling race.
  } finally { await store.close(); driver.close(); await rm(root, { recursive: true, force: true }); }
});
