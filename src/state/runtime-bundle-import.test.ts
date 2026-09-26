import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, mkdir, readFile, readdir, rm, stat, writeFile, chmod } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { KERNEL_CAS_DIRECTORY } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { policyProfile, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { PACKAGE_READER_NATIVE_ENTRY_ID, PACKAGE_READER_NATIVE_RELATIVE_PATH } from '../runtime-bundle/native-package-reader.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_PATH, STATE_OWNER_NATIVE_RELATIVE_PATH } from './native-owner.js';
import { openStateStore, type StateStore } from './store.js';
import { makePrivateDir } from './testing/fixtures.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';
const packageReader = fileURLToPath(new URL(`../../dist/${PACKAGE_READER_NATIVE_RELATIVE_PATH}`, import.meta.url));

async function fileIdentity(filePath: string): Promise<{ digest: string; byteCount: number }> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return { digest: hash.digest('hex'), byteCount: (await stat(filePath)).size };
}

async function signedPackage(rootPath: string) {
  const key = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'import-fixture',
    publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const profile = policyProfile();
  const entries: RuntimeBundleManifest['entries'] = [];
  const add = async (entryId: string, role: string, relativePath: string,
    source: string | Buffer, executable: boolean) => {
    const target = path.join(rootPath, relativePath);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    if (typeof source === 'string') await copyFile(source, target);
    else await writeFile(target, source);
    await chmod(target, executable ? 0o500 : 0o400);
    const { digest, byteCount } = await fileIdentity(target);
    entries.push({ entryId, role, version: '1', relativePath, digest, byteCount, executable });
  };
  await add('supervisor', 'supervisor', 'payload/supervisor', process.execPath, true);
  await add('worker', 'worker', 'payload/worker', Buffer.from('fixture worker'), true);
  await add(STATE_OWNER_NATIVE_ENTRY_ID, 'platform_helper', STATE_OWNER_NATIVE_RELATIVE_PATH, STATE_OWNER_NATIVE_PATH, true);
  await add(PACKAGE_READER_NATIVE_ENTRY_ID, 'platform_helper', PACKAGE_READER_NATIVE_RELATIVE_PATH, packageReader, true);
  await add('policy', 'policy_engine', 'payload/policy', canonicalJsonBytes(profile), false);
  await add('default_https_trust_store', 'trust_store', 'payload/trust', Buffer.from('fixture trust'), false);
  await add('sandbox-root', 'sandbox_root_profile', 'payload/root', Buffer.from('fixture root'), false);
  const manifest: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'state-store-import-fixture-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 2 }, workerProtocolRange: { min: 1, max: 1 },
    entries, structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy',
      rootEntryId: 'policy', artifactRef: entries.find((entry) => entry.entryId === 'policy')!.digest,
      semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId,
    manifestDigest: '', signature: ''
  };
  const resign = () => {
    const { signature: _signature, manifestDigest: _digest, ...core } = manifest;
    manifest.manifestDigest = canonicalSha256(core);
    manifest.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifest.manifestDigest}`),
      key.privateKey).toString('base64');
    return canonicalJsonBytes(manifest);
  };
  await writeFile(path.join(rootPath, 'runtime-bundle.json'), resign(), { mode: 0o400 });
  return { manifest, releaseKeys, resign };
}

test('signed StateOwner imports its exact package into real CAS and retains bytes after owner restart',
  { skip: !supported }, async () => {
    const packageRoot = await makePrivateDir('.cliq-package-owner-source-');
    const stateRoot = await makePrivateDir('.cliq-package-owner-state-');
    let store: StateStore | undefined;
    try {
      const fixture = await signedPackage(packageRoot);
      const bundleRef = canonicalSha256(fixture.manifest);
      const policyRef = fixture.manifest.entries.find((entry) => entry.entryId === 'policy')!.digest;
      store = await openStateStore(stateRoot, {
        bundle: fixture.manifest, releaseKeys: fixture.releaseKeys
      });
      const casPath = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
      const importAttempt = store.importRuntimeBundlePackage(packageRoot);
      assert.throws(() => store!.importRuntimeBundlePackage(packageRoot), /already in progress/);
      const closing = store.close();
      assert.equal(await importAttempt, bundleRef);
      await closing;
      assert.deepEqual(await readFile(path.join(casPath, policyRef)), canonicalJsonBytes(policyProfile()));
      assert.equal((await stat(path.join(casPath, fixture.manifest.entries[0]!.digest))).size,
        fixture.manifest.entries[0]!.byteCount);
      store = await openStateStore(stateRoot, {
        bundle: fixture.manifest, releaseKeys: fixture.releaseKeys
      });
      assert.deepEqual(await store.artifacts.readBytes(policyRef), canonicalJsonBytes(policyProfile()));
      const before = await readdir(casPath);
      fixture.manifest.bundleVersion = 'other-signed-version';
      const otherManifest = fixture.resign();
      await chmod(path.join(packageRoot, 'runtime-bundle.json'), 0o600);
      await writeFile(path.join(packageRoot, 'runtime-bundle.json'), otherManifest);
      await chmod(path.join(packageRoot, 'runtime-bundle.json'), 0o400);
      await assert.rejects(store.importRuntimeBundlePackage(packageRoot),
        /package manifest differs from the active signed StateOwner bundle/);
      assert.deepEqual(await readdir(casPath), before);
      assert.notEqual(sha256Bytes(otherManifest), bundleRef);
    } finally {
      await store?.close();
      await rm(packageRoot, { recursive: true, force: true });
      await rm(stateRoot, { recursive: true, force: true });
    }
  });
