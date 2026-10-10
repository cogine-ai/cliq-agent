import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ContentAddressedStore } from './cas.js';
import { createInstalledRuntime } from './installed-runtime.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from './native-owner.js';

/** Real signed files for installer/CAS semantics only. The opaque executable
 * entries are deliberately not running Supervisor/worker/addon images and are
 * never spawned or dlopened. They establish no execution qualification. */
async function writeInstallerOnlyPackage(packageRoot: string, unclosedPromptRole?: 'system_prompt' | 'compaction_prompt') {
  await mkdir(packageRoot, { mode: 0o700 });
  const profile = policyProfile();
  const rootCore = {
    schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'],
    persistent: false, networkConfiguration: 'none',
  };
  const rootRecipe = { ...rootCore, profileDigest: canonicalSha256(rootCore) };
  const contents = [
    { entryId: 'installer-only-supervisor', role: 'supervisor', relativePath: 'supervisor', executable: true,
      bytes: Buffer.from('installer-only opaque Supervisor bytes; not a runnable image\n') },
    { entryId: 'installer-only-worker', role: 'worker', relativePath: 'workers/worker', executable: true,
      bytes: Buffer.from('installer-only opaque worker bytes; not a runnable image\n') },
    { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH,
      executable: true, bytes: Buffer.from('installer-only opaque addon bytes; not a loadable native module\n') },
    { entryId: 'policy-v1', role: 'policy_engine', relativePath: 'profiles/policy.json', executable: false,
      bytes: canonicalJsonBytes(profile) },
    { entryId: 'default_https_trust_store', role: 'trust_store', relativePath: 'profiles/https-trust.pem', executable: false,
      bytes: Buffer.from(rootCertificates.join('\n')) },
    { entryId: 'installer-only-empty-root', role: 'sandbox_root_profile', relativePath: 'profiles/empty-root.json', executable: false,
      bytes: canonicalJsonBytes(rootRecipe) },
  ];
  if (unclosedPromptRole) contents.push({
    entryId: `installer-only-${unclosedPromptRole}`, role: unclosedPromptRole,
    relativePath: `prompts/${unclosedPromptRole}.txt`, executable: false,
    bytes: Buffer.from(`legitimately signed ${unclosedPromptRole} bytes without a structured root\n`),
  });
  const entries: RuntimeBundleManifest['entries'] = [];
  for (const { bytes, ...entry } of contents) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
    entries.push({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength });
  }
  const keys = generateKeyPairSync('ed25519');
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'installer-file-verification-only-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries,
    // The empty-root recipe is an acyclic sandbox_root_profile entry, not
    // resource/permission policy or a new structured-artifact kind. The sole
    // supported structured policy root is self-contained.
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy-v1', rootEntryId: 'policy-v1',
      artifactRef: canonicalSha256(profile), semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: 'explicit-installer-unit-test-root', manifestDigest: '', signature: '',
  };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const releaseKeys = [{ keyId: bundle.publisherKeyId,
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  verifyRuntimeBundle(bundle, releaseKeys);
  await writeFile(path.join(packageRoot, 'manifest.json'), canonicalJsonBytes(bundle), { flag: 'wx', mode: 0o400 });
  return { bundle, releaseKeys, profile, rootRecipe, contents };
}

if (process.platform === 'linux') test('initial installation retains the complete signed package and CAS roots independently of its source, without owning state', async () => {
  // Resolve macOS's /var alias so the fixture itself never requires a symlink
  // traversal. The StateRoot does not exist before the initial installer call.
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-runtime-first-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  try {
    const signed = await writeInstallerOnlyPackage(packageRoot);
    // This factory seam is trusted composition, not a client key/path override.
    // The final SEA bootstrap supplies its compiled-in root; this file does not
    // claim to qualify that entry, actual process images or native execution.
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const bundleBytes = canonicalJsonBytes(signed.bundle);
    const bundleDigest = sha256Bytes(bundleBytes);
    assert.notEqual(bundleDigest, signed.bundle.manifestDigest, 'complete-byte and semantic digest domains are distinct');
    assert.deepEqual(await runtime.installInitial({ packageRoot, stateRoot }), {
      bundleDigest, manifestDigest: signed.bundle.manifestDigest,
    });

    const installation = path.join(stateRoot, 'runtime', 'bundles', bundleDigest);
    const uid = process.geteuid!();
    for (const directory of [stateRoot, path.join(stateRoot, 'runtime'), path.join(stateRoot, KERNEL_CAS_DIRECTORY),
      path.join(stateRoot, 'runtime', 'bundles'), installation]) {
      const metadata = await lstat(directory);
      assert(metadata.isDirectory());
      assert.equal(metadata.uid, uid);
      assert.equal(metadata.mode & 0o7777, 0o700);
    }
    const activePath = path.join(stateRoot, 'runtime', 'active.json');
    const active = await lstat(activePath);
    assert(active.isFile());
    assert.equal(active.uid, uid);
    assert.equal(active.nlink, 1);
    assert.equal(active.mode & 0o7777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(activePath, 'utf8')), { schemaVersion: 1, bundleDigest });
    assert.deepEqual(await readFile(path.join(installation, 'manifest.json')), bundleBytes);
    assert.equal((await lstat(path.join(installation, 'manifest.json'))).mode & 0o7777, 0o400);
    const bootstrapPath = path.join(stateRoot, 'runtime', 'bootstrap');
    const bootstrap = await lstat(bootstrapPath);
    assert(bootstrap.isFile());
    assert.equal(bootstrap.uid, uid);
    assert.equal(bootstrap.nlink, 1);
    assert.equal(bootstrap.mode & 0o7777, 0o500);
    assert.deepEqual(await readFile(bootstrapPath), signed.contents.find(entry => entry.role === 'supervisor')!.bytes);
    for (const entry of signed.contents) {
      const filename = path.join(installation, entry.relativePath);
      const metadata = await lstat(filename);
      assert(metadata.isFile());
      assert.equal(metadata.uid, uid);
      assert.equal(metadata.nlink, 1);
      assert.equal(metadata.mode & 0o7777, entry.executable ? 0o500 : 0o400);
      assert.deepEqual(await readFile(filename), entry.bytes);
    }

    const cas = new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
    for (const bytes of [bundleBytes, canonicalJsonBytes(signed.profile), canonicalJsonBytes(signed.rootRecipe)]) {
      const ref = sha256Bytes(bytes);
      assert.deepEqual(await cas.read(ref), bytes);
      assert.deepEqual(await cas.verify(ref), { ref, byteLength: bytes.byteLength });
    }
    const assertNoStateOwner = async () => {
      await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
      await assert.rejects(lstat(path.join(stateRoot, 'runtime', 'state-owner.lock')), { code: 'ENOENT' });
    };
    await assertNoStateOwner();
    const selected = await runtime.openSelected(stateRoot);
    try {
      assert.equal(selected.bundleDigest, bundleDigest);
      assert.deepEqual(selected.bundle, signed.bundle);
      await selected.assertHeld();
      await rm(packageRoot, { recursive: true });
      await selected.assertHeld();
    } finally { await selected.close(); }
    const reopened = await runtime.openSelected(stateRoot);
    try {
      assert.equal(reopened.bundleDigest, bundleDigest);
      assert.deepEqual(reopened.bundle, signed.bundle);
      await reopened.assertHeld();
    } finally { await reopened.close(); }
    await assertNoStateOwner();
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
else test('unsupported platforms refuse trusted installed-runtime construction without writing a StateRoot', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-runtime-unsupported-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  try {
    const signed = await writeInstallerOnlyPackage(packageRoot);
    const manifestBefore = await readFile(path.join(packageRoot, 'manifest.json'));
    // A real unsupported-platform contract, not a skipped Linux success case.
    // Construction refuses before returning install/open authority or doing IO.
    assert.throws(() => createInstalledRuntime({ releaseKeys: signed.releaseKeys }), { code: 'UNSUPPORTED_PLATFORM' });
    await assert.rejects(lstat(stateRoot), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime', 'active.json')), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    assert.deepEqual(await readFile(path.join(packageRoot, 'manifest.json')), manifestBefore);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') for (const role of ['system_prompt', 'compaction_prompt'] as const) {
  test(`initial installation rejects a signed ${role} entry without a supported structured closure before creating StateRoot`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), `cliq-installed-runtime-${role}-`)));
    await chmod(fixture, 0o700);
    const packageRoot = path.join(fixture, 'package');
    const stateRoot = path.join(fixture, 'state');
    try {
      // All entry bytes, counts and the full manifest are honestly signed. The
      // unchanged sole-policy graph cannot authorize this additional root.
      const signed = await writeInstallerOnlyPackage(packageRoot, role);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      await assert.rejects(runtime.installInitial({ packageRoot, stateRoot }), { code: 'ARTIFACT_MISMATCH' });
      await assert.rejects(lstat(stateRoot), { code: 'ENOENT' });
    } finally { await rm(fixture, { recursive: true, force: true }); }
  });
}
