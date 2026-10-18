import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, sha256Bytes } from '../kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore } from './cas.js';
import { assertInstalledManagerObservationAvailable, createInstalledRuntime, loadInstalledCredentialPlatform, loadInstalledManagerObserver,
  type HeldInstalledRuntime } from './installed-runtime.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from './native-owner.js';
import { openInstalledLinuxWorkerLauncher } from '../sandbox/linux-worker.js';
import { KernelStorageError } from './errors.js';
import { GUEST_EXTRACTOR_RECIPE } from '../sandbox/guest-toolchain.js';
import { observeInstalledCredentialSupervisor } from './installed-services.js';

/** Real signed files for installer/CAS semantics only. The opaque executable
 * entries are deliberately not running Supervisor/worker/addon images and are
 * never spawned or dlopened. They establish no execution qualification. */
async function writeInstallerOnlyPackage(packageRoot: string, unclosedPromptRole?: 'system_prompt' | 'compaction_prompt',
  supervisorBytes?: Buffer, guestImageBytes?: Buffer) {
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
      bytes: supervisorBytes ?? Buffer.from('installer-only opaque Supervisor bytes; not a runnable image\n') },
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
  const keys = generateKeyPairSync('ed25519');
  let guestRoot: RuntimeBundleManifest['structuredArtifacts'][number] | undefined;
  let guestManifestRef: string | undefined;
  if (guestImageBytes) {
    // Opaque signed data only: these bytes are neither ext4/ELF nor an
    // executable qualification. The installer must still retain their exact
    // complete signed closure through the real bounded CAS stream.
    const imageRef = sha256Bytes(guestImageBytes);
    const executable = (logicalName: string, canonicalGuestPath: string) => ({ logicalName, canonicalGuestPath,
      version: 'installer-data-only', digest: sha256Bytes(Buffer.from(logicalName)) });
    const core = { schemaVersion: 1, format: 'cliq-guest-toolchain-v1', guestImageRef: imageRef,
      guestImageDigest: imageRef, guestImageByteCount: guestImageBytes.length, guestImageFormat: 'raw-ext4-v1',
      architecture: 'x86_64', kernelAbi: 'linux-x86_64-v1', userspaceAbi: 'linux-x86_64-glibc-v1',
      worker: executable('cliq-worker', '/runtime/cliq-linux-worker'), shell: executable('sh', '/bin/sh'),
      git: executable('git', '/usr/bin/git'), node: executable('node', '/usr/bin/node'),
      searchTools: [], verifiers: [], admittedExecutables: [], publisherKeyId: 'explicit-installer-unit-test-root' };
    const manifestDigest = canonicalSha256(core);
    const signature = sign(null, Buffer.from(`cliq-guest-toolchain-v1\0${manifestDigest}`), keys.privateKey);
    const signatureRef = sha256Bytes(signature);
    const manifestBytes = canonicalJsonBytes({ ...core, manifestDigest, signatureRef });
    guestManifestRef = sha256Bytes(manifestBytes);
    const rootEntryId = 'installer-only-guest-root';
    guestRoot = { kind: 'guest_toolchain', artifactId: 'installer-only-guest', rootEntryId,
      artifactRef: guestManifestRef, semanticDigest: manifestDigest, memberRefs: [imageRef, signatureRef].sort() };
    contents.push({ entryId: rootEntryId, role: 'guest_toolchain', relativePath: 'profiles/guest.json',
      executable: false, bytes: manifestBytes },
    { entryId: GUEST_EXTRACTOR_RECIPE.entryId, role: 'platform_helper', relativePath: GUEST_EXTRACTOR_RECIPE.relativePath,
      executable: true, bytes: Buffer.from('installer-only opaque guest extractor; never loaded\n') },
    ...[{ ref: imageRef, bytes: guestImageBytes }, { ref: signatureRef, bytes: signature }].map(({ ref, bytes }) => ({
      entryId: identityHash('runtime-bundle-object-v1', ref), role: 'bundle_object',
      relativePath: `objects/sha256/${ref.slice(0, 2)}/${ref}`, executable: false, bytes })));
  }
  const entries: RuntimeBundleManifest['entries'] = [];
  for (const { bytes, ...entry } of contents) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
    entries.push({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength });
  }
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'installer-file-verification-only-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries,
    // The empty-root recipe is an acyclic sandbox_root_profile entry, not
    // resource/permission policy or a new structured-artifact kind. The sole
    // supported structured policy root is self-contained.
    structuredArtifacts: [...(guestRoot ? [guestRoot] : []), { kind: 'policy_engine_profile', artifactId: 'policy-v1', rootEntryId: 'policy-v1',
      artifactRef: canonicalSha256(profile), semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: guestManifestRef ? [guestManifestRef] : [], publisherKeyId: 'explicit-installer-unit-test-root', manifestDigest: '', signature: '',
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

test('installed read-only manager observation rejects structural selections before inspecting caller properties', () => {
  let inspected = false;
  const fake = new Proxy({}, { get() { inspected = true; throw new Error('caller property was inspected'); } });
  assert.throws(() => loadInstalledManagerObserver(fake as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  assert.throws(() => assertInstalledManagerObservationAvailable(fake as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(inspected, false);
});

if (process.platform === 'linux') test('readiness hints cannot outlive a genuine selected runtime close', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-readiness-close-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  try {
    const signed = await writeInstallerOnlyPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    // This is only a genuine held-selection lifetime/metadata gate. Opaque
    // fixture executables are never loaded or treated as manager readiness.
    assert.doesNotThrow(() => assertInstalledManagerObservationAvailable(selected!));
    const closing = selected.close();
    assert.throws(() => assertInstalledManagerObservationAvailable(selected!), {
      code: 'ARTIFACT_MISMATCH', message: 'installed runtime handle is closed'
    });
    await closing;
    assert.throws(() => assertInstalledManagerObservationAvailable(selected!), { code: 'ARTIFACT_MISMATCH' });
    selected = undefined;
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
  } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux' && process.arch === 'x64') test('ordinary installed manager observation requires its actual signed addon without granting credential authority', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-manager-observer-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  try {
    // Genuine signed installation, deliberately without a native platform.
    // No successful manager observation or native qualification is asserted.
    const signed = await writeInstallerOnlyPackage(packageRoot);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    const noPlatform = (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
      error.message === 'fixed signed credential platform module is missing';
    // This must reach the actual signed-entry check, not the unrelated SEA
    // credential-authority gate that formerly rejected every ordinary client.
    await assert.rejects(loadInstalledManagerObserver(selected), noPlatform);
    await assert.rejects(observeInstalledCredentialSupervisor(selected), noPlatform);
    await assert.rejects(observeInstalledCredentialSupervisor(selected, true), { code: 'UNSUPPORTED_PLATFORM' });
    await assert.rejects(loadInstalledCredentialPlatform(selected), { code: 'UNSUPPORTED_PLATFORM' });
    const copy = { ...selected };
    assert.throws(() => loadInstalledManagerObserver(copy), { code: 'ARTIFACT_MISMATCH' });
    await selected.close(); selected = undefined;
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
  } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('initial installation streams a complete signed guest image across the unchanged CAS chunk bound', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-guest-stream-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  try {
    const image = Buffer.alloc(ARTIFACT_CHUNK_BYTES + 17, 0x61);
    image.fill(0x62, ARTIFACT_CHUNK_BYTES); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installed = await runtime.installInitial({ packageRoot, stateRoot });
    const imageRef = sha256Bytes(image);
    const entry = signed.bundle.entries.find(entry => entry.digest === imageRef)!;
    const installedFile = path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, entry.relativePath);
    const cas = new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
    assert.deepEqual(await readFile(installedFile), image);
    assert.deepEqual(await cas.verify(imageRef), { ref: imageRef, byteLength: image.length });
    assert.deepEqual(await cas.read(imageRef), image);
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/state-owner.lock')), { code: 'ENOENT' });
    await rm(packageRoot, { recursive: true });
    const selected = await runtime.openSelected(stateRoot);
    try {
      await selected.assertHeld();
      assert.deepEqual(selected.bundle, signed.bundle);
      assert.deepEqual(await cas.read(imageRef), image);
    } finally { await selected.close(); }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('initial installation retains the complete signed package and CAS roots independently of its source, without owning state', async () => {
  // Resolve macOS's /var alias so the fixture itself never requires a symlink
  // traversal. The StateRoot does not exist before the initial installer call.
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-runtime-first-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  try {
    // Exercise complete streaming copy/hash and a partial final batch using opaque
    // signed data, never an executable or installed execution qualification.
    const supervisorBytes = Buffer.alloc(2 * 1_048_576 + 17, 0x61);
    supervisorBytes.fill(0x63, 1_048_576, 2 * 1_048_576);
    supervisorBytes[supervisorBytes.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, supervisorBytes);
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
      let observed = 0;
      const untrusted = () => { observed++; throw new Error('untrusted anchor property'); };
      const proxy = new Proxy({}, { get: untrusted, getPrototypeOf: untrusted, ownKeys: untrusted,
        getOwnPropertyDescriptor: untrusted });
      const anchorShape = { assertHeld() {}, close() {} };
      for (const anchor of [undefined, {}, proxy, { ...anchorShape }, structuredClone({})]) {
        // The selection is genuine but these anchors are not. Refusal must
        // precede dlopen of this deliberately opaque installer-only package.
        await assert.rejects(() => openInstalledLinuxWorkerLauncher(selected, anchor as never),
          error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
            error.message === 'installed anchor does not belong to this exact held selection');
      }
      for (const copy of [{ ...selected }, structuredClone({ bundle: selected.bundle, bundleDigest: selected.bundleDigest })]) {
        await assert.rejects(() => openInstalledLinuxWorkerLauncher(copy as never, proxy as never),
          error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
            error.message === 'installed runtime is not a verified held selection');
      }
      assert.equal(observed, 0);
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

if (process.platform === 'linux') test('initial installation rejects corruption at the end of a large signed entry before creating StateRoot', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-runtime-tail-')));
  await chmod(fixture, 0o700);
  const packageRoot = path.join(fixture, 'package');
  const stateRoot = path.join(fixture, 'state');
  try {
    const bytes = Buffer.alloc(2 * 1_048_576 + 17, 0x61);
    bytes.fill(0x63, 1_048_576, 2 * 1_048_576);
    bytes[bytes.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, bytes);
    const filename = path.join(packageRoot, 'supervisor');
    const corrupt = Buffer.from(bytes);
    corrupt[corrupt.length - 1] = 0x62;
    await chmod(filename, 0o700);
    await writeFile(filename, corrupt);
    await chmod(filename, 0o500);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await assert.rejects(runtime.installInitial({ packageRoot, stateRoot }), error =>
      error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
      error.message === 'installed runtime signed file digest differs');
    await assert.rejects(lstat(stateRoot), { code: 'ENOENT' });
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
