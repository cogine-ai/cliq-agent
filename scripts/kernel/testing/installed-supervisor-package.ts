// Qualification-only signed package recipe, not a release publisher or I1.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { rootCertificates } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';

import { KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../../src/state/native-owner.js';
import { buildSupervisorSeaImage, prepareInstalledSupervisorSeaCarrier } from './supervisor-sea-builder.js';
import { installedModelPackageEntries, writeInstalledModelAuthority, type InstalledModelPackageFixture } from './installed-model-package.js';
import { writeInstalledGuestToolchain } from './installed-guest-package.js';
import { validateGuestToolchainMetadata } from '../../../src/state/guest-toolchain.js';

/** Construct the same actual SEA/helper package for independent Linux startup
 * and user-manager qualifiers. Real worker images are installed, not launched:
 * they do not qualify admission, execution, release signing or complete I1. */
export async function buildInstalledSupervisorPackage(fixture: string,
  variant: 'complete' | 'retirement-native-missing' = 'complete', modelFixture?: InstalledModelPackageFixture,
  options: Readonly<{ guestToolchain?: 'node-test-v1'; guestImageProfile?: 'qualification_max'; publicationRetirementDiagnostics?: true; credentialPhaseDiagnostics?: true; serverAuthenticationDiagnostics?: true; storeFailureDiagnostics?: true }> = {}) {
  assert(Object.keys(options).every(key => key === 'guestToolchain' || key === 'guestImageProfile' || key === 'publicationRetirementDiagnostics' || key === 'credentialPhaseDiagnostics' || key === 'serverAuthenticationDiagnostics' || key === 'storeFailureDiagnostics'));
  assert(options.guestToolchain === undefined || options.guestToolchain === 'node-test-v1');
  // Publisher construction only: keep the original maximum-load qualifier
  // separate from the default official compact image. No runtime flag exists.
  assert(options.guestImageProfile === undefined || options.guestImageProfile === 'qualification_max');
  if (options.guestImageProfile) assert(options.guestToolchain === 'node-test-v1');
  assert(options.publicationRetirementDiagnostics === undefined || options.publicationRetirementDiagnostics === true);
  assert(options.credentialPhaseDiagnostics === undefined || options.credentialPhaseDiagnostics === true);
  assert(options.serverAuthenticationDiagnostics === undefined || options.serverAuthenticationDiagnostics === true);
  assert(options.storeFailureDiagnostics === undefined || options.storeFailureDiagnostics === true);
  if (options.serverAuthenticationDiagnostics) assert(options.publicationRetirementDiagnostics === true,
    'fixed server observations belong only to the explicit delayed delivery qualification image');
  if (options.publicationRetirementDiagnostics) assert(options.guestToolchain === 'node-test-v1',
    'fixed publication observations belong only to the installed delivery qualification image');
  if (options.guestToolchain) assert(variant === 'complete' && modelFixture, 'installed verifier requires the complete model and native package');
  const repository = fileURLToPath(new URL('../../..', import.meta.url));
  const { nodeRoot, carrier, supervisorCarrier } = await prepareInstalledSupervisorSeaCarrier(fixture);
  const keys = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'explicit-installed-startup-test-root',
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const rootAsset = path.join(fixture, 'release-trust-roots.json');
  await writeFile(rootAsset, canonicalJsonBytes(releaseKeys), { flag: 'wx', mode: 0o400 });
  const packageRoot = path.join(fixture, 'package');
  await mkdir(packageRoot, { mode: 0o700 });
  const supervisorFile = await buildSupervisorSeaImage({ fixture, carrier: supervisorCarrier,
    entryPoint: path.join(repository, 'src/state/installed-entry.ts'),
    executable: path.join(packageRoot, 'supervisor'), variant: 'installed-supervisor',
    // Fixed observations belong only to explicitly selected qualifiers.
    // Default installed campaigns retain their original stderr contract.
    ...(options.guestToolchain === 'node-test-v1' || options.credentialPhaseDiagnostics ? { credentialPhaseDiagnostics: true as const } : {}),
    ...(options.publicationRetirementDiagnostics ? { publicationRetirementDiagnostics: true as const } : {}),
    ...(options.serverAuthenticationDiagnostics ? { serverAuthenticationDiagnostics: true as const } : {}),
    ...(options.storeFailureDiagnostics ? { storeFailureDiagnostics: true as const } : {}),
    assets: { 'release-trust-roots.json': rootAsset } });
  const helper = path.join(packageRoot, STATE_OWNER_NATIVE_RELATIVE_PATH);
  await mkdir(path.dirname(helper), { recursive: true, mode: 0o700 });
  const sqliteInclude = await verifiedSqliteExtensionIncludes();
  const compilation = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
    '-I', sqliteInclude, '-I', path.join(nodeRoot, 'include/node'),
    path.join(repository, 'native/state-owner/state-owner.c'), '-o', helper],
  { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(compilation.error, undefined, `cc: ${compilation.error}`);
  assert.equal(compilation.status, 0, `cc: ${compilation.stderr}`);
  await chmod(helper, 0o500);
  // Reuse the production recipe, outside the closed package tree. Its addon
  // must use this SEA carrier's headers, not the client's ambient Node headers.
  const workerRoot = path.join(fixture, 'worker-images');
  const workers = spawnSync(process.execPath, [path.join(repository, 'scripts/kernel/build-linux-worker.mjs'),
    workerRoot, path.join(nodeRoot, 'include/node')],
  { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(workers.error, undefined, 'production worker image construction did not join');
  assert.equal(workers.status, 0, `production worker image construction: ${workers.stderr}`);
  const credentialRoot = path.join(fixture, 'credential-platform-image');
  const credentials = spawnSync(process.execPath, [path.join(repository, 'scripts/kernel/build-linux-credential-platform.mjs'),
    credentialRoot, path.join(nodeRoot, 'include/node')],
  { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(credentials.error, undefined, 'production credential platform construction did not join');
  assert.equal(credentials.status, 0, `production credential platform construction: ${credentials.stderr}`);
  let modelBrokerBytes: Buffer | undefined;
  if (modelFixture) {
    const brokerRoot = path.join(fixture, 'model-broker-image');
    const broker = spawnSync(process.execPath, [path.join(repository, 'scripts/kernel/build-linux-model-broker.mjs'),
      brokerRoot, path.join(nodeRoot, 'include/node')],
    { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(broker.error, undefined, 'production model broker construction did not join');
    assert.equal(broker.status, 0, `production model broker construction: ${broker.stderr}`);
    modelBrokerBytes = await readFile(path.join(brokerRoot, 'linux-model-broker.node'));
  }
  const workerEntries = await Promise.all(([
    ['linux_worker_native', 'platform_helper', 'linux-worker.node'],
    ['linux_worker_controller', 'platform_helper', 'cliq-linux-worker-controller'],
    ['linux_bubblewrap', 'platform_helper', 'cliq-linux-bubblewrap'],
    ['linux_worker', 'worker', 'cliq-linux-worker'],
    ['edit', 'tool_adapter', 'cliq-linux-edit'],
  ] as const).filter(([entryId]) => variant !== 'retirement-native-missing' || entryId !== 'linux_worker_native')
    .map(async ([entryId, role, filename]) => ({ entryId, role,
    relativePath: `workers/${filename}`, executable: true, bytes: await readFile(path.join(workerRoot, filename)) })));
  const modelMaterial = modelFixture ? installedModelPackageEntries(modelFixture, modelBrokerBytes!,
    workerEntries.find(entry => entry.entryId === 'edit')!.bytes) : undefined;
  let guest: Awaited<ReturnType<typeof writeInstalledGuestToolchain>> | undefined;
  if (options.guestToolchain) {
    const guestImageRoot = path.join(fixture, 'guest-image');
    const built = spawnSync(process.execPath, [path.join(repository, 'scripts/kernel/build-linux-guest-toolchain.mjs'),
      guestImageRoot, workerRoot, carrier, ...(options.guestImageProfile ? ['--qualification-max'] : [])],
    { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(built.error, undefined, 'actual pinned guest image construction did not join');
    assert.equal(built.status, 0, 'actual pinned guest image construction refused');
    guest = await writeInstalledGuestToolchain({ packageRoot, guestImageRoot,
      extractorPath: path.join(workerRoot, 'linux-guest-extractor.node'), publisherKeyId: releaseKeys[0]!.keyId, privateKey: keys.privateKey });
  }
  const profile = policyProfile();
  const rootCore = { schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'], persistent: false, networkConfiguration: 'none' };
  const contents = [
    { entryId: 'installed-supervisor', role: 'supervisor', relativePath: 'supervisor', executable: true, bytes: await readFile(supervisorFile) },
    { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH,
      executable: true, bytes: await readFile(helper) },
    ...workerEntries,
    { entryId: 'linux_credential_platform', role: 'platform_helper', relativePath: 'native/linux-x64/linux-credential-platform.node',
      executable: true, bytes: await readFile(path.join(credentialRoot, 'linux-credential-platform.node')) },
    { entryId: 'installed-policy', role: 'policy_engine', relativePath: 'profiles/policy.json', executable: false, bytes: canonicalJsonBytes(profile) },
    { entryId: 'default_https_trust_store', role: 'trust_store', relativePath: 'profiles/https-trust.pem', executable: false,
      bytes: modelFixture ? Buffer.from(modelFixture.tls.caPem) : Buffer.from(rootCertificates.join('\n')) },
    { entryId: 'installed-empty-root', role: 'sandbox_root_profile', relativePath: 'profiles/empty-root.json', executable: false,
      bytes: canonicalJsonBytes({ ...rootCore, profileDigest: canonicalSha256(rootCore) }) },
    ...(modelMaterial?.entries ?? []),
  ];
  for (const entry of contents.slice(2)) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, entry.bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
  }
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: guest ? 'installed-sea-verifier-fixture-v1'
      : modelFixture ? 'installed-sea-run-fixture-v1' : 'installed-sea-read-qualification-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries: [...contents.map(({ bytes, ...entry }) => ({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength })),
      ...(guest?.entries ?? [])],
    structuredArtifacts: [
      ...(modelMaterial?.structuredArtifacts.filter(root => root.kind === 'compaction_prompt') ?? []),
      ...(guest ? [guest.root] : []),
      { kind: 'policy_engine_profile', artifactId: 'installed-policy', rootEntryId: 'installed-policy',
        artifactRef: canonicalSha256(profile), semanticDigest: profile.profileDigest, memberRefs: [] },
      ...(modelMaterial?.structuredArtifacts.filter(root => root.kind === 'system_prompt') ?? []),
    ],
    guestToolchainManifestRefs: guest ? [guest.manifestRef] : [], publisherKeyId: releaseKeys[0]!.keyId, manifestDigest: '', signature: '',
  };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  verifyRuntimeBundle(bundle, releaseKeys);
  if (guest) validateGuestToolchainMetadata(bundle, guest.manifestRef, canonicalJsonBytes(guest.manifest),
    await readFile(path.join(packageRoot, `objects/sha256/${guest.manifest.signatureRef.slice(0, 2)}/${guest.manifest.signatureRef}`)), releaseKeys);
  await writeFile(path.join(packageRoot, 'manifest.json'), canonicalJsonBytes(bundle), { flag: 'wx', mode: 0o400 });
  const modelAuthority = modelFixture ? await writeInstalledModelAuthority({ packageRoot, bundle,
    privateKey: keys.privateKey, fixture: modelFixture, material: modelMaterial! }) : undefined;
  return { packageRoot, releaseKeys, bundle, contents, carrier, ...(modelAuthority ? { modelAuthority } : {}),
    ...(guest ? { guestToolchain: { manifest: guest.manifest, manifestRef: guest.manifestRef,
      manifestId: guest.manifestId, imageLayout: guest.imageLayout } } : {}) };
}
