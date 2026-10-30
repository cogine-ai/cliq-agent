import { readQualificationSource, type FrozenQualificationSource } from './qualification-source.js';
import { createInstalledQualificationPublisher, qualificationPublisherMaterial, type InstalledQualificationPublisher } from '../../../src/state/testing/qualification-publisher.js';
import { schemaConversionProfile } from '../../../src/state/signed-schema.js';
import { signedKernelSchemaProfile } from '../../../src/state/signed-schema.js';
// Qualification-only signed package recipe, not a release publisher or I1.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { sign } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { rootCertificates } from 'node:tls';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';

import { KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { policyProfile, SINGLE_CAS_STREAMS_LAYOUT, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../../src/state/native-owner.js';
import { buildSupervisorSeaImage, prepareInstalledSupervisorSeaCarrier } from './supervisor-sea-builder.js';
import { installedModelPackageEntries, writeInstalledModelAuthority, type InstalledModelPackageFixture } from './installed-model-package.js';
import { buildInstalledModelPackageEntries } from '../model-package.js';
import { providerModelDefinition, writeInstalledProviderModelAuthority, type InstalledProviderModelDefinition } from '../installed-provider-model.js';
import { writeInstalledGuestToolchain } from './installed-guest-package.js';
import { validateGuestToolchainMetadata } from '../../../src/state/guest-toolchain.js';
import { buildSourceGitInspectorAsset } from './source-git-inspector-package.js';
import { buildBuiltinToolsAsset } from './builtin-tools-package.js';
import { buildBundledSkillPackageData, type BundledSkillPackageInput } from './installed-skill-package.js';
import { checkCanonicalBytes, validateBundle } from '../../../src/state/installed-artifacts.js';
import { emitQualificationFailure } from './qualification-failure-diagnostic.js';

type PackageBuildOptions = Readonly<{ source?: FrozenQualificationSource; publisher?: InstalledQualificationPublisher; upgradeSourceBundle?: RuntimeBundleManifest; bundledSkills?: readonly BundledSkillPackageInput[]; headlessSchemaVersion?: 3; guestToolchain?: 'node-test-v1'; guestImageProfile?: 'qualification_max'; publicationRetirementDiagnostics?: true; credentialPhaseDiagnostics?: true; serverAuthenticationDiagnostics?: true; storeFailureDiagnostics?: true; resourceDiagnostics?: true; npmDependencyArchive?: Buffer; providerModel?: InstalledProviderModelDefinition }>;
import { buildInstalledNpmAdapterAsset, buildInstalledNpmDataAsset } from './installed-npm-package.js';
import { DEPENDENCY_BROKER_ENTRY_ID, DEPENDENCY_BROKER_RELATIVE_PATH } from '../../../src/state/dependency-broker-native.js';
import { NPM_DATA_RECIPE } from '../../../src/sandbox/npm-data-image.js';

/** Construct the same actual SEA/helper package for independent Linux startup
 * and user-manager qualifiers. Real worker images are installed, not launched:
 * they do not qualify admission, execution, release signing or complete I1. */
async function buildInstalledSupervisorPackageCore(fixture: string,
  variant: 'complete' | 'retirement-native-missing' = 'complete', modelFixture?: InstalledModelPackageFixture,
  options: PackageBuildOptions = {}, diagnostics={phase:0}) {
  assert(Object.keys(options).every(key => key === 'source' || key === 'publisher' || key === 'upgradeSourceBundle' || key === 'bundledSkills' || key === 'headlessSchemaVersion' || key === 'guestToolchain' || key === 'guestImageProfile' || key === 'publicationRetirementDiagnostics' || key === 'credentialPhaseDiagnostics' || key === 'serverAuthenticationDiagnostics' || key === 'storeFailureDiagnostics' || key === 'resourceDiagnostics' || key === 'npmDependencyArchive' || key === 'providerModel'));
  assert(!(modelFixture && options.providerModel), 'owned fixture and real provider definitions cannot be combined');
  const providerModel = options.providerModel === undefined ? undefined : providerModelDefinition(options.providerModel);
  if (providerModel) assert(variant === 'complete', 'real provider qualification requires the complete signed native package');
  const hasModel = modelFixture !== undefined || providerModel !== undefined;
  assert(options.headlessSchemaVersion === undefined || options.headlessSchemaVersion === 3);
  assert(options.guestToolchain === undefined || options.guestToolchain === 'node-test-v1');
  // Publisher construction only: keep the original maximum-load qualifier
  // separate from the default official compact image. No runtime flag exists.
  assert(options.guestImageProfile === undefined || options.guestImageProfile === 'qualification_max');
  if (options.guestImageProfile) assert(options.guestToolchain === 'node-test-v1');
  assert(options.publicationRetirementDiagnostics === undefined || options.publicationRetirementDiagnostics === true);
  assert(options.credentialPhaseDiagnostics === undefined || options.credentialPhaseDiagnostics === true);
  assert(options.serverAuthenticationDiagnostics === undefined || options.serverAuthenticationDiagnostics === true);
  assert(options.storeFailureDiagnostics === undefined || options.storeFailureDiagnostics === true);
  assert(options.resourceDiagnostics === undefined || options.resourceDiagnostics === true);
  if (options.serverAuthenticationDiagnostics) assert(options.publicationRetirementDiagnostics === true,
    'fixed server observations belong only to the explicit delayed delivery qualification image');
  if (options.publicationRetirementDiagnostics) assert(options.guestToolchain === 'node-test-v1',
    'fixed publication observations belong only to the installed delivery qualification image');
  if (options.guestToolchain) assert(variant === 'complete' && hasModel, 'installed verifier requires the complete model and native package');
  // Publisher-only fixed source. This is not a runtime flag, path, registry
  // selector or interpreter choice. Validate the entire official source
  // before starting any builder or publishing a signed dependency entry.
  assert(options.npmDependencyArchive === undefined || Buffer.isBuffer(options.npmDependencyArchive) &&
    options.npmDependencyArchive.length === NPM_DATA_RECIPE.archiveBytes, 'installed npm requires its exact bounded official source');
  const npmData = options.npmDependencyArchive === undefined ? undefined : buildInstalledNpmDataAsset(Buffer.from(options.npmDependencyArchive));
  if (npmData) assert(options.guestToolchain === 'node-test-v1' && variant === 'complete' && hasModel,
    'installed npm requires its complete signed guest, model and native package');
  diagnostics.phase=1;
  const source = options.source === undefined ? undefined : await readQualificationSource(options.source);
  const repository = source?.root ?? fileURLToPath(new URL('../../..', import.meta.url));
  const schemaVersion = source?.schemaVersion ?? KERNEL_STATE_SCHEMA_VERSION;
  if (providerModel && schemaVersion !== 8) throw new TypeError('real provider qualification requires the current signed schema8 recipe');
  if (options.npmDependencyArchive !== undefined && schemaVersion !== 8) throw new TypeError('the original schema7 product cannot consume a later npm recipe');
  if (options.upgradeSourceBundle && schemaVersion !== 8) throw new TypeError('conversion can only be signed by the target8 recipe');
  if (options.bundledSkills !== undefined && schemaVersion !== 8) throw new TypeError('the original schema7 product cannot consume a later skills recipe');
  // An explicit old source compiles with that original product's actual SEA
  // builder and its separately integrity-installed lock, never today's deps.
  const sea = source ? await import(pathToFileURL(path.join(repository, 'scripts/kernel/testing/supervisor-sea-builder.ts')).href) as
    Pick<typeof import('./supervisor-sea-builder.js'), 'prepareInstalledSupervisorSeaCarrier' | 'buildSupervisorSeaImage'>
    : { prepareInstalledSupervisorSeaCarrier, buildSupervisorSeaImage };
  // A real old product's serialized tool contracts must come from its same
  // original verified source, just like its executable/native recipes. The
  // current compiler cannot silently add a later handler to an old image.
  const modelProducer = source ? await import(pathToFileURL(path.join(repository, 'scripts/kernel/testing/installed-model-package.ts')).href) as
    Pick<typeof import('./installed-model-package.js'), 'installedModelPackageEntries'> : { installedModelPackageEntries };
  const providerProducer = providerModel && source ? await import(pathToFileURL(path.join(repository, 'scripts/kernel/model-package.ts')).href) as
    Pick<typeof import('../model-package.js'), 'buildInstalledModelPackageEntries'> : { buildInstalledModelPackageEntries };
  diagnostics.phase=2;
  const { nodeRoot, carrier, supervisorCarrier } = await sea.prepareInstalledSupervisorSeaCarrier(fixture);
  diagnostics.phase=3;
  const publisher = options.publisher ?? createInstalledQualificationPublisher();
  const keys = qualificationPublisherMaterial(publisher);
  const releaseKeys = [...keys.releaseKeys];
  if (options.upgradeSourceBundle) verifyRuntimeBundle(options.upgradeSourceBundle, releaseKeys);
  const rootAsset = path.join(fixture, 'release-trust-roots.json');
  await writeFile(rootAsset, canonicalJsonBytes(releaseKeys), { flag: 'wx', mode: 0o400 });
  const packageRoot = path.join(fixture, 'package');
  await mkdir(packageRoot, { mode: 0o700 });
  diagnostics.phase=4;
  const supervisorFile = await sea.buildSupervisorSeaImage({ fixture, carrier: supervisorCarrier,
    entryPoint: path.join(repository, 'src/state/installed-entry.ts'),
    executable: path.join(packageRoot, 'supervisor'), variant: 'installed-supervisor',
    // Fixed observations belong only to explicitly selected qualifiers.
    // Default installed campaigns retain their original stderr contract.
    ...(options.guestToolchain === 'node-test-v1' || options.credentialPhaseDiagnostics ? { credentialPhaseDiagnostics: true as const } : {}),
    ...(options.publicationRetirementDiagnostics ? { publicationRetirementDiagnostics: true as const } : {}),
    ...(options.serverAuthenticationDiagnostics ? { serverAuthenticationDiagnostics: true as const } : {}),
    ...(options.storeFailureDiagnostics ? { storeFailureDiagnostics: true as const } : {}),
    ...(options.resourceDiagnostics ? { resourceDiagnostics: true as const } : {}),
    assets: { 'release-trust-roots.json': rootAsset } });
  const supervisorBytes = await readFile(supervisorFile);
  diagnostics.phase=5;
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
  if (hasModel) {
    const brokerRoot = path.join(fixture, 'model-broker-image');
    const broker = spawnSync(process.execPath, [path.join(repository, 'scripts/kernel/build-linux-model-broker.mjs'),
      brokerRoot, path.join(nodeRoot, 'include/node')],
    { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(broker.error, undefined, 'production model broker construction did not join');
    assert.equal(broker.status, 0, `production model broker construction: ${broker.stderr}`);
    modelBrokerBytes = await readFile(path.join(brokerRoot, 'linux-model-broker.node'));
  }
  let dependencyBrokerBytes: Buffer | undefined;
  if (npmData) {
    const brokerRoot = path.join(fixture, 'dependency-broker-image');
    const broker = spawnSync(process.execPath, [path.join(repository, 'scripts/kernel/build-linux-dependency-broker.mjs'),
      brokerRoot, path.join(nodeRoot, 'include/node')],
    { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(broker.error, undefined, 'production dependency broker construction did not join');
    assert.equal(broker.status, 0, 'production dependency broker construction refused');
    dependencyBrokerBytes = await readFile(path.join(brokerRoot, 'linux-dependency-broker.node'));
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
  diagnostics.phase=6;
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
  const builtinTools = guest ? await buildBuiltinToolsAsset(repository) : undefined;
  const npmAdapter = npmData ? await buildInstalledNpmAdapterAsset(repository) : undefined;
  const scriptMaterial = builtinTools && guest ? {
      entry: builtinTools, supervisor: { entryId: 'installed-supervisor', role: 'supervisor', relativePath: 'supervisor',
        executable: true, version: '1', digest: sha256Bytes(supervisorBytes), byteCount: supervisorBytes.length },
      guest: { manifestRef: guest.manifestRef, manifest: guest.manifest }
    } : undefined;
  const editBytes = workerEntries.find(entry => entry.entryId === 'edit')!.bytes;
  const modelMaterial = modelFixture ? modelProducer.installedModelPackageEntries(modelFixture, modelBrokerBytes!, editBytes, scriptMaterial)
    : providerModel ? providerProducer.buildInstalledModelPackageEntries(providerModel, modelBrokerBytes!, editBytes, scriptMaterial) : undefined;
  const profile = policyProfile();
  const originalStructuredCount = 1 + (guest ? 1 : 0) + (modelMaterial?.structuredArtifacts.length ?? 0);
  if (options.bundledSkills && options.bundledSkills.length + originalStructuredCount > 65)
    throw new TypeError('bundled skills exceed the unchanged total structured root bound');
  const skillData = buildBundledSkillPackageData(options.bundledSkills ?? []);
  const sourceInspector = guest ? await buildSourceGitInspectorAsset(repository) : undefined;
  const rootCore = { schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'], persistent: false, networkConfiguration: 'none' };
  const contents: Array<Omit<RuntimeBundleManifest['entries'][number], 'version' | 'digest' | 'byteCount'> & { version?: string; bytes: Buffer }> = [
    { entryId: 'installed-supervisor', role: 'supervisor', relativePath: 'supervisor', executable: true, bytes: supervisorBytes },
    { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH,
      executable: true, bytes: await readFile(helper) },
    ...workerEntries,
    ...(options.upgradeSourceBundle ? [{ entryId: 'schema_conversion', role: 'schema', relativePath: 'schema/convert-v7-to-v8.json', executable: false,
      bytes: canonicalJsonBytes(schemaConversionProfile(options.upgradeSourceBundle)) }] : []),
    ...(schemaVersion === 8 ? [{ entryId: 'kernel_schema', role: 'schema', relativePath: 'schema/kernel-v8.json', executable: false, bytes: canonicalJsonBytes(signedKernelSchemaProfile()) }] : []),
    { entryId: 'linux_credential_platform', role: 'platform_helper', relativePath: 'native/linux-x64/linux-credential-platform.node',
      executable: true, bytes: await readFile(path.join(credentialRoot, 'linux-credential-platform.node')) },
    { entryId: 'installed-policy', role: 'policy_engine', relativePath: 'profiles/policy.json', executable: false, bytes: canonicalJsonBytes(profile) },
    { entryId: 'default_https_trust_store', role: 'trust_store', relativePath: 'profiles/https-trust.pem', executable: false,
      bytes: modelFixture ? Buffer.from(modelFixture.tls.caPem) : Buffer.from(rootCertificates.join('\n')) },
    { entryId: 'installed-empty-root', role: 'sandbox_root_profile', relativePath: 'profiles/empty-root.json', executable: false,
      bytes: canonicalJsonBytes({ ...rootCore, profileDigest: canonicalSha256(rootCore) }) },
    ...(modelMaterial?.entries ?? []),
    ...(builtinTools ? [{ entryId: builtinTools.entryId, role: builtinTools.role, relativePath: builtinTools.relativePath,
      executable: builtinTools.executable, bytes: builtinTools.bytes }] : []),
    ...(sourceInspector ? [{ entryId: sourceInspector.entryId, role: sourceInspector.role, relativePath: sourceInspector.relativePath,
      executable: sourceInspector.executable, bytes: sourceInspector.bytes }] : []),
    ...skillData.contents,
    ...(npmAdapter && npmData && dependencyBrokerBytes ? [
      { entryId: DEPENDENCY_BROKER_ENTRY_ID, role: 'platform_helper' as const, relativePath: DEPENDENCY_BROKER_RELATIVE_PATH,
        version: '1', executable: true, bytes: dependencyBrokerBytes },
      ...[npmAdapter, npmData].map(({ entryId, role, relativePath, version, executable, bytes }) =>
        ({ entryId, role, relativePath, version, executable, bytes }))
    ] : []),
  ];
  for (const entry of contents.slice(2)) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, entry.bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
  }
  diagnostics.phase=7;
  const bundle: RuntimeBundleManifest = {
    ...(schemaVersion === 7 ? { schemaVersion: 1 as const } : { schemaVersion: 2 as const, installedLayout: SINGLE_CAS_STREAMS_LAYOUT }),
    bundleVersion: providerModel ? 'installed-sea-provider-qualification-v1' : guest ? 'installed-sea-verifier-fixture-v1'
      : modelFixture ? 'installed-sea-run-fixture-v1' : 'installed-sea-read-qualification-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: options.headlessSchemaVersion ?? 1, max: options.headlessSchemaVersion ?? 1 },
    stateSchemaRange: { min: 1, max: schemaVersion }, workerProtocolRange: { min: 1, max: 1 },
    entries: [...contents.map(({ bytes, version, ...entry }) => ({ ...entry, version: entry.entryId === 'kernel_schema' ? '8' : entry.entryId === 'schema_conversion' ? '7-to-8' : version ?? '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength })),
      ...(guest?.entries ?? [])],
    structuredArtifacts: [
      ...skillData.roots,
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
  checkCanonicalBytes(canonicalJsonBytes(bundle)); validateBundle(bundle, releaseKeys);
  if (guest) validateGuestToolchainMetadata(bundle, guest.manifestRef, canonicalJsonBytes(guest.manifest),
    await readFile(path.join(packageRoot, `objects/sha256/${guest.manifest.signatureRef.slice(0, 2)}/${guest.manifest.signatureRef}`)), releaseKeys);
  await writeFile(path.join(packageRoot, 'manifest.json'), canonicalJsonBytes(bundle), { flag: 'wx', mode: 0o400 });
  diagnostics.phase=8;
  const modelAuthority = modelFixture ? await writeInstalledModelAuthority({ packageRoot, bundle,
    privateKey: keys.privateKey, fixture: modelFixture, material: modelMaterial! })
    : providerModel ? await writeInstalledProviderModelAuthority({ packageRoot, bundle,
      privateKey: keys.privateKey, definition: providerModel, material: modelMaterial! }) : undefined;
  if (options.source) { const current = await readQualificationSource(options.source);
    assert.deepEqual(current, source, 'the original frozen source changed during actual package construction'); }
  return { packageRoot, releaseKeys, bundle, contents, carrier, ...(source ? { sourceProvenance: source } : {}), ...(modelAuthority ? { modelAuthority } : {}),
    ...(guest ? { guestToolchain: { manifest: guest.manifest, manifestRef: guest.manifestRef,
      manifestId: guest.manifestId, imageLayout: guest.imageLayout } } : {}) };
}

export async function buildInstalledSupervisorPackage(fixture:string,
  variant:'complete'|'retirement-native-missing'='complete',modelFixture?:InstalledModelPackageFixture,options:PackageBuildOptions={}) {
  const diagnostics={phase:0};
  try { return await buildInstalledSupervisorPackageCore(fixture,variant,modelFixture,options,diagnostics); }
  catch (error) { emitQualificationFailure('package',error,diagnostics.phase); throw error; }
}

/** A controlled real-provider experiment uses the original SEA/native/guest
 * build and installer, with public CAs and compiled qualification roots. This
 * does not publish an official release, call the model or persist its key. */
export function buildInstalledProviderQualificationPackage(directory: string, definition: InstalledProviderModelDefinition,
  options: Omit<PackageBuildOptions, 'providerModel' | 'headlessSchemaVersion' | 'guestToolchain'> = {}) {
  return buildInstalledSupervisorPackage(directory, 'complete', undefined,
    { ...options, providerModel: definition, headlessSchemaVersion: 3, guestToolchain: 'node-test-v1' });
}
