import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { channel } from 'node:diagnostics_channel';
import { constants, fstatSync, promises as installFixtureFs } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, writeFile, type FileHandle } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';
import { Worker } from 'node:worker_threads';
import ts from 'typescript';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, sha256Bytes } from '../kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore } from './cas.js';
import { assertInstalledManagerObservationAvailable, createInstalledRuntime, loadInstalledCredentialPlatform, loadInstalledManagerObserver,
  readInstalledRuntimeObservation, retainInstalledSourceGitRecipe, type InstalledRuntimeObservation, type HeldInstalledRuntime, withHeldInstalledRuntime } from './installed-runtime.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from './native-owner.js';
import { openInstalledLinuxWorkerLauncher } from '../sandbox/linux-worker.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { GUEST_EXTRACTOR_RECIPE } from '../sandbox/guest-toolchain.js';
import { validateBundle, validateInstalledStructuredArtifacts } from './installed-artifacts.js';
import { NPM_DATA_RECIPE } from '../sandbox/npm-data-image.js';
import { NPM_DEPENDENCY_RECIPE } from '../sandbox/dependency-recipe.js';
import { observeInstalledCredentialSupervisor } from './installed-services.js';
import { INSTALLED_INSTALL_PHASE_CHANNEL, INSTALLED_INSTALL_PHASES, INSTALLED_WORK_CHANNEL, type InstalledWorkSnapshot } from './installed-work-diagnostics.js';
import { buildBundledSkillPackageData } from './bundled-skill-package.js';

/** Real signed files for installer/CAS semantics only. The opaque executable
 * entries are deliberately not running Supervisor/worker/addon images and are
 * never spawned or dlopened. They establish no execution qualification. */
type InstallerFile = Omit<RuntimeBundleManifest['entries'][number], 'digest' | 'byteCount' | 'version'> & {
  bytes: Buffer; version?: string;
};
async function writeInstallerOnlyPackage(packageRoot: string, unclosedPromptRole?: 'system_prompt' | 'compaction_prompt',
  supervisorBytes?: Buffer, guestImageBytes?: Buffer, sourceInspector?: InstallerFile, builtinScriptBytes?: Buffer,
  skills?: ReturnType<typeof buildBundledSkillPackageData>, sourceControllerBytes?: Buffer) {
  await mkdir(packageRoot, { mode: 0o700 });
  const profile = policyProfile();
  const rootCore = {
    schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'],
    persistent: false, networkConfiguration: 'none',
  };
  const rootRecipe = { ...rootCore, profileDigest: canonicalSha256(rootCore) };
  const contents: InstallerFile[] = [
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
  if (sourceInspector) contents.push(sourceInspector);
  if (sourceControllerBytes) contents.push({ entryId: 'linux_worker_controller', role: 'platform_helper', version: '1',
    relativePath: 'native/cliq-linux-worker-controller', executable: true, bytes: sourceControllerBytes });
  if (builtinScriptBytes) contents.push({ entryId: 'builtin_tools', role: 'tool_adapter',
    relativePath: 'adapters/builtin-tools.mjs', executable: false, bytes: builtinScriptBytes });
  if (skills) contents.push(...skills.contents);
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
  for (const { bytes, version = '1', ...entry } of contents) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
    entries.push({ ...entry, version, digest: sha256Bytes(bytes), byteCount: bytes.byteLength });
  }
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 2, installedLayout: 'single_cas_streams_v1', bundleVersion: 'installer-file-verification-only-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries,
    // The empty-root recipe is an acyclic sandbox_root_profile entry, not
    // resource/permission policy or a new structured-artifact kind. The sole
    // supported structured policy root is self-contained.
    structuredArtifacts: [...(skills?.roots ?? []), ...(guestRoot ? [guestRoot] : []), { kind: 'policy_engine_profile', artifactId: 'policy-v1', rootEntryId: 'policy-v1',
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

const sourceInspectorFile = (overrides: Partial<InstallerFile> = {}): InstallerFile => ({
  entryId: 'source_git_inspector', role: 'platform_helper', version: '1',
  relativePath: 'helpers/source-git-inspector.mjs', executable: false,
  bytes: Buffer.from('// signed installer-only source inspector; never executed\n'), ...overrides,
});

test('the signed installed layout is explicit, versioned and cannot be changed without a new release signature', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-layout-signature-'));
  try {
    const original = await writeInstallerOnlyPackage(path.join(root, 'package'));
    const keys = generateKeyPairSync('ed25519');
    const releaseKeys = [{ keyId: 'layout-signature-component', publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
    const signed = (version: number, layout: unknown) => {
      const { signature: _signature, manifestDigest: _digest, ...old } = original.bundle;
      const core = { ...old, schemaVersion: version, installedLayout: layout, publisherKeyId: releaseKeys[0]!.keyId };
      const manifestDigest = canonicalSha256(core);
      return { ...core, manifestDigest, signature: sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`), keys.privateKey).toString('base64') };
    };
    const modern = signed(2, 'single_cas_streams_v1');
    assert.doesNotThrow(() => verifyRuntimeBundle(modern as unknown as RuntimeBundleManifest, releaseKeys));
    assert.doesNotThrow(() => validateBundle(modern, releaseKeys));
    for (const value of [signed(1, 'single_cas_streams_v1'), signed(2, 'arbitrary_data'), signed(2, null), signed(2, true),
      { ...modern, installedLayout: 'arbitrary_data' }, { ...modern, schemaVersion: 1 }]) {
      assert.throws(() => verifyRuntimeBundle(value as unknown as RuntimeBundleManifest, releaseKeys));
    }
    // This is retained signed data only; an old manifest is not a capability
    // to open a new installed execution scope or select a fallback layout.
    const { installedLayout: _layout, ...modernCore } = modern;
    const { signature: _signature, manifestDigest: _digest, ...legacyCore } = { ...modernCore, schemaVersion: 1 };
    const manifestDigest = canonicalSha256(legacyCore);
    const legacy = { ...legacyCore, manifestDigest, signature: sign(null,
      Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`), keys.privateKey).toString('base64') };
    assert.doesNotThrow(() => verifyRuntimeBundle(legacy as RuntimeBundleManifest, releaseKeys));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('npm data has one exact signed non-executable pair without widening other script or bundle-object roles', async () => {
  // Real signatures over metadata only. No opaque file here is executed or
  // materialized, and known data-image pins are not an installation receipt.
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-npm-entry-contract-'));
  try {
    const signed = await writeInstallerOnlyPackage(path.join(root, 'package'));
    const adapter: RuntimeBundleManifest['entries'][number] = { entryId: NPM_DEPENDENCY_RECIPE.adapterId, role: 'tool_adapter', version: '1',
      relativePath: NPM_DEPENDENCY_RECIPE.adapterPath, executable: false, digest: sha256Bytes(Buffer.from(';')), byteCount: 1 };
    const image: RuntimeBundleManifest['entries'][number] = { entryId: NPM_DATA_RECIPE.entryId, role: 'bundle_object', version: NPM_DATA_RECIPE.version,
      relativePath: NPM_DATA_RECIPE.relativePath, executable: false, digest: NPM_DATA_RECIPE.completeImageDigest, byteCount: NPM_DATA_RECIPE.completeImageBytes };
    const keys = generateKeyPairSync('ed25519');
    const signEntries = (extra: RuntimeBundleManifest['entries']) => {
      const bundle = { ...signed.bundle, entries: [...signed.bundle.entries, ...extra], publisherKeyId: 'npm-data-pair-fixture', manifestDigest: '', signature: '' };
      const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
      bundle.manifestDigest = canonicalSha256(core);
      bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
      return { bundle, releaseKeys: [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }] };
    };
    const positive = signEntries([adapter, image]);
    const accepted = validateBundle(positive.bundle, positive.releaseKeys);
    assert.equal(accepted.entries.find(entry => entry.entryId === NPM_DATA_RECIPE.entryId)!.byteCount, 11_950_276);
    const buffers = new Map(signed.contents.map(entry => [sha256Bytes(entry.bytes), entry.bytes]));
    buffers.set(adapter.digest, Buffer.from(';'));
    assert(validateInstalledStructuredArtifacts(accepted, buffers).objects.some(entry => entry.artifactRef === image.digest && entry.schemaKind === 'cliq-npm-data-image-v1'));
    for (const extra of [
      [adapter], [image], [adapter, { ...image, digest: 'a'.repeat(64) }], [adapter, { ...image, byteCount: image.byteCount + 1 }],
      [adapter, { ...image, version: '10.9.3' }], [adapter, { ...image, executable: true }],
      [{ ...adapter, executable: true }, image], [{ ...adapter, relativePath: 'adapters/arbitrary.mjs' }, image],
      [{ ...adapter, entryId: 'arbitrary_js' }, image], [{ ...adapter, byteCount: 1_048_577 }, image],
    ]) { const invalid = signEntries(extra); assert.throws(() => validateBundle(invalid.bundle, invalid.releaseKeys), { code: 'ARTIFACT_MISMATCH' }); }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('the signed installer accepts only the fixed source inspector as non-executable helper code', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-source-helper-manifest-'));
  try {
    for (const [name, bytes] of [['small', Buffer.from(';')], ['maximum', Buffer.alloc(1_048_576, 0x20)]] as const) {
      const signed = await writeInstallerOnlyPackage(path.join(root, name), undefined, undefined, undefined, sourceInspectorFile({ bytes }));
      const checked = validateBundle(signed.bundle, signed.releaseKeys);
      const helper = checked.entries.find(entry => entry.entryId === 'source_git_inspector')!;
      assert.equal(helper.executable, false); assert.equal(helper.byteCount, bytes.length);
      assert.equal(helper.digest, sha256Bytes(bytes)); assert(Object.isFrozen(checked));
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('a real signature cannot widen the fixed non-executable helper recipe', async t => {
  const variants: Record<string, Partial<InstallerFile>> = {
    id: { entryId: 'other_helper' }, version: { version: '2' }, path: { relativePath: 'helpers/other.mjs' },
    role: { role: 'tool_adapter' }, executable: { executable: true }, empty: { bytes: Buffer.alloc(0) },
    oversized: { bytes: Buffer.alloc(1_048_577, 0x20) },
  };
  for (const [name, changes] of Object.entries(variants)) await t.test(name, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-source-helper-refusal-'));
    try {
      const signed = await writeInstallerOnlyPackage(path.join(root, 'package'), undefined, undefined, undefined, sourceInspectorFile(changes));
      assert.throws(() => validateBundle(signed.bundle, signed.releaseKeys), { code: 'ARTIFACT_MISMATCH' });
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

if (process.platform === 'linux') test('the installer preserves and rechecks the complete signed non-executable source helper', async () => {
  // Real signed files/install/held-selection only. Opaque executable fixtures
  // are never launched; this supplies no worker or StateOwner proof.
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-source-helper-install-')));
  const packageRoot = path.join(root, 'package'), stateRoot = path.join(root, 'state');
  let selected: HeldInstalledRuntime | undefined;
  try {
    const source = sourceInspectorFile();
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, undefined, source);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    const file = path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, source.relativePath);
    assert.deepEqual(await readFile(file), source.bytes); assert.equal((await lstat(file)).mode & 0o777, 0o400);
    await withHeldInstalledRuntime(selected, async installed => {
      assert(!installed.seed.some(entry => entry.artifactRef === sha256Bytes(source.bytes)), 'code remains in its original signed runtime closure');
    });
    await selected.close(); selected = undefined;
    const changed = Buffer.from(source.bytes); changed[0] = changed[0]! ^ 1;
    await chmod(file, 0o600); await writeFile(file, changed); await chmod(file, 0o400);
    await assert.rejects(runtime.openSelected(stateRoot), { code: 'ARTIFACT_MISMATCH' });
    assert(!(await readdir(stateRoot)).includes(KERNEL_DATABASE_FILENAME), 'installation never creates StateOwner or business state');
  } finally { await selected?.close(); await rm(root, { recursive: true, force: true }); }
});

test('the signed installer keeps the builtin script recipe closed alongside the source inspector', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-builtin-script-manifest-'));
  const builtin: InstallerFile = { entryId: 'builtin_tools', role: 'tool_adapter', version: '1',
    relativePath: 'adapters/builtin-tools.mjs', executable: false, bytes: Buffer.from(';') };
  try {
    for (const [name, bytes] of [['small', builtin.bytes], ['maximum', Buffer.alloc(1_048_576, 0x20)]] as const) {
      await t.test(name, async () => {
        const signed = await writeInstallerOnlyPackage(path.join(root, name), undefined, undefined, undefined,
          sourceInspectorFile(), bytes);
        const checked = validateBundle(signed.bundle, signed.releaseKeys);
        for (const id of ['source_git_inspector', 'builtin_tools']) {
          const entry = checked.entries.find(item => item.entryId === id)!;
          assert.equal(entry.executable, false);
          if (id === 'builtin_tools') { assert.equal(entry.byteCount, bytes.length); assert.equal(entry.digest, sha256Bytes(bytes)); }
        }
      });
    }
    const variants: Record<string, Partial<InstallerFile>> = {
      id: { entryId: 'other_tools' }, version: { version: '2' }, path: { relativePath: 'adapters/other.mjs' },
      role: { role: 'platform_helper' }, roleData: { role: 'bundle_object' },
      roleExecutable: { role: 'platform_helper', executable: true },
      executable: { executable: true }, empty: { bytes: Buffer.alloc(0) },
      oversized: { bytes: Buffer.alloc(1_048_577, 0x20) },
    };
    for (const [name, changes] of Object.entries(variants)) await t.test(name, async () => {
      const signed = await writeInstallerOnlyPackage(path.join(root, 'invalid-' + name), undefined, undefined,
        undefined, { ...builtin, ...changes });
      assert.throws(() => validateBundle(signed.bundle, signed.releaseKeys), { code: 'ARTIFACT_MISMATCH' });
    });
  } finally { await rm(root, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('installed signed builtin script remains complete non-JSON data in the exact original seed and CAS', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-tool-data-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  try {
    const bytes = Buffer.from('// Deliberately not JSON or ELF. Never execute this installer-only fixture.\nexport const inert = true;\n');
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, undefined, undefined, bytes);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot });
    selected = await runtime.openSelected(stateRoot);
    const digest = sha256Bytes(bytes), entry = signed.bundle.entries.find(entry => entry.entryId === 'builtin_tools')!;
    assert.equal(entry.executable, false);
    await withHeldInstalledRuntime(selected, async held => {
      await held.revalidate();
      const seed = held.seed.find(member => member.artifactRef === digest);
      assert.deepEqual(seed, { artifactRef: digest, byteCount: bytes.length,
        mediaType: 'application/octet-stream', schemaKind: 'cliq-builtin-tool-script-v1' });
      assert.deepEqual(held.objects.get(digest), bytes);
    });
    const installedPath = path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, entry.relativePath);
    const casPath = path.join(stateRoot, KERNEL_CAS_DIRECTORY, digest);
    assert.deepEqual(await readFile(installedPath), bytes); assert.deepEqual(await readFile(casPath), bytes);
    const [installedInfo, casInfo] = await Promise.all([lstat(installedPath), lstat(casPath)]);
    for (const info of [installedInfo, casInfo]) { assert.equal(info.nlink, 1); assert.equal(info.mode & 0o7777, 0o400); }
    assert.notEqual(`${installedInfo.dev}:${installedInfo.ino}`, `${casInfo.dev}:${casInfo.ino}`);
  } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
});

test('signed skill metadata stays within the original total root cap and non-executable member rules', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-skill-metadata-'));
  try {
    const skill = buildBundledSkillPackageData([{ skillId: 'example', files: [
      { canonicalRelativePath: 'SKILL.md', bytes: Buffer.from('---\nname: example\ndescription: Frozen metadata.\n---\n[schema](assets/root.json)\n') },
      { canonicalRelativePath: 'assets/root.json', bytes: Buffer.from('{"type":"string"}') }
    ] }]);
    const signed = await writeInstallerOnlyPackage(path.join(fixture, 'package'), undefined, undefined, undefined, undefined, undefined, skill);
    validateBundle(signed.bundle, signed.releaseKeys);
    assert(signed.bundle.entries.filter(entry => entry.role === 'skill_bundle' || skill.roots[0]!.memberRefs.includes(entry.digest)).every(entry => !entry.executable));
    const keys = generateKeyPairSync('ed25519');
    const resign = (value: RuntimeBundleManifest) => {
      const { signature: _signature, manifestDigest: _digest, ...core } = { ...value, publisherKeyId: 'exact-root-cap-test' };
      const manifestDigest = canonicalSha256(core);
      return { ...core, manifestDigest, signature: sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`), keys.privateKey).toString('base64') };
    };
    const release = [{ keyId: 'exact-root-cap-test', publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
    const over = resign({ ...signed.bundle, structuredArtifacts: Array.from({ length: 66 }, (_, index) => ({
      ...signed.bundle.structuredArtifacts[0]!, artifactId: `skill-${index}` })) });
    assert.throws(() => validateBundle(over, release), { code: 'ARTIFACT_MISMATCH' });
    for (const role of ['skill_bundle', 'bundle_object']) {
      const bad = resign({ ...signed.bundle, entries: signed.bundle.entries.map(entry => entry.role === role ? { ...entry, executable: true } : entry) });
      assert.throws(() => validateBundle(bad, release), { code: 'ARTIFACT_MISMATCH' });
    }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') test('installer imports the complete signed skill closure into CAS and reopens without the original package', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-skill-data-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state'); let selected: HeldInstalledRuntime | undefined;
  try {
    const raw = Buffer.from('deliberately inert resource bytes\n'), skill = buildBundledSkillPackageData([{ skillId: 'example', files: [
      { canonicalRelativePath: 'SKILL.md', bytes: Buffer.from('---\nname: example\ndescription: Frozen install.\n---\n[resource](assets/data.bin)\n') },
      { canonicalRelativePath: 'assets/data.bin', bytes: raw }
    ] }]);
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, undefined, undefined, undefined, skill);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot }); selected = await runtime.openSelected(stateRoot);
    await withHeldInstalledRuntime(selected, async held => {
      for (const entry of skill.contents) {
        const digest = sha256Bytes(entry.bytes); assert(held.seed.some(member => member.artifactRef === digest && member.byteCount === entry.bytes.length));
        assert((await readFile(path.join(stateRoot, KERNEL_CAS_DIRECTORY, digest))).equals(entry.bytes));
      }
    });
    await selected.close(); selected = undefined; await rm(packageRoot, { recursive: true }); selected = await runtime.openSelected(stateRoot);
    assert.equal((await readInstalledRuntimeObservation(selected)).bundleDigest, installation.bundleDigest);
    assert(!(await readdir(stateRoot)).includes(KERNEL_DATABASE_FILENAME), 'opaque signed installer data supplies no StateOwner or Run execution proof');
  } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
});

async function platformRevalidationExpressions() {
  const source = await readFile(new URL('./installed-runtime.ts', import.meta.url), 'utf8');
  const parsed = ts.createSourceFile('installed-platform-read-data.ts', source, ts.ScriptTarget.Latest, true);
  const loaders: ts.MethodDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isMethodDeclaration(node) && node.name.getText(parsed) === 'loadCredentialPlatform') loaders.push(node);
    ts.forEachChild(node, visit);
  };
  visit(parsed); assert.equal(loaders.length, 1);
  const calls: ts.CallExpression[] = [];
  const reads = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'checkedRevalidate') calls.push(node);
    ts.forEachChild(node, reads);
  };
  reads(loaders[0]!); assert.equal(calls.length, 2, 'keep both original full-image revalidations');
  return calls.map(call => {
    const output = ts.transpileModule(`return ${call.getText(parsed)};`,
      { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    return new Function('checkedRevalidate', 'signal', output) as
      (revalidate: (signal?: AbortSignal) => Promise<void>, signal: AbortSignal) => Promise<void>;
  });
}

test('assembly forwards its read cancellation through the fixed platform bridge to both original complete revalidations', async () => {
  // Source wiring only; this never passes or impersonates the Linux SEA gate.
  const source = await readFile(new URL('./installed-runtime.ts', import.meta.url), 'utf8');
  const assembly = await readFile(new URL('./installed-run.ts', import.meta.url), 'utf8');
  assert.match(assembly, /loadInstalledCredentialPlatform\(selected, signal\)/u);
  assert.match(source, /loadCredentialPlatform\(signal\?: AbortSignal\): Promise<NativeCredentialPlatformBinding>/u);
  assert.match(source, /export function loadInstalledCredentialPlatform\(selected: HeldInstalledRuntime, signal\?: AbortSignal\)/u);
  assert.match(source, /return managerObservationBinding\(selected\).loadCredentialPlatform\(signal\);/u);
  const start = source.indexOf('          loadCredentialPlatform(signal) {'), end = source.indexOf('          loadManagerObserver()', start);
  assert(start >= 0 && end > start);
  const loader = source.slice(start, end);
  assert.equal(loader.match(/await checkedRevalidate\(signal\)/gu)?.length, 2);
  assert.match(loader, /!isMainThread \|\| !isSea\(\) \|\| process.platform !== 'linux' \|\| process.arch !== 'x64' \|\| process.versions.node !== '24.21.0'/u);
  assert.equal((await platformRevalidationExpressions()).length, 2);
});

for (const index of [0, 1] as const) test(`platform loader complete revalidation ${index + 1} cancels and joins its genuine signed image read`,
  { skip: process.platform !== 'linux' }, async () => {
  // Actual installer-only R/FD fixture plus the original read expression only.
  // Opaque signed images are never loaded; this is not platform/SEA execution.
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-platform-image-read-join-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined, checking: Promise<void> | undefined, closing: Promise<void> | undefined;
  let prototype: object | undefined, readDescriptor: PropertyDescriptor | undefined, captured: FileHandle | undefined, closeDescriptor: PropertyDescriptor | undefined;
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; }), delivered = new Promise<void>(resolve => { entered = resolve; });
  const abort = new AbortController(), reason = new Error('the original platform image read was revoked');
  let armed = false, intercepted = false, settled = false, closeSettled = false, closeAttempts = 0;
  const restore = () => {
    if (prototype && readDescriptor) Object.defineProperty(prototype, 'read', readDescriptor);
    if (captured && closeDescriptor) Object.defineProperty(captured, 'close', closeDescriptor);
  };
  try {
    const image = Buffer.alloc(3 * 1_048_576 + 17, 0x61); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installed = await runtime.installInitial({ packageRoot, stateRoot }); selected = await runtime.openSelected(stateRoot);
    const filename = path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, 'supervisor');
    const expected = await lstat(filename, { bigint: true }), probe = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { prototype = Object.getPrototypeOf(probe); } finally { await probe.close(); }
    readDescriptor = Object.getOwnPropertyDescriptor(prototype!, 'read')!;
    const read = readDescriptor.value as FileHandle['read'];
    Object.defineProperty(prototype!, 'read', { ...readDescriptor, value: function (this: FileHandle, ...args: unknown[]) {
      const actual = fstatSync(this.fd, { bigint: true });
      if (!armed || intercepted || actual.dev !== expected.dev || actual.ino !== expected.ino) return Reflect.apply(read, this, args);
      intercepted = true; captured = this; closeDescriptor = Object.getOwnPropertyDescriptor(this, 'close')!;
      assert(closeDescriptor?.configurable && typeof closeDescriptor.value === 'function');
      const close = closeDescriptor.value as FileHandle['close'];
      Object.defineProperty(this, 'close', { ...closeDescriptor, value: function (this: FileHandle, ...values: unknown[]) {
        closeAttempts++; return Reflect.apply(close, this, values);
      } });
      const original = Reflect.apply(read, this, args) as ReturnType<FileHandle['read']>;
      return original.then(async result => { entered(); await gate; return result; });
    } });
    const expressions = await platformRevalidationExpressions();
    checking = withHeldInstalledRuntime(selected, async installed => {
      armed = true;
      return expressions[index]!(installed.revalidate.bind(installed), abort.signal);
    });
    void checking.then(() => { settled = true; }, () => { settled = true; });
    await Promise.race([delivered, checking.then(() => { throw new Error('the genuine selected-image read did not reach its original delivery gate'); })]);
    abort.abort(reason); closing = selected.close();
    void closing.then(() => { closeSettled = true; }, () => { closeSettled = true; });
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(settled, false); assert.equal(closeSettled, false); assert.equal(closeAttempts, 0);
    release(); await assert.rejects(checking, error => error === reason); await closing;
    assert.equal(closeAttempts, 1, 'the original descriptor closes once only after its real pending read returns');
  } finally {
    release(); await Promise.allSettled([checking, closing]); restore();
    await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

test('installed read-only manager observation rejects structural selections before inspecting caller properties', () => {
  let inspected = false;
  const fake = new Proxy({}, { get() { inspected = true; throw new Error('caller property was inspected'); } });
  assert.throws(() => loadInstalledManagerObserver(fake as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  assert.throws(() => assertInstalledManagerObservationAvailable(fake as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  assert.throws(() => readInstalledRuntimeObservation(fake as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(inspected, false);
});

if (process.platform === 'linux') test('a status-side installed read can finish before the model-side borrow receives its external response', async () => {
  // Real installation/held-selection seam only. The signed opaque files are not
  // runnable images and this test creates no StateOwner or model authority.
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-status-borrow-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined, model: Promise<void> | undefined, queued: Promise<void> | undefined;
  let status: Promise<InstalledRuntimeObservation> | undefined;
  let modelEntered!: () => void, externalResponse!: () => void, timer: ReturnType<typeof setTimeout> | undefined;
  const entered = new Promise<void>(resolve => { modelEntered = resolve; });
  const response = new Promise<void>(resolve => { externalResponse = resolve; });
  let responseReleased = false, queuedEntered = false;
  try {
    const signed = await writeInstallerOnlyPackage(packageRoot), runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot }); selected = await runtime.openSelected(stateRoot);
    model = withHeldInstalledRuntime(selected, async () => { modelEntered(); await response; });
    await entered;
    queued = withHeldInstalledRuntime(selected, async () => { queuedEntered = true; });
    status = readInstalledRuntimeObservation(selected);
    const result = await Promise.race([status.then(inventory => ({ kind: 'observed' as const, inventory })),
      new Promise<{ kind: 'deadline' }>(resolve => { timer = setTimeout(() => resolve({ kind: 'deadline' }), 5000); })]);
    assert.equal(result.kind, 'observed', 'the status read must not wait behind the external response its caller is preparing');
    assert.equal(responseReleased, false);
    assert.equal(queuedEntered, false, 'ordinary authority-bearing borrows must retain their original FIFO');
    if (result.kind === 'observed') {
      assert.deepEqual(Object.keys(result.inventory).sort(), ['bundleDigest', 'bundleVersion', 'casRoot', 'manifestDigest', 'stateRoot']);
      assert.equal(result.inventory.bundleDigest, installation.bundleDigest);
      assert.equal(result.inventory.manifestDigest, signed.bundle.manifestDigest);
      assert(Object.isFrozen(result.inventory) && Object.isFrozen(result.inventory.stateRoot) && Object.isFrozen(result.inventory.casRoot));
    }
    responseReleased = true; externalResponse();
    await model; await queued;
    assert.equal(queuedEntered, true, 'the original queued business borrow resumes only after its predecessor releases');
  } finally {
    if (timer) clearTimeout(timer);
    responseReleased = true; externalResponse();
    await Promise.allSettled([model, queued, status]); await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') test('installed work measurements count the complete package and one physical CAS guest per R without changing validation', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-work-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  const diagnostic = channel(INSTALLED_WORK_CHANNEL), observed: InstalledWorkSnapshot[] = [];
  const subscriber = (value: unknown) => { if (typeof value === 'object') observed.push(value as InstalledWorkSnapshot); };
  let selected: HeldInstalledRuntime | undefined;
  try {
    const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61);
    image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot });
    const manifestBytes = canonicalJsonBytes(signed.bundle).length;
    const packageBytes = manifestBytes + signed.contents.reduce((sum, entry) => sum + entry.bytes.length, 0);
    const activeBytes = (await readFile(path.join(stateRoot, 'runtime/active.json'))).length;
    const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
    let casBytes = 0;
    for (const name of await readdir(casRoot)) casBytes += (await readFile(path.join(casRoot, name))).length;
    const supervisorBytes = signed.contents.find(entry => entry.role === 'supervisor')!.bytes.length;
    // Package verification still reads every declared entry, including the
    // delegated image. R retains that original CAS holder in signed.entries;
    // casFiles contains only the remaining mirrors, never a second image FD.
    const revalidationBytes = activeBytes + packageBytes + supervisorBytes + casBytes - image.length;
    diagnostic.subscribe(subscriber);
    selected = await runtime.openSelected(stateRoot);
    const opened = observed.at(-1)!;
    assert.deepEqual({ ...opened.package, spanElapsedMs: 0 }, { started: 1, completed: 1, bytesRead: packageBytes, spanElapsedMs: 0 });
    assert.deepEqual({ ...opened.revalidate, spanElapsedMs: 0 }, { started: 1, completed: 1, bytesRead: revalidationBytes, spanElapsedMs: 0 });
    await selected.assertHeld();
    assert.equal(observed.at(-1)!.revalidate.bytesRead, revalidationBytes * 2);
    const supervisor = path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, 'supervisor');
    await chmod(supervisor, 0o700); await writeFile(supervisor, 'changed'); await chmod(supervisor, 0o500);
    await assert.rejects(selected.assertHeld(), { code: 'ARTIFACT_MISMATCH' });
    assert.equal(observed.at(-1)!.revalidate.started, 3); assert.equal(observed.at(-1)!.revalidate.completed, 3);
  } finally {
    diagnostic.unsubscribe(subscriber); await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

function exactSourceRecipeCorruption(reference: string) {
  return (error: unknown) => error instanceof Error && error.name === 'Error' &&
    error.message === `artifact ${reference} is corrupt` && !('code' in error);
}

test('source recipe corruption expectations match the actual CAS guard and refuse unrelated storage failures', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-recipe-corrupt-guard-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cas = new ContentAddressedStore(root), bytes = Buffer.from('complete ordinary CAS recipe data\n'), ref = await cas.publish(bytes);
  const filename = path.join(root, ref); await chmod(filename, 0o600);
  const changed = Buffer.from(bytes); changed[changed.length - 1] ^= 1;
  await writeFile(filename, changed); await chmod(filename, 0o400);
  const matches = exactSourceRecipeCorruption(ref);
  await assert.rejects(cas.read(ref), matches);
  assert.deepEqual(await readFile(filename), changed, 'the rejected CAS bytes remain unrepaired');
  for (const error of [Object.assign(new Error(`artifact ${ref} is corrupt`), { code: 'ENOSPC' }),
    new ResourceRetirementError(`artifact ${ref} is corrupt`, new Error('negative retirement report')),
    new Error(`artifact ${'0'.repeat(64)} is corrupt`), new Error('unrelated read failure'),
    { name: 'Error', message: `artifact ${ref} is corrupt` }]) assert.equal(matches(error), false);
});

if (process.platform === 'linux') test('source preparation retains its two original fixed recipe members as inert CAS data through the held installation', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-source-recipe-retain-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined;
  try {
    const inspector = sourceInspectorFile(), controllerBytes = Buffer.from('opaque controller data; never executed by this test\n');
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, undefined, inspector, undefined, undefined, controllerBytes);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installed = await runtime.installInitial({ packageRoot, stateRoot }); selected = await runtime.openSelected(stateRoot);
    const members = signed.contents.filter(entry => ['source_git_inspector', 'linux_worker_controller'].includes(entry.entryId));
    assert.equal(members.length, 2);
    for (const entry of members) await assert.rejects(lstat(path.join(stateRoot, KERNEL_CAS_DIRECTORY, sha256Bytes(entry.bytes))), { code: 'ENOENT' });
    await retainInstalledSourceGitRecipe(selected);
    for (const entry of members) {
      const original = path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, entry.relativePath);
      const audit = path.join(stateRoot, KERNEL_CAS_DIRECTORY, sha256Bytes(entry.bytes));
      const [host, cas] = await Promise.all([lstat(original), lstat(audit)]);
      assert.equal(host.nlink, 1); assert.equal(cas.nlink, 1); assert.equal(cas.mode & 0o7777, 0o400);
      assert.equal(host.mode & 0o7777, entry.executable ? 0o500 : 0o400);
      assert.notEqual(`${host.dev}:${host.ino}`, `${cas.dev}:${cas.ino}`);
      assert.deepEqual(await readFile(original), entry.bytes); assert.deepEqual(await readFile(audit), entry.bytes);
    }
    await retainInstalledSourceGitRecipe(selected); // Existing CAS must be completely verified again.
    const inspectorRef = sha256Bytes(inspector.bytes), audit = path.join(stateRoot, KERNEL_CAS_DIRECTORY, inspectorRef);
    await chmod(audit, 0o600);
    const writer = await open(audit, constants.O_WRONLY | constants.O_NOFOLLOW);
    try { await writer.write(Buffer.from([inspector.bytes[0]! ^ 1]), 0, 1, 0); await writer.sync(); }
    finally { await writer.close(); }
    await chmod(audit, 0o400);
    await assert.rejects(retainInstalledSourceGitRecipe(selected), exactSourceRecipeCorruption(inspectorRef));
    assert.notDeepEqual(await readFile(audit), inspector.bytes, 'the old corrupted CAS object is not overwritten from a current host file');
    await assert.rejects(new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY)).read(inspectorRef), exactSourceRecipeCorruption(inspectorRef));
    const closedSelection = selected;
    await selected.close(); selected = undefined;
    assert.throws(() => retainInstalledSourceGitRecipe(closedSelection), { code: 'ARTIFACT_MISMATCH' });
    await assert.rejects(lstat(path.join(stateRoot, KERNEL_DATABASE_FILENAME)), { code: 'ENOENT' });
    assert.throws(() => retainInstalledSourceGitRecipe({} as HeldInstalledRuntime), { code: 'ARTIFACT_MISMATCH' });
  } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
});

if (process.platform === 'linux') for (const mutation of ['missing', 'replacement', 'symlink', 'hardlink', 'mode', 'length'] as const)
  test(`held single-CAS custody refuses actual ${mutation} drift before lending the image again`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-single-cas-drift-')));
    let selected: HeldInstalledRuntime | undefined;
    try {
      const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state'), image = Buffer.alloc(65_537, 0x61);
      const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      await runtime.installInitial({ packageRoot, stateRoot }); selected = await runtime.openSelected(stateRoot);
      await selected.assertHeld();
      const filename = path.join(stateRoot, KERNEL_CAS_DIRECTORY, sha256Bytes(image)), other = path.join(fixture, 'original-image');
      if (mutation === 'missing') await rm(filename);
      else if (mutation === 'replacement' || mutation === 'symlink') {
        await installFixtureFs.rename(filename, other);
        if (mutation === 'replacement') await writeFile(filename, image, { flag: 'wx', mode: 0o400 });
        else await installFixtureFs.symlink(other, filename);
      } else if (mutation === 'hardlink') await installFixtureFs.link(filename, other);
      else {
        await chmod(filename, 0o600);
        if (mutation === 'length') { await installFixtureFs.truncate(filename, image.length - 1); await chmod(filename, 0o400); }
      }
      await assert.rejects(selected.assertHeld(), { code: mutation === 'missing' ? 'ENOENT' : 'ARTIFACT_MISMATCH' });
    } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
  });

if (process.platform === 'linux') for (const copy of ['obsolete_bundle', 'cas'] as const) {
  test(`single-CAS selection rejects ${copy === 'cas' ? 'the last corrupted CAS byte' : 'an identical extra image at the obsolete bundle path'}`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), `cliq-installed-${copy}-tail-`)));
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    let selected: HeldInstalledRuntime | undefined;
    try {
      const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61);
      image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
      const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      const installation = await runtime.installInitial({ packageRoot, stateRoot }), ref = sha256Bytes(image);
      const entry = signed.bundle.entries.find(value => value.digest === ref)!;
      const installedImage = path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, entry.relativePath);
      const casImage = path.join(stateRoot, KERNEL_CAS_DIRECTORY, ref);
      const sourceImage = path.join(packageRoot, entry.relativePath);
      const sourceInfo = await lstat(sourceImage), casInfo = await lstat(casImage);
      assert.equal(sourceInfo.nlink, 1); assert.equal(casInfo.nlink, 1);
      assert.notEqual(`${sourceInfo.dev}:${sourceInfo.ino}`, `${casInfo.dev}:${casInfo.ino}`);
      await assert.rejects(lstat(installedImage), { code: 'ENOENT' });
      assert.deepEqual(await readFile(sourceImage), image); assert.deepEqual(await readFile(casImage), image);
      if (copy === 'obsolete_bundle') {
        await mkdir(path.dirname(installedImage), { recursive: true, mode: 0o700 });
        await writeFile(installedImage, image, { flag: 'wx', mode: 0o400 });
        await assert.rejects(async () => { selected = await runtime.openSelected(stateRoot); }, error =>
          error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
          error.message === 'installed runtime graph contains missing or unsigned paths');
        assert.deepEqual(await readFile(casImage), image);
        return;
      }
      // This owner-controlled corruption precedes openSelected's fresh stat.
      // Refusal must therefore reach the full signed digest, not an old mtime.
      const filename = casImage;
      await chmod(filename, 0o600);
      const handle = await open(filename, constants.O_WRONLY | constants.O_NOFOLLOW);
      try {
        const { bytesWritten } = await handle.write(Buffer.from([0x62]), 0, 1, image.length - 1);
        assert.equal(bytesWritten, 1); await handle.sync();
      } finally { await handle.close(); }
      await chmod(filename, 0o400);
      assert.deepEqual(await readFile(sourceImage), image,
        'the complete independent source cannot substitute for corrupt installed custody');
      await assert.rejects(async () => { selected = await runtime.openSelected(stateRoot); }, error =>
        error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' &&
        error.message === 'installed runtime signed file digest differs');
    } finally { await selected?.close(); await rm(fixture, { recursive: true, force: true }); }
  });
}

if (process.platform === 'linux') test('successive installed borrows re-read every byte while sharing only idle hash threads, and close joins them', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-reuse-')));
  const diagnostic = channel(INSTALLED_WORK_CHANNEL), observed: InstalledWorkSnapshot[] = [];
  const subscriber = (value: unknown) => { if (value && typeof value === 'object') observed.push(value as InstalledWorkSnapshot); };
  const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
  const workers = new Set<Worker>(), exited = new Set<Worker>(), ids = new Set<number>();
  let selected: HeldInstalledRuntime | undefined, other: HeldInstalledRuntime | undefined, armed = false, smallJobs = 0, imageJobs = 0;
  try {
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61);
    const controller = Buffer.alloc(8 * 1_048_576 + 43, 0x43);
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image,
      undefined, undefined, undefined, controller);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    const imageInfo = await lstat(path.join(stateRoot, KERNEL_CAS_DIRECTORY, sha256Bytes(image)), { bigint: true });
    Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
      const message = args[0] as { fd?: number; id?: number; byteCount?: number } | undefined;
      if (armed && typeof message?.fd === 'number') {
        if (!workers.has(this)) { workers.add(this); this.once('exit', () => exited.add(this)); }
        assert(Number.isSafeInteger(message.id)); assert(!ids.has(message.id!)); ids.add(message.id!);
        if (message.byteCount === image.length) {
          const actual = fstatSync(message.fd, { bigint: true });
          assert.equal(actual.dev, imageInfo.dev); assert.equal(actual.ino, imageInfo.ino); imageJobs++;
        }
        if (message.byteCount! < 8_388_608) smallJobs++;
      }
      return Reflect.apply(descriptor.value, this, args);
    } });
    diagnostic.subscribe(subscriber); armed = true;
    selected = await runtime.openSelected(stateRoot);
    const initial = observed.at(-1)!.revalidate, bytes = initial.bytesRead - observed[0]!.revalidate.bytesRead;
    const initialImageJobs = imageJobs;
    assert.equal(workers.size, 2); assert.equal(exited.size, 0);
    for (let round = 1; round <= 16; round++) {
      await selected.assertHeld();
      const current = observed.at(-1)!.revalidate;
      assert.equal(current.bytesRead - initial.bytesRead, round * bytes);
      assert.equal(current.completed - initial.completed, round);
      assert.equal(imageJobs - initialImageJobs, round, 'each original R fully hashes the one actual installed CAS image exactly once');
      assert.equal(workers.size, 2, 'threads, not results or observations, may be retained');
      assert.equal(exited.size, 0);
    }
    const originalSmallJobs = smallJobs;
    other = await runtime.openSelected(stateRoot);
    assert(smallJobs > originalSmallJobs, 'fresh package standalone reads use the original idle pool');
    assert.equal(workers.size, 2, 'fresh package verification reuses healthy threads, never FD or hash results');
    assert.equal(exited.size, 0);
    await selected.assertHeld();
    assert.equal(workers.size, 2, 'two live original Scopes share only the current idle executor');
    await selected.close(); selected = undefined;
    assert.equal(exited.size, workers.size, 'idle threads are genuine resources owned until selected close');
    await other.assertHeld();
    assert.equal(workers.size, 4, 'a still-live Scope starts fresh threads after the shared close barrier');
    await other.close(); other = undefined;
    assert.equal(exited.size, workers.size);
  } finally {
    armed = false; diagnostic.unsubscribe(subscriber);
    Object.defineProperty(Worker.prototype, 'postMessage', descriptor);
    await other?.close(); await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') test('a cancelled original revalidation job joins before selected close and a fresh selection verifies all image bytes', async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-image-cancel-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  const diagnostic = channel(INSTALLED_WORK_CHANNEL), abort = new AbortController();
  const reason = new Error('complete image verification cancelled');
  let selected: HeldInstalledRuntime | undefined, reopened: HeldInstalledRuntime | undefined;
  let closing: Promise<void> | undefined, armed = false, scheduled = false;
  let baselineStarted = 0, initialReadBase: number | undefined, last: InstalledWorkSnapshot | undefined;
  const subscriber = (value: unknown) => {
    if (!value || typeof value !== 'object') return;
    last = value as InstalledWorkSnapshot;
    initialReadBase ??= last.revalidate.bytesRead;
    if (armed && !scheduled && last.revalidate.started > baselineStarted) {
      scheduled = true;
      // The real original job is registered, not a fabricated I/O owner. This
      // checks entry cancellation/close, not an in-flight pread fault seam.
      abort.abort(reason); closing = selected!.close();
    }
  };
  try {
    const image = Buffer.alloc(3 * 1_048_576 + 17, 0x61);
    image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    diagnostic.subscribe(subscriber);
    selected = await runtime.openSelected(stateRoot);
    const opened = last!;
    const completeBytes = opened.revalidate.bytesRead - initialReadBase!;
    baselineStarted = opened.revalidate.started; armed = true;
    let borrowed = false;
    await assert.rejects(withHeldInstalledRuntime(selected, async () => { borrowed = true; }, abort.signal), error => error === reason);
    assert.equal(borrowed, false, 'a cancelled prefix is not a successful verified borrow');
    assert.equal(scheduled, true);
    await closing;
    assert.equal(last!.revalidate.started, opened.revalidate.started + 1);
    assert.equal(last!.revalidate.completed, opened.revalidate.completed + 1);
    armed = false;
    const beforeReopen = last!;
    reopened = await runtime.openSelected(stateRoot);
    assert.equal(last!.revalidate.bytesRead - beforeReopen.revalidate.bytesRead, completeBytes,
      'a fresh selection repeats the entire original bundle and independent CAS image');
    await reopened.assertHeld();
    assert.equal(last!.revalidate.bytesRead - beforeReopen.revalidate.bytesRead, completeBytes * 2);
  } finally {
    armed = false; diagnostic.unsubscribe(subscriber);
    await closing; await reopened?.close(); await selected?.close();
    await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') for (const operation of ['borrow-close', 'observation-close', 'observation-execute'] as const) test(
  `${operation} waits for a submitted real image read to deliver after cancellation`, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-image-read-join-')));
  const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
  let selected: HeldInstalledRuntime | undefined, reopened: HeldInstalledRuntime | undefined;
  let verification: Promise<void> | undefined, closing: Promise<void> | undefined;
  let prototype: object | undefined, readDescriptor: PropertyDescriptor | undefined;
  let captured: FileHandle | undefined, closeDescriptor: PropertyDescriptor | undefined;
  let releaseDelivery!: () => void, actualReturned!: (bytesRead: number) => void;
  const delivery = new Promise<void>(resolve => { releaseDelivery = resolve; });
  const returned = new Promise<number>(resolve => { actualReturned = resolve; });
  const diagnostic = channel(INSTALLED_WORK_CHANNEL);
  let initialReadBase: number | undefined, observed: InstalledWorkSnapshot | undefined;
  const subscriber = (value: unknown) => {
    if (!value || typeof value !== 'object') return;
    observed = value as InstalledWorkSnapshot; initialReadBase ??= observed.revalidate.bytesRead;
  };
  let reads = 0, closeAttempts = 0, verificationSettled = false, closeSettled = false, borrowed = false;
  const restore = () => {
    if (prototype && readDescriptor) Object.defineProperty(prototype, 'read', readDescriptor);
    if (captured && closeDescriptor) Object.defineProperty(captured, 'close', closeDescriptor);
  };
  try {
    const image = Buffer.alloc(3 * 1_048_576 + 17, 0x61);
    image.fill(0x63, 1_048_576, 2 * 1_048_576); image[image.length - 1] = 0x7a;
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    const installation = await runtime.installInitial({ packageRoot, stateRoot });
    diagnostic.subscribe(subscriber);
    selected = await runtime.openSelected(stateRoot);
    const completeBytes = observed!.revalidate.bytesRead - initialReadBase!;
    const imageRef = sha256Bytes(image), entry = signed.bundle.entries.find(value => value.digest === imageRef)!;
    const filename = path.join(stateRoot, KERNEL_CAS_DIRECTORY, imageRef);
    assert.equal(entry.byteCount, image.length);
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/bundles', installation.bundleDigest, entry.relativePath)), { code: 'ENOENT' });
    const expected = await lstat(filename, { bigint: true });
    const probe = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { prototype = Object.getPrototypeOf(probe); }
    finally { await probe.close(); }
    readDescriptor = Object.getOwnPropertyDescriptor(prototype!, 'read')!;
    const originalRead = readDescriptor.value as FileHandle['read'];
    Object.defineProperty(prototype!, 'read', { ...readDescriptor, value: function (this: FileHandle, ...args: unknown[]) {
      // Complete every potentially throwing identity/descriptor check before
      // submitting I/O, so a test observer failure cannot orphan a real read.
      const actual = fstatSync(this.fd, { bigint: true });
      if (actual.dev !== expected.dev || actual.ino !== expected.ino || ++reads !== 2)
        return Reflect.apply(originalRead, this, args);
      captured = this;
      closeDescriptor = Object.getOwnPropertyDescriptor(this, 'close')!;
      assert(closeDescriptor?.configurable && typeof closeDescriptor.value === 'function');
      const originalClose = closeDescriptor.value as FileHandle['close'];
      Object.defineProperty(this, 'close', { ...closeDescriptor, value: function (this: FileHandle, ...closeArgs: unknown[]) {
        closeAttempts++; return Reflect.apply(originalClose, this, closeArgs);
      } });
      // Now the original genuine FileHandle submits the real system I/O. Its
      // unchanged result promise is immediately owned by the returned chain.
      const result = Reflect.apply(originalRead, this, args) as ReturnType<FileHandle['read']>;
      return result.then(async value => {
        // The OS read has already returned. Only JS delivery is delayed; this
        // is explicitly not a physical slow-disk or stalled-kernel fixture.
        actualReturned(value.bytesRead); await delivery; return value;
      });
    } });
    const abort = new AbortController(), reason = new Error('submitted image read cancelled');
    verification = operation === 'borrow-close'
      ? withHeldInstalledRuntime(selected, async () => { borrowed = true; }, abort.signal)
      : readInstalledRuntimeObservation(selected, abort.signal).then(() => { borrowed = true; });
    void verification.then(() => { verificationSettled = true; }, () => { verificationSettled = true; });
    assert((await Promise.race([returned, verification.then(() => { throw new Error('real image read was not observed'); })])) > 0);
    if (operation === 'observation-execute') {
      // The real terminal consumer must cancel/join observation reads before
      // trying to load this deliberately non-executable addon fixture. No
      // actual exec or fake native image is accepted by the existing guard.
      const refused = runtime.executeSelected(selected, 'supervisor');
      closing = assert.rejects(refused, error => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH' ||
        (error as NodeJS.ErrnoException).code === 'ERR_DLOPEN_FAILED');
    } else {
      // The old business borrow keeps its explicit cancellation regression.
      // The new observation must instead be cancelled by close itself.
      if (operation === 'borrow-close') abort.abort(reason);
      closing = selected.close();
    }
    void closing.then(() => { closeSettled = true; }, () => { closeSettled = true; });
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(verificationSettled, false, 'the submitted original read has not delivered');
    assert.equal(closeAttempts, 0, 'the original FileHandle must not close before its read delivers');
    assert.equal(closeSettled, false);
    releaseDelivery();
    await assert.rejects(verification, error => operation === 'borrow-close'
      ? error === reason : (error as Error).name === 'AbortError');
    await closing;
    assert.equal(borrowed, false);
    assert.equal(closeAttempts, 1, 'the original image descriptor retires once, after the read joins');
    restore();
    const beforeReopen = observed!.revalidate.bytesRead;
    reopened = await runtime.openSelected(stateRoot);
    assert.equal(observed!.revalidate.bytesRead - beforeReopen, completeBytes);
    await reopened.assertHeld();
    assert.equal(observed!.revalidate.bytesRead - beforeReopen, completeBytes * 2);
  } finally {
    releaseDelivery();
    await Promise.allSettled([...(verification ? [verification] : []), ...(closing ? [closing] : [])]);
    restore();
    await reopened?.close(); await selected?.close();
    diagnostic.unsubscribe(subscriber);
    await rm(fixture, { recursive: true, force: true });
  }
});

// Test rendezvous only: these values identify issued tasks, never authorize a
// Worker, descriptor or joined receipt. A wrong pool width must reach the exact
// width assertion rather than wait for a shutdown the test itself withholds.
function allDispatchedWorkersClosing<T>(workers: ReadonlySet<T>, closings: readonly { worker: T }[]): boolean {
  return workers.size > 0 && [...workers].every(worker => closings.some(closing => closing.worker === worker));
}

test('hash shutdown rendezvous follows the actual dispatched identities before the exact pool-width assertion', () => {
  const first = Symbol('first issued task'), second = Symbol('second issued task');
  const dispatched = new Set([first, second]), closing = [{ worker: first }];
  assert.equal(allDispatchedWorkersClosing(dispatched, closing), false);
  assert.equal(allDispatchedWorkersClosing(dispatched, [{ worker: first }, { worker: first }]), false);
  closing.push({ worker: second });
  assert.equal(allDispatchedWorkersClosing(dispatched, closing), true);
  assert.throws(() => assert.equal(dispatched.size, 4), { code: 'ERR_ASSERTION' },
    'a two-task regression reaches the unchanged exact four-worker refusal');
  const third = Symbol('third issued task'), fourth = Symbol('fourth issued task');
  dispatched.add(third); dispatched.add(fourth);
  assert.equal(allDispatchedWorkersClosing(dispatched, closing), false);
  closing.push({ worker: third }, { worker: fourth });
  assert.equal(allDispatchedWorkersClosing(dispatched, closing), true);
  assert.equal(allDispatchedWorkersClosing(new Set<symbol>(), []), false);
});

test('opaque signed hash fixtures declare two or four independent large holders without a second guest copy', async t => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-hash-width-data-')));
  t.after(() => rm(fixture, { recursive: true, force: true }));
  for (const laneCount of [2, 4] as const) {
    const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61); image[image.length - 1] = 0x7a;
    const supervisor = laneCount === 4 ? Buffer.alloc(8 * 1_048_576 + 31, 0x73) : undefined;
    const controller = Buffer.alloc(8 * 1_048_576 + 43, 0x43);
    const signed = await writeInstallerOnlyPackage(path.join(fixture, String(laneCount)), undefined, supervisor, image,
      undefined, undefined, undefined, controller);
    const entry = signed.bundle.entries.find(value => value.entryId === 'linux_worker_controller')!;
    assert.equal(entry.byteCount, controller.length); assert.equal(entry.digest, sha256Bytes(controller));
    assert.notEqual(entry.digest, sha256Bytes(image));
    const largeEntries = signed.bundle.entries.filter(value => value.byteCount >= 8_388_608);
    // Metadata arithmetic only, not actual Linux pool/FD qualification: the
    // selected read has one entry per signed member plus its separate bootstrap.
    const bootstrap = signed.bundle.entries.find(value => value.role === 'supervisor')!;
    const largeCount = largeEntries.length + Number(bootstrap.byteCount >= 8_388_608);
    assert.equal(largeCount, laneCount);
    assert.equal(largeEntries.filter(value => value.digest === sha256Bytes(image)).length, 1);
    for (const value of largeEntries) {
      const bytes = await readFile(path.join(fixture, String(laneCount), value.relativePath));
      assert.equal(bytes.length, value.byteCount); assert.equal(sha256Bytes(bytes), value.digest);
    }
  }
});

if (process.platform === 'linux') for (const laneCount of [2, 4] as const) test(`discard batches join all ${laneCount} actual hash Workers before original image FDs close`, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-exit-')));
  let selected: HeldInstalledRuntime | undefined, reopened: HeldInstalledRuntime | undefined;
  let checking: Promise<void> | undefined, closing: Promise<void> | undefined;
  let prototype: object | undefined, statDescriptor: PropertyDescriptor | undefined;
  const postDescriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
  const actual = new Map<number, FileHandle>(), workers = new Set<Worker>(), exited = new Set<Worker>();
  const closes = new Map<FileHandle, { descriptor: PropertyDescriptor; attempts: number }>();
  const delayed: Array<{ worker: Worker; args: unknown[] }> = [];
  let armed = false, borrowed = false, earlyClose = false, firstReply = false, ready!: () => void;
  const abort = new AbortController(), reason = new Error('owned parallel verification cancelled');
  const bothClosing = new Promise<void>(resolve => { ready = resolve; });
  const release = () => { for (const job of delayed.splice(0)) Reflect.apply(postDescriptor.value, job.worker, job.args); };
  const restore = () => {
    Object.defineProperty(Worker.prototype, 'postMessage', postDescriptor);
    if (prototype && statDescriptor) Object.defineProperty(prototype, 'stat', statDescriptor);
    for (const [handle, value] of closes) Object.defineProperty(handle, 'close', value.descriptor);
  };
  try {
    const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
    const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61); image[image.length - 1] = 0x7a;
    const supervisor = laneCount === 4 ? Buffer.alloc(8 * 1_048_576 + 31, 0x73) : undefined;
    const controller = Buffer.alloc(8 * 1_048_576 + 43, 0x43);
    const signed = await writeInstallerOnlyPackage(packageRoot, undefined, supervisor, image,
      undefined, undefined, undefined, controller);
    const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
    await runtime.installInitial({ packageRoot, stateRoot });
    const probe = await open(path.join(stateRoot, 'runtime/active.json'), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { prototype = Object.getPrototypeOf(probe); } finally { await probe.close(); }
    statDescriptor = Object.getOwnPropertyDescriptor(prototype!, 'stat')!;
    Object.defineProperty(prototype!, 'stat', { ...statDescriptor, value: function (this: FileHandle, ...args: unknown[]) {
      if (armed) actual.set(this.fd, this);
      return Reflect.apply(statDescriptor!.value, this, args);
    } });
    Object.defineProperty(Worker.prototype, 'postMessage', { ...postDescriptor, value: function (this: Worker, ...args: unknown[]) {
      const message = args[0] as { fd?: number; kind?: string } | undefined;
      if (typeof message?.fd === 'number') {
        if (!workers.has(this)) { workers.add(this); this.once('exit', () => exited.add(this)); }
      }
      if (armed && typeof message?.fd === 'number') {
        if (!firstReply) {
          firstReply = true;
          // Cancel only after an original Worker has returned its actual hash
          // packet. No bytes/syscall/positive proof are fabricated or paused.
          this.prependOnceListener('message', () => abort.abort(reason));
        }
        const handle = actual.get(message.fd); assert(handle, 'the real original parent FileHandle preceded dispatch');
        if (!closes.has(handle)) {
          const descriptor = Object.getOwnPropertyDescriptor(handle, 'close')!;
          const record = { descriptor, attempts: 0 }; closes.set(handle, record);
          Object.defineProperty(handle, 'close', { ...descriptor, value: function (this: FileHandle, ...closeArgs: unknown[]) {
            record.attempts++; if ([...workers].some(worker => !exited.has(worker))) earlyClose = true;
            return Reflect.apply(descriptor.value, this, closeArgs);
          } });
        }
      }
      if (armed && workers.has(this) && message?.kind === 'close') {
        // Real hashing has completed; delay only JS delivery of shutdown to
        // the original Worker. This does not claim physically blocked I/O.
        delayed.push({ worker: this, args }); if (allDispatchedWorkersClosing(workers, delayed)) ready(); return;
      }
      return Reflect.apply(postDescriptor.value, this, args);
    } });
    selected = await runtime.openSelected(stateRoot); armed = true;
    checking = withHeldInstalledRuntime(selected, async () => { borrowed = true; }, abort.signal);
    await Promise.race([bothClosing, checking.then(() => { throw new Error('actual hash Workers were not observed'); })]);
    assert.equal(workers.size, laneCount); assert.equal(exited.size, 0);
    abort.abort(reason); closing = selected.close(); await new Promise<void>(resolve => setImmediate(resolve));
    assert([...closes.values()].every(value => value.attempts === 0));
    release(); await assert.rejects(checking, error => error === reason); await closing;
    assert.equal(borrowed, false); assert.equal(earlyClose, false); assert.equal(exited.size, laneCount);
    assert([...closes.values()].every(value => value.attempts === 1));
    armed = false; restore(); reopened = await runtime.openSelected(stateRoot); await reopened.assertHeld();
  } finally {
    armed = false; release(); await Promise.allSettled([...(checking ? [checking] : []), ...(closing ? [closing] : [])]);
    restore(); await reopened?.close(); await selected?.close(); await rm(fixture, { recursive: true, force: true });
  }
});

if (process.platform === 'linux') for (const fault of ['nonplain', 'unsolicited_cancelled', 'undefined_dispatch'] as const) {
  test(`actual hash Worker ${fault} refuses verification, joins, and cannot clear its failure`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-refusal-')));
    let selected: HeldInstalledRuntime | undefined, armed = false, injected = false, borrowed = false;
    const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
    const workers = new Set<Worker>(), exited = new Set<Worker>();
    try {
      const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
      const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61); image[image.length - 1] = 0x7a;
      const controller = Buffer.alloc(8 * 1_048_576 + 43, 0x43);
      const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image,
        undefined, undefined, undefined, controller);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      await runtime.installInitial({ packageRoot, stateRoot }); selected = await runtime.openSelected(stateRoot);
      Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
        const message = args[0] as { fd?: number } | undefined;
        if (armed && typeof message?.fd === 'number') {
          if (!workers.has(this)) { workers.add(this); this.once('exit', () => exited.add(this)); }
          if (!injected) {
            injected = true;
            if (fault === 'undefined_dispatch') throw undefined;
            // Only alter a genuine child's returned inert packet. No positive
            // proof/Worker/FD is fabricated and no private runtime export exists.
            this.prependOnceListener('message', (reply: { code: string; digest?: string }) => {
              if (fault === 'nonplain') Object.setPrototypeOf(reply, null);
              else { reply.code = 'cancelled'; delete reply.digest; }
            });
          }
        }
        return Reflect.apply(descriptor.value, this, args);
      } });
      armed = true;
      let rejected = false, reason: unknown;
      await withHeldInstalledRuntime(selected, async () => { borrowed = true; }).then(
        () => undefined, error => { rejected = true; reason = error; });
      assert.equal(injected, true); assert.equal(rejected, true); assert.equal(borrowed, false);
      assert.equal(exited.size, workers.size, 'every observed real thread exited before rejection returned');
      if (fault === 'undefined_dispatch') assert.equal(reason, undefined);
      else assert(reason instanceof KernelStorageError && reason.code === 'ARTIFACT_MISMATCH');
      const before = workers.size; rejected = false;
      await selected.assertHeld().then(() => undefined, error => { rejected = true; assert.equal(error, reason); });
      assert.equal(rejected, true); assert.equal(workers.size, before, 'sticky failure never silently starts replacement work');
    } finally {
      armed = false; Object.defineProperty(Worker.prototype, 'postMessage', descriptor);
      await selected?.close(); await rm(fixture, { recursive: true, force: true });
    }
  });
}

if (process.platform === 'linux') for (const fault of ['idle_exit', 'idle_exit_close', 'stale_reply'] as const) {
  test(`an actual idle hash Worker ${fault} is retained as a failure, never silently replaced`, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-hash-idle-failure-')));
    const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage')!;
    const workers = new Set<Worker>(), exited = new Set<Worker>();
    let selected: HeldInstalledRuntime | undefined, packet: unknown, original: Worker | undefined;
    try {
      const packageRoot = path.join(fixture, 'package'), stateRoot = path.join(fixture, 'state');
      const image = Buffer.alloc(8 * 1_048_576 + 17, 0x61);
      const controller = Buffer.alloc(8 * 1_048_576 + 43, 0x43);
      const signed = await writeInstallerOnlyPackage(packageRoot, undefined, undefined, image,
        undefined, undefined, undefined, controller);
      const runtime = createInstalledRuntime({ releaseKeys: signed.releaseKeys });
      await runtime.installInitial({ packageRoot, stateRoot });
      Object.defineProperty(Worker.prototype, 'postMessage', { ...descriptor, value: function (this: Worker, ...args: unknown[]) {
        const message = args[0] as { fd?: number } | undefined;
        if (typeof message?.fd === 'number' && !workers.has(this)) {
          workers.add(this); this.once('exit', () => exited.add(this));
          if (!original) { original = this; this.once('message', reply => { packet = structuredClone(reply); }); }
        }
        return Reflect.apply(descriptor.value, this, args);
      } });
      selected = await runtime.openSelected(stateRoot);
      assert(original && packet, 'the two-large signed fixture must dispatch a real Worker and receive its original packet');
      assert.equal(workers.size, 2); assert.equal(exited.size, 0);
      if (fault !== 'stale_reply') await original.terminate();
      else {
        // Replay only an already returned inert packet from this real Worker.
        // This malicious negative response creates no positive authority/proof.
        original.emit('message', packet);
      }
      if (fault === 'idle_exit_close') {
        await assert.rejects(selected.close(), { code: 'ARTIFACT_MISMATCH' }); selected = undefined;
        assert.equal(exited.size, workers.size, 'close reports the original idle failure after every actual exit');
        return;
      }
      let borrowed = false;
      await assert.rejects(withHeldInstalledRuntime(selected, async () => { borrowed = true; }), { code: 'ARTIFACT_MISMATCH' });
      assert.equal(borrowed, false); assert.equal(workers.size, 2);
      assert.equal(exited.size, workers.size, 'all original threads actually exit before refusal');
      await assert.rejects(selected.assertHeld(), { code: 'ARTIFACT_MISMATCH' });
      assert.equal(workers.size, 2, 'the failed selection cannot transparently start a replacement executor');
    } finally {
      Object.defineProperty(Worker.prototype, 'postMessage', descriptor);
      await selected?.close(); await rm(fixture, { recursive: true, force: true });
    }
  });
}

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
    assert.throws(() => readInstalledRuntimeObservation(selected!), { code: 'ARTIFACT_MISMATCH' });
    await closing;
    assert.throws(() => assertInstalledManagerObservationAvailable(selected!), { code: 'ARTIFACT_MISMATCH' });
    assert.throws(() => readInstalledRuntimeObservation(selected!), { code: 'ARTIFACT_MISMATCH' });
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
    const installedFile = path.join(stateRoot, KERNEL_CAS_DIRECTORY, imageRef);
    await assert.rejects(lstat(path.join(stateRoot, 'runtime/bundles', installed.bundleDigest, entry.relativePath)), { code: 'ENOENT' });
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


if (process.platform === 'linux') test('fixed initial-install stages complete only after the original real descriptor owners close', async t => {
  // Actual signed files/install/CAS only. Opaque executable fixtures never run
  // or create StateOwner/Run authority; this is not installed qualification.
  const root = await mkdtemp(path.join(await realpath(os.tmpdir()), 'cliq-initial-install-stages-'));
  const phaseChannel = channel(INSTALLED_INSTALL_PHASE_CHANNEL), phases: Array<{ phase: number; items: number }> = [];
  const active = new Set<FileHandle>(); let openCount = 0, closedAtComplete = false;
  const observer = (value: unknown) => {
    const phase = value as { phase: number; items: number }; phases.push(phase);
    if (phase.phase === 16) closedAtComplete = active.size === 0;
  };
  try {
    const signed = await writeInstallerOnlyPackage(path.join(root, 'package'));
    const publishFour = ContentAddressedStore.prototype.publishFour;
    let rootGroups = 0;
    const groupMock = t.mock.method(ContentAddressedStore.prototype, 'publishFour', function (this: ContentAddressedStore,
      ...args: Parameters<ContentAddressedStore['publishFour']>) {
      rootGroups++; return Reflect.apply(publishFour, this, args);
    });
    const actualOpen = installFixtureFs.open;
    const mock = t.mock.method(installFixtureFs, 'open', async (...args: Parameters<typeof installFixtureFs.open>) => {
      const handle = await actualOpen(...args), actualClose = handle.close.bind(handle); active.add(handle); openCount++;
      t.mock.method(handle, 'close', async () => { await actualClose(); assert(active.delete(handle)); }); return handle;
    });
    (await import('node:module')).syncBuiltinESMExports(); phaseChannel.subscribe(observer);
    try {
      const installed = await createInstalledRuntime({ releaseKeys: signed.releaseKeys }).installInitial({
        packageRoot: path.join(root, 'package'), stateRoot: path.join(root, 'state') });
      assert.equal(installed.bundleDigest, canonicalSha256(signed.bundle));
      assert(rootGroups > 0, 'the real initial installer uses the same complete four-root CAS protocol');
      assert.deepEqual([...new Set(phases.map(value => value.phase))], INSTALLED_INSTALL_PHASES.map((_, index) => index + 1));
      assert.equal(phases.at(-1)!.phase, 16); assert(openCount > 0); assert.equal(active.size, 0); assert.equal(closedAtComplete, true);
      const entryPhase = phases.filter(value => value.phase === 3).at(-1)!; assert.equal(entryPhase.items, signed.bundle.entries.length);
    } finally { phaseChannel.unsubscribe(observer); mock.mock.restore(); groupMock.mock.restore(); (await import('node:module')).syncBuiltinESMExports(); }
  } finally { phaseChannel.unsubscribe(observer); await rm(root, { recursive: true, force: true }); }
});
