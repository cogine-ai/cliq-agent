// Qualification-only signed package recipe, not a release publisher or I1.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { rootCertificates } from 'node:tls';
import { fileURLToPath } from 'node:url';

import { KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../../src/state/native-owner.js';
import { buildSupervisorSeaImage, prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

/** Construct the same actual SEA/helper package for independent Linux startup
 * and user-manager qualifiers. Its unused opaque worker grants no execution,
 * admission/model, release-signature or complete I1 qualification. */
export async function buildInstalledSupervisorPackage(fixture: string) {
  const repository = fileURLToPath(new URL('../../..', import.meta.url));
  const { nodeRoot, carrier } = await prepareSupervisorSeaCarrier(fixture);
  const keys = generateKeyPairSync('ed25519');
  const releaseKeys = [{ keyId: 'explicit-installed-startup-test-root',
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const rootAsset = path.join(fixture, 'release-trust-roots.json');
  await writeFile(rootAsset, canonicalJsonBytes(releaseKeys), { flag: 'wx', mode: 0o400 });
  const packageRoot = path.join(fixture, 'package');
  await mkdir(packageRoot, { mode: 0o700 });
  const supervisorFile = await buildSupervisorSeaImage({ fixture, carrier,
    entryPoint: path.join(repository, 'src/state/installed-entry.ts'),
    executable: path.join(packageRoot, 'supervisor'), variant: 'installed-supervisor',
    assets: { 'release-trust-roots.json': rootAsset } });
  const helper = path.join(packageRoot, STATE_OWNER_NATIVE_RELATIVE_PATH);
  await mkdir(path.dirname(helper), { recursive: true, mode: 0o700 });
  const compilation = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
    '-I', path.join(nodeRoot, 'include/node'), path.join(repository, 'native/state-owner/state-owner.c'), '-o', helper],
  { encoding: 'utf8', timeout: 60_000, cwd: fixture, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(compilation.error, undefined, `cc: ${compilation.error}`);
  assert.equal(compilation.status, 0, `cc: ${compilation.stderr}`);
  await chmod(helper, 0o500);
  const profile = policyProfile();
  const rootCore = { schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'], persistent: false, networkConfiguration: 'none' };
  const contents = [
    { entryId: 'installed-supervisor', role: 'supervisor', relativePath: 'supervisor', executable: true, bytes: await readFile(supervisorFile) },
    { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH,
      executable: true, bytes: await readFile(helper) },
    { entryId: 'unused-installed-worker', role: 'worker', relativePath: 'workers/worker', executable: true,
      bytes: Buffer.from('opaque qualification-only worker; never exec or dlopen\n') },
    { entryId: 'installed-policy', role: 'policy_engine', relativePath: 'profiles/policy.json', executable: false, bytes: canonicalJsonBytes(profile) },
    { entryId: 'default_https_trust_store', role: 'trust_store', relativePath: 'profiles/https-trust.pem', executable: false,
      bytes: Buffer.from(rootCertificates.join('\n')) },
    { entryId: 'installed-empty-root', role: 'sandbox_root_profile', relativePath: 'profiles/empty-root.json', executable: false,
      bytes: canonicalJsonBytes({ ...rootCore, profileDigest: canonicalSha256(rootCore) }) },
  ];
  for (const entry of contents.slice(2)) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, entry.bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
  }
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'installed-sea-read-qualification-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries: contents.map(({ bytes, ...entry }) => ({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength })),
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'installed-policy', rootEntryId: 'installed-policy',
      artifactRef: canonicalSha256(profile), semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: releaseKeys[0]!.keyId, manifestDigest: '', signature: '',
  };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  verifyRuntimeBundle(bundle, releaseKeys);
  await writeFile(path.join(packageRoot, 'manifest.json'), canonicalJsonBytes(bundle), { flag: 'wx', mode: 0o400 });
  return { packageRoot, releaseKeys, bundle, contents };
}
