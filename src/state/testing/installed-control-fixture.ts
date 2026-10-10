import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { rootCertificates } from 'node:tls';

import { KERNEL_STATE_SCHEMA_VERSION } from '../../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { sha256Bytes } from '../../kernel/identity.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_PATH, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../native-owner.js';

/** Actual current Node and built StateOwner addon bytes under an explicit test
 * release root. The installed bootstrap is not executed, and this is not SEA,
 * worker, headless-output, admission/model or complete I1 qualification.
 * The independently signed opaque worker is never exec'ed or dlopened. */
export async function writeInstalledControlPackage(packageRoot: string) {
  await mkdir(packageRoot, { mode: 0o700 });
  const profile = policyProfile();
  const rootCore = {
    schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'],
    persistent: false, networkConfiguration: 'none',
  };
  const rootRecipe = { ...rootCore, profileDigest: canonicalSha256(rootCore) };
  const contents = [
    { entryId: 'native-control-supervisor', role: 'supervisor', relativePath: 'supervisor', executable: true,
      bytes: await readFile(process.execPath) },
    { entryId: 'unused-control-worker', role: 'worker', relativePath: 'workers/worker', executable: true,
      bytes: Buffer.from('native control fixture opaque worker; never execute or load\n') },
    { entryId: STATE_OWNER_NATIVE_ENTRY_ID, role: 'platform_helper', relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH,
      executable: true, bytes: await readFile(STATE_OWNER_NATIVE_PATH) },
    { entryId: 'control-policy-v1', role: 'policy_engine', relativePath: 'profiles/policy.json', executable: false,
      bytes: canonicalJsonBytes(profile) },
    { entryId: 'default_https_trust_store', role: 'trust_store', relativePath: 'profiles/https-trust.pem', executable: false,
      bytes: Buffer.from(rootCertificates.join('\n')) },
    { entryId: 'control-empty-root', role: 'sandbox_root_profile', relativePath: 'profiles/empty-root.json', executable: false,
      bytes: canonicalJsonBytes(rootRecipe) },
  ];
  const entries: RuntimeBundleManifest['entries'] = [];
  for (const { bytes, ...entry } of contents) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
    entries.push({ ...entry, version: '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength });
  }
  const keys = generateKeyPairSync('ed25519');
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 1, bundleVersion: 'native-uds-read-fixture-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries,
    // The sandbox recipe is acyclic data, not a self-referential Run policy.
    // Only the fixed, self-contained policy profile has a structured root.
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'control-policy-v1', rootEntryId: 'control-policy-v1',
      artifactRef: canonicalSha256(profile), semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: 'explicit-native-control-test-root', manifestDigest: '', signature: '',
  };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const releaseKeys = [{ keyId: bundle.publisherKeyId,
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  verifyRuntimeBundle(bundle, releaseKeys);
  const manifestBytes = canonicalJsonBytes(bundle);
  await writeFile(path.join(packageRoot, 'manifest.json'), manifestBytes, { flag: 'wx', mode: 0o400 });

  // Independent expected payloads from the signed source package. These are
  // audit values only, never an allowlist or authority passed to StateStore.
  const seedObjects = [manifestBytes, ...contents.filter(entry =>
    ['policy_engine', 'trust_store', 'sandbox_root_profile'].includes(entry.role)).map(entry => entry.bytes)]
    .map(bytes => ({ artifactRef: sha256Bytes(bytes), bytes }));
  return { bundle, releaseKeys, seedObjects };
}
