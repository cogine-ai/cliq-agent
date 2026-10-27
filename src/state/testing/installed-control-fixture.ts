import { signedKernelSchemaProfile } from '../signed-schema.js';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { rootCertificates } from 'node:tls';

import { KERNEL_STATE_SCHEMA_VERSION } from '../../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { sha256Bytes } from '../../kernel/identity.js';
import { verifyInstalledModelAuthority, type InstalledModelAuthorityClosureV1,
  type SignedModelCatalogEntryV1 } from '../../model/installed-authority.js';
import { priceTableDigest, type ModelPriceTableV1 } from '../../model/pricing.js';
import { policyProfile, verifyRuntimeBundle, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_PATH, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../native-owner.js';

/** Actual current Node and built StateOwner addon bytes under an explicit test
 * release root. The installed bootstrap is not executed, and this is not SEA,
 * worker, headless-output, admission/model or complete I1 qualification.
 * The independently signed opaque worker is never exec'ed or dlopened. */
export async function writeInstalledControlPackage(packageRoot: string,
  options: { modelAuthority?: boolean; credentialPlatform?: string } = {}) {
  await mkdir(packageRoot, { mode: 0o700 });
  const profile = policyProfile();
  const rootCore = {
    schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'],
    persistent: false, networkConfiguration: 'none',
  };
  const rootRecipe = { ...rootCore, profileDigest: canonicalSha256(rootCore) };
  const contents = [
    { entryId: 'kernel_schema', role: 'schema', relativePath: 'schema/kernel-v8.json', executable: false, bytes: canonicalJsonBytes(signedKernelSchemaProfile()) },
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
  if (options.credentialPlatform) contents.push({ entryId: 'linux_credential_platform', role: 'platform_helper',
    relativePath: 'native/linux-x64/linux-credential-platform.node', executable: true,
    bytes: await readFile(options.credentialPlatform) });
  if (options.modelAuthority) contents.push({ entryId: 'unused-control-provider', role: 'provider_adapter',
    relativePath: 'adapters/unused-control-provider', executable: true,
    bytes: Buffer.from('signed control fixture opaque provider adapter; never execute or load\n') });
  const entries: RuntimeBundleManifest['entries'] = [];
  for (const { bytes, ...entry } of contents) {
    const filename = path.join(packageRoot, entry.relativePath);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, bytes, { flag: 'wx', mode: entry.executable ? 0o500 : 0o400 });
    entries.push({ ...entry, version: entry.entryId === 'kernel_schema' ? '8' : '1', digest: sha256Bytes(bytes), byteCount: bytes.byteLength });
  }
  const keys = generateKeyPairSync('ed25519');
  const bundle: RuntimeBundleManifest = {
    schemaVersion: 2, installedLayout: 'single_cas_streams_v1', bundleVersion: 'native-uds-read-fixture-v1',
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
    ['policy_engine', 'trust_store', 'sandbox_root_profile', 'schema'].includes(entry.role)).map(entry => entry.bytes)]
    .map(bytes => ({ artifactRef: sha256Bytes(bytes), bytes }));
  const modelAuthority = options.modelAuthority ? await writeControlCompanion(packageRoot, bundle, keys.privateKey) : undefined;
  if (modelAuthority) {
    verifyInstalledModelAuthority({ bundle, releaseKeys, closure: modelAuthority.closure, objects: modelAuthority.objects });
    seedObjects.push({ artifactRef: modelAuthority.closureRef, bytes: canonicalJsonBytes(modelAuthority.closure) },
      ...[...modelAuthority.objects].map(([artifactRef, bytes]) => ({ artifactRef, bytes })));
  }
  return { bundle, releaseKeys, seedObjects, modelAuthority };
}

/** Signed import bytes only. The opaque executable adapter is never loaded;
 * neither these claims/rates nor genesis qualify a provider or execution. */
async function writeControlCompanion(packageRoot: string, bundle: RuntimeBundleManifest, key: KeyObject) {
  const objects = new Map<string, Buffer>();
  const inventory: InstalledModelAuthorityClosureV1['objects'] = [];
  const retain = (bytes: Buffer, kind: InstalledModelAuthorityClosureV1['objects'][number]['kind']) => {
    const artifactRef = sha256Bytes(bytes);
    objects.set(artifactRef, bytes); inventory.push({ artifactRef, byteCount: bytes.length, kind });
    return artifactRef;
  };
  const signature = (domain: string, digest: string) => retain(sign(null, Buffer.from(`${domain}\0${digest}`), key), 'ed25519_signature');
  const adapter = bundle.entries.find(entry => entry.entryId === 'unused-control-provider')!;
  const common = { signerKeyId: bundle.publisherKeyId, signatureAlgorithm: 'ed25519' as const,
    provider: 'openai-compatible' as const, model: 'signed-control-import-only',
    endpointIdentityDigest: canonicalSha256({ fixture: 'control-companion-import-only' }),
    validFrom: '2026-01-01T00:00:00.000Z', validThrough: '2099-01-01T00:00:00.000Z' };
  const catalogCore = { schemaVersion: 1 as const, format: 'cliq-signed-model-catalog-entry-v1' as const, ...common,
    runtimeBundleRef: canonicalSha256(bundle), runtimeBundleManifestDigest: bundle.manifestDigest,
    adapter: { adapterId: adapter.entryId, version: adapter.version, codeDigest: adapter.digest },
    claims: { nativeToolCalling: true, streaming: false, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 8192 } };
  const catalogEntryDigest = canonicalSha256(catalogCore);
  const catalog: SignedModelCatalogEntryV1 = { ...catalogCore, catalogEntryDigest,
    signatureRef: signature('cliq-model-catalog-entry-v1', catalogEntryDigest) };
  retain(canonicalJsonBytes(catalog), 'model_catalog_entry');
  const price: ModelPriceTableV1 = { schemaVersion: 1, format: 'cliq-model-price-table-v1', ...common,
    signatureRef: '', currency: 'USD', unit: 'micros_per_million_tokens',
    prices: { input: 100, output: 200, cacheRead: 0, cacheWrite: 0 },
    requestTokenCeiling: { inputTokens: 32768, outputTokens: 8192, cacheReadTokens: 0, cacheWriteTokens: 0 }, tableDigest: '' };
  price.tableDigest = priceTableDigest(price);
  price.signatureRef = signature('cliq-model-price-table-v1', price.tableDigest);
  retain(canonicalJsonBytes(price), 'model_price_table');
  inventory.sort((left, right) => left.artifactRef < right.artifactRef ? -1 : 1);
  const core = { schemaVersion: 1 as const, format: 'cliq-installed-model-authority-v1' as const,
    publisherKeyId: bundle.publisherKeyId, signatureAlgorithm: 'ed25519' as const,
    runtimeBundleRef: canonicalSha256(bundle), runtimeBundleManifestDigest: bundle.manifestDigest, objects: inventory };
  const closureDigest = canonicalSha256(core);
  const closure: InstalledModelAuthorityClosureV1 = { ...core, closureDigest,
    signature: sign(null, Buffer.from(`cliq-installed-model-authority-v1\0${closureDigest}`), key).toString('base64') };
  await writeFile(path.join(packageRoot, 'model-authority.json'), canonicalJsonBytes(closure), { flag: 'wx', mode: 0o400 });
  for (const [ref, bytes] of objects) {
    const directory = path.join(packageRoot, 'model-objects/sha256', ref.slice(0, 2));
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(path.join(directory, ref), bytes, { flag: 'wx', mode: 0o400 });
  }
  return { closure, closureRef: canonicalSha256(closure), objects };
}
