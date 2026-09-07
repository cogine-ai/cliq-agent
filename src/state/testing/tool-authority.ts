import { generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { sha256Bytes } from '../../kernel/identity.js';
import type { RunAssemblyV1, ToolContractManifestV1 } from '../../kernel/types.js';
import { policyProfile, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';

let supervisorImage: Promise<{ digest: string; byteCount: number }> | undefined;

/** A real Ed25519 signature under an explicitly injected test root. Not a Cliq release/installation qualification. */
export async function signedToolBundle(assembly: RunAssemblyV1, tools: ToolContractManifestV1['entries']) {
  supervisorImage ??= readFile(process.execPath).then((bytes) => ({ digest: sha256Bytes(bytes), byteCount: bytes.byteLength }));
  const image = await supervisorImage;
  const keys = generateKeyPairSync('ed25519');
  const profile = policyProfile();
  const profileRef = canonicalSha256(profile);
  const entry = (entryId: string, role: string, executable: boolean, digest = canonicalSha256({ entryId }), version = '1', byteCount = 1) =>
    ({ entryId, role, version, relativePath: `test/${entryId}`, digest, byteCount, executable });
  const bundle: RuntimeBundleManifest = { schemaVersion: 1, bundleVersion: 'offline-tool-authority-test-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: 2 }, workerProtocolRange: { min: 1, max: 1 },
    entries: [entry('supervisor-test', 'supervisor', true, image.digest, '1', image.byteCount), entry(assembly.runtime.workerExecutableId, 'worker', true, assembly.runtime.workerExecutableDigest),
      entry(assembly.provider.adapter.adapterId, 'provider_adapter', true, assembly.provider.adapter.codeDigest, assembly.provider.adapter.version),
      entry('policy-v1', 'policy_engine', false, profileRef, '1', canonicalJsonBytes(profile).byteLength),
      entry('default_https_trust_store', 'trust_store', false), entry('root-profile-test', 'sandbox_root_profile', false),
      ...tools.flatMap((tool) => tool.execution.kind === 'builtin'
        ? [entry(tool.execution.adapterId, 'tool_adapter', true, tool.execution.adapterCodeDigest, tool.execution.adapterVersion)] : [])],
    structuredArtifacts: [{ kind: 'policy_engine_profile', artifactId: 'policy-v1', rootEntryId: 'policy-v1',
      artifactRef: profileRef, semanticDigest: profile.profileDigest, memberRefs: [] }],
    guestToolchainManifestRefs: [], publisherKeyId: 'offline-test-release', manifestDigest: '', signature: '' };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const bundleRef = canonicalSha256(bundle);
  assembly.runtime.runtimeBundleRef = bundleRef;
  assembly.runtime.runtimeBundleManifestDigest = bundle.manifestDigest;
  return { bundle, profile, releaseKeys: [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }],
    engine: { id: 'cliq-policy-v1' as const, version: '1', runtimeBundleRef: bundleRef,
      profileEntryId: 'policy-v1', profileRef, profileDigest: profile.profileDigest } };
}
