import { signedKernelSchemaProfile } from '../signed-schema.js';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { KERNEL_STATE_SCHEMA_VERSION } from '../../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { sha256Bytes } from '../../kernel/identity.js';
import type { RunAssemblyV1, ToolContractManifestV1 } from '../../kernel/types.js';
import { policyProfile, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_PATH, STATE_OWNER_NATIVE_RELATIVE_PATH } from '../native-owner.js';

let supervisorImage: Promise<{ digest: string; byteCount: number }> | undefined;
let nativeImage: Promise<{ digest: string; byteCount: number }> | undefined;

/** Fixed public test certificate; its discarded private key is not retained.
 * Offline artifact data only, never an installed TLS/provider qualification. */
export const OFFLINE_MODEL_TRUST_STORE_PEM = `-----BEGIN CERTIFICATE-----
MIIC0DCCAbgCCQCjpyAgsuVh1DANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDDB9D
bGlxIG9mZmxpbmUgbW9kZWwgZGF0YSBmaXh0dXJlMB4XDTI2MTAxNDE5Mjg1MFoX
DTM2MTAxMTE5Mjg1MFowKjEoMCYGA1UEAwwfQ2xpcSBvZmZsaW5lIG1vZGVsIGRh
dGEgZml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALKLqi3X
5Cxn3MQGUtIs1wIJ+iCHBHEtEfxkz820tJrKfTlKmT/8RuXXR0Wnh3nK5KdmTQ+b
NYHOQpolw0FMtv0Tig3ucgW/hxqQcs/W0VOdbooOmlC0KYjBj8BdzhftXTdZiZJG
s6it26V3U83W7UGRiB1ApkDJOYn/N5Pp1RoQzB5bK4SubGlRZdGsU2hWuAJ32Yk/
Rubxgpcnn8N6DUtHTxiaJbLj0lWncIe71pnp6cq/81PIjJbN6PWTG5wCnF4VJEA8
s0EReG/BqfkjonEvn6tjP+tElL3kECBMD7Z3n79i/UvLRSZD23RVjQRmBYFBdXuC
fb7+AdbVtQ9sSjECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAIeMDGg4poGnMNg3x
tA3rFni/7CD/TBt+tLCY8hYIjXFUc1zDAp8qUAU+P9aElEs9Rxa7Kt7e2U8u2tuG
yeTucftNXxl2i2cJIwzRUnYUY3IaaCi7o0Fwg/JIXEDJEyJcx9j25ufK30TSjiwl
1mviZnfkMfYFXb/ZL0Am7KRoD2a5LdW4N9NhwTk4qcLlACbrLJnJ8J+JtZ1lU5lr
uWCIn2hJIPBKvBFJa5lWShhvQji1ZJzbq+TsQRTnah287dcI/gFAZ6oNILCNWSe8
/WC2F/znIrjWD1U7m71V541PrOhq2BNmD4InInkeSUBcbNIuu4E2IpR1hKvF4M6T
Pi66oQ==
-----END CERTIFICATE-----
`;

/** A real Ed25519 signature under an explicitly injected test root. Not a Cliq release/installation qualification. */
export async function signedToolBundle(assembly: RunAssemblyV1, tools: ToolContractManifestV1['entries'], schemaVersion: 1 | 2 = 1) {
  supervisorImage ??= readFile(process.execPath).then((bytes) => ({ digest: sha256Bytes(bytes), byteCount: bytes.byteLength }));
  nativeImage ??= readFile(STATE_OWNER_NATIVE_PATH).then((bytes) => ({ digest: sha256Bytes(bytes), byteCount: bytes.byteLength }));
  const image = await supervisorImage;
  const helper = await nativeImage;
  const keys = generateKeyPairSync('ed25519');
  const profile = policyProfile();
  const profileRef = canonicalSha256(profile);
  const entry = (entryId: string, role: string, executable: boolean, digest = canonicalSha256({ entryId }), version = '1', byteCount = 1) =>
    ({ entryId, role, version, relativePath: `test/${entryId}`, digest, byteCount, executable });
  const bundle: RuntimeBundleManifest = { ...(schemaVersion === 2
    ? { schemaVersion: 2 as const, installedLayout: 'single_cas_streams_v1' as const } : { schemaVersion: 1 as const }),
    bundleVersion: 'offline-tool-authority-test-v1',
    controlProtocolRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    stateSchemaRange: { min: 1, max: KERNEL_STATE_SCHEMA_VERSION }, workerProtocolRange: { min: 1, max: 1 },
    entries: [entry('supervisor-test', 'supervisor', true, image.digest, '1', image.byteCount), entry(assembly.runtime.workerExecutableId, 'worker', true, assembly.runtime.workerExecutableDigest),
      { ...entry(STATE_OWNER_NATIVE_ENTRY_ID, 'platform_helper', true, helper.digest, '1', helper.byteCount), relativePath: STATE_OWNER_NATIVE_RELATIVE_PATH },
      entry(assembly.provider.adapter.adapterId, 'provider_adapter', true, assembly.provider.adapter.codeDigest, assembly.provider.adapter.version),
      { entryId: 'kernel_schema', role: 'schema', version: '8', relativePath: 'schema/kernel-v8.json', executable: false,
        digest: canonicalSha256(signedKernelSchemaProfile()), byteCount: canonicalJsonBytes(signedKernelSchemaProfile()).length },
      entry('policy-v1', 'policy_engine', false, profileRef, '1', canonicalJsonBytes(profile).byteLength),
      entry('default_https_trust_store', 'trust_store', false, sha256Bytes(Buffer.from(OFFLINE_MODEL_TRUST_STORE_PEM)), '1',
        Buffer.byteLength(OFFLINE_MODEL_TRUST_STORE_PEM)), entry('root-profile-test', 'sandbox_root_profile', false),
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
  return { bundle, profile, trustStorePem: OFFLINE_MODEL_TRUST_STORE_PEM,
    releaseKeys: [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }],
    engine: { id: 'cliq-policy-v1' as const, version: '1', runtimeBundleRef: bundleRef,
      profileEntryId: 'policy-v1', profileRef, profileDigest: profile.profileDigest } };
}
