import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpRecoveryProfile, mcpProfileSigningIdentityDigest } from '../kernel/mcp-recovery.js';
import type { McpResolvedTransportV1 } from '../kernel/mcp.js';
import { mcpRecoveryAdapterMemberRefs, verifyMcpRecoveryAdapterAuthority } from './mcp-recovery-authority.js';
import type { RuntimeBundleManifest } from './runtime-authority.js';

const hash = (value: unknown) => canonicalSha256(value);
test('MCP independently signed profile publishes before its outer Bundle without a hash cycle, and cannot be borrowed by a substituted root', () => {
  const keys = generateKeyPairSync('ed25519'), releaseKeys = [{ keyId: 'publisher', publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  const original = { kind: 'stdio', executionIdentityGrantId: 'grant', executionIdentityConsumptionReceiptRef: hash('consumption'),
    executionIdentityConsumptionReceiptDigest: hash('consumption-semantic'), executable: { kind: 'runtime_bundle', runtimeBundleRef: hash('not-published-yet'),
      executableId: 'mcp-server', executableDigest: hash('server-bytes'), executionPath: '/runtime/mcp-server' }, argv: [{ kind: 'non_secret_literal', value: 'status-capable' }] } satisfies McpResolvedTransportV1;
  const profileCore = { profileId: 'fixed', profileSigningIdentityDigest: mcpProfileSigningIdentityDigest(original), serverToolName: 'effect',
    initializeDigest: hash('initialize'), capabilityDigest: hash('capability'), probedToolsListDigest: hash('tools'), effectToolInterfaceDigest: hash('effect'),
    statusOperationName: 'status', statusOperationSemantics: 'signed_read_only_status_query', statusToolInterfaceDigest: hash('status'),
    statusInputSchemaDigest: hash('input'), statusOutputSchemaDigest: hash('output'), staticArgumentsRef: hash('static'), staticArgumentsDigest: hash('static'),
    completedPredicateRef: hash('complete'), completedPredicateDigest: hash('complete-semantic'), failedPredicateRef: hash('failed'), failedPredicateDigest: hash('failed-semantic') };
  const profile = decodeMcpRecoveryProfile({ ...profileCore, profileDigest: hash(profileCore) });
  const adapterCore = { schemaVersion: 1 as const, format: 'cliq-mcp-recovery-adapter-v1' as const, adapterId: 'fixed-adapter', entryId: 'recovery-executable',
    version: '1', executableDigest: hash('adapter-bytes'), protocol: 'cliq-mcp-reconcile-v1' as const, profiles: [profile], publisherKeyId: 'publisher' };
  const adapterDigest = hash(adapterCore), manifest = { ...adapterCore, adapterDigest,
    signature: sign(null, Buffer.from(`cliq-mcp-recovery-adapter-v1\0${adapterDigest}`), keys.privateKey).toString('base64') };
  const adapterRef = hash(manifest);
  const entry = (entryId: string, role: string, executable: boolean, digest = hash(entryId), byteCount = 10) =>
    ({ entryId, role, version: '1', relativePath: `fixed/${entryId}`, executable, digest, byteCount });
  const core = { schemaVersion: 1 as const, bundleVersion: '1', controlProtocolRange: { min: 1 as const, max: 1 as const },
    headlessSchemaRange: { min: 1, max: 1 }, stateSchemaRange: { min: 1, max: 1 }, workerProtocolRange: { min: 1, max: 1 },
    entries: [entry('supervisor', 'supervisor', true), entry('worker', 'worker', true), entry('policy', 'policy_engine', false),
      entry('default_https_trust_store', 'trust_store', false), entry('root', 'sandbox_root_profile', false),
      entry('mcp-server', 'mcp_server', true, hash('server-bytes')), entry('recovery-executable', 'mcp_recovery_adapter', true, manifest.executableDigest),
      entry('profile-data', 'mcp_recovery_profile', false, adapterRef, canonicalJsonBytes(manifest).byteLength)],
    structuredArtifacts: [{ artifactId: manifest.adapterId, rootEntryId: 'profile-data', artifactRef: adapterRef, semanticDigest: adapterDigest,
      memberRefs: mcpRecoveryAdapterMemberRefs(manifest), kind: 'mcp_recovery_adapter', executableEntryId: manifest.entryId }],
    guestToolchainManifestRefs: [], publisherKeyId: 'publisher' };
  const signedBundle = (value: typeof core): RuntimeBundleManifest => {
    const manifestDigest = hash(value); return { ...value, manifestDigest,
      signature: sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${manifestDigest}`), keys.privateKey).toString('base64') };
  };
  const bundle = signedBundle(core);
  assert.equal(verifyMcpRecoveryAdapterAuthority({ bundle, releaseKeys, adapterId: manifest.adapterId, adapterRef, manifest }).adapterDigest, adapterDigest);
  const finalTransport: McpResolvedTransportV1 = { ...original, executable: { ...original.executable, runtimeBundleRef: hash(bundle) } };
  assert.equal(mcpProfileSigningIdentityDigest(finalTransport), profile.profileSigningIdentityDigest);
  assert.notEqual(hash(bundle), hash('not-published-yet'));
  const missingMembers = signedBundle({ ...core, structuredArtifacts: core.structuredArtifacts.map(root => ({ ...root, memberRefs: [] })) });
  assert.throws(() => verifyMcpRecoveryAdapterAuthority({ bundle: missingMembers, releaseKeys, adapterId: manifest.adapterId, adapterRef, manifest }));
  const wrongRole = signedBundle({ ...core, entries: core.entries.map(item => item.entryId === manifest.entryId ? { ...item, role: 'mcp_server' } : item) });
  assert.throws(() => verifyMcpRecoveryAdapterAuthority({ bundle: wrongRole, releaseKeys, adapterId: manifest.adapterId, adapterRef, manifest }));
  const otherKeys = generateKeyPairSync('ed25519');
  const forged = { ...manifest, signature: sign(null, Buffer.from(`cliq-mcp-recovery-adapter-v1\0${adapterDigest}`), otherKeys.privateKey).toString('base64') };
  const forgedCore = { ...core, entries: core.entries.map(item => item.entryId === 'profile-data' ? { ...item, digest: hash(forged) } : item),
    structuredArtifacts: core.structuredArtifacts.map(root => ({ ...root, artifactRef: hash(forged) })) };
  assert.throws(() => verifyMcpRecoveryAdapterAuthority({ bundle: signedBundle(forgedCore), releaseKeys, adapterId: manifest.adapterId, adapterRef: hash(forged), manifest: forged }));
});
