// Signature and exact selection of the publisher's narrow status contract.
// This checks data authority, never installation, native readiness or dispatch.
import { createPublicKey, verify } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpRecoveryAdapterManifest, mcpProfileSigningIdentityDigest, type McpRecoveryAdapterManifestV1,
  type McpRecoveryProfileV1 } from '../kernel/mcp-recovery.js';
import { decodeMcpAdminProbeResult, decodeMcpAdminProbeTarget, type McpAdminProbeResultV1,
  type McpAdminProbeTargetV1 } from '../kernel/mcp.js';
import { exactKeys, verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from './runtime-authority.js';

export function mcpRecoveryAdapterMemberRefs(manifest: McpRecoveryAdapterManifestV1): string[] {
  const checked = decodeMcpRecoveryAdapterManifest(manifest);
  return [...new Set(checked.profiles.flatMap(profile => [profile.staticArgumentsRef, profile.completedPredicateRef, profile.failedPredicateRef]))]
    .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}
export function verifyMcpRecoveryAdapterAuthority(input: Readonly<{
  bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[]; adapterId: string; adapterRef: string; manifest: unknown;
}>): McpRecoveryAdapterManifestV1 {
  verifyRuntimeBundle(input.bundle, input.releaseKeys);
  const manifest = decodeMcpRecoveryAdapterManifest(input.manifest);
  const roots = input.bundle.structuredArtifacts.filter(root => root.kind === 'mcp_recovery_adapter' && root.artifactId === input.adapterId);
  const root = roots[0], data = root && input.bundle.entries.find(entry => entry.entryId === root.rootEntryId);
  const executables = input.bundle.entries.filter(entry => entry.entryId === manifest.entryId), executable = executables[0];
  if (roots.length !== 1 || !root || !exactKeys(root, ['artifactId', 'rootEntryId', 'artifactRef', 'semanticDigest', 'memberRefs', 'kind', 'executableEntryId']) ||
      manifest.adapterId !== input.adapterId || canonicalSha256(manifest) !== input.adapterRef || root.artifactRef !== input.adapterRef ||
      root.semanticDigest !== manifest.adapterDigest || root.executableEntryId !== manifest.entryId || !data || data.executable ||
      data.role !== 'mcp_recovery_profile' || data.digest !== input.adapterRef || data.version !== manifest.version ||
      data.byteCount !== canonicalJsonBytes(manifest).byteLength || executables.length !== 1 || !executable?.executable ||
      executable.role !== 'mcp_recovery_adapter' || executable.digest !== manifest.executableDigest || executable.version !== manifest.version ||
      canonicalSha256(root.memberRefs) !== canonicalSha256(mcpRecoveryAdapterMemberRefs(manifest)))
    throw new TypeError('MCP recovery adapter is not the unique exact current signed structured/executable closure');
  const keys = input.releaseKeys.filter(key => key.keyId === manifest.publisherKeyId), trusted = keys[0];
  if (keys.length !== 1 || !trusted) throw new TypeError('MCP recovery adapter has no unique trusted release key');
  const key = createPublicKey(trusted.publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.from(`cliq-mcp-recovery-adapter-v1\0${manifest.adapterDigest}`, 'utf8'),
      key, Buffer.from(manifest.signature, 'base64'))) throw new TypeError('MCP recovery adapter independent release signature is invalid');
  return manifest;
}
/** The outer bundle is checked first. The selector-free signing digest by
 * itself cannot select a server from another bundle, path or executable role. */
export function selectMcpRecoveryProfile(input: Readonly<{
  bundle: RuntimeBundleManifest; target: McpAdminProbeTargetV1; result: McpAdminProbeResultV1;
  manifest: McpRecoveryAdapterManifestV1; serverToolName: string;
}>): McpRecoveryProfileV1 {
  const target = decodeMcpAdminProbeTarget(input.target), result = decodeMcpAdminProbeResult(input.result);
  const transport = target.resolvedTransport, manifest = decodeMcpRecoveryAdapterManifest(input.manifest);
  if (transport.kind !== 'stdio' || transport.executable.kind !== 'runtime_bundle' ||
      transport.executable.runtimeBundleRef !== canonicalSha256(input.bundle)) throw new TypeError('MCP recovery profile substitutes its original signed Bundle');
  const identity = transport.executable;
  const executable = input.bundle.entries.filter(entry => entry.entryId === identity.executableId);
  const entry = executable[0];
  if (executable.length !== 1 || !entry?.executable || entry.role !== 'mcp_server' || entry.digest !== transport.executable.executableDigest ||
      transport.executable.executionPath !== '/runtime/mcp-server') throw new TypeError('MCP profile substitutes its exact signed server role/image/path');
  if (result.targetRef !== canonicalSha256(target) || result.targetDigest !== target.targetDigest ||
      result.normalizedTools.filter(tool => tool.name === input.serverToolName).length !== 1)
    throw new TypeError('MCP recovery profile lacks its exact original target and effect interface');
  const effect = result.normalizedTools.find(tool => tool.name === input.serverToolName);
  if (!effect) throw new TypeError('MCP effect interface is absent');
  const matches = manifest.profiles.filter(profile => profile.profileSigningIdentityDigest === mcpProfileSigningIdentityDigest(transport) &&
    profile.serverToolName === effect.name && profile.effectToolInterfaceDigest === effect.interfaceDigest &&
    profile.initializeDigest === result.initializeDigest && profile.capabilityDigest === result.capabilityDigest &&
    profile.probedToolsListDigest === result.probedToolsListDigest);
  const profile = matches[0], status = profile && result.normalizedTools.filter(tool => tool.name === profile.statusOperationName);
  const statusTool = status?.[0];
  if (matches.length !== 1 || !profile || status?.length !== 1 || !statusTool || statusTool.name === effect.name ||
      statusTool.interfaceDigest !== profile.statusToolInterfaceDigest || statusTool.inputSchemaDigest !== profile.statusInputSchemaDigest ||
      statusTool.outputSchemaDigest !== profile.statusOutputSchemaDigest || statusTool.outputSchemaRef !== profile.statusOutputSchemaDigest)
    throw new TypeError('MCP recovery has no unique signed profile with its exact distinct status interface/schema');
  return profile;
}
