// Data normalization metadata is derived from the original exact frozen
// registry. It is never permission, an executable identity or native proof.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpRegistryRevision } from '../kernel/mcp.js';
import type { ToolInputAuthority } from '../tools/input-contract.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';

export async function readMcpInputAuthority(artifacts: ArtifactCatalog, value: ToolInputAuthority): Promise<ToolInputAuthority> {
  const execution = value.execution;
  if (execution.kind !== 'mcp') {
    if (value.mcpRecovery !== undefined) throw new TypeError('ordinary input authority carries unrelated MCP recovery');
    return value;
  }
  const registry = decodeMcpRegistryRevision(await readCanonicalArtifact(artifacts, execution.registryRevisionRef));
  const matching = registry.tools.filter(tool => tool.name === execution.serverToolName), tool = matching[0];
  if (canonicalSha256(registry) !== execution.registryRevisionRef || registry.registrationId !== execution.registrationId ||
      registry.manifestDigest !== execution.registryManifestDigest || matching.length !== 1 || !tool ||
      tool.toolContractDigest !== execution.toolContractDigest || tool.recovery.kind !== value.replayClass ||
      tool.inputSchemaRef !== value.inputSchemaRef || tool.inputSchemaDigest !== value.inputSchemaDigest ||
      tool.outputSchemaRef !== value.outputSchemaRef || tool.outputSchemaDigest !== value.outputSchemaDigest ||
      value.mcpRecovery !== undefined && canonicalSha256(value.mcpRecovery) !== canonicalSha256(tool.recovery))
    throw new TypeError('MCP normalization metadata differs from original frozen registry/tool/recovery');
  return immutableSnapshot({ ...value, mcpRecovery: tool.recovery });
}
