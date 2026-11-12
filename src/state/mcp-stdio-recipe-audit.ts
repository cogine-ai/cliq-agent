// Complete original fixed recipe data audit, shared by its first prepared
// transaction and retained native image/hash-chain reader. No live authority.
import { mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData, mcpToolsCallRequestData } from '../kernel/mcp-wire.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import type { McpResolvedTransportV1 } from '../kernel/mcp.js';
import type { McpStdioRecipeData } from './mcp-stdio-recipe.js';
import { requireEqual } from '../policy/runtime-authority.js';

type Common = Readonly<{ transport: Extract<McpResolvedTransportV1, { kind: 'stdio' }>; serverByteCount: number; resources: SandboxResourceSpec }>;
export function assertMcpStdioRecipeData(data: McpStdioRecipeData, input: Common & (
  Readonly<{ purpose: 'admin' }> | Readonly<{ purpose: 'run'; serverToolName: string; arguments: Readonly<Record<string, unknown>> }> |
  Readonly<{ purpose: 'recovery'; adapterExecutableDigest: string; effectServerToolName: string; statusOperationName: string; arguments: Readonly<Record<string, unknown>> }>)) {
  const originalServerDigest = input.transport.executable.executableDigest;
  const executableDigest = input.purpose === 'recovery' ? input.adapterExecutableDigest : originalServerDigest;
  if (data.version !== 1 || data.purpose !== input.purpose || data.serverDigest !== executableDigest ||
      data.serverByteCount !== input.serverByteCount || data.maximumResponseBytes !== 1_048_576 || data.maximumOutputBytes !== input.resources.maxInvocationOutputBytes)
    throw new TypeError('MCP stdio original native recipe changes its exact purpose/server/response/resource bounds');
  requireEqual(data.argv, input.transport.argv.map(argument => argument.value), 'MCP stdio original complete non-secret argv');
  if (input.purpose === 'recovery' && (input.effectServerToolName === input.statusOperationName || executableDigest === originalServerDigest))
    throw new TypeError('MCP recovery recipe requires a distinct signed adapter and status operation');
  const frames = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(), mcpToolsListRequestData(2),
    ...(input.purpose === 'admin' ? [] : [mcpToolsCallRequestData(3,
      input.purpose === 'run' ? input.serverToolName : input.statusOperationName, input.arguments)])];
  requireEqual(data.recipe, frames.map(frame => ({ phase: frame.phase, bodyJson: frame.json, bodyBytesDigest: frame.digest })),
    'MCP stdio original complete fixed client/initialize/list/exact-tools-call recipe');
}
