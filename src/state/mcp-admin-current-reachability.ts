// Fixed data edges, never a current-retirement capability. Both original and
// current complete raw captures are mandatory; callers fail whole GC closed
// when this context or its loaded production decoder is unavailable.
import type { CoreRetentionArtifactPurpose } from '../kernel/retention-purpose.js';
import { controlWireRef, assertControlWireJson } from '../kernel/control-wire-data.js';
import { sha256Bytes } from '../kernel/identity.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { decodeMcpAdminOriginalRetirementData } from './native-owner.js';
import type { McpStdioReachabilityPurpose } from './mcp-stdio-reachability.js';

export const MCP_ADMIN_CURRENT_RETIREMENT_PURPOSES = ['mcp_admin_current_retirement_raw', 'mcp_admin_current_retirement_projection'] as const;
export type McpAdminCurrentRetirementPurpose = typeof MCP_ADMIN_CURRENT_RETIREMENT_PURPOSES[number];
export type McpAdminCurrentRetirementContext = Readonly<{ currentRaw: Buffer; originalLifecycleRaw: Buffer }>;
export class UnsupportedMcpAdminCurrentRetirementReachability extends TypeError {
  constructor() { super('unsupported or incomplete original/current Admin retirement retention context'); }
}
export function readMcpAdminCurrentRetirementEdges(purpose: McpAdminCurrentRetirementPurpose, value: unknown,
  context?: McpAdminCurrentRetirementContext): readonly Readonly<{ ref: string; purpose: CoreRetentionArtifactPurpose | McpStdioReachabilityPurpose }>[] {
  if (!context || !Buffer.isBuffer(context.currentRaw) || !Buffer.isBuffer(context.originalLifecycleRaw))
    throw new UnsupportedMcpAdminCurrentRetirementReachability();
  const data = decodeMcpAdminOriginalRetirementData(context.currentRaw, context.originalLifecycleRaw);
  if (purpose === 'mcp_admin_current_retirement_raw') {
    if (!Buffer.isBuffer(value) || !value.equals(context.currentRaw)) throw new UnsupportedMcpAdminCurrentRetirementReachability();
  } else if (purpose === 'mcp_admin_current_retirement_projection') {
    assertControlWireJson(value); requireEqual(value, data, 'MCP current original-retirement exact complete raw projection');
  } else throw new UnsupportedMcpAdminCurrentRetirementReachability();
  if (data.originalLifecycleRef !== sha256Bytes(context.originalLifecycleRaw) || data.originalLifecycleByteCount !== context.originalLifecycleRaw.length)
    throw new UnsupportedMcpAdminCurrentRetirementReachability();
  const binding = data.originalBinding;
  return [
    { ref: controlWireRef(data.originalLifecycleRef), purpose: data.transport === 'stdio' ? 'mcp.stdio.native_launch_raw' : 'mcp_admin_native_lifecycle_raw' },
    { ref: controlWireRef(binding.targetRef), purpose: 'mcp_admin_probe_target' },
    { ref: controlWireRef(binding.probePayloadCoreRef), purpose: 'mcp_admin_probe_core' },
    { ref: controlWireRef(binding.plannedContainmentRef), purpose: 'process_containment_plan' },
    { ref: controlWireRef(binding.sandboxLaunchSpecRef), purpose: 'sandbox_launch_spec' }
  ];
}
