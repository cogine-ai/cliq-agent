// Fixed qualification sink. No serialization, message/cause/stack inspection,
// timer, flush retry, pause or authority. All sink failures are contained.
import { types } from 'node:util';
import { decodeMcpAdminLifecycleObservation, type McpAdminLifecycleObservation } from '../../../src/state/mcp-admin-diagnostics.js';
export const MCP_ADMIN_LIFECYCLE_PREFIX = 'CLIQ_MCP_ADMIN_LIFECYCLE_V1:';
export function createMcpAdminLifecycleSink(write: (line: string) => number | void): (value: McpAdminLifecycleObservation) => void {
  let emitted = 0, stopped = false;
  return value => {
    if (stopped) return;
    try {
      if (types.isProxy(value)) return;
      const row = decodeMcpAdminLifecycleObservation(value);
      if (emitted === 128) { stopped = true; write(MCP_ADMIN_LIFECYCLE_PREFIX + 'truncated\n'); return; }
      const line = MCP_ADMIN_LIFECYCLE_PREFIX + [row.transport, row.phase, row.event, row.errorClass ?? '-', row.code ?? '-'].join(':') + '\n';
      if (line.length > 192) return;
      emitted++; const count = write(line); if (count !== undefined && count !== Buffer.byteLength(line)) stopped = true;
    } catch { stopped = true; }
  };
}
