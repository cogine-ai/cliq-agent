// Pure bounded journal projection. Matching metadata is diagnostic provenance,
// never resource join, original-process death or authority to change a claim.
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeMcpAdminLifecycleObservation, type McpAdminLifecycleObservation } from '../../../src/state/mcp-admin-diagnostics.js';
import { MCP_ADMIN_LIFECYCLE_PREFIX } from './installed-mcp-admin-sink.js';
export function readInstalledMcpAdminJournal(text: string, binding: Readonly<{ uid: number; pid: number; invocationId: string }>) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 256 * 1024 || !Number.isSafeInteger(binding.uid) || binding.uid < 0 ||
      !Number.isSafeInteger(binding.pid) || binding.pid < 1 || !/^[0-9a-f]{32}$/u.test(binding.invocationId)) throw new TypeError('invalid bounded original MCP journal');
  const lines = text.split('\n').filter(Boolean);
  if (lines.length > 4096) throw new TypeError('MCP journal exceeds its original bounded record count');
  const records: McpAdminLifecycleObservation[] = []; let truncated = false;
  for (const line of lines) {
    const value = parseJsonStrict(line);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('invalid MCP journal record');
    const row = value as Record<string, unknown>, message = row.MESSAGE;
    if (typeof message !== 'string' || !message.startsWith(MCP_ADMIN_LIFECYCLE_PREFIX)) continue;
    if (row._UID !== String(binding.uid) || row._PID !== String(binding.pid) || row._SYSTEMD_INVOCATION_ID !== binding.invocationId ||
        row._TRANSPORT !== 'stdout') throw new TypeError('MCP marker belongs to another original lifetime');
    if (truncated) throw new TypeError('MCP journal continues after its explicit truncated marker');
    const body = message.slice(MCP_ADMIN_LIFECYCLE_PREFIX.length);
    if (body === 'truncated') { truncated = true; continue; }
    const fields = body.split(':');
    if (fields.length !== 5 || records.length === 128) throw new TypeError('invalid bounded MCP lifecycle marker');
    records.push(decodeMcpAdminLifecycleObservation({ transport: fields[0], phase: fields[1], event: fields[2],
      errorClass: fields[3] === '-' ? null : fields[3], code: fields[4] === '-' ? null : fields[4] }));
  }
  return records.length || truncated ? Object.freeze({ records: Object.freeze(records), truncated }) : undefined;
}
