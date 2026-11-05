// Owned HTTPS model responses only. Every MCP claim, native join, signed
// status response, workspace edit and verifier is produced by the installation.
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { mcpExposedToolName } from '../../../src/kernel/mcp.js';
import { MCP_BEFORE, MCP_AFTER } from './installed-mcp-model.js';
import { MCP_RECOVERY_EFFECT, MCP_RECOVERY_STATUS } from './installed-mcp-recovery-package.js';
import { MCP_RETRY_HTTP_TOOL, MCP_RETRY_HTTP_RESULT } from './installed-mcp-retry-http.js';

type Data = Record<string, any>;
export const INSTALLED_MCP_RECOVERY_CASES = ['signed_status_completed', 'retry_server_capacity', 'http_retry_completed', 'signed_status_owning_stop'] as const;
export type InstalledMcpRecoveryCase = typeof INSTALLED_MCP_RECOVERY_CASES[number];
export const INSTALLED_MCP_RECOVERY_MODEL_POSTS = 8;
export const installedMcpRecoveryRegistration = (kind: InstalledMcpRecoveryCase) => `owned-recovery-${kind}`;
export const installedMcpRecoveryObjective = (kind: InstalledMcpRecoveryCase) =>
  `Owned installed MCP recovery case: ${kind}. Call the original no-op effect before editing example.txt; never repeat a tool call from the model.`;

export function createInstalledMcpRecoveryModelResponder(model: string, builtins: () => readonly string[]) {
  const posts = new Map<InstalledMcpRecoveryCase, number>();
  return {
    begin(kind: InstalledMcpRecoveryCase) { assert(!posts.has(kind)); posts.set(kind, 0); },
    posts(kind: InstalledMcpRecoveryCase) { const count = posts.get(kind); assert(count !== undefined); return count; },
    respond(body: Data): Data | undefined {
      const matches = INSTALLED_MCP_RECOVERY_CASES.filter(kind => body.messages.some((entry: Data) =>
        entry.role === 'user' && entry.content === installedMcpRecoveryObjective(kind)));
      if (!matches.length) return;
      assert.equal(matches.length, 1); const kind = matches[0]; if (!kind) assert.fail('missing fixed recovery case');
      const previous = posts.get(kind); assert(previous !== undefined);
      const http = kind === 'http_retry_completed', known = kind === 'signed_status_completed' || http;
      const registration = installedMcpRecoveryRegistration(kind), effect = mcpExposedToolName(registration, http ? MCP_RETRY_HTTP_TOOL : MCP_RECOVERY_EFFECT),
        status = mcpExposedToolName(registration, MCP_RECOVERY_STATUS), names = body.tools.map((entry: Data) => entry.function.name);
      assert.equal(canonicalSha256([...names].sort()), canonicalSha256([...builtins(), effect, ...(!http ? [status] : [])].sort()));
      assert.equal(new Set(names).size, names.length);
      const ordinal = previous + 1; assert(ordinal <= (known ? 3 : 1),
        'retry scheduling and unresolved effects must never be resent through another model turn');
      if (ordinal > 1) {
        const callId = ordinal === 2 ? 'owned-recovery-effect' : 'owned-recovery-edit';
        const results = body.messages.filter((entry: Data) => entry.role === 'tool' && entry.tool_call_id === callId);
        assert.equal(results.length, 1); assert.equal(typeof results[0]?.content, 'string');
        if (ordinal === 2) {
          if (http) assert(results[0].content.includes(MCP_RETRY_HTTP_RESULT), 'the model must consume the actual later claimed HTTP result rather than an old UNKNOWN');
          else assert.deepEqual(parseJsonStrict(results[0].content), {
            code: 'TOOL_RESULT_UNAVAILABLE', effect: 'confirmed_completed', originalResponse: 'unavailable',
          }, 'the model must consume truthful signed completion without an invented old effect payload');
        }
      }
      posts.set(kind, ordinal);
      const tool = ordinal === 1 ? { id: 'owned-recovery-effect', type: 'function', function: { name: effect,
        arguments: JSON.stringify({ idempotencyKey: '' }) } }
        : ordinal === 2 ? { id: 'owned-recovery-edit', type: 'function', function: { name: 'edit', arguments: JSON.stringify({
          path: 'example.txt', old_text: MCP_BEFORE, new_text: MCP_AFTER }) } } : undefined;
      return { id: `owned-recovery-model-${kind}-${ordinal}`, object: 'chat.completion', model,
        choices: [{ index: 0, finish_reason: tool ? 'tool_calls' : 'stop', message: tool ? { role: 'assistant', content: '', tool_calls: [tool] }
          : { role: 'assistant', content: 'The private edit consumes its original retained result and is ready for the required Node check.' } }],
        usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
    },
  };
}
