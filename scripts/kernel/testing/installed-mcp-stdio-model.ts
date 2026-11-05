// Owned HTTPS provider replies only. Every MCP response, process, claim and
// filesystem result still comes from the actual signed installed runtime.
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { mcpExposedToolName } from '../../../src/kernel/mcp.js';
import { MCP_BEFORE, MCP_AFTER } from './installed-mcp-model.js';

type Data = Record<string, any>;
export const INSTALLED_MCP_STDIO_CASES = ['known', 'ping', 'fork_holder', 'result_exit',
  'unknown_deadline', 'unknown_cancel', 'unknown_restart'] as const;
export type InstalledMcpStdioCase = typeof INSTALLED_MCP_STDIO_CASES[number];
export const installedMcpStdioKnown = (kind: InstalledMcpStdioCase) => !kind.startsWith('unknown_');
export const installedMcpStdioMode = (kind: InstalledMcpStdioCase) => installedMcpStdioKnown(kind) ? kind : 'hang';
export const installedMcpStdioRegistrationId = (kind: InstalledMcpStdioCase) => `owned-stdio-${kind}`;
export const installedMcpStdioObjective = (kind: InstalledMcpStdioCase) =>
  `Owned installed stdio MCP case: ${kind}. Call the registered tool before changing example.txt.`;
export const INSTALLED_MCP_STDIO_TOOL = 'stdio_echo';
export const INSTALLED_MCP_STDIO_MODEL_POSTS = INSTALLED_MCP_STDIO_CASES.reduce((sum, kind) =>
  sum + (installedMcpStdioKnown(kind) ? 3 : 1), 0);

export function createInstalledMcpStdioModelResponder(model: string, builtins: () => readonly string[]) {
  const posts = new Map<InstalledMcpStdioCase, number>();
  return {
    begin(kind: InstalledMcpStdioCase) { assert(!posts.has(kind)); posts.set(kind, 0); },
    posts(kind: InstalledMcpStdioCase) { const count = posts.get(kind); assert(count !== undefined); return count; },
    respond(body: Data): Data | undefined {
      const matches = INSTALLED_MCP_STDIO_CASES.filter(kind => body.messages.some((entry: Data) =>
        entry.role === 'user' && entry.content === installedMcpStdioObjective(kind)));
      if (!matches.length) return;
      assert.equal(matches.length, 1);
      const kind = matches[0]!, previous = posts.get(kind); assert(previous !== undefined);
      const name = mcpExposedToolName(installedMcpStdioRegistrationId(kind), INSTALLED_MCP_STDIO_TOOL);
      const names = body.tools.map((entry: Data) => entry.function.name);
      assert.equal(canonicalSha256([...names].sort()), canonicalSha256([...builtins(), name].sort()));
      assert.equal(new Set(names).size, names.length);
      const ordinal = previous + 1;
      assert(ordinal <= (installedMcpStdioKnown(kind) ? 3 : 1), 'an uncertain stdio call must never resume or repeat through the model');
      if (ordinal > 1) {
        const id = ordinal === 2 ? 'owned-stdio-call' : 'owned-stdio-edit';
        const results = body.messages.filter((entry: Data) => entry.role === 'tool' && entry.tool_call_id === id);
        assert.equal(results.length, 1); assert.equal(typeof results[0]!.content, 'string');
        if (ordinal === 2) assert(results[0]!.content.includes('called once'), 'the edit must consume the actual contained server response');
      }
      posts.set(kind, ordinal);
      const tool = ordinal === 1 ? { id: 'owned-stdio-call', type: 'function', function: { name, arguments: '{}' } }
        : ordinal === 2 ? { id: 'owned-stdio-edit', type: 'function', function: { name: 'edit', arguments: JSON.stringify({
          path: 'example.txt', old_text: MCP_BEFORE, new_text: MCP_AFTER }) } } : undefined;
      return { id: `owned-stdio-model-${kind}-${ordinal}`, object: 'chat.completion', model,
        choices: [{ index: 0, finish_reason: tool ? 'tool_calls' : 'stop', message: tool
          ? { role: 'assistant', content: '', tool_calls: [tool] }
          : { role: 'assistant', content: 'The stdio-assisted private edit is ready for its required Node check.' } }],
        usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
    }
  };
}
