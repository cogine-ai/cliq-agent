// Fixed owned provider replies. This does not invoke a tool, create a claim,
// accept an MCP response or provide a native/installed qualification result.
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { mcpExposedToolName } from '../../../src/kernel/mcp.js';
import { INSTALLED_MCP_CASES, OWNED_MCP_INPUT, OWNED_MCP_RESULT, OWNED_MCP_TOOL,
  type InstalledMcpCase } from './installed-mcp-responder.js';

type Data = Record<string, any>;
export const MCP_BEFORE = 'before the owned MCP-assisted edit\n';
export const MCP_AFTER = 'after the owned MCP-assisted edit\n';
export const installedMcpRegistrationId = (kind: InstalledMcpCase) => `owned-${kind}`;
export const installedMcpObjective = (kind: InstalledMcpCase) => `Owned installed MCP case: ${kind}. Use the registered owned tool before changing example.txt.`;
export const installedMcpKnown = (kind: InstalledMcpCase) => kind === 'known_json' || kind === 'known_sse_ping';

export function createInstalledMcpModelResponder(model: string, builtins: () => readonly string[]) {
  const posts = new Map<InstalledMcpCase, number>();
  return {
    begin(kind: InstalledMcpCase): void { assert(!posts.has(kind)); posts.set(kind, 0); },
    posts(kind: InstalledMcpCase): number { const value = posts.get(kind); assert(value !== undefined); return value; },
    respond(body: Data): Data | undefined {
      const matches = INSTALLED_MCP_CASES.filter(kind => body.messages.some((message: Data) =>
        message.role === 'user' && message.content === installedMcpObjective(kind)));
      if (!matches.length) return;
      assert.equal(matches.length, 1);
      const kind = matches[0]!, previous = posts.get(kind); assert(previous !== undefined);
      const name = mcpExposedToolName(installedMcpRegistrationId(kind), OWNED_MCP_TOOL);
      const names = body.tools.map((entry: Data) => entry.function.name);
      assert.equal(canonicalSha256([...names].sort()), canonicalSha256([...builtins(), name].sort()), 'the real provider manifest omits or substitutes the frozen registered tool');
      assert.equal(new Set(names).size, names.length);
      const ordinal = previous + 1;
      assert(ordinal <= (installedMcpKnown(kind) ? 3 : 1), 'an unknown MCP claim must not resume or repeat through another model request');
      const prior = ordinal > 1 ? body.messages.filter((message: Data) => message.role === 'tool' &&
        message.tool_call_id === (ordinal === 2 ? 'owned-mcp-call' : 'owned-mcp-edit')) : [];
      if (ordinal > 1) {
        assert.equal(prior.length, 1, 'the model must consume the actual previous typed tool result once');
        assert(typeof prior[0]!.content === 'string');
        if (ordinal === 2) assert(prior[0]!.content.includes(OWNED_MCP_RESULT), 'the code edit must follow the actual owned MCP result');
      }
      posts.set(kind, ordinal);
      const tool = ordinal === 1 ? { id: 'owned-mcp-call', type: 'function', function: {
        name, arguments: JSON.stringify({ value: OWNED_MCP_INPUT }) } }
        : ordinal === 2 ? { id: 'owned-mcp-edit', type: 'function', function: { name: 'edit', arguments: JSON.stringify({
          path: 'example.txt', old_text: MCP_BEFORE, new_text: MCP_AFTER }) } } : undefined;
      return { id: `owned-mcp-model-${kind}-${ordinal}`, object: 'chat.completion', model,
        choices: [{ index: 0, finish_reason: tool ? 'tool_calls' : 'stop', message: tool
          ? { role: 'assistant', content: '', tool_calls: [tool] }
          : { role: 'assistant', content: 'The MCP-assisted private edit is ready for its real Node check.' } }],
        usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
    }
  };
}
