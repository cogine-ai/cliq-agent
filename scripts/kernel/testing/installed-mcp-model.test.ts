// Owned provider data only: these tests create no claim, native result, Run,
// authenticated registration or external-effect evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mcpExposedToolName } from '../../../src/kernel/mcp.js';
import { createInstalledMcpModelResponder, installedMcpObjective, installedMcpRegistrationId,
  MCP_BEFORE, MCP_AFTER } from './installed-mcp-model.js';
import { OWNED_MCP_INPUT, OWNED_MCP_RESULT, OWNED_MCP_TOOL, type InstalledMcpCase } from './installed-mcp-responder.js';

const builtins = ['read', 'edit', 'bash'];
function body(kind: InstalledMcpCase) {
  return { messages: [{ role: 'user', content: installedMcpObjective(kind) }],
    tools: [...builtins, mcpExposedToolName(installedMcpRegistrationId(kind), OWNED_MCP_TOOL)]
      .map(name => ({ type: 'function', function: { name } })) };
}

test('owned model must consume the exact MCP result before it requests a code edit and a final verifier candidate', () => {
  const responder = createInstalledMcpModelResponder('owned-model', () => builtins);
  responder.begin('known_json'); const request = body('known_json');
  const first = responder.respond(request)!;
  assert.equal(first.choices[0].message.tool_calls[0].function.name,
    mcpExposedToolName(installedMcpRegistrationId('known_json'), OWNED_MCP_TOOL));
  assert.deepEqual(JSON.parse(first.choices[0].message.tool_calls[0].function.arguments), { value: OWNED_MCP_INPUT });
  assert.throws(() => responder.respond(request));
  assert.equal(responder.posts('known_json'), 1, 'a rejected fixture input must not consume the next legitimate model reply');
  request.messages.push({ role: 'tool', content: JSON.stringify({ content: [{ type: 'text', text: OWNED_MCP_RESULT }] }),
    tool_call_id: 'owned-mcp-call' } as typeof request.messages[number]);
  const edit = responder.respond(request)!;
  assert.equal(edit.choices[0].message.tool_calls[0].function.name, 'edit');
  assert.deepEqual(JSON.parse(edit.choices[0].message.tool_calls[0].function.arguments), {
    path: 'example.txt', old_text: MCP_BEFORE, new_text: MCP_AFTER });
  request.messages.push({ role: 'tool', content: '{}', tool_call_id: 'owned-mcp-edit' } as typeof request.messages[number]);
  assert.equal(responder.respond(request)!.choices[0].finish_reason, 'stop');
  assert.throws(() => responder.respond(request)); assert.equal(responder.posts('known_json'), 3);
});

test('every ambiguous owned case refuses a second model reply rather than inventing a returned MCP result', () => {
  for (const kind of ['unknown_after_effect', 'unknown_after_effect_restart', 'unknown_cancel_then_ack',
    'discovery_changed', 'unterminated_event'] as const) {
    const responder = createInstalledMcpModelResponder('owned-model', () => builtins); responder.begin(kind);
    const request = body(kind); assert.equal(responder.respond(request)!.choices[0].finish_reason, 'tool_calls');
    assert.throws(() => responder.respond(request)); assert.equal(responder.posts(kind), 1);
  }
});

test('owned provider refuses missing, substituted or duplicate exposed tools and unrelated objectives', () => {
  const responder = createInstalledMcpModelResponder('owned-model', () => builtins); responder.begin('known_sse_ping');
  const request = body('known_sse_ping');
  assert.throws(() => responder.respond({ ...request, tools: request.tools.slice(0, -1) }));
  assert.throws(() => responder.respond({ ...request, tools: [...request.tools, request.tools[0]] }));
  const wrong = structuredClone(request); wrong.tools.at(-1)!.function.name = 'mcp_unregistered';
  assert.throws(() => responder.respond(wrong)); assert.equal(responder.posts('known_sse_ping'), 0);
  assert.equal(responder.respond({ messages: [{ role: 'user', content: 'unrelated' }], tools: [] }), undefined);
});
