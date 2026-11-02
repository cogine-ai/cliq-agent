// Decisions for the owned external MCP service. This is not a client, native
// receipt, effect-status endpoint or substitute for installed qualification.
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';

export const INSTALLED_MCP_CASES = ['known_json', 'known_sse_ping', 'unknown_after_effect', 'unknown_after_effect_restart', 'unknown_cancel_then_ack',
  'discovery_changed', 'unterminated_event'] as const;
export type InstalledMcpCase = typeof INSTALLED_MCP_CASES[number];
const VERSION = '2025-11-25';
export const OWNED_MCP_INPUT = 'owned_mcp_input';
export const OWNED_MCP_RESULT = 'owned_mcp_result';
export const OWNED_MCP_TOOL = 'owned_echo';
export const OWNED_MCP_INPUT_SCHEMA = Object.freeze({ type: 'object', properties: {
  value: { type: 'string', const: OWNED_MCP_INPUT } }, required: ['value'], additionalProperties: false });
const outputSchema = { type: 'object', properties: { value: { type: 'string', const: OWNED_MCP_RESULT } },
  required: ['value'], additionalProperties: false };
type Id = string | number;
type Data = Record<string, unknown>;
export type OwnedMcpReply = Readonly<{ kind: 'ack' }> | Readonly<{ kind: 'disconnect_after_effect' }> |
  Readonly<{ kind: 'response'; mediaType: 'application/json' | 'text/event-stream'; bytes: Buffer;
    holdOpen: boolean; awaitingPingReply: boolean }> |
  Readonly<{ kind: 'ping_ack'; continuation: Buffer }>;
type State = { kind: InstalledMcpCase; client: number; phase: 'fresh' | 'initialize' | 'initialized' | 'listed' | 'called';
  ids: Set<Id>; posts: number; calls: number; effects: number; pingReplies: number;
  ping?: { id: string; responseId: Id }; methods: string[] };
function data(value: unknown): Data {
  assert(value !== null && typeof value === 'object' && !Array.isArray(value), 'owned MCP envelope must be an object');
  return value as Data;
}
function equal(left: unknown, right: unknown, message: string): void {
  // A failed fixture assertion must not print arbitrary request content.
  assert(canonicalSha256(left) === canonicalSha256(right), message);
}
function response(id: Id, result: Data): Buffer { return Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, result })); }
function event(bytes: Buffer): Buffer {
  return Buffer.concat([Buffer.from('event: message\r\ndata: '), bytes, Buffer.from('\r\n\r\n')]);
}
const toolResult = () => ({ content: [{ type: 'text', text: OWNED_MCP_RESULT }],
  structuredContent: { value: OWNED_MCP_RESULT }, isError: false });

/** Exactly one Admin discovery and one Run logical client for each owned case.
 * A reconnect cannot silently restart the recipe or reset its effect count. */
export function createInstalledMcpResponder() {
  const states = new Map<InstalledMcpCase, State>();
  return {
    begin(kind: InstalledMcpCase): void {
      assert(INSTALLED_MCP_CASES.includes(kind) && !states.has(kind), 'owned MCP case is not new');
      states.set(kind, { kind, client: 0, phase: 'fresh', ids: new Set(), posts: 0, calls: 0,
        effects: 0, pingReplies: 0, methods: [] });
    },
    accept(kind: InstalledMcpCase, value: unknown, headers: Readonly<Record<string, unknown>>): OwnedMcpReply {
      const state = states.get(kind); assert(state, 'owned MCP case must be selected before any request');
      assert(headers.cookie === undefined && headers['mcp-session-id'] === undefined &&
        headers['last-event-id'] === undefined && headers.authorization === undefined,
      'the first owned public MCP profile cannot borrow sessions, resumption or credentials');
      const accept = typeof headers.accept === 'string' ? headers.accept.split(',').map(value => value.split(';')[0]!.trim()) : [];
      assert(accept.includes('application/json') && accept.includes('text/event-stream'), 'MCP must advertise both response types');
      assert(headers['content-type'] === 'application/json', 'owned MCP request media type differs');
      const request = data(value);
      assert(request.jsonrpc === '2.0', 'owned MCP requires JSON-RPC 2.0');
      state.posts++;
      if (Object.hasOwn(request, 'result')) {
        assert(state.ping && state.phase === 'called', 'there is no original inbound ping to acknowledge');
        equal(Object.keys(request).sort(), ['id', 'jsonrpc', 'result'], 'ping reply has extra fields');
        assert(request.id === state.ping.id, 'ping reply changed its exact original id');
        equal(request.result, {}, 'ping reply must be the exact empty result');
        assert(headers['mcp-protocol-version'] === VERSION, 'ping reply omitted the negotiated version');
        state.methods.push('ping_reply'); state.pingReplies++;
        const continuation = Buffer.concat([
          event(Buffer.from(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' }))),
          event(response(state.ping.responseId, toolResult())),
          Buffer.from(': already received tail must remain in the original capture\r\n')]);
        state.ping = undefined;
        return { kind: 'ping_ack', continuation };
      }
      assert(typeof request.method === 'string', 'owned MCP request has no method');
      state.methods.push(request.method);
      if (request.method === 'notifications/initialized') {
        equal(Object.keys(request).sort(), ['jsonrpc', 'method'], 'initialized notification has unexpected data');
        assert(state.phase === 'initialize' && !state.ping, 'initialized must follow the actual initialization result');
        assert(headers['mcp-protocol-version'] === VERSION, 'initialized omitted negotiated version');
        state.phase = 'initialized'; return { kind: 'ack' };
      }
      assert(typeof request.id === 'string' || typeof request.id === 'number' && Number.isSafeInteger(request.id), 'owned MCP request has invalid id');
      const id = request.id as Id;
      if (request.method === 'initialize') {
        assert(state.client < 2 && (state.phase === 'fresh' || state.phase === 'listed' && state.client === 1),
          'a logical client cannot restart or resend initialization');
        equal(Object.keys(request).sort(), ['id', 'jsonrpc', 'method', 'params'], 'initialize fields differ');
        const params = data(request.params), client = data(params.clientInfo);
        equal(Object.keys(params).sort(), ['capabilities', 'clientInfo', 'protocolVersion'], 'initialize params differ');
        equal(params.capabilities, {}, 'owned profile has no ambient client capabilities');
        assert(params.protocolVersion === VERSION && client.name === '@cogineai/cliq' && typeof client.version === 'string',
          'owned initialize must name the real fixed Cliq recipe');
        state.client++; state.phase = 'initialize'; state.ids.clear(); state.ids.add(id);
        const bytes = response(id, { protocolVersion: VERSION, capabilities: { tools: { listChanged: kind === 'known_sse_ping' } },
          serverInfo: { name: 'cliq-owned-mcp-fixture', version: '1' } });
        return { kind: 'response', mediaType: kind === 'known_sse_ping' ? 'text/event-stream' : 'application/json',
          bytes: kind === 'known_sse_ping' ? event(bytes) : bytes, holdOpen: kind === 'known_sse_ping', awaitingPingReply: false };
      }
      assert(headers['mcp-protocol-version'] === VERSION, 'owned MCP stage omitted negotiated version');
      assert(!state.ids.has(id), 'a logical client reused an original JSON-RPC request id'); state.ids.add(id);
      if (request.method === 'tools/list') {
        assert(state.phase === 'initialized' && !state.ping, 'tools/list requires a complete initialized acknowledgement');
        equal(Object.keys(request).sort(), ['id', 'jsonrpc', 'method'], 'owned unpaginated tools/list fields differ');
        state.phase = 'listed';
        const schema = kind === 'discovery_changed' && state.client === 2
          ? { ...OWNED_MCP_INPUT_SCHEMA, required: [] } : OWNED_MCP_INPUT_SCHEMA;
        const bytes = response(id, { tools: [{ name: OWNED_MCP_TOOL, description: 'Return the exact owned input as a typed fixture result.',
          inputSchema: schema, outputSchema }] });
        return { kind: 'response', mediaType: kind === 'known_sse_ping' ? 'text/event-stream' : 'application/json',
          bytes: kind === 'known_sse_ping' ? event(bytes) : bytes, holdOpen: kind === 'known_sse_ping', awaitingPingReply: false };
      }
      assert(request.method === 'tools/call', 'the owned recipe accepts no hidden method');
      state.calls++;
      assert(state.client === 2 && state.phase === 'listed' && state.calls === 1 && kind !== 'discovery_changed',
        'Admin cannot call tools and a changed discovery or unknown result cannot release another effect');
      equal(Object.keys(request).sort(), ['id', 'jsonrpc', 'method', 'params'], 'tools/call fields differ');
      equal(request.params, { name: OWNED_MCP_TOOL, arguments: { value: OWNED_MCP_INPUT } }, 'owned MCP call target or exact arguments changed');
      state.phase = 'called'; state.effects++;
      if (kind === 'unknown_after_effect' || kind === 'unknown_after_effect_restart' || kind === 'unknown_cancel_then_ack')
        return { kind: 'disconnect_after_effect' };
      const bytes = response(id, toolResult());
      if (kind === 'unterminated_event') return { kind: 'response', mediaType: 'text/event-stream',
        bytes: Buffer.concat([Buffer.from('data: '), bytes, Buffer.from('\n')]), holdOpen: false, awaitingPingReply: false };
      if (kind === 'known_sse_ping') {
        state.ping = { id: 'owned-inbound-ping', responseId: id };
        return { kind: 'response', mediaType: 'text/event-stream',
          bytes: event(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: state.ping.id, method: 'ping' }))),
          holdOpen: true, awaitingPingReply: true };
      }
      return { kind: 'response', mediaType: 'application/json', bytes, holdOpen: false, awaitingPingReply: false };
    },
    inspect(kind: InstalledMcpCase) {
      const state = states.get(kind); assert(state, 'owned MCP case was never started');
      return Object.freeze({ diagnosticOnly: true as const, kind, clients: state.client, posts: state.posts,
        callRequests: state.calls, effects: state.effects, pingReplies: state.pingReplies, pingPending: state.ping !== undefined,
        methods: Object.freeze([...state.methods]) });
    },
  };
}
