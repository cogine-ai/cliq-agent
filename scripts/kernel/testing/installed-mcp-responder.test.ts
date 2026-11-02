// Finite owned-service decisions only. No server, socket, Store, native proof
// or installed Run is created by these tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMcpHttpCaptureData } from '../../../src/kernel/mcp-wire.js';
import { createInstalledMcpResponder, OWNED_MCP_INPUT, OWNED_MCP_RESULT,
  OWNED_MCP_TOOL, type InstalledMcpCase } from './installed-mcp-responder.js';

const headers = { accept: 'application/json, text/event-stream', 'content-type': 'application/json',
  'mcp-protocol-version': '2025-11-25' };
const initialize = (id: string) => ({ jsonrpc: '2.0', id, method: 'initialize', params: {
  protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: '@cogineai/cliq', version: '0.15.0' } } });
const initialized = { jsonrpc: '2.0', method: 'notifications/initialized' };
const list = (id: string) => ({ jsonrpc: '2.0', id, method: 'tools/list' });
const call = { jsonrpc: '2.0', id: 'run-call', method: 'tools/call', params: {
  name: OWNED_MCP_TOOL, arguments: { value: OWNED_MCP_INPUT } } };
function discover(responder: ReturnType<typeof createInstalledMcpResponder>, kind: InstalledMcpCase, prefix: string) {
  const negotiated = responder.accept(kind, initialize(prefix + '-init'), headers);
  if (kind === 'known_sse_ping') {
    assert(negotiated.kind === 'response');
    const captured = decodeMcpHttpCaptureData({ bytes: negotiated.bytes, mediaType: negotiated.mediaType,
      reportedCompletion: 'sse_response_event', expectedId: prefix + '-init' });
    assert.deepEqual(captured.response, { kind: 'result', id: prefix + '-init', result: {
      protocolVersion: '2025-11-25', capabilities: { tools: { listChanged: true } },
      serverInfo: { name: 'cliq-owned-mcp-fixture', version: '1' } } },
    'Admin and Run must freeze the same list-changed capability');
  }
  assert.equal(responder.accept(kind, initialized, headers).kind, 'ack');
  return responder.accept(kind, list(prefix + '-list'), headers);
}
function ready(kind: InstalledMcpCase) {
  const responder = createInstalledMcpResponder(); responder.begin(kind);
  discover(responder, kind, 'admin'); discover(responder, kind, 'run'); return responder;
}

test('owned JSON recipe observes one real discovery client and one distinct call client without hidden methods', () => {
  const responder = ready('known_json'), reply = responder.accept('known_json', call, headers);
  assert.equal(reply.kind, 'response');
  if (reply.kind !== 'response') return;
  assert.equal(reply.mediaType, 'application/json'); assert.equal(reply.holdOpen, false);
  assert.deepEqual(JSON.parse(reply.bytes.toString()), { jsonrpc: '2.0', id: 'run-call', result: {
    content: [{ type: 'text', text: OWNED_MCP_RESULT }], structuredContent: { value: OWNED_MCP_RESULT }, isError: false } });
  const observed = responder.inspect('known_json');
  assert.equal(observed.clients, 2); assert.equal(observed.posts, 7); assert.equal(observed.effects, 1);
  assert.deepEqual(observed.methods, ['initialize', 'notifications/initialized', 'tools/list',
    'initialize', 'notifications/initialized', 'tools/list', 'tools/call']);
  assert.throws(() => responder.accept('known_json', call, headers));
  assert.throws(() => responder.accept('known_json', initialize('reconnect'), headers));
});

test('owned SSE result waits for the exact correlated ping reply and retains already-received tail', () => {
  const responder = ready('known_sse_ping'), reply = responder.accept('known_sse_ping', call, headers);
  assert.equal(reply.kind, 'response'); if (reply.kind !== 'response') return;
  assert.equal(reply.mediaType, 'text/event-stream'); assert.equal(reply.holdOpen, true); assert.equal(reply.awaitingPingReply, true);
  assert(reply.bytes.includes(Buffer.from('"method":"ping"')));
  assert.equal(responder.inspect('known_sse_ping').pingReplies, 0);
  assert.throws(() => responder.accept('known_sse_ping', { jsonrpc: '2.0', id: 'foreign', result: {} }, headers));
  const ack = responder.accept('known_sse_ping', { jsonrpc: '2.0', id: 'owned-inbound-ping', result: {} }, headers);
  assert.equal(ack.kind, 'ping_ack'); if (ack.kind !== 'ping_ack') return;
  assert(ack.continuation.includes(Buffer.from('"id":"run-call"')));
  assert(ack.continuation.includes(Buffer.from(OWNED_MCP_RESULT)));
  assert(ack.continuation.toString().endsWith('original capture\r\n'));
  const changedAt = ack.continuation.indexOf(Buffer.from('"method":"notifications/tools/list_changed"'));
  const resultAt = ack.continuation.indexOf(Buffer.from('"id":"run-call"'));
  assert(changedAt >= 0 && resultAt > changedAt, 'the complete list-changed notification precedes the original call result');
  const bytes = Buffer.concat([reply.bytes, ack.continuation]);
  const captured = decodeMcpHttpCaptureData({ bytes, mediaType: 'text/event-stream',
    reportedCompletion: 'sse_response_event', expectedId: 'run-call' });
  assert.deepEqual(captured.messagesBeforeResponse, [{ kind: 'ping', id: 'owned-inbound-ping' },
    { kind: 'notification', method: 'notifications/tools/list_changed' }]);
  assert.deepEqual(captured.response, { kind: 'result', id: 'run-call', result: {
    content: [{ type: 'text', text: OWNED_MCP_RESULT }], structuredContent: { value: OWNED_MCP_RESULT }, isError: false } });
  assert.equal(captured.rawFinitePrefixBytes, bytes.length);
  assert.equal(captured.receivedTailBytes, Buffer.byteLength(': already received tail must remain in the original capture\r\n'));
  assert.equal(captured.responseEventEndOffset! + captured.receivedTailBytes, bytes.length);
  assert.equal(responder.inspect('known_sse_ping').pingReplies, 1);
  assert.equal(responder.inspect('known_sse_ping').pingPending, false);
  assert.equal(responder.inspect('known_sse_ping').callRequests, 1);
  assert.equal(responder.inspect('known_sse_ping').effects, 1);
  assert.throws(() => responder.accept('known_sse_ping', { jsonrpc: '2.0', id: 'owned-inbound-ping', result: {} }, headers));
});

test('owned disconnect follows the external effect and cannot be relabeled a received result or sent again', () => {
  const responder = ready('unknown_after_effect');
  assert.deepEqual(responder.accept('unknown_after_effect', call, headers), { kind: 'disconnect_after_effect' });
  assert.equal(responder.inspect('unknown_after_effect').effects, 1);
  assert.throws(() => responder.accept('unknown_after_effect', call, headers));
  assert.throws(() => discover(responder, 'unknown_after_effect', 'retry'));
  assert.equal(responder.inspect('unknown_after_effect').effects, 1);
});

test('owned changed discovery is genuine changed schema data and refuses any tools/call', () => {
  const responder = createInstalledMcpResponder(); responder.begin('discovery_changed');
  const original = discover(responder, 'discovery_changed', 'admin'), changed = discover(responder, 'discovery_changed', 'run');
  assert.equal(original.kind, 'response'); assert.equal(changed.kind, 'response');
  if (original.kind !== 'response' || changed.kind !== 'response') return;
  assert.deepEqual(JSON.parse(original.bytes.toString()).result.tools[0].inputSchema.required, ['value']);
  assert.deepEqual(JSON.parse(changed.bytes.toString()).result.tools[0].inputSchema.required, []);
  assert.throws(() => responder.accept('discovery_changed', call, headers));
  assert.equal(responder.inspect('discovery_changed').effects, 0);
});

test('owned incomplete SSE really lacks the blank-line delimiter even when its JSON is valid', () => {
  const responder = ready('unterminated_event'), reply = responder.accept('unterminated_event', call, headers);
  assert.equal(reply.kind, 'response'); if (reply.kind !== 'response') return;
  assert.equal(reply.mediaType, 'text/event-stream'); assert.equal(reply.holdOpen, false);
  const bytes = reply.bytes.toString(); assert(bytes.startsWith('data: ')); assert(bytes.endsWith('\n'));
  assert(!bytes.endsWith('\n\n')); assert.doesNotThrow(() => JSON.parse(bytes.slice(6).trimEnd()));
  assert.equal(responder.inspect('unterminated_event').effects, 1);
});

test('owned protocol refuses missing negotiation, hidden requests, extra capabilities and session authority', () => {
  const fresh = () => { const responder = createInstalledMcpResponder(); responder.begin('known_json'); return responder; };
  assert.throws(() => fresh().accept('known_json', call, headers));
  assert.throws(() => fresh().accept('known_json', initialize('init'), { ...headers, accept: 'application/json' }));
  for (const key of ['cookie', 'authorization', 'mcp-session-id', 'last-event-id']) {
    assert.throws(() => fresh().accept('known_json', initialize('init'), { ...headers, [key]: 'unowned' }));
  }
  const changed = initialize('init'); changed.params.capabilities = { roots: {} };
  assert.throws(() => fresh().accept('known_json', changed, headers));
  const responder = fresh(); responder.accept('known_json', initialize('init'), headers);
  assert.throws(() => responder.accept('known_json', initialized, { ...headers, 'mcp-protocol-version': '2024-11-05' }));
  responder.accept('known_json', initialized, headers);
  assert.throws(() => responder.accept('known_json', { jsonrpc: '2.0', id: 'unexpected', method: 'resources/list' }, headers));
});
