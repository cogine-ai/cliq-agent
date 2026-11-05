// Owned external HTTPS peer behavior only. A received request counter is not
// an installed claim, native join, safe-retry assertion or provider receipt.
import assert from 'node:assert/strict';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';

export const MCP_RETRY_HTTP_PATH = '/mcp-retry/unknown-unknown-known';
export const MCP_RETRY_HTTP_TOOL = 'owned_retry_effect', MCP_RETRY_HTTP_RESULT = 'owned_actual_third_attempt_result';
const VERSION = '2025-11-25';
const inputSchema = { type: 'object', properties: { idempotencyKey: { type: 'string', pattern: '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$' } },
  required: ['idempotencyKey'], additionalProperties: false };
const outputSchema = { type: 'object', properties: { value: { type: 'string', const: MCP_RETRY_HTTP_RESULT } },
  required: ['value'], additionalProperties: false };
type Data = Record<string, any>;
function same(left: unknown, right: unknown, message: string) { assert.equal(canonicalSha256(left), canonicalSha256(right), message); }
function record(value: unknown): Data {
  assert(value !== null && typeof value === 'object' && !Array.isArray(value), 'owned retry RPC must be an object'); return value as Data;
}
export function createInstalledMcpRetryHttpHandler(scan: (bytes: Uint8Array) => void) {
  let started = false, clients = 0, posts = 0, effects = 0, phase: 'fresh' | 'initialize' | 'initialized' | 'listed' | 'called' = 'fresh';
  let originalKey: string | undefined, lastClosedAt: number | undefined;
  const ids = new Set<string | number>(), sockets = new Set<IncomingMessage['socket']>(), seenSockets = new WeakSet<IncomingMessage['socket']>();
  function respond(outgoing: ServerResponse, id: string | number, result: Data) {
    const bytes = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, result })); scan(bytes);
    outgoing.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(bytes.length), Connection: 'close' }); outgoing.end(bytes);
  }
  return {
    begin() { assert.equal(started, false); started = true; },
    posts: () => posts,
    inspect() { return { diagnosticOnly: true, clients, posts, effects, originalKey, phase }; },
    async waitForJoined(deadlineAt: number) {
      assert(posts > 0, 'the owned retry endpoint must actually have observed its original peer');
      while (sockets.size) { assert(Date.now() < deadlineAt, 'the original HTTP retry peer sockets did not join in their source window'); await delay(10); }
      assert(lastClosedAt !== undefined && lastClosedAt < deadlineAt);
    },
    assertJoined() { assert.equal(sockets.size, 0, 'the external retry endpoint still observes a live original socket'); },
    async handle(incoming: IncomingMessage, outgoing: ServerResponse): Promise<boolean> {
      if (incoming.url !== MCP_RETRY_HTTP_PATH) return false;
      assert(started, 'the fixed HTTP retry case must be selected before its first request');
      if (!seenSockets.has(incoming.socket)) {
        seenSockets.add(incoming.socket); sockets.add(incoming.socket);
        incoming.socket.once('close', () => { sockets.delete(incoming.socket); lastClosedAt = Date.now(); });
      }
      assert.equal(incoming.method, 'POST');
      for (const name of ['cookie', 'authorization', 'mcp-session-id', 'last-event-id']) assert.equal(incoming.headers[name], undefined);
      assert.equal(incoming.headers['content-type'], 'application/json');
      const accepts = String(incoming.headers.accept).split(',').map(value => value.split(';')[0]?.trim());
      assert(accepts.includes('application/json') && accepts.includes('text/event-stream'));
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of incoming) { size += chunk.length; assert(size <= 1_048_576); chunks.push(Buffer.from(chunk)); }
      const bytes = Buffer.concat(chunks); scan(bytes); assert.equal(Number(incoming.headers['content-length']), bytes.length);
      const request = record(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); assert.equal(request.jsonrpc, '2.0'); posts++;
      if (request.method === 'notifications/initialized') {
        same(Object.keys(request).sort(), ['jsonrpc', 'method'], 'initialized has extra fields'); assert.equal(phase, 'initialize');
        assert.equal(incoming.headers['mcp-protocol-version'], VERSION); phase = 'initialized';
        outgoing.writeHead(202, { 'Content-Length': '0', Connection: 'close' }); outgoing.end(); return true;
      }
      assert(typeof request.id === 'string' || typeof request.id === 'number' && Number.isSafeInteger(request.id)); const id = request.id;
      if (request.method === 'initialize') {
        assert(clients < 4 && (phase === 'fresh' || clients === 1 && phase === 'listed' || clients > 1 && phase === 'called'),
          'the single Admin and three real Run clients cannot resend or restart an existing recipe');
        same(Object.keys(request).sort(), ['id', 'jsonrpc', 'method', 'params'], 'initialize has extra fields');
        const params = record(request.params), client = record(params.clientInfo);
        same(Object.keys(params).sort(), ['capabilities', 'clientInfo', 'protocolVersion'], 'initialize params differ');
        same(params.capabilities, {}, 'the fixed retry peer has no ambient capabilities');
        assert(params.protocolVersion === VERSION && client.name === '@cogineai/cliq' && typeof client.version === 'string');
        clients++; phase = 'initialize'; ids.clear(); ids.add(id);
        respond(outgoing, id, { protocolVersion: VERSION, capabilities: { tools: {} }, serverInfo: { name: 'cliq-owned-retry-http-fixture', version: '1' } }); return true;
      }
      assert.equal(incoming.headers['mcp-protocol-version'], VERSION); assert(!ids.has(id)); ids.add(id);
      if (request.method === 'tools/list') {
        same(Object.keys(request).sort(), ['id', 'jsonrpc', 'method'], 'tools/list has extra fields'); assert.equal(phase, 'initialized'); phase = 'listed';
        respond(outgoing, id, { tools: [{ name: MCP_RETRY_HTTP_TOOL, description: 'Owned actual retry fixture effect; prior requests may have succeeded.', inputSchema, outputSchema }] });
        return true;
      }
      assert.equal(request.method, 'tools/call'); assert(clients >= 2 && clients <= 4 && phase === 'listed' && effects === clients - 2);
      same(Object.keys(request).sort(), ['id', 'jsonrpc', 'method', 'params'], 'tools/call has extra fields');
      const params = record(request.params), args = record(params.arguments); same(Object.keys(params).sort(), ['arguments', 'name'], 'call params differ');
      assert.equal(params.name, MCP_RETRY_HTTP_TOOL); same(Object.keys(args), ['idempotencyKey'], 'effect arguments changed');
      assert(typeof args.idempotencyKey === 'string' && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(args.idempotencyKey));
      originalKey ??= args.idempotencyKey; assert.equal(args.idempotencyKey, originalKey); phase = 'called'; effects++;
      if (effects < 3) {
        // The complete original real request was actually received. No result
        // bytes are sent, so only the installed owner's true UNKNOWN/join can
        // authorize any later attempt under the original risk consent.
        outgoing.destroy(); return true;
      }
      assert.equal(effects, 3); respond(outgoing, id, { content: [{ type: 'text', text: MCP_RETRY_HTTP_RESULT }],
        structuredContent: { value: MCP_RETRY_HTTP_RESULT }, isError: false }); return true;
    },
  };
}
