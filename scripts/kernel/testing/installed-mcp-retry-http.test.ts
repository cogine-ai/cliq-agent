// Actual owned HTTP peer behavior only. No TLS, installed Run, StateOwner,
// native broker, claim, deadline, retry authority or billing is established.
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import test from 'node:test';
import { identityHash } from '../../../src/kernel/identity.js';
import { createInstalledMcpRetryHttpHandler, MCP_RETRY_HTTP_PATH, MCP_RETRY_HTTP_TOOL, MCP_RETRY_HTTP_RESULT } from './installed-mcp-retry-http.js';

test('owned retry peer receives two complete real requests without response, then returns one actual third result and joins all sockets', { timeout: 15_000 }, async t => {
  let failures = 0, scanned = 0;
  const handler = createInstalledMcpRetryHttpHandler(bytes => { scanned += bytes.length; }); handler.begin();
  const server = createServer((incoming, outgoing) => {
    void handler.handle(incoming, outgoing).then(handled => assert.equal(handled, true)).catch(() => { failures++; outgoing.destroy(); });
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address(); assert(address && typeof address === 'object');
  t.after(async () => {
    server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    handler.assertJoined(); assert(scanned > 0); assert.equal(failures, 1);
  });
  const post = (data: unknown) => new Promise<{ status: number | undefined; bytes: Buffer }>((resolve, reject) => {
    const bytes = Buffer.from(JSON.stringify(data));
    const outgoing = request({ host: '127.0.0.1', port: address.port, path: MCP_RETRY_HTTP_PATH, method: 'POST', agent: false,
      headers: { Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json',
        'Content-Length': String(bytes.length), 'MCP-Protocol-Version': '2025-11-25' } }, incoming => {
      const chunks: Buffer[] = []; incoming.once('error', reject); incoming.on('data', chunk => chunks.push(Buffer.from(chunk)));
      incoming.once('end', () => resolve({ status: incoming.statusCode, bytes: Buffer.concat(chunks) }));
    });
    outgoing.once('error', reject); outgoing.setTimeout(5_000, () => outgoing.destroy(new Error('owned retry peer request did not join'))); outgoing.end(bytes);
  });
  const key = identityHash('owned-http-retry-data-only'), call = { jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: MCP_RETRY_HTTP_TOOL, arguments: { idempotencyKey: key } } };
  for (let client = 0; client < 4; client++) {
    const initialize = await post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {},
      clientInfo: { name: '@cogineai/cliq', version: 'owned-peer-data-test' } } });
    assert.equal(initialize.status, 200); assert.equal(JSON.parse(initialize.bytes.toString()).id, 1);
    const ack = await post({ jsonrpc: '2.0', method: 'notifications/initialized' }); assert.equal(ack.status, 202); assert.equal(ack.bytes.length, 0);
    const list = await post({ jsonrpc: '2.0', id: 2, method: 'tools/list' }); assert.equal(list.status, 200);
    assert.equal(JSON.parse(list.bytes.toString()).result.tools[0].name, MCP_RETRY_HTTP_TOOL);
    if (!client) continue;
    if (client < 3) await assert.rejects(post(call), { code: 'ECONNRESET' });
    else {
      const result = await post(call); assert.equal(result.status, 200);
      assert.deepEqual(JSON.parse(result.bytes.toString()).result.structuredContent, { value: MCP_RETRY_HTTP_RESULT });
    }
  }
  await handler.waitForJoined(Date.now() + 5_000); assert.deepEqual(handler.inspect(), {
    diagnosticOnly: true, clients: 4, posts: 15, effects: 3, originalKey: key, phase: 'called',
  });
  await assert.rejects(post(call), { code: 'ECONNRESET' });
  await handler.waitForJoined(Date.now() + 5_000); assert.equal(handler.inspect().effects, 3);
});
