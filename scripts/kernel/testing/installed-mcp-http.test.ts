// Actual loopback HTTP adapter tests only. These do not load a broker, claim
// an installed Run, exercise TLS, or establish external-effect safety.
import assert from 'node:assert/strict';
import { createServer, request, type IncomingMessage } from 'node:http';
import test, { type TestContext } from 'node:test';
import { createInstalledMcpHttpHandler } from './installed-mcp-http.js';
import { OWNED_MCP_INPUT, OWNED_MCP_TOOL, type InstalledMcpCase } from './installed-mcp-responder.js';

const headers = { Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json',
  'MCP-Protocol-Version': '2025-11-25' };
const initialize = (id: string) => ({ jsonrpc: '2.0', id, method: 'initialize', params: {
  protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: '@cogineai/cliq', version: 'owned-adapter-test' } } });
const initialized = { jsonrpc: '2.0', method: 'notifications/initialized' };
const list = (id: string) => ({ jsonrpc: '2.0', id, method: 'tools/list' });
const call = { jsonrpc: '2.0', id: 'run-call', method: 'tools/call', params: {
  name: OWNED_MCP_TOOL, arguments: { value: OWNED_MCP_INPUT } } };

async function service(t: TestContext, kind: InstalledMcpCase) {
  let failures = 0, scanned = 0;
  const handler = createInstalledMcpHttpHandler(bytes => { scanned += bytes.length; });
  handler.responder.begin(kind);
  const server = createServer((incoming, outgoing) => {
    void handler.handle(incoming, outgoing).then(handled => {
      if (!handled) { outgoing.writeHead(404, { Connection: 'close' }); outgoing.end(); }
    }).catch(() => { failures++; outgoing.destroy(); });
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address(); assert(address && typeof address === 'object');
  const active = new Set<IncomingMessage>(), joins: Promise<void>[] = [];
  t.after(async () => {
    for (const response of active) response.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await Promise.all(joins); handler.assertJoined(); assert.equal(failures, 0); assert(scanned > 0);
  });
  const post = async (value: unknown) => {
    const bytes = Buffer.from(JSON.stringify(value));
    const response = await new Promise<IncomingMessage>((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port: address.port, path: `/mcp/${kind}`, method: 'POST', agent: false,
        headers: { ...headers, 'Content-Length': String(bytes.length) } }, resolve);
      req.once('error', reject); req.setTimeout(5000, () => req.destroy(new Error('owned adapter request did not join'))); req.end(bytes);
    });
    active.add(response); response.on('error', () => {});
    joins.push(new Promise<void>(resolve => response.once('close', () => { active.delete(response); resolve(); })));
    return response;
  };
  const complete = async (value: unknown) => {
    const response = await post(value), chunks: Buffer[] = [];
    for await (const chunk of response) chunks.push(Buffer.from(chunk));
    return { status: response.statusCode, bytes: Buffer.concat(chunks) };
  };
  const firstEvent = async (value: unknown) => {
    const response = await post(value); assert.equal(response.statusCode, 200);
    assert.equal(response.headers['content-type'], 'text/event-stream');
    const first = await new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      const data = (chunk: Buffer) => {
        chunks.push(Buffer.from(chunk)); const bytes = Buffer.concat(chunks);
        if (bytes.includes(Buffer.from('\r\n\r\n'))) { response.off('data', data); response.pause(); resolve(bytes); }
      };
      response.on('data', data); response.once('error', reject); response.once('end', () => reject(new Error('owned event stream ended before a complete event')));
    });
    return { response, first };
  };
  return { handler, complete, post, firstEvent };
}

test('actual owned HTTP adapter keeps initialized ACK empty and JSON responses finite', { timeout: 10000 }, async t => {
  const owner = await service(t, 'known_json');
  for (const prefix of ['admin', 'run']) {
    const init = await owner.complete(initialize(prefix + '-init')); assert.equal(init.status, 200);
    assert.equal(JSON.parse(init.bytes.toString()).id, prefix + '-init');
    const ack = await owner.complete(initialized); assert.equal(ack.status, 202); assert.equal(ack.bytes.length, 0);
    const tools = await owner.complete(list(prefix + '-list')); assert.equal(tools.status, 200);
    assert.equal(JSON.parse(tools.bytes.toString()).result.tools[0].name, OWNED_MCP_TOOL);
  }
  const result = await owner.complete(call); assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.bytes.toString()).id, 'run-call');
  await owner.handler.waitForCaseJoined('known_json', Date.now() + 5000);
  assert.equal(owner.handler.posts(), 7); assert.equal(owner.handler.responder.inspect('known_json').effects, 1);
});

test('actual owned SSE adapter retains the original stream across a separate correlated ping POST', { timeout: 10000 }, async t => {
  const owner = await service(t, 'known_sse_ping');
  for (const prefix of ['admin', 'run']) {
    const init = await owner.firstEvent(initialize(prefix + '-init')); init.response.destroy();
    const ack = await owner.complete(initialized); assert.equal(ack.status, 202); assert.equal(ack.bytes.length, 0);
    const tools = await owner.firstEvent(list(prefix + '-list')); tools.response.destroy();
  }
  const original = await owner.firstEvent(call); assert(original.first.includes(Buffer.from('"method":"ping"')));
  const continuation = new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    original.response.on('data', (chunk: Buffer) => {
      chunks.push(Buffer.from(chunk)); const bytes = Buffer.concat(chunks);
      if (bytes.includes(Buffer.from('already received tail'))) resolve(bytes);
    });
    original.response.once('error', reject); original.response.resume();
  });
  const ack = await owner.complete({ jsonrpc: '2.0', id: 'owned-inbound-ping', result: {} });
  assert.equal(ack.status, 202); assert.equal(ack.bytes.length, 0);
  const bytes = await continuation;
  assert(bytes.includes(Buffer.from('"id":"run-call"'))); assert(bytes.includes(Buffer.from('original capture\r\n')));
  await assert.rejects(owner.handler.waitForCaseJoined('known_sse_ping', Date.now() + 30),
    /original MCP peer sockets did not actually join/u);
  original.response.destroy();
  await owner.handler.waitForCaseJoined('known_sse_ping', Date.now() + 5000);
  assert.equal(owner.handler.posts(), 8); assert.equal(owner.handler.responder.inspect('known_sse_ping').pingReplies, 1);
});
