// Pure finite bytes/data only: no native image, SQL, process, timer or endpoint.
import assert from 'node:assert/strict';
import test from 'node:test';
import { sha256Bytes } from './identity.js';
import { decodeMcpHttpCaptureData, decodeMcpInboundMessageData, mcpInitializeRequestData,
  mcpInitializedNotificationData, mcpPingReplyData, mcpToolsCallRequestData, mcpToolsListRequestData } from './mcp-wire.js';

const response = { jsonrpc: '2.0', id: 3, result: { content: [{ type: 'text', text: 'received' }] } };
const event = (value: unknown, eol = '\n') => `data: ${JSON.stringify(value)}${eol}${eol}`;
const capture = (bytes: string | Uint8Array, extra: Partial<Parameters<typeof decodeMcpHttpCaptureData>[0]> = {}) =>
  decodeMcpHttpCaptureData({ bytes: typeof bytes === 'string' ? Buffer.from(bytes) : bytes,
    mediaType: 'text/event-stream', reportedCompletion: 'sse_response_event', expectedId: 3, ...extra });

test('fixed real MCP request data has initialize, initialized, list and one call without ambient transport fields', () => {
  const frames = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(),
    mcpToolsListRequestData(2), mcpToolsCallRequestData(3, 'owned-tool', { exact: 'original input' })];
  assert.deepEqual(frames.map(frame => frame.phase), ['initialize', 'initialized', 'tools_list', 'tools_call']);
  assert.deepEqual(frames.map(frame => JSON.parse(frame.json).method),
    ['initialize', 'notifications/initialized', 'tools/list', 'tools/call']);
  assert.deepEqual(JSON.parse(frames[0].json).params, { protocolVersion: '2025-11-25', capabilities: {},
    clientInfo: { name: '@cogineai/cliq', version: '0.15.0' } });
  for (const frame of frames) {
    assert.equal(frame.digest, sha256Bytes(Buffer.from(frame.json)));
    assert(Object.isFrozen(frame));
    assert.deepEqual(Object.keys(frame).sort(), ['digest', 'json', 'phase']);
  }
  assert.deepEqual(JSON.parse(mcpPingReplyData('e\u0301')), { jsonrpc: '2.0', id: 'e\u0301', result: {} });
  assert.throws(() => mcpPingReplyData('x'.repeat(1_048_573)));
  assert.throws(() => mcpToolsCallRequestData(3, 'owned-tool', []));
  assert.throws(() => mcpToolsListRequestData(0.5));
  let read = false;
  const input = Object.defineProperty({}, 'value', { enumerable: true, get() { read = true; return 'unread'; } });
  assert.throws(() => mcpToolsCallRequestData(3, 'owned-tool', input));
  assert.equal(read, false);
});

test('JSON data requires an entire matching UTF-8 response and retains received errors as data', () => {
  const bytes = Buffer.from(JSON.stringify(response));
  const data = capture(bytes, { mediaType: 'application/json', reportedCompletion: 'http_eof' });
  assert.equal(data.rawFinitePrefixDigest, sha256Bytes(bytes));
  assert.equal(data.response.kind, 'result');
  assert.equal(data.reportedCompletion, 'http_eof');
  assert.equal(data.receivedTailBytes, 0);
  assert(!Object.hasOwn(data, 'responseEventEndOffset'));
  bytes.fill(0);
  assert.equal((data.response as any).result.content[0].text, 'received');
  const rejected = capture(JSON.stringify({ jsonrpc: '2.0', id: 3, error: { code: -32602, message: 'bad input' } }),
    { mediaType: 'application/json', reportedCompletion: 'http_eof' });
  assert.equal(rejected.response.kind, 'error');
  for (const text of ['{"jsonrpc":"2.0","id":3,"id":3,"result":{}}',
    JSON.stringify({ ...response, id: '3' }), JSON.stringify([response]), `${JSON.stringify(response)}x`])
    assert.throws(() => capture(text, { mediaType: 'application/json', reportedCompletion: 'http_eof' }));
  assert.throws(() => capture(JSON.stringify(response), { mediaType: 'application/json' }));
  assert.throws(() => capture(Buffer.from([0xff]), { mediaType: 'application/json', reportedCompletion: 'http_eof' }));
});

test('SSE framing accepts CR, LF, CRLF, BOM, comments and multiple data lines at original byte offsets', () => {
  for (const eol of ['\r', '\n', '\r\n']) {
    const text = `\ufeff: keepalive${eol}${eol}event: message${eol}id: inert-resume-id${eol}retry: 1${eol}` +
      `data: {"jsonrpc":"2.0",${eol}data: "id":3,"result":{"text":"\u2603"}}${eol}${eol}`;
    const data = capture(text);
    assert.equal(data.response.kind, 'result');
    assert.equal(data.responseEventEndOffset, Buffer.byteLength(text));
    assert.equal(data.receivedTailBytes, 0);
    assert.equal(data.reportedCompletion, 'sse_response_event');
    assert.equal(data.rawFinitePrefixDigest, sha256Bytes(Buffer.from(text)));
    assert(Object.isFrozen(data)); assert(Object.isFrozen(data.response));
  }
});

test('finite SSE prefix never claims EOF and every received tail byte is retained in its hash and original B', () => {
  const terminal = Buffer.from(event(response));
  // Includes read-ahead with an incomplete UTF-8 scalar: it is received raw
  // custody, not another complete event, and still needs native NoEcho.
  const tail = Buffer.concat([Buffer.from(': received after the complete event\n\ndata: unfinished'), Buffer.from([0xe2, 0x82])]);
  const bytes = Buffer.concat([terminal, tail]);
  const data = capture(bytes);
  assert.equal(data.reportedCompletion, 'sse_response_event');
  assert.equal(data.responseEventEndOffset, terminal.length);
  assert.equal(data.receivedTailBytes, tail.length);
  assert.equal(data.rawFinitePrefixBytes, bytes.length);
  assert.equal(data.rawFinitePrefixDigest, sha256Bytes(bytes));
  assert.notEqual(data.rawFinitePrefixDigest, sha256Bytes(terminal));
  const eofData = capture(bytes, { reportedCompletion: 'http_eof' });
  assert.equal(eofData.reportedCompletion, 'http_eof');
  assert.equal(eofData.receivedTailBytes, tail.length);
  const exact = Buffer.concat([terminal, Buffer.alloc(65_536 - terminal.length, 32)]);
  assert.equal(capture(exact, { maximumResponseBytes: 65_536 }).rawFinitePrefixBytes, 65_536);
  assert.throws(() => capture(Buffer.concat([exact, Buffer.from('x')]), { maximumResponseBytes: 65_536 }));
  assert.throws(() => capture(terminal, { maximumResponseBytes: 65_535 }));
  assert.throws(() => capture(terminal, { maximumResponseBytes: 1_048_577 }));
});

test('EOF never dispatches partial SSE and an earlier malformed or foreign response cannot be skipped', () => {
  for (const ending of ['', '\n', '\r\n']) {
    const partial = `data: ${JSON.stringify(response)}${ending}`;
    assert.throws(() => capture(partial));
    assert.throws(() => capture(partial, { reportedCompletion: 'http_eof' }));
  }
  for (const prefix of ['data: {broken}\n\n', event({ ...response, id: 4 }),
    'data: {"jsonrpc":"2.0","id":3,"result":{},"result":{}}\n\n',
    'event: unsupported\ndata: {}\n\n', 'data: [DONE]\n\n']) assert.throws(() => capture(prefix + event(response)));
});

test('only fixed bounded inbound messages precede the response; pings never become a transport authority', () => {
  const ping = { jsonrpc: '2.0', id: 'server-id', method: 'ping' };
  const changed = { jsonrpc: '2.0', method: 'notifications/tools/list_changed' };
  const data = capture(event(ping) + event(changed) + event(response));
  assert.deepEqual(data.messagesBeforeResponse, [{ kind: 'ping', id: 'server-id' },
    { kind: 'notification', method: 'notifications/tools/list_changed' }]);
  assert.equal(capture(event(ping).repeat(8) + event(response)).messagesBeforeResponse.length, 8);
  assert.throws(() => capture(event(ping).repeat(9) + event(response)));
  for (const value of [{ ...ping, method: 'sampling/createMessage' }, { ...ping, params: { target: 'other' } },
    { jsonrpc: '2.0', method: 'notifications/unknown' }, { ...response, error: { code: 1, message: 'mixed' } },
    { ...response, id: null }, { ...response, result: 'not an MCP result object' }])
    assert.throws(() => decodeMcpInboundMessageData(value));
  // Count JSON members across events, rather than resetting per SSE event.
  const log = event({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'bounded' } });
  assert.throws(() => capture(log.repeat(2000) + event(response)));
  let nested: unknown = {};
  for (let depth = 0; depth < 33; depth++) nested = { next: nested };
  assert.throws(() => capture(event({ ...response, result: nested })));
});
