// Pure protocol data. Call only with native-screened bytes in production.
// No value returned here proves receipt, NoEcho, EOF, join, claim or permission.
import { types } from 'node:util';
import { canonicalJsonBytes } from './canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireText } from './control-wire-data.js';
import { assertBoundedJsonValue, MAX_JSON_CONTAINER_ENTRIES, measureBoundedJsonValue, parseJsonStrict } from './json.js';
import { sha256Bytes } from './identity.js';
import { MCP_PROTOCOL_VERSION, MCP_RESPONSE_BYTES } from './mcp.js';
import { immutableSnapshot } from '../model/immutable.js';

export type McpRpcId = string | number;
export type McpFixedRequestData = Readonly<{
  phase: 'initialize' | 'initialized' | 'tools_list' | 'tools_call';
  json: string; digest: string;
}>;
export type McpInboundMessageData = Readonly<{ kind: 'result'; id: McpRpcId; result: Readonly<Record<string, unknown>> }> |
  Readonly<{ kind: 'error'; id: McpRpcId; error: Readonly<{ code: number; message: string; data?: unknown }> }> |
  Readonly<{ kind: 'ping'; id: McpRpcId }> |
  Readonly<{ kind: 'notification'; method: 'notifications/tools/list_changed' | 'notifications/progress' | 'notifications/message';
    params?: Readonly<Record<string, unknown>> }>;
export type McpCaptureCompletionData = 'http_eof' | 'sse_response_event';
export type McpDecodedCaptureData = Readonly<{
  mediaType: 'application/json' | 'text/event-stream';
  // This is the entire finite capture, including any read-ahead after the
  // matching event. It is a full body only when the genuine owner observed EOF.
  rawFinitePrefixBytes: number; rawFinitePrefixDigest: string;
  reportedCompletion: McpCaptureCompletionData;
  responseEventEndOffset?: number; receivedTailBytes: number;
  messagesBeforeResponse: readonly McpInboundMessageData[];
  response: Extract<McpInboundMessageData, { kind: 'result' | 'error' }>;
}>;

function id(value: unknown): McpRpcId {
  if (typeof value === 'string') {
    // Correlated server ids are wire values, not canonical public identifiers.
    // Preserve their exact Unicode spelling in the fixed empty-result reply.
    if (canonicalJsonBytes(value).byteLength > MCP_RESPONSE_BYTES) throw new TypeError('MCP id exceeds the original byte bound');
    return value;
  }
  return controlWireInteger(value, Number.MIN_SAFE_INTEGER);
}
function bounded(value: unknown): void {
  assertControlWireJson(value);
  assertBoundedJsonValue(value, 'MCP wire data');
  if (canonicalJsonBytes(value).byteLength > MCP_RESPONSE_BYTES) throw new TypeError('MCP wire JSON exceeds its byte bound');
}
function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('MCP JSON-RPC value must be an object');
  return value as Record<string, unknown>;
}
function frame(phase: McpFixedRequestData['phase'], value: unknown): McpFixedRequestData {
  bounded(value);
  const bytes = canonicalJsonBytes(value);
  return Object.freeze({ phase, json: bytes.toString('utf8'), digest: sha256Bytes(bytes) });
}

/** Builds data for the fixed recipe; it cannot release or send a stage. */
export function mcpInitializeRequestData(requestId: McpRpcId, clientVersion: string): McpFixedRequestData {
  return frame('initialize', { jsonrpc: '2.0', id: id(requestId), method: 'initialize', params: {
    protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {},
    clientInfo: { name: '@cogineai/cliq', version: controlWireText(clientVersion) },
  } });
}
export function mcpInitializedNotificationData(): McpFixedRequestData {
  return frame('initialized', { jsonrpc: '2.0', method: 'notifications/initialized' });
}
export function mcpToolsListRequestData(requestId: McpRpcId): McpFixedRequestData {
  return frame('tools_list', { jsonrpc: '2.0', id: id(requestId), method: 'tools/list' });
}
export function mcpToolsCallRequestData(requestId: McpRpcId, toolName: string, argumentsData: unknown): McpFixedRequestData {
  bounded(argumentsData); record(argumentsData);
  return frame('tools_call', { jsonrpc: '2.0', id: id(requestId), method: 'tools/call', params: {
    name: controlWireText(toolName, 128), arguments: argumentsData,
  } });
}

/** The native owner must independently correlate and authorize every ping. */
export function mcpPingReplyData(inboundId: McpRpcId): string {
  const value = { jsonrpc: '2.0', id: id(inboundId), result: {} };
  bounded(value);
  return canonicalJsonBytes(value).toString('utf8');
}

export function decodeMcpInboundMessageData(value: unknown): McpInboundMessageData {
  bounded(value);
  const data = record(value);
  if (data.jsonrpc !== '2.0') throw new TypeError('MCP JSON-RPC version differs');
  if (Object.hasOwn(data, 'result')) {
    controlWireRecord(data, ['jsonrpc', 'id', 'result']); id(data.id); record(data.result);
    return immutableSnapshot({ kind: 'result', id: data.id as McpRpcId, result: data.result as Record<string, unknown> });
  }
  if (Object.hasOwn(data, 'error')) {
    controlWireRecord(data, ['jsonrpc', 'id', 'error']); id(data.id);
    const error = controlWireRecord(data.error, ['code', 'message'], ['data']);
    controlWireInteger(error.code, Number.MIN_SAFE_INTEGER);
    if (typeof error.message !== 'string') throw new TypeError('MCP error message must be text');
    return immutableSnapshot({ kind: 'error', id: data.id as McpRpcId,
      error: error as { code: number; message: string; data?: unknown } });
  }
  if (Object.hasOwn(data, 'id')) {
    controlWireRecord(data, ['jsonrpc', 'id', 'method'], ['params']); id(data.id);
    if (data.method !== 'ping') throw new TypeError('MCP server request is outside the fixed profile');
    if (Object.hasOwn(data, 'params')) controlWireRecord(data.params, []);
    return immutableSnapshot({ kind: 'ping', id: data.id as McpRpcId });
  }
  controlWireRecord(data, ['jsonrpc', 'method'], ['params']);
  if (!['notifications/tools/list_changed', 'notifications/progress', 'notifications/message'].includes(data.method as string))
    throw new TypeError('MCP notification is outside the fixed profile');
  if (Object.hasOwn(data, 'params')) record(data.params);
  if (data.method === 'notifications/tools/list_changed' && Object.hasOwn(data, 'params')) controlWireRecord(data.params, []);
  return immutableSnapshot({ kind: 'notification', method: data.method as Extract<McpInboundMessageData, { kind: 'notification' }>['method'],
    ...(Object.hasOwn(data, 'params') ? { params: data.params as Record<string, unknown> } : {}) });
}

/** Offline validation of one finite, already-screened capture, never a live
 * stream/EOF detector. Tail bytes are hashed/counted, never dropped or parsed
 * as part of the earlier response. Native still owns their NoEcho screening. */
export function decodeMcpHttpCaptureData(input: Readonly<{
  bytes: Uint8Array; mediaType: 'application/json' | 'text/event-stream';
  reportedCompletion: McpCaptureCompletionData; expectedId: McpRpcId; maximumResponseBytes?: number;
}>): McpDecodedCaptureData {
  const expectedId = id(input.expectedId);
  const limit = controlWireInteger(input.maximumResponseBytes ?? MCP_RESPONSE_BYTES, 65_536, MCP_RESPONSE_BYTES);
  if (input.reportedCompletion !== 'http_eof' && input.reportedCompletion !== 'sse_response_event')
    throw new TypeError('MCP capture completion is outside the fixed profile');
  if (types.isProxy(input.bytes) || !types.isUint8Array(input.bytes) || input.bytes.byteLength === 0 || input.bytes.byteLength > limit)
    throw new TypeError('MCP raw response exceeds its original byte bound');
  // Copy only after bounding allocation: no caller-owned mutable view is custody.
  const bytes = Buffer.from(input.bytes);
  const base = { mediaType: input.mediaType, rawFinitePrefixBytes: bytes.byteLength, rawFinitePrefixDigest: sha256Bytes(bytes),
    reportedCompletion: input.reportedCompletion };
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const messages: McpInboundMessageData[] = [];
  let entries = 0;
  let pings = 0;
  const parseMessage = (text: string): McpInboundMessageData => {
    const value = parseJsonStrict(text);
    entries += measureBoundedJsonValue(value, 'MCP response').containerEntries;
    if (entries > MAX_JSON_CONTAINER_ENTRIES) throw new TypeError('MCP response exceeds its aggregate JSON entry bound');
    const message = decodeMcpInboundMessageData(value);
    if (message.kind === 'ping' && ++pings > 8) throw new TypeError('MCP response exceeds the owner ping bound');
    if ((message.kind === 'result' || message.kind === 'error') && message.id !== expectedId)
      throw new TypeError('MCP response id does not match the original request');
    return message;
  };
  if (input.mediaType === 'application/json') {
    if (input.reportedCompletion !== 'http_eof') throw new TypeError('JSON requires genuine complete HTTP body data');
    const response = parseMessage(decoder.decode(bytes));
    if (response.kind !== 'result' && response.kind !== 'error') throw new TypeError('JSON POST response must match the original request');
    return immutableSnapshot({ ...base, receivedTailBytes: 0, messagesBeforeResponse: [], response });
  }
  if (input.mediaType !== 'text/event-stream') throw new TypeError('MCP response media type is outside the fixed profile');
  let lineStart = 0;
  let data: string[] = [];
  let eventName = '';
  // Only the wire-leading SSE BOM is ignored. Offsets always name original bytes.
  if (bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) lineStart = 3;
  for (let offset = lineStart; offset < bytes.length; offset++) {
    if (bytes[offset] !== 10 && bytes[offset] !== 13) continue;
    const line = decoder.decode(bytes.subarray(lineStart, offset));
    if (bytes[offset] === 13 && bytes[offset + 1] === 10) offset++;
    lineStart = offset + 1;
    if (line === '') {
      if (data.length) {
        if (eventName !== '' && eventName !== 'message') throw new TypeError('MCP SSE event type is outside the fixed profile');
        const message = parseMessage(data.join('\n'));
        if (message.kind === 'result' || message.kind === 'error') {
          return immutableSnapshot({ ...base, responseEventEndOffset: lineStart, receivedTailBytes: bytes.length - lineStart,
            messagesBeforeResponse: messages, response: message });
        }
        messages.push(message);
      }
      data = []; eventName = '';
    } else if (!line.startsWith(':')) {
      const colon = line.indexOf(':');
      const field = colon < 0 ? line : line.slice(0, colon);
      const raw = colon < 0 ? '' : line.slice(colon + 1);
      const content = raw.startsWith(' ') ? raw.slice(1) : raw;
      if (field === 'data') data.push(content);
      else if (field === 'event') eventName = content;
      // id/retry/unknown fields have SSE framing semantics only. They never
      // authorize session storage, reconnect, resume, timers or another send.
    }
  }
  // Even genuine EOF does not dispatch an unterminated SSE event.
  throw new TypeError('MCP SSE capture has no complete matching response event');
}
