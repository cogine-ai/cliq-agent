// Closed stdio lifecycle/protocol data only. None of these decoders can mint
// a live server, native receipt, launch grant, process death or recovery proof.
import { types } from 'node:util';
import type { ArtifactRef } from './types.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from './identity.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertBoundedJsonValue, MAX_JSON_CONTAINER_ENTRIES, measureBoundedJsonValue, parseJsonStrict } from './json.js';
import { MCP_RESPONSE_BYTES } from './mcp.js';
import { decodeMcpInboundMessageData, type McpInboundMessageData, type McpRpcId } from './mcp-wire.js';
import { immutableSnapshot } from '../model/immutable.js';

export type McpServerInstanceIdentityV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-server-instance-identity-v1'; runId: string;
  batchItemId: string; callId: string; callIndex: number; registrationId: string;
  registryRevisionRef: ArtifactRef; registryManifestDigest: string; lifecycleSeq: number;
  launchOpId: string; launchAttempt: number; launchDispatchId: string;
  sandboxLaunchSpecRef: ArtifactRef; processContainmentRef: ArtifactRef;
  initializeDigest: string; capabilityDigest: string; probedToolsListDigest: string;
  instanceNonceDigest: string; initializedAt: string; identityDigest: string;
}>;
export type McpServerLaunchReceiptV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-server-launch-receipt-v1'; instanceIdentityRef: ArtifactRef; instanceIdentityDigest: string;
  preparedJournalSeq: number; claimedJournalSeq: number; completedJournalSeq: number;
  budgetSettlementRef: ArtifactRef; stoppedItemId: string; containmentDeathEvidenceRef: ArtifactRef;
  stoppedAt: string; receiptDigest: string;
  nativeClosure: Readonly<{ kind: 'linux_original_join'; lifecycleRawRef: ArtifactRef; lifecycleProjectionRef: ArtifactRef }> |
    Readonly<{ kind: 'linux_successor_cleanup'; lifecycleRawRef: ArtifactRef; lifecycleProjectionRef: ArtifactRef;
      cleanupRawRef: ArtifactRef; cleanupProjectionRef: ArtifactRef }>;
}>;
export type McpServerStoppedItem = Readonly<{
  schemaVersion: 1; itemId: string; runId: string; kind: 'mcp_server_stopped'; batchItemId: string; callId: string; callIndex: number;
  serverManifestRef: ArtifactRef; lifecycleSeq: number; launchOpId: string; instanceIdentityRef: ArtifactRef; instanceIdentityDigest: string;
  launchReceiptRef: ArtifactRef; launchReceiptDigest: string;
  cause: 'normal' | 'lease_release' | 'crash' | 'cancel' | 'deadline' | 'manifest_mismatch';
  containmentEvidenceRef: ArtifactRef; createdAt: string;
}>;
export type McpStdioCaptureV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-mcp-stdio-capture-v1'; phase: 'initialize' | 'tools_list' | 'tools_call'; expectedId: McpRpcId;
  framing: 'newline_json_rpc'; termination: 'stdio_response_line'; rawResponseRef: ArtifactRef;
  rawFinitePrefixBytes: number; responseLineEndOffset: number; receivedTailBytes: number; captureDigest: string;
}>;
export function decodeMcpStdioExecutableIdentity(value: unknown) {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP stdio executable identity projection');
  const data = controlWireRecord(value, ['kind', 'runtimeBundleRef', 'executableId', 'executionPath', 'executableDigest']);
  if (data.kind !== 'runtime_bundle' || data.executionPath !== '/runtime/mcp-server') throw new TypeError('unsupported MCP stdio executable identity closure');
  return immutableSnapshot({ kind: 'runtime_bundle' as const, runtimeBundleRef: controlWireRef(data.runtimeBundleRef),
    executableId: controlWireText(data.executableId, 256), executionPath: '/runtime/mcp-server' as const, executableDigest: controlWireRef(data.executableDigest) });
}

export function mcpServerLaunchOperationId(runId: string, batchItemId: string, callIndex: number, callId: string,
  registryManifestDigest: string, lifecycleSeq: number) {
  controlWireText(runId); controlWireText(batchItemId); controlWireInteger(callIndex); controlWireText(callId);
  controlWireRef(registryManifestDigest); controlWireInteger(lifecycleSeq);
  return identityHash(runId, batchItemId, callIndex, callId, registryManifestDigest, lifecycleSeq);
}
function json(value: unknown) { assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP stdio data'); }
export function decodeMcpServerInstanceIdentity(value: unknown): McpServerInstanceIdentityV1 {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'batchItemId', 'callId', 'callIndex', 'registrationId',
    'registryRevisionRef', 'registryManifestDigest', 'lifecycleSeq', 'launchOpId', 'launchAttempt', 'launchDispatchId',
    'sandboxLaunchSpecRef', 'processContainmentRef', 'initializeDigest', 'capabilityDigest', 'probedToolsListDigest',
    'instanceNonceDigest', 'initializedAt', 'identityDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-server-instance-identity-v1') throw new TypeError('foreign MCP server identity');
  for (const member of ['runId', 'batchItemId', 'callId', 'registrationId', 'launchOpId', 'launchDispatchId']) controlWireText(data[member]);
  for (const member of ['registryRevisionRef', 'registryManifestDigest', 'sandboxLaunchSpecRef', 'processContainmentRef',
    'initializeDigest', 'capabilityDigest', 'probedToolsListDigest', 'instanceNonceDigest', 'identityDigest']) controlWireRef(data[member]);
  controlWireInteger(data.callIndex); controlWireInteger(data.lifecycleSeq); controlWireInteger(data.launchAttempt);
  parseCanonicalTime(data.initializedAt as string);
  if (data.launchOpId !== mcpServerLaunchOperationId(data.runId as string, data.batchItemId as string, data.callIndex as number,
    data.callId as string, data.registryManifestDigest as string, data.lifecycleSeq as number) || data.identityDigest !== digestOmitting(data, 'identityDigest'))
    throw new TypeError('MCP server identity changes its original call/lifecycle or digest');
  return immutableSnapshot(data) as McpServerInstanceIdentityV1;
}
export function decodeMcpServerLaunchReceipt(value: unknown): McpServerLaunchReceiptV1 {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'instanceIdentityRef', 'instanceIdentityDigest',
    'preparedJournalSeq', 'claimedJournalSeq', 'completedJournalSeq', 'budgetSettlementRef', 'stoppedItemId',
    'containmentDeathEvidenceRef', 'stoppedAt', 'receiptDigest', 'nativeClosure']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-server-launch-receipt-v1') throw new TypeError('foreign MCP launch receipt');
  for (const member of ['instanceIdentityRef', 'instanceIdentityDigest', 'budgetSettlementRef', 'containmentDeathEvidenceRef', 'receiptDigest']) controlWireRef(data[member]);
  controlWireText(data.stoppedItemId); parseCanonicalTime(data.stoppedAt as string);
  const native = controlWireRecord(data.nativeClosure, ['kind', 'lifecycleRawRef', 'lifecycleProjectionRef'], ['cleanupRawRef', 'cleanupProjectionRef']);
  if (native.kind === 'linux_original_join') controlWireRecord(native, ['kind', 'lifecycleRawRef', 'lifecycleProjectionRef']);
  else if (native.kind === 'linux_successor_cleanup') {
    controlWireRecord(native, ['kind', 'lifecycleRawRef', 'lifecycleProjectionRef', 'cleanupRawRef', 'cleanupProjectionRef']);
    controlWireRef(native.cleanupRawRef); controlWireRef(native.cleanupProjectionRef);
  } else throw new TypeError('MCP server receipt has no supported complete native closure');
  controlWireRef(native.lifecycleRawRef); controlWireRef(native.lifecycleProjectionRef);
  const prepared = controlWireInteger(data.preparedJournalSeq, 1), claimed = controlWireInteger(data.claimedJournalSeq, 1), completed = controlWireInteger(data.completedJournalSeq, 1);
  if (prepared >= claimed || claimed >= completed || data.receiptDigest !== digestOmitting(data, 'receiptDigest'))
    throw new TypeError('MCP launch receipt changes its original ordered Journal or digest');
  return immutableSnapshot(data) as McpServerLaunchReceiptV1;
}
export function decodeMcpServerStoppedItem(value: unknown): McpServerStoppedItem {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'itemId', 'runId', 'kind', 'batchItemId', 'callId', 'callIndex', 'serverManifestRef',
    'lifecycleSeq', 'launchOpId', 'instanceIdentityRef', 'instanceIdentityDigest', 'launchReceiptRef', 'launchReceiptDigest', 'cause', 'containmentEvidenceRef', 'createdAt']);
  if (data.schemaVersion !== 1 || data.kind !== 'mcp_server_stopped' ||
      !['normal', 'lease_release', 'crash', 'cancel', 'deadline', 'manifest_mismatch'].includes(data.cause as string)) throw new TypeError('foreign MCP stopped item');
  for (const member of ['itemId', 'runId', 'batchItemId', 'callId', 'launchOpId']) controlWireText(data[member]);
  for (const member of ['serverManifestRef', 'instanceIdentityRef', 'instanceIdentityDigest', 'launchReceiptRef', 'launchReceiptDigest', 'containmentEvidenceRef']) controlWireRef(data[member]);
  controlWireInteger(data.callIndex); controlWireInteger(data.lifecycleSeq); parseCanonicalTime(data.createdAt as string);
  return immutableSnapshot(data) as McpServerStoppedItem;
}
export function decodeMcpStdioCapture(value: unknown): McpStdioCaptureV1 {
  json(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'phase', 'expectedId', 'framing', 'termination', 'rawResponseRef',
    'rawFinitePrefixBytes', 'responseLineEndOffset', 'receivedTailBytes', 'captureDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-stdio-capture-v1' || data.framing !== 'newline_json_rpc' ||
      data.termination !== 'stdio_response_line' || !['initialize', 'tools_list', 'tools_call'].includes(data.phase as string))
    throw new TypeError('foreign MCP stdio capture');
  decodeMcpInboundMessageData({ jsonrpc: '2.0', id: data.expectedId, result: {} });
  controlWireRef(data.rawResponseRef); controlWireRef(data.captureDigest);
  const count = controlWireInteger(data.rawFinitePrefixBytes, 1, MCP_RESPONSE_BYTES), end = controlWireInteger(data.responseLineEndOffset, 1, count);
  if (controlWireInteger(data.receivedTailBytes, 0, count) !== count - end || data.captureDigest !== digestOmitting(data, 'captureDigest'))
    throw new TypeError('MCP stdio finite capture identity or tail differs');
  return immutableSnapshot(data) as McpStdioCaptureV1;
}

/** Offline finite capture only, after native NoEcho and actual final custody
 * join. A newline event never establishes process/stdout EOF or remote effect. */
export function decodeMcpStdioCaptureData(input: Readonly<{
  bytes: Uint8Array; termination: 'stdio_response_line'; expectedId: McpRpcId; maximumResponseBytes?: number;
}>) {
  const limit = controlWireInteger(input.maximumResponseBytes ?? MCP_RESPONSE_BYTES, 65_536, MCP_RESPONSE_BYTES);
  if (input.termination !== 'stdio_response_line' || types.isProxy(input.bytes) || !types.isUint8Array(input.bytes) ||
      !input.bytes.byteLength || input.bytes.byteLength > limit) throw new TypeError('invalid bounded MCP stdio capture');
  const expected = decodeMcpInboundMessageData({ jsonrpc: '2.0', id: input.expectedId, result: {} });
  if (expected.kind !== 'result') throw new TypeError('MCP stdio expected id is invalid');
  const bytes = Buffer.from(input.bytes), decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const messages: McpInboundMessageData[] = [];
  let start = 0, entries = 0, pings = 0;
  for (let offset = 0; offset < bytes.length; offset++) {
    if (bytes[offset] !== 10) continue;
    const value = parseJsonStrict(decoder.decode(bytes.subarray(start, offset))); start = offset + 1;
    entries += measureBoundedJsonValue(value, 'MCP stdio response').containerEntries;
    if (entries > MAX_JSON_CONTAINER_ENTRIES) throw new TypeError('MCP stdio response exceeds its aggregate JSON entry bound');
    const message = decodeMcpInboundMessageData(value);
    if (message.kind === 'ping' && ++pings > 8) throw new TypeError('MCP stdio response exceeds the owner ping bound');
    if (message.kind === 'result' || message.kind === 'error') {
      if (message.id !== expected.id) throw new TypeError('MCP stdio response differs from the original request id');
      return immutableSnapshot({ framing: 'newline_json_rpc' as const, termination: 'stdio_response_line' as const,
        rawFinitePrefixBytes: bytes.length, rawFinitePrefixDigest: sha256Bytes(bytes), responseLineEndOffset: start,
        receivedTailBytes: bytes.length - start, messagesBeforeResponse: messages, response: message });
    }
    messages.push(message);
  }
  throw new TypeError('MCP stdio capture has no complete matching response line');
}
