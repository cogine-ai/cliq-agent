// Pure serialized protocol/lifecycle data. These values are not native
// receipts, process/death evidence, an admitted Run or installed qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { digestOmitting, sha256Bytes } from './identity.js';
import { decodeMcpServerInstanceIdentity, decodeMcpServerLaunchReceipt, decodeMcpStdioCapture, decodeMcpStdioCaptureData,
  mcpServerLaunchOperationId, type McpServerInstanceIdentityV1, type McpServerLaunchReceiptV1 } from './mcp-stdio.js';

const line = (value: unknown) => JSON.stringify(value) + '\n';
const response = { jsonrpc: '2.0', id: 1, result: { tools: [] } };
test('stdio completion is an actual matching newline event and preserves every received tail byte', () => {
  const prefix = line({ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } }) + line(response);
  const bytes = Buffer.concat([Buffer.from(prefix), Buffer.from([0xff, 0x00, 0x7b])]);
  const result = decodeMcpStdioCaptureData({ bytes, termination: 'stdio_response_line', expectedId: 1 });
  assert.equal(result.response.kind, 'result'); assert.equal(result.responseLineEndOffset, Buffer.byteLength(prefix));
  assert.equal(result.rawFinitePrefixBytes, bytes.length); assert.equal(result.rawFinitePrefixDigest, sha256Bytes(bytes));
  assert.equal(result.receivedTailBytes, 3); assert.equal(result.messagesBeforeResponse.length, 1);
  assert.equal(Object.hasOwn(result, 'eof'), false); assert.equal(Object.hasOwn(result, 'joined'), false);
  assert.throws(() => decodeMcpStdioCaptureData({ bytes: Buffer.from(JSON.stringify(response)), termination: 'stdio_response_line', expectedId: 1 }),
    'even valid JSON at EOF cannot invent the missing newline event');
  for (const termination of ['http_eof', 'sse_response_event']) assert.throws(() => decodeMcpStdioCaptureData({ bytes,
    termination: termination as never, expectedId: 1 }));
  assert.throws(() => decodeMcpStdioCaptureData({ bytes, termination: 'stdio_response_line', expectedId: '1' }));
  assert.throws(() => decodeMcpStdioCaptureData({ bytes: Buffer.from('\n' + line(response)), termination: 'stdio_response_line', expectedId: 1 }));
});

test('stdio reuses exact JSON decoding, aggregate entries, capacity and ping bounds across complete lines', () => {
  const decode = (bytes: Buffer) => decodeMcpStdioCaptureData({ bytes, termination: 'stdio_response_line', expectedId: 1 });
  assert.throws(() => decode(Buffer.from('{"jsonrpc":"2.0","id":1,"id":1,"result":{}}\n')));
  assert.throws(() => decode(Buffer.from(line({ jsonrpc: '2.0', id: 1, method: 'sampling/createMessage', params: {} }) + line(response))));
  const ping = line({ jsonrpc: '2.0', id: 'original-server-ping', method: 'ping' });
  assert.equal(decode(Buffer.from(ping.repeat(8) + line(response))).messagesBeforeResponse.length, 8);
  assert.throws(() => decode(Buffer.from(ping.repeat(9) + line(response))));
  const notification = line({ jsonrpc: '2.0', method: 'notifications/message', params: { data: Array(5000).fill(0) } });
  assert.throws(() => decode(Buffer.from(notification.repeat(2) + line(response))), 'a new line does not reset aggregate JSON accounting');
  assert.throws(() => decode(Buffer.alloc(1_048_577, 0x20)));
  let traps = 0;
  const proxy = new Proxy(Buffer.from(line(response)), { get() { traps++; throw 0; } });
  assert.throws(() => decode(proxy)); assert.equal(traps, 0);
});

function identity(): McpServerInstanceIdentityV1 {
  const ref = 'a'.repeat(64), value: McpServerInstanceIdentityV1 = {
    schemaVersion: 1, format: 'cliq-mcp-server-instance-identity-v1', runId: 'inert-run', batchItemId: 'inert-batch', callId: 'inert-call', callIndex: 0,
    registrationId: 'inert-registration', registryRevisionRef: ref, registryManifestDigest: ref, lifecycleSeq: 0,
    launchOpId: mcpServerLaunchOperationId('inert-run', 'inert-batch', 0, 'inert-call', ref, 0), launchAttempt: 0, launchDispatchId: 'inert-dispatch',
    sandboxLaunchSpecRef: ref, processContainmentRef: ref, initializeDigest: ref, capabilityDigest: ref, probedToolsListDigest: ref,
    instanceNonceDigest: ref, initializedAt: '2026-11-03T00:00:00.000Z', identityDigest: '' };
  return { ...value, identityDigest: digestOmitting(value, 'identityDigest') };
}
test('stdio lifecycle data pins the exact call tuple and requires complete separately rooted native closure data', () => {
  const original = identity(), ref = 'a'.repeat(64); assert.deepEqual(decodeMcpServerInstanceIdentity(original), original);
  const changed = { ...original, callId: 'foreign-call' }; changed.identityDigest = digestOmitting(changed, 'identityDigest');
  assert.throws(() => decodeMcpServerInstanceIdentity(changed));
  const receipt: McpServerLaunchReceiptV1 = { schemaVersion: 1, format: 'cliq-mcp-server-launch-receipt-v1', instanceIdentityRef: ref,
    instanceIdentityDigest: original.identityDigest, preparedJournalSeq: 1, claimedJournalSeq: 2, completedJournalSeq: 6,
    budgetSettlementRef: ref, stoppedItemId: 'inert-stopped', containmentDeathEvidenceRef: ref,
    stoppedAt: original.initializedAt, receiptDigest: '', nativeClosure: { kind: 'linux_original_join', lifecycleRawRef: ref, lifecycleProjectionRef: ref } };
  const seal = (value: Record<string, unknown>) => ({ ...value, receiptDigest: digestOmitting(value, 'receiptDigest') });
  assert.deepEqual(decodeMcpServerLaunchReceipt(seal(receipt)).nativeClosure, receipt.nativeClosure);
  const cleanup = { kind: 'linux_successor_cleanup', lifecycleRawRef: ref, lifecycleProjectionRef: ref,
    cleanupRawRef: 'b'.repeat(64), cleanupProjectionRef: 'c'.repeat(64) };
  assert.deepEqual(decodeMcpServerLaunchReceipt(seal({ ...receipt, nativeClosure: cleanup })).nativeClosure, cleanup);
  for (const nativeClosure of [undefined, { kind: 'linux_original_join' }, { ...cleanup, cleanupProjectionRef: undefined },
    { ...receipt.nativeClosure, cleanupRawRef: ref }, { ...receipt.nativeClosure, lifecycleRawDigest: ref }])
    assert.throws(() => decodeMcpServerLaunchReceipt(seal({ ...receipt, nativeClosure })));
  assert.throws(() => decodeMcpServerLaunchReceipt(seal({ ...receipt, completedJournalSeq: 2 })));
});

test('stdio capture metadata never borrows HTTP/SSE completion and binds exact finite tail arithmetic', () => {
  const bytes = Buffer.from(line(response)), core = { schemaVersion: 1, format: 'cliq-mcp-stdio-capture-v1', phase: 'tools_list', expectedId: 1,
    framing: 'newline_json_rpc', termination: 'stdio_response_line', rawResponseRef: sha256Bytes(bytes), rawFinitePrefixBytes: bytes.length,
    responseLineEndOffset: bytes.length, receivedTailBytes: 0, captureDigest: '' };
  const seal = (value: Record<string, unknown>) => ({ ...value, captureDigest: digestOmitting(value, 'captureDigest') });
  assert.deepEqual(decodeMcpStdioCapture(seal(core)), seal(core));
  for (const changed of [{ termination: 'http_eof' }, { framing: 'sse' }, { receivedTailBytes: 1 }, { responseLineEndOffset: 0 }])
    assert.throws(() => decodeMcpStdioCapture(seal({ ...core, ...changed })));
});
