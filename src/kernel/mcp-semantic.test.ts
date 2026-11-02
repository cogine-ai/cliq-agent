import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalSha256 } from './canonical.js';
import { decodeMcpInitializeResult, decodeMcpToolsListResult, decodeMcpCallResult,
  decodeToolAbandonedItem, MCP_PROTOCOL_VERSION } from './mcp.js';
import { mcpExposedToolName, mcpExposedToolDescription, mcpNoReleaseCheckpointId, decodeMcpKnownUnusableResponse, decodeMcpHttpCapture } from './mcp.js';
import { identityHash } from './identity.js';
import { decodeBrokerInvocationAmbiguity } from './broker-ambiguity.js';

test('provider-safe qualified names retain the full original identity without truncation collisions', () => {
  const names = [['registration', 'tool'], ['r'.repeat(128), 'x'.repeat(128)], ['工作区', '工具'], ['same-prefix:a', 'x'], ['same-prefix:b', 'x']];
  const exposed = names.map(([registration, tool]) => mcpExposedToolName(registration!, tool!));
  assert.equal(new Set(exposed).size, names.length);
  for (const name of exposed) assert.match(name, /^[A-Za-z0-9_-]{44,64}$/u);
  assert.equal(mcpExposedToolName('工作区', '工具'), mcpExposedToolName('工作区', '工具'));
  assert.notEqual(mcpExposedToolName('a:b', 'c'), mcpExposedToolName('a', 'b:c'));
  const description = mcpExposedToolDescription('工作区', '工具', 'description');
  assert.match(description, /工作区/u); assert.match(description, /工具/u); assert.match(description, /description/u);
});
test('MCP no-I/O ready checkpoint has one shared numeric original attempt identity', () => {
  assert.equal(mcpNoReleaseCheckpointId('run', 'op', 0), identityHash('cliq-mcp-no-release-checkpoint-v1', 'run', 'op', 0));
  assert.notEqual(mcpNoReleaseCheckpointId('run', 'op', 0), identityHash('cliq-mcp-no-release-checkpoint-v1', 'run', 'op', '0'));
  assert.equal(new Set([mcpNoReleaseCheckpointId('run', 'op', 0), mcpNoReleaseCheckpointId('run', 'op', 1),
    mcpNoReleaseCheckpointId('other-run', 'op', 0), mcpNoReleaseCheckpointId('run', 'other-op', 0)]).size, 4);
  assert.throws(() => mcpNoReleaseCheckpointId('run', 'op', -1));
});

test('initialize capabilities are projections of one actual result, with no downgrade', () => {
  const received = { protocolVersion: MCP_PROTOCOL_VERSION, serverInfo: { name: 'fixture', version: '1' }, capabilities: { tools: { listChanged: true } } };
  const projected = decodeMcpInitializeResult(received);
  assert.equal(projected.initializeDigest, canonicalSha256(received));
  assert.equal(projected.capabilityDigest, canonicalSha256(received.capabilities));
  assert.throws(() => decodeMcpInitializeResult({ ...received, protocolVersion: '2025-03-26' }));
  assert.throws(() => decodeMcpInitializeResult({ ...received, capabilities: {} }));
});
test('tools discovery compiles finite schemas and preserves exact sorted interface identity', () => {
  const schema = { type: 'object', properties: { input: { type: 'string' } }, required: ['input'], additionalProperties: false };
  const tools = decodeMcpToolsListResult({ tools: [{ name: 'z', inputSchema: schema }, { name: 'a', inputSchema: schema, annotations: { readOnlyHint: true } }] });
  assert.deepEqual(tools.map(item => item.interface.name), ['a', 'z']);
  assert.equal(tools[0]!.interface.access, 'exec');
  assert.equal(tools[0]!.interface.inputSchemaRef, canonicalSha256(schema));
  assert.throws(() => decodeMcpToolsListResult({ tools: [{ name: 'x', inputSchema: schema }], nextCursor: '' }));
  assert.throws(() => decodeMcpToolsListResult({ tools: [{ name: 'x', inputSchema: schema }, { name: 'x', inputSchema: schema }] }));
  assert.throws(() => decodeMcpToolsListResult({ tools: [{ name: 'x', inputSchema: { type: 'object', $ref: 'https://example.invalid/schema' } }] }));
});
test('received isError remains typed result data and cannot bypass malformed content', () => {
  assert.deepEqual(decodeMcpCallResult({ content: [{ type: 'text', text: 'failed' }], isError: true }),
    { kind: 'tool_result', content: [{ type: 'text', text: 'failed' }], isError: true });
  assert.throws(() => decodeMcpCallResult({ content: [{ type: 'image', mimeType: 'image/png', data: 'invalid%' }], isError: true }));
  assert.throws(() => decodeMcpCallResult({ content: [], isError: 'true' }));
});
test('frozen output schema validates structuredContent and never executes or follows links', () => {
  const schema = { type: 'object', properties: { ok: { const: true } }, required: ['ok'], additionalProperties: false };
  assert.equal(decodeMcpCallResult({ content: [], structuredContent: { ok: true } }, schema).kind, 'tool_result');
  assert.throws(() => decodeMcpCallResult({ content: [], structuredContent: { ok: false } }, schema));
  assert.throws(() => decodeMcpCallResult({ content: [{ type: 'resource_link', uri: 'https://example.invalid/a', name: 'a' }] }, schema));
  assert.equal(decodeMcpCallResult({ content: [], isError: true }, schema).kind, 'tool_result');
});
test('abandoned audit marker is exact, terminal-only data and has no tool success outcome', () => {
  const item = { schemaVersion: 1, itemId: 'item', runId: 'run', kind: 'tool_abandoned', batchItemId: 'batch', callId: 'call',
    index: 0, opId: 'op', attempt: 0, abandonedJournalSeq: 4, attestationRef: 'a'.repeat(64), createdAt: '2026-11-03T00:00:00.000Z' };
  assert.deepEqual(decodeToolAbandonedItem(item), item);
  assert.throws(() => decodeToolAbandonedItem({ ...item, outcome: 'executed' }));
  assert.throws(() => decodeToolAbandonedItem({ ...item, abandonedJournalSeq: 0 }));
});
test('known-unusable native audit cannot masquerade as an ordinary retained complete capture', () => {
  const core = { schemaVersion: 1, format: 'cliq-mcp-known-unusable-response-v1', phase: 'tools_call', expectedId: 3,
    safeMessageRef: 'a'.repeat(64), safeMessageDigest: 'a'.repeat(64), safeMessageBytes: 40, mediaType: 'text/event-stream',
    termination: 'sse_response_event', rawFinitePrefixBytes: 120, rawFinitePrefixDigest: 'b'.repeat(64),
    responseEventEndOffset: 100, receivedTailBytes: 20, reason: 'full_capture_no_echo_refused' };
  const audit = { ...core, auditDigest: canonicalSha256(core) };
  assert.deepEqual(decodeMcpKnownUnusableResponse(audit), audit);
  assert.throws(() => decodeMcpHttpCapture(audit));
  for (const mutation of [{ rawResponseRef: 'b'.repeat(64) }, { reason: 'network_failed' }, { phase: 'initialize' },
    { receivedTailBytes: 21 }, { safeMessageDigest: 'c'.repeat(64) }, { safeMessageBytes: 0 }]) {
    const changed = { ...core, ...mutation }; assert.throws(() => decodeMcpKnownUnusableResponse({ ...changed, auditDigest: canonicalSha256(changed) }));
  }
  const beforeEvent = { ...core, responseEventEndOffset: 120, receivedTailBytes: 0 };
  assert.equal(decodeMcpKnownUnusableResponse({ ...beforeEvent, auditDigest: canonicalSha256(beforeEvent) }).receivedTailBytes, 0);
});
test('successor creator-death ambiguity requires an exact paired MCP-purpose audit', () => {
  const core = { schemaVersion: 1, format: 'cliq-invocation-ambiguity-evidence-v1', runId: 'run', opId: 'op', opKind: 'mcp',
    frontierRef: 'a'.repeat(64), frontierDigest: 'a'.repeat(64), attempt: 0, dispatchId: 'dispatch', dispatchJournalSeq: 2,
    operationRequestRef: 'b'.repeat(64), operationRequestDigest: 'c'.repeat(64), operationTargetRef: 'd'.repeat(64), operationTargetDigest: 'e'.repeat(64),
    claimingSupervisorInstanceId: 'original', claimingStateOwnerEpoch: 1, inspectorIdentityRef: 'f'.repeat(64), inspectorIdentityDigest: '1'.repeat(64),
    observedAt: '2026-11-03T00:00:00.000Z', ambiguityKind: 'broker_channel_lost_after_claim', brokerFenceTokenDigest: '2'.repeat(64),
    failureCode: 'response_stream_interrupted', durableTerminalResultAbsent: true, creatorProcessDeathEvidenceRef: '3'.repeat(64), creatorProcessDeathEvidenceDigest: '4'.repeat(64) };
  assert.equal(decodeBrokerInvocationAmbiguity({ ...core, evidenceDigest: canonicalSha256(core) }).opKind, 'mcp');
  for (const mutation of [{ opKind: 'model' }, { creatorProcessDeathEvidenceDigest: undefined }]) {
    const changed = { ...core, ...mutation }; assert.throws(() => decodeBrokerInvocationAmbiguity({ ...changed, evidenceDigest: canonicalSha256(changed) }));
  }
});
