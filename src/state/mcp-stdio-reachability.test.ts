// Ordinary closed-data tests only. No native image is loaded and no process,
// SQLite row, signed runtime, cleanup or receipt authority is constructed.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import { readMcpStdioArtifactEdges, UnsupportedMcpStdioReachability } from './mcp-stdio-reachability.js';

const ref = canonicalSha256, at = '2026-11-01T00:00:00.000Z';
test('manual wait follows its frontier and never treats operation identifiers as CAS references', () => {
  const frontierRef = ref('frontier'), opId = ref('hash-shaped operation id');
  const edges = readMcpStdioArtifactEdges('mcp.stdio.manual_wait', { schemaVersion: 1, kind: 'reconciliation', runId: ref('hash-shaped run id'),
    createdFromRevision: 3, createdAt: at, frontierRef, subject: { kind: 'invocation', recovery: 'manual', opKind: 'mcp', opId, attempt: 0 },
    probeState: { phase: 'manual_only', automaticProbeCount: 0, userProbeCount: 0 } });
  assert.deepEqual(edges, [{ ref: frontierRef, purpose: 'run_frontier' }]); assert(Object.isFrozen(edges));
  assert(!edges.some(edge => edge.ref === opId));
});
test('closed native closure receipts retain independent original and current cleanup roots', () => {
  const core = { schemaVersion: 1, format: 'cliq-mcp-server-launch-receipt-v1', instanceIdentityRef: ref('instance'), instanceIdentityDigest: ref('omission instance digest'),
    preparedJournalSeq: 4, claimedJournalSeq: 5, completedJournalSeq: 9, budgetSettlementRef: ref('settlement'), stoppedItemId: ref('hash-shaped stopped id'),
    containmentDeathEvidenceRef: ref('death'), stoppedAt: at, nativeClosure: { kind: 'linux_successor_cleanup', lifecycleRawRef: ref('old raw'),
      lifecycleProjectionRef: ref('old projection'), cleanupRawRef: ref('current raw'), cleanupProjectionRef: ref('current projection') } };
  const edges = readMcpStdioArtifactEdges('mcp.stdio.launch_receipt', { ...core, receiptDigest: ref(core) });
  assert.deepEqual(edges.filter(edge => edge.purpose.startsWith('mcp.stdio.native_')), [
    { ref: ref('old raw'), purpose: 'mcp.stdio.native_launch_raw' }, { ref: ref('old projection'), purpose: 'mcp.stdio.native_launch_projection' },
    { ref: ref('current raw'), purpose: 'mcp.stdio.native_cleanup_raw' }, { ref: ref('current projection'), purpose: 'mcp.stdio.native_cleanup_projection' }]);
  assert(!edges.some(edge => edge.ref === core.stoppedItemId || edge.ref === core.instanceIdentityDigest));
  const { cleanupProjectionRef: _missing, ...partial } = core.nativeClosure;
  const incomplete = { ...core, nativeClosure: partial };
  assert.throws(() => readMcpStdioArtifactEdges('mcp.stdio.launch_receipt', { ...incomplete, receiptDigest: ref(incomplete) }));
});
test('finite newline captures retain the original opaque raw tail and reject mismatched paired bytes', () => {
  const line = Buffer.from('{"jsonrpc":"2.0","id":3,"result":{"content":[]}}\n'), raw = Buffer.concat([line, Buffer.from([0xff, 0x80])]);
  const core = { schemaVersion: 1, format: 'cliq-mcp-stdio-capture-v1', phase: 'tools_call', expectedId: 3, framing: 'newline_json_rpc',
    termination: 'stdio_response_line', rawResponseRef: sha256Bytes(raw), rawFinitePrefixBytes: raw.length,
    responseLineEndOffset: line.length, receivedTailBytes: 2 };
  const value = { ...core, captureDigest: ref(core) };
  assert.deepEqual(readMcpStdioArtifactEdges('mcp.stdio.capture', value, { kind: 'capture', rawBytes: raw }), [{ ref: sha256Bytes(raw), purpose: 'opaque_blob' }]);
  assert.throws(() => readMcpStdioArtifactEdges('mcp.stdio.capture', value), UnsupportedMcpStdioReachability);
  assert.throws(() => readMcpStdioArtifactEdges('mcp.stdio.capture', value, { kind: 'capture', rawBytes: line }));
});
test('known-unusable audit follows screened bytes and never follows omitted unsafe raw digest or user result keys', () => {
  const fakeRef = ref('arbitrary user result data'), safeMessageBytes = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 3, result: { content: [], fakeRef } }));
  const omitted = ref('omitted unsafe finite bytes'), core = { schemaVersion: 1, format: 'cliq-mcp-stdio-known-unusable-response-v1', phase: 'tools_call',
    expectedId: 3, safeMessageRef: sha256Bytes(safeMessageBytes), safeMessageDigest: sha256Bytes(safeMessageBytes), safeMessageBytes: safeMessageBytes.length,
    framing: 'newline_json_rpc', termination: 'stdio_response_line', rawFinitePrefixBytes: safeMessageBytes.length + 8,
    rawFinitePrefixDigest: omitted, responseLineEndOffset: safeMessageBytes.length + 1, receivedTailBytes: 7, reason: 'full_capture_no_echo_refused' };
  const value = { ...core, auditDigest: ref(core) }, edges = readMcpStdioArtifactEdges('mcp.stdio.unusable_response', value, { kind: 'unusable_response', safeMessageBytes });
  assert.deepEqual(edges, [{ ref: sha256Bytes(safeMessageBytes), purpose: 'opaque_blob' }]);
  assert(!edges.some(edge => edge.ref === omitted || edge.ref === fakeRef));
  assert.throws(() => readMcpStdioArtifactEdges('mcp.stdio.unusable_response', value), UnsupportedMcpStdioReachability);
});
test('native projections require the paired original binary context before any native decoder can be used', () => {
  assert.throws(() => readMcpStdioArtifactEdges('mcp.stdio.native_launch_projection', {}), UnsupportedMcpStdioReachability);
  assert.throws(() => readMcpStdioArtifactEdges('mcp.stdio.native_cleanup_projection', {}), UnsupportedMcpStdioReachability);
});
