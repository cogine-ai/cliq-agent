// Pure received-data projection only. These values create no native receipt,
// process retirement, Run, StateOwner, authenticated query or effect outcome.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeMcpRecoveryPredicate } from '../kernel/mcp-recovery.js';
import { compileOutputSchema } from '../tools/input-schema.js';
import { projectMcpStatusResponse } from './mcp-status-protocol.js';

function predicate(value: string) {
  const core = { schemaVersion: 1, format: 'cliq-mcp-recovery-predicate-v1', expression: { op: 'equals', jsonPointer: '/state', value } };
  return decodeMcpRecoveryPredicate({ ...core, predicateDigest: canonicalSha256(core) });
}
const source = {
  validateOutput: compileOutputSchema({ type: 'object', properties: { state: { type: 'string', enum: ['completed', 'failed', 'waiting'] } },
    required: ['state'], additionalProperties: false }),
  completed: predicate('completed'), failed: predicate('failed'),
};
function result(structuredContent: Record<string, unknown>) {
  return { kind: 'result' as const, id: 3, result: { content: [], structuredContent } };
}

test('only schema-valid structured status with one matching predicate classifies a signed result', () => {
  for (const state of ['completed', 'failed', 'waiting']) {
    const original = result({ state }), before = structuredClone(original);
    const projected = projectMcpStatusResponse(original, source);
    assert.deepEqual(projected, { response: { state }, projection: 'structured_content', schemaValid: true,
      disposition: state === 'waiting' ? 'unresolved' : state });
    assert.deepEqual(original, before, 'projection never changes the original screened response');
  }
  assert.throws(() => projectMcpStatusResponse(result({ state: 'completed' }), { ...source, failed: source.completed }), /must be distinct/u);
  const exists = { schemaVersion: 1, format: 'cliq-mcp-recovery-predicate-v1', expression: { op: 'exists', jsonPointer: '/state' } };
  const overlapping = decodeMcpRecoveryPredicate({ ...exists, predicateDigest: canonicalSha256(exists) });
  const ambiguous = projectMcpStatusResponse(result({ state: 'completed' }), { ...source, failed: overlapping });
  assert.equal(ambiguous.schemaValid, true); assert.equal(ambiguous.disposition, 'unresolved');
  for (const structuredContent of [{ state: 'completed', extra: true }, { state: 'other' }, {}]) {
    const projected = projectMcpStatusResponse(result(structuredContent), source);
    assert.equal(projected.projection, 'structured_content'); assert.equal(projected.schemaValid, false);
    assert.equal(projected.disposition, 'unresolved'); assert.deepEqual(projected.response, structuredContent);
  }
});

test('RPC, tool, missing-structured and malformed errors preserve their actual data and never assert effect failure', () => {
  const rpc = { kind: 'error' as const, id: 3, error: { code: -32000, message: 'status unavailable', data: { state: 'failed' } } };
  assert.deepEqual(projectMcpStatusResponse(rpc, source), { response: rpc.error, projection: 'rpc_error', schemaValid: false, disposition: 'unresolved' });
  const cases = [
    { response: { ...result({ state: 'failed' }), result: { content: [], structuredContent: { state: 'failed' }, isError: true } }, projection: 'tool_error' },
    { response: { kind: 'result' as const, id: 3, result: { content: [{ type: 'text', text: '{"state":"completed"}' }] } }, projection: 'missing_structured_content' },
    { response: { kind: 'result' as const, id: 3, result: { content: 'invalid', structuredContent: { state: 'completed' } } }, projection: 'malformed_result' },
  ];
  for (const { response, projection } of cases) {
    const projected = projectMcpStatusResponse(response, source);
    assert.equal(projected.projection, projection); assert.equal(projected.schemaValid, false);
    assert.equal(projected.disposition, 'unresolved'); assert.deepEqual(projected.response, response.result);
  }
});
