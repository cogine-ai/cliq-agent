import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { modelToolBatchItemId } from '../model/attempt.js';
import { toolOperationId } from '../policy/tool-policy.js';
import type { ObservedToolCallInputV1 } from '../protocol/agent-ir.js';
import { loadToolContracts, type ToolInputAuthority } from './input-contract.js';

const ref = (name: string) => canonicalSha256(name);
function authority(): ToolInputAuthority {
  const inputSchema = { type: 'object', additionalProperties: false, required: ['request', 'payload'], properties: {
    request: { type: 'object', additionalProperties: false, required: ['key'], properties: { key: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' } } },
    payload: { type: 'string' } } };
  return { name: 'mcp_effect', version: 'mcp-tool-contract-v1', description: 'exact frozen MCP tool', access: 'exec', replayClass: 'retry',
    inputSchema, inputSchemaRef: canonicalSha256(inputSchema), inputSchemaDigest: canonicalSha256(inputSchema),
    execution: { kind: 'mcp', registrationId: 'registration', registryRevisionRef: ref('registry'), registryManifestDigest: ref('manifest'),
      serverToolName: 'effect', toolContractDigest: ref('contract') }, mcpRecovery: { kind: 'retry', explicitRiskConsentRef: ref('consent'),
      explicitRiskConsentDigest: ref('consent-data'), safetyAssertionRef: ref('assertion'), safetyAssertionDigest: ref('assertion-data'),
      idempotencyKeyInjection: { jsonPointer: '/request/key' } } };
}
function observed(value: unknown): ObservedToolCallInputV1 {
  const core = { schemaVersion: 1 as const, format: 'cliq-observed-tool-call-input-v1' as const, encoding: 'jcs_json' as const,
    value, byteCount: canonicalJsonBytes(value).byteLength };
  return { ...core, observedInputDigest: canonicalSha256(core) };
}
test('MCP stable key is resolved into the original immutable input before request, policy projection and actual-wire audit', () => {
  const tool = authority(), resolver = loadToolContracts([tool]), raw = observed({ request: { key: 'model-untrusted-value' }, payload: 'exact payload' });
  const runId = 'run', batchItemId = modelToolBatchItemId(runId, 'model-operation', 0), callId = 'call', opId = toolOperationId(runId, batchItemId, callId);
  const key = identityHash('cliq-mcp-tool-idempotency-v1', runId, opId, ref('registry'), 'effect');
  const call = { runId, batchItemId, callId, index: 0, toolName: tool.name, observedInput: raw };
  const normalized = resolver.resolveToolInput(call);
  assert.equal(normalized.kind, 'resolved');
  if (normalized.kind !== 'resolved') throw new TypeError('expected a resolved exact MCP call');
  assert.equal(key.length, 43); assert.equal(Buffer.from(key, 'base64url').byteLength, 32);
  assert.deepEqual(normalized.value, { request: { key }, payload: 'exact payload' });
  assert.deepEqual(raw.value, { request: { key: 'model-untrusted-value' }, payload: 'exact payload' }, 'original model bytes are retained unchanged');
  const view = resolver.projectInvocation({ callId, index: 0, toolName: tool.name, input: normalized.value });
  assert.deepEqual(view.invocation.input, normalized.value);
  assert.equal(view.display.detail, canonicalJsonBytes(normalized.value).toString('utf8'));
  assert.equal(view.manifestEntryDigest, canonicalSha256((({ inputSchema: _schema, mcpRecovery: _normalization, ...entry }) => entry)(tool)));
  assert.deepEqual(resolver.resolveToolInput(call), normalized, 'historical re-normalization reproduces the original key and arguments');
  assert.equal(Object.isFrozen(normalized.value), true);
});
test('MCP input normalization refuses absent original identity/metadata and rejects invalid target before permission or I/O', () => {
  const tool = authority(), resolver = loadToolContracts([tool]), raw = observed({ request: {}, payload: 'value' });
  assert.throws(() => resolver.resolveToolInput({ callId: 'call', index: 0, toolName: tool.name, observedInput: raw }));
  const { mcpRecovery: _removed, ...missing } = tool;
  assert.throws(() => loadToolContracts([missing]));
  const invalid = resolver.resolveToolInput({ runId: 'run', batchItemId: modelToolBatchItemId('run', 'op', 0), callId: 'call', index: 0,
    toolName: tool.name, observedInput: observed({ payload: 'no parent object' }) });
  assert.equal(invalid.kind, 'invalid_input');
  if (invalid.kind !== 'invalid_input') throw new TypeError('expected fixed invalid-input diagnostic');
  assert.equal(Object.hasOwn(invalid, 'value'), false);
});
