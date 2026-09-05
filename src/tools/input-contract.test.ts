import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ObservedToolCallInputV1 } from '../protocol/agent-ir.js';
import { createToolInputResolver } from './input-contract.js';

function tool<T>(inputSchema: T) {
  const ref = canonicalSha256(inputSchema);
  return { name: 'read', description: 'Read a file', inputSchema, inputSchemaRef: ref, inputSchemaDigest: ref, replayClass: 'retry' as const };
}
function observed(value: unknown): ObservedToolCallInputV1 {
  return { schemaVersion: 1, format: 'cliq-observed-tool-call-input-v1', encoding: 'jcs_json', value,
    byteCount: 0, observedInputDigest: '' }; // The compiler owns observation identity, not the schema validator.
}
const schema = { type: 'object', required: ['path'], additionalProperties: false,
  properties: { path: { type: 'string' }, start: { type: 'integer', minimum: 1 } } };
const call = { callId: 'c', index: 0, toolName: 'read' };

test('frozen tool schemas validate typed values directly and retain an immutable normalized input', () => {
  const contract = tool(structuredClone(schema));
  const resolve = createToolInputResolver([contract]);
  contract.inputSchema.properties.path.type = 'number';
  const input = { path: 'a.ts', start: 2 };
  const resolved = resolve({ ...call, observedInput: observed(input) });
  assert.equal(resolved.kind, 'resolved');
  if (resolved.kind !== 'resolved') return;
  input.path = 'changed';
  assert.deepEqual(resolved.value, { path: 'a.ts', start: 2 });
  assert.equal(Object.isFrozen(resolved.value), true);
  for (const value of [{ path: 3 }, { path: 'a', start: '2' }, { path: 'a', start: 0 }, { path: 'a', extra: true }, {}, []]) {
    assert.equal(resolve({ ...call, observedInput: observed(value) }).kind, 'invalid_input');
  }
});

test('unknown tools and malformed arguments produce bounded deterministic diagnostics without copying arguments', () => {
  const resolve = createToolInputResolver([tool(schema)]);
  const malformed: ObservedToolCallInputV1 = { schemaVersion: 1, format: 'cliq-observed-tool-call-input-v1',
    encoding: 'utf8_json_fragment', utf8: '{secret', byteCount: 7, observedInputDigest: '' };
  const invalid = resolve({ ...call, observedInput: malformed });
  assert.equal(invalid.kind, 'invalid_input');
  if (invalid.kind !== 'invalid_input') return;
  assert.doesNotMatch(Buffer.from(invalid.diagnostic.bytes).toString(), /secret/);
  assert.deepEqual(resolve({ ...call, observedInput: malformed }), invalid);
  assert.equal(resolve({ ...call, toolName: 'bash', observedInput: observed({}) }).kind, 'unknown_tool');
  assert.throws(() => resolve({ ...call, observedInput: observed({ path: Infinity }) }), /non-finite/);
});

test('schema loading fails closed on changed identities, unresolved references, unknown keywords and async contracts', () => {
  assert.throws(() => createToolInputResolver([{ ...tool(schema), inputSchema: {} }]), /frozen reference/);
  assert.throws(() => createToolInputResolver([tool(schema), tool(schema)]), /unique/);
  for (const value of [{ $ref: 'https://example.invalid/schema' }, { type: 'object', unknownKeyword: true },
    { $async: true, type: 'object' }]) assert.throws(() => createToolInputResolver([tool(value)]));
  const resolve = createToolInputResolver([tool({ type: 'object', properties: { path: { type: 'string', default: 'unsafe' } } })]);
  const input = {};
  assert.equal(resolve({ ...call, observedInput: observed(input) }).kind, 'resolved');
  assert.deepEqual(input, {});
});
