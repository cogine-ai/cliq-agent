import assert from 'node:assert/strict';
import test from 'node:test';

import { createToolRegistry } from './registry.js';

test('registry exposes model-visible tool schemas and maps structured tool calls back to actions', () => {
  const registry = createToolRegistry();

  const bashSpec = registry.modelVisibleToolSpecs().find((spec) => spec.name === 'bash');
  assert.equal(bashSpec?.description.includes('shell'), true);
  assert.equal(bashSpec?.inputSchema.properties?.command.type, 'string');

  assert.deepEqual(
    registry.resolveToolCall({
      id: 'call_1',
      name: 'bash',
      arguments: { command: 'pwd' }
    }).action,
    { bash: 'pwd' }
  );
});

test('registry rejects unknown structured tool names', () => {
  const registry = createToolRegistry();

  assert.throws(
    () =>
      registry.resolveToolCall({
        id: 'call_unknown',
        name: 'unknown',
        arguments: {}
      }),
    /No tool registered for structured tool call: unknown/
  );
});

test('registry rejects invalid structured tool arguments before dispatch', () => {
  const registry = createToolRegistry();

  for (const call of [
    { id: 'call_bash', name: 'bash', arguments: {} },
    { id: 'call_edit', name: 'edit', arguments: { path: 'a.ts', old_text: 'before' } },
    { id: 'call_find', name: 'find', arguments: { name: '' } },
    { id: 'call_grep', name: 'grep', arguments: { pattern: '' } },
    { id: 'call_read', name: 'read', arguments: { path: 'a.ts', start_line: 1.5 } },
    { id: 'call_skill', name: 'skill', arguments: { name: '' } }
  ]) {
    assert.throws(() => registry.resolveToolCall(call), /Invalid .* tool arguments/);
  }
});

test('registry exposes integer line range schema for read', () => {
  const registry = createToolRegistry();
  const readSpec = registry.modelVisibleToolSpecs().find((spec) => spec.name === 'read');

  assert.equal(readSpec?.inputSchema.properties?.start_line.type, 'integer');
  assert.equal(readSpec?.inputSchema.properties?.start_line.minimum, 1);
  assert.equal(readSpec?.inputSchema.properties?.end_line.type, 'integer');
  assert.equal(readSpec?.inputSchema.properties?.end_line.minimum, 1);
});
