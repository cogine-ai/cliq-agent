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
