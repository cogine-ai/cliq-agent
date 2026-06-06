import assert from 'node:assert/strict';
import test from 'node:test';

import type { ModelAction } from '../protocol/model/actions.js';
import { createToolRegistry } from './registry.js';
import type { ToolDefinition } from './types.js';

test('createToolRegistry resolves the matching tool by action shape', () => {
  const registry = createToolRegistry();

  assert.equal(registry.resolve({ read: { path: 'src/cli.ts' } }).definition.name, 'read');
  assert.equal(registry.resolve({ bash: 'git status' }).definition.name, 'bash');
});

test('createToolRegistry throws when no tool supports the action', () => {
  const stub: ToolDefinition = {
    name: 'stub',
    access: 'read',
    supports(_action: ModelAction): _action is ModelAction {
      return false;
    },
    execute: async () => ({ tool: 'stub', status: 'ok', content: '', meta: {} })
  };
  const registry = createToolRegistry([stub]);

  assert.throws(
    () => registry.resolve({ read: { path: 'missing.ts' } }),
    /No tool registered for action/
  );
});
