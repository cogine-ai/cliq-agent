import assert from 'node:assert/strict';
import test from 'node:test';

import { buildInstructionMessages } from './builder.js';

test('buildInstructionMessages preserves deterministic layer order', async () => {
  const messages = await buildInstructionMessages({
    cwd: '/tmp/workspace',
    basePrompt: 'BASE',
    workspaceInstructions: ['WORKSPACE'],
    skills: [{ name: 'reviewer', prompt: 'SKILL' }],
    extensionMessages: [{ role: 'system', layer: 'extension', source: 'logger', content: 'EXTENSION' }]
  });

  assert.deepEqual(
    messages.map((message) => `${message.layer}:${message.source}:${message.content}`),
    [
      'core:base:BASE',
      'workspace:workspace:WORKSPACE',
      'skill:skill:reviewer:SKILL',
      'extension:logger:EXTENSION'
    ]
  );
});
