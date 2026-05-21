import assert from 'node:assert/strict';
import test from 'node:test';

import { buildInstructionMessages } from './builder.js';

test('buildInstructionMessages preserves deterministic layer order', async () => {
  const messages = await buildInstructionMessages({
    cwd: '/tmp/workspace',
    basePrompt: 'BASE',
    workspaceInstructions: ['WORKSPACE'],
    skills: [{ name: 'reviewer', skillDir: '/tmp/workspace/.cliq/skills/reviewer', prompt: 'SKILL' }],
    extensionMessages: [{ role: 'system', layer: 'extension', source: 'logger', content: 'EXTENSION' }]
  });

  assert.deepEqual(
    messages.map((message) => `${message.layer}:${message.source}:${message.content}`),
    [
      'core:base:BASE',
      'workspace:workspace:WORKSPACE',
      'skill:skill:reviewer:Skill directory: /tmp/workspace/.cliq/skills/reviewer\nBundled resources and scripts are relative to this directory. Use absolute paths when running bundled scripts with bash.\n\nSKILL',
      'extension:logger:EXTENSION'
    ]
  );
});
