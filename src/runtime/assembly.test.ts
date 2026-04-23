import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createRuntimeAssembly } from './assembly.js';
import { createSession } from '../session/store.js';

test('createRuntimeAssembly merges config skills, CLI skills, and extension instructions', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-assembly-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'skills', 'reviewer'), { recursive: true });
    await mkdir(path.join(cwd, '.cliq', 'skills', 'safe-edit'), { recursive: true });
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        instructionFiles: ['.cliq/instructions.md'],
        extensions: ['builtin:policy-instructions', './.cliq/extensions/echo.js'],
        defaultSkills: ['reviewer']
      }),
      'utf8'
    );
    await writeFile(path.join(cwd, '.cliq', 'instructions.md'), 'Workspace instruction file.', 'utf8');
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'reviewer', 'SKILL.md'),
      `---
name: reviewer
---

Review before editing.`,
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'skills', 'safe-edit', 'SKILL.md'),
      `---
name: safe-edit
---

Prefer exact edits over shell mutation when possible.`,
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'echo.js'),
      `export default {
        name: 'echo',
        instructionSources: [
          async () => [{ role: 'system', layer: 'extension', source: 'echo', content: 'EXTENSION ECHO' }]
        ],
        hooks: []
      };`,
      'utf8'
    );

    const assembly = await createRuntimeAssembly({
      cwd,
      session: createSession(cwd),
      policyMode: 'read-only',
      cliSkillNames: ['safe-edit']
    });

    const messages = await assembly.instructions(assembly.session);

    assert.deepEqual(assembly.skillNames, ['reviewer', 'safe-edit']);
    assert.equal(assembly.extensionNames.includes('policy-instructions'), true);
    assert.equal(messages.some((message) => message.layer === 'workspace'), true);
    assert.equal(messages.some((message) => message.source === 'echo'), true);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createRuntimeAssembly surfaces extension instruction source failures clearly', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-assembly-fail-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        extensions: ['./.cliq/extensions/broken.js']
      }),
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'broken.js'),
      `export default {
        name: 'broken',
        instructionSources: [async () => { throw new Error('instruction source exploded'); }],
        hooks: []
      };`,
      'utf8'
    );

    const assembly = await createRuntimeAssembly({
      cwd,
      session: createSession(cwd),
      policyMode: 'auto',
      cliSkillNames: []
    });

    await assert.rejects(
      () => assembly.instructions(assembly.session),
      /Extension broken instruction source failed: instruction source exploded/i
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createRuntimeAssembly rejects extension instruction sources that return non-arrays', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-assembly-invalid-array-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        extensions: ['./.cliq/extensions/broken.js']
      }),
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'broken.js'),
      `export default {
        name: 'broken',
        instructionSources: [async () => 'not-an-array'],
        hooks: []
      };`,
      'utf8'
    );

    const assembly = await createRuntimeAssembly({
      cwd,
      session: createSession(cwd),
      policyMode: 'auto',
      cliSkillNames: []
    });

    await assert.rejects(
      () => assembly.instructions(assembly.session),
      /Extension broken instruction source failed: Extension broken instruction source returned invalid value, expected array/i
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createRuntimeAssembly rejects extension instruction sources that return invalid messages', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-assembly-invalid-message-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        extensions: ['./.cliq/extensions/broken.js']
      }),
      'utf8'
    );
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'broken.js'),
      `export default {
        name: 'broken',
        instructionSources: [async () => [{ role: 'user', content: 'bad' }]],
        hooks: []
      };`,
      'utf8'
    );

    const assembly = await createRuntimeAssembly({
      cwd,
      session: createSession(cwd),
      policyMode: 'auto',
      cliSkillNames: []
    });

    await assert.rejects(
      () => assembly.instructions(assembly.session),
      /Extension broken instruction source failed: Extension broken instruction source returned invalid message at index 0/i
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
