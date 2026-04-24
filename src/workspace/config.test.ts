import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadWorkspaceConfig } from './config.js';

test('loadWorkspaceConfig returns empty defaults when config is missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-config-'));
  try {
    const first = await loadWorkspaceConfig(cwd);
    first.instructionFiles.push('mutated');

    assert.deepEqual(await loadWorkspaceConfig(cwd), {
      instructionFiles: [],
      extensions: [],
      defaultSkills: []
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadWorkspaceConfig validates array fields', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-config-invalid-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({ instructionFiles: 'bad', extensions: [], defaultSkills: [] }),
      'utf8'
    );

    await assert.rejects(() => loadWorkspaceConfig(cwd), /instructionFiles must be an array of strings/i);

    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({ instructionFiles: [], extensions: 'bad', defaultSkills: [] }),
      'utf8'
    );

    await assert.rejects(() => loadWorkspaceConfig(cwd), /extensions must be an array of strings/i);

    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({ instructionFiles: [], extensions: [], defaultSkills: 'bad' }),
      'utf8'
    );

    await assert.rejects(() => loadWorkspaceConfig(cwd), /defaultSkills must be an array of strings/i);

    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify([]),
      'utf8'
    );

    await assert.rejects(() => loadWorkspaceConfig(cwd), /workspace config must be a JSON object/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadWorkspaceConfig reads model config', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-model-config-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        model: {
          provider: 'ollama',
          model: 'qwen3:14b',
          baseUrl: 'http://localhost:11434',
          streaming: 'auto'
        }
      }),
      'utf8'
    );

    assert.deepEqual(await loadWorkspaceConfig(cwd), {
      instructionFiles: [],
      extensions: [],
      defaultSkills: [],
      model: {
        provider: 'ollama',
        model: 'qwen3:14b',
        baseUrl: 'http://localhost:11434',
        streaming: 'auto'
      }
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadWorkspaceConfig validates model config shape', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-model-config-invalid-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(path.join(cwd, '.cliq', 'config.json'), JSON.stringify({ model: 'bad' }), 'utf8');
    await assert.rejects(() => loadWorkspaceConfig(cwd), /model must be an object/i);

    await writeFile(path.join(cwd, '.cliq', 'config.json'), JSON.stringify({ model: { provider: 1 } }), 'utf8');
    await assert.rejects(() => loadWorkspaceConfig(cwd), /model.provider must be a string/i);

    await writeFile(path.join(cwd, '.cliq', 'config.json'), JSON.stringify({ model: { streaming: 'bad' } }), 'utf8');
    await assert.rejects(() => loadWorkspaceConfig(cwd), /model.streaming must be one of/i);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
