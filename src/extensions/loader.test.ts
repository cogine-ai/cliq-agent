import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadExtensions } from './loader.js';

test('loadExtensions resolves built-in extension aliases', async () => {
  const loaded = await loadExtensions('/tmp/workspace', ['builtin:policy-instructions']);
  assert.equal(loaded[0]?.name, 'policy-instructions');
});

test('loadExtensions resolves workspace-relative extension modules', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-extension-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
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

    const loaded = await loadExtensions(cwd, ['./.cliq/extensions/echo.js']);
    assert.equal(loaded[0]?.name, 'echo');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadExtensions rejects duplicate extension names', async () => {
  await assert.rejects(
    () => loadExtensions('/tmp/workspace', ['builtin:policy-instructions', 'builtin:policy-instructions']),
    /duplicate extension name/i
  );
});

test('loadExtensions reports the failing specifier on import failure', async () => {
  await assert.rejects(
    () => loadExtensions('/tmp/workspace', ['./.cliq/extensions/missing.js']),
    /missing\.js/i
  );
});

test('loadExtensions rejects invalid instructionSources values', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-extension-invalid-sources-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'broken.js'),
      `export default {
        name: 'broken',
        instructionSources: 'nope',
        hooks: []
      };`,
      'utf8'
    );

    await assert.rejects(
      () => loadExtensions(cwd, ['./.cliq/extensions/broken.js']),
      /invalid instructionSources, expected array/i
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('loadExtensions rejects invalid hooks values', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-extension-invalid-hooks-'));
  try {
    await mkdir(path.join(cwd, '.cliq', 'extensions'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'extensions', 'broken.js'),
      `export default {
        name: 'broken',
        instructionSources: [],
        hooks: {}
      };`,
      'utf8'
    );

    await assert.rejects(
      () => loadExtensions(cwd, ['./.cliq/extensions/broken.js']),
      /invalid hooks, expected array/i
    );
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
