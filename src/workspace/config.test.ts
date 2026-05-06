import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadWorkspaceConfig, parseWorkspaceConfig } from './config.js';

test('loadWorkspaceConfig returns empty defaults when config is missing', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-config-'));
  try {
    const first = await loadWorkspaceConfig(cwd);
    first.instructionFiles.push('mutated');

    assert.deepEqual(await loadWorkspaceConfig(cwd), {
      instructionFiles: [],
      extensions: [],
      defaultSkills: [],
      autoCompact: {}
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
      autoCompact: {},
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

test('loadWorkspaceConfig reads autoCompact config', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-workspace-auto-compact-'));
  try {
    await mkdir(path.join(cwd, '.cliq'), { recursive: true });
    await writeFile(
      path.join(cwd, '.cliq', 'config.json'),
      JSON.stringify({
        autoCompact: {
          enabled: 'on',
          contextWindowTokens: 128000,
          thresholdRatio: 0.75,
          reserveTokens: 12000,
          keepRecentTokens: 16000,
          minNewTokens: 3000,
          maxThresholdCompactionsPerTurn: 2,
          maxOverflowRetriesPerModelCall: 1
        }
      }),
      'utf8'
    );

    assert.deepEqual((await loadWorkspaceConfig(cwd)).autoCompact, {
      enabled: 'on',
      contextWindowTokens: 128000,
      thresholdRatio: 0.75,
      reserveTokens: 12000,
      keepRecentTokens: 16000,
      minNewTokens: 3000,
      maxThresholdCompactionsPerTurn: 2,
      maxOverflowRetriesPerModelCall: 1
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('parseWorkspaceConfig accepts transactions block with full settings', () => {
  const parsed = parseWorkspaceConfig({
    transactions: {
      mode: 'edit',
      auto: 'per-turn',
      applyPolicy: 'interactive',
      bashPolicy: 'passthrough',
      stagedView: { copyMode: 'auto', bindPaths: ['node_modules'] },
      validators: {
        shell: [
          { name: 'tsc', command: 'npm run typecheck', severity: 'blocking', timeoutMs: 60000 }
        ],
        disabled: [],
        serial: false
      },
      abortRetention: '7d'
    }
  });
  assert.equal(parsed.transactions?.mode, 'edit');
  assert.equal(parsed.transactions?.auto, 'per-turn');
  assert.equal(parsed.transactions?.applyPolicy, 'interactive');
  assert.equal(parsed.transactions?.bashPolicy, 'passthrough');
  assert.equal(parsed.transactions?.stagedView?.copyMode, 'auto');
  assert.deepEqual(parsed.transactions?.stagedView?.bindPaths, ['node_modules']);
  assert.equal(parsed.transactions?.validators?.shell?.[0].name, 'tsc');
  assert.equal(parsed.transactions?.validators?.shell?.[0].command, 'npm run typecheck');
  assert.equal(parsed.transactions?.validators?.shell?.[0].severity, 'blocking');
  assert.equal(parsed.transactions?.validators?.shell?.[0].timeoutMs, 60000);
  assert.equal(parsed.transactions?.validators?.serial, false);
  assert.equal(parsed.transactions?.abortRetention, '7d');
});

test('parseWorkspaceConfig leaves transactions undefined when block is absent', () => {
  const parsed = parseWorkspaceConfig({});
  assert.equal(parsed.transactions, undefined);
});

test('parseWorkspaceConfig rejects invalid transactions.mode', () => {
  assert.throws(
    () => parseWorkspaceConfig({ transactions: { mode: 'worktree' } }),
    /transactions\.mode/
  );
});

test('parseWorkspaceConfig rejects invalid transactions.bashPolicy', () => {
  assert.throws(
    () => parseWorkspaceConfig({ transactions: { bashPolicy: 'sandbox' } }),
    /transactions\.bashPolicy/
  );
});

test('parseWorkspaceConfig rejects invalid stagedView.copyMode', () => {
  assert.throws(
    () => parseWorkspaceConfig({ transactions: { stagedView: { copyMode: 'fast' } } }),
    /transactions\.stagedView\.copyMode/
  );
});

test('parseWorkspaceConfig rejects non-object transactions block', () => {
  assert.throws(
    () => parseWorkspaceConfig({ transactions: 'edit' }),
    /transactions must be an object/
  );
});

test('parseWorkspaceConfig rejects null transactions block', () => {
  assert.throws(
    () => parseWorkspaceConfig({ transactions: null }),
    /transactions must be an object/
  );
});

test('parseWorkspaceConfig rejects array transactions block', () => {
  assert.throws(
    () => parseWorkspaceConfig({ transactions: [] }),
    /transactions must be an object/
  );
});

test('parseWorkspaceConfig rejects validators.shell entry with non-string name', () => {
  assert.throws(
    () => parseWorkspaceConfig({
      transactions: { validators: { shell: [{ name: 42, command: 'x', severity: 'blocking' }] } }
    }),
    /transactions\.validators\.shell/
  );
});
