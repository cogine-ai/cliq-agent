import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { appendBashEffect, readBashEffects, bashEffectsPath } from './bash-effects.js';
import { resolveTxRoot, txDir } from './store.js';

test('appendBashEffect writes JSONL entries and readBashEffects parses them in order', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-be-'));
  try {
    const root = resolveTxRoot(home);
    await mkdir(txDir(root, 'tx_x'), { recursive: true });
    await appendBashEffect(root, 'tx_x', { command: 'pwd', exitCode: 0, ts: '2026-05-07T00:00:00Z', pathsChanged: [], outOfBand: true });
    await appendBashEffect(root, 'tx_x', { command: 'rm a.txt', exitCode: 0, ts: '2026-05-07T00:00:01Z', pathsChanged: ['a.txt'], outOfBand: true });
    const effects = await readBashEffects(root, 'tx_x');
    assert.equal(effects.length, 2);
    assert.equal(effects[0].command, 'pwd');
    assert.deepEqual(effects[1].pathsChanged, ['a.txt']);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('readBashEffects returns [] when bash-effects.json is missing', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-be-missing-'));
  try {
    const root = resolveTxRoot(home);
    await mkdir(txDir(root, 'tx_y'), { recursive: true });
    const effects = await readBashEffects(root, 'tx_y');
    assert.deepEqual(effects, []);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('bashEffectsPath returns <txDir>/bash-effects.json', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-be-path-'));
  try {
    const root = resolveTxRoot(home);
    assert.equal(bashEffectsPath(root, 'tx_z'), path.join(root, 'tx_z', 'bash-effects.json'));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
