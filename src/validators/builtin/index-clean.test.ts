import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { indexClean } from './index-clean.js';

const execFileAsync = promisify(execFile);
const ctx = (cwd: string) => ({ txId: 'tx_test', workspaceView: cwd, realCwd: cwd, signal: new AbortController().signal });

test('index-clean passes on a clean repo', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-clean-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'a', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: dir });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
    const result = await indexClean.run(ctx(dir));
    assert.equal(result.status, 'pass');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('index-clean fails when index has staged changes', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-staged-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'a', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: dir });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'b', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: dir });
    const result = await indexClean.run(ctx(dir));
    assert.equal(result.status, 'fail');
    assert.ok(result.findings && result.findings.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('index-clean returns pass with skip message when not a git repo', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-nogit-'));
  try {
    const result = await indexClean.run(ctx(dir));
    assert.equal(result.status, 'pass');
    assert.match(result.message ?? '', /not a git repository/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
