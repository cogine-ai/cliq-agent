import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { GREP_MAX_FILE_BYTES } from '../config.js';
import { createSession } from '../session/store.js';
import { grepTool } from './grep.js';

test('grepTool returns line matches with file and line numbers', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-grep-'));
  try {
    await mkdir(path.join(cwd, 'src'));
    await writeFile(path.join(cwd, 'src', 'runner.ts'), 'export function runTurn() {}\n', 'utf8');

    const result = await grepTool.execute({ grep: { path: 'src', pattern: 'runTurn' } }, { cwd, session: createSession(cwd) });

    assert.equal(result.status, 'ok');
    assert.match(result.content, /src\/runner\.ts:1:/);
    assert.match(result.content, /runTurn/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('grepTool skips symlinked and oversized files', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-grep-safety-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'cliq-grep-outside-'));
  try {
    await mkdir(path.join(cwd, 'src'));
    await writeFile(path.join(outside, 'secret.txt'), 'runTurn outside\n', 'utf8');
    await symlink(path.join(outside, 'secret.txt'), path.join(cwd, 'src', 'secret-link.txt'));
    await writeFile(path.join(cwd, 'src', 'big.txt'), `${'a'.repeat(GREP_MAX_FILE_BYTES + 1)}runTurn`, 'utf8');

    const result = await grepTool.execute({ grep: { path: 'src', pattern: 'runTurn' } }, { cwd, session: createSession(cwd) });

    assert.equal(result.status, 'ok');
    assert.doesNotMatch(result.content, /secret-link\.txt/);
    assert.doesNotMatch(result.content, /big\.txt/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('grepTool supports searching a single file path', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-grep-file-'));
  try {
    await mkdir(path.join(cwd, 'src'));
    await writeFile(path.join(cwd, 'src', 'runner.ts'), 'export function runTurn() {}\n', 'utf8');

    const result = await grepTool.execute(
      { grep: { path: 'src/runner.ts', pattern: 'runTurn' } },
      { cwd, session: createSession(cwd) }
    );

    assert.equal(result.status, 'ok');
    assert.match(result.content, /src\/runner\.ts:1:/);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
