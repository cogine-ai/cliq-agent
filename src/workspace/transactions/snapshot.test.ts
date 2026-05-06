import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createApplyPreSnapshot } from './snapshot.js';

const execFileAsync = promisify(execFile);

async function withCliqHome<T>(callback: (home: string) => Promise<T>) {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-snap-home-'));
  const previousHome = process.env.CLIQ_HOME;
  try {
    process.env.CLIQ_HOME = home;
    return await callback(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.CLIQ_HOME;
    } else {
      process.env.CLIQ_HOME = previousHome;
    }
    await rm(home, { recursive: true, force: true });
  }
}

test('createApplyPreSnapshot returns a snapshot id for a git workspace', async () => {
  await withCliqHome(async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-snap-git-'));
    try {
      await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
      await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
      await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
      await writeFile(path.join(dir, 'a.txt'), 'a', 'utf8');
      await execFileAsync('git', ['add', 'a.txt'], { cwd: dir });
      await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
      const id = await createApplyPreSnapshot(dir);
      assert.match(id, /^wchk_/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

test('createApplyPreSnapshot throws a clear error when path is not a git repo', async () => {
  await withCliqHome(async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-snap-nogit-'));
    try {
      await assert.rejects(
        createApplyPreSnapshot(dir),
        /requires a git repository/
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
