import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  checkIndexUnchanged,
  IndexChangedSinceValidation,
  indexClean
} from './index-clean.js';
import { resolveTxRoot, validatorsDir } from '../../workspace/transactions/store.js';
import type { ValidatorResult } from '../types.js';

const execFileAsync = promisify(execFile);
const ctx = (cwd: string) => ({ txId: 'tx_test', workspaceView: cwd, realCwd: cwd, signal: new AbortController().signal });

function assertHasIndexFingerprint(result: Awaited<ReturnType<typeof indexClean.run>>): void {
  const fingerprint = result.metadata?.indexFingerprint as Record<string, unknown> | undefined;
  assert.equal(fingerprint?.version, 'git-index-v1');
  assert.equal(typeof fingerprint?.entriesSha256, 'string');
}

async function writeIndexCleanBaselineFile(
  root: string,
  txId: string,
  baseline: Partial<ValidatorResult>
): Promise<void> {
  await mkdir(validatorsDir(root, txId), { recursive: true });
  await writeFile(
    path.join(validatorsDir(root, txId), 'builtin_index-clean.json'),
    JSON.stringify(
      {
        name: 'builtin:index-clean',
        severity: 'blocking',
        status: 'pass',
        durationMs: 0,
        ...baseline
      },
      null,
      2
    ),
    'utf8'
  );
}

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
    assertHasIndexFingerprint(result);
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
    assertHasIndexFingerprint(result);
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
    assert.equal(result.metadata, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('index-clean preserves spaces in staged paths (porcelain v2 parsing)', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-spaces-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
    const fileName = 'name with spaces.txt';
    await writeFile(path.join(dir, fileName), 'a', 'utf8');
    await execFileAsync('git', ['add', '--', fileName], { cwd: dir });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
    await writeFile(path.join(dir, fileName), 'b', 'utf8');
    await execFileAsync('git', ['add', '--', fileName], { cwd: dir });
    const result = await indexClean.run(ctx(dir));
    assert.equal(result.status, 'fail');
    assert.ok(result.findings && result.findings.length > 0);
    assert.equal(result.findings![0].path, fileName);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('index-clean returns blocking fail when git execution fails for reasons other than not-a-repo', async () => {
  // Point at a path that doesn't exist as cwd; execFile errors with ENOENT,
  // which is not a "not a git repository" error. Should surface as fail rather
  // than the not-a-repo skip path.
  const result = await indexClean.run(ctx('/nonexistent/path/that/does/not/exist'));
  assert.equal(result.status, 'fail');
  assert.match(result.message ?? '', /git (status|index fingerprint) failed/);
});

test('index-clean preserves spaces in renamed paths (porcelain v2 "2 " parsing)', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-rename-spaces-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
    await writeFile(path.join(dir, 'old name.txt'), 'a', 'utf8');
    await execFileAsync('git', ['add', '--', 'old name.txt'], { cwd: dir });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
    await execFileAsync('git', ['mv', 'old name.txt', 'new name.txt'], { cwd: dir });
    const result = await indexClean.run(ctx(dir));
    assert.equal(result.status, 'fail');
    assert.ok(
      result.findings?.some((f) => f.path === 'new name.txt'),
      `expected finding for "new name.txt", got ${JSON.stringify(result.findings)}`
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('index-clean reports unmerged conflict files (porcelain v2 "u " records)', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-unmerged-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'one', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: dir });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
    await execFileAsync('git', ['checkout', '-b', 'feat'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'feat', 'utf8');
    await execFileAsync('git', ['commit', '-am', 'feat'], { cwd: dir });
    await execFileAsync('git', ['checkout', 'main'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'main', 'utf8');
    await execFileAsync('git', ['commit', '-am', 'main'], { cwd: dir });
    // Trigger the conflict; merge will exit non-zero but leave the index in
    // an unmerged state — exactly the porcelain v2 `u ` record we exercise.
    try {
      await execFileAsync('git', ['merge', 'feat'], { cwd: dir });
    } catch {
      // expected — conflict
    }
    const result = await indexClean.run(ctx(dir));
    assert.equal(result.status, 'fail');
    assert.ok(
      result.findings?.some((f) => /^unmerged:/.test(f.message)),
      `expected an "unmerged:" finding, got ${JSON.stringify(result.findings)}`
    );
    assert.ok(result.findings?.some((f) => f.path === 'a.txt'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged is a no-op when no validation baseline exists', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-no-baseline-'));
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-no-baseline-ws-'));
  try {
    const root = resolveTxRoot(home);
    await checkIndexUnchanged({ root, txId: 'tx_missing_baseline', realCwd: ws });
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged passes when the current Git index fingerprint matches the baseline', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-match-'));
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-match-ws-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'a', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: dir });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });

    const baseline = await indexClean.run(ctx(dir));
    const root = resolveTxRoot(home);
    await writeIndexCleanBaselineFile(root, 'tx_match', baseline);

    await checkIndexUnchanged({ root, txId: 'tx_match', realCwd: dir });
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged skips when the baseline recorded a not-a-git-repository skip', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-skip-nogit-'));
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-skip-nogit-ws-'));
  try {
    const root = resolveTxRoot(home);
    await writeIndexCleanBaselineFile(root, 'tx_skip_nogit', {
      message: 'not a git repository — index check skipped'
    });

    await checkIndexUnchanged({ root, txId: 'tx_skip_nogit', realCwd: dir });
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged rejects when the Git index fingerprint changed since validation', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-changed-'));
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-changed-ws-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: dir });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: dir });
    await writeFile(path.join(dir, 'a.txt'), 'a', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: dir });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });

    const baseline = await indexClean.run(ctx(dir));
    const root = resolveTxRoot(home);
    await writeIndexCleanBaselineFile(root, 'tx_changed', baseline);

    await writeFile(path.join(dir, 'b.txt'), 'staged after validation', 'utf8');
    await execFileAsync('git', ['add', 'b.txt'], { cwd: dir });

    await assert.rejects(
      () => checkIndexUnchanged({ root, txId: 'tx_changed', realCwd: dir }),
      (err: unknown) =>
        err instanceof IndexChangedSinceValidation &&
        /Git index changed since builtin:index-clean validation/.test((err as Error).message)
    );
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged rejects baselines that are missing an index fingerprint', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-missing-fp-'));
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-missing-fp-ws-'));
  try {
    const root = resolveTxRoot(home);
    await writeIndexCleanBaselineFile(root, 'tx_missing_fp', {
      status: 'pass',
      findings: undefined,
      metadata: undefined
    });

    await assert.rejects(
      () => checkIndexUnchanged({ root, txId: 'tx_missing_fp', realCwd: dir }),
      (err: unknown) =>
        err instanceof IndexChangedSinceValidation &&
        /missing index fingerprint/.test((err as Error).message)
    );
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged rejects baselines with the wrong validator name', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-wrong-name-'));
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-wrong-name-ws-'));
  try {
    const root = resolveTxRoot(home);
    await writeIndexCleanBaselineFile(root, 'tx_wrong_name', {
      name: 'builtin:other-validator',
      metadata: {
        indexFingerprint: {
          version: 'git-index-v1',
          entriesSha256: 'abc'
        }
      }
    });

    await assert.rejects(
      () => checkIndexUnchanged({ root, txId: 'tx_wrong_name', realCwd: dir }),
      (err: unknown) =>
        err instanceof IndexChangedSinceValidation &&
        /invalid builtin:index-clean validation baseline/.test((err as Error).message)
    );
  } finally {
    await rm(home, { recursive: true, force: true });
    await rm(dir, { recursive: true, force: true });
  }
});
