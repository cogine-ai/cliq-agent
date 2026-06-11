import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { validatorsDir } from '../../workspace/transactions/store.js';
import { checkIndexUnchanged, indexClean, IndexChangedSinceValidation } from './index-clean.js';

const execFileAsync = promisify(execFile);
const ctx = (cwd: string) => ({ txId: 'tx_test', workspaceView: cwd, realCwd: cwd, signal: new AbortController().signal });

function assertHasIndexFingerprint(result: Awaited<ReturnType<typeof indexClean.run>>): void {
  const fingerprint = result.metadata?.indexFingerprint as Record<string, unknown> | undefined;
  assert.equal(fingerprint?.version, 'git-index-v1');
  assert.equal(typeof fingerprint?.entriesSha256, 'string');
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

async function writeIndexCleanBaselineFile(
  root: string,
  txId: string,
  baseline: Record<string, unknown>
): Promise<void> {
  await mkdir(validatorsDir(root, txId), { recursive: true });
  await writeFile(
    path.join(validatorsDir(root, txId), 'builtin_index-clean.json'),
    JSON.stringify(baseline, null, 2),
    'utf8'
  );
}

test('checkIndexUnchanged is a no-op when no validation baseline exists', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-baseline-missing-'));
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-ws-'));
  try {
    await assert.doesNotReject(
      checkIndexUnchanged({ root, txId: 'tx_missing', realCwd: ws })
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged passes when the Git index fingerprint matches the baseline', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-baseline-match-'));
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-ws-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: ws });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: ws });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: ws });
    await writeFile(path.join(ws, 'a.txt'), 'a', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });

    const baseline = await indexClean.run(ctx(ws));
    await writeIndexCleanBaselineFile(root, 'tx_match', baseline as Record<string, unknown>);

    await assert.doesNotReject(
      checkIndexUnchanged({ root, txId: 'tx_match', realCwd: ws })
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged rejects when the Git index changed since validation', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-baseline-changed-'));
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-ws-'));
  try {
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: ws });
    await execFileAsync('git', ['config', 'user.email', 't@t'], { cwd: ws });
    await execFileAsync('git', ['config', 'user.name', 't'], { cwd: ws });
    await writeFile(path.join(ws, 'a.txt'), 'a', 'utf8');
    await execFileAsync('git', ['add', 'a.txt'], { cwd: ws });
    await execFileAsync('git', ['commit', '-m', 'init'], { cwd: ws });

    const baseline = await indexClean.run(ctx(ws));
    await writeIndexCleanBaselineFile(root, 'tx_changed', baseline as Record<string, unknown>);

    await writeFile(path.join(ws, 'b.txt'), 'staged after validation', 'utf8');
    await execFileAsync('git', ['add', 'b.txt'], { cwd: ws });

    await assert.rejects(
      checkIndexUnchanged({ root, txId: 'tx_changed', realCwd: ws }),
      (err: unknown) =>
        err instanceof IndexChangedSinceValidation &&
        /Git index changed since builtin:index-clean validation/.test((err as Error).message)
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged rejects legacy baselines that are missing index fingerprints', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-baseline-legacy-'));
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-ws-'));
  try {
    await writeIndexCleanBaselineFile(root, 'tx_legacy', {
      name: 'builtin:index-clean',
      severity: 'blocking',
      status: 'pass',
      durationMs: 1
    });

    await assert.rejects(
      checkIndexUnchanged({ root, txId: 'tx_legacy', realCwd: ws }),
      (err: unknown) =>
        err instanceof IndexChangedSinceValidation &&
        /missing index fingerprint/.test((err as Error).message)
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
});

test('checkIndexUnchanged skips fingerprint comparison for not-a-git-repository baselines', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-baseline-nogit-'));
  const ws = await mkdtemp(path.join(os.tmpdir(), 'cliq-ic-ws-'));
  try {
    await writeIndexCleanBaselineFile(root, 'tx_nogit', {
      name: 'builtin:index-clean',
      severity: 'blocking',
      status: 'pass',
      durationMs: 1,
      message: 'not a git repository — index check skipped'
    });

    await assert.doesNotReject(
      checkIndexUnchanged({ root, txId: 'tx_nogit', realCwd: ws })
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(ws, { recursive: true, force: true });
  }
});
