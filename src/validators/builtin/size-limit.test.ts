import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { sizeLimit, createSizeLimit } from './size-limit.js';

async function withFakeCliqHome<T>(fn: (cliqHome: string) => Promise<T>): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-size-limit-'));
  const prev = process.env.CLIQ_HOME;
  process.env.CLIQ_HOME = home;
  try {
    return await fn(home);
  } finally {
    if (prev === undefined) delete process.env.CLIQ_HOME; else process.env.CLIQ_HOME = prev;
    await rm(home, { recursive: true, force: true });
  }
}

async function writeDiff(cliqHome: string, txId: string, diff: unknown) {
  const txDir = path.join(cliqHome, 'tx', txId);
  await mkdir(txDir, { recursive: true });
  await writeFile(path.join(txDir, 'diff.json'), JSON.stringify(diff), 'utf8');
}

const ctx = (txId: string) => ({ txId, workspaceView: '/tmp', realCwd: '/tmp', signal: new AbortController().signal });

test('size-limit passes when all files are within threshold', async () => {
  await withFakeCliqHome(async (home) => {
    await writeDiff(home, 'tx_a', { files: [{ path: 'a.ts', op: 'modify', oldContent: '', newContent: 'a\nb\nc' }], outOfBand: [] });
    const result = await sizeLimit.run(ctx('tx_a'));
    assert.equal(result.status, 'pass');
  });
});

test('size-limit fails when a file exceeds the configured threshold (advisory severity)', async () => {
  await withFakeCliqHome(async (home) => {
    const big = Array.from({ length: 5001 }, () => 'x').join('\n');
    await writeDiff(home, 'tx_b', { files: [{ path: 'big.ts', op: 'modify', oldContent: '', newContent: big }], outOfBand: [] });
    const result = await sizeLimit.run(ctx('tx_b'));
    assert.equal(result.severity, 'advisory');
    assert.equal(result.status, 'fail');
    assert.ok(result.findings && result.findings.length === 1);
  });
});

test('createSizeLimit accepts a custom threshold', async () => {
  await withFakeCliqHome(async (home) => {
    await writeDiff(home, 'tx_c', { files: [{ path: 'a.ts', op: 'modify', oldContent: '', newContent: 'a\nb\nc' }], outOfBand: [] });
    const result = await createSizeLimit(2).run(ctx('tx_c'));
    assert.equal(result.status, 'fail');
  });
});
