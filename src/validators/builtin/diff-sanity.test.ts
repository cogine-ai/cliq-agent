import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { diffSanity } from './diff-sanity.js';

async function withFakeCliqHome<T>(fn: (cliqHome: string) => Promise<T>): Promise<T> {
  const home = await mkdtemp(path.join(os.tmpdir(), 'cliq-diff-sanity-'));
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

test('diff-sanity passes on workspace-relative modify entries with text content', async () => {
  await withFakeCliqHome(async (home) => {
    await writeDiff(home, 'tx_1', { files: [{ path: 'a.ts', op: 'modify', oldContent: 'a', newContent: 'b' }], outOfBand: [] });
    const result = await diffSanity.run(ctx('tx_1'));
    assert.equal(result.status, 'pass');
    assert.equal(result.findings, undefined);
  });
});

test('diff-sanity fails when path escapes workspace', async () => {
  await withFakeCliqHome(async (home) => {
    await writeDiff(home, 'tx_2', { files: [{ path: '../escape.txt', op: 'modify', oldContent: 'a', newContent: 'b' }], outOfBand: [] });
    const result = await diffSanity.run(ctx('tx_2'));
    assert.equal(result.status, 'fail');
    assert.ok(result.findings?.some((f) => f.message.includes('escapes workspace')));
  });
});

test('diff-sanity fails when content contains NUL byte', async () => {
  await withFakeCliqHome(async (home) => {
    await writeDiff(home, 'tx_3', { files: [{ path: 'a.bin', op: 'modify', oldContent: 'a', newContent: 'a\u0000b' }], outOfBand: [] });
    const result = await diffSanity.run(ctx('tx_3'));
    assert.equal(result.status, 'fail');
    assert.ok(result.findings?.some((f) => f.message.includes('binary')));
  });
});

test('diff-sanity fails when entry op is not modify', async () => {
  await withFakeCliqHome(async (home) => {
    await writeDiff(home, 'tx_4', { files: [{ path: 'a.txt', op: 'create', newContent: 'a' }], outOfBand: [] });
    const result = await diffSanity.run(ctx('tx_4'));
    assert.equal(result.status, 'fail');
    assert.ok(result.findings?.some((f) => f.message.includes('op=create')));
  });
});
