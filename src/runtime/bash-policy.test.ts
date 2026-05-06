import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { enforceBashPolicy, snapshotMtimes, diffMtimes, recordBashEffect } from './bash-policy.js';

test('bashPolicy=passthrough allows', async () => {
  const r = await enforceBashPolicy({ policy: 'passthrough', txMode: 'edit', headless: false });
  assert.equal(r.decision, 'allow');
});

test('bashPolicy=deny rejects with tx-overlay-error', async () => {
  const r = await enforceBashPolicy({ policy: 'deny', txMode: 'edit', headless: false });
  assert.equal(r.decision, 'deny');
  if (r.decision === 'deny') {
    assert.equal(r.code, 'tx-overlay-error');
    assert.match(r.message, /deny/);
  }
});

test('bashPolicy=confirm allows when user accepts', async () => {
  const r = await enforceBashPolicy({
    policy: 'confirm',
    txMode: 'edit',
    headless: false,
    confirm: async () => true
  });
  assert.equal(r.decision, 'allow');
});

test('bashPolicy=confirm denies when user rejects', async () => {
  const r = await enforceBashPolicy({
    policy: 'confirm',
    txMode: 'edit',
    headless: false,
    confirm: async () => false
  });
  assert.equal(r.decision, 'deny');
  if (r.decision === 'deny') {
    assert.match(r.message, /rejected by user/);
  }
});

test('bashPolicy=confirm promoted to deny under --headless', async () => {
  const r = await enforceBashPolicy({
    policy: 'confirm',
    txMode: 'edit',
    headless: true,
    confirm: async () => true
  });
  assert.equal(r.decision, 'deny');
  if (r.decision === 'deny') {
    assert.match(r.message, /headless/);
  }
});

test('bashPolicy is bypassed when tx mode is off', async () => {
  const r = await enforceBashPolicy({ policy: 'deny', txMode: 'off', headless: false });
  assert.equal(r.decision, 'allow');
});

test('snapshotMtimes captures all files; diffMtimes finds modifications and additions', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-policy-'));
  try {
    await writeFile(path.join(dir, 'a.txt'), 'one', 'utf8');
    await mkdir(path.join(dir, 'sub'), { recursive: true });
    await writeFile(path.join(dir, 'sub', 'b.txt'), 'two', 'utf8');
    const before = await snapshotMtimes(dir);
    assert.equal(before.size, 2);
    // Wait > 10ms to ensure mtime advances on macOS APFS.
    await new Promise((r) => setTimeout(r, 20));
    await writeFile(path.join(dir, 'a.txt'), 'ONE', 'utf8');
    await writeFile(path.join(dir, 'c.txt'), 'three', 'utf8');
    const after = await snapshotMtimes(dir);
    const changed = diffMtimes(before, after);
    assert.deepEqual(changed.sort(), ['a.txt', 'c.txt'].sort());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('snapshotMtimes ignores .git and node_modules by default', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-ignore-'));
  try {
    await writeFile(path.join(dir, 'a.txt'), 'a', 'utf8');
    await mkdir(path.join(dir, '.git'), { recursive: true });
    await writeFile(path.join(dir, '.git', 'HEAD'), 'ref', 'utf8');
    await mkdir(path.join(dir, 'node_modules'), { recursive: true });
    await writeFile(path.join(dir, 'node_modules', 'pkg.txt'), 'p', 'utf8');
    const map = await snapshotMtimes(dir);
    assert.deepEqual(Array.from(map.keys()).sort(), ['a.txt']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('diffMtimes finds deletions', async () => {
  const before: Map<string, number> = new Map([['a.txt', 1000], ['b.txt', 1000]]);
  const after: Map<string, number> = new Map([['a.txt', 1000]]);
  assert.deepEqual(diffMtimes(before, after), ['b.txt']);
});

test('recordBashEffect builds BashEffect with outOfBand=true', () => {
  const eff = recordBashEffect({ command: 'npm test', exitCode: 0, pathsChanged: ['a.txt'] });
  assert.equal(eff.command, 'npm test');
  assert.equal(eff.exitCode, 0);
  assert.deepEqual(eff.pathsChanged, ['a.txt']);
  assert.equal(eff.outOfBand, true);
  assert.match(eff.ts, /^\d{4}-\d{2}-\d{2}T/);
});
