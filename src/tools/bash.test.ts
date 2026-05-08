import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { bashTool } from './bash.js';
import { createSession } from '../session/store.js';
import type { BashEffect } from '../workspace/transactions/types.js';

function makeCtx(cwd: string, opts: { tx?: any } = {}) {
  return {
    cwd,
    session: createSession(cwd),
    signal: undefined,
    ...opts
  } as Parameters<typeof bashTool.execute>[1];
}

test('bash tool runs unchanged when context.tx is undefined (tx-off)', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-off-'));
  try {
    const result = await bashTool.execute({ bash: 'echo hello' }, makeCtx(dir));
    assert.equal(result.status, 'ok');
    assert.match(result.content, /hello/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('bash tool denies under bashPolicy=deny when context.tx is set', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-deny-'));
  try {
    const recorded: BashEffect[] = [];
    const ctx = makeCtx(dir, {
      tx: {
        mode: 'edit',
        bashPolicy: 'deny',
        txId: 'tx_test',
        headless: false,
        recordBashEffect: async (eff: BashEffect) => { recorded.push(eff); }
      }
    });
    const result = await bashTool.execute({ bash: 'echo hello' }, ctx);
    assert.equal(result.status, 'error');
    assert.equal(result.meta.code, 'tx-overlay-error');
    assert.equal(recorded.length, 0); // nothing recorded on deny
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('bash tool with bashPolicy=passthrough records BashEffect after run', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-pass-'));
  try {
    await writeFile(path.join(dir, 'before.txt'), 'before', 'utf8');
    const recorded: BashEffect[] = [];
    const ctx = makeCtx(dir, {
      tx: {
        mode: 'edit',
        bashPolicy: 'passthrough',
        txId: 'tx_pass',
        headless: false,
        recordBashEffect: async (eff: BashEffect) => { recorded.push(eff); }
      }
    });
    const result = await bashTool.execute({ bash: `echo new > ${path.join(dir, 'after.txt')}` }, ctx);
    assert.equal(result.status, 'ok');
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].command, `echo new > ${path.join(dir, 'after.txt')}`);
    assert.equal(recorded[0].outOfBand, true);
    assert.equal(recorded[0].exitCode, 0); // success preserved
    assert.ok(recorded[0].pathsChanged.some((p) => p.endsWith('after.txt')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('bash tool with bashPolicy=passthrough preserves non-zero exit code in BashEffect', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-exit-'));
  try {
    const recorded: BashEffect[] = [];
    const ctx = makeCtx(dir, {
      tx: {
        mode: 'edit',
        bashPolicy: 'passthrough',
        txId: 'tx_exit',
        headless: false,
        recordBashEffect: async (eff: BashEffect) => { recorded.push(eff); }
      }
    });
    const result = await bashTool.execute({ bash: 'exit 42' }, ctx);
    assert.equal(result.status, 'error');
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].exitCode, 42); // non-zero exit code preserved, not coerced to 1
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('bash tool with bashPolicy=confirm + headless promotes to deny', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-confirm-headless-'));
  try {
    const ctx = makeCtx(dir, {
      tx: {
        mode: 'edit',
        bashPolicy: 'confirm',
        txId: 'tx_ch',
        headless: true,
        recordBashEffect: async () => {}
      }
    });
    const result = await bashTool.execute({ bash: 'echo hi' }, ctx);
    assert.equal(result.status, 'error');
    assert.equal(result.meta.code, 'tx-overlay-error');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
