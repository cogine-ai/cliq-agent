import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test, { mock } from 'node:test';

import { BASH_TIMEOUT_MS } from '../config.js';
import { createSession } from '../session/store.js';
import type { BashEffect } from '../workspace/transactions/types.js';
import { bashTool } from './bash.js';

function makeCtx(cwd: string, opts: { tx?: unknown } = {}) {
  return {
    cwd,
    session: createSession(cwd),
    signal: undefined,
    ...opts
  } as Parameters<typeof bashTool.execute>[1];
}

async function waitForText(file: string) {
  const deadline = Date.now() + 2_000;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const text = await readFile(file, 'utf8');
      if (text.trim().length > 0) return text;
      lastError = new Error(`${file} is still empty`);
    } catch (error) {
      lastError = error;
    }
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw lastError instanceof Error ? lastError : new Error(`Timed out waiting for ${file}`);
}

async function waitForProcessExit(pid: number) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') {
        return;
      }
      throw error;
    }
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`process ${pid} is still running`);
}

function rejectAfterRealMs(ms: number) {
  const startedAt = Date.now();
  return new Promise<never>((_, reject) => {
    const tick = () => {
      if (Date.now() - startedAt >= ms) {
        reject(new Error('bash timeout did not settle promptly'));
        return;
      }
      setImmediate(tick);
    };
    tick();
  });
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
        recordBashEffect: async (eff: BashEffect) => {
          recorded.push(eff);
        }
      }
    });
    const result = await bashTool.execute({ bash: 'echo hello' }, ctx);
    assert.equal(result.status, 'error');
    assert.equal(result.meta.code, 'tx-overlay-error');
    assert.equal(recorded.length, 0);
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
        recordBashEffect: async (eff: BashEffect) => {
          recorded.push(eff);
        }
      }
    });
    const result = await bashTool.execute({ bash: `echo new > ${path.join(dir, 'after.txt')}` }, ctx);
    assert.equal(result.status, 'ok');
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].command, `echo new > ${path.join(dir, 'after.txt')}`);
    assert.equal(recorded[0].outOfBand, true);
    assert.equal(recorded[0].exitCode, 0);
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
        recordBashEffect: async (eff: BashEffect) => {
          recorded.push(eff);
        }
      }
    });
    const result = await bashTool.execute({ bash: 'exit 42' }, ctx);
    assert.equal(result.status, 'error');
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].exitCode, 42);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('bash tool with bashPolicy=confirm in interactive mode records BashEffect', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-confirm-'));
  try {
    const recorded: BashEffect[] = [];
    const ctx = makeCtx(dir, {
      tx: {
        mode: 'edit',
        bashPolicy: 'confirm',
        txId: 'tx_confirm',
        headless: false,
        recordBashEffect: async (eff: BashEffect) => {
          recorded.push(eff);
        }
      }
    });
    const result = await bashTool.execute({ bash: 'echo confirmed' }, ctx);
    assert.equal(result.status, 'ok');
    assert.equal(recorded.length, 1);
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

test('bash timeout terminates descendant process group', async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'cliq-bash-timeout-'));
  const pidFile = path.join(cwd, 'child.pid');
  let childPid: number | undefined;

  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const resultPromise = bashTool.execute(
      { bash: `sleep 30 & echo $! > ${JSON.stringify(pidFile)}; wait` },
      { cwd, session: createSession(cwd) }
    );
    childPid = Number((await waitForText(pidFile)).trim());
    assert.ok(Number.isInteger(childPid) && childPid > 0, `invalid child pid: ${childPid}`);

    mock.timers.tick(BASH_TIMEOUT_MS);
    const result = await Promise.race([resultPromise, rejectAfterRealMs(1_000)]);

    assert.equal(result.status, 'error');
    assert.equal(result.meta.timed_out, true);
    await waitForProcessExit(childPid);
  } finally {
    mock.timers.reset();
    if (childPid) {
      try {
        process.kill(childPid, 'SIGKILL');
      } catch {
        // Best-effort cleanup; the assertion above already proves the expected path.
      }
    }
    await rm(cwd, { recursive: true, force: true });
  }
});
