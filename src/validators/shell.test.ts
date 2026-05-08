import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createShellValidator } from './shell.js';

const ctx = (cwd: string) => ({
  txId: 'tx_test',
  workspaceView: cwd,
  realCwd: '/tmp',
  signal: new AbortController().signal
});

test('shell validator passes on exit 0', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-shval-pass-'));
  try {
    const v = createShellValidator({
      name: 'echo-ok',
      command: `${process.execPath} -e "console.log('ok')"`,
      severity: 'blocking'
    });
    const result = await v.run(ctx(dir));
    assert.equal(result.status, 'pass');
    assert.match(result.message ?? '', /ok/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('shell validator fails on non-zero exit', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-shval-fail-'));
  try {
    const v = createShellValidator({
      name: 'fail',
      command: `${process.execPath} -e "console.error('boom'); process.exit(1)"`,
      severity: 'blocking'
    });
    const result = await v.run(ctx(dir));
    assert.equal(result.status, 'fail');
    assert.match(result.message ?? '', /boom/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('shell validator status=error on timeout', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-shval-timeout-'));
  try {
    const v = createShellValidator({
      name: 'sleep',
      command: `${process.execPath} -e "setTimeout(()=>{}, 5000)"`,
      severity: 'blocking',
      timeoutMs: 50
    });
    const result = await v.run(ctx(dir));
    assert.equal(result.status, 'error');
    assert.match(result.message ?? '', /timed out/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('shell validator runs in workspaceView, not realCwd', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-shval-cwd-'));
  try {
    const v = createShellValidator({
      name: 'pwd',
      command: `${process.execPath} -e "process.stdout.write(process.cwd())"`,
      severity: 'blocking'
    });
    const result = await v.run(ctx(dir));
    assert.equal(result.status, 'pass');
    // On macOS, mkdtemp can return /var/folders/... while realpath is /private/var/folders/...
    // Use realpath comparison to handle this.
    const expected = await realpath(dir);
    const got = await realpath((result.message ?? '').trim());
    assert.equal(got, expected);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('shell validator stdout truncated to 256 KB', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-shval-trunc-'));
  try {
    // Generate ~1 MB of output. The capture is capped at 256 KB internally;
    // the user-visible message field is capped at 2048 chars.
    const v = createShellValidator({
      name: 'big',
      command: `${process.execPath} -e "process.stdout.write('x'.repeat(1024*1024))"`,
      severity: 'blocking',
      timeoutMs: 5000
    });
    const result = await v.run(ctx(dir));
    assert.equal(result.status, 'pass');
    assert.ok(result.message);
    assert.ok((result.message?.length ?? 0) <= 2048);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
