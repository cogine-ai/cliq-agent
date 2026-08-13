import assert from 'node:assert/strict';
import { chmod, mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { qualifyExecutionBackend } from './probe.js';

test('execution qualification fails closed until a real strong backend probe exists', async () => {
  const result = await qualifyExecutionBackend();

  assert.equal(result.ok, false);
  assert.equal(result.authorityReady, false);
  assert.equal('capability' in result, false);

  if (process.platform === 'darwin' || process.platform === 'linux') {
    assert.equal(result.error.code, 'UNSUPPORTED_EXECUTION_IDENTITY');
    assert.equal(result.observedPlatform, process.platform);
    assert.match(result.error.message, /qualification bundle/i);
    return;
  }

  assert.equal(result.error.code, 'UNSUPPORTED_PLATFORM');
  assert.equal(result.observedPlatform, process.platform);
});

test('execution qualification rejects an unsigned caller-created macOS bundle', async (context) => {
  if (process.platform !== 'darwin') {
    const result = await qualifyExecutionBackend({
      backend: 'macos_vm',
      bundlePath: '/tmp/unsigned/CliqKernelProbe.app',
      expectedManifestDigest: '1'.repeat(64),
      expectedHelperDigest: '2'.repeat(64),
      scratchRoot: '/tmp'
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, 'UNSUPPORTED_PLATFORM');
    return;
  }

  const scratchRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-probe-test-'));
  await chmod(scratchRoot, 0o700);
  const bundlePath = path.join(scratchRoot, 'CliqKernelProbe.app');
  const helperPath = path.join(bundlePath, 'Contents', 'MacOS', 'cliq-kernel-probe');
  await mkdir(path.dirname(helperPath), { recursive: true });
  await writeFile(helperPath, '#!/bin/sh\nexit 0\n', { mode: 0o755 });

  const result = await qualifyExecutionBackend({
    backend: 'macos_vm',
    bundlePath,
    expectedManifestDigest: '1'.repeat(64),
    expectedHelperDigest: '2'.repeat(64),
    scratchRoot
  });

  assert.equal(result.ok, false);
  assert.equal(result.authorityReady, false);
  assert.equal(result.error.code, 'UNSUPPORTED_EXECUTION_IDENTITY');
  assert.match(result.error.message, /signature/i);
});
