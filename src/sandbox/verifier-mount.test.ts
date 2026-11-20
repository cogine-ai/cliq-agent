import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('the native mount reader consumes short reads through EOF and retains duplicate, flag and size refusals',
  { skip: !['darwin', 'linux'].includes(process.platform) }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-mount-reader-'));
  try {
    const binary = path.join(directory, 'component');
    const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      fileURLToPath(new URL('../../native/linux/verifier-mount-component.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(built.status, 0, built.stderr);
    const result = spawnSync(binary, [path.join(directory, 'mountinfo.XXXXXX')], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { checks: 7, shortReadBytes: 4096, physicalContainmentQualified: false });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
