import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('source READY diagnostic accepts only its original bounded private marker', { skip: process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-source-ready-diagnostic-'));
  try {
    const binary = path.join(dir, 'component');
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      fileURLToPath(new URL('../../native/linux/source-ready-diagnostic.test.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr);
    const observed = spawnSync(binary, [], { encoding: 'utf8', maxBuffer: 65_536 });
    assert.equal(observed.status, 0, observed.stderr);
    const result = JSON.parse(observed.stdout);
    assert.equal(result.format, 'cliq-source-ready-diagnostic-data-v1'); assert(result.checks >= 35);
    assert.equal(result.actualRunQualified, false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
