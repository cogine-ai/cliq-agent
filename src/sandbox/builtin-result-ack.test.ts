import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('builtin ACK closes only the exact original data slots without granting effects or reusing scope IDs', { skip: process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-builtin-result-ack-'));
  try {
    const binary = path.join(dir, 'component');
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      fileURLToPath(new URL('../../native/linux/builtin-result-ack.test.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr);
    const observed = spawnSync(binary, [], { encoding: 'utf8', maxBuffer: 65_536 });
    assert.equal(observed.status, 0, observed.stderr);
    const result = JSON.parse(observed.stdout);
    assert.deepEqual(Object.keys(result).sort(), ['actualRunQualified', 'checks', 'format']);
    assert.equal(result.format, 'cliq-builtin-result-ack-data-v1'); assert(result.checks >= 50);
    assert.equal(result.actualRunQualified, false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
