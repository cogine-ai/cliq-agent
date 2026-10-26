import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('full raw source data preserves historical wire6 and current wire7 while rejecting mixed or builtin ACK chains', { skip: process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-source-history-wire-'));
  try {
    const binary = path.join(dir, 'component');
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      `-DCLIQ_SOURCE_COMPONENT_DIRECTORY=${JSON.stringify(dir)}`,
      fileURLToPath(new URL('../../native/linux/source-git-component.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr);
    const observed = spawnSync(binary, [], { encoding: 'utf8', maxBuffer: 65_536 });
    assert.equal(observed.status, 0, observed.stderr);
    assert.match(observed.stdout, /^source component checks=\d+; no authority or installed qualification\n$/u);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
