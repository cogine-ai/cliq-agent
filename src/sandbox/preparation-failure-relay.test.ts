import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('preparation failure relay joins the original producer and forwards only exact zero-FD diagnostic packets',
  { skip: process.platform !== 'linux' }, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-preparation-failure-relay-'));
    try {
      const binary = path.join(directory, 'component');
      const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-D_FORTIFY_SOURCE=2',
        fileURLToPath(new URL('../../native/linux/preparation-failure-relay.test.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
      assert.equal(compiled.status, 0, compiled.stderr);
      const observed = spawnSync(binary, [], { encoding: 'utf8', maxBuffer: 65_536 });
      assert.equal(observed.status, 0, observed.stderr);
      const result = JSON.parse(observed.stdout);
      assert.deepEqual(Object.keys(result).sort(), ['actualRunQualified', 'checks', 'format']);
      assert.equal(result.format, 'cliq-preparation-failure-relay-component-v1'); assert(result.checks >= 300);
      assert.equal(result.actualRunQualified, false);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
