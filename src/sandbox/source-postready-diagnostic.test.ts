import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('post-READY diagnostics require the original attempt and joined bounded helper observations', { skip: process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-source-postready-diagnostic-'));
  try {
    const binary = path.join(dir, 'component');
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      fileURLToPath(new URL('../../native/linux/source-postready-diagnostic.test.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr);
    const observed = spawnSync(binary, [], { encoding: 'utf8', maxBuffer: 65_536 });
    assert.equal(observed.status, 0, observed.stderr);
    const result = JSON.parse(observed.stdout);
    assert.deepEqual(Object.keys(result).sort(), ['actualRunQualified', 'checks', 'format']);
    assert.equal(result.format, 'cliq-source-postready-diagnostic-data-v1'); assert(result.checks >= 350);
    assert.equal(result.actualRunQualified, false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});


test('fixed output collector preserves full immutable bytes and rejects actual namespace/link/size substitutions', { skip: process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-source-output-'));
  try {
    const binary = path.join(dir, 'component');
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      fileURLToPath(new URL('../../native/linux/source-git-output.test.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr);
    const observed = spawnSync(binary, [], { encoding: 'utf8', maxBuffer: 65_536 });
    assert.equal(observed.status, 0, observed.stderr);
    const result = JSON.parse(observed.stdout);
    assert.deepEqual(Object.keys(result).sort(), ['actualRunQualified', 'checks', 'format', 'scratchRemountQualified']);
    assert.equal(result.format, 'cliq-source-output-component-v1'); assert(result.checks >= 70_000);
    assert.equal(result.actualRunQualified, false); assert.equal(result.scratchRemountQualified, false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
