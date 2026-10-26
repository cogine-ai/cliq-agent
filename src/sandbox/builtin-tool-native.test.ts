import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { Module } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import type { NativeWorkerBinding } from './linux-worker.js';

test('fixed native recipe rejects relabelled configs and validates real sealed bytes, without creating execution authority', { skip: process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-builtin-native-data-'));
  try {
    const binary = path.join(dir, 'component');
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      fileURLToPath(new URL('../../native/linux/builtin-tool-component.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr);
    const run = spawnSync(binary, [], { encoding: 'utf8', maxBuffer: 65_536 });
    assert.equal(run.status, 0, run.stderr);
    const result = JSON.parse(run.stdout);
    assert.equal(result.format, 'cliq-fixed-builtin-native-data-component-v1'); assert(result.checks >= 40);
    assert.equal(result.runAuthority, false); assert.equal(result.physicalContainmentQualified, false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('actual native script receiver owns immutable bytes and a distinct non-executable seal, never a JS descriptor substitute', { skip: process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-builtin-native-seal-'));
  try {
    const binary = path.join(dir, 'worker.node');
    const includes = JSON.parse(execFileSync(process.execPath, [
      fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'
    ], { encoding: 'utf8' })) as string[];
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
      ...includes.flatMap(include => ['-I', include]), fileURLToPath(new URL('../../native/linux/worker-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
    assert.equal(compiled.status, 0, compiled.stderr);
    const loaded = new Module('cliq-owned-builtin-seal-component'); process.dlopen(loaded, binary);
    const native = loaded.exports as NativeWorkerBinding;
    assert.equal(native.builtinToolInterfaceVersion, 2);
    const bytes = Buffer.from('opaque owned script fixture; not a signed tool or authority');
    const filename = path.join(dir, 'owned-data'); await writeFile(filename, bytes, { flag: 'wx', mode: 0o400 });
    const file = await open(filename, 'r');
    try {
      const image = native.sealBuiltinToolScript(file.fd);
      assert.deepEqual(image.identity, { sha256: createHash('sha256').update(bytes).digest('hex'), byteCount: bytes.length });
      assert(Object.isFrozen(image)); assert(Object.isFrozen(image.identity)); assert.equal('descriptor' in image, false);
      assert.throws(() => image.close.call({})); image.close(); image.close();
    } finally { await file.close(); }
    assert.throws(() => native.sealBuiltinToolScript(-1));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
