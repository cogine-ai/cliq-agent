import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { buildInstalledNpmAdapterAsset, buildInstalledNpmDataAsset } from './installed-npm-package.js';

test('fixed npm adapter is one signed data asset and rejects ordinary host execution before reading any repository input', async () => {
  const asset = await buildInstalledNpmAdapterAsset(fileURLToPath(new URL('../../../', import.meta.url)));
  assert.deepEqual({ entryId: asset.entryId, role: asset.role, version: asset.version, relativePath: asset.relativePath, executable: asset.executable }, {
    entryId: 'npm_dependency_adapter', role: 'tool_adapter', version: '1', relativePath: 'adapters/npm-dependency.mjs', executable: false });
  assert(asset.bytes.length < 1_048_576); assert.equal(asset.byteCount, asset.bytes.length); assert.equal(asset.digest, sha256Bytes(asset.bytes));
  const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-npm-host-refusal-'));
  try {
    const entry = path.join(root, 'adapter.mjs'); await writeFile(entry, asset.bytes, { flag: 'wx', mode: 0o400 });
    const result = await new Promise<{ code: number | string | undefined; stdout: string; stderr: string }>(resolve => {
      // Exact own child; callback is after its process and stdio actually join.
      execFile(process.execPath, ['--no-addons', entry], { cwd: root, env: {}, timeout: 5000 }, (error, stdout, stderr) =>
        resolve({ code: (error as NodeJS.ErrnoException & { code?: number } | null)?.code, stdout, stderr }));
    });
    assert.equal(result.code, 70); assert.equal(result.stdout, ''); assert.equal(result.stderr, 'FIXED_DEPENDENCY_EXECUTION_FAILED\n');
    assert.throws(() => buildInstalledNpmDataAsset(Buffer.from('not the pinned official source')));
  } finally { await rm(root, { recursive: true, force: true }); }
});
