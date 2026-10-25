import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { buildSourceGitInspectorAsset } from './source-git-inspector-package.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';

test('source inspector publisher measures one fixed non-executable asset and cannot run it as a host Git adapter', async () => {
  const repository = fileURLToPath(new URL('../../..', import.meta.url));
  const asset = await buildSourceGitInspectorAsset(repository);
  assert.equal(asset.entryId, 'source_git_inspector'); assert.equal(asset.role, 'platform_helper');
  assert.equal(asset.executable, false); assert.equal(asset.relativePath, 'helpers/source-git-inspector.mjs');
  assert.equal(asset.byteCount, asset.bytes.length); assert.equal(asset.digest, sha256Bytes(asset.bytes));
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-git-asset-'));
  try {
    const file = path.join(directory, 'fixed-inspector.mjs'); await writeFile(file, asset.bytes, { flag: 'wx', mode: 0o400 });
    const child = spawn(process.execPath, [file], { cwd: directory, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    child.stdout.on('data', chunk => stdout.push(Buffer.from(chunk))); child.stderr.on('data', chunk => stderr.push(Buffer.from(chunk)));
    const actual = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
    });
    assert.deepEqual(actual, { code: 74, signal: null });
    assert.equal(Buffer.concat(stdout).length, 0); assert.equal(Buffer.concat(stderr).length, 0);
    // This is a negative ordinary child/pipe test. It proves neither the
    // source native tags nor a successful signed Linux Git inspection.
  } finally { await rm(directory, { recursive: true, force: true }); }
});
