import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { buildBuiltinToolsAsset } from './builtin-tools-package.js';

test('fixed builtin publisher measures raw non-executable data and actual script refuses host execution', async () => {
  const repository = fileURLToPath(new URL('../../../', import.meta.url));
  const asset = await buildBuiltinToolsAsset(repository);
  assert.equal(asset.entryId, 'builtin_tools'); assert.equal(asset.version, '1'); assert.equal(asset.role, 'tool_adapter');
  assert.equal(asset.relativePath, 'adapters/builtin-tools.mjs'); assert.equal(asset.executable, false);
  assert.equal(asset.digest, sha256Bytes(asset.bytes)); assert.equal(asset.byteCount, asset.bytes.length); assert(asset.byteCount <= 1_048_576);
  const dir = await mkdtemp(path.join(os.tmpdir(), 'cliq-builtin-host-refusal-'));
  try {
    const script = path.join(dir, 'program.mjs'); await writeFile(script, asset.bytes, { flag: 'wx', mode: 0o400 });
    const child = spawn(process.execPath, ['--no-addons', script], { stdio: ['ignore', 'pipe', 'pipe'],
      env: { LANG: 'C', LC_ALL: 'C', HOME: '/home/cliq', TMPDIR: '/tmp', PATH: '/usr/bin' } });
    const output: Buffer[] = [], error: Buffer[] = [];
    child.stdout.on('data', chunk => output.push(Buffer.from(chunk))); child.stderr.on('data', chunk => error.push(Buffer.from(chunk)));
    const status = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
    assert.equal(status, 70); assert.equal(Buffer.concat(output).length, 0); assert.equal(Buffer.concat(error).toString(), 'FIXED_TOOL_EXECUTION_FAILED\n');
  } finally { await rm(dir, { recursive: true, force: true }); }
});
