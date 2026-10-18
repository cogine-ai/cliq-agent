import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

test('installed client driver refuses an unowned composition without reflecting supplied input', () => {
  const driver = fileURLToPath(new URL('./installed-control-client-driver.ts', import.meta.url));
  const result = spawnSync(process.execPath, ['--import', 'tsx', driver,
    '/var/tmp/owned-untrusted-diagnostic-sentinel/ownership-ledger.json'], {
    input: '{"apiKey":"owned-untrusted-diagnostic-sentinel"}\n', timeout: 10_000,
    env: { PATH: '/usr/bin:/bin', NODE_NO_WARNINGS: '1' }, encoding: 'utf8'
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, `installed control client driver failed phase=${process.platform === 'linux' && process.arch === 'x64' ? 'composition' : 'platform'}\n`);
});

test('installed client driver bundles as one ordinary Node consumer with no external application loader', async () => {
  const result = await build({ entryPoints: [fileURLToPath(new URL('./installed-control-client-driver.ts', import.meta.url))],
    outfile: 'installed-control-client-driver.mjs', bundle: true, platform: 'node', format: 'esm', target: 'node22.13',
    metafile: true, write: false });
  assert.equal(result.outputFiles?.length, 1);
  assert(result.outputFiles[0]!.contents.length > 0 && result.outputFiles[0]!.contents.length <= 16 * 1024 * 1024);
  assert(Object.values(result.metafile!.outputs).flatMap(output => output.imports).every(item => item.external && item.path.startsWith('node:')));
});
