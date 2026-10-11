import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

test('fixed same-engine private credential scope returns callback results and permanently fences escaped tokens', { timeout: 180000 }, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-bridge-')));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const helper = path.join(fixture, 'state-owner.node');
    const source = fileURLToPath(new URL('../../../native/state-owner/state-owner.c', import.meta.url));
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
      ...(process.platform === 'darwin' ? ['-dynamiclib', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC']),
      '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'), source, '-o', helper],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(compiled.error, undefined); assert.equal(compiled.status, 0, compiled.stderr);
    await chmod(helper, 0o500);
    const root = path.join(fixture, 'root');
    await mkdir(root, { mode: 0o700 }); await mkdir(path.join(root, 'runtime'), { mode: 0o700 });
    const entryPoint = fileURLToPath(new URL('./credential-authority-bridge-child.ts', import.meta.url));
    const childFile = path.join(fixture, 'bridge.cjs');
    await build({ entryPoints: [entryPoint], outfile: childFile, bundle: true, platform: 'node', format: 'cjs',
      target: 'node24.21', define: { 'import.meta.url': JSON.stringify(new URL('../../../src/state/native-owner.ts', import.meta.url).href) } });
    const child = spawnSync(carrier.carrier, ['--no-warnings', childFile, helper, root],
      { cwd: fixture, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), { diagnosticOnly: true, sameEnginePrivateScope: true, installedQualification: false });
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
