import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { STATE_OWNER_NATIVE_RELATIVE_PATH } from '../../../src/state/native-owner.js';
import { verifiedSqliteExtensionIncludes } from '../sqlite-extension-headers.mjs';
import { buildSupervisorSeaImage, prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

// Linux-only installed producer. This is not qualification of the macOS store
// or of the production installed startup/control/admission/secret-store chain.
if (process.platform === 'linux') test('fixed signed application enters and drains the original installed credential scope without StateOwner', { timeout: 180000 }, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-installed-')));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const helper = path.join(fixture, STATE_OWNER_NATIVE_RELATIVE_PATH);
    await mkdir(path.dirname(helper), { recursive: true, mode: 0o700 });
    const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
      '-I', await verifiedSqliteExtensionIncludes(), '-I', path.join(carrier.nodeRoot, 'include/node'),
      fileURLToPath(new URL('../../../native/state-owner/state-owner.c', import.meta.url)), '-o', helper],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(compiled.error, undefined); assert.equal(compiled.status, 0, compiled.stderr); await chmod(helper, 0o500);
    // The scope race loads the actual fixed platform addon but never invokes
    // a manager or Secret Service operation. No synthetic platform can satisfy
    // the signed installation's native loader/receiver checks.
    const platform = spawnSync(process.execPath, [fileURLToPath(new URL('../build-linux-credential-platform.mjs', import.meta.url)),
      path.join(fixture, 'credential-platform'), path.join(carrier.nodeRoot, 'include/node')],
    { encoding: 'utf8', timeout: 65000, maxBuffer: 65536 });
    assert.equal(platform.error, undefined); assert.equal(platform.signal, null); assert.equal(platform.status, 0, platform.stderr);
    const executable = await buildSupervisorSeaImage({ fixture, carrier: carrier.carrier,
      entryPoint: fileURLToPath(new URL('../../../src/state/testing/credential-scope-sea-child.ts', import.meta.url)),
      executable: path.join(fixture, 'credential-scope-supervisor'), variant: 'credential-scope', assets: {} });
    const child = spawnSync(executable, [fixture], { cwd: fixture, env: { PATH: process.env.PATH },
      encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536 });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), { diagnosticOnly: true, signedImageInstalledProducerScope: true,
      stateOwnerAcquired: false, platformCredentialsQualified: false, installedI1Qualified: false });
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
