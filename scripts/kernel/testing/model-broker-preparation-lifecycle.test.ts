import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { OFFLINE_MODEL_TRUST_STORE_PEM } from '../../../src/state/testing/tool-authority.js';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

async function runtimeIdentity(name: string) {
  try { const value = await lstat(name, { bigint: true }); return [value.dev, value.ino, value.uid, value.gid, value.mode]; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
}

// Native resource lifecycle only: not installed StopIntent, a platform store,
// model release, StateOwner, provider, full Run or I1 qualification.
if (process.platform === 'linux' && process.arch === 'x64')
  test('close promptly joins genuine native model preparation while its external credential reply is delayed',
    { timeout: 180000 }, async () => {
      assert(process.getuid!() > 0, 'only the private mount coordinator uses sudo');
      const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-broker-preparation-'));
      const hostRuntime = ['/run', '/run/user', `/run/user/${process.getuid!()}`, `/run/user/${process.getuid!()}/bus`];
      const originalRuntime = await Promise.all(hostRuntime.map(runtimeIdentity));
      try {
        const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
        for (const kind of ['credential-platform', 'model-broker']) {
          const recipe = fileURLToPath(new URL(`../build-linux-${kind}.mjs`, import.meta.url));
          const compiled = spawnSync(process.execPath, [recipe, path.join(fixture, kind), path.join(carrier.nodeRoot, 'include/node')],
            { encoding: 'utf8', timeout: 65000, maxBuffer: 65536 });
          assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null); assert.equal(compiled.status, 0, compiled.stderr);
        }
        const flags = spawnSync('pkg-config', ['--cflags', '--libs', 'gio-2.0'], { encoding: 'utf8', timeout: 5000 });
        assert.equal(flags.error, undefined); assert.equal(flags.signal, null); assert.equal(flags.status, 0, flags.stderr);
        const coordinator = path.join(fixture, 'preparation-lifecycle');
        const source = fileURLToPath(new URL('./credential-platform-timeout-fixture.c', import.meta.url));
        const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', coordinator,
          ...flags.stdout.trim().split(/\s+/u)], { encoding: 'utf8', timeout: 30000, maxBuffer: 65536 });
        assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
        const trust = path.join(fixture, 'component-public-trust.pem');
        await writeFile(trust, OFFLINE_MODEL_TRUST_STORE_PEM, { flag: 'wx', mode: 0o600 });
        const childSource = fileURLToPath(new URL('./model-broker-preparation-lifecycle-child.mjs', import.meta.url));
        const child = spawnSync('/usr/bin/sudo', ['--non-interactive', '--', coordinator, carrier.carrier, childSource,
          path.join(fixture, 'credential-platform/linux-credential-platform.node'), path.join(fixture, 'model-broker/linux-model-broker.node'), trust],
        { encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536, cwd: fixture,
          env: { PATH: process.env.PATH, UV_THREADPOOL_SIZE: '4' } });
        assert.equal(child.error, undefined); assert.equal(child.signal, null);
        const report = JSON.parse(child.stdout);
        console.log(JSON.stringify(report)); // Fixed source-owned diagnostics survive expected RED.
        assert.equal(report.actualPreparationEntered, true, 'the real preparation must reach the deliberately delayed external call');
        assert.equal(report.actualPreparationConnectionRetired, true, 'even RED must positively retire its original bus connection');
        assert.equal(report.childrenJoined, true, 'even RED must join both actual fixture children');
        assert.equal(child.status, 0, child.stderr);
        assert.deepEqual(report, { diagnosticOnly: true, actualPreparationEntered: true, closeJoinedWithin1500ms: true,
          actualPreparationConnectionRetired: true, childrenJoined: true, installedI1Qualified: false });
      } finally {
        try { assert.deepEqual(await Promise.all(hostRuntime.map(runtimeIdentity)), originalRuntime,
          'the isolated fixture must not modify the host runtime namespace'); }
        finally { await rm(fixture, { recursive: true, force: true }); }
      }
    });
