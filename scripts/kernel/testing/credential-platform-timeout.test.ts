import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

async function runtimeIdentity(name: string) {
  try {
    const value = await lstat(name, { bigint: true });
    return [value.dev, value.ino, value.uid, value.gid, value.mode];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

// Actual public native platform behavior, not a systemd/Secret Service,
// installed producer, StateOwner or I1 qualification. The isolated external
// service can delay replies but cannot manufacture production observations.
if (process.platform === 'linux' && process.arch === 'x64')
  test('an executing credential platform timeout retires its connection and permits a healthy subsequent operation',
    { timeout: 180000 }, async () => {
      assert(process.getuid!() > 0, 'invoke from the real runner user; only the mount coordinator uses sudo');
      const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-platform-timeout-'));
      const hostRuntime = ['/run', '/run/user', `/run/user/${process.getuid!()}`, `/run/user/${process.getuid!()}/bus`];
      const originalRuntime = await Promise.all(hostRuntime.map(runtimeIdentity));
      try {
        const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
        const output = path.join(fixture, 'native');
        const recipe = fileURLToPath(new URL('../build-linux-credential-platform.mjs', import.meta.url));
        const compiled = spawnSync(process.execPath, [recipe, output, path.join(carrier.nodeRoot, 'include/node')],
          { encoding: 'utf8', timeout: 65000, maxBuffer: 65536 });
        assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null);
        assert.equal(compiled.status, 0, compiled.stderr);
        const flags = spawnSync('pkg-config', ['--cflags', '--libs', 'gio-2.0'], { encoding: 'utf8', timeout: 5000 });
        assert.equal(flags.error, undefined); assert.equal(flags.signal, null); assert.equal(flags.status, 0, flags.stderr);
        const coordinator = path.join(fixture, 'credential-platform-timeout');
        const fixtureSource = fileURLToPath(new URL('./credential-platform-timeout-fixture.c', import.meta.url));
        const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', fixtureSource, '-o', coordinator,
          ...flags.stdout.trim().split(/\s+/u)], { encoding: 'utf8', timeout: 30000, maxBuffer: 65536 });
        assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
        const childSource = fileURLToPath(new URL('./credential-platform-timeout-child.mjs', import.meta.url));
        const child = spawnSync('/usr/bin/sudo', ['--non-interactive', '--', coordinator, carrier.carrier,
          childSource, path.join(output, 'linux-credential-platform.node')],
        { encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536, cwd: fixture,
          env: { PATH: process.env.PATH, UV_THREADPOOL_SIZE: '4' } });
        assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr);
        const report = JSON.parse(child.stdout);
        assert.equal(typeof report.preExecProcRootOwned, 'boolean'); // Observed diagnostic, not a qualification prerequisite.
        const { preExecProcRootOwned, ...qualified } = report;
        assert.deepEqual(qualified, { diagnosticOnly: true, postExecSameUidProc: true, actualFirstConnectionRetired: true,
          healthySubsequentOperation: true, childrenJoined: true, installedI1Qualified: false });
        console.log(JSON.stringify(report)); // Retain only this source-owned closed evidence shape.
      } finally {
        try { assert.deepEqual(await Promise.all(hostRuntime.map(runtimeIdentity)), originalRuntime,
          'the isolated component must not replace or modify the host runtime namespace'); }
        finally { await rm(fixture, { recursive: true, force: true }); }
      }
    });
