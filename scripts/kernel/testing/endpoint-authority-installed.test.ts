import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { createInstalledRuntime } from '../../../src/state/installed-runtime.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

// The actual signed production entry, not a qualification-only producer entry
// or a structural token factory. Linux positive evidence comes from the runner.
if (process.platform === 'linux') test('signed installed endpoint read works without a keeper or StateOwner and does not write Run CAS', { timeout: 180000 }, async () => {
  const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-endpoint-installed-')));
  try {
    const signed = await buildInstalledSupervisorPackage(fixture);
    const stateRoot = path.join(fixture, 'state');
    await createInstalledRuntime({ releaseKeys: signed.releaseKeys }).installInitial({ packageRoot: signed.packageRoot, stateRoot });
    const casBefore = await readdir(path.join(stateRoot, KERNEL_CAS_DIRECTORY));
    const response = spawnSync(path.join(stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], {
      input: JSON.stringify({ schemaVersion: 1, kind: 'read', endpointRegistrationId: 'missing-endpoint' }),
      encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536,
      env: { PATH: process.env.PATH }, cwd: fixture,
    });
    assert.equal(response.error, undefined); assert.equal(response.signal, null);
    assert.equal(response.status, 0, response.stderr);
    assert.deepEqual(JSON.parse(response.stdout), { schemaVersion: 1, record: null });
    assert.deepEqual(await readdir(path.join(stateRoot, KERNEL_CAS_DIRECTORY)), casBefore);
    for (const relative of [KERNEL_DATABASE_FILENAME, 'runtime/state-owner.lock', 'runtime/keeper.ready', 'runtime/control-v1.sock'])
      await assert.rejects(lstat(path.join(stateRoot, relative)), { code: 'ENOENT' });
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
