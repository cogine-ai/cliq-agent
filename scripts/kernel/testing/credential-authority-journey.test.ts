import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../../src/config.js';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { createInstalledRuntime } from '../../../src/state/installed-runtime.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

// Same signed production entry as local auth. This first tracer is metadata
// only: portable/macOS success cannot qualify the actual Linux invocation.
if (process.platform === 'linux') test('signed installed credential read needs neither Supervisor nor secret input and does not write Run state',
  { timeout: 180000 }, async () => {
    const fixture = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-journey-')));
    try {
      const signed = await buildInstalledSupervisorPackage(fixture);
      const stateRoot = path.join(fixture, 'state');
      await createInstalledRuntime({ releaseKeys: signed.releaseKeys }).installInitial({ packageRoot: signed.packageRoot, stateRoot });
      const casSnapshot = async () => {
        const directory = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
        return Promise.all((await readdir(directory)).sort().map(async ref =>
          [ref, sha256Bytes(await readFile(path.join(directory, ref)))]));
      };
      const casBefore = await casSnapshot();
      // Command metadata goes in argv; raw credential bytes must never do so.
      // Read/replay must decide their result before requesting secret input.
      const command = canonicalJsonBytes({ schemaVersion: 1, kind: 'read', credentialGrantId: 'missing-credential' }).toString('base64url');
      const response = spawnSync(path.join(stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential', command], {
        encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 65536,
        env: { PATH: process.env.PATH }, cwd: fixture, stdio: ['ignore', 'pipe', 'pipe'],
      });
      assert.equal(response.error, undefined); assert.equal(response.signal, null);
      assert.equal(response.status, 0, response.stderr);
      assert.deepEqual(JSON.parse(response.stdout), { schemaVersion: 1, record: null });
      assert.deepEqual(await casSnapshot(), casBefore);
      for (const relative of [KERNEL_DATABASE_FILENAME, 'runtime/state-owner.lock', 'runtime/keeper.ready', 'runtime/control-v1.sock'])
        await assert.rejects(lstat(path.join(stateRoot, relative)), { code: 'ENOENT' });
    } finally { await rm(fixture, { recursive: true, force: true }); }
  });
