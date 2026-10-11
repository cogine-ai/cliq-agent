// Local process-level FD-consumption conformance, not credential/platform qualification.
// A close error does not prove that the original descriptor or its lock survives.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildCredentialVfsRetirementProbe } from './sqlite-vfs-mechanism-build.js';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

const order = ['journal', 'wal', 'credentials', 'root', 'main', 'lock'] as const;

test('retirement consumes a real closed-and-reused FD once and fails closed for every fixed role', { timeout: 180000 }, async (t) => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-vfs-retirement-'));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const built = await buildCredentialVfsRetirementProbe(fixture, carrier.nodeRoot);
    for (const [index, role] of order.entries()) {
      await t.test(role, async () => {
        const requestedHome = path.join(fixture, role);
        const directory = path.join(requestedHome, 'probe/credential-vfs/credentials');
        await mkdir(directory, { recursive: true, mode: 0o700 });
        for (const parent of [requestedHome, path.join(requestedHome, 'probe'), path.dirname(directory), directory]) {
          await chmod(parent, 0o700);
        }
        const home = await realpath(requestedHome);
        const child = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
          const assert = require('node:assert/strict');
          const fs = require('node:fs');
          const {DatabaseSync} = require('node:sqlite');
          const loaded = {exports:{}};
          process.dlopen(loaded, ${JSON.stringify(built.helper)});
          const native = loaded.exports;
          const prepared = native.prepare();
          const targetFd = prepared.descriptors[${JSON.stringify(role)}].fd;
          const bootstrap = new DatabaseSync(':memory:', {allowExtension:true});
          bootstrap.loadExtension(${JSON.stringify(built.helper)}, 'sqlite3_cliqcredentialvfsprobe_init');
          bootstrap.enableLoadExtension(false); bootstrap.close();
          const location = 'file:cliq-credential-authority?vfs=cliq-credential-vfs-probe-v1';
          const db = new DatabaseSync(location, {allowExtension:false});
          assert.equal(db.prepare('PRAGMA locking_mode=EXCLUSIVE').get().locking_mode, 'exclusive');
          db.exec('PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0');
          assert.equal(db.prepare('PRAGMA journal_mode=WAL').get().journal_mode, 'wal');
          db.exec("CREATE TABLE proof(value TEXT NOT NULL); INSERT INTO proof VALUES ('original')");
          assert.equal(db.prepare('SELECT value FROM proof').get().value, 'original');
          db.close();
          const healthy = native.observe();
          assert.equal(healthy.liveFiles, 0);
          assert.equal(healthy.uncertain, false); assert.equal(healthy.fenced, false);
          assert.equal(healthy.counts.closes, 0);
          assert(healthy.counts.writes > 0);
          assert.throws(() => native.retire(), /close is uncertain/);
          const failed = native.observe();
          assert.equal(failed.prepared, true);
          assert.equal(failed.retired, false); assert.equal(failed.uncertain, true);
          assert.equal(failed.counts.closes, ${index + 1});
          const order = ${JSON.stringify(order)};
          for (let position=0; position<order.length; position++) {
            const name = order[position];
            if (position <= ${index}) assert.equal(failed.descriptors[name], null);
            else {
              assert.equal(failed.descriptors[name].fd, prepared.descriptors[name].fd);
              assert.equal(failed.descriptors[name].dev, prepared.descriptors[name].dev);
              assert.equal(failed.descriptors[name].ino, prepared.descriptors[name].ino);
            }
          }
          // The wrapper owns these newly opened /dev/zero descriptors; no dup2,
          // no synthetic descriptor number and no duplicate authoritative FD.
          function assertReusedFdLives() {
            const actual = fs.fstatSync(targetFd, {bigint:true});
            const expected = fs.statSync('/dev/zero', {bigint:true});
            assert(actual.isCharacterDevice());
            assert.equal(actual.dev, expected.dev); assert.equal(actual.ino, expected.ino);
            const bytes = Buffer.alloc(32, 0xa5);
            assert.equal(fs.readSync(targetFd, bytes, 0, bytes.length, null), 32);
            assert.deepEqual(bytes, Buffer.alloc(32));
          }
          assertReusedFdLives();
          assert.throws(() => native.retire(), /cannot be retired/);
          assert.throws(() => native.prepare(), /cannot prepare twice/);
          assert.throws(() => new DatabaseSync(location, {allowExtension:false}), /unable to open/);
          assert.equal(native.observe().counts.closes, ${index + 1});
          assertReusedFdLives();
        `], {
          cwd: home, env: { ...process.env, HOME: home, CLIQ_CREDENTIAL_VFS_RETIREMENT_ROLE: role },
          encoding: 'utf8', timeout: 15000, killSignal: 'SIGKILL', maxBuffer: 65536,
        });
        assert.equal(child.error, undefined);
        assert.equal(child.signal, null);
        assert.equal(child.status, 0, child.stderr + child.stdout);
      });
    }
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
