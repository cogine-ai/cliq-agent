// Candidate I/O conformance only. No credential, installed or platform qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildCredentialVfsProbe } from './sqlite-vfs-mechanism-build.js';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

test('same-engine descriptor VFS initializes WAL, rolls back and reopens original inodes after empty or DELETE genesis', { timeout: 180000 }, async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-vfs-test-'));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const built = await buildCredentialVfsProbe(fixture, carrier.nodeRoot);
    for (const genesis of ['empty', 'delete']) {
      const home = path.join(fixture, `home-${genesis}`);
      const authorityRoot = path.join(home, 'probe/credential-vfs');
      const directory = path.join(authorityRoot, 'credentials');
      await mkdir(directory, { recursive: true, mode: 0o700 });
      for (const parent of [home, path.join(home, 'probe'), authorityRoot, directory]) await chmod(parent, 0o700);
      const canonicalHome = await realpath(home);
      if (genesis === 'delete') {
        const database = path.join(directory, 'authority.sqlite');
        await writeFile(database, '', { flag: 'wx', mode: 0o600 });
        // A separate actual engine creates the nonempty rollback-journal starting state.
        const seed = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
          const assert = require('node:assert/strict');
          const {DatabaseSync} = require('node:sqlite');
          const db = new DatabaseSync(${JSON.stringify(database)}, {allowExtension:false});
          assert.equal(db.prepare('PRAGMA journal_mode=DELETE').get().journal_mode, 'delete');
          db.exec("PRAGMA synchronous=FULL; CREATE TABLE seed(value TEXT); INSERT INTO seed VALUES ('original-row')");
          db.close();
        `], { encoding: 'utf8', timeout: 15000 });
        assert.equal(seed.error, undefined); assert.equal(seed.signal, null); assert.equal(seed.status, 0, seed.stderr);
      }
      let prior: Record<string, { dev: bigint; ino: bigint }> | undefined;
      for (const mode of ['create', 'reopen']) {
        const child = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
          const assert = require('node:assert/strict');
          const {DatabaseSync} = require('node:sqlite');
          const loaded = {exports:{}};
          process.dlopen(loaded, ${JSON.stringify(built.helper)});
          const native = loaded.exports;
          assert.throws(() => native.prepare('forbidden'), /argument/);
          const prepared = native.prepare();
          const bootstrap = new DatabaseSync(':memory:', {allowExtension:true});
          bootstrap.loadExtension(${JSON.stringify(built.helper)}, 'sqlite3_cliqcredentialvfsprobe_init');
          bootstrap.enableLoadExtension(false);
          bootstrap.close();
          const db = new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-probe-v1', {allowExtension:false});
          assert.equal(db.prepare('PRAGMA locking_mode=EXCLUSIVE').get().locking_mode, 'exclusive');
          db.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL');
          assert.equal(db.prepare('PRAGMA journal_mode=WAL').get().journal_mode, 'wal');
          assert.throws(() => db.enableLoadExtension(true), /disabled at database creation/);
          assert.throws(() => db.exec("SELECT load_extension('forbidden')"), /not authorized/);
          if (${JSON.stringify(mode)} === 'create') {
            db.exec("BEGIN IMMEDIATE; CREATE TABLE proof (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO proof VALUES (1, 'metadata-only'); COMMIT");
          }
          assert.equal(db.prepare('SELECT value FROM proof WHERE id=1').get().value, 'metadata-only');
          db.exec("BEGIN IMMEDIATE; UPDATE proof SET value='rolled-back'; ROLLBACK");
          assert.equal(db.prepare('SELECT value FROM proof WHERE id=1').get().value, 'metadata-only');
          if (${JSON.stringify(genesis)} === 'delete') {
            assert.equal(db.prepare('SELECT value FROM seed').get().value, 'original-row');
            if (${JSON.stringify(mode)} === 'create') assert(native.observe().counts.journalRetirements > 0);
          }
          assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
          const ordinary = new DatabaseSync(':memory:', {allowExtension:false});
          assert.equal(native.observe().sourceId, ordinary.prepare('SELECT sqlite_source_id() AS id').get().id);
          assert.equal(native.observe().defaultUnchanged, true);
          ordinary.close();
          assert.throws(() => native.retire(), /live|open/);
          db.close();
          const beforeRetire = native.observe();
          assert.equal(beforeRetire.liveFiles, 0);
          assert.equal(beforeRetire.fenced, false);
          assert.equal(beforeRetire.uncertain, false);
          for (const role of ['root', 'credentials', 'lock', 'main', 'wal', 'journal']) {
            assert.equal(beforeRetire.descriptors[role].dev, prepared.descriptors[role].dev);
            assert.equal(beforeRetire.descriptors[role].ino, prepared.descriptors[role].ino);
          }
          assert(beforeRetire.counts.reads > 0);
          if (${JSON.stringify(mode)} === 'create') {
            assert(beforeRetire.counts.writes > 0); assert(beforeRetire.counts.syncs > 0);
          }
          native.retire();
          require('node:fs').writeSync(1, JSON.stringify({beforeRetire, afterRetire:native.observe()}));
        `], { cwd: home, env: { ...process.env, HOME: canonicalHome }, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
        assert.equal(child.error, undefined); assert.equal(child.signal, null);
        assert.equal(child.status, 0, child.stderr + child.stdout);
        const result = JSON.parse(child.stdout);
        assert.equal(result.afterRetire.prepared, false);
        const names = ['authority.lock', 'authority.sqlite', 'authority.sqlite-journal', 'authority.sqlite-wal'];
        assert.deepEqual((await readdir(directory)).sort(), names);
        const current: NonNullable<typeof prior> = {};
        for (const leaf of names) {
          const info = await lstat(path.join(directory, leaf), { bigint: true });
          assert(info.isFile()); assert.equal(info.nlink, 1n); assert.equal(info.mode & 0o7777n, 0o600n);
          assert.equal(info.uid, BigInt(process.geteuid!()));
          current[leaf] = { dev: info.dev, ino: info.ino };
        }
        if (prior) assert.deepEqual(current, prior);
        prior = current;
      }
    }
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
