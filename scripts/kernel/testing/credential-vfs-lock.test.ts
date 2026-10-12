// Process-level candidate lock conformance, not installed/credential qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildCredentialVfsProbe } from './sqlite-vfs-mechanism-build.js';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

test('a second private process cannot share original storage after lock-only or partial-closure replacement', { timeout: 180000 }, async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-vfs-lock-'));
  try {
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const built = await buildCredentialVfsProbe(fixture, carrier.nodeRoot);
    const home = path.join(fixture, 'home');
    const directory = path.join(home, 'probe/credential-vfs/credentials');
    await mkdir(directory, { recursive: true, mode: 0o700 });
    for (const parent of [home, path.join(home, 'probe'), path.dirname(directory), directory]) await chmod(parent, 0o700);
    const replacementMain = path.join(home, 'replacement.sqlite');
    const replacementWal = path.join(home, 'replacement-wal');
    await writeFile(replacementMain, '', { flag: 'wx', mode: 0o600 });
    await writeFile(replacementWal, '', { flag: 'wx', mode: 0o600 });
    // Seed before acquiring guards; never open/close a duplicate of a guarded inode.
    const seed = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
      const {DatabaseSync} = require('node:sqlite');
      const db = new DatabaseSync(${JSON.stringify(replacementMain)}, {allowExtension:false});
      db.exec('CREATE TABLE replacement(value INTEGER); INSERT INTO replacement VALUES (23)'); db.close();
    `], { encoding: 'utf8', timeout: 5000 });
    assert.equal(seed.error, undefined); assert.equal(seed.signal, null); assert.equal(seed.status, 0, seed.stderr);
    const contenderSource = `
      const assert = require('node:assert/strict');
      const loaded = {exports:{}};
      process.dlopen(loaded, ${JSON.stringify(built.helper)});
      assert.throws(() => loaded.exports.prepare(), /prerequisites refused/);
      const cut = loaded.exports.observe();
      assert.equal(cut.prepared, false);
      assert.equal(cut.counts.reads, 0); assert.equal(cut.counts.writes, 0);
    `;
    const primary = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
      const assert = require('node:assert/strict');
      const fs = require('node:fs');
      const {spawnSync} = require('node:child_process');
      const {DatabaseSync} = require('node:sqlite');
      const loaded = {exports:{}};
      process.dlopen(loaded, ${JSON.stringify(built.helper)});
      const native = loaded.exports;
      const prepared = native.prepare();
      const bootstrap = new DatabaseSync(':memory:', {allowExtension:true});
      bootstrap.loadExtension(${JSON.stringify(built.helper)}, 'sqlite3_cliqcredentialvfsprobe_init');
      bootstrap.enableLoadExtension(false); bootstrap.close();
      const db = new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-probe-v1', {allowExtension:false});
      db.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA synchronous=FULL');
      assert.equal(db.prepare('PRAGMA journal_mode=WAL').get().journal_mode, 'wal');
      db.exec('CREATE TABLE proof(value INTEGER); INSERT INTO proof VALUES (17)');
      function contend() {
        const child = spawnSync(process.execPath, ['--no-warnings', '-e', ${JSON.stringify(contenderSource)}],
          {env:process.env, encoding:'utf8', timeout:5000});
        assert.equal(child.error, undefined); assert.equal(child.signal, null);
        assert.equal(child.status, 0, child.stderr + child.stdout);
      }
      contend();
      const lock = ${JSON.stringify(path.join(directory, 'authority.lock'))};
      fs.renameSync(lock, lock + '-retired');
      fs.writeFileSync(lock, '', {flag:'wx', mode:0o600});
      // Old native gate and original SQLite lease remain continuously held.
      const cut = native.observe();
      assert(cut.liveFiles > 0);
      for (const role of ['main', 'wal', 'journal', 'lock']) {
        assert.equal(cut.descriptors[role].dev, prepared.descriptors[role].dev);
        assert.equal(cut.descriptors[role].ino, prepared.descriptors[role].ino);
      }
      contend();
      const main = ${JSON.stringify(path.join(directory, 'authority.sqlite'))};
      fs.renameSync(main, main + '-retired');
      fs.renameSync(${JSON.stringify(replacementMain)}, main);
      // New lock+MAIN must not bypass the continuously held original WAL.
      contend();
      const wal = ${JSON.stringify(path.join(directory, 'authority.sqlite-wal'))};
      fs.renameSync(wal, wal + '-retired');
      fs.renameSync(${JSON.stringify(replacementWal)}, wal);
      // New lock+MAIN+WAL must not bypass the original journal either.
      contend();
      assert.throws(() => db.exec('INSERT INTO proof VALUES (19)'), /disk I.O|unable to open/);
      db.close();
      assert.equal(native.observe().fenced, true);
      assert.throws(() => native.retire(), /retained|cannot be retired/);
    `], { cwd: home, env: { ...process.env, HOME: await realpath(home) }, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 });
    assert.equal(primary.error, undefined); assert.equal(primary.signal, null);
    assert.equal(primary.status, 0, primary.stderr + primary.stdout);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
