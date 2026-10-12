// Local candidate recovery conformance only: SIGKILL is not power loss, and
// this is not signed-install, fresh-UID, physical-storage or credential qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildCredentialVfsProbe } from './sqlite-vfs-mechanism-build.js';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

type Cut = { phase: string; before?: { writes: number; syncs: number }; beforeCommitSyncs?: number;
  after?: { writes: number; syncs: number } };
type Identity = { dev: bigint; ino: bigint };
const recordCount = 64;

function run(carrier: string, source: string, home: string) {
  const child = spawnSync(carrier, ['--no-warnings', '-e', source], {
    cwd: home, env: { ...process.env, HOME: home }, encoding: 'utf8', timeout: 15000, maxBuffer: 65536,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.signal, null);
  assert.equal(child.status, 0, child.stderr + child.stdout);
  return child.stdout;
}

async function identity(file: string): Promise<Identity> {
  const info = await lstat(file, { bigint: true });
  assert(info.isFile());
  assert.equal(info.nlink, 1n);
  assert.equal(info.mode & 0o7777n, 0o600n);
  return { dev: info.dev, ino: info.ino };
}

/** Kill only after real SQL reaches the barrier, then join before reopening. */
async function killWriter(carrier: string, source: string, home: string, inspect: (cut: Cut) => Promise<void>) {
  const child = spawn(carrier, ['--no-warnings', '-e', source], {
    cwd: home, env: { ...process.env, HOME: home }, stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 15000, killSignal: 'SIGKILL',
  });
  let output = '', errors = '';
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  // A spawn error can precede the ready waiter; retain it without an unhandled rejection.
  void joined.catch(() => {});
  let rejectReady: (error: Error) => void = () => {};
  const ready = new Promise<Cut>((resolve, reject) => {
    rejectReady = reject;
    child.once('error', reject);
    child.once('close', (code, signal) => reject(new Error(`writer exited before kill: ${code}/${signal}: ${errors}${output}`)));
    child.stderr!.on('data', (chunk: Buffer) => {
      errors += chunk.toString('utf8');
      if (errors.length > 65536) reject(new Error('writer stderr exceeded bound'));
    });
    child.stdout!.on('data', (chunk: Buffer) => {
      output += chunk.toString('utf8');
      if (output.length > 65536) { reject(new Error('writer stdout exceeded bound')); return; }
      const end = output.indexOf('\n');
      if (end >= 0) {
        try { resolve(JSON.parse(output.slice(0, end)) as Cut); }
        catch (error) { reject(error); }
      }
    });
  });
  const watchdog = setTimeout(() => {
    rejectReady(new Error(`writer barrier timed out: ${errors}${output}`));
    child.kill('SIGKILL');
  }, 12000);
  try {
    await inspect(await ready);
    assert(child.kill('SIGKILL'), 'writer must still be alive at the verified cut');
    const exit = await joined;
    assert.equal(exit.code, null);
    assert.equal(exit.signal, 'SIGKILL');
  } finally {
    clearTimeout(watchdog);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await joined;
  }
}

function privateDatabase(helper: string) {
  return `
    const assert = require('node:assert/strict');
    const fs = require('node:fs');
    const {DatabaseSync} = require('node:sqlite');
    const loaded = {exports:{}};
    process.dlopen(loaded, ${JSON.stringify(helper)});
    const native = loaded.exports;
    const prepared = native.prepare();
    const bootstrap = new DatabaseSync(':memory:', {allowExtension:true});
    bootstrap.loadExtension(${JSON.stringify(helper)}, 'sqlite3_cliqcredentialvfsprobe_init');
    bootstrap.enableLoadExtension(false); bootstrap.close();
    const db = new DatabaseSync('file:cliq-credential-authority?vfs=cliq-credential-vfs-probe-v1', {allowExtension:false});
    assert.equal(db.prepare('PRAGMA locking_mode=EXCLUSIVE').get().locking_mode, 'exclusive');
    db.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA synchronous=FULL; PRAGMA cache_size=1; PRAGMA cache_spill=ON; PRAGMA wal_autocheckpoint=0');
    assert.equal(db.prepare('PRAGMA journal_mode=WAL').get().journal_mode, 'wal');
  `;
}

test('descriptor VFS recovers genuine hot DELETE and spilled WAL transactions after joined SIGKILL', { timeout: 180000 }, async (t) => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-vfs-crash-'));
  try {
    // The carrier is checksum-verified and freshly extracted, once per fixture.
    const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
    const built = await buildCredentialVfsProbe(fixture, carrier.nodeRoot);
    for (const mode of ['hot-delete', 'wal-uncommitted', 'wal-committed'] as const) {
      await t.test(mode, async () => {
        const requestedHome = path.join(fixture, mode);
        const directory = path.join(requestedHome, 'probe/credential-vfs/credentials');
        await mkdir(directory, { recursive: true, mode: 0o700 });
        for (const parent of [requestedHome, path.join(requestedHome, 'probe'), path.dirname(directory), directory]) {
          await chmod(parent, 0o700);
        }
        const home = await realpath(requestedHome);
        const main = path.join(directory, 'authority.sqlite');
        const journal = `${main}-journal`;
        const wal = `${main}-wal`;
        await writeFile(main, '', { flag: 'wx', mode: 0o600 });
        // A separate real default engine seeds DELETE mode before any native guard.
        run(carrier.carrier, `
          const assert = require('node:assert/strict');
          const {DatabaseSync} = require('node:sqlite');
          const db = new DatabaseSync(${JSON.stringify(main)}, {allowExtension:false});
          db.exec('PRAGMA page_size=4096; PRAGMA synchronous=FULL');
          assert.equal(db.prepare('PRAGMA journal_mode=DELETE').get().journal_mode, 'delete');
          db.exec('CREATE TABLE proof(id INTEGER PRIMARY KEY, revision INTEGER NOT NULL, payload TEXT NOT NULL); BEGIN IMMEDIATE');
          const insert = db.prepare('INSERT INTO proof VALUES (?, 0, ?)');
          for (let id=1; id<=${recordCount}; id++) insert.run(id, 'A'.repeat(8192));
          db.exec('COMMIT'); db.close();
        `, home);
        const originalMain = await readFile(main);
        let originalJournal: Identity | undefined;
        const beforeRecovery: Record<string, Identity> = {};
        const writer = mode === 'hot-delete' ? `
          const assert = require('node:assert/strict');
          const {DatabaseSync} = require('node:sqlite');
          const db = new DatabaseSync(${JSON.stringify(main)}, {allowExtension:false});
          assert.equal(db.prepare('PRAGMA journal_mode=DELETE').get().journal_mode, 'delete');
          db.exec('PRAGMA synchronous=FULL; PRAGMA cache_size=1; PRAGMA cache_spill=ON; BEGIN IMMEDIATE');
          db.prepare('UPDATE proof SET revision=1, payload=?').run('B'.repeat(8192));
          require('node:fs').writeSync(1, JSON.stringify({phase:'hot-delete'}) + '\\n');
          setTimeout(() => { process.stderr.write('writer was not killed at barrier: ' + String(db)); process.exit(97); }, 15000);
        ` : privateDatabase(built.helper) + `
          const before = native.observe().counts;
          db.exec('BEGIN IMMEDIATE');
          db.prepare('UPDATE proof SET revision=1, payload=?').run('B'.repeat(8192));
          // First WAL spill may sync its header; isolate the COMMIT itself.
          const beforeCommitSyncs = native.observe().counts.syncs;
          ${mode === 'wal-committed' ? "db.exec('COMMIT');" : ''}
          const after = native.observe().counts;
          assert(after.writes > before.writes, 'transaction must spill through real native writes');
          ${mode === 'wal-committed' ? "assert(after.syncs > beforeCommitSyncs, 'FULL commit itself must sync through native I/O');" : ''}
          fs.writeSync(1, JSON.stringify({phase:${JSON.stringify(mode)}, before, beforeCommitSyncs, after}) + '\\n');
          setTimeout(() => { process.stderr.write('writer was not killed at barrier: ' + String(db)); process.exit(97); }, 15000);
        `;
        await killWriter(carrier.carrier, writer, home, async (cut) => {
          assert.equal(cut.phase, mode);
          beforeRecovery['authority.sqlite'] = await identity(main);
          beforeRecovery['authority.sqlite-journal'] = await identity(journal);
          if (mode === 'hot-delete') {
            // Independent raw observations; the owning child never duplicates its data FD.
            // Genuine header format: https://www.sqlite.org/fileformat2.html#the_rollback_journal
            const bytes = await readFile(journal);
            assert(bytes.length > 512, 'real rollback journal must contain page records');
            assert.equal(bytes.subarray(0, 8).toString('hex'), 'd9d505f920a163d7');
            assert(bytes.readUInt32BE(8) > 0, 'spilled journal must have a nonzero page count');
            assert.equal(bytes.readUInt32BE(24), 4096);
            assert(!(await readFile(main)).equals(originalMain), 'uncommitted spill must have changed actual MAIN bytes');
            originalJournal = beforeRecovery['authority.sqlite-journal'];
          } else {
            assert(cut.before && cut.after);
            assert(cut.after.writes > cut.before.writes);
            if (mode === 'wal-committed') {
              assert.equal(typeof cut.beforeCommitSyncs, 'number');
              assert(cut.after.syncs > cut.beforeCommitSyncs!);
            }
            const bytes = await readFile(wal);
            assert(bytes.length > 32 + 24 + 4096, 'real WAL must contain spilled frames');
            assert([0x377f0682, 0x377f0683].includes(bytes.readUInt32BE(0)));
            beforeRecovery['authority.sqlite-wal'] = await identity(wal);
          }
        });
        const expectedRevision = mode === 'wal-committed' ? 1 : 0;
        const recovered = JSON.parse(run(carrier.carrier, privateDatabase(built.helper) + `
          const rows = db.prepare('SELECT id, revision, payload FROM proof ORDER BY id').all();
          assert.equal(rows.length, ${recordCount});
          for (let i=0; i<rows.length; i++) {
            assert.equal(rows[i].id, i+1);
            assert.equal(rows[i].revision, ${expectedRevision});
            assert.equal(rows[i].payload, ${expectedRevision === 1 ? "'B'" : "'A'"}.repeat(8192));
          }
          assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
          ${mode === 'hot-delete' ? "assert(native.observe().counts.journalRetirements > 0, 'hot journal must be logically retired');" : ''}
          db.close();
          const beforeRetire = native.observe();
          assert.equal(beforeRetire.liveFiles, 0);
          assert.equal(beforeRetire.fenced, false); assert.equal(beforeRetire.uncertain, false);
          for (const role of ['main', 'wal', 'journal']) {
            assert.equal(beforeRetire.descriptors[role].dev, prepared.descriptors[role].dev);
            assert.equal(beforeRetire.descriptors[role].ino, prepared.descriptors[role].ino);
          }
          native.retire();
          fs.writeSync(1, JSON.stringify({beforeRetire, afterRetire:native.observe()}));
        `, home));
        assert.equal(recovered.afterRetire.prepared, false);
        for (const [leaf, held] of Object.entries(beforeRecovery)) {
          assert.deepEqual(await identity(path.join(directory, leaf)), held);
        }
        if (originalJournal) {
          assert.deepEqual(await identity(journal), originalJournal);
          assert.equal((await lstat(journal)).size, 0);
        }
        assert.deepEqual((await readdir(directory)).sort(), [
          'authority.lock', 'authority.sqlite', 'authority.sqlite-journal', 'authority.sqlite-wal',
        ]);
      });
    }
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
