// Closed SEA storage experiment. No credential/Run authority or release artifact.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync,
  readFileSync, readSync, renameSync, writeFileSync, writeSync, type BigIntStats } from 'node:fs';
import path from 'node:path';
import { getAsset, isSea } from 'node:sea';
import { DatabaseSync } from 'node:sqlite';

const modes = ['normal', 'main_before_open', 'parent_after_open', 'main_after_open',
  'wal_after_open', 'journal_after_open', 'lock_after_open'] as const;
type Mode = typeof modes[number];
type Action = 'seed' | 'mutate' | 'primary' | 'reopen';
type Snapshot = { prepared: boolean; registered: boolean; fenced: boolean; uncertain: boolean;
  retired: boolean; liveFiles: number; defaultUnchanged: boolean; sourceId: string | null;
  counts: Record<string, number>; descriptors: Record<string, { fd: number; dev: string; ino: string } | null> };
type Native = { prepare(): Snapshot; observe(): Snapshot; retire(): Snapshot };
// The diagnostic asserts fixed Node 24.21; the checkout's older typings omit
// that carrier's optional SQLite extension entry point.
type FixedBootstrap = DatabaseSync & { loadExtension(filename: string, entryPoint: string): void };
const leafNames = ['authority.lock', 'authority.sqlite', 'authority.sqlite-wal', 'authority.sqlite-journal'];
const uri = 'file:cliq-credential-authority?vfs=cliq-credential-vfs-probe-v1';

function identity(info: BigIntStats) {
  return { dev: String(info.dev), ino: String(info.ino), size: String(info.size), uid: String(info.uid),
    gid: String(info.gid), mode: String(info.mode), nlink: String(info.nlink),
    mtimeNs: String(info.mtimeNs), ctimeNs: String(info.ctimeNs) };
}

let lifetime: Record<string, unknown> = {};
function output(phase: string, facts: Record<string, unknown> = {}) {
  writeSync(1, JSON.stringify({ protocol: 'cliq-credential-vfs-storage-v1', diagnosticOnly: true,
    ...lifetime, phase, ...facts }) + '\n');
}
function barrier(phase: string, facts: Record<string, unknown>) {
  output(phase, facts);
  const byte = Buffer.alloc(1);
  let token = '';
  while (!token.endsWith('\n') && token.length < 16) {
    assert.equal(readSync(0, byte, 0, 1, null), 1);
    token += byte.toString('ascii');
  }
  assert.equal(token, 'continue\n');
}

// Only fixed proof rows in a fixture. The default VFS is used exclusively by
// the independent seeder, before the owning process acquires any inode guard.
function seed(directory: string, value: string) {
  mkdirSync(directory, { mode: 0o700 });
  const filename = path.join(directory, 'authority.sqlite');
  writeFileSync(filename, '', { flag: 'wx', mode: 0o600 });
  const db = new DatabaseSync(filename, { allowExtension: false });
  try {
    assert.equal(db.prepare('PRAGMA journal_mode=DELETE').get()!.journal_mode, 'delete');
    db.exec('PRAGMA synchronous=FULL; CREATE TABLE proof(id INTEGER PRIMARY KEY, value TEXT NOT NULL); BEGIN IMMEDIATE');
    db.prepare('INSERT INTO proof VALUES(1, ?)').run(value);
    db.exec('COMMIT');
  } finally { db.close(); }
  for (const leaf of leafNames.filter(leaf => leaf !== 'authority.sqlite')) {
    writeFileSync(path.join(directory, leaf), '', { flag: 'wx', mode: 0o600 });
  }
}

function load(): Native {
  const claim = JSON.parse(Buffer.from(getAsset('cliq-credential-vfs-storage-claim')).toString('utf8')) as {
    leaf: string; byteCount: number; sha256: string };
  assert.equal(claim.leaf, 'credential-vfs-probe.node');
  assert(Number.isSafeInteger(claim.byteCount) && claim.byteCount > 0);
  assert.match(claim.sha256, /^[0-9a-f]{64}$/u);
  const filename = path.join(path.dirname(process.execPath), claim.leaf);
  let held: number | undefined = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let bootstrap: FixedBootstrap | undefined;
  try {
    const before = fstatSync(held, { bigint: true });
    assert(before.isFile()); assert.equal(before.uid, 0n); assert.equal(before.gid, 0n);
    assert.equal(before.nlink, 1n); assert.equal(before.mode & 0o7777n, 0o555n);
    assert.equal(before.size, BigInt(claim.byteCount));
    assert.equal(createHash('sha256').update(readFileSync(held)).digest('hex'), claim.sha256);
    const revalidate = () => {
      assert.deepEqual(identity(fstatSync(held!, { bigint: true })), identity(before));
      assert.deepEqual(identity(lstatSync(filename, { bigint: true })), identity(before));
    };
    revalidate();
    const fdPath = `/proc/self/fd/${held}`;
    const loaded = { exports: {} };
    process.dlopen(loaded, fdPath);
    revalidate();
    const native = loaded.exports as Native;
    const prepared = native.prepare();
    assert.equal(prepared.prepared, true); assert.equal(prepared.registered, false);
    bootstrap = new DatabaseSync(':memory:', { allowExtension: true }) as FixedBootstrap;
    bootstrap.loadExtension(fdPath, 'sqlite3_cliqcredentialvfsprobe_init');
    bootstrap.enableLoadExtension(false);
    assert.throws(() => bootstrap!.loadExtension(fdPath, 'sqlite3_cliqcredentialvfsprobe_init'), /extension loading is not allowed/);
    revalidate();
    const consumed = bootstrap; bootstrap = undefined; consumed.close();
    const consumedFd = held; held = undefined; closeSync(consumedFd);
    return native;
  } finally {
    if (bootstrap) { const consumed = bootstrap; bootstrap = undefined; consumed.close(); }
    if (held !== undefined) { const consumed = held; held = undefined; closeSync(consumed); }
  }
}

function database(native: Native) {
  const db = new DatabaseSync(uri, { allowExtension: false });
  assert.equal(db.prepare('PRAGMA locking_mode=EXCLUSIVE').get()!.locking_mode, 'exclusive');
  db.exec('PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL');
  assert.equal(db.prepare('PRAGMA journal_mode=WAL').get()!.journal_mode, 'wal');
  assert.throws(() => db.enableLoadExtension(true), /disabled at database creation/);
  assert.throws(() => db.exec("SELECT load_extension('forbidden')"), /not authorized/);
  const ordinary = new DatabaseSync(':memory:', { allowExtension: false });
  try {
    assert.equal(ordinary.prepare('SELECT sqlite_source_id() AS id').get()!.id, native.observe().sourceId);
    assert.equal(native.observe().defaultUnchanged, true);
  } finally { ordinary.close(); }
  return db;
}

function refusal(operation: () => void) {
  let error: unknown;
  try { operation(); } catch (caught) { error = caught; }
  assert(error instanceof Error, 'replacement must refuse the actual operation');
  const actual = error as Error & { code: string; errcode: number };
  assert.equal(actual.code, 'ERR_SQLITE_ERROR');
  assert([10, 14].includes(actual.errcode & 0xff));
  return { code: actual.code, errcode: actual.errcode, message: actual.message };
}

try {
  assert(isSea()); assert.equal(process.platform, 'linux'); assert.equal(process.version, 'v24.21.0');
  assert(process.geteuid!() > 0); assert.equal(process.getuid!(), process.geteuid!());
  assert.equal(process.getgid!(), process.getegid!()); assert.deepEqual(process.getgroups!(), [process.getegid!()]);
  assert.equal(process.argv.length, 4);
  const action = process.argv[2] as Action, mode = process.argv[3] as Mode;
  assert(['seed', 'mutate', 'primary', 'reopen'].includes(action)); assert(modes.includes(mode));
  if (action === 'reopen') assert.equal(mode, 'normal');
  if (action === 'mutate') assert.notEqual(mode, 'normal');
  const home = process.env.HOME!;
  assert.match(home, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+\/home\/probe\/sqlite-path-cases\/credential-vfs-[a-z_]+$/u);
  assert.equal(path.basename(home), `credential-vfs-${mode}`);
  const homeInfo = lstatSync(home, { bigint: true });
  assert(homeInfo.isDirectory() && !homeInfo.isSymbolicLink());
  assert.equal(homeInfo.uid, BigInt(process.geteuid!())); assert.equal(homeInfo.gid, BigInt(process.getegid!()));
  assert.equal(homeInfo.mode & 0o7777n, 0o700n);
  const startTicks = readFileSync('/proc/self/stat', 'utf8').split(') ').slice(1).join(') ').trim().split(/\s+/u)[19];
  assert.match(startTicks!, /^[1-9][0-9]*$/u);
  lifetime = { action, mode, pid: process.pid, startTicks, uid: process.getuid!(), euid: process.geteuid!(),
    gid: process.getgid!(), egid: process.getegid!(), groups: process.getgroups!(), nodeVersion: process.version };
  const root = path.join(home, 'probe/credential-vfs');
  const credentials = path.join(root, 'credentials'), replacement = path.join(root, 'replacement');
  if (action === 'seed') {
    mkdirSync(path.join(home, 'probe'), { mode: 0o700 }); mkdirSync(root, { mode: 0o700 });
    seed(credentials, 'original'); seed(replacement, 'replacement');
    output('seeded');
  } else if (action === 'mutate') {
    if (mode === 'parent_after_open') {
      renameSync(credentials, path.join(root, 'retired-credentials')); renameSync(replacement, credentials);
    } else {
      const leaf = mode.startsWith('main_') ? 'authority.sqlite' : mode.startsWith('wal_') ? 'authority.sqlite-wal'
        : mode.startsWith('journal_') ? 'authority.sqlite-journal' : 'authority.lock';
      renameSync(path.join(credentials, leaf), path.join(root, `retired-${leaf}`));
      renameSync(path.join(replacement, leaf), path.join(credentials, leaf));
    }
    output('mutated');
  } else {
    const native = load();
    barrier('prepared', { snapshot: native.observe() });
    let db: DatabaseSync | undefined;
    if (mode === 'main_before_open') {
      const error = refusal(() => { db = new DatabaseSync(uri, { allowExtension: false }); });
      db?.close();
      assert.equal(native.observe().fenced, true); assert.equal(native.observe().liveFiles, 0);
      assert.throws(() => native.retire(), /retained|cannot be retired/);
      barrier('refused', { error, snapshot: native.observe() });
    } else {
      db = database(native);
      if (action === 'primary') {
        assert.equal(db.prepare('SELECT value FROM proof WHERE id=1').get()!.value, 'original');
        db.exec("BEGIN IMMEDIATE; UPDATE proof SET value='committed' WHERE id=1; COMMIT");
        db.exec("BEGIN IMMEDIATE; UPDATE proof SET value='rolled-back' WHERE id=1; ROLLBACK");
      }
      assert.equal(db.prepare('SELECT value FROM proof WHERE id=1').get()!.value, 'committed');
      barrier('opened', { value: 'committed', snapshot: native.observe() });
      if (mode === 'normal') {
        assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
        const consumed = db; db = undefined; consumed.close();
        assert.equal(native.observe().liveFiles, 0); native.retire();
        assert.equal(native.observe().prepared, false); assert.equal(native.observe().retired, true);
        barrier('retired', { snapshot: native.observe() });
      } else {
        const error = refusal(() => db!.exec("BEGIN IMMEDIATE; UPDATE proof SET value='forbidden' WHERE id=1; COMMIT"));
        const consumed = db; db = undefined; consumed.close();
        assert.equal(native.observe().fenced, true); assert.equal(native.observe().liveFiles, 0);
        assert.throws(() => native.retire(), /retained|cannot be retired/);
        barrier('refused', { error, snapshot: native.observe() });
      }
    }
    output('completed', { productionCredentialAuthorityQualified: false, installedI1Qualified: false,
      powerLossDurabilityQualified: false });
  }
} catch (error) { output('fatal', { error: String((error as Error).stack ?? error) }); process.exitCode = 1; }
