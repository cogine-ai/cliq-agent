// SEA-only, test-only path diagnostic. No credential authority or production role.
import assert from 'node:assert/strict';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  readSync, renameSync, writeSync, type BigIntStats } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { isSea } from 'node:sea';
import { openSqliteDriver, type SqliteDriver } from '../../../src/state/sqlite-driver.js';

type PathKind = 'canonical' | 'held_parent';
type Cut = 'normal' | 'parent_before_open' | 'parent_after_open' | 'leaf_before_open';
const protocol = 'cliq-sqlite-path-v1';
const cuts: Cut[] = ['normal', 'parent_before_open', 'parent_after_open', 'leaf_before_open'];
const json = (value: unknown) => JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? String(item) : item);
function output(phase: string, facts: Record<string, unknown> = {}) {
  writeSync(1, json({ protocol, diagnosticOnly: true, phase, ...facts }) + '\n');
}
function barrier(phase: string, facts: Record<string, unknown> = {}) {
  output(phase, facts);
  // The one outstanding barrier accepts one fixed token, never code or paths.
  let input = '';
  const byte = Buffer.alloc(1);
  while (!input.endsWith('\n') && input.length < 16) {
    assert.equal(readSync(0, byte, 0, 1, null), 1, 'diagnostic orchestrator ended before joined close');
    input += byte.toString('ascii');
  }
  assert.equal(input, 'continue\n', 'invalid diagnostic continuation');
}
function identity(metadata: BigIntStats) {
  return { dev: String(metadata.dev), ino: String(metadata.ino), size: String(metadata.size),
    uid: String(metadata.uid), gid: String(metadata.gid), mode: String(metadata.mode),
    nlink: String(metadata.nlink), mtimeNs: String(metadata.mtimeNs), ctimeNs: String(metadata.ctimeNs) };
}
function privateDirectory(filename: string) {
  const info = lstatSync(filename, { bigint: true });
  assert(info.isDirectory() && !info.isSymbolicLink());
  assert.equal(info.uid, BigInt(process.geteuid!())); assert.equal(info.gid, BigInt(process.getegid!()));
  assert.equal(info.mode & 0o7777n, 0o700n);
  return info;
}
function privateDatabase(filename: string) {
  const info = lstatSync(filename, { bigint: true });
  assert(info.isFile() && !info.isSymbolicLink()); assert.equal(info.nlink, 1n);
  assert.equal(info.uid, BigInt(process.geteuid!())); assert.equal(info.gid, BigInt(process.getegid!()));
  assert.equal(info.mode & 0o7777n, 0o600n);
  return info;
}
function lifetime() {
  const value = readFileSync('/proc/self/stat', 'utf8');
  const fields = value.slice(value.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert.match(fields[19]!, /^[1-9][0-9]*$/u);
  return { pid: process.pid, startTicks: fields[19], uid: process.getuid!(), euid: process.geteuid!(),
    gid: process.getgid!(), egid: process.getegid!(), groups: process.getgroups!(), nodeVersion: process.version };
}
function physicalPaths(caseDirectory: string, cut: Cut) {
  return cut === 'leaf_before_open'
    ? { original: path.join(caseDirectory, 'credentials/original-authority.sqlite'),
      replacement: path.join(caseDirectory, 'credentials/authority.sqlite') }
    : cut === 'parent_before_open' || cut === 'parent_after_open'
      ? { original: path.join(caseDirectory, 'retired-credentials/authority.sqlite'),
        replacement: path.join(caseDirectory, 'credentials/authority.sqlite') }
      : { original: path.join(caseDirectory, 'credentials/authority.sqlite'),
        replacement: path.join(caseDirectory, 'replacement/authority.sqlite') };
}

function seed(caseDirectory: string) {
  mkdirSync(caseDirectory, { mode: 0o700 });
  for (const [directory, marker] of [['credentials', 'A'], ['replacement', 'B']] as const) {
    const parent = path.join(caseDirectory, directory);
    mkdirSync(parent, { mode: 0o700 });
    const filename = path.join(parent, 'authority.sqlite');
    const db = openSqliteDriver(filename);
    try {
      db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE diagnostic_marker(value TEXT NOT NULL); '
        + 'CREATE TABLE diagnostic_writes(kind TEXT PRIMARY KEY, marker TEXT NOT NULL)');
      db.transaction(connection => connection.prepare('INSERT INTO diagnostic_marker VALUES (?)').run(marker));
    } finally { db.close(); }
    privateDirectory(parent); privateDatabase(filename);
  }
  output('seeded', { ...lifetime(), original: identity(privateDatabase(path.join(caseDirectory, 'credentials/authority.sqlite'))),
    replacement: identity(privateDatabase(path.join(caseDirectory, 'replacement/authority.sqlite'))) });
}
function mutate(caseDirectory: string, cut: Cut) {
  assert.notEqual(cut, 'normal');
  privateDirectory(caseDirectory);
  privateDirectory(path.join(caseDirectory, 'credentials')); privateDirectory(path.join(caseDirectory, 'replacement'));
  privateDatabase(path.join(caseDirectory, 'credentials/authority.sqlite'));
  privateDatabase(path.join(caseDirectory, 'replacement/authority.sqlite'));
  if (cut === 'leaf_before_open') {
    renameSync(path.join(caseDirectory, 'credentials/authority.sqlite'), path.join(caseDirectory, 'credentials/original-authority.sqlite'));
    renameSync(path.join(caseDirectory, 'replacement/authority.sqlite'), path.join(caseDirectory, 'credentials/authority.sqlite'));
  } else {
    renameSync(path.join(caseDirectory, 'credentials'), path.join(caseDirectory, 'retired-credentials'));
    renameSync(path.join(caseDirectory, 'replacement'), path.join(caseDirectory, 'credentials'));
  }
  const targets = physicalPaths(caseDirectory, cut);
  output('mutated', { ...lifetime(), original: identity(privateDatabase(targets.original)),
    replacement: identity(privateDatabase(targets.replacement)) });
}
function reopen(caseDirectory: string, cut: Cut, target: 'original' | 'replacement') {
  const filename = physicalPaths(caseDirectory, cut)[target];
  privateDirectory(path.dirname(filename));
  const before = privateDatabase(filename);
  // This runs only after the entire traced primary has joined. Read-only does
  // not mean a VFS never touches sidecars; the orchestrator records both cuts.
  const db = new DatabaseSync(filename, { readOnly: true, allowExtension: false,
    enableDoubleQuotedStringLiterals: false, enableForeignKeyConstraints: true });
  let facts: Record<string, unknown>;
  try {
    facts = { filename, identity: identity(before), marker: db.prepare('SELECT value FROM diagnostic_marker').get(),
      writes: db.prepare('SELECT kind, marker FROM diagnostic_writes ORDER BY kind').all(),
      integrity: db.prepare('PRAGMA integrity_check').all(), sqliteVersion: db.prepare('SELECT sqlite_version() AS version').get() };
  } finally { db.close(); }
  output('reopened', { ...lifetime(), target, ...facts!, after: identity(privateDatabase(filename)) });
}
function primary(caseDirectory: string, pathKind: PathKind, cut: Cut) {
  const ownLifetime = lifetime();
  const parentPath = path.join(caseDirectory, 'credentials');
  const originalPath = path.join(parentPath, 'authority.sqlite');
  const beforeParent = privateDirectory(parentPath); const beforeDb = privateDatabase(originalPath);
  const parentFd = openSync(parentPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let originalFd: number | undefined;
  let db: SqliteDriver | undefined;
  let connectionClosed = true;
  let outcome: Record<string, unknown> = {};
  try {
    originalFd = openSync(originalPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    assert.equal(fstatSync(parentFd, { bigint: true }).ino, beforeParent.ino);
    assert.equal(fstatSync(originalFd, { bigint: true }).ino, beforeDb.ino);
    const databasePath = pathKind === 'canonical' ? originalPath : `/proc/self/fd/${parentFd}/authority.sqlite`;
    // Referenced only by the uniquely transformed diagnostic bundle, never
    // by unchanged production source. The callback cannot choose a new path.
    (globalThis as typeof globalThis & { __cliqSqlitePathPreopen?: () => void }).__cliqSqlitePathPreopen = () => {
      barrier('preopen', { ...ownLifetime, databasePath, parentFd, originalFd,
        parent: identity(fstatSync(parentFd, { bigint: true })), original: identity(fstatSync(originalFd!, { bigint: true })) });
    };
    db = openSqliteDriver(databasePath); connectionClosed = false;
    const marker = db.prepare('SELECT value FROM diagnostic_marker').get<{ value: string }>()!.value;
    barrier('after_open', { marker, databaseList: db.prepare('PRAGMA database_list').all(),
      sqliteVersion: db.prepare('SELECT sqlite_version() AS version').get() });
    db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=500');
    db.transaction(connection => {
      connection.prepare('INSERT INTO diagnostic_writes VALUES (?, ?)').run('delete-committed', marker);
      barrier('delete_active');
    });
    const rollback = new Error('fixed diagnostic rollback');
    assert.throws(() => db!.transaction(connection => {
      connection.prepare('INSERT INTO diagnostic_writes VALUES (?, ?)').run('delete-rollback', marker);
      throw rollback;
    }), error => error === rollback);
    const wal = db.prepare('PRAGMA journal_mode=WAL').get();
    assert.equal(wal?.journal_mode, 'wal', 'requested WAL must actually be active');
    barrier('wal_open', { wal });
    db.transaction(connection => {
      connection.prepare('INSERT INTO diagnostic_writes VALUES (?, ?)').run('wal-committed', marker);
      barrier('wal_active');
    });
    barrier('wal_committed', { writes: db.prepare('SELECT kind, marker FROM diagnostic_writes ORDER BY kind').all() });
    const checkpoint = db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').all();
    assert.equal(checkpoint.length, 1); assert.equal(checkpoint[0]!.busy, 0n);
    assert.equal(checkpoint[0]!.log, 0n); assert.equal(checkpoint[0]!.checkpointed, 0n);
    barrier('checkpointed', { checkpoint });
    outcome = { operation: 'completed', marker, checkpoint };
  } catch (error) {
    outcome = { operation: 'refused_or_failed', error: String((error as Error).message),
      code: (error as NodeJS.ErrnoException).code ?? null };
  } finally {
    delete (globalThis as typeof globalThis & { __cliqSqlitePathPreopen?: () => void }).__cliqSqlitePathPreopen;
    // Any extra descriptor for this database can release the process's POSIX
    // SQLite locks when closed. Never retire it before every connection closes.
    try { db?.close(); connectionClosed = true; }
    finally {
      if (connectionClosed && originalFd !== undefined) closeSync(originalFd);
      closeSync(parentFd);
    }
  }
  // Do not reopen /proc/self/stat after close: it could reuse a just-retired
  // database/directory number and obscure the independently traced close cut.
  output('outcome', { ...outcome, closeOrder: 'sqlite_then_extra_database_fd_then_parent_fd', ...ownLifetime });
}

try {
  assert(isSea(), 'diagnostic must execute the compiled SEA, not an ordinary module');
  assert.equal(process.platform, 'linux'); assert.equal(process.version, 'v24.21.0');
  assert(process.geteuid!() > 0 && process.getuid!() === process.geteuid!());
  assert.equal(process.getgid!(), process.getegid!());
  assert.deepEqual(process.getgroups!(), [process.getegid!()]);
  process.umask(0o077);
  const [mode, caseDirectory, pathKind, cut, target] = process.argv.slice(2);
  assert(['--seed', '--mutate', '--primary', '--reopen'].includes(mode!));
  assert.equal(process.argv.length, mode === '--reopen' ? 7 : 6);
  assert.match(caseDirectory!, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+\/home\/probe\/sqlite-path-cases\/(canonical|held_parent)-(normal|parent_before_open|parent_after_open|leaf_before_open)$/u);
  assert(['canonical', 'held_parent'].includes(pathKind!)); assert(cuts.includes(cut as Cut));
  assert.equal(path.basename(caseDirectory!), `${pathKind}-${cut}`);
  privateDirectory(path.dirname(caseDirectory!));
  if (mode === '--seed') { assert.equal(target, undefined); seed(caseDirectory!); }
  else {
    privateDirectory(caseDirectory!);
    if (mode === '--mutate') { assert.equal(target, undefined); mutate(caseDirectory!, cut as Cut); }
    else if (mode === '--primary') { assert.equal(target, undefined); primary(caseDirectory!, pathKind as PathKind, cut as Cut); }
    else { assert(['original', 'replacement'].includes(target!)); reopen(caseDirectory!, cut as Cut, target as 'original' | 'replacement'); }
  }
} catch (error) {
  output('fatal', { error: String((error as Error).message) });
  process.exitCode = 1;
}
