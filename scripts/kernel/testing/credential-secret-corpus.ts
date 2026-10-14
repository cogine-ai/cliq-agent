// Test-private byte qualification. These are copied diagnostic SQLite reads,
// never a production connection, credential authority or recovery decision.
import { constants, lstatSync, type BigIntStats } from 'node:fs';
import { lstat, mkdtemp, open, opendir, rm, writeFile, type FileHandle } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { iterateNodeSqliteStatement } from '../../../src/state/sqlite-driver.js';
import { CredentialSecretScanError, type CredentialSecretScanner } from './credential-secret-scan.js';

const chunkBytes = 64 * 1024, sqliteLimit = 16 * 1024 * 1024, fileLimit = 512 * 1024 * 1024;
const entryLimit = 1024, rowLimit = 8192, cellLimit = 65536;
type DatabaseFailureStage = 'open' | 'configure' | 'schema' | 'prepare' | 'rows' | 'stability';
type DatabaseFailureClass = 'sqlite_error' | 'sqlite_busy' | 'sqlite_locked' | 'sqlite_io' | 'sqlite_corrupt'
  | 'sqlite_readonly' | 'sqlite_not_database' | 'out_of_range' | 'type_error' | 'other';
export class CredentialSecretCorpusError extends Error {
  constructor(readonly databaseFailure?: Readonly<{ database: 'kernel' | 'authority'; stage: DatabaseFailureStage; errorClass: DatabaseFailureClass }>) {
    super('credential secret corpus did not qualify'); this.name = 'CredentialSecretCorpusError';
  }
}
function refused(): never { throw new CredentialSecretCorpusError(); }
function check(value: unknown): asserts value { if (!value) refused(); }
const identity = (info: BigIntStats) => [info.dev, info.ino, info.uid, info.gid, info.mode, info.nlink,
  info.size, info.mtimeNs, info.ctimeNs].join(':');
const directoryIdentity = (info: BigIntStats) => [info.dev, info.ino, info.uid, info.gid, info.mode].join(':');
type Directory = { handle: FileHandle; physicalPath: string; info: BigIntStats };
type Stats = { filesScanned: number; fileBytesScanned: number; sqliteDatabasesScanned: number;
  logicalRowsScanned: number; logicalValuesScanned: number; logicalBytesScanned: number; evidenceDirectoriesScanned: number };
function scanValue(scanner: CredentialSecretScanner, bytes: Uint8Array): void {
  const stream = scanner.openStream();
  try { for (let offset = 0; offset < bytes.length; offset += chunkBytes) stream.scan(bytes.subarray(offset, offset + chunkBytes)); }
  finally { stream.close(); }
}

/** Read-only default-engine diagnostics of a caller-owned COPY. Reading
 * logical values additionally catches a secret split across SQLite pages.
 * Nothing here accepts a retained object as proof or rehashes secret bytes. */
export function scanCopiedCredentialDatabase(filename: string, scanner: CredentialSecretScanner) {
  let database: DatabaseSync | undefined;
  let stage: DatabaseFailureStage = 'open';
  let logicalRowsScanned = 0, logicalValuesScanned = 0, logicalBytesScanned = 0;
  try {
    check(typeof filename === 'string');
    check(path.isAbsolute(filename) && path.normalize(filename) === filename &&
      /^cliq-credential-corpus-[A-Za-z0-9]+$/u.test(path.basename(path.dirname(filename))) &&
      ['authority.sqlite', 'kernel.sqlite3'].includes(path.basename(filename)));
    const directory = lstatSync(path.dirname(filename), { bigint: true }), original = lstatSync(filename, { bigint: true });
    check(directory.isDirectory() && !directory.isSymbolicLink() && directory.uid === BigInt(process.geteuid!()) &&
      (directory.mode & 0o7777n) === 0o700n);
    check(original.isFile() && !original.isSymbolicLink() && original.uid === directory.uid && original.nlink === 1n &&
      (original.mode & 0o7777n) === 0o600n && original.size <= BigInt(sqliteLimit));
    database = new DatabaseSync(filename, { readOnly: true, allowExtension: false });
    stage = 'configure';
    database.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON');
    stage = 'schema';
    const tables = database.prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' LIMIT 65").all();
    check(tables.length > 0 && tables.length <= 64);
    const scan = (value: unknown) => {
      if (typeof value !== 'string' && !(value instanceof Uint8Array)) return;
      const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
      try {
        check(bytes.length <= sqliteLimit && ++logicalValuesScanned <= cellLimit);
        logicalBytesScanned += bytes.length; check(logicalBytesScanned <= 128 * 1024 * 1024);
        scanValue(scanner, bytes);
      } finally { bytes.fill(0); }
    };
    for (const table of tables) {
      check(typeof table.name === 'string' && /^[a-z][a-z0-9_]{0,63}$/u.test(table.name));
      check(typeof table.sql === 'string' && /^CREATE TABLE\s/iu.test(table.sql));
      scan(table.name); scan(table.sql);
      const query = `SELECT * FROM "${table.name}"`;
      stage = 'prepare'; const statement = database.prepare(query);
      // INTEGER cells are not byte needles. Preserve SQLite's whole signed
      // 64-bit domain so conversion cannot stop the following TEXT/BLOB scan.
      statement.setReadBigInts(true);
      stage = 'rows';
      for (const row of iterateNodeSqliteStatement(statement)) {
        check(++logicalRowsScanned <= rowLimit);
        for (const value of Object.values(row)) scan(value);
      }
      // Node 22.13's iterator does not retain its statement. Keep the actual
      // owner live through iteration and reject a finalized/mismatched query;
      // a temporary prepare(...).iterate() can lose it during scanning's GC.
      check(statement.sourceSQL === query);
    }
    stage = 'stability';
    check(identity(lstatSync(filename, { bigint: true })) === identity(original));
    check(directoryIdentity(lstatSync(path.dirname(filename), { bigint: true })) === directoryIdentity(directory));
    return Object.freeze({ logicalRowsScanned, logicalValuesScanned, logicalBytesScanned });
  } catch (error) {
    if (error instanceof CredentialSecretScanError || error instanceof CredentialSecretCorpusError) throw error;
    // Keep only a closed code class and source-owned stage, never SQLite's
    // messages, input, table/column names, paths, numeric values or causes.
    const code = error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'code')?.value : undefined;
    const engineCode = error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'errcode')?.value : undefined;
    const sqliteClasses: Readonly<Record<number, DatabaseFailureClass>> = { 5: 'sqlite_busy', 6: 'sqlite_locked',
      8: 'sqlite_readonly', 10: 'sqlite_io', 11: 'sqlite_corrupt', 26: 'sqlite_not_database' };
    const errorClass: DatabaseFailureClass = code === 'ERR_SQLITE_ERROR'
      ? typeof engineCode === 'number' && Number.isSafeInteger(engineCode) && engineCode >= 0 && engineCode <= 65535
        ? sqliteClasses[engineCode & 255] ?? 'sqlite_error' : 'sqlite_error'
      : code === 'ERR_OUT_OF_RANGE' ? 'out_of_range' : error instanceof TypeError ? 'type_error' : 'other';
    throw new CredentialSecretCorpusError(Object.freeze({ database: path.basename(filename) === 'kernel.sqlite3' ? 'kernel' : 'authority', stage, errorClass }));
  } finally { try { database?.close(); } catch { refused(); } }
}

export type CredentialSecretCorpusInput = Readonly<{ stateRoot: string; uid: number;
  evidenceDirs: readonly string[]; scanner: CredentialSecretScanner }>;

/** Invoke after all fixture credential writers and Supervisor/keeper have
 * positively joined. Linux /proc descriptor paths pin every ancestor without
 * following a directory symlink. Only fixed SQLite files, flat CAS names and
 * explicitly supplied sibling crash trace directories are in scope. */
export async function scanCredentialSecretCorpus(input: CredentialSecretCorpusInput) {
  const directories: Directory[] = [];
  const observedFiles: { directory: Directory; leaf: string; info?: BigIntStats }[] = [];
  const stats: Stats = { filesScanned: 0, fileBytesScanned: 0, sqliteDatabasesScanned: 0,
    logicalRowsScanned: 0, logicalValuesScanned: 0, logicalBytesScanned: 0, evidenceDirectoriesScanned: 0 };
  const deadline = performance.now() + 60000;
  const bounded = () => check(performance.now() < deadline && stats.filesScanned <= 2048);
  const descriptorPath = (directory: Directory, leaf = '') => path.join(`/proc/self/fd/${directory.handle.fd}`, leaf);
  const current = async (directory: Directory, exact = false) => {
    const held = await directory.handle.stat({ bigint: true });
    const visible = await lstat(directory.physicalPath, { bigint: true });
    check(held.isDirectory() && visible.isDirectory() && !visible.isSymbolicLink());
    check(directoryIdentity(held) === directoryIdentity(directory.info) && directoryIdentity(visible) === directoryIdentity(directory.info));
    if (exact) check(identity(held) === identity(directory.info) && identity(visible) === identity(directory.info));
  };
  const openDirectory = async (physicalPath: string, parent?: Directory, leaf?: string): Promise<Directory> => {
    bounded(); if (parent) await current(parent);
    const filename = parent ? descriptorPath(parent, leaf) : physicalPath;
    const before = await lstat(filename, { bigint: true }); check(before.isDirectory() && !before.isSymbolicLink());
    const handle = await open(filename, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const directory = { handle, physicalPath, info: before }; directories.push(directory);
    check(identity(await handle.stat({ bigint: true })) === identity(before));
    if (parent) await current(parent); await current(directory); return directory;
  };
  const absoluteDirectory = async (filename: string) => {
    check(path.isAbsolute(filename) && path.normalize(filename) === filename && !filename.includes('\0'));
    let directory = await openDirectory('/');
    for (const component of filename.split('/').filter(Boolean)) directory = await openDirectory(path.join(directory.physicalPath, component), directory, component);
    return directory;
  };
  const names = async (directory: Directory) => {
    await current(directory); const entries: string[] = [];
    // Streaming enumeration is bounded; readdir would allocate all entries.
    const opened = await opendir(descriptorPath(directory));
    try { for (;;) { const entry = await opened.read(); if (!entry) break; check(entries.length < entryLimit); entries.push(entry.name); } }
    finally { await opened.close(); }
    await current(directory, true); return entries.sort();
  };
  const file = async (directory: Directory, leaf: string, options: { mode: readonly bigint[]; links?: readonly bigint[];
    limit: number; optional?: boolean; copy?: boolean }) => {
    bounded(); await current(directory);
    const filename = descriptorPath(directory, leaf);
    let before: BigIntStats;
    try { before = await lstat(filename, { bigint: true }); }
    catch (error) { if (options.optional && (error as NodeJS.ErrnoException).code === 'ENOENT') {
      observedFiles.push({ directory, leaf }); return undefined;
    } throw error; }
    check(before.isFile() && !before.isSymbolicLink() && before.uid === BigInt(input.uid) &&
      options.mode.includes(before.mode & 0o7777n) && (options.links ?? [1n]).includes(before.nlink) &&
      before.size >= 0n && before.size <= BigInt(options.limit));
    const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const chunk = Buffer.alloc(chunkBytes);
    let stream: ReturnType<CredentialSecretScanner['openStream']> | undefined;
    let copied: Buffer | undefined;
    try {
      check(identity(await handle.stat({ bigint: true })) === identity(before));
      stream = input.scanner.openStream();
      if (options.copy) copied = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < Number(before.size)) {
        bounded(); const { bytesRead } = await handle.read(chunk, 0, Math.min(chunk.length, Number(before.size) - offset), offset);
        check(bytesRead > 0); stream.scan(chunk.subarray(0, bytesRead)); copied?.set(chunk.subarray(0, bytesRead), offset);
        offset += bytesRead; stats.fileBytesScanned += bytesRead;
      }
      check((await handle.read(chunk, 0, 1, offset)).bytesRead === 0);
      check(identity(await handle.stat({ bigint: true })) === identity(before) && identity(await lstat(filename, { bigint: true })) === identity(before));
      await current(directory, true); stats.filesScanned++; observedFiles.push({ directory, leaf, info: before }); return copied ?? Buffer.alloc(0);
    } catch (error) { copied?.fill(0); throw error; }
    finally { chunk.fill(0); stream?.close(); await handle.close(); }
  };
  let snapshot: string | undefined;
  try {
    check(process.platform === 'linux' && Number.isSafeInteger(input.uid) && input.uid > 0);
    check(/^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+\/home\/probe\/credential-state$/u.test(input.stateRoot));
    check(Array.isArray(input.evidenceDirs) && input.evidenceDirs.length <= 16 && new Set(input.evidenceDirs).size === input.evidenceDirs.length);
    const fixture = path.resolve(input.stateRoot, '../../..');
    for (const filename of input.evidenceDirs) check(path.dirname(filename) === fixture && /^credential-prepared-crash-[A-Za-z0-9]+$/u.test(path.basename(filename)));
    const root = await absoluteDirectory(input.stateRoot);
    check(root.info.uid === BigInt(input.uid) && (root.info.mode & 0o7777n) === 0o700n);
    const credential = await openDirectory(path.join(input.stateRoot, 'credentials'), root, 'credentials');
    check(credential.info.uid === BigInt(input.uid) && (credential.info.mode & 0o7777n) === 0o700n);
    snapshot = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-corpus-'));
    for (const [directory, main] of [[root, 'kernel.sqlite3'], [credential, 'authority.sqlite']] as const) {
      const mainBytes = await file(directory, main, { mode: [0o600n], limit: sqliteLimit, copy: true });
      let walBytes: Buffer | undefined;
      try {
        walBytes = await file(directory, `${main}-wal`, { mode: [0o600n], limit: sqliteLimit, optional: true, copy: true });
        check(mainBytes && mainBytes.length >= 100);
        await file(directory, `${main}-journal`, { mode: [0o600n], limit: sqliteLimit, optional: true });
        await file(directory, `${main}-shm`, { mode: [0o600n], limit: sqliteLimit, optional: true });
        const copied = path.join(snapshot, main); await writeFile(copied, mainBytes, { flag: 'wx', mode: 0o600 });
        if (walBytes) await writeFile(`${copied}-wal`, walBytes, { flag: 'wx', mode: 0o600 });
        const logical = scanCopiedCredentialDatabase(copied, input.scanner);
        stats.logicalRowsScanned += logical.logicalRowsScanned; stats.logicalValuesScanned += logical.logicalValuesScanned;
        stats.logicalBytesScanned += logical.logicalBytesScanned; stats.sqliteDatabasesScanned++;
      } finally { mainBytes?.fill(0); walBytes?.fill(0); }
    }
    const cas = await openDirectory(path.join(input.stateRoot, 'cas'), root, 'cas');
    check(cas.info.uid === BigInt(input.uid) && (cas.info.mode & 0o7777n) === 0o700n);
    const casNames = await names(cas);
    for (const leaf of casNames) {
      const published = /^[0-9a-f]{64}$/u.test(leaf);
      check(published || /^\.tmp-[0-9a-f]{64}-[0-9a-f]{32}$/u.test(leaf));
      const nameBytes = Buffer.from(leaf, 'ascii');
      try { scanValue(input.scanner, nameBytes); } finally { nameBytes.fill(0); }
      await file(cas, leaf, { mode: published ? [0o400n] : [0o400n, 0o600n], links: published ? [1n] : [1n, 2n], limit: fileLimit });
    }
    check(JSON.stringify(await names(cas)) === JSON.stringify(casNames));
    for (const filename of input.evidenceDirs) {
      const evidence = await absoluteDirectory(filename);
      check(evidence.info.uid === 0n && (evidence.info.mode & 0o7777n) === 0o755n);
      check(JSON.stringify(await names(evidence)) === '["trace"]');
      const trace = await openDirectory(path.join(filename, 'trace'), evidence, 'trace');
      check(trace.info.uid === BigInt(input.uid) && (trace.info.mode & 0o7777n) === 0o700n);
      const traceNames = await names(trace); check(traceNames.length > 0);
      for (const leaf of traceNames) {
        check(/^auth\.trace\.[1-9][0-9]*$/u.test(leaf));
        await file(trace, leaf, { mode: [0o600n, 0o644n], limit: 8 * 1024 * 1024 });
      }
      check(JSON.stringify(await names(trace)) === JSON.stringify(traceNames)); stats.evidenceDirectoriesScanned++;
    }
    for (const observed of observedFiles) {
      let info: BigIntStats | undefined;
      try { info = await lstat(descriptorPath(observed.directory, observed.leaf), { bigint: true }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      check(observed.info ? info && identity(info) === identity(observed.info) : !info);
    }
    for (const directory of directories) await current(directory);
    return Object.freeze({ diagnosticOnly: true as const, qualified: true as const, ...stats });
  } catch (error) {
    if (error instanceof CredentialSecretScanError || error instanceof CredentialSecretCorpusError) throw error;
    return refused();
  } finally {
    let failed = false;
    if (snapshot) try { await rm(snapshot, { recursive: true, force: true }); } catch { failed = true; }
    for (const directory of directories.reverse()) try { await directory.handle.close(); } catch { failed = true; }
    if (failed) refused();
  }
}
