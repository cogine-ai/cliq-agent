// Test-private byte qualification. These are copied diagnostic SQLite reads,
// never a production connection, credential authority or recovery decision.
import { constants, lstatSync, type BigIntStats } from 'node:fs';
import { lstat, mkdtemp, open, opendir, rm, writeFile, type FileHandle } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { REQUEST_ID_PATTERN } from '../../../src/kernel/identity.js';
import { iterateNodeSqliteStatement } from '../../../src/state/sqlite-driver.js';
import { CredentialSecretScanError, type CredentialSecretScanner } from './credential-secret-scan.js';

const chunkBytes = 64 * 1024, sqliteLimit = 16 * 1024 * 1024, fileLimit = 512 * 1024 * 1024;
const entryLimit = 1024, rowLimit = 8192, cellLimit = 65536;
type DatabaseFailureStage = 'open' | 'configure' | 'schema' | 'prepare' | 'rows' | 'stability';
type DatabaseFailureClass = 'sqlite_error' | 'sqlite_busy' | 'sqlite_locked' | 'sqlite_io' | 'sqlite_corrupt'
  | 'sqlite_readonly' | 'sqlite_not_database' | 'out_of_range' | 'type_error' | 'other';
type CorpusFailureStage = 'input' | 'root' | 'databases' | 'cas_inventory' | 'cas_files' | 'evidence' | 'stability' | 'cleanup';
type CorpusFailureClass = 'guard_refused' | 'deadline_exceeded' | 'file_limit_exceeded' | 'entry_limit_exceeded'
  | 'not_found' | 'access_refused' | 'symlink_refused' | 'descriptor_limit' | 'io_error' | 'other';
export type CredentialSecretCorpusFailure = Readonly<Stats & { stage: CorpusFailureStage; errorClass: CorpusFailureClass; inventoryEntriesObserved: number }>;
export class CredentialSecretCorpusError extends Error {
  constructor(readonly databaseFailure?: Readonly<{ database: 'kernel' | 'authority'; stage: DatabaseFailureStage; errorClass: DatabaseFailureClass }>,
    readonly corpusFailure?: CredentialSecretCorpusFailure) {
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
type TableBucket = 'artifacts' | 'control' | 'events' | 'items' | 'checkpoints' | 'journal' | 'other'
  | 'canonical_time_fence' | 'state_owners' | 'sessions' | 'runs' | 'worker_launches' | 'workspace_generations'
  | 'local_inference_activation_cycles' | 'local_inference_launches' | 'list_read_cuts' | 'list_read_cut_entries'
  | 'child_allocations' | 'authorization_grants' | 'source_inspection_attempts' | 'mcp_registrations' | 'admin_operations';
type ScanSource = Readonly<{
  kind: 'database_logical'; database: 'kernel' | 'authority'; tableBucket: TableBucket;
  part: 'table_name' | 'table_sql' | 'cell';
  logicalRowsObserved: number; logicalValuesAttempted: number; logicalBytesObserved: number;
}> | Readonly<{ kind: 'database_file'; database: 'kernel' | 'authority'; part: 'main' | 'wal' | 'journal' | 'shm' }>
  | Readonly<{ kind: 'cas'; part: 'entry_name' | 'file_bytes' }> | Readonly<{ kind: 'evidence'; part: 'entry_name' | 'file_bytes' }>;
export type CredentialSecretCorpusScanProgress = Readonly<{ diagnosticOnly: true; source: ScanSource;
  corpusCounters?: Readonly<Stats & { inventoryEntriesObserved: number }> }>;
const scanFailures = new WeakMap<object, CredentialSecretCorpusScanProgress>();

/** Counts attached only to the actual thrown scanner error, never caller data
 * or proof. A value attempt may not have opened a stream or scanned any byte.
 * Read after the corpus call rejects, not from the scanner's earlier observer. */
export function readCredentialSecretCorpusScanProgress(error: unknown): CredentialSecretCorpusScanProgress | undefined {
  if ((typeof error !== 'object' && typeof error !== 'function') || error === null) return;
  return scanFailures.get(error);
}
function tableBucket(name: string): TableBucket {
  switch (name) {
    case 'artifacts': return 'artifacts';
    case 'control_requests': return 'control';
    case 'run_events': return 'events';
    case 'items': return 'items';
    case 'checkpoints': return 'checkpoints';
    case 'run_journal': return 'journal';
    case 'canonical_time_fence': return 'canonical_time_fence';
    case 'state_owners': return 'state_owners';
    case 'sessions': return 'sessions';
    case 'runs': return 'runs';
    case 'worker_launches': return 'worker_launches';
    case 'workspace_generations': return 'workspace_generations';
    case 'local_inference_activation_cycles': return 'local_inference_activation_cycles';
    case 'local_inference_launches': return 'local_inference_launches';
    case 'list_read_cuts': return 'list_read_cuts';
    case 'list_read_cut_entries': return 'list_read_cut_entries';
    case 'child_allocations': return 'child_allocations';
    case 'authorization_grants': return 'authorization_grants';
    case 'source_inspection_attempts': return 'source_inspection_attempts';
    case 'mcp_registrations': return 'mcp_registrations';
    case 'admin_operations': return 'admin_operations';
    default: return 'other';
  }
}
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
  let bucket: TableBucket = 'other', part: 'table_name' | 'table_sql' | 'cell' = 'table_name';
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
      bucket = tableBucket(table.name);
      part = 'table_name'; scan(table.name); part = 'table_sql'; scan(table.sql);
      const query = `SELECT * FROM "${table.name}"`;
      stage = 'prepare'; const statement = database.prepare(query);
      // INTEGER cells are not byte needles. Preserve SQLite's whole signed
      // 64-bit domain so conversion cannot stop the following TEXT/BLOB scan.
      statement.setReadBigInts(true);
      stage = 'rows';
      part = 'cell';
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
    if (error instanceof CredentialSecretScanError) {
      try {
        scanFailures.set(error, Object.freeze({ diagnosticOnly: true, source: Object.freeze({ kind: 'database_logical',
          database: path.basename(filename) === 'kernel.sqlite3' ? 'kernel' : 'authority', tableBucket: bucket, part,
          logicalRowsObserved: logicalRowsScanned, logicalValuesAttempted: logicalValuesScanned, logicalBytesObserved: logicalBytesScanned }) }));
      } catch { /* Diagnosis cannot change the original error or its finally. */ }
      throw error;
    }
    if (error instanceof CredentialSecretCorpusError) throw error;
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
  evidenceDirs: readonly string[]; scanner: CredentialSecretScanner; scanInstalledClientData?: true }>;

/** Invoke after all fixture credential writers and Supervisor/keeper have
 * positively joined. Linux /proc descriptor paths pin every ancestor without
 * following a directory symlink. Only fixed SQLite files, flat CAS names and
 * explicitly supplied sibling crash trace directories are in scope. The fixed
 * fixed option additionally covers its actual physical installation's
 * client data partition; it supplies no caller-selected path or authority. */
export async function scanCredentialSecretCorpus(input: CredentialSecretCorpusInput) {
  const directories: Directory[] = [];
  const clientDirectories: Directory[] = [];
  const observedFiles: { directory: Directory; leaf: string; info?: BigIntStats }[] = [];
  const stats: Stats = { filesScanned: 0, fileBytesScanned: 0, sqliteDatabasesScanned: 0,
    logicalRowsScanned: 0, logicalValuesScanned: 0, logicalBytesScanned: 0, evidenceDirectoriesScanned: 0 };
  const deadline = performance.now() + 60000;
  let stage: CorpusFailureStage = 'input', inventoryEntriesObserved = 0;
  let scanSource: ScanSource | undefined;
  const diagnostic = (errorClass: CorpusFailureClass): CredentialSecretCorpusFailure => Object.freeze({ stage, errorClass, ...stats, inventoryEntriesObserved });
  const fail = (errorClass: CorpusFailureClass): never => { throw new CredentialSecretCorpusError(undefined, diagnostic(errorClass)); };
  const bounded = () => {
    if (performance.now() >= deadline) fail('deadline_exceeded');
    if (stats.filesScanned > 2048) fail('file_limit_exceeded');
  };
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
    try { for (;;) { const entry = await opened.read(); if (!entry) break; inventoryEntriesObserved = entries.length + 1;
      if (entries.length >= entryLimit) fail('entry_limit_exceeded'); entries.push(entry.name); } }
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
    check(/^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+\/home\/(?:probe\/credential-state|\.cliq\/kernel-v1)$/u.test(input.stateRoot));
    check(input.scanInstalledClientData === undefined || input.scanInstalledClientData === true);
    if (input.scanInstalledClientData) check(input.stateRoot.endsWith('/home/.cliq/kernel-v1'));
    check(Array.isArray(input.evidenceDirs) && input.evidenceDirs.length <= 16 && new Set(input.evidenceDirs).size === input.evidenceDirs.length);
    if (input.scanInstalledClientData) check(input.evidenceDirs.length === 0);
    const fixture = path.resolve(input.stateRoot, '../../..');
    for (const filename of input.evidenceDirs) check(path.dirname(filename) === fixture && /^credential-prepared-crash-[A-Za-z0-9]+$/u.test(path.basename(filename)));
    stage = 'root';
    const root = await absoluteDirectory(input.stateRoot);
    check(root.info.uid === BigInt(input.uid) && (root.info.mode & 0o7777n) === 0o700n);
    const credential = await openDirectory(path.join(input.stateRoot, 'credentials'), root, 'credentials');
    check(credential.info.uid === BigInt(input.uid) && (credential.info.mode & 0o7777n) === 0o700n);
    snapshot = await mkdtemp(path.join(os.tmpdir(), 'cliq-credential-corpus-'));
    stage = 'databases';
    for (const [directory, main] of [[root, 'kernel.sqlite3'], [credential, 'authority.sqlite']] as const) {
      const database = main === 'kernel.sqlite3' ? 'kernel' : 'authority';
      scanSource = { kind: 'database_file', database, part: 'main' };
      const mainBytes = await file(directory, main, { mode: [0o600n], limit: sqliteLimit, copy: true });
      let walBytes: Buffer | undefined;
      try {
        scanSource = { kind: 'database_file', database, part: 'wal' };
        walBytes = await file(directory, `${main}-wal`, { mode: [0o600n], limit: sqliteLimit, optional: true, copy: true });
        check(mainBytes && mainBytes.length >= 100);
        scanSource = { kind: 'database_file', database, part: 'journal' };
        await file(directory, `${main}-journal`, { mode: [0o600n], limit: sqliteLimit, optional: true });
        scanSource = { kind: 'database_file', database, part: 'shm' };
        await file(directory, `${main}-shm`, { mode: [0o600n], limit: sqliteLimit, optional: true });
        const copied = path.join(snapshot, main); await writeFile(copied, mainBytes, { flag: 'wx', mode: 0o600 });
        if (walBytes) await writeFile(`${copied}-wal`, walBytes, { flag: 'wx', mode: 0o600 });
        scanSource = undefined;
        const logical = scanCopiedCredentialDatabase(copied, input.scanner);
        stats.logicalRowsScanned += logical.logicalRowsScanned; stats.logicalValuesScanned += logical.logicalValuesScanned;
        stats.logicalBytesScanned += logical.logicalBytesScanned; stats.sqliteDatabasesScanned++;
      } finally { mainBytes?.fill(0); walBytes?.fill(0); }
    }
    const cas = await openDirectory(path.join(input.stateRoot, 'cas'), root, 'cas');
    check(cas.info.uid === BigInt(input.uid) && (cas.info.mode & 0o7777n) === 0o700n);
    stage = 'cas_inventory';
    const casNames = await names(cas);
    stage = 'cas_files';
    for (const leaf of casNames) {
      const published = /^[0-9a-f]{64}$/u.test(leaf);
      check(published || /^\.tmp-[0-9a-f]{64}-[0-9a-f]{32}$/u.test(leaf));
      const nameBytes = Buffer.from(leaf, 'ascii');
      scanSource = { kind: 'cas', part: 'entry_name' };
      try { scanValue(input.scanner, nameBytes); } finally { nameBytes.fill(0); }
      scanSource = { kind: 'cas', part: 'file_bytes' };
      await file(cas, leaf, { mode: published ? [0o400n] : [0o400n, 0o600n], links: published ? [1n] : [1n, 2n], limit: fileLimit });
    }
    check(JSON.stringify(await names(cas)) === JSON.stringify(casNames));
    stage = 'evidence';
    for (const filename of input.evidenceDirs) {
      const evidence = await absoluteDirectory(filename);
      check(evidence.info.uid === 0n && (evidence.info.mode & 0o7777n) === 0o755n);
      check(JSON.stringify(await names(evidence)) === '["trace"]');
      const trace = await openDirectory(path.join(filename, 'trace'), evidence, 'trace');
      check(trace.info.uid === BigInt(input.uid) && (trace.info.mode & 0o7777n) === 0o700n);
      const traceNames = await names(trace); check(traceNames.length > 0);
      for (const leaf of traceNames) {
        check(/^auth\.trace\.[1-9][0-9]*$/u.test(leaf));
        scanSource = { kind: 'evidence', part: 'file_bytes' };
        await file(trace, leaf, { mode: [0o600n, 0o644n], limit: 8 * 1024 * 1024 });
      }
      check(JSON.stringify(await names(trace)) === JSON.stringify(traceNames)); stats.evidenceDirectoriesScanned++;
    }
    if (input.scanInstalledClientData) {
      // Same canonical locator and actual dev/ino/uid tuple as
      // installedClientDataPath. These are byte-diagnostic locators only, never
      // an installed runtime, authenticated response or retry permission.
      const partition = canonicalSha256({ deviceId: String(root.info.dev), fileId: String(root.info.ino),
        ownerUid: input.uid, canonicalPath: input.stateRoot });
      const parent = directories.find(directory => directory.physicalPath === path.dirname(input.stateRoot)); check(parent);
      const privateDirectory = async (parent: Directory, leaf: string) => {
        const directory = await openDirectory(path.join(parent.physicalPath, leaf), parent, leaf);
        check(directory.info.uid === BigInt(input.uid) && (directory.info.mode & 0o7777n) === 0o700n);
        clientDirectories.push(directory); return directory;
      };
      const inventory = async (directory: Directory) => {
        const result = await names(directory);
        for (const leaf of result) {
          const bytes = Buffer.from(leaf, 'utf8'); scanSource = { kind: 'evidence', part: 'entry_name' };
          try { scanValue(input.scanner, bytes); } finally { bytes.fill(0); }
        }
        return result;
      };
      const client = await privateDirectory(parent, 'client-v1'), clientNames = await inventory(client);
      check(JSON.stringify(clientNames) === '["installations"]');
      const installations = await privateDirectory(client, 'installations'), installationNames = await inventory(installations);
      check(JSON.stringify(installationNames) === JSON.stringify([partition]));
      const selected = await privateDirectory(installations, partition), selectedNames = await inventory(selected);
      // A readonly SDK/CLI host creates requests-v1 before any mutation or
      // model selection. Optional data must be scanned when present; absence
      // is not a model-configuration or execution-authority decision.
      check(selectedNames.includes('requests-v1'));
      for (const leaf of selectedNames) {
        if (leaf === 'requests-v1') continue;
        check(leaf === 'client-mutation.lock' || leaf === 'preferences.json' || /^model-setup-[0-9a-f]{64}\.json$/u.test(leaf));
        scanSource = { kind: 'evidence', part: 'file_bytes' };
        await file(selected, leaf, { mode: [0o600n], limit: leaf === 'client-mutation.lock' ? 0 : 65_536 });
      }
      const requests = await privateDirectory(selected, 'requests-v1'), requestNames = await inventory(requests);
      for (const leaf of requestNames) {
        const acknowledged = /^\.ack-([0-9a-f-]{36})-([0-9a-f]{64})-([0-9a-f]{32})$/u.exec(leaf);
        check(REQUEST_ID_PATTERN.test(acknowledged?.[1] ?? leaf));
        const group = await privateDirectory(requests, leaf), groupNames = await inventory(group);
        if (acknowledged) {
          check(acknowledged[2] === canonicalSha256({ deviceId: String(group.info.dev), fileId: String(group.info.ino), ownerUid: input.uid }));
        } else check(groupNames.includes('metadata.json') && groupNames.includes('request.json'));
        // A genuine acknowledgement residue may have already removed any of
        // these three files. Its physical name binding is mandatory; neither
        // it nor the scan turns a disk response into an authenticated result.
        for (const name of groupNames) {
          check(['metadata.json', 'request.json', 'response.json'].includes(name));
          scanSource = { kind: 'evidence', part: 'file_bytes' };
          await file(group, name, { mode: [0o600n], limit: name === 'metadata.json' ? 4_096 : 1_048_576 });
        }
        check(JSON.stringify(await names(group)) === JSON.stringify(groupNames));
      }
      check(JSON.stringify(await names(requests)) === JSON.stringify(requestNames));
      check(JSON.stringify(await names(selected)) === JSON.stringify(selectedNames));
      check(JSON.stringify(await names(installations)) === JSON.stringify(installationNames));
      check(JSON.stringify(await names(client)) === JSON.stringify(clientNames));
      stats.evidenceDirectoriesScanned++;
    }
    stage = 'stability';
    for (const observed of observedFiles) {
      let info: BigIntStats | undefined;
      try { info = await lstat(descriptorPath(observed.directory, observed.leaf), { bigint: true }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      check(observed.info ? info && identity(info) === identity(observed.info) : !info);
    }
    for (const directory of directories) await current(directory);
    for (const directory of clientDirectories) await current(directory, true);
    return Object.freeze({ diagnosticOnly: true as const, qualified: true as const, ...stats,
      ...(input.scanInstalledClientData ? { installedClientDataScanned: true as const } : {}) });
  } catch (error) {
    if (error instanceof CredentialSecretScanError) {
      try {
        const source = scanFailures.get(error)?.source ?? scanSource;
        if (source) scanFailures.set(error, Object.freeze({ diagnosticOnly: true, source: Object.freeze(source),
          corpusCounters: Object.freeze({ ...stats, inventoryEntriesObserved }) }));
      } catch { /* Diagnosis cannot change the original error or its finally. */ }
      throw error;
    }
    if (error instanceof CredentialSecretCorpusError) {
      if (error.corpusFailure) throw error;
      throw new CredentialSecretCorpusError(error.databaseFailure, diagnostic('guard_refused'));
    }
    const code = error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'code')?.value : undefined;
    const errorClass: CorpusFailureClass = code === 'ENOENT' ? 'not_found' : code === 'EACCES' || code === 'EPERM' ? 'access_refused'
      : code === 'ELOOP' ? 'symlink_refused' : code === 'EMFILE' || code === 'ENFILE' ? 'descriptor_limit' : code === 'EIO' ? 'io_error' : 'other';
    throw new CredentialSecretCorpusError(undefined, diagnostic(errorClass));
  } finally {
    let failed = false;
    if (snapshot) try { await rm(snapshot, { recursive: true, force: true }); } catch { failed = true; }
    for (const directory of directories.reverse()) try { await directory.handle.close(); } catch { failed = true; }
    if (failed) { stage = 'cleanup'; fail('io_error'); }
  }
}
