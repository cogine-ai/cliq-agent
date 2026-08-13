import { chmod, lstat, mkdtemp, open, rm, statfs } from 'node:fs/promises';
import path from 'node:path';

import { openSqliteDriver } from './sqlite-driver.js';

const SQLITE_APPLICATION_ID = 0x434c4951;
const SQLITE_USER_VERSION = 1;
const SQLITE_BUSY_TIMEOUT_MS = 5_000;
const LIMITATIONS = Object.freeze(['native_descriptor_helper_required'] as const);

interface SqliteStatement {
  get(...parameters: unknown[]): unknown;
  all(...parameters: unknown[]): unknown[];
}

export interface StateProbeSqliteDatabase {
  exec(sql: string): void;
  prepare(sql: string): SqliteStatement;
  close(): void;
}

export type StateProbeSqliteFactory = (filename: string) => StateProbeSqliteDatabase;

export type StateBackendQualificationFailureCode =
  | 'invalid_state_root'
  | 'unsupported_platform'
  | 'state_root_unavailable'
  | 'state_root_symlink'
  | 'state_root_not_directory'
  | 'state_root_owner_mismatch'
  | 'state_root_mode_mismatch'
  | 'filesystem_probe_failed'
  | 'filesystem_not_local'
  | 'durability_probe_failed'
  | 'sqlite_probe_failed';

interface StateBackendQualificationBase {
  authorityReady: false;
  limitations: typeof LIMITATIONS;
}

export interface StateBackendQualificationSuccess extends StateBackendQualificationBase {
  ok: true;
  stateRoot: string;
  filesystem: {
    platform: 'darwin' | 'linux';
    type: string;
    local: true;
  };
  durability: {
    fileFsync: true;
    directoryFsync: true;
  };
  sqlite: {
    foreignKeys: true;
    synchronous: 'FULL';
    busyTimeoutMs: 5_000;
    applicationId: number;
    userVersion: 1;
    journalMode: 'delete';
    foreignKeyCheck: 'ok';
    integrityCheck: 'ok';
  };
}

export interface StateBackendQualificationFailure extends StateBackendQualificationBase {
  ok: false;
  error: {
    code: StateBackendQualificationFailureCode;
    message: string;
    causeCode?: string;
  };
}

export type StateBackendQualification =
  | StateBackendQualificationSuccess
  | StateBackendQualificationFailure;

export interface QualifyStateBackendOptions {
  stateRoot: string;
  sqliteFactory?: StateProbeSqliteFactory;
}

function failure(
  code: StateBackendQualificationFailureCode,
  message: string,
  cause?: unknown
): StateBackendQualificationFailure {
  const causeCode =
    typeof cause === 'object' && cause !== null && 'code' in cause && typeof cause.code === 'string'
      ? cause.code
      : undefined;
  return {
    ok: false,
    authorityReady: false,
    limitations: LIMITATIONS,
    error: causeCode === undefined ? { code, message } : { code, message, causeCode }
  };
}

function defaultSqliteFactory(filename: string): StateProbeSqliteDatabase {
  return openSqliteDriver(filename);
}

function pragmaScalar(database: StateProbeSqliteDatabase, name: string): unknown {
  const row = database.prepare(`PRAGMA ${name}`).get();
  if (typeof row !== 'object' || row === null) return undefined;
  return Object.values(row)[0];
}

function sqliteSynchronousName(value: unknown): string | undefined {
  if (value === 2 || value === 2n || value === '2' || value === 'FULL' || value === 'full') return 'FULL';
  return undefined;
}

function sqliteJournalMode(value: unknown): string | undefined {
  return typeof value === 'string' ? value.toLowerCase() : undefined;
}

function sqliteIntegerEquals(value: unknown, expected: number): boolean {
  return value === expected || value === BigInt(expected);
}

export function isLocalFilesystem(platform: 'darwin' | 'linux', type: bigint): boolean {
  const normalized = BigInt.asUintN(32, type);
  if (platform === 'darwin') {
    // Darwin f_type values. Only filesystems with local durability semantics
    // accepted by this qualification probe are listed here.
    return new Set([
      1n,
      4n,
      17n,
      21n,
      25n, // HFS
      26n // APFS
    ]).has(normalized);
  }

  // Linux statfs magic values for persistent local disk or local union
  // filesystems used by supported hosts and CI. Network/FUSE/9p and
  // in-memory tmpfs/ramfs types fail closed by omission.
  return new Set([
    0xef53n, // ext2/3/4
    0x58465342n, // XFS
    0x9123683en, // Btrfs
    0x794c7630n, // overlayfs
    0x2fc12fc1n, // ZFS
    0xf2f52010n, // F2FS
    0x3153464an, // JFS
    0x52654973n, // ReiserFS
    0x24051905n // UBIFS
  ]).has(normalized);
}

async function fsyncFile(filename: string): Promise<void> {
  const handle = await open(filename, 'r+');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function fsyncDirectory(dirname: string): Promise<void> {
  const handle = await open(dirname, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Runs a destructive-but-contained durability qualification in a fresh random
 * child directory. Passing this probe never grants Kernel authority: path
 * validation remains raceable until the native descriptor helper lands.
 */
export async function qualifyStateBackend(
  options: QualifyStateBackendOptions
): Promise<StateBackendQualification> {
  const { stateRoot } = options;
  if (!path.isAbsolute(stateRoot) || path.normalize(stateRoot) !== stateRoot) {
    return failure('invalid_state_root', 'State root must be a normalized absolute path.');
  }

  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    return failure('unsupported_platform', `State qualification is unsupported on ${process.platform}.`);
  }
  const platform = process.platform;

  if (typeof process.geteuid !== 'function') {
    return failure('unsupported_platform', 'State qualification requires a POSIX effective uid.');
  }

  let rootStat;
  try {
    rootStat = await lstat(stateRoot);
  } catch (cause) {
    return failure('state_root_unavailable', 'State root cannot be inspected.', cause);
  }
  if (rootStat.isSymbolicLink()) {
    return failure('state_root_symlink', 'State root must not be a symbolic link.');
  }
  if (!rootStat.isDirectory()) {
    return failure('state_root_not_directory', 'State root must be a directory.');
  }
  if (rootStat.uid !== process.geteuid()) {
    return failure('state_root_owner_mismatch', 'State root must be owned by the effective uid.');
  }
  if ((rootStat.mode & 0o7777) !== 0o700) {
    return failure('state_root_mode_mismatch', 'State root mode must be exactly 0700.');
  }

  let filesystemType: bigint;
  try {
    filesystemType = (await statfs(stateRoot, { bigint: true })).type;
  } catch (cause) {
    return failure('filesystem_probe_failed', 'Filesystem type cannot be inspected.', cause);
  }
  if (!isLocalFilesystem(platform, filesystemType)) {
    return failure(
      'filesystem_not_local',
      `State root filesystem type 0x${BigInt.asUintN(32, filesystemType).toString(16)} is not an approved local filesystem.`
    );
  }

  let probeDirectory: string | undefined;
  try {
    probeDirectory = await mkdtemp(path.join(stateRoot, '.cliq-state-probe-'));
    await chmod(probeDirectory, 0o700);
  } catch (cause) {
    return failure('durability_probe_failed', 'A private state probe directory cannot be created.', cause);
  }

  const durabilityFilename = path.join(probeDirectory, 'durability-probe');
  const sqliteFilename = path.join(probeDirectory, 'state-probe.sqlite');
  try {
    try {
      await fsyncDirectory(stateRoot);
      const durabilityHandle = await open(durabilityFilename, 'wx', 0o600);
      try {
        await durabilityHandle.writeFile('cliq-state-probe-v1\n', 'utf8');
        await durabilityHandle.sync();
      } finally {
        await durabilityHandle.close();
      }
      await fsyncDirectory(probeDirectory);
    } catch (cause) {
      return failure('durability_probe_failed', 'File or directory fsync failed.', cause);
    }

    let database: StateProbeSqliteDatabase | undefined;
    let sqliteFailure: unknown;
    try {
      database = (options.sqliteFactory ?? defaultSqliteFactory)(sqliteFilename);
      database.exec(`
        PRAGMA journal_mode=DELETE;
        PRAGMA foreign_keys=ON;
        PRAGMA synchronous=FULL;
        PRAGMA busy_timeout=${SQLITE_BUSY_TIMEOUT_MS};
        PRAGMA application_id=${SQLITE_APPLICATION_ID};
        PRAGMA user_version=${SQLITE_USER_VERSION};
        CREATE TABLE probe_parent (id INTEGER PRIMARY KEY);
        CREATE TABLE probe_child (
          id INTEGER PRIMARY KEY,
          parent_id INTEGER NOT NULL REFERENCES probe_parent(id)
        );
        BEGIN IMMEDIATE;
        INSERT INTO probe_parent(id) VALUES (1);
        INSERT INTO probe_child(id, parent_id) VALUES (1, 1);
        COMMIT;
      `);

      const foreignKeys = pragmaScalar(database, 'foreign_keys');
      const synchronous = sqliteSynchronousName(pragmaScalar(database, 'synchronous'));
      const busyTimeout = pragmaScalar(database, 'busy_timeout');
      const applicationId = pragmaScalar(database, 'application_id');
      const userVersion = pragmaScalar(database, 'user_version');
      const journalMode = sqliteJournalMode(pragmaScalar(database, 'journal_mode'));
      const foreignKeyViolations = database.prepare('PRAGMA foreign_key_check').all();
      const integrityCheck = pragmaScalar(database, 'integrity_check');

      if (
        !sqliteIntegerEquals(foreignKeys, 1) ||
        synchronous !== 'FULL' ||
        !sqliteIntegerEquals(busyTimeout, SQLITE_BUSY_TIMEOUT_MS) ||
        !sqliteIntegerEquals(applicationId, SQLITE_APPLICATION_ID) ||
        !sqliteIntegerEquals(userVersion, SQLITE_USER_VERSION) ||
        journalMode !== 'delete' ||
        foreignKeyViolations.length !== 0 ||
        integrityCheck !== 'ok'
      ) {
        throw new Error('SQLite did not retain the required state profile.');
      }
    } catch (cause) {
      sqliteFailure = cause;
    }
    try {
      database?.close();
    } catch (cause) {
      sqliteFailure ??= cause;
    }
    if (sqliteFailure !== undefined) {
      return failure('sqlite_probe_failed', 'SQLite durability/profile qualification failed.', sqliteFailure);
    }

    try {
      await chmod(sqliteFilename, 0o600);
      await fsyncFile(sqliteFilename);
      await fsyncDirectory(probeDirectory);
    } catch (cause) {
      return failure('durability_probe_failed', 'SQLite file or parent directory fsync failed.', cause);
    }

    return {
      ok: true,
      stateRoot,
      authorityReady: false,
      limitations: LIMITATIONS,
      filesystem: {
        platform,
        type: `0x${BigInt.asUintN(32, filesystemType).toString(16)}`,
        local: true
      },
      durability: { fileFsync: true, directoryFsync: true },
      sqlite: {
        foreignKeys: true,
        synchronous: 'FULL',
        busyTimeoutMs: SQLITE_BUSY_TIMEOUT_MS,
        applicationId: SQLITE_APPLICATION_ID,
        userVersion: SQLITE_USER_VERSION,
        journalMode: 'delete',
        foreignKeyCheck: 'ok',
        integrityCheck: 'ok'
      }
    };
  } finally {
    try {
      await rm(probeDirectory, { recursive: true, force: true });
      await fsyncDirectory(stateRoot);
    } catch (cause) {
      return failure('durability_probe_failed', 'State probe cleanup or parent directory fsync failed.', cause);
    }
  }
}
