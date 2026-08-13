import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  isLocalLinuxFilesystem,
  parseDarwinFilesystemObservation,
  qualifyStateBackend,
  type StateProbeSqliteDatabase
} from './probe.js';
import { openSqliteDriver } from './sqlite-driver.js';

test('Darwin filesystem qualification uses the stable mount name and local flag', () => {
  assert.deepEqual(
    parseDarwinFilesystemObservation(
      'Filesystem 512-blocks Used Available Capacity Mounted on\n/dev/disk9s1 100 1 99 1% /System/Volumes/Data\n',
      '/dev/disk9s1 on /System/Volumes/Data (apfs, local, journaled)\n'
    ),
    { type: 'apfs', local: true }
  );
  assert.deepEqual(
    parseDarwinFilesystemObservation(
      'Filesystem 512-blocks Used Available Capacity Mounted on\nserver:/volume 100 1 99 1% /Volumes/remote\n',
      'server:/volume on /Volumes/remote (nfs, nodev, nosuid)\n'
    ),
    { type: 'nfs', local: false }
  );
  assert.equal(isLocalLinuxFilesystem(0xef53n), true);
});

test('qualifyStateBackend proves a local durable SQLite probe without granting authority', async () => {
  const stateRoot = await makeStateRoot();
  await chmod(stateRoot, 0o700);

  try {
    const result = await qualifyStateBackend({ stateRoot });

    if (!result.ok) assert.fail(`${result.error.code}: ${result.error.message}`);
    assert.equal(result.ok, true);
    assert.equal(result.stateRoot, stateRoot);
    assert.equal(result.authorityReady, false);
    assert.deepEqual(result.limitations, ['native_descriptor_helper_required']);
    assert.equal(result.filesystem.local, true);
    assert.equal(result.durability.fileFsync, true);
    assert.equal(result.durability.directoryFsync, true);
    assert.deepEqual(result.sqlite, {
      foreignKeys: true,
      synchronous: 'FULL',
      busyTimeoutMs: 5_000,
      applicationId: 0x434c4951,
      userVersion: 1,
      journalMode: 'delete',
      foreignKeyCheck: 'ok',
      integrityCheck: 'ok'
    });
    assert.deepEqual(await readdir(stateRoot), [], 'the random probe directory is removed');
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('qualifyStateBackend returns a SQLite failure when the probe database cannot close cleanly', async () => {
  const stateRoot = await makeStateRoot();
  await chmod(stateRoot, 0o700);

  try {
    const result = await qualifyStateBackend({
      stateRoot,
      sqliteFactory(filename) {
        const database = openSqliteDriver(filename);
        return {
          exec(sql) {
            database.exec(sql);
          },
          prepare(sql) {
            return database.prepare(sql) as ReturnType<StateProbeSqliteDatabase['prepare']>;
          },
          close() {
            database.close();
            const error = new Error('injected close failure') as Error & { code: string };
            error.code = 'ECLOSE';
            throw error;
          }
        };
      }
    });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'sqlite_probe_failed');
    assert.equal(result.error.causeCode, 'ECLOSE');
    assert.equal(result.authorityReady, false);
    assert.deepEqual(result.limitations, ['native_descriptor_helper_required']);
    assert.deepEqual(await readdir(stateRoot), [], 'failed probes are removed');
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('qualifyStateBackend returns a failure instead of throwing when probe cleanup is blocked', async () => {
  const stateRoot = await makeStateRoot();
  await chmod(stateRoot, 0o700);

  try {
    const result = await qualifyStateBackend({
      stateRoot,
      sqliteFactory(filename) {
        const database = openSqliteDriver(filename);
        return {
          exec(sql) {
            database.exec(sql);
          },
          prepare(sql) {
            return database.prepare(sql) as ReturnType<StateProbeSqliteDatabase['prepare']>;
          },
          close() {
            database.close();
            chmodSync(stateRoot, 0o500);
          }
        };
      }
    });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'durability_probe_failed');
    assert.equal(result.authorityReady, false);
  } finally {
    await chmod(stateRoot, 0o700);
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('qualifyStateBackend preserves the primary failure when cleanup also fails', async () => {
  const stateRoot = await makeStateRoot();
  await chmod(stateRoot, 0o700);

  try {
    const result = await qualifyStateBackend({
      stateRoot,
      sqliteFactory() {
        chmodSync(stateRoot, 0o500);
        const error = new Error('injected primary SQLite failure') as Error & { code: string };
        error.code = 'EPRIMARY';
        throw error;
      }
    });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'sqlite_probe_failed');
    assert.equal(result.error.causeCode, 'EPRIMARY');
  } finally {
    await chmod(stateRoot, 0o700);
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('qualifyStateBackend rejects a relative state root without throwing', async () => {
  const result = await qualifyStateBackend({ stateRoot: 'relative/state' });

  assert.equal(result.ok, false);
  if (result.ok) assert.fail('qualification must fail closed');
  assert.equal(result.error.code, 'invalid_state_root');
  assert.equal(result.authorityReady, false);
});

test('qualifyStateBackend rejects a symlink as the current state root', async () => {
  const parent = await makeStateParent();
  const target = path.join(parent, 'target');
  const stateRoot = path.join(parent, 'current');
  await mkdirPrivate(target);
  await symlink(target, stateRoot, 'dir');

  try {
    const result = await qualifyStateBackend({ stateRoot });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'state_root_symlink');
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test('qualifyStateBackend requires exact 0700 state-root permissions', async () => {
  const stateRoot = await makeStateRoot();
  await chmod(stateRoot, 0o750);

  try {
    const result = await qualifyStateBackend({ stateRoot });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'state_root_mode_mismatch');
    assert.deepEqual(await readdir(stateRoot), [], 'no probe is created in an unsafe root');
  } finally {
    await chmod(stateRoot, 0o700);
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('qualifyStateBackend requires the state root to match the effective uid', async () => {
  const stateRoot = await makeStateRoot();
  await chmod(stateRoot, 0o700);
  const getEffectiveUid = process.geteuid;
  if (typeof getEffectiveUid !== 'function') assert.fail('POSIX test requires process.geteuid');

  try {
    process.geteuid = () => getEffectiveUid() + 1;
    const result = await qualifyStateBackend({ stateRoot });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'state_root_owner_mismatch');
    assert.deepEqual(await readdir(stateRoot), [], 'no probe is created for another owner');
  } finally {
    process.geteuid = getEffectiveUid;
    await rm(stateRoot, { recursive: true, force: true });
  }
});

test('qualifyStateBackend returns an unavailable failure for a missing root', async () => {
  const parent = await makeStateParent();
  const stateRoot = path.join(parent, 'missing');

  try {
    const result = await qualifyStateBackend({ stateRoot });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'state_root_unavailable');
    assert.equal(result.error.causeCode, 'ENOENT');
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test('qualifyStateBackend rejects a non-directory root', async () => {
  const parent = await makeStateParent();
  const stateRoot = path.join(parent, 'state-file');
  await writeFile(stateRoot, 'not a directory', { mode: 0o700 });

  try {
    const result = await qualifyStateBackend({ stateRoot });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'state_root_not_directory');
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test('qualifyStateBackend contains SQLite factory failures and removes the probe', async () => {
  const stateRoot = await makeStateRoot();
  await chmod(stateRoot, 0o700);

  try {
    const result = await qualifyStateBackend({
      stateRoot,
      sqliteFactory() {
        const error = new Error('injected open failure') as Error & { code: string };
        error.code = 'ESQLITE';
        throw error;
      }
    });

    assert.equal(result.ok, false);
    if (result.ok) assert.fail('qualification must fail closed');
    assert.equal(result.error.code, 'sqlite_probe_failed');
    assert.equal(result.error.causeCode, 'ESQLITE');
    assert.deepEqual(await readdir(stateRoot), [], 'failed probes are removed');
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});

async function mkdirPrivate(dirname: string): Promise<void> {
  await mkdir(dirname, { mode: 0o700 });
}

async function makeStateRoot(): Promise<string> {
  const stateRoot = await mkdtemp(path.join(process.cwd(), '.cliq-state-root-'));
  await chmod(stateRoot, 0o700);
  return stateRoot;
}

async function makeStateParent(): Promise<string> {
  const parent = await mkdtemp(path.join(process.cwd(), '.cliq-state-parent-'));
  await chmod(parent, 0o700);
  return parent;
}
