// Readiness observer regression, not installed admission or native-owner evidence.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { digestOmitting } from '../../../src/kernel/identity.js';
import type { CanonicalTimeFenceV1, StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { inspectInstalledOwner, inspectInstalledOwnerHistory } from './installed-read-control.js';

async function fixture() {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'cliq-installed-read-control-'));
  const filename = path.join(stateRoot, KERNEL_DATABASE_FILENAME);
  const hash = 'a'.repeat(64), time = '2026-10-11T00:00:00.000Z';
  // Retained unit-fixture rows only. No CAS/native/process authority is created.
  const owner: StateOwnerRecordV1 = { schemaVersion: 1, ownerEpoch: 1, supervisorInstanceId: 'fixture-owner',
    runtimeBundleRef: hash, runtimeBundleManifestDigest: hash, supervisorEntryId: 'fixture-supervisor',
    supervisorEntryVersion: '1', supervisorExecutableDigest: hash, processIdentityRef: hash, processIdentityDigest: hash,
    stateLockIdentityRef: hash, stateLockIdentityDigest: hash, acquisitionEvidenceRef: hash, acquisitionEvidenceDigest: hash,
    instanceNonceDigest: hash, acquiredAt: time, state: 'active', rowVersion: 1, rowDigest: '' };
  owner.rowDigest = digestOmitting(owner, 'rowDigest');
  const fence: CanonicalTimeFenceV1 = { schemaVersion: 1, format: 'cliq-canonical-time-fence-v1', stateOwnerEpoch: 1,
    lastAcceptedAt: time, observedWallClockAt: time, state: 'healthy', updatedAt: time, fenceDigest: '' };
  fence.fenceDigest = digestOmitting(fence, 'fenceDigest');
  const db = new DatabaseSync(filename);
  try {
    assert.equal(db.prepare('PRAGMA journal_mode=DELETE').get()!.journal_mode, 'delete');
    db.exec(`PRAGMA user_version=${KERNEL_STATE_SCHEMA_VERSION};
      CREATE TABLE state_owners(owner_epoch INTEGER, supervisor_instance_id TEXT, record_json TEXT, state TEXT, row_digest TEXT);
      CREATE TABLE canonical_time_fence(id INTEGER, state_owner_epoch INTEGER, last_accepted_at TEXT,
        observed_wall_clock_at TEXT, state TEXT, updated_at TEXT, fence_digest TEXT)`);
    db.prepare('INSERT INTO state_owners VALUES(1, ?, ?, ?, ?)').run(owner.supervisorInstanceId, JSON.stringify(owner), owner.state, owner.rowDigest);
    db.prepare('INSERT INTO canonical_time_fence VALUES(1, 1, ?, ?, ?, ?, ?)')
      .run(time, time, fence.state, time, fence.fenceDigest);
  } finally { db.close(); }
  return { stateRoot, filename, owner, close: () => rm(stateRoot, { recursive: true, force: true }) };
}

async function withExclusiveWriter(filename: string, operation: () => void) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { DatabaseSync } from 'node:sqlite';
    const db = new DatabaseSync(process.argv[1]);
    db.exec('BEGIN EXCLUSIVE');
    process.stdout.write('locked\\n');
    process.stdin.once('data', token => {
      assert.equal(token.toString(), 'release\\n');
      db.exec('COMMIT'); db.close();
      process.stdout.write('released\\n'); process.stdin.destroy();
    });
  `, filename], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', spawnError: Error | undefined, stdinError: Error | undefined, timedOut = false;
  let unlockReady!: () => void, failReady!: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => { unlockReady = resolve; failReady = reject; });
  const joined = new Promise<void>(resolve => {
    child.once('error', error => { spawnError = error; failReady(error); });
    child.once('close', () => { if (!stdout.startsWith('locked\n')) failReady(new Error(stderr || 'writer exited before holding its lock')); resolve(); });
  });
  child.stdin.on('error', error => {
    stdinError = error; failReady(error);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  });
  child.stdout.on('data', bytes => { stdout += bytes.toString(); if (stdout.startsWith('locked\n')) unlockReady(); });
  child.stderr.on('data', bytes => { stderr += bytes.toString(); });
  // This fixed child has no descendants. Kill and join that exact owned child
  // on a missing barrier; never leave a real SQLite writer behind on RED.
  const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); failReady(new Error('writer barrier timed out')); }, 5000);
  try { await ready; operation(); }
  finally {
    if (child.exitCode === null && child.signalCode === null) child.stdin.end('release\n');
    await joined; clearTimeout(timer);
    assert.equal(spawnError, undefined); assert.equal(stdinError, undefined); assert.equal(timedOut, false);
    assert.equal(child.signalCode, null); assert.equal(child.exitCode, 0, stderr);
    assert.equal(stdout, 'locked\nreleased\n');
  }
}

test('readiness remains pending during a real exclusive writer and sees the retained owner after release', { timeout: 10000 }, async () => {
  const retained = await fixture();
  try {
    await withExclusiveWriter(retained.filename, () => {
      assert.throws(() => inspectInstalledOwnerHistory(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 5 });
      assert.equal(inspectInstalledOwner(retained.stateRoot), undefined);
    });
    assert.deepEqual(structuredClone(inspectInstalledOwner(retained.stateRoot)), retained.owner);
  } finally { await retained.close(); }
});

test('a persistent real writer keeps readiness pending without adding a blocking wait', { timeout: 10000 }, async () => {
  const retained = await fixture();
  try {
    await withExclusiveWriter(retained.filename, () => {
      const started = performance.now();
      for (let attempt = 0; attempt < 5; attempt++) assert.equal(inspectInstalledOwner(retained.stateRoot), undefined);
      assert(performance.now() - started < 1000, 'readiness must leave waiting to its existing bounded poll loop');
      assert.throws(() => inspectInstalledOwnerHistory(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 5 });
    });
    assert.deepEqual(structuredClone(inspectInstalledOwner(retained.stateRoot)), retained.owner);
  } finally { await retained.close(); }
});

test('readiness propagates a damaged database instead of calling it pending', async () => {
  const retained = await fixture();
  try {
    await writeFile(retained.filename, 'not a SQLite database');
    assert.throws(() => inspectInstalledOwner(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 26 });
  } finally { await retained.close(); }
});

test('readiness propagates non-BUSY SQLite errors and invalid owner metadata', async () => {
  const retained = await fixture();
  try {
    const db = new DatabaseSync(retained.filename);
    try { db.exec("UPDATE state_owners SET row_digest='corrupt'"); } finally { db.close(); }
    assert.throws(() => inspectInstalledOwner(retained.stateRoot), { code: 'ERR_ASSERTION' });
    const missing = new DatabaseSync(retained.filename);
    try { missing.exec('DROP TABLE state_owners'); } finally { missing.close(); }
    assert.throws(() => inspectInstalledOwner(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 1 });
  } finally { await retained.close(); }
});
