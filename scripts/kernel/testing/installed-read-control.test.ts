// Readiness observer regression, not installed admission or native-owner evidence.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import ts from 'typescript';
import { KERNEL_DATABASE_FILENAME, KERNEL_STATE_SCHEMA_VERSION } from '../../../src/config.js';
import { digestOmitting } from '../../../src/kernel/identity.js';
import type { CanonicalTimeFenceV1, StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { inspectInstalledOwner, inspectInstalledOwnerHistory, observeInstalledOwnerHistory,
  waitForInstalledOwnerHistory } from './installed-read-control.js';
import * as readControl from './installed-read-control.js';

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
  return { stateRoot, filename, owner, fence, close: () => rm(stateRoot, { recursive: true, force: true }) };
}

function replaceFence(filename: string, fence: CanonicalTimeFenceV1): void {
  const db = new DatabaseSync(filename);
  try {
    db.prepare(`UPDATE canonical_time_fence SET state_owner_epoch = ?, last_accepted_at = ?,
      observed_wall_clock_at = ?, state = ?, updated_at = ?, fence_digest = ? WHERE id = 1`)
      .run(fence.stateOwnerEpoch, fence.lastAcceptedAt, fence.observedWallClockAt, fence.state, fence.updatedAt, fence.fenceDigest);
  } finally { db.close(); }
}

function replaceOwner(filename: string, owner: Record<string, unknown>): void {
  assert(typeof owner.ownerEpoch === 'number' && typeof owner.supervisorInstanceId === 'string' &&
    typeof owner.state === 'string' && typeof owner.rowDigest === 'string');
  const db = new DatabaseSync(filename);
  try {
    db.prepare(`UPDATE state_owners SET owner_epoch = ?, supervisor_instance_id = ?, record_json = ?, state = ?, row_digest = ?`)
      .run(owner.ownerEpoch, owner.supervisorInstanceId, JSON.stringify(owner), owner.state, owner.rowDigest);
  } finally { db.close(); }
}

// Execute only the real installed qualifier's final SQL-cut comparison over
// retained unit rows. This is neither a successful CAS/native-owner graph nor
// an installed lifecycle qualification; the preceding evidence walk is not run.
async function assertQualifierFinalCut(stateRoot: string, history: ReturnType<typeof inspectInstalledOwnerHistory>): Promise<void> {
  const source = ts.createSourceFile('installed-owner-history.ts', await readFile(
    new URL('./installed-owner-history.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declaration = source.statements.find((node): node is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(node) && node.name?.text === 'qualifyInstalledOwnerLinks');
  assert(declaration?.body, 'the real owner qualifier must retain its final cut check');
  const statements = declaration.body.statements, guard = statements.at(-3), publication = statements.at(-2), returned = statements.at(-1);
  assert(guard && ts.isExpressionStatement(guard), 'the final cut check must precede qualification');
  assert(publication && ts.isExpressionStatement(publication) && ts.isBinaryExpression(publication.expression) &&
    publication.expression.left.getText(source) === 'input.report.qualified' && publication.expression.right.kind === ts.SyntaxKind.TrueKeyword,
  'qualification must follow the final cut check');
  assert(returned && ts.isReturnStatement(returned) && returned.expression?.getText(source) === 'history',
    'the qualifier must return its original validated SQL cut');
  const exports = Object.entries(readControl);
  const check = new Function('assert', 'input', 'history', ...exports.map(([name]) => name), guard.getText(source));
  check(assert, { stateRoot }, history, ...exports.map(([, value]) => value));
}

test('the installed owner qualifier permits a healthy same-owner fence to advance during its evidence walk', async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot), next = { ...retained.fence,
      lastAcceptedAt: '2026-10-11T00:00:01.000Z', observedWallClockAt: '2026-10-11T00:00:01.000Z', updatedAt: '2026-10-11T00:00:01.000Z' };
    next.fenceDigest = digestOmitting(next, 'fenceDigest'); replaceFence(retained.filename, next);
    assert.deepEqual(inspectInstalledOwnerHistory(retained.stateRoot).owners, before.owners);
    await assertQualifierFinalCut(retained.stateRoot, before);
  } finally { await retained.close(); }
});

test('the final lineage observation accepts an unchanged complete SQL snapshot', async () => {
  const retained = await fixture();
  try {
    readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, inspectInstalledOwnerHistory(retained.stateRoot));
  } finally { await retained.close(); }
});

test('the lineage check does not pretend the observed wall clock is monotonic or a healthy-fence authority', async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot), regressed = { ...retained.fence,
      state: 'clock_regressed' as const, observedWallClockAt: '2026-10-10T23:59:59.000Z' };
    regressed.fenceDigest = digestOmitting(regressed, 'fenceDigest'); replaceFence(retained.filename, regressed);
    readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before);
    assert.equal(inspectInstalledOwnerHistory(retained.stateRoot).fence?.state, 'clock_regressed');
  } finally { await retained.close(); }
});

test('the final lineage observation rejects changes to every retained owner field, even when the row is rehashed', async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot);
    for (const [key, previous] of Object.entries(retained.owner)) {
      const changed = { ...retained.owner } as Record<string, unknown>;
      changed[key] = typeof previous === 'number' ? previous + 1 : key === 'acquiredAt'
        ? '2026-10-11T00:00:01.000Z' : typeof previous === 'string' && previous.length === 64 ? 'b'.repeat(64) : 'changed-' + previous;
      if (key !== 'rowDigest') changed.rowDigest = digestOmitting(changed, 'rowDigest');
      replaceOwner(retained.filename, changed);
      assert.throws(() => readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before), { code: 'ERR_ASSERTION' },
        'the original owner field must remain current: ' + key);
      await assert.rejects(assertQualifierFinalCut(retained.stateRoot, before), { code: 'ERR_ASSERTION' },
        'the installed qualifier must retain the complete owner comparison: ' + key);
      replaceOwner(retained.filename, retained.owner);
    }
  } finally { await retained.close(); }
});

test('the final lineage observation rejects a complete graceful terminal transition instead of ignoring state or evidence', async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot), terminal = { ...retained.owner,
      state: 'terminal', rowVersion: 2, releasedAt: '2026-10-11T00:00:01.000Z', terminalReason: 'graceful_release',
      transitionEvidenceRef: 'b'.repeat(64), transitionEvidenceDigest: 'b'.repeat(64) };
    terminal.rowDigest = digestOmitting(terminal, 'rowDigest'); replaceOwner(retained.filename, terminal);
    assert.equal(inspectInstalledOwnerHistory(retained.stateRoot).owners[0]?.state, 'terminal');
    assert.throws(() => readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before), { code: 'ERR_ASSERTION' });
  } finally { await retained.close(); }
});

test('the final lineage observation rejects a real SQL successor append and time-fence ownership transfer', async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot), terminal = { ...retained.owner,
      state: 'terminal', rowVersion: 2, releasedAt: '2026-10-11T00:00:01.000Z', terminalReason: 'graceful_release',
      transitionEvidenceRef: 'b'.repeat(64), transitionEvidenceDigest: 'b'.repeat(64) };
    terminal.rowDigest = digestOmitting(terminal, 'rowDigest'); replaceOwner(retained.filename, terminal);
    const successor = { ...retained.owner, ownerEpoch: 2, supervisorInstanceId: 'fixture-successor', instanceNonceDigest: 'b'.repeat(64) };
    successor.rowDigest = digestOmitting(successor, 'rowDigest');
    const db = new DatabaseSync(retained.filename);
    try { db.prepare('INSERT INTO state_owners VALUES(?, ?, ?, ?, ?)')
      .run(2, successor.supervisorInstanceId, JSON.stringify(successor), successor.state, successor.rowDigest); }
    finally { db.close(); }
    const fence = { ...retained.fence, stateOwnerEpoch: 2 }; fence.fenceDigest = digestOmitting(fence, 'fenceDigest');
    replaceFence(retained.filename, fence);
    assert.equal(inspectInstalledOwnerHistory(retained.stateRoot).owners.length, 2);
    assert.throws(() => readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before), { code: 'ERR_ASSERTION' });
  } finally { await retained.close(); }
});

test('the final lineage observation preserves every already-terminal historical owner field', async () => {
  const retained = await fixture();
  try {
    const terminal = { ...retained.owner, state: 'terminal', rowVersion: 2, releasedAt: '2026-10-11T00:00:01.000Z',
      terminalReason: 'graceful_release', transitionEvidenceRef: 'b'.repeat(64), transitionEvidenceDigest: 'b'.repeat(64) };
    terminal.rowDigest = digestOmitting(terminal, 'rowDigest'); replaceOwner(retained.filename, terminal);
    const before = inspectInstalledOwnerHistory(retained.stateRoot);
    for (const key of ['releasedAt', 'terminalReason', 'transitionEvidenceRef', 'transitionEvidenceDigest'] as const) {
      const changed = { ...terminal };
      changed[key] = key === 'releasedAt' ? '2026-10-11T00:00:02.000Z' : key === 'terminalReason'
        ? 'superseded_after_owner_death' : 'c'.repeat(64);
      changed.rowDigest = digestOmitting(changed, 'rowDigest'); replaceOwner(retained.filename, changed);
      assert.throws(() => readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before), { code: 'ERR_ASSERTION' },
        'historical terminal fields must not change: ' + key);
      replaceOwner(retained.filename, terminal);
    }
  } finally { await retained.close(); }
});

for (const kind of ['epoch', 'accepted_time', 'updated_time', 'digest', 'invalid_time', 'invalid_state', 'missing'] as const) {
  test('the final lineage observation rejects a damaged or backward time fence: ' + kind, async () => {
    const retained = await fixture();
    try {
      const before = inspectInstalledOwnerHistory(retained.stateRoot), fence = { ...retained.fence };
      switch (kind) {
        case 'epoch': fence.stateOwnerEpoch++; break;
        case 'accepted_time':
          fence.lastAcceptedAt = fence.observedWallClockAt = fence.updatedAt = '2026-10-10T23:59:59.000Z'; break;
        case 'updated_time': fence.updatedAt = '2026-10-10T23:59:59.000Z'; break;
        case 'invalid_time': fence.lastAcceptedAt = 'not a time'; break;
        case 'invalid_state': Object.assign(fence, { state: 'not a fence state' }); break;
      }
      fence.fenceDigest = kind === 'digest' ? 'b'.repeat(64) : digestOmitting(fence, 'fenceDigest');
      replaceFence(retained.filename, fence);
      if (kind === 'missing') {
        const db = new DatabaseSync(retained.filename);
        try { db.exec('DELETE FROM canonical_time_fence'); } finally { db.close(); }
      }
      assert.throws(() => readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before),
        kind === 'invalid_time' ? TypeError : { code: 'ERR_ASSERTION' }, 'a damaged or backward fence cannot qualify: ' + kind);
    } finally { await retained.close(); }
  });
}

async function withExclusiveWriter(filename: string, operation: (release: () => void) => void | Promise<void>) {
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
  let released = false;
  const release = () => {
    if (!released && child.exitCode === null && child.signalCode === null) { released = true; child.stdin.end('release\n'); }
  };
  try { await ready; await operation(release); }
  finally {
    release();
    await joined; clearTimeout(timer);
    assert.equal(spawnError, undefined); assert.equal(stdinError, undefined); assert.equal(timedOut, false);
    assert.equal(child.signalCode, null); assert.equal(child.exitCode, 0, stderr);
    assert.equal(stdout, 'locked\nreleased\n');
  }
}

test('the final lineage observation propagates actual SQLite BUSY and only succeeds after the writer joins', { timeout: 10000 }, async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot);
    await withExclusiveWriter(retained.filename, () => {
      assert.throws(() => readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before), { code: 'ERR_SQLITE_ERROR', errcode: 5 });
    });
    readControl.assertInstalledOwnerHistoryCurrent(retained.stateRoot, before);
  } finally { await retained.close(); }
});

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

test('a full-history readiness observation is pending, never successful, during a real exclusive writer', { timeout: 10000 }, async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot);
    await withExclusiveWriter(retained.filename, () => {
      assert.throws(() => inspectInstalledOwnerHistory(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 5 });
      assert.equal(observeInstalledOwnerHistory(retained.stateRoot), undefined);
    });
    assert.deepEqual(observeInstalledOwnerHistory(retained.stateRoot), before);
  } finally { await retained.close(); }
});

test('full-history readiness joins each real observation and returns the complete snapshot only after writer release', { timeout: 10000 }, async () => {
  const retained = await fixture();
  try {
    const before = inspectInstalledOwnerHistory(retained.stateRoot);
    await withExclusiveWriter(retained.filename, async release => {
      let returned = false;
      const waiting = waitForInstalledOwnerHistory(retained.stateRoot, Date.now() + 5000).then(value => { returned = true; return value; });
      void waiting.catch(() => {}); // A failing implementation still releases and joins the real writer before rethrowing.
      await delay(30); assert.equal(returned, false, 'BUSY cannot be returned as a successful history');
      release();
      assert.deepEqual(await waiting, before);
    });
  } finally { await retained.close(); }
});

test('a persistent real writer exhausts the caller original absolute readiness budget without restarting it', { timeout: 10000 }, async () => {
  const retained = await fixture();
  try {
    await withExclusiveWriter(retained.filename, async () => {
      const started = performance.now(), by = Date.now() + 100;
      await assert.rejects(waitForInstalledOwnerHistory(retained.stateRoot, by),
        { code: 'ERR_ASSERTION', message: 'installed owner history exceeded the original readiness budget' });
      assert(performance.now() - started < 1000, 'BUSY must not replace the caller deadline with a fresh wait');
      assert.equal(observeInstalledOwnerHistory(retained.stateRoot), undefined);
    });
    assert.equal(observeInstalledOwnerHistory(retained.stateRoot)?.owners.length, 1);
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
    assert.throws(() => observeInstalledOwnerHistory(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 26 });
    await assert.rejects(waitForInstalledOwnerHistory(retained.stateRoot, Date.now() + 5000), { code: 'ERR_SQLITE_ERROR', errcode: 26 });
  } finally { await retained.close(); }
});

test('readiness propagates non-BUSY SQLite errors and invalid owner metadata', async () => {
  const retained = await fixture();
  try {
    const db = new DatabaseSync(retained.filename);
    try { db.exec("UPDATE state_owners SET row_digest='corrupt'"); } finally { db.close(); }
    assert.throws(() => inspectInstalledOwner(retained.stateRoot), { code: 'ERR_ASSERTION' });
    assert.throws(() => observeInstalledOwnerHistory(retained.stateRoot), { code: 'ERR_ASSERTION' });
    await assert.rejects(waitForInstalledOwnerHistory(retained.stateRoot, Date.now() + 5000), { code: 'ERR_ASSERTION' });
    const missing = new DatabaseSync(retained.filename);
    try { missing.exec('DROP TABLE state_owners'); } finally { missing.close(); }
    assert.throws(() => inspectInstalledOwner(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 1 });
    assert.throws(() => observeInstalledOwnerHistory(retained.stateRoot), { code: 'ERR_SQLITE_ERROR', errcode: 1 });
    await assert.rejects(waitForInstalledOwnerHistory(retained.stateRoot, Date.now() + 5000), { code: 'ERR_SQLITE_ERROR', errcode: 1 });
  } finally { await retained.close(); }
});
